extern crate byteorder;
#[macro_use]
extern crate common;
extern crate crc;
extern crate crossbeam;
#[macro_use]
extern crate fomat_macros;
extern crate futures;
extern crate fxhash;
#[macro_use]
extern crate gstuff;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate rand;
extern crate serde;
//#[macro_use]
//extern crate serde_derive;
#[macro_use]
extern crate serde_json;
extern crate serde_bencode;
extern crate serde_bytes;
#[macro_use]
extern crate unwrap;
// As of now the large payloads are not compressable,
// 01 13:30:15, peers:617] peers_send_compat] Compression from 16046 to 16056
// 01 13:30:16, peers:617] peers_send_compat] Compression from 32084 to 32094
// but we're going to refactor these payloads in the future,
// and there might be different other payloads as we go through the port.
extern crate zstd_safe;  // https://github.com/facebook/zstd/blob/dev/lib/zstd.h

#[doc(hidden)]
pub mod tests;

use byteorder::{LittleEndian, WriteBytesExt};
use common::{bits256, for_c, slice_to_malloc, stack_trace, stack_trace_frame};
use common::log::TagParam;
use common::mm_ctx::{from_ctx, MmArc};
use crc::crc32;
use crossbeam::channel;
use fxhash::FxHashMap;
use gstuff::{now_float, now_ms};
use libc::{c_char, c_void};
use serde::Serialize;
use serde_bytes::{Bytes, ByteBuf};
use std::ffi::{CStr, CString};
use std::mem::{uninitialized, zeroed};
use std::slice::from_raw_parts;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Any unprocessed libtorrent alers are logged if this knob is set to "true".
const LOG_UNHANDLED_ALERTS: Option<&'static str> = option_env! ("LOG_UNHANDLED_ALERTS");

// NB: C++ structures and functions are defined in "dht.cc".

#[repr(C)]
struct dugout_t {
    err: *const c_char,  // strdup of a C++ exception `what`.
    sett: *mut c_void,  // `lt::settings_pack*` (from C++ `new`).
    session: *mut c_void,  // `lt::session*` (from C++ `new`).
}
impl dugout_t {
    fn has_err (&self) -> Option<&str> {
        if !self.err.is_null() {
            let what = if let Ok (msg) = unsafe {CStr::from_ptr (self.err)} .to_str() {msg} else {"Non-unicode `what`"};
            Some (what)
        } else {
            None
        }
    }
}
impl Drop for dugout_t {
    fn drop (&mut self) {
        let err = unsafe {delete_dugout (self)};
        if !err.is_null() {
            let what = unwrap! (unsafe {CStr::from_ptr (err)} .to_str());
            log! ("delete_dugout error: " (what));
            unsafe {libc::free (err as *mut c_void);}
        }
    }
}

enum Alert {}

extern "C" {
    fn delete_dugout (dugout: *mut dugout_t) -> *const c_char;
    fn dht_init (listen_interfaces: *const c_char, read_only: bool) -> dugout_t;
    fn enable_dht (dugout: *mut dugout_t);
    fn dht_alerts (dugout: *mut dugout_t, cb: extern fn (dugout: *mut dugout_t, cbctx: *mut c_void, alert: *mut Alert), cbctx: *mut c_void);
    fn alert_message (alert: *const Alert) -> *const c_char;
    fn is_dht_bootstrap_alert (alert: *const Alert) -> bool;
    fn as_listen_succeeded_alert (alert: *const Alert) -> *const c_char;
    fn as_listen_failed_alert (alert: *const Alert) -> *const c_char;
    fn as_dht_mutable_item_alert (alert: *const Alert,
        pkbuf: *mut u8, pkbuflen: i32,
        saltbuf: *mut i8, saltbuflen: i32,
        buf: *mut u8, buflen: i32,
        seq: *mut i64, auth: *mut bool) -> i32;
    // * `key` - The 32-byte seed which is given to `ed25519_create_keypair` in order to generate the key pair.
    //           The public key of that pair is also a pointer into the DHT space: nodes closest to it will be asked to store the value.
    // * `keylen` - The length of the `key` in bytes. Must be 32 bytes, no more no less.
    // * `salt` - Identifies the value without affecting its DHT location (TODO: check).
    // * `saltlen` - The length of the `salt` in bytes. 0 if not used.
    // * `callback` - Invoked from inside the libtorrent code, after the latter obtains the previous (existing) value from the DHT.
    // * `arg` - A pointer passed to the `callback`.
    // 
    // Callback arguments are:
    // 
    // * `arg` - A pointer passed to the `callback` via the `dht_put`.
    //           Usually points to a `Rust` struct, allowing the callback to communicate with the rest of the program.
    // * `arg2` - An integer passed to the `callback` via the `dht_put`.
    //            Might be used to verify the `arg`, for example.
    // * `have` - Bencoded value that was already present under the `key`.
    // * `havelen` - The length of `have` in bytes.
    // * `benload` - Bencoded value that should be saved under the `key`.
    //               In order to pass the value the callback must allocate the memory from `libc` (the C code will later `free` it).
    // * `benlen` - The length of `benload` in bytes.
    // * `seq` - The current version of the value (fetched together with `have`). We must increment it.
    //           DHT nodes will not accept a new value if our version is smaller than theirs.
    fn dht_put (dugout: *mut dugout_t,
                key: *const u8, keylen: i32,
                salt: *const u8, saltlen: i32,
                callback: extern fn (*mut c_void, u64, *const u8, i32, *mut *mut u8, *mut i32, *mut i64), arg: *const c_void, arg2: u64);
    // * `key` - The 32-byte seed which is given to `ed25519_create_keypair` in order to generate the key pair.
    //           The public key of that pair is also a pointer into the DHT space: nodes closest to it will be asked to store the value.
    // * `salt` - Identifies the value without affecting its DHT location (TODO: check).
    // * `pkbuf` - The public key derived from the `key` seed.
    //             If not zero, it is reused, skipping the `ed25519_create_keypair`.
    //             If zero, receives the generated public key.
    //             This public key identifies the entries obtained via the `dht_mutable_item_alert` (because DHT storage nodes don't know our seed).
    // * `pkbuflen` - Must be 32 bytes. Passed explicitly in order for us to check it.
    fn dht_get (dugout: *mut dugout_t, key: *const u8, keylen: i32, salt: *const u8, saltlen: i32, pkbuf: *mut u8, pkbuflen: i32);
}

/// Helps logging binary data (particularly with text-readable parts, such as bencode, netstring)
/// by replacing all the non-printable bytes with the `blank` character.
#[allow(unused)]
fn binprint (bin: &[u8], blank: u8) -> String {
    let mut bin: Vec<u8> = bin.into();
    for ch in bin.iter_mut() {if *ch < 0x20 || *ch >= 0x7F {*ch = blank}}
    unsafe {String::from_utf8_unchecked (bin)}
}

/// In order to emulate the synchronous exchange of messages with a peer on top of an asynchronous and optional delivery
/// (optional - because the message might come through a different channel, via the MM1 nanomsg for example)
/// we need a clock counter incremeted with each interaction.
/// 
/// That is, Alice sends message 1 and Bob tries to get message 1 through the DHT,
/// then Bob sends a message 2 reply and Alice tries to get it through the DHT,
/// then Alice sends a third message and Bob attempts to fetch it from DHT.
/// The numbers `1`, `2` and `3` in this example represent the order of the sequential communication between two peers.
/// We might say that these numbers *clock* the communication, that is, by telling Bob that we've *past* waiting for message 1
/// (having obtained it by other means perhaps) and are now waiting for message 2, etc.
type Clock = u32;

/// A command delivered to the `dht_thread` via the `PeersContext::cmd_tx`.
enum LtCommand {
    Put {
        // The 32-byte seed which is given to `ed25519_create_keypair` in order to generate the key pair.
        // The public key of the pair is also a pointer into the DHT space: nodes closest to it will be asked to store the value.
        seed: [u8; 32],
        // Identifies the value without affecting its DHT location (need to double-check this). Can be empty.  
        // Should not be too large (BEP 44 mentions error code 207 "salt too big").  
        // Must not contain zero bytes (we're passing it as a zero-terminated string sometimes).  
        // NB: If the `data` is large then `dht_thread` will append chunk number to `salt` for every extra DHT chunk.
        salt: Vec<u8>,
        data: Vec<u8>
    },
    // Starts a new get operation, unless it is already in progress.
    Get {
        seed: [u8; 32],
        salt: Vec<u8>
    }
}

/// The peer-to-peer and connectivity information local to the MM2 instance.
pub struct PeersContext {
    dht_thread: Mutex<Option<thread::JoinHandle<()>>>,
    /// A map from a nanomsg socket (created in C code) and the `LP_mypub25519` peer ID.  
    /// Also tracked here is the order of sequential communication on that socket - the Clock.
    /// 
    /// It is not yet clear whether we'll retain the nanomsg compatibility RPC layer,
    /// but even if we happen to facktor it away in the future, the socket abstraction might still be useful here
    /// because it represent a separate thread of sequential communication,
    /// allowing us to have multiple channels of communication between two peers.
    sock2peer: Mutex<FxHashMap<i32, (bits256, Clock)>>,
    cmd_tx: channel::Sender<LtCommand>,
    /// Should only be used by the `dht_thread`.
    cmd_rx: channel::Receiver<LtCommand>,
    // TODO: Remove the outdated `recently_fetched` entries after a while.
    /// seed, salt -> last-modified, value
    recently_fetched: Mutex<FxHashMap<([u8; 32], Vec<u8>), (f64, Vec<u8>)>>
}

impl PeersContext {
    /// Obtains a reference to this crate context, creating it if necessary.
    pub fn from_ctx (ctx: &MmArc) -> Result<Arc<PeersContext>, String> {
        Ok (try_s! (from_ctx (&ctx.peers_ctx, move || {
            let (cmd_tx, cmd_rx) = channel::unbounded::<LtCommand>();
            Ok (PeersContext {
                dht_thread: Mutex::new (None),
                sock2peer: Mutex::new (FxHashMap::default()),
                cmd_tx,
                cmd_rx,
                recently_fetched: Mutex::new (FxHashMap::default())
            })
        })))
    }
}

/// Data passed through the C code and into the callback during the put operation.
struct PutShuttle {
    // NB: Looks like it can invoked multiple times by libtorrent.
    put_handler: Box<Fn (&[u8]) -> Result<Vec<u8>, String> + 'static + Send + Sync>
}

lazy_static! {
    /// A buffer of the `PutShuttle` structures which are shared with the `callback` executed from the libtorrent and "dht.cc" code.
    /// We don't know when libtorrent will stop using the `put_handler`.
    /// Probably after the corresponding put alert, but we aren't catching one yet.
    /// So we have to keep the shuttles around for a while.
    static ref PUT_SHUTTLES: Mutex<FxHashMap<usize, (u64, Arc<PutShuttle>)>> = Mutex::new (FxHashMap::default());
    /// seed -> lm, ops
    static ref RATELIM: Mutex<FxHashMap<[u8; 32], (f64, f32)>> = Mutex::new (FxHashMap::default());
}

fn with_ratelim<F> (seed: [u8; 32], cb: F) where F: FnOnce (&mut f64, &mut f32) {
    if let Ok (mut ratelim) = RATELIM.lock() {
        let mut lim_entry = ratelim.entry (seed) .or_default();
        if lim_entry.0 == 0. {lim_entry.0 = now_float() - 0.01}
        cb (&mut lim_entry.0, &mut lim_entry.1)
    } else {log! ("Can't lock RATELIM")}
}

/// Invoked from the `dht_thread`, implementing the `LtCommand::Put` op.
fn split_and_put (seed: [u8; 32], mut salt: Vec<u8>, mut data: Vec<u8>, dugout: &mut dugout_t) {
    // chunk 1 {{number of chunks, 1 byte; piece of data} crc32}
    // chunk 2 {{piece of data} crc32}
    // chunk 3 {{piece of data} crc32}

    // Prepend the number of chunks into the `data`,
    // allowing the receiving side to get the number of chunks from the first one.
    // We can store at most 992 bytes in a chunk (BEP44 1000 bytes limit - 4 bytes bencode overhead - 4 bytes checksum).

    // We're using `(1..)` ranges and as of today they seem to overflow on `254u8`. For example, this overflows:
    // println! ("{:?}", (1u8..) .zip (0..254) .collect::<Vec<_>>());
    let max_chunks = 253;

    let number_of_chunks = (data.len() + 1) / 992 + if (data.len() + 1) % 992 != 0 {1} else {0};
    let number_of_chunks = if number_of_chunks > max_chunks {
        log! ("split_and_put] Error, payload (" (data.len()) " bytes) is too large for `peers`.");
        return
    } else {
        number_of_chunks as u8
    };
    data.insert (0, number_of_chunks);

    // Split the `data` into chunks.

    let mut chunks: Vec<Vec<u8>> = data.chunks (992) .map (|slice| slice.into()) .collect();
    assert_eq! (chunks.len(), number_of_chunks as usize);

    // Calculate the CRC for every chunk.
    // We should be able to check the chunks independently on the receiving side (that is, no CRC streaming between the chunks)
    // in order for the receiving side to swiftly retry getting the chunk if there's a CRC mismatch.

    for (idx, mut chunk) in (0..) .zip (chunks.iter_mut()) {
        use crc32::{update, IEEE_TABLE};
        let mut crc = update (idx, &IEEE_TABLE, &chunk);
        crc = update (crc, &IEEE_TABLE, &seed[..]);
        crc = update (crc, &IEEE_TABLE, &salt);
        unwrap! (chunk.write_u32::<LittleEndian> (crc));
        assert! (chunk.len() <= 996);
    }

    // Submit the chunks to libtorrent, appending the chunk number (1-based) to salt.

    extern fn callback (arg: *mut c_void, arg2: u64, have: *const u8, havelen: i32, benload: *mut *mut u8, benlen: *mut i32, seq: *mut i64) {
        assert! (!arg.is_null());
        assert! (!have.is_null());
        assert! (!benload.is_null());
        assert! (!benlen.is_null());
        assert! (!seq.is_null());
        //log! ("peers_send_compat] callback] " [=arg] ' ' [=have] ' ' [=havelen] ' ' [=benload] ' ' [=benlen] " seq " (unsafe {*seq}));
        let shuttles = unwrap! (PUT_SHUTTLES.lock());
        let shuttle = match shuttles.get (&(arg as usize)) {
            Some ((created, shuttle)) if *created == arg2 => shuttle,
            _ => panic! ("No such shuttle: {:?}", arg)
        };
        let have = unsafe {from_raw_parts (have, havelen as usize)};
        match (shuttle.put_handler) (have) {
            Ok (new_load) => unsafe {
                *benload = slice_to_malloc (&new_load);
                *benlen = new_load.len() as i32;
                *seq += 1
            },
            Err (err) => unsafe {
                log! ("put_handler error: " (err));
                // Keeping the previous value is probably the least invasive in that it doesn't affect the value parsers.
                *benload = slice_to_malloc (have);
                *benlen = have.len() as i32
            }
        }
    }

    // TODO: Maybe a more efficient cleanup.
    let now = now_ms();
    unwrap! (PUT_SHUTTLES.lock()) .retain (|_, (created, _)| now - *created < 600 * 1000);

    let salt_base_len = salt.len();

    with_ratelim (seed, |_lm, ops| *ops += chunks.len() as f32);

    for (idx, chunk) in (1..) .zip (chunks) {
        salt.truncate (salt_base_len);
        salt.push (idx);  // Should not be zero. A zero in the salt might be lost along the way (`CStr::from_ptr`).

        let shuttle = Arc::new (PutShuttle {
            put_handler: Box::new (move |have: &[u8]| -> Result<Vec<u8>, String> {
                let chunk = Bytes::new (&chunk);
                let benload = try_s! (serde_bencode::ser::to_bytes (&chunk));
                log! (
                    "chunk " (idx) ", existing bencoded is " (have.len()) " bytes, replacing with " (benload.len()) " bytes"
                    //"\n  from " (binprint (have, b'.'))
                    //"\n  to   " (binprint (&benload, b'.'))
                );
                with_ratelim (seed, |_lm, ops| *ops += 1.);
                Ok (benload)
            })
        });
        let mut shuttles = unwrap! (PUT_SHUTTLES.lock());
        let shuttle_ptr = (&*shuttle) as *const PutShuttle as *const c_void;
        shuttles.insert (shuttle_ptr as usize, (now, shuttle));

        //log! ("dht_put " [=seed] ", " [=salt]);
        unsafe {dht_put (dugout, seed.as_ptr(), seed.len() as i32, salt.as_ptr(), salt.len() as i32, callback, shuttle_ptr, now)}
    }
}

/// Big values are split into chunks in order to conform to the BEP 44 size limit.
/// This structure keeps information about a fetched chunk.
#[derive(Debug)]
struct ChunkGetsEntry {
    /// The time when we last issued a `dht_get` for the chunk.
    restarted: f64,
    /// Checksum-verified chunk data obtained from libtorrent.
    payload: Option<Vec<u8>>
}

/// Tracks the get operations currently in progress in libtorrent.
#[derive(Debug)]
struct GetsEntry {
    /// The public key derived from `seed` and used ad the value's location withing the DHT. (TODO: Confirm that salt is not the part of location).
    pk: [u8; 32],
    reassembled_at: Option<f64>,
    number_of_chunks: Option<u8>,
    chunks: Vec<ChunkGetsEntry>
}

type Gets = FxHashMap<([u8; 32], Vec<u8>), GetsEntry>;

/// Responsible for reassembling all the DHT pieces stored for a potentially large value.
/// Invoked whenever we see continued interest for the value
/// (note that the fetching should be dropped if the interest vanishes)
/// or when after one of the fetched pieces arrives.
fn get_pieces_scheduler (seed: [u8; 32], salt: Vec<u8>, dugout: &mut dugout_t, gets: &mut Gets, pctx: &PeersContext) {
    use std::collections::hash_map::Entry;

    let mut limops = 0f32;
    with_ratelim (seed, |lm, ops| {
        // Burn away ~10 ops per second.
        *ops = 0f32 .max (*ops - (now_float() - *lm) as f32 * 10.);
        limops = *ops;
        *lm = now_float();
    });
    if limops > 10. {return}  // Seed nodes are too busy. Skip adding more traffic for now. We'll proceed when the user invokes us later.

    let mut gets = match gets.entry ((seed, salt)) {
        Entry::Vacant (ve) => {
            // Fetch the first chunk.
            // Having it we'll know the number of chunks necessary to reassemble the entire value.
            let mut chunk_salt = ve.key().1.clone();
            chunk_salt.push (1);  // Identifies the first chunk.
            let mut pk: [u8; 32] = unsafe {zeroed()};
            unsafe {dht_get (dugout, seed.as_ptr(), seed.len() as i32, chunk_salt.as_ptr(), chunk_salt.len() as i32, pk.as_mut_ptr(), pk.len() as i32)}
            ve.insert (GetsEntry {
                pk,
                reassembled_at: None,
                number_of_chunks: None,
                chunks: vec! [ChunkGetsEntry {restarted: now_float(), payload: None}]
            });
            return
        },
        Entry::Occupied (oe) => oe
    };

    // See if the first chunk has arrived and the number of chunks with it.

    let now = now_float();
    if let Some (number_of_chunks) = gets.get().number_of_chunks {
        let chunks = &mut gets.get_mut().chunks;
        while chunks.len() < number_of_chunks as usize {
            chunks.push (ChunkGetsEntry {restarted: now, payload: None})
        }
    }

    // Go over the chunks and see if it's time to maybe retry fetching some of them.

    let salt = gets.key().1.clone();
    let mut pk = gets.get().pk;
    for (idx, chunk) in (1..) .zip (gets.get_mut().chunks.iter_mut()) {
        // Note that DHT nodes will ban us if we ask for too much too soon.
        if chunk.payload.is_none() && now - chunk.restarted > 4. && limops < 10. {
            let mut chunk_salt = salt.clone();
            chunk_salt.push (idx);  // Identifies the chunk.
            unsafe {dht_get (dugout,
                seed.as_ptr(), seed.len() as i32,
                chunk_salt.as_ptr(), chunk_salt.len() as i32,
                pk.as_mut_ptr(), pk.len() as i32)}
            chunk.restarted = now;
            with_ratelim (seed, |_lm, ops| {*ops += 1.; limops = *ops})
        }
    }

    // Reassemble the value.

    if gets.get().reassembled_at.is_none() {
        let missing_chunks = gets.get().chunks.iter().any (|chunk| chunk.payload.is_none());
        if missing_chunks {return}
        let mut buf = Vec::with_capacity (gets.get().chunks.len() * 992);
        for chunk in &gets.get().chunks {for &byte in unwrap! (chunk.payload.as_ref()) {buf.push (byte)}}
        //log! ("reassembled " (binprint (&buf, b'.')));
        gets.get_mut().reassembled_at = Some (now);

        let mut fetched = match pctx.recently_fetched.lock() {
            Ok (gets) => gets,
            Err (err) => {log! ("get_pieces_scheduler] Can't lock the `PeersContext::recently_fetched`: " (err)); return}
        };
        match fetched.entry ((seed, gets.key().1.clone())) {
            Entry::Vacant (ve) => {ve.insert ((now_float(), buf));},
            Entry::Occupied (oe) => *oe.into_mut() = (now_float(), buf)
        }
        return
    }

    // Remove the `gets` entry.
    // This allows, in particular, the user to *refetch* the value.
    // We still wait a second though, otherwise `peers_recv_compat` would start a refetch
    // immediately after returning a value and before the user had a chance to check it.

    let reassembled_at = unwrap! (gets.get().reassembled_at);
    if now_float() - reassembled_at > 1. {gets.remove_entry();}
}

const BOOTSTRAP_STATUS: &[&TagParam] = &[&"dht-boot"];

/// I've noticed that if we create a libtorrent session (`lt::session`) and destroy it right away
/// then it will often crash. Apparently we're catching it unawares during some initalization procedures.
/// This seems like a good enough reason to use a separate thread for managing the libtorrent,
/// allowing it to initialize and then stop at its own pace.
fn dht_thread (ctx: MmArc, _netid: u16, _our_public_key: bits256, preferred_port: u16, read_only: bool) {
    let listen_interfaces = fomat! ("0.0.0.0:" (preferred_port) ",[::]:" (preferred_port));
    // TODO: Use the configured IP.
    //log! ("preferred_port: " (preferred_port) "; listen_interfaces: " (listen_interfaces));
    let listen_interfaces = unwrap! (CString::new (listen_interfaces));
    let mut dugout = unsafe {dht_init (listen_interfaces.as_ptr(), read_only)};
    if let Some (err) = dugout.has_err() {
        // TODO: User-friendly log message (`LogState::log`).
        log! ("dht_init error: " (err));
        return
    }
       
    // Skip DHT bootstrapping if we're already stopping. But give libtorrent a bit of time first, just in case.
    if ctx.is_stopping() {thread::sleep (Duration::from_millis (200)); return}

    ctx.log.status (BOOTSTRAP_STATUS, "DHT bootstrap ...") .detach();
    unsafe {enable_dht (&mut dugout)};
    if let Some (err) = dugout.has_err() {
        ctx.log.status (BOOTSTRAP_STATUS, &fomat! ("DHT bootstrap error: " (err)));
        return
    }

    let pctx = unwrap! (PeersContext::from_ctx (&ctx));

    struct CbCtx<'a, 'b, 'c> {
        gets: &'a mut Gets,
        pctx: &'b PeersContext,
        ctx: &'c MmArc
    }

    // TODO: Remove the outdated `gets` entries after a while.
    let mut gets = Gets::default();

    loop {
        extern fn cb (dugout: *mut dugout_t, cbctx: *mut c_void, alert: *mut Alert) {
            let cbctx = cbctx as *mut CbCtx;
            let cbctx: &mut CbCtx = unsafe {&mut *cbctx};

            // We don't want to hit the 1000 bytes limit
            // (in BEP 44 it's optional, but I guess a lot of implementations enforce it by default),
            // meaning that a limited-size buffer is enough to get the data from C.
            let mut buf: [u8; 1024] = unsafe {uninitialized()};

            let mut keybuf: [u8; 32] = unsafe {uninitialized()};
            let mut saltbuf: [i8; 256] = unsafe {uninitialized()};
            let mut seq: i64 = 0;
            let mut auth: bool = false;
            let rc = unsafe {as_dht_mutable_item_alert (alert,
                keybuf.as_mut_ptr(), keybuf.len() as i32,
                saltbuf.as_mut_ptr(), saltbuf.len() as i32,
                buf.as_mut_ptr(), buf.len() as i32,
                &mut seq, &mut auth)};
            if rc > 0 {
                let bencoded = &buf[0 .. rc as usize];
                let chunk_salt = unsafe {CStr::from_ptr (saltbuf.as_ptr())} .to_bytes();
                let chunk = chunk_salt[chunk_salt.len() - 1] as usize;  // 1-based.
                log! (
                    "chunk " (chunk) ", dht_mutable_item_alert, " [=rc] ' ' [=seq] ' ' [=auth]
                    //"\n  " (binprint (bencoded, b'.'))
                );

                let payload: ByteBuf = if bencoded == b"0:" {ByteBuf::new()} else {
                    match serde_bencode::de::from_bytes (bencoded) {
                        Ok (payload) => payload,
                        Err (err) => {log! ("dht_thread] Can not decode the received payload: " (err)); return}
                    }
                };
                let mut payload = payload.to_vec();

                let salt: Vec<u8> = (&chunk_salt[0 .. chunk_salt.len() - 1]) .into();  // Without the chunk number suffix.

                let seed = {
                    let (seed, gets) = match cbctx.gets.iter_mut().find (|en| (en.0).1 == salt && en.1.pk == keybuf) {
                        Some (gets_entry) => ((gets_entry.0).0, gets_entry.1),
                        None => return
                    };
                    if chunk > gets.chunks.len() {
                        log! ("dht_thread] Error, `dht_mutable_item_alert` without a corresponding chunk entry " (chunk) " in `gets`"
                            " (there are " (gets.chunks.len()) " entries in `gets`");
                        return
                    }

                    // TODO: Check the checksum.

                    if payload.len() > (if chunk == 1 {5} else {4}) {
                        if chunk == 1 {gets.number_of_chunks = Some (payload.remove (0))}
                        for _ in 0..4 {payload.pop();}  // Checksum.
                        //log! ("chunk " (chunk) " cleaned " (binprint (&payload, b'.')));
                        gets.chunks[chunk-1].payload = Some (payload)
                    }

                    seed
                };

                // See if we can now reassemble the value.
                get_pieces_scheduler (seed, salt, unsafe {&mut *dugout}, cbctx.gets, cbctx.pctx)
            } else if rc < 0 {
                log! ("as_dht_mutable_item_alert error: " (rc));
            }

            if unsafe {is_dht_bootstrap_alert (alert)} {
                cbctx.ctx.log.claim_status (BOOTSTRAP_STATUS) .map (|status| status.append (" Done."));
                return
            }

            // TODO: Use `buf`.
            // NB: Looks like libtorrent automatically tries the next port number when it can't bind on the `preferred_port`.
            let endpoint_cs = unsafe {as_listen_succeeded_alert (alert)};
            if !endpoint_cs.is_null() {
                let _endpoint = unwrap! (unsafe {CStr::from_ptr (endpoint_cs)} .to_str());
                // TODO: Listen on "myipaddr" if present.
                //log! ("Listening on " (endpoint));
                unsafe {libc::free (endpoint_cs as *mut c_void)}
                return
            }

            // TODO: Use `buf`.
            let endpoint_cs = unsafe {as_listen_failed_alert (alert)};
            if !endpoint_cs.is_null() {
                let endpoint = unwrap! (unsafe {CStr::from_ptr (endpoint_cs)} .to_str());
                log! ("Can't listen on " (endpoint));
                return
            }

            if LOG_UNHANDLED_ALERTS == Some ("true") {
                // TODO: Use `buf`.
                let cs = unsafe {alert_message (alert)};
                if let Ok (alert_message) = unsafe {CStr::from_ptr (cs)} .to_str() {
                    log! ("lt: " (alert_message))
                }
                unsafe {libc::free (cs as *mut c_void)}
            }
        }
        // Invoke the `cb` on the libtorrent alerts.
        {
            let mut cbctx = CbCtx {
                gets: &mut gets,
                pctx: &*pctx,
                ctx: &ctx
            };
            unsafe {dht_alerts (&mut dugout, cb, &mut cbctx as *mut CbCtx as *mut c_void)};
        }
        if let Some (err) = dugout.has_err() {
            // TODO: User-friendly log message (`LogState::log`).
            log! ("dht_alerts error: " (err));
            return
        }

        if ctx.is_stopping() {break}

        match pctx.cmd_rx.recv_timeout (Duration::from_millis (50)) {
            Ok (LtCommand::Put {seed, salt, data}) => split_and_put (seed, salt, data, &mut dugout),
            Ok (LtCommand::Get {seed, salt}) => get_pieces_scheduler (seed, salt, &mut dugout, &mut gets, &*pctx),
            Err (channel::RecvTimeoutError::Timeout) => {},
            Err (channel::RecvTimeoutError::Disconnected) => break
        };
    }
}

/// * `netid` - We ignore the peers not matching the `netid`. Usually 0.
/// * `our_public_key` - Aka `LP_mypub25519`. This is our ID, allowing us to be different from other peers
///                      and to prove our identity (ownership of the corresponding private key) to a peer.
/// * `preferred_port` - We'll try to open an UDP endpoint on this port,
///                      which might help if the user configured this port in firewall and forwarding rules.
///                      We're not limited to this port though and might try other ports as well.
/// * `session_id` - Identifies our incarnation, allowing other peers to know if they're talking with the same instance.
pub fn initialize (ctx: &MmArc, netid: u16, our_public_key: bits256, preferred_port: u16, _session_id: u32) -> Result<(), String> {
    // NB: From the `fn test_trade` logs it looks like the `session_id` isn't shared with the peers currently.
    log! ("initialize] netid " (netid) " public key " (our_public_key) " preferred port " (preferred_port));
    if !our_public_key.nonz() {return ERR! ("No public key")}

    // TODO: Set it to `true` for smaller tests and to `false` for real-life deployments.
    // Maybe take the saved DHT state into account: tests always have a fresh directory,
    // whereas the real-life MM2 deployments are often restarted in an existing directory.
    // For small non-DHT tests we don't need to register ourselves.
    let read_only = true;  // Whether to register in the DHT network.

    let pctx = try_s! (PeersContext::from_ctx (&ctx));
    *try_s! (pctx.dht_thread.lock()) =
        Some (try_s! (thread::Builder::new().name ("dht".into()) .spawn ({
            let ctx = ctx.clone();
            move || dht_thread (ctx, netid, our_public_key, preferred_port, read_only)
        })));
    ctx.on_stop ({
        let ctx = ctx.clone();
        let pctx = pctx.clone();
        Box::new (move || -> Result<(), String> {
            if let Ok (mut dht_thread) = pctx.dht_thread.lock() {
                if let Some (dht_thread) = dht_thread.take() {
                    let join_status = ctx.log.status (&[&"dht-stop"], "Waiting for the dht_thread to stop...");
                    let _ = dht_thread.join();
                    join_status.append (" Done.");
                }
            }
            Ok(())
        })
    });

    *try_s! (for_c::PEERS_CLOCK_TICK_COMPAT.lock()) = Some (peers_clock_tick_compat);
    *try_s! (for_c::PEERS_SEND_COMPAT.lock()) = Some (peers_send_compat);
    *try_s! (for_c::PEERS_RECV_COMPAT.lock()) = Some (peers_recv_compat);

    Ok(())
}

/// Try to reach a peer and establish connectivity with it while knowing no more than its port and IP.
/// 
/// * `ip` - The public IP where the peer is supposedly listens for incoming connections.
/// * `preferred_port` - The preferred port of the peer.
pub fn investigate_peer (_ctx: &MmArc, ip: &str, preferred_port: u16) -> Result<(), String> {
    log! ("investigate_peer] ip " (ip) " preferred port " (preferred_port));
    Ok(())
}

/// Leave a message for the peer.
/// 
/// The message might be sent across a number of different delivery methods.
/// As of now we're going to send it via the Bittorrent DHT.
/// 
/// Delivery is not guaranteed (to check delivery we should manually get a reply from the peer).
/// 
/// * `to` - Recipient of the message (`LP_mypub25519` of the receiving MM2 instance).
/// * `payload` - Contents of the message.
pub fn send<T: Serialize> (_ctx: &MmArc, _to: bits256, payload: &T) -> Result<(), String> {
    // TODO: `send` should return a custom `Future`, finishing when we get the corresponding alert.
    //       We might even get some interesting statistics as the result:
    //       the number of nodes where the value was stored,
    //       the number of nodes currently unreachable,
    //       IP addresses of the storage nodes.
    //       The `Future` COULD be custom in order to provide the progress and completion status in a non-blocking way.
    //       Or maybe a better abstraction here is a `Stream` of status updates?
    //       Or on multiple levels, it might be a callback API sharing the status of an operation
    //       and then a sometimes convenient `Future` interface on top of it.

    // TODO: Serialization happens inside this method,
    //       that is, we don't know the actual size of the bencoded payload outside of it,
    //       and so the spilling of the value into the extra items, to workaround the 1000 bytes limit,
    //       should happen there automatically.
    //       Most likely we'll need to wrap the payload, adding a versioned struct around it.
    //       ⇒ It might be better to stick to the binary encoding of the value,
    //       rather than treating it as a sub-`Serialize` in the same structure,
    //       because we don't know the `Deserialize` of that structure beforehand.
    //       That is, the bits of data we use to reassemble a big chunk, et cetera,
    //       are a part of the layer that is being used before the user tries to access the payload
    //       and provides us a means to decode it.

/*
    #[derive(Serialize)]
    struct Wrap<'a, T: Serialize> {
        p: &'a T  // Field names should be small, though it might be even better if we could use a tuple.
    }
    let _wrap = Wrap {
        p: payload
    };
*/

    // By wrapping payload in a tuple we can avoid the cost of the field names.
    let _tuple = serde_bencode::ser::to_bytes (&(123u8, payload));

    ERR! ("TBD")
}

/// Associate a nanomsg socket with a p2p `LP_mypub25519` identifier of the peer.  
/// Also resets the clock counter to zero, initiating a new session with that peer.
pub fn bind (ctx: &MmArc, sock: i32, peer: bits256) -> Result<(), String> {
    log! ("bind] sock " (sock) " = peer " (peer));
    let pctx = try_s! (PeersContext::from_ctx (ctx));
    let mut sock2peer = try_s! (pctx.sock2peer.lock());
    sock2peer.insert (sock, (peer, 0 as Clock));
    Ok(())
}

/// Advances the clock counter, switching the communication with the peer to the next message.
/// 
/// The counter should be advanced before sending a new message or receiving one,
/// in order to maintain the communication sequence, discriminating one message from another.
/// 
/// For example:  
/// Clock 1: Alice sends "Hi!". Bob waits for "Hi!".  
/// Clock 2: Bob answers with "Hi yourself!". Alice waits for "Hi yourself!".
/// 
/// Affects `fn send`, `fn peers_send_compat` and `fn peers_recv_compat`.
/// 
/// The counter is reset to zero in `fn bind`.
/// 
/// * `ctx` - `MmCtx` handler.
/// * `sock` - The nanomsg socket that `fn bind` has previously associated with a peer ID.
fn peers_clock_tick_compat (ctx: u32, sock: i32) {
    if let Err (err) = (move || -> Result<(), String> {
        let ctx = try_s! (MmArc::from_ffi_handle (ctx));
        let pctx = try_s! (PeersContext::from_ctx (&ctx));
        let mut sock2peer = try_s! (pctx.sock2peer.lock());
        use std::collections::hash_map::Entry;
        match sock2peer.entry (sock) {
            Entry::Vacant (_) => {
                ERR! ("Unknown sock: {}", sock)
            },
            Entry::Occupied (mut oe) => {
                oe.get_mut().1 += 1;
                Ok(())
            }
        }
    })() {log! ("peers_clock_tick_compat error: " (err))}
}

lazy_static! {
    /// Allows us to skip logging the trace when it hasn't changed from the last time.
    static ref PREVIOUS_TRACE: Mutex<String> = Mutex::new (String::new());
}

/// Start sending `data` to the peer.
/// 
/// Returns (almost) immediately, scheduling a transfer of the provided payload to the peer identified by `sock`.
/// 
/// The transfer itself might take some time,
/// given that we might be waiting for the DHT bootstrap to finish
/// and then for the data to be routed to the corresponding DHT nodes.
/// 
/// NB: The clock counter must be incremented with `fn peers_clock_tick_compat` before sending a new message,
/// in order to discern one message from another.
/// 
/// * `ctx` - `MmCtx` handler.
/// * `sock` - The nanomsg socket that `fn bind` has previously associated with a peer ID.
/// * `data` - Binary payload, usually generated by the `datagen` functions in "LP_swap.c".
///            (We plan to replace it with Rust `Serialize` structures in future,
///            in order to waste less space and to make the swap communication more transparent and debug-friendly).
/// * `datalen` - The length of the payload in `data`.
/// 
/// Returns 0 if successfull, negative number if not.
fn peers_send_compat (ctx: u32, sock: i32, data: *const u8, datalen: i32) -> i32 {
    assert! (sock > 0);
    assert! (!data.is_null());
    assert! (datalen > 0);
    let ret = (move || -> Result<i32, String> {
        let ctx = try_s! (MmArc::from_ffi_handle (ctx));
        let pctx = try_s! (PeersContext::from_ctx (&ctx));
        let sock2peer = try_s! (pctx.sock2peer.lock());
        if let Some ((peer, clock)) = sock2peer.get (&sock) {
            let mut trace = String::with_capacity (4096);
            stack_trace (&mut stack_trace_frame, &mut |l| trace.push_str (l));
            let mut prev = try_s! (PREVIOUS_TRACE.lock());

            let pk = fomat! ((peer));
            log! (
                "peers_send_compat] sock: " (sock) "; datalen: " (datalen) "; peer " (&pk[0..3]) "; clock " (clock)
                if trace != *prev {'\n' (trace)}
            );

            *prev = trace;

            // TODO: Consider storing several seeds for reliability.
            //       Maybe after a certain delay.
            //       Might need a feedback mechanism, repeating the `put`s and expanding the number of seeds used if there is no answer from the other side.

            // TODO: Use the `peer.bytes` as the seed.
            let mut seed: [u8; 32] = unsafe {zeroed()};
            seed[0] = 7;
            // TODO: Use our own public key and the `clock` to generate the salt.
            // NB: There should be no zero bytes in the salt (due to `CStr::from_ptr` and the possibility of a similar problem abroad).
            let salt = b"qwe";
            let salt = Vec::from (&salt[..]);

            let mut data: Vec<u8> = unsafe {from_raw_parts (data, datalen as usize)} .into();

            // Tell `dht_thread` to save the data.
            try_s! (pctx.cmd_tx.send (LtCommand::Put {seed, salt, data}));

            Ok (0)
        } else {ERR! ("Unknown sock: {}", sock)}
    })();
    match ret {
        Ok (ret) => ret,
        Err (err) => {log! ("peers_send_compat error: " (err)); -1}
    }
}

/// See if we've got some data from the peer.
/// 
/// * `ctx` - `MmCtx` handler.
/// * `sock` - The nanomsg socket that `fn bind` has previously associated with a peer ID.
/// 
/// The function is non-blocking.
/// The caller should invoke it repeatedly until the message has arrived
/// (here or on another RPC channel, such as the MM1 nanomsg).
/// 
/// The function doesn't advance the clock counter (the sequential number of the message that we are trying to get).
/// Consequently, if we call `peers_recv_compat` without advancing the clock counter
/// then the function will simply return the same message over and over.
/// In order to switch to the *next* message the clock counter should be incremented with `fn peers_clock_tick_compat`.
/// 
/// Returns the length of the `data` buffer allocated with `malloc`,
/// or `0` if no data was received (if the message has not arrived yet),
/// or a negative number if there was an error.
fn peers_recv_compat (ctx: u32, sock: i32, data: *mut *mut u8) -> i32 {
    match (move || -> Result<i32, String> {
        let ctx = try_s! (MmArc::from_ffi_handle (ctx));
        let pctx = try_s! (PeersContext::from_ctx (&ctx));
        let sock2peer = try_s! (pctx.sock2peer.lock());
        if let Some ((peer, clock)) = sock2peer.get (&sock) {
            let mut trace = String::with_capacity (4096);
            stack_trace (&mut stack_trace_frame, &mut |l| trace.push_str (l));
            let mut prev = try_s! (PREVIOUS_TRACE.lock());

            let pk = fomat! ((peer));
            if option_env! ("TEST_RECV") != Some ("true") {log! (
                "peers_recv_compact] sock: " (sock) "; peer " (&pk[0..3]) "; clock " (clock)
                if trace != *prev {'\n' (trace)}
            )}

            *prev = trace;

            // TODO: Use our public key as the seed.
            let mut seed: [u8; 32] = unsafe {zeroed()};
            seed[0] = 7;
            // TODO: Use the peer's public key and the `clock` to generate the salt.
            let salt = b"qwe";
            let salt = Vec::from (&salt[..]);

            // Ask the `dht_thread` to fetch the data.
            // Note that we should do that even if the `PeersContext::recently_fetched` already has a value,
            // because that value might be invalid or outdated.
            // We should keep re-fetching the value until the user stops calling `peers_recv_compat`.
            try_s! (pctx.cmd_tx.send (LtCommand::Get {seed, salt: salt.clone()}));

            {   // Check if the data has arrived.
                let fetched = try_s! (pctx.recently_fetched.lock());
                if let Some ((_lm, value)) = fetched.get (&(seed, salt)) {
                    unsafe {*data = slice_to_malloc (&value)}
                    return Ok (value.len() as i32)
                }
            }

            Ok (0)
        } else {ERR! ("Unknown sock: {}", sock)}
    })() {
        Ok (l) => l,
        Err (err) => {log! ("peers_recv_compact error: " (err)); -1}
    }
}
