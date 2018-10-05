//! A common dependency for the non-WASM crates.
//! 
//!                  helpers
//!                     ^
//!                     |
//!     subcrate A   ---+---   subcrate B
//!         ^                      ^
//!         |                      |
//!         +-----------+----------+
//!                     |
//!                   main

extern crate backtrace;
extern crate chrono;
#[macro_use]
extern crate duct;
#[macro_use]
extern crate fomat_macros;
extern crate futures;
extern crate fxhash;
#[macro_use]
extern crate gstuff;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate hyper;
extern crate hyper_rustls;
extern crate rand;
extern crate serde;
#[macro_use]
extern crate serde_json;
extern crate term;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

pub mod log;

use futures::Future;
use futures::sync::oneshot::{self, Receiver};
use fxhash::FxHashMap;
use gstuff::{any_to_str, now_float};
use hyper::{Body, Client, Request, StatusCode, HeaderMap};
use hyper::rt::Stream;
use libc::{malloc, free};
use rand::random;
use serde_json::{Value as Json};
use std::fmt;
use std::ffi::{CStr, CString};
use std::intrinsics::copy;
use std::io::Write;
use std::mem::{forget, size_of, uninitialized, zeroed};
use std::net::{SocketAddr};
use std::os::raw::{c_char, c_void};
use std::ops::Deref;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::abort;
use std::ptr::{null_mut, read_volatile};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::str;
use tokio_core::reactor::Remote;

use hyper::header::{ HeaderValue, CONTENT_TYPE };
use hyper_rustls::HttpsConnector;

#[allow(dead_code,non_upper_case_globals,non_camel_case_types,non_snake_case)]
pub mod lp {include! ("c_headers/LP_include.rs");}
use lp::{_bits256 as bits256};

#[allow(dead_code,non_upper_case_globals,non_camel_case_types,non_snake_case)]
pub mod os {include! ("c_headers/OS_portable.rs");}

#[allow(dead_code,non_upper_case_globals,non_camel_case_types,non_snake_case)]
pub mod nn {include! ("c_headers/nn.rs");}

#[allow(dead_code,non_upper_case_globals,non_camel_case_types,non_snake_case)]
pub mod etomiclib {include! ("c_headers/etomiclib.rs");}

pub const MM_VERSION: &'static str = env! ("MM_VERSION");

pub const SATOSHIS: u64 = 100000000;

/// Converts u64 satoshis to f64
pub fn sat_to_f(sat: u64) -> f64 { sat as f64 / SATOSHIS as f64 }

/// Created by `void *bitcoin_ctx()`.
pub enum BitcoinCtx {}

pub struct BtcCtxBox(*mut BitcoinCtx);

extern "C" {
    pub fn bitcoin_ctx() -> *mut BitcoinCtx;
    fn bitcoin_ctx_destroy (ctx: *mut BitcoinCtx);
    pub fn bitcoin_priv2wif (symbol: *const u8, wiftaddr: u8, wifstr: *mut c_char, privkey: bits256, addrtype: u8) -> i32;
    fn bits256_str (hexstr: *mut u8, x: bits256) -> *const c_char;
}

impl fmt::Display for bits256 {
    fn fmt (&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf: [u8; 65] = unsafe {zeroed()};
        let cs = unsafe {bits256_str (buf.as_mut_ptr(), *self)};
        let hex = unwrap! (unsafe {CStr::from_ptr (cs)} .to_str());
        f.write_str (hex)
    }
}

/// Apparently helps to workaround `double` fluctuations occuring on *certain* systems.
/// cf. https://stackoverflow.com/questions/19804472/double-randomly-adds-0-000000000000001.
/// Not sure it's needed in Rust, the floating point operations should be determenistic here,
/// but better safe than sorry.
pub const SMALLVAL: f64 = 0.000000000000001;

/// MarketMaker state, shared between the various MarketMaker threads.
///
/// Every MarketMaker has one and only one instance of `MmCtx`.
///
/// Should fully replace `LP_globals`.
///
/// *Not* a singleton: we should be able to run multiple MarketMakers instances in a process.
///
/// Any function directly using `MmCtx` is automatically a stateful function.
/// In the future we might want to replace direct state access with traceable and replayable
/// state modifications
/// (cf. https://github.com/artemii235/SuperNET/blob/mm2-dice/mm2src/README.md#purely-functional-core).
/// 
/// `MmCtx` never moves in memory (and it isn't `Send`), it is created and then destroyed in place
/// (this invariant should make it a bit simpler thinking about aliasing and thread-safety,
/// particularly of the C structures during the gradual port).
/// Only the pointers (`MmArc`, `MmWeak`) can be moved around.
/// 
/// Threads only have the non-`mut` access to `MmCtx`, allowing us to directly share certain fields.
pub struct MmCtx {
    /// MM command-line configuration.
    pub conf: Json,
    /// Human-readable log and status dashboard.
    pub log: log::LogState,
    /// Bitcoin elliptic curve context, obtained from the C library linked with "eth-secp256k1".
    btc_ctx: *mut BitcoinCtx,
    /// Set to true after `LP_passphrase_init`, indicating that we have a usable state.
    ///
    /// Should be refactored away in the future. State should always be valid.
    /// If there are things that are loaded in background then they should be separately optional,
    /// without invalidating the entire state.
    pub initialized: AtomicBool,
    /// True if the MarketMaker instance needs to stop.
    stop: AtomicBool,
    /// IP and port for the RPC server to listen on.
    pub rpc_ip_port: SocketAddr,
    /// Unique context identifier, allowing us to more easily pass the context through the FFI boundaries.  
    /// 0 if the handler ID is allocated yet.
    ffi_handler: AtomicUsize,
    stop_listeners: Mutex<Vec<Box<FnMut()->Result<(), String>>>>
}
impl MmCtx {
    pub fn new (conf: Json, rpc_ip_port: SocketAddr) -> MmArc {
        let log = log::LogState::mm (&conf);
        MmArc (Arc::new (MmCtx {
            conf,
            log,
            btc_ctx: unsafe {bitcoin_ctx()},
            initialized: AtomicBool::new (false),
            stop: AtomicBool::new (false),
            rpc_ip_port,
            ffi_handler: AtomicUsize::new (0),
            stop_listeners: Mutex::new (Vec::new())
        }))
    }
    /// This field is freed when `MmCtx` is dropped, make sure `MmCtx` stays around while it's used.
    pub unsafe fn btc_ctx (&self) -> *mut BitcoinCtx {self.btc_ctx}
    pub fn stop (&self) {
        if self.stop.compare_and_swap (false, true, Ordering::Relaxed) == false {
            let mut stop_listeners = unwrap! (self.stop_listeners.lock(), "Can't lock stop_listeners");
            for listener in stop_listeners.iter_mut() {
                if let Err (err) = listener() {
                    eprintln! ("MmCtx::stop] Listener error: {}", err)
                }
            }
        }
    }
    /// True if the MarketMaker instance needs to stop.
    pub fn is_stopping (&self) -> bool {
        if unsafe {lp::LP_STOP_RECEIVED != 0} {return true}
        self.stop.load (Ordering::Relaxed)
    }
    /// Register a callback to be invoked when the MM receives the "stop" request.  
    /// The callback is invoked immediately if the MM is stopped already.
    pub fn on_stop (&self, mut cb: Box<FnMut()->Result<(), String>>) {
        let mut stop_listeners = unwrap! (self.stop_listeners.lock(), "Can't lock stop_listeners");
        if self.stop.load (Ordering::Relaxed) {
            if let Err (err) = cb() {
                eprintln! ("MmCtx::on_stop] Listener error: {}", err)
            }
        } else {
            stop_listeners.push (cb)
        }
    }
}
impl Drop for MmCtx {
    fn drop (&mut self) {
        unsafe {bitcoin_ctx_destroy (self.btc_ctx)}
    }
}

// We don't want to send `MmCtx` across threads, it will only obstruct the normal use case
// (and might result in undefined behavior if there's a C struct or value in the context that is aliased from the various MM threads).
// Only the `MmArc` is `Send`.
// Also, `MmCtx` not being `Send` allows us to easily keep various C pointers on the context,
// which will likely come useful during the gradual port.
//not-implemented-on-stable// impl !Send for MmCtx {}

pub struct MmArc (Arc<MmCtx>);
// NB: Explicit `Send` and `Sync` marks here should become unnecessary later,
// after we finish the initial port and replace the C values with the corresponding Rust alternatives.
unsafe impl Send for MmArc {}
unsafe impl Sync for MmArc {}
impl Clone for MmArc {fn clone (&self) -> MmArc {MmArc (self.0.clone())}}
impl Deref for MmArc {type Target = MmCtx; fn deref (&self) -> &MmCtx {&*self.0}}

pub struct MmWeak (Weak<MmCtx>);
// Same as `MmArc`.
unsafe impl Send for MmWeak {}
unsafe impl Sync for MmWeak {}

lazy_static! {
    /// A map from a unique context ID to the corresponding MM context, facilitating context access across the FFI boundaries.  
    /// NB: The entries are not removed in order to keep the FFI handlers unique.
    pub static ref MM_CTX_FFI: Mutex<FxHashMap<u32, MmWeak>> = Mutex::new (FxHashMap::default());
}

impl MmArc {
    /// Unique context identifier, allowing us to more easily pass the context through the FFI boundaries.
    pub fn ffi_handler (&self) -> Result<u32, String> {
        use std::collections::hash_map::Entry;

        let mut mm_ctx_ffi = try_s! (MM_CTX_FFI.lock());
        let have = self.ffi_handler.load (Ordering::Relaxed) as u32;
        if have != 0 {return Ok (have)}
        let mut tries = 0;
        loop {
            if tries > 999 {panic! ("MmArc] out of RIDs")} else {tries += 1}
            let rid: u32 = random();
            if rid == 0 {continue}
            match mm_ctx_ffi.entry (rid) {
                Entry::Occupied (_) => continue,  // Try another ID.
                Entry::Vacant (ve) => {
                    ve.insert (self.weak());
                    self.ffi_handler.store (rid as usize, Ordering::Relaxed);
                    return Ok (rid)
                }
            }
        }
    }

    /// Tries getting access to the MM context.  
    /// Fails if an invalid MM context handler is passed (no such context or dropped context).
    pub fn from_ffi_handler (ffi_handler: u32) -> Result<MmArc, String> {
        if ffi_handler == 0 {return ERR! ("MmArc] Zeroed ffi_handler")}
        let mm_ctx_ffi = try_s! (MM_CTX_FFI.lock());
        match mm_ctx_ffi.get (&ffi_handler) {
            Some (weak) => match MmArc::from_weak (weak) {
                Some (ctx) => Ok (ctx),
                None => ERR! ("MmArc] ffi_handler {} is dead", ffi_handler)
            },
            None => ERR! ("MmArc] ffi_handler {} does not exists", ffi_handler)
        }
    }

    /// Generates a weak link, to track the context without prolonging its life.
    pub fn weak (&self) -> MmWeak {
        MmWeak (Arc::downgrade (&self.0))
    }

    /// Tries to obtain the MM context from the weak link.  
    pub fn from_weak (weak: &MmWeak) -> Option<MmArc> {
        weak.0.upgrade().map (|arc| MmArc (arc))
    }
}

#[no_mangle]
pub fn r_btc_ctx (mm_ctx_id: u32) -> *mut c_void {
    if let Ok (ctx) = MmArc::from_ffi_handler (mm_ctx_id) {
        unsafe {ctx.btc_ctx() as *mut c_void}
    } else {
        null_mut()
    }
}

/// RAII and MT wrapper for `cJSON`.
pub struct CJSON (pub *mut lp::cJSON);
impl CJSON {
    pub fn from_zero_terminated (json: *const c_char) -> Result<CJSON, String> {
        lazy_static! {static ref LOCK: Mutex<()> = Mutex::new(());}
        let _lock = try_s! (LOCK.lock());  // Probably need a lock to access the error singleton.
        let c_json = unsafe {lp::cJSON_Parse (json)};
        if c_json == null_mut() {
            let err = unsafe {lp::cJSON_GetErrorPtr()};
            let err = try_s! (unsafe {CStr::from_ptr (err)} .to_str());
            ERR! ("Can't parse JSON, error: {}", err)
        } else {
            Ok (CJSON (c_json))
        }
    }
    pub fn from_str (json: &str) -> Result<CJSON, String> {
        let cs = try_s! (CString::new (json));
        CJSON::from_zero_terminated (cs.as_ptr())
    }
}
impl Drop for CJSON {
    fn drop (&mut self) {
        unsafe {lp::cJSON_Delete (self.0)}
        self.0 = null_mut()
    }
}
unsafe impl Send for CJSON {}

/// Helps sharing a string slice with C code by allocating a zero-terminated string with the C standard library allocator.
/// 
/// The difference from `CString` is that the memory is then *owned* by the C code instead of being temporarily borrowed,
/// that is it doesn't need to be recycled in Rust.
/// Plus we don't check the slice for zeroes, most of our code doesn't need that extra check.
pub fn str_to_malloc (s: &str) -> *mut c_char {unsafe {
    let buf = malloc (s.len() + 1) as *mut u8;
    copy (s.as_ptr(), buf, s.len());
    *buf.offset (s.len() as isize) = 0;
    buf as *mut c_char
}}

/// Converts *mut c_char to Rust String
/// Doesn't free the allocated memory
/// It's responsibility of the caller to free the memory when required
/// Returns error in case of null pointer input
pub fn c_char_to_string(ptr: *mut c_char) -> Result<String, String> { unsafe {
    if !ptr.is_null() {
        let res_str = try_s!(CStr::from_ptr(ptr).to_str());
        let res_str = String::from(res_str);
        Ok(res_str)
    } else {
        ERR!("Tried to convert null pointer to Rust String!")
    }
}}

/// Frees C raw pointer
/// Does nothing in case of null pointer input
pub fn free_c_ptr(ptr: *mut c_void) { unsafe {
    if !ptr.is_null() {
        free(ptr as *mut libc::c_void);
    }
}}

//? pub fn bytes_to_malloc (slice: &[u8]) -> *mut c_void

/// Use the value, preventing the compiler and linker from optimizing it away.
pub fn black_box<T> (v: T) -> T {
    // https://github.com/rust-lang/rfcs/issues/1484#issuecomment-240853111
    let ret = unsafe {read_volatile (&v)};
    forget (v);
    ret
}

/// Using a static buffer in order to minimize the chance of heap and stack allocations in the signal handler.
fn trace_buf() -> MutexGuard<'static, [u8; 256]> {
    lazy_static! {static ref TRACE_BUF: Mutex<[u8; 256]> = Mutex::new (unsafe {uninitialized()});}
    unwrap! (TRACE_BUF.lock())
}

fn trace_name_buf() -> MutexGuard<'static, [u8; 128]> {
    lazy_static! {static ref TRACE_NAME_BUF: Mutex<[u8; 128]> = Mutex::new (unsafe {uninitialized()});}
    unwrap! (TRACE_NAME_BUF.lock())
}

/// Formats a stack frame.
/// Some common and less than useful frames are skipped.
pub fn stack_trace_frame (buf: &mut Write, symbol: &backtrace::Symbol) {
    let filename = match symbol.filename() {Some (path) => path, None => return};
    let filename = match filename.components().rev().next() {Some (c) => c.as_os_str().to_string_lossy(), None => return};
    let lineno = match symbol.lineno() {Some (lineno) => lineno, None => return};
    let name = match symbol.name() {Some (name) => name, None => return};
    let mut name_buf = trace_name_buf();
    let name = gstring! (name_buf, {
        let _ = write! (name_buf, "{}", name);  // NB: `fmt` is different from `SymbolName::as_str`.
    });

    // Skip common and less than informative frames.

    if name.starts_with ("backtrace::") {return}
    if name.starts_with ("core::") {return}
    if name.starts_with ("alloc::") {return}
    if name.starts_with ("panic_unwind::") {return}
    if name.starts_with ("std::") {return}
    if name == "mm2::crash_reports::rust_seh_handler" {return}
    if name == "veh_exception_filter" {return}
    if name == "helpers::stack_trace" {return}
    if name == "mm2::log_stacktrace" {return}
    if name == "__scrt_common_main_seh" {return}  // Super-main on Windows.
    if name.starts_with ("helpers::stack_trace") {return}
    if name.starts_with ("mm2::crash_reports::signal_handler") {return}

    let _ = writeln! (buf, "  {}:{}] {}", filename, lineno, name);
}

/// Generates a string with the current stack trace.
///
/// * `format` - Generates the string representation of a frame.
/// * `output` - Function used to print the stack trace.
///              Printing immediately, without buffering, should make the tracing somewhat more reliable.
pub fn stack_trace (format: &mut FnMut (&mut Write, &backtrace::Symbol), output: &mut FnMut (&str)) {
    backtrace::trace (|frame| {
        backtrace::resolve (frame.ip(), |symbol| {
            let mut trace_buf = trace_buf();
            let trace = gstring! (trace_buf, {
              format (trace_buf, symbol);
            });
            output (trace);
        });
        true
    });
}

fn start_core_thread() -> Remote {
    let (tx, rx) = oneshot::channel();
    unwrap! (thread::Builder::new().name ("CORE".into()) .spawn (move || {
        if let Err (err) = catch_unwind (AssertUnwindSafe (move || {
            let mut core = unwrap! (tokio_core::reactor::Core::new(), "!core");
            unwrap! (tx.send (core.remote()), "Can't send Remote.");
            loop {core.turn (None)}
        })) {
            eprintln! ("CORE panic! {:?}", any_to_str (&*err));
            abort()
        }
    }), "!spawn");
    let core: Remote = unwrap! (rx.wait(), "!wait");
    core
}

lazy_static! {
    /// Shared asynchronous reactor.
    pub static ref CORE: Remote = start_core_thread();
}

/// With a shared reactor drives the future `f` to completion.
///
/// NB: This function is only useful if you need to get the results of the execution.
/// If the results are not necessary then a future can be scheduled directly on the reactor:
///
///     CORE.spawn (|_| f);
pub fn drive<F, R, E> (f: F) -> Receiver<Result<R, E>> where
F: Future<Item=R, Error=E> + Send + 'static,
R: Send + 'static,
E: Send + 'static {
    let (sx, rx) = oneshot::channel();
    CORE.spawn (move |_handle| {
        f.then (move |fr: Result<R, E>| -> Result<(),()> {
            let _ = sx.send (fr);
            Ok(())
        })
    });
    rx
}

/// With a shared reactor drives the future `f` to completion.
///
/// Similar to `fn drive`, but returns a stringified error,
/// allowing us to collapse the `Receiver` and return the `R` directly.
pub fn drive_s<F, R, E> (f: F) -> impl Future<Item=R, Error=String> where
F: Future<Item=R, Error=E> + Send + 'static,
R: Send + 'static,
E: fmt::Display + Send + 'static {
    drive (f) .then (move |r| -> Result<R, String> {
        let r = try_s! (r);  // Peel the `Receiver`.
        let r = try_s! (r);  // `E` to `String`.
        Ok (r)
    })
}

/// Initialize the crate.
pub fn init() {
    // Pre-allocate the stack trace buffer in order to avoid allocating it from a signal handler.
    black_box (&*trace_buf());
    black_box (&*trace_name_buf());
}

type SlurpFut = Box<Future<Item=(StatusCode, HeaderMap, Vec<u8>), Error=String> + Send + 'static>;

/// Executes a Hyper request, returning the response status, headers and body.
pub fn slurp_req (request: Request<Body>) -> SlurpFut {
    // We're doing only a single request with the `Client`,
    // so likely a single or sequential DNS access, probably don't need to spawn more than a single DNS thread.
    let dns_threads = 1;

    let https = HttpsConnector::new (dns_threads);
    let client = Client::builder().executor (CORE.clone()) .build (https);
    let request_f = client.request (request);
    let response_f = request_f.then (move |res| -> SlurpFut {
        let res = try_fus! (res);
        let status = res.status();
        let headers = res.headers().clone();
        let body_f = res.into_body().concat2();
        let combined_f = body_f.then (move |body| -> Result<(StatusCode, HeaderMap, Vec<u8>), String> {
            let body = try_s! (body);
            Ok ((status, headers, body.to_vec()))
        });
        Box::new (combined_f)
    });
    Box::new (drive_s (response_f))
}

/// Executes a GET request, returning the response status, headers and body.
pub fn slurp_url (url: &str) -> SlurpFut {
    slurp_req (try_fus! (Request::builder().uri (url) .body (Body::empty())))
}

#[test]
fn test_slurp_req() {
    let (status, _headers, _body) = unwrap! (slurp_url ("https://httpbin.org/get") .wait());
    assert! (status.is_success());
}

/// Fetch URL by HTTPS and parse JSON response
pub fn fetch_json<T>(url: &str) -> Box<Future<Item=T, Error=String>>
    where T: serde::de::DeserializeOwned + Send + 'static {
    Box::new(slurp_url(url).and_then(|result| {
        // try to parse as json with serde_json
        let result = try_s!(serde_json::from_slice(&result.2));

        Ok(result)
    }))
}

/// Send POST JSON HTTPS request and parse response
pub fn post_json<T>(url: &str, json: String) -> Box<Future<Item=T, Error=String>>
    where T: serde::de::DeserializeOwned + Send + 'static {
    let request = try_fus!(Request::builder()
        .method("POST")
        .uri(url)
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json")
        )
        .body(json.into())
    );

    Box::new(slurp_req(request).and_then(|result| {
        // try to parse as json with serde_json
        let result = try_s!(serde_json::from_slice(&result.2));

        Ok(result)
    }))
}

/// Wrapper for LP_coinfind C function
pub fn find_coin (coin: Option<&str>) -> Option<(*mut lp::iguana_info, String)> {
    let coin = match coin {Some (c) => c, None => return None};
    let coin_cs = unwrap! (CString::new (coin));
    let coin_inf = unsafe {lp::LP_coinfind (coin_cs.as_ptr() as *mut c_char)};
    if coin_inf == null_mut() {return None}
    if unsafe {(*coin_inf).inactive} != 0 {return None}
    Some ((coin_inf, coin.into()))
}

/// A closure that would (re)start a `Future` to synchronize with an external resource in `RefreshedExternalResource`.
type ExternalResourceSync<R> = Box<Fn()->Box<Future<Item=R,Error=String> + Send + 'static> + Send + 'static>;

/// Memory space accessible to the `Future` tail spawned by the `RefreshedExternalResource`.
struct RerShelf<R: Send + 'static> {
    /// The time when the `Future` generated by `sync` has filled this shell.
    time: f64,
    /// Results of the `sync`-generated `Future`.
    result: Result<R, String>
}

/// Often we have an external resource that we need a fresh copy of.
/// (Or the other way around, when there is an external resource that we need to periodically update or synchronize with).
/// Particular property of such resources is that they might be unavailable,
/// might be slow due to resource overload or network congestion,
/// need to be resynchronized periodically
/// while being nice to the resource by maintaining rate limits.
///
/// Some of these resources are naturally singleton.
/// For exampe, we have only one "bittrex.com" and we need not multiple copies of its market data withing the process.
///
/// This helper here will organize the handling of such synchronization, periodically starting the synchronization `Future`,
/// restarting it on timeout, maintaining rate limits.
pub struct RefreshedExternalResource<R: Send + 'static> {
    sync: Mutex<ExternalResourceSync<R>>,
    /// Rate limit in the form of the desired number of seconds between the syncs.
    every_n_sec: f64,
    /// Start a new `Future` and drop the old one if it fails to finish after this number of seconds.
    timeout_sec: f64,
    /// The time (in f64 seconds) when we last (re)started the `sync`.
    /// We want `AtomicU64` but it isn't yet stable.
    last_start: AtomicUsize,
    shelf: Arc<Mutex<Option<RerShelf<R>>>>
}
impl<R: Send + 'static> RefreshedExternalResource<R> {
    /// New instance of the external resource tracker.
    ///
    /// * `every_n_sec` - Desired number of seconds between the syncs.
    /// * `timeout_sec` - Start a new `sync` and drop the old `Future` if it fails to finish after this number of seconds.
    ///                   Automatically bumped to be at least `every_n_sec` large.
    /// * `sync` - Generates the `Future` that should synchronize with the external resource in background.
    ///            Note that we'll tail the `Future`, polling the tail from the shared asynchronous reactor;
    ///            *spawn* the `Future` onto a different reactor if the shared asynchronous reactor is not the best option.
    pub fn new (every_n_sec: f64, timeout_sec: f64, sync: ExternalResourceSync<R>) -> RefreshedExternalResource<R> {
        assert_eq! (size_of::<usize>(), 8);
        RefreshedExternalResource {
            sync: Mutex::new (sync),
            every_n_sec,
            timeout_sec: timeout_sec .max (every_n_sec),
            last_start: AtomicUsize::new (0f64.to_bits() as usize),
            shelf: Arc::new (Mutex::new (None))
        }
    }

    /// Performs the maintenance operations necessary to periodically refresh the resource.
    pub fn tick (&self) -> Result<(), String> {
        let now = now_float();
        let last_finish = match * try_s! (self.shelf.lock()) {Some (ref rer_shelf) => rer_shelf.time, None => 0.};
        let last_start = f64::from_bits (self.last_start.load (Ordering::Relaxed) as u64);

        if now - last_start > self.timeout_sec || (last_finish > last_start && now - last_start > self.every_n_sec) {
            self.last_start.store (now.to_bits() as usize, Ordering::Relaxed);
            let sync = try_s! (self.sync.lock());
            let f = (*sync)();
            let shelf_tx = self.shelf.clone();
            let f = f.then (move |result| -> Result<(), ()> {
                let mut shelf = match shelf_tx.lock() {Ok (l) => l, Err (err) => {
                    eprintln! ("RefreshedExternalResource::tick] Can't lock the shelf: {}", err);
                    return Err(())
                }};
                let shelf_time = match *shelf {Some (ref r) => r.time, None => 0.};
                if now > shelf_time {  // This check prevents out-of-order shelf updates.
                    *shelf = Some (RerShelf {
                        time: now_float(),
                        result
                    })
                }
                Ok(())
            });
            CORE.spawn (move |_| f);  // Polls `f` in background.
        }

        Ok(())
    }

    /// The time, in seconds since UNIX epoch, when the refresh `Future` resolved.
    pub fn last_finish (&self) -> Result<f64, String> {
        Ok (match * try_s! (self.shelf.lock()) {
            Some (ref rer_shelf) => rer_shelf.time,
            None => 0.
        })
    }

    pub fn with_result<V, F: Fn (Option<&Result<R, String>>) -> Result<V, String>> (&self, cb: F) -> Result<V, String> {
        let shelf = try_s! (self.shelf.lock());
        match *shelf {
            Some (ref rer_shelf) => cb (Some (&rer_shelf.result)),
            None => cb (None)
        }
    }
}

/// Helpers used in the unit and integration tests.
pub mod for_tests {
    use chrono::Local;

    use duct::Handle;

    use futures::Future;

    use gstuff::{now_float, slurp, ISATTY};

    use hyper::{Request, StatusCode};

    use serde_json::{self as json, Value as Json};

    use term;

    use rand::{thread_rng, Rng};

    use std::collections::HashSet;
    use std::env;
    use std::fs;
    use std::io::{Write};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::{Path, PathBuf};
    use std::str::{from_utf8};
    use std::sync::Mutex;
    use std::thread::{sleep};
    use std::time::Duration;

    use super::slurp_req;

    /// Automatically kill a wrapped process.
    pub struct RaiiKill {handle: Handle, running: bool}
    impl RaiiKill {
        pub fn from_handle (handle: Handle) -> RaiiKill {
            RaiiKill {handle, running: true}
        }
        pub fn running (&mut self) -> bool {
            if !self.running {return false}
            match self.handle.try_wait() {Ok (None) => true, _ => {self.running = false; false}}
        }
    }
    impl Drop for RaiiKill {
        fn drop (&mut self) {
            // The cached `running` check might provide some protection against killing a wrong process under the same PID,
            // especially if the cached `running` check is also used to monitor the status of the process.
            if self.running() {
                let _ = self.handle.kill();
            }
        }
    }

    /// When `drop`ped, dumps the given file to the stdout.
    /// 
    /// Used in the tests, copying the MM log to the test output.
    /// 
    /// Note that because of https://github.com/rust-lang/rust/issues/42474 it's currently impossible to share the MM log interactively,
    /// hence we're doing it in the `drop`.
    pub struct RaiiDump {
        pub log_path: PathBuf
    }
    impl Drop for RaiiDump {
        fn drop (&mut self) {
            // `term` bypasses the stdout capturing, we should only use it if the capturing was disabled.
            let nocapture = env::args().any (|a| a == "--nocapture");

            let log = slurp (&self.log_path);

            // Make sure the log is Unicode.
            // We'll get the "io error when listing tests: Custom { kind: InvalidData, error: StringError("text was not valid unicode") }" otherwise.
            let log = String::from_utf8_lossy (&log);
            let log = log.trim();

            if let (true, true, Some (mut t)) = (nocapture, *ISATTY, term::stdout()) {
                let _ = t.fg (term::color::BRIGHT_YELLOW);
                let _ = t.write (format! ("vvv {:?} vvv\n", self.log_path) .as_bytes());
                let _ = t.fg (term::color::YELLOW);
                let _ = t.write (log.as_bytes());
                let _ = t.write (b"\n");
                let _ = t.reset();
            } else {
                println! ("vvv {:?} vvv\n{}", self.log_path, log);
            }
        }
    }

    lazy_static! {
        /// A singleton with the IPs used by the MarketMakerIt instances created in this session.
        static ref MM_IPS: Mutex<HashSet<IpAddr>> = Mutex::new (HashSet::new());
    }

    /// An instance of a MarketMaker process started by and for an integration test.  
    /// Given that [in CI] the tests are executed before the build, the binary of that process is the tests binary.
    pub struct MarketMakerIt {
        /// The MarketMaker's current folder where it will try to open the database files.
        pub folder: PathBuf,
        /// Unique (to run multiple instances) IP, like "127.0.0.$x".
        pub ip: IpAddr,
        /// The file we redirected the standard output and error streams to.
        pub log_path: PathBuf,
        /// The PID of the MarketMaker process.
        pub pc: Option<RaiiKill>,
        /// RPC API key.
        pub userpass: String
    }
    impl MarketMakerIt {
        /// Create a new temporary directory and start a new MarketMaker process there.
        /// 
        /// * `conf` - The command-line configuration passed to the MarketMaker.
        ///            Unique local IP address is injected as "myipaddr" unless this field is already present.
        /// * `userpass` - RPC API key. We should probably extract it automatically from the MM log.
        /// * `local` - Function to start the MarketMaker in a local thread, instead of spawning a process.
        ///             Used when the `LOCAL_THREAD_MM` env is `1` and allows to more easily debug the tested MM.
        pub fn start (mut conf: Json, userpass: String, local: fn (folder: PathBuf, log_path: PathBuf, conf: Json))
        -> Result<MarketMakerIt, String> {
            let executable = try_s! (env::args().next().ok_or ("No program name"));
            let executable = try_s! (Path::new (&executable) .canonicalize());

            let ip: IpAddr = if conf["myipaddr"].is_null() {  // Generate an unique IP.
                let mut attempts = 0;
                let mut rng = thread_rng();
                loop {
                    let ip4 = if cfg! (target_os = "macos") {
                        // For some reason we can't use the 127.0.0.2-255 range of IPs on Travis/MacOS,
                        // cf. https://travis-ci.org/artemii235/SuperNET/jobs/428167579
                        // I plan to later look into this, but for now we're always using 127.0.0.1 on MacOS.
                        //
                        // P.S. 127.0.0.2:7783 works when tested with static+cURL,
                        // cf. https://travis-ci.org/artemii235/SuperNET/builds/428350505
                        // but with MM it mysteriously fails,
                        // cf. https://travis-ci.org/artemii235/SuperNET/jobs/428341581#L4534.
                        // I think that something might be wrong with the HTTP server on our side.
                        // Hopefully porting it to Hyper (https://github.com/artemii235/SuperNET/issues/155) will help.
                        if attempts > 0 {sleep (Duration::from_millis (1000 + attempts * 200))}
                        Ipv4Addr::new (127, 0, 0, 1)
                    } else {
                        Ipv4Addr::new (127, 0, 0, rng.gen_range (1, 255))
                    };
                    if attempts > 128 {return ERR! ("Out of local IPs?")}
                    let ip: IpAddr = ip4.clone().into();
                    let mut mm_ips = try_s! (MM_IPS.lock());
                    if mm_ips.contains (&ip) {attempts += 1; continue}
                    mm_ips.insert (ip.clone());
                    conf["myipaddr"] = format! ("{}", ip) .into();
                    conf["rpcip"] = format! ("{}", ip) .into();

                    if cfg! (target_os = "macos") && ip4.octets()[3] > 1 {
                        // Make sure the local IP is enabled on MAC (and in the Travis CI).
                        // cf. https://superuser.com/a/458877
                        let cmd = cmd! ("sudo", "ifconfig", "lo0", "alias", format! ("{}", ip), "up");
                        match cmd.stderr_to_stdout().read() {
                            Err (err) => println! ("MarketMakerIt] Error trying to `up` the {}: {}", ip, err),
                            Ok (output) => println! ("MarketMakerIt] Upped the {}: {}", ip, output)
                        }
                    }
                    break ip
                }
            } else {  // Just use the IP given in the `conf`.
                let ip: IpAddr = try_s! (try_s! (conf["myipaddr"].as_str().ok_or ("myipaddr is not a string")) .parse());
                let mut mm_ips = try_s! (MM_IPS.lock());
                if mm_ips.contains (&ip) {println! ("MarketMakerIt] Warning, IP {} was already used.", ip)}
                mm_ips.insert (ip.clone());
                ip
            };

            // Use a separate (unique) temporary folder for each MM.
            // (We could also remove the old folders after some time in order not to spam the temporary folder.
            // Though we don't always want to remove them right away, allowing developers to check the files).
            let now = Local::now();
            let folder = format! ("mm2_{}_{}", now.format ("%Y-%m-%d_%H-%M-%S-%3f"), ip);
            let folder = env::temp_dir().join (folder);
            try_s! (fs::create_dir (&folder));
            try_s! (fs::create_dir (folder.join ("DB")));
            let log_path = folder.join ("mm2.log");
            conf["log"] = unwrap! (log_path.to_str()) .into();

            // If `LOCAL_THREAD_MM` is set to `1`
            // then instead of spawning a process we start the MarketMaker in a local thread,
            // allowing us to easily *debug* the tested MarketMaker code.
            // Note that this should only be used while running a single test,
            // using this option while running multiple tests (or multiple MarketMaker instances) is currently UB.
            let pc = if env::var ("LOCAL_THREAD_MM") == Ok ("1".into()) {
                local (folder.clone(), log_path.clone(), conf);
                None
            } else {
                Some (RaiiKill::from_handle (try_s! (cmd! (&executable, "test_mm_start", "--nocapture")
                    .dir (&folder)
                    .env ("_MM2_TEST_CONF", try_s! (json::to_string (&conf)))
                    .env ("MM2_UNBUFFERED_OUTPUT", "1")
                    .stderr_to_stdout().stdout (&log_path) .start())))
            };

            Ok (MarketMakerIt {folder, ip, log_path, pc, userpass})
        }
        pub fn log_as_utf8 (&self) -> Result<String, String> {
            let mm_log = slurp (&self.log_path);
            Ok (unsafe {String::from_utf8_unchecked (mm_log)})
        }
        /// Busy-wait on the log until the `pred` returns `true` or `timeout_sec` expires.
        pub fn wait_for_log (&self, timeout_sec: f64, pred: &Fn (&str) -> bool) -> Result<(), String> {
            let start = now_float();
            let ms = 50 .min ((timeout_sec * 1000.) as u64 / 20 + 10);
            loop {
                let mm_log = try_s! (self.log_as_utf8());
                if pred (&mm_log) {return Ok(())}
                if now_float() - start > timeout_sec {return ERR! ("Timeout expired waiting for a log condition")}
                sleep (Duration::from_millis (ms));
            }
        }
        /// Invokes the locally running MM and returns it's reply.
        pub fn rpc (&self, payload: Json) -> Result<(StatusCode, String), String> {
            let payload = try_s! (json::to_string (&payload));
            let uri = format! ("http://{}:7783", self.ip);
            let request = try_s! (Request::builder().method ("POST") .uri (uri) .body (payload.into()));
            let (status, _headers, body) = try_s! (slurp_req (request) .wait());
            Ok ((status, try_s! (from_utf8 (&body)) .trim().into()))
        }
        /// Sends the &str payload to the locally running MM and returns it's reply.
        pub fn rpc_str (&self, payload: &'static str) -> Result<(StatusCode, String), String> {
            let uri = format! ("http://{}:7783", self.ip);
            let request = try_s! (Request::builder().method ("POST") .uri (uri) .body (payload.into()));
            let (status, _headers, body) = try_s! (slurp_req (request) .wait());
            Ok ((status, try_s! (from_utf8 (&body)) .trim().into()))
        }
        /// Send the "stop" request to the locally running MM.
        pub fn stop (&self) -> Result<(), String> {
            let (status, body) = try_s! (self.rpc (json! ({"userpass": self.userpass, "method": "stop"})));
            if status != StatusCode::OK {return ERR! ("MM didn't accept a stop. body: {}", body)}
            Ok(())
        }
    }
    impl Drop for MarketMakerIt {
        fn drop (&mut self) {
            if let Ok (mut mm_ips) = MM_IPS.lock() {
                mm_ips.remove (&self.ip);
            } else {println! ("MarketMakerIt] Can't lock MM_IPS.")}
        }
    }
}
