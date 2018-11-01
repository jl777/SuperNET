use fxhash::FxHashMap;
use hyper::header::HeaderValue;
use libc::{c_void};
use rand::random;
use serde_json::{Value as Json};
use std::any::Any;
use std::net::{SocketAddr};
use std::ops::Deref;
use std::ptr::{null_mut};
use std::sync::{Arc, Mutex, Weak};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use super::{bitcoin_ctx, bitcoin_ctx_destroy, lp, log, BitcoinCtx};

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
    // TODO: Refactor away, CORS headers should be generated in the RPC layer,
    // there is no need to complicate stuff by pulling them through several other layers.
    /// CORS header value for RPC server (ACCESS_CONTROL_ALLOW_ORIGIN)
    pub rpc_cors: HeaderValue,
    /// Unique context identifier, allowing us to more easily pass the context through the FFI boundaries.  
    /// 0 if the handler ID is allocated yet.
    ffi_handler: AtomicUsize,
    /// Callbacks to invoke from `fn stop`.
    stop_listeners: Mutex<Vec<Box<FnMut()->Result<(), String>>>>,
    /// The context belonging to the `portfolio` crate: `PortfolioContext`.
    pub portfolio_ctx: Mutex<Option<Arc<Any + 'static + Send + Sync>>>,
    /// The context belonging to the `ordermatch` mod: `OrdermatchContext`.
    pub ordermatch_ctx: Mutex<Option<Arc<Any + 'static + Send + Sync>>>,
}
impl MmCtx {
    pub fn new (conf: Json, rpc_ip_port: SocketAddr, rpc_cors: HeaderValue) -> MmArc {
        let log = log::LogState::mm (&conf);
        MmArc (Arc::new (MmCtx {
            conf,
            log,
            btc_ctx: unsafe {bitcoin_ctx()},
            initialized: AtomicBool::new (false),
            stop: AtomicBool::new (false),
            rpc_ip_port,
            rpc_cors,
            ffi_handler: AtomicUsize::new (0),
            stop_listeners: Mutex::new (Vec::new()),
            portfolio_ctx: Mutex::new (None),
            ordermatch_ctx: Mutex::new (None),
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

    /// `true` if the MarketMaker was configured with the `{"client": 1}` command-line flag.
    /// 
    /// Should be used instead of the C `IAMLP` (where 1 means NOT client).
    /// 
    /// Soon as we learn it, should clarify the exact meaning of what being a client means.
    pub fn am_client (&self) -> bool {
        self.conf["client"].as_i64() == Some (1)
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

#[derive(Clone)]
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
