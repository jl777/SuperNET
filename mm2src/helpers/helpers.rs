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
extern crate futures;
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
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

use futures::Future;
use futures::sync::oneshot::{self, Receiver};
use gstuff::any_to_str;
use hyper::{Body, Client, Request, StatusCode, HeaderMap};
use hyper::rt::Stream;
use libc::malloc;
use std::fmt::Display;
use std::intrinsics::copy;
use std::io::Write;
use std::mem::{forget, uninitialized};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::abort;
use std::ptr::read_volatile;
use std::os::raw::{c_char};
use std::sync::{Mutex, MutexGuard};
use tokio_core::reactor::Remote;

use hyper::header::{ HeaderValue, CONTENT_TYPE };
use hyper_rustls::HttpsConnector;

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
    unwrap! (std::thread::Builder::new().name ("CORE".into()) .spawn (move || {
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
E: Display + Send + 'static {
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

type SlurpFut = Box<Future<Item=(StatusCode, HeaderMap, Vec<u8>), Error=String> + Send>;

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

/// Helpers used in the unit and integration tests.
pub mod for_tests {
    use chrono::Local;

    use duct::Handle;

    use futures::Future;

    use gstuff::{now_float, slurp};

    use hyper::{Request, StatusCode};

    use serde_json::{self as json, Value as Json};

    use rand::{thread_rng, Rng};

    use std::collections::HashSet;
    use std::env;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::{Path, PathBuf};
    use std::str::{from_utf8};
    use std::sync::Mutex;
    use std::thread::sleep;
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
                let mut mm_ips = try_s! (MM_IPS.lock());
                let mut attempts = 0;
                let mut rng = thread_rng();
                loop {
                    let ip = Ipv4Addr::new (127, 0, 0, rng.gen_range (1, 255));
                    if attempts > 128 {return ERR! ("Out of local IPs?")}
                    let ip: IpAddr = ip.into();
                    if mm_ips.contains (&ip) {attempts += 1; continue}
                    conf["myipaddr"] = format! ("{}", ip) .into();

                    if cfg! (macos) {
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
