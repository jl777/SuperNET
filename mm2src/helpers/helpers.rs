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
extern crate futures;
#[macro_use]
extern crate gstuff;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate hyper;
extern crate hyper_rustls;
extern crate serde;
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
    if name.starts_with ("mm2::crash_reports::stack_trace") {return}

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
