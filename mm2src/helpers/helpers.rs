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
#[macro_use]
extern crate gstuff;
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate unwrap;

use libc::malloc;
use std::intrinsics::copy;
use std::io::Write;
use std::mem::{forget, uninitialized};
use std::ptr::read_volatile;
use std::os::raw::{c_char};
use std::sync::{Mutex, MutexGuard};

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

/// Initialize the crate.
pub fn init() {
    // Pre-allocate the stack trace buffer in order to avoid allocating it from a signal handler.
    black_box (&*trace_buf());
    black_box (&*trace_name_buf());
}
