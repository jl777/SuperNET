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

use libc::malloc;
use std::cell::UnsafeCell;
use std::mem::uninitialized;
use std::os::raw::c_char;
use std::intrinsics::copy;
use std::io::Write;

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

struct NotThreadSafe<T> (UnsafeCell<T>);
unsafe impl<T> Sync for NotThreadSafe<T> {}

/// Using a static buffer in order to minimize the chance of heap and stack allocations in the signal handler.
/// NB: Not thread-safe, but we're only running a single signal handler at a time.
fn trace_buf() -> &'static mut [u8; 256] {
    // We're on stable and don't have `const fn`s yet, so resort to dynamic allocation instead.
    lazy_static! {static ref TRACE_BUF: NotThreadSafe<[u8; 256]> = NotThreadSafe (UnsafeCell::new (unsafe {uninitialized()}));}
    unsafe {&mut *TRACE_BUF.0.get()}

    // In the future (when `const fn`s are made stable) I'd like to replace this with a fully static buffer:

    // https://github.com/rust-lang/rfcs/issues/411#issuecomment-367704087
    // Waiting for https://github.com/rust-lang/rust/issues/24111
    //unsafe const fn uninitialized<T>() -> T {Foo {u: ()} .t}

    //static mut TRACE_BUF: [u8; 256] = unsafe {uninitialized()};
}

/// Generates a string with the current stack trace.
/// 
/// * `format` - Generates the string representation of a frame.
/// * `output` - Function used to print the stack trace.
///              Printing immediately, without buffering, should make the tracing somewhat more reliable.
pub fn stack_trace (format: &mut FnMut (&mut Write, &backtrace::Symbol), output: &mut FnMut (&str)) {
    backtrace::trace (|frame| {
        backtrace::resolve (frame.ip(), |symbol| {
            let trace_buf = trace_buf();
            let trace = gstring! (trace_buf, {
              format (trace_buf, symbol);
            });
            output (trace);
        });
        true
    });
}
