use backtrace;
use std::mem::transmute;
#[cfg(not(test))] use std::process::abort;
#[cfg(test)] use std::sync::Mutex;

type StackTrace = String;
/// https://docs.microsoft.com/en-us/windows/desktop/debug/getexceptioncode
#[cfg(test)] type ExceptionCode = u32;
#[cfg(test)] lazy_static! {static ref SEH_CAUGHT: Mutex<Option<(ExceptionCode, StackTrace)>> = Mutex::new (None);}

#[allow(dead_code)]
fn stack_trace_frame (buf: &mut String, symbol: &backtrace::Symbol) {
    let filename = match symbol.filename() {Some (path) => path, None => return};
    let filename = match filename.components().rev().next() {Some (c) => c.as_os_str().to_string_lossy(), None => return};
    let lineno = match symbol.lineno() {Some (lineno) => lineno, None => return};
    let name = match symbol.name() {Some (name) => name, None => return};
    let name = format! ("{}", name);  // NB: `fmt` is different from `SymbolName::as_str`.

    // Skip common and less than informative frames.

    if name.starts_with ("backtrace::") {return}
    if name.starts_with ("core::") {return}
    if name.starts_with ("alloc::") {return}
    if name.starts_with ("panic_unwind::") {return}
    if name.starts_with ("std::") {return}
    if name == "mm2::crash_reports::rust_seh_handler" {return}
    if name == "mm2::crash_reports::under_seh" {return}
    if name == "mm2::crash_reports::with_crash_reports" {return}
    if name == "__scrt_common_main_seh" {return}  // Super-main on Windows.
    if name.starts_with ("mm2::crash_reports::stack_trace") {return}
    // seh.c
    if name == "ExpFilter" {return}
    if name == "with_seh$filt$0" {return}

    if !buf.is_empty() {buf.push ('\n')}
    use std::fmt::Write;
    let _ = write! (buf, "  {}:{}] {}", filename, lineno, name);
}

/// Generates a string with the current stack trace.
pub fn stack_trace (format: &mut FnMut (&mut String, &backtrace::Symbol)) -> StackTrace {
    let mut buf = String::with_capacity (128);

    backtrace::trace (|frame| {
        backtrace::resolve (frame.ip(), |symbol| format (&mut buf, symbol));
        true
    });

    buf
}

#[cfg(test)]
#[no_mangle]
pub extern fn rust_seh_handler (exception_code: ExceptionCode) {
    let mut seh_caught = SEH_CAUGHT.lock().expect("!SEH_CAUGHT");
    *seh_caught = Some ((exception_code, stack_trace(&mut stack_trace_frame)));
}

#[cfg(not(test))]
#[no_mangle]
pub extern fn rust_seh_handler (exception_code: u32) {
    println! ("SEH caught! ExceptionCode: {}.", exception_code);
    let trace = stack_trace(&mut stack_trace_frame);
    println! ("Stack trace:\n{}", trace);
    abort()
}

#[cfg(windows)]
extern "C" {fn with_seh (cb: extern fn (u64, u64) -> (), a1: u64, a2: u64);}

#[cfg(windows)]
#[cfg(test)]
extern "C" {fn c_access_violation (a1: u64, a2: u64);}

#[cfg(windows)]
#[cfg(test)]
extern fn call_access_violation (_a1: u64, _a2: u64) {access_violation()}

#[cfg(windows)]
#[cfg(test)]
#[inline(never)]
fn access_violation() {
    let ptr: *mut i32 = 0 as *mut i32;
    unsafe {*ptr = 123};
}

#[cfg(windows)]
#[cfg(test)]
#[inline(never)]
extern fn call_c_access_violation (a1: u64, a2: u64) {
    unsafe {c_access_violation (a1, a2)}
}

#[cfg(windows)]
#[test]
fn test_seh_handler() {
    use winapi::um::minwinbase::EXCEPTION_ACCESS_VIOLATION;

    *SEH_CAUGHT.lock().expect("!SEH_CAUGHT") = None;
    unsafe {with_seh (call_access_violation, 0, 0)};
    let seh = SEH_CAUGHT.lock().expect("!SEH_CAUGHT").take().expect("!trace");
    println! ("ExceptionCode: {}\n{}", seh.0, seh.1);
    assert_eq! (seh.0, EXCEPTION_ACCESS_VIOLATION);
    assert! (seh.1.contains ("with_seh"));
    assert! (seh.1.contains ("mm2::crash_reports::call_access_violation"));
    assert! (seh.1.contains ("mm2::crash_reports::access_violation"));

    unsafe {with_seh (call_c_access_violation, 0, 0)};
    let seh = SEH_CAUGHT.lock().expect("!SEH_CAUGHT").take().expect("!trace");
    println! ("ExceptionCode: {}\n{}", seh.0, seh.1);
    assert! (seh.1.contains ("with_seh"));
    assert! (seh.1.contains ("mm2::crash_reports::call_c_access_violation"));
    assert! (seh.1.contains ("c_access_violation"));
}

/// This is a piece of Rust code invoked under `with_seh` in order to invoke a Rust closure from there.
/// 
/// * `f` - points to the Rust closure that was passed to `with_crash_reports`.
#[cfg(windows)]
extern fn under_seh (a1: u64, a2: u64) {
    // Converting the two 64-bit integers back into the 128-bit fat closure pointer.
    let p2f: [u64; 2] = [a1, a2];
    let p2f: *const *mut FnMut() = unsafe {transmute (p2f.as_ptr())};
    let f: *mut FnMut() = unsafe {*p2f};
    let f: &mut FnMut() = unsafe {&mut *f};
    f()
}

/// Executes the given function withing a crash catching context,
/// turning panics and segmentation faults into stack trace crash reports.
pub fn with_crash_reports (f: &mut FnMut()) {
    use std::mem::size_of;
    if cfg! (windows) {
        // Converting the 128-bit fat closure pointer into the two 64-bit integers in order to harbor it through the FFI.
        assert_eq! (size_of::<*const FnMut()>(), 128 / 8);
        let f: *mut FnMut() = f;
        let p2f = &f as *const *mut FnMut();
        let p2f: *const u64 = unsafe {transmute (p2f)};
        unsafe {with_seh (under_seh, *p2f, *p2f.offset (1))}
    } else {
        f()
    }
}