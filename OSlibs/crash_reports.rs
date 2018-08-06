use backtrace;
#[cfg(test)] use std::sync::Mutex;
#[cfg(test)] use winapi::um::minwinbase::EXCEPTION_ACCESS_VIOLATION;

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
    if name.starts_with ("mm2::crash_reports::") {return}

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
pub extern fn rust_seh_handler (_exception_code: i32) {
    println! ("SEH caught!\n");
}

#[cfg(windows)]
#[cfg(test)]
extern "C" {
    fn with_seh (cb: extern fn()->());
    fn c_access_violation();
}

#[cfg(windows)]
#[cfg(test)]
#[inline(never)]
extern fn access_violation() {
    let ptr: *mut i32 = 0 as *mut i32;
    unsafe {*ptr = 123};
}

#[cfg(windows)]
#[cfg(test)]
#[inline(never)]
extern fn call_c_access_violation() {
    unsafe {c_access_violation()}
}

#[cfg(windows)]
#[test]
fn test_seh_handler() {
    *SEH_CAUGHT.lock().expect("!SEH_CAUGHT") = None;
    unsafe {with_seh (access_violation)};
    let seh = SEH_CAUGHT.lock().expect("!SEH_CAUGHT").take().expect("!trace");
    println! ("ExceptionCode: {}\n{}", seh.0, seh.1);
    assert_eq! (seh.0, EXCEPTION_ACCESS_VIOLATION);
    assert! (seh.1.contains ("with_seh"));
    // SEH handler is executed by Windows after unwinding, we won't see past the `with_seh`.
    assert! (!seh.1.contains ("access_violation"));

    unsafe {with_seh (call_c_access_violation)};
    let seh = SEH_CAUGHT.lock().expect("!SEH_CAUGHT").take().expect("!trace");
    println! ("ExceptionCode: {}\n{}", seh.0, seh.1);
    assert! (seh.1.contains ("with_seh"));
    // SEH handler is executed by Windows after unwinding, we won't see past the `with_seh`.
    assert! (!seh.1.contains ("c_access_violation"));
}
