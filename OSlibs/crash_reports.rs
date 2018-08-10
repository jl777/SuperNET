use backtrace;
use std::env;
#[cfg(not(test))] use std::process::abort;
use std::sync::Once;
#[cfg(test)] use std::sync::Mutex;
#[cfg(test)] #[cfg(windows)] use winapi::um::minwinbase::EXCEPTION_ACCESS_VIOLATION;

type StackTrace = String;
/// https://docs.microsoft.com/en-us/windows/desktop/debug/getexceptioncode
#[cfg(test)] type ExceptionCode = u32;
#[cfg(test)] lazy_static! {
    /// The testing version of `rust_seh_handler` is rigged to put the captured stack trace here.
    static ref SEH_CAUGHT: Mutex<Option<(ExceptionCode, StackTrace)>> = Mutex::new (None);
    /// Used to avoid the empty `SEH_CAUGHT` races.
    static ref SEH_LOCK: Mutex<()> = Mutex::new(());
}

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
    if name == "__scrt_common_main_seh" {return}  // Super-main on Windows.
    if name.starts_with ("mm2::crash_reports::stack_trace") {return}

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
    let mut seh_caught = unwrap! (SEH_CAUGHT.lock(), "!SEH_CAUGHT");
    *seh_caught = Some ((exception_code, stack_trace(&mut stack_trace_frame)));
}

/// Performs a crash report and aborts.
#[cfg(not(test))]
#[no_mangle]
pub extern fn rust_seh_handler (exception_code: u32) {
    println! ("SEH caught! ExceptionCode: {}.", exception_code);
    let trace = stack_trace(&mut stack_trace_frame);
    println! ("Stack trace:\n{}", trace);
    abort()
}

#[cfg(windows)]
#[cfg(test)]
extern "C" {fn c_access_violation();}

#[cfg(windows)]
#[cfg(test)]
extern fn call_access_violation() {access_violation()}

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
extern fn call_c_access_violation() {unsafe {c_access_violation()}}

#[cfg(windows)]
#[test]
fn test_seh_handler() {
    init_crash_reports();
    let _seh_lock = unwrap! (SEH_LOCK.lock());

    *unwrap! (SEH_CAUGHT.lock(), "!SEH_CAUGHT") = None;
    call_access_violation();
    let seh = unwrap! (unwrap! (SEH_CAUGHT.lock(), "!SEH_CAUGHT") .take(), "!trace");
    println! ("ExceptionCode: {}\n{}", seh.0, seh.1);
    assert_eq! (seh.0, EXCEPTION_ACCESS_VIOLATION);
    assert! (seh.1.contains ("mm2::crash_reports::call_access_violation"));
    assert! (seh.1.contains ("mm2::crash_reports::access_violation"));

    call_c_access_violation();
    let seh = unwrap! (unwrap! (SEH_CAUGHT.lock(), "!SEH_CAUGHT") .take(), "!trace");
    println! ("ExceptionCode: {}\n{}", seh.0, seh.1);
    assert! (seh.1.contains ("mm2::crash_reports::call_c_access_violation"));
    assert! (seh.1.contains ("c_access_violation"));
}

/// Setup the crash handlers.
pub fn init_crash_reports() {
    static ONCE: Once = Once::new();
    ONCE.call_once (|| {
        // Try to invoke the `rust_seh_handler` whenever the C code crashes.
        extern "C" {fn init_veh();}
        unsafe {init_veh();}

        // Log Rust panics.
        env::set_var ("RUST_BACKTRACE", "1")
    })
}

/// Check that access violations are handled in a spawned thread.
#[test]
fn test_crash_reports_mt() {
    use std::thread;
    init_crash_reports();
    let _seh_lock = unwrap! (SEH_LOCK.lock());

    *unwrap! (SEH_CAUGHT.lock(), "!SEH_CAUGHT") = None;
    unwrap! (thread::spawn (|| {
        call_c_access_violation()
    }) .join(), "!join");
    let seh = unwrap! (unwrap! (SEH_CAUGHT.lock(), "!SEH_CAUGHT") .take(), "!trace");
    println! ("ExceptionCode: {}\n{}", seh.0, seh.1);
    assert_eq! (seh.0, EXCEPTION_ACCESS_VIOLATION);
    assert! (seh.1.contains ("mm2::crash_reports::call_c_access_violation"));
}
