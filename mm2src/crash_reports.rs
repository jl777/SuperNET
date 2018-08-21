use backtrace;
#[cfg(unix)] use std::os::raw::c_int;
use std::cell::UnsafeCell;
use std::env;
#[allow(unused_imports)] use std::io::stderr;
use std::io::Write;
use std::mem::{uninitialized};
#[allow(unused_imports)] use std::process::abort;
use std::sync::Once;
#[allow(unused_imports)] use std::sync::Mutex;

#[cfg(test)] #[cfg(windows)] type StackTrace = String;
/// https://docs.microsoft.com/en-us/windows/desktop/debug/getexceptioncode
#[cfg(test)] #[cfg(windows)] type ExceptionCode = u32;
#[cfg(test)] #[cfg(windows)] lazy_static! {
    /// The testing version of `rust_seh_handler` is rigged to put the captured stack trace here.
    static ref SEH_CAUGHT: Mutex<Option<(ExceptionCode, StackTrace)>> = Mutex::new (None);
    /// Used to avoid the empty `SEH_CAUGHT` races.
    static ref SEH_LOCK: Mutex<()> = Mutex::new(());
}

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
fn trace_name_buf() -> &'static mut [u8; 128] {
    //static mut TRACE_NAME_BUF: [u8; 128] = unsafe {uninitialized()};
    lazy_static! {static ref TRACE_NAME_BUF: NotThreadSafe<[u8; 128]> = NotThreadSafe (UnsafeCell::new (unsafe {uninitialized()}));}
    unsafe {&mut *TRACE_NAME_BUF.0.get()}
}

fn stack_trace_frame (buf: &mut Write, symbol: &backtrace::Symbol) {
    let filename = match symbol.filename() {Some (path) => path, None => return};
    let filename = match filename.components().rev().next() {Some (c) => c.as_os_str().to_string_lossy(), None => return};
    let lineno = match symbol.lineno() {Some (lineno) => lineno, None => return};
    let name = match symbol.name() {Some (name) => name, None => return};
    let name_buf = trace_name_buf();
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
    if name == "__scrt_common_main_seh" {return}  // Super-main on Windows.
    if name.starts_with ("mm2::crash_reports::stack_trace") {return}

    let _ = writeln! (buf, "  {}:{}] {}", filename, lineno, name);
}

/// Generates a string with the current stack trace.
/// 
/// * `format` - Generates the string representation of a frame.
/// * `output` - Function used to print the stack trace.
///              Printing immediately, without buffering, should make the tracing somewhat more reliable.
fn stack_trace (format: &mut FnMut (&mut Write, &backtrace::Symbol), output: &mut FnMut (&str)) {
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

#[cfg(windows)]
#[cfg(test)]
#[no_mangle]
pub extern fn rust_seh_handler (exception_code: ExceptionCode) {
    let mut seh_caught = unwrap! (SEH_CAUGHT.lock(), "!SEH_CAUGHT");
    let mut trace = String::with_capacity (4096);
    stack_trace (&mut stack_trace_frame, &mut |l| trace.push_str (l));
    *seh_caught = Some ((exception_code, trace));
}

/// Performs a crash report and aborts.
#[cfg(windows)]
#[cfg(not(test))]
#[no_mangle]
pub extern fn rust_seh_handler (exception_code: u32) {
    use winapi::um::minwinbase::EXCEPTION_ACCESS_VIOLATION;

    let exception_name = match exception_code {
        EXCEPTION_ACCESS_VIOLATION => "Access Violation",
        0xE06D7363 => "VC++ Exception",  // https://blogs.msdn.microsoft.com/oldnewthing/20100730-00/?p=13273
        _ => ""
    };

    eprintln! ("SEH caught! ExceptionCode: {} ({}).", exception_code, exception_name);
    stack_trace (&mut stack_trace_frame, &mut |trace| {
        let stderr = stderr();
        let mut stderr = stderr.lock();
        let _ = stderr.write_all (trace.as_bytes());
        let _ = stderr.flush();
    });
    abort()
}

#[cfg(windows)]
#[cfg(test)]
extern "C" {fn c_access_violation();}

#[cfg(windows)]
#[cfg(test)]
extern fn call_access_violation() {access_violation()}

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
    use winapi::um::minwinbase::EXCEPTION_ACCESS_VIOLATION;

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

#[cfg(unix)]
extern fn signal_handler (sig: c_int) {
    {
        // NB: Manually writing to `stderr` is more reliable than using `eprintln!`, especially around `dup2`.
        let stderr = stderr();
        let mut stderr = stderr.lock();
        let _ = writeln! (&mut stderr, "Signal caught! sig {}", sig);
        let _ = stderr.flush();
    }

    stack_trace (&mut stack_trace_frame, &mut |trace| {
        let stderr = stderr();
        let mut stderr = stderr.lock();
        let _ = stderr.write_all (trace.as_bytes());
        // Explicitly flush the output stream. Under at least the Docker/Linux the tail is sometimes lost on `abort`.
        let _ = stderr.flush();
    });
    abort();
}

#[cfg(unix)]
fn init_signal_handling() {
    use nix::sys::signal::{sigaction, SaFlags, Signal, SigAction, SigHandler, SigSet};

    lazy_static! {
        static ref ACTION: SigAction = SigAction::new (
            SigHandler::Handler (signal_handler),
            SaFlags::empty(),
            SigSet::empty()
        );
    }

    for signal in [Signal::SIGILL, Signal::SIGFPE, Signal::SIGSEGV, Signal::SIGBUS, Signal::SIGSYS].iter() {
        unsafe {unwrap! (sigaction (*signal, &*ACTION), "!sigaction");}
    }
}

#[cfg(not(unix))]
fn init_signal_handling() {}

/// Check that access violation stack traces are being reported to stderr under macOS and Linux.
/// 
/// Unix signal handling should work NP with threading. Not testing it here though,
/// since Rust threading might not work just as well with forking. If such test is needed in the future,
/// it should be a separate unit test and maybe with a different non-forking design.
#[cfg(unix)]
#[test]
fn test_signal_handling() {
    use nix::unistd::{dup2, fork, ForkResult};
    use nix::sys::wait::waitpid;
    use std::env::temp_dir;
    use std::fs;
    use std::io::Read;
    use std::os::unix::io::AsRawFd;

    init_signal_handling();

    let stderr_tmp_path = temp_dir().join ("test_signal_handling.stderr");
    let _ = fs::remove_file (&stderr_tmp_path);
    let stderr_tmp_file = unwrap! (fs::File::create (&stderr_tmp_path));
    let stderr_tmp_fd = stderr_tmp_file.as_raw_fd();

    let stderr_fd = stderr().as_raw_fd();

    if let ForkResult::Parent {child} = unwrap! (fork()) {
        println! ("Forked, child PID is {}, waiting for the child to exit...", child);
        let wait_status = unwrap! (waitpid (child, None));
        println! ("wait_status: {:?}", wait_status);
        let mut stderr = String::new();
        let mut stderr_tmp_file = unwrap! (fs::File::open (&stderr_tmp_path));
        unwrap! (stderr_tmp_file.read_to_string (&mut stderr));
        println! ("Obtained stderr is: ---\n{}", stderr);
        unwrap! (fs::remove_file (&stderr_tmp_path));
        assert! (stderr.contains ("This should go to the temporary file"));
        assert! (stderr.contains ("Signal caught!"));
        assert! (stderr.contains ("mm2::crash_reports::access_violation"));
    } else {
        println! ("Hi from the child. Redirecting stderr to {:?}.", &stderr_tmp_path);
        unwrap! (dup2 (stderr_tmp_fd, stderr_fd));
        {
            let stderr = stderr();
            let mut stderr = stderr.lock();
            unwrap! (writeln! (&mut stderr, "This should go to the temporary file."));
            unwrap! (stderr.flush());
        }
        access_violation();
    }
}

/// Setup the crash handlers.
pub fn init_crash_reports() {
    static ONCE: Once = Once::new();
    ONCE.call_once (|| {
        // Try to invoke the `rust_seh_handler` whenever the C code crashes.
        if cfg! (windows) {
            extern "C" {fn init_veh();}
            unsafe {init_veh();}
        } else if cfg! (unix) {
            init_signal_handling()
        }

        // Log Rust panics.
        env::set_var ("RUST_BACKTRACE", "1")
    })
}

/// Check that access violations are handled in a spawned thread.
#[cfg(windows)]  // We always `abort` on UNIX, even in tests, so this particular test won't work on UNIX.
#[test]
fn test_crash_reports_mt() {
    use std::thread;
    init_crash_reports();
    let _seh_lock = unwrap! (SEH_LOCK.lock());

    *unwrap! (SEH_CAUGHT.lock(), "!SEH_CAUGHT") = None;
    unwrap! (thread::spawn (|| {
        access_violation()
    }) .join(), "!join");
    let seh = unwrap! (unwrap! (SEH_CAUGHT.lock(), "!SEH_CAUGHT") .take(), "!trace");
    println! ("ExceptionCode: {}\n{}", seh.0, seh.1);
    assert! (seh.1.contains ("mm2::crash_reports::access_violation"));
}
