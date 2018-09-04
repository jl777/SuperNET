use helpers::{self, stack_trace, stack_trace_frame};
#[cfg(unix)] use std::os::raw::c_int;
use std::env;
#[allow(unused_imports)] use std::io::stderr;
#[allow(unused_imports)] use std::io::Write;
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
    use winapi::um::minwinbase::{EXCEPTION_ACCESS_VIOLATION, EXCEPTION_ILLEGAL_INSTRUCTION};

    let exception_name = match exception_code {
        EXCEPTION_ACCESS_VIOLATION => "Access Violation",
        EXCEPTION_ILLEGAL_INSTRUCTION => "Illegal Instruction",
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
        helpers::init();

        // Try to invoke the `rust_seh_handler` whenever the C code crashes.
        if cfg! (windows) {
            extern "C" {fn init_veh();}
            unsafe {init_veh();}
        } else if cfg! (unix) {
            init_signal_handling()
        }

        // Log Rust panics.
        env::set_var ("RUST_BACKTRACE", "1")
        // ^^ NB: In the future this might also affect the normal errors, cf. https://github.com/rust-lang/rfcs/blob/master/text/2504-fix-error.md.
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
