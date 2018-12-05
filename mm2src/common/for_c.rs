use libc::c_char;
use std::ffi::CStr;

// Example of a function forward:
//lazy_static! {pub static ref PEERS_SEND_COMPAT: Mutex<Option<fn (u32, i32, *const u8, i32) -> i32>> = Mutex::new (None);}

#[no_mangle]
pub extern fn log_stacktrace (desc: *const c_char) {
    let desc = if desc.is_null() {
        ""
    } else {
        match unsafe {CStr::from_ptr (desc)} .to_str() {
            Ok (s) => s,
            Err (err) => {
                log! ({"log_stacktrace] Bad trace description: {}", err});
                ""
            }
        }
    };
    let mut trace = String::with_capacity (4096);
    ::stack_trace (&mut ::stack_trace_frame, &mut |l| trace.push_str (l));
    log! ({"Stacktrace. {}\n{}", desc, trace});
}
