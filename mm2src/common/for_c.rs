use libc::c_char;
use std::sync::Mutex;
use std::ffi::CStr;

lazy_static! {
    pub static ref PEERS_CLOCK_TICK_COMPAT: Mutex<Option<fn (u32, i32)>> = Mutex::new (None);
    pub static ref PEERS_SEND_COMPAT: Mutex<Option<fn (u32, i32, *const u8, i32) -> i32>> = Mutex::new (None);
    pub static ref PEERS_RECV_COMPAT: Mutex<Option<fn (u32, i32, *mut *mut u8) -> i32>> = Mutex::new (None);
}

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

/// cf. `peers::peers_clock_tick_compat`.
#[no_mangle]
pub extern fn peers_clock_tick_compat (ctx: u32, sock: i32) {
    let fun = unwrap! (unwrap! (PEERS_CLOCK_TICK_COMPAT.lock()) .ok_or ("!PEERS_CLOCK_TICK_COMPAT"));
    fun (ctx, sock)
}

/// cf. `peers::peers_send_compat`.
#[no_mangle]
pub extern fn peers_send_compat (ctx: u32, sock: i32, data: *const u8, datalen: i32) -> i32 {
    let fun = unwrap! (unwrap! (PEERS_SEND_COMPAT.lock()) .ok_or ("!PEERS_SEND_COMPAT"));
    fun (ctx, sock, data, datalen)
}

/// cf. `peers::peers_recv_compact`.
#[no_mangle]
pub extern fn peers_recv_compat (ctx: u32, sock: i32, data: *mut *mut u8) -> i32 {
    let fun = unwrap! (unwrap! (PEERS_RECV_COMPAT.lock()) .ok_or ("!PEERS_RECV_COMPAT"));
    fun (ctx, sock, data)
}
