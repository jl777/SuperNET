#![feature(non_ascii_idents)]
#![feature(drain_filter)]

#[macro_use] extern crate common;
#[allow(unused_imports)]
#[macro_use] extern crate duct;
#[macro_use] extern crate fomat_macros;
#[macro_use] extern crate gstuff;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serialization_derive;
#[macro_use] extern crate unwrap;

#[path = "mm2.rs"]
mod mm2;

#[no_mangle]
pub extern fn mm2_main() {
    mm2::mm2_main()
}

#[no_mangle]
pub extern fn mm2_test (torch: i32, log_cb: extern fn (line: *const c_char)) -> i32 {
    if let Ok (mut log_output) = LOG_OUTPUT.lock() {
        *log_output = Some (log_cb);
    } else {
        panic! ("Can't lock LOG_OUTPUT")
    }

    log! ("test_status…");
    common::log::tests::test_status();

    log! ("peers_dht…");
    peers::peers_tests::peers_dht();

    log! ("peers_direct_send…");
    peers::peers_tests::peers_direct_send();

    log! ("peers_http_fallback_kv…");
    peers::peers_tests::peers_http_fallback_kv();

    log! ("peers_http_fallback_recv…");
    peers::peers_tests::peers_http_fallback_recv();

    torch
}
