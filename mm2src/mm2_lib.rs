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

    // NB: We have to catch the panic because the error isn't logged otherwise.
    // (In the release mode the `ud2` op will trigger a crash or debugger on panic
    // but we don't have debugging symbols in the Rust code then).
    let rc = catch_unwind (|| {
        log! ("mm2_test] test_status…");
        common::log::tests::test_status();

        log! ("mm2_test] peers_dht…");
        peers::peers_tests::peers_dht();

        log! ("mm2_test] peers_direct_send…");
        peers::peers_tests::peers_direct_send();

        log! ("mm2_test] peers_http_fallback_kv…");
        peers::peers_tests::peers_http_fallback_kv();

        log! ("mm2_test] peers_http_fallback_recv…");
        peers::peers_tests::peers_http_fallback_recv();
    });
    if let Err (err) = rc {
        log! ("mm2_test] There was an error: " (any_to_str (&*err) .unwrap_or ("-")));
        -1
    } else {
        log! ("mm2_test] All done, passing the torch.");
        torch
    }
}
