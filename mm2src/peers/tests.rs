use common::bits256;
use common::for_tests::wait_for_log;
use common::mm_ctx::MmCtx;
use gstuff::now_float;
use std::mem::zeroed;
use std::net::{Ipv4Addr, SocketAddr};
use std::ptr::null_mut;
use std::slice::from_raw_parts;
use std::thread;
use std::time::Duration;

pub fn test_dht() {
    // Create the Alice and Bob contexts.

    let alice = MmCtx::new (json! ({}), SocketAddr::new (Ipv4Addr::new (127, 0, 0, 1) .into(), 123));

    let bob = MmCtx::new (json! ({}), SocketAddr::new (Ipv4Addr::new (127, 0, 0, 1) .into(), 123));

    // Initialize the DHT on both, using different preferred ports.

    let mut alice_key: bits256 = unsafe {zeroed()};
    unsafe {alice_key.bytes[0] = 1}
    unwrap! (::initialize (&alice, 9999, alice_key, 2111, 0));

    let mut bob_key: bits256 = unsafe {zeroed()};
    unsafe {bob_key.bytes[0] = 2}
    unwrap! (::initialize (&bob, 9999, bob_key, 2112, 0));

    unwrap! (wait_for_log (&alice.log, 33., &|en| en.contains ("[dht-boot] DHT bootstrap ... Done.")));
    unwrap! (wait_for_log (&bob.log, 33., &|en| en.contains ("[dht-boot] DHT bootstrap ... Done.")));

    // Send a message to Bob.

    unwrap! (::bind (&alice, 1, bob_key));
    let alice_ctx = unwrap! (alice.ffi_handle());
    ::peers_clock_tick_compat (alice_ctx, 1);
    ::peers_send_compat (alice_ctx, 1, b"foobar".as_ptr(), 6);

    // TODO: Get a message from Alice.

    return;

    unwrap! (::bind (&bob, 1, alice_key));
    let bob_ctx = unwrap! (bob.ffi_handle());
    ::peers_clock_tick_compat (bob_ctx, 1);
    let started_at = now_float();
    loop {
        let mut data: *mut u8 = null_mut();
        let rc = ::peers_recv_compat (bob_ctx, 1, &mut data);
        if rc < 0 {panic! ("peers_recv_compat error: {}", rc)}
        if rc > 0 {
            let payload = unsafe {from_raw_parts (data, rc as usize)};
            assert_eq! (payload, b"foobar");
        }
        if now_float() - started_at > 120.0 {panic! ("Out of time waiting for DHT payload")}
        thread::sleep (Duration::from_millis (20));
    }
}
