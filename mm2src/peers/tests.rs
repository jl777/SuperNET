use common::bits256;
use common::for_tests::wait_for_log;
use common::mm_ctx::MmCtx;
use std::mem::zeroed;
use std::net::{Ipv4Addr, SocketAddr};

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

    // TODO: Send a message to Bob.

    //unwrap! (::send (&alice, bob_key, &"test"));

    // TODO: Get a message from Alice.

}
