use common::bits256;
use common::for_tests::wait_for_log;
use common::mm_ctx::MmCtx;
use std::mem::zeroed;
use std::net::{Ipv4Addr, SocketAddr};

pub fn test_dht() {
    // TODO: Create the Alice and Bob contexts.

    let alice = MmCtx::new (json! ({}), SocketAddr::new (Ipv4Addr::new (127, 0, 0, 1) .into(), 123));

    let _bob = MmCtx::new (json! ({}), SocketAddr::new (Ipv4Addr::new (127, 0, 0, 1) .into(), 123));

    // TODO: Initialize the DHT on both, using different preferred ports.

    let mut alice_key: bits256 = unsafe {zeroed()};
    unsafe {alice_key.bytes[0] = 1}
    unwrap! (::initialize (&alice, 9999, alice_key, 2111, 0));
    unwrap! (wait_for_log (&alice.log, 33., &|en| en.contains ("[dht-boot] DHT bootstrapping ... Done.")));

    // TODO: Send a message to Bob.

    //let bob_id: bits256 = unsafe {zeroed()};  // XXX
    //unwrap! (::send (&alice, bob_id, &"qwe"));

    // TODO: Get a message from Alice.

}
