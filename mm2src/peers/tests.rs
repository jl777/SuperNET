use common::bits256;
use common::mm_ctx::MmCtx;
use std::mem::zeroed;
use std::net::{Ipv4Addr, SocketAddr};

pub fn test_dht() {
    if 1 == 1 {return}

    // TODO: Create the Alice and Bob contexts.

    let alice = MmCtx::new (json! ({}), SocketAddr::new (Ipv4Addr::new (127, 0, 0, 1) .into(), 123));

    let _bob = MmCtx::new (json! ({}), SocketAddr::new (Ipv4Addr::new (127, 0, 0, 1) .into(), 123));

    // TODO: Initialize the DHT on both, using different preferred ports.

    // TODO: Send a message to Bob.

    let bob_id: bits256 = unsafe {zeroed()};  // XXX
    unwrap! (::send (&alice, bob_id, &"qwe"));

    // TODO: Get a message from Alice.

}
