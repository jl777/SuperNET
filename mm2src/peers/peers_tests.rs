use common::bits256;
use common::for_tests::wait_for_log;
use common::mm_ctx::{MmArc, MmCtx};
use futures::Future;
use rand::{self, Rng};
use serde_json::Value as Json;
use std::mem::zeroed;
use std::net::{Ipv4Addr, SocketAddr};

fn peer (conf: Json, port: u16) -> MmArc {
    let ctx = MmCtx::new (conf, SocketAddr::new (Ipv4Addr::new (127, 0, 0, 1) .into(), 123));
    let mut rng = rand::thread_rng();

    let mut alice_key: bits256 = unsafe {zeroed()};
    unsafe {rng.fill (&mut alice_key.bytes[..])}
    unwrap! (super::initialize (&ctx, 9999, alice_key, port, 0));

    ctx
}

pub fn test_peers_dht() {
    let alice = peer (json! ({"dht": "on"}), 2111);
    let bob = peer (json! ({"dht": "on"}), 2112);

    unwrap! (wait_for_log (&alice.log, 33., &|en| en.contains ("[dht-boot] DHT bootstrap ... Done.")));
    unwrap! (wait_for_log (&bob.log, 33., &|en| en.contains ("[dht-boot] DHT bootstrap ... Done.")));

    let tested_lengths: &[usize] = if option_env! ("TEST_MAX_LENGTH") == Some ("true") {
        &[992 /* (1000 - bencode overhead - checksum) */ * 253 /* Compatible with (1u8..) */ - 1 /* space for number_of_chunks */]
    } else {
        &[16 * 1024, 1]
    };
    let mut rng = rand::thread_rng();
    for message_len in tested_lengths.iter() {
        // Send a message to Bob.

        let message: Vec<u8> = (0..*message_len).map (|_| rng.gen()) .collect();

        println! ("Sending {} bytes …", message.len());
        let _sending_f = super::send (&alice, unwrap! (super::key (&bob)), b"test_dht", message.clone());

        // Get that message from Alice.

        let receiving_f = super::recv (&bob, b"test_dht", Box::new ({
            let message = message.clone();
            move |payload| payload == &message[..]
        }));
        let received = unwrap! (receiving_f.wait());
        assert_eq! (received, message);
    }

    // WIP, direct UDP communication (triggered by `send`).
    unwrap! (wait_for_log (&alice.log, 12., &|en| en.contains ("[dht] Direct packet received!")));
}

pub fn test_peers_direct_send() {
    let alice = peer (json! ({"dht": "on"}), 2121);
    let bob = peer (json! ({"dht": "on"}), 2122);

    let bob_key = unwrap! (super::key (&bob));

    // Bob isn't a friend yet.
    let alice_pctx = unwrap! (super::PeersContext::from_ctx (&alice));
    assert! (!unwrap! (alice_pctx.friends.lock()) .contains_key (&bob_key));

    let _sending_f = super::send (&alice, bob_key, b"subj", Vec::from (&b"foobar"[..]));

    // Confirm that Bob was added into the friendlist and that we don't know its address yet.
    assert! (unwrap! (alice_pctx.friends.lock()) .contains_key (&bob_key));

    // Hint at the Bob's endpoint.
    //investigate_peer ();

    // Confirm that Bob now has the address.

    // And see if Bob received the message.
}
