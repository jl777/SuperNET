use common::bits256;
use common::for_tests::wait_for_log;
use common::mm_ctx::MmCtx;
use futures::Future;
use rand::{self, Rng};
use std::mem::zeroed;
use std::net::{Ipv4Addr, SocketAddr};

pub fn test_dht() {
    // Create the Alice and Bob contexts.

    let alice = MmCtx::new (json! ({}), SocketAddr::new (Ipv4Addr::new (127, 0, 0, 1) .into(), 123));

    let bob = MmCtx::new (json! ({}), SocketAddr::new (Ipv4Addr::new (127, 0, 0, 1) .into(), 123));

    let mut rng = rand::thread_rng();

    // Initialize the DHT on both, using different preferred ports.

    let mut alice_key: bits256 = unsafe {zeroed()};
    unsafe {rng.fill (&mut alice_key.bytes[..])}
    unwrap! (::initialize (&alice, 9999, alice_key, 2111, 0));

    let mut bob_key: bits256 = unsafe {zeroed()};
    unsafe {rng.fill (&mut bob_key.bytes[..])}
    unwrap! (::initialize (&bob, 9999, bob_key, 2112, 0));

    unwrap! (wait_for_log (&alice.log, 33., &|en| en.contains ("[dht-boot] DHT bootstrap ... Done.")));
    unwrap! (wait_for_log (&bob.log, 33., &|en| en.contains ("[dht-boot] DHT bootstrap ... Done.")));

    let tested_lengths: &[usize] = if option_env! ("TEST_MAX_LENGTH") == Some ("true") {
        &[992 /* (1000 - bencode overhead - checksum) */ * 253 /* Compatible with (1u8..) */ - 1 /* space for number_of_chunks */]
    } else {
        &[16 * 1024, 1]
    };
    for message_len in tested_lengths.iter() {
        // Send a message to Bob.

        let message: Vec<u8> = (0..*message_len).map (|_| rng.gen()) .collect();

        println! ("Sending {} bytes …", message.len());
        let _sending_f = ::send (&alice, bob_key, b"test_dht", message.clone());

        // Get that message from Alice.

        let receiving_f = ::recv (&bob, b"test_dht", Box::new ({
            let message = message.clone();
            move |payload| payload == &message[..]
        }));
        let received = unwrap! (receiving_f.wait());
        assert_eq! (received, message);
    }
}
