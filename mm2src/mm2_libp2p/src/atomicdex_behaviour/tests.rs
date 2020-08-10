use super::start_gossipsub;
use crate::atomicdex_behaviour::AdexBehaviorCmd;
use crate::request_response::PeerResponse;
use async_std::task::spawn;
use futures::channel::oneshot;
use futures::{Future, SinkExt, StreamExt};
use secp256k1::SecretKey;
use std::time::Duration;

fn spawn_boxed(fut: Box<dyn Future<Output = ()> + Send + Unpin + 'static>) { spawn(fut); }

struct Node {
    #[allow(dead_code)]
    secret: SecretKey,
}

impl Node {
    fn spawn(ip: String, port: u16, seednodes: Option<Vec<String>>, initiate: bool) -> Node {
        let my_address = ip.parse().unwrap();

        let mut rng = rand::thread_rng();
        let secret = SecretKey::random(&mut rng);
        let mut priv_key = secret.serialize();

        let (mut cmd_tx, _gossip_event_rx, mut request_rx, _my_peer_id) =
            start_gossipsub(my_address, port, spawn_boxed, seednodes, &mut priv_key);

        let cmd_tx_clone = cmd_tx.clone();
        // spawn a response future
        spawn(async move {
            // hold the cmd_tx clone to keep cmd channel opened if the `initiate` is false
            let _ = cmd_tx_clone.clone();
            loop {
                match request_rx.next().await {
                    Some((request, response_tx)) => {
                        assert_eq!(request.topic, "test:topic");
                        assert_eq!(request.req, b"test request");

                        assert_eq!(
                            response_tx.send(PeerResponse::Ok {
                                res: b"test response".to_vec()
                            }),
                            Ok(())
                        );
                    },
                    _ => {
                        println!("Finish response future");
                        break;
                    },
                }
            }
        });

        // check if the Node should initiate a PeerRequest
        if initiate {
            // spawn a request future
            spawn(async move {
                async_std::task::block_on(async { async_std::task::sleep(Duration::from_secs(3)).await });
                let req = b"test request".to_vec();
                let topic = "test:topic".to_string();
                let (response_tx, response_rx) = oneshot::channel();
                assert_eq!(
                    cmd_tx
                        .send(AdexBehaviorCmd::SendRequest {
                            req,
                            topic,
                            response_tx
                        })
                        .await,
                    Ok(())
                );

                let expected = PeerResponse::Ok {
                    res: b"test response".to_vec(),
                };
                let actual = response_rx.await;
                assert_eq!(actual, Ok(expected));
                println!("Finish request future");
            });
        }

        Node { secret }
    }
}

#[test]
fn test_request_response_ok() {
    std::env::set_var("RUST_LOG", "debug");
    // let _ = env_logger::try_init();
    let _ = env_logger::builder().is_test(true).try_init();

    let _node1 = Node::spawn("127.0.0.1".into(), 7783, None, false);
    let _node2 = Node::spawn(
        "127.0.0.1".into(),
        7784,
        Some(vec!["/ip4/127.0.0.1/tcp/7783".into()]),
        true,
    );

    async_std::task::block_on(async { async_std::task::sleep(Duration::from_secs(6)).await });
}
