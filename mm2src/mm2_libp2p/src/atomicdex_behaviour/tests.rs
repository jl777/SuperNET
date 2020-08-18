use super::start_gossipsub;
use crate::atomicdex_behaviour::{AdexBehaviorCmd, AdexBehaviourEvent, AdexResponse};
use async_std::task::{block_on, spawn};
use futures::channel::{mpsc, oneshot};
use futures::{Future, SinkExt, StreamExt};
use secp256k1::SecretKey;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn spawn_boxed(fut: Box<dyn Future<Output = ()> + Send + Unpin + 'static>) { spawn(fut); }

struct Node {
    #[allow(dead_code)]
    secret: SecretKey,
    cmd_tx: mpsc::UnboundedSender<AdexBehaviorCmd>,
}

impl Node {
    fn spawn<F>(ip: String, port: u16, seednodes: Option<Vec<String>>, on_event: F) -> Node
    where
        F: Fn(mpsc::UnboundedSender<AdexBehaviorCmd>, AdexBehaviourEvent) + Send + 'static,
    {
        let my_address = ip.parse().unwrap();

        let mut rng = rand::thread_rng();
        let secret = SecretKey::random(&mut rng);
        let mut priv_key = secret.serialize();

        let (cmd_tx, mut event_rx, _my_peer_id) =
            start_gossipsub(my_address, port, spawn_boxed, seednodes, &mut priv_key, true);

        // spawn a response future
        let cmd_tx_fut = cmd_tx.clone();
        spawn(async move {
            loop {
                let cmd_tx_fut = cmd_tx_fut.clone();
                match event_rx.next().await {
                    Some(r) => on_event(cmd_tx_fut, r),
                    _ => {
                        println!("Finish response future");
                        break;
                    },
                }
            }
        });

        Node { secret, cmd_tx }
    }

    async fn send_cmd(&mut self, cmd: AdexBehaviorCmd) { self.cmd_tx.send(cmd).await.unwrap(); }

    async fn wait_peers(&mut self, number: usize) {
        loop {
            let (tx, rx) = oneshot::channel();
            self.cmd_tx
                .send(AdexBehaviorCmd::GetPeersInfo { result_tx: tx })
                .await
                .unwrap();
            match rx.await {
                Ok(map) => {
                    if map.len() >= number {
                        return;
                    }
                    async_std::task::sleep(Duration::from_millis(500)).await;
                },
                Err(e) => panic!("{}", e),
            }
        }
    }
}

#[test]
fn test_request_response_ok() {
    let _ = env_logger::try_init();

    let request_received = Arc::new(AtomicBool::new(false));
    let request_received_cpy = request_received.clone();
    let _node1 = Node::spawn("127.0.0.1".into(), 57783, None, move |cmd_tx, event| {
        let (request, response_channel) = match event {
            AdexBehaviourEvent::PeerRequest {
                request,
                response_channel,
                ..
            } => (request, response_channel),
            _ => return,
        };

        request_received_cpy.store(true, Ordering::Relaxed);
        assert_eq!(request, b"test request");

        let res = AdexResponse::Ok {
            response: b"test response".to_vec(),
        };
        cmd_tx
            .unbounded_send(AdexBehaviorCmd::SendResponse { res, response_channel })
            .unwrap();
    });

    let mut node2 = Node::spawn(
        "127.0.0.1".into(),
        57784,
        Some(vec!["/ip4/127.0.0.1/tcp/57783".into()]),
        |_, _| (),
    );

    block_on(async { node2.wait_peers(1).await });

    let (response_tx, response_rx) = oneshot::channel();
    block_on(async move {
        node2
            .send_cmd(AdexBehaviorCmd::RequestAnyPeer {
                req: b"test request".to_vec(),
                response_tx,
            })
            .await;

        let res = response_rx.await;
        assert_eq!(
            res,
            Ok(AdexResponse::Ok {
                response: b"test response".to_vec()
            })
        );
    });

    assert!(request_received.load(Ordering::Relaxed));
}

#[test]
fn test_request_response_ok_three_peers() {
    let _ = env_logger::try_init();

    #[derive(Default)]
    struct RequestHandler {
        requests: u8,
    }

    impl RequestHandler {
        fn handle(&mut self, cmd_tx: mpsc::UnboundedSender<AdexBehaviorCmd>, event: AdexBehaviourEvent) {
            let (request, response_channel) = match event {
                AdexBehaviourEvent::PeerRequest {
                    request,
                    response_channel,
                    ..
                } => (request, response_channel),
                _ => return,
            };

            self.requests += 1;

            assert_eq!(request, b"test request");

            // the first time we should respond the none
            if self.requests == 1 {
                let res = AdexResponse::None;
                cmd_tx
                    .unbounded_send(AdexBehaviorCmd::SendResponse { res, response_channel })
                    .unwrap();
                return;
            }

            // the second time we should respond an error
            if self.requests == 2 {
                let res = AdexResponse::Err {
                    error: "test error".into(),
                };
                cmd_tx
                    .unbounded_send(AdexBehaviorCmd::SendResponse { res, response_channel })
                    .unwrap();
                return;
            }

            // the third time we should respond an ok
            if self.requests == 3 {
                let res = AdexResponse::Ok {
                    response: format!("success {} request", self.requests).as_bytes().to_vec(),
                };
                cmd_tx
                    .unbounded_send(AdexBehaviorCmd::SendResponse { res, response_channel })
                    .unwrap();
                return;
            }

            panic!("Request received more than 3 times");
        }
    }

    let request_handler = Arc::new(Mutex::new(RequestHandler::default()));

    let handler = request_handler.clone();
    let _receiver1 = Node::spawn("127.0.0.1".into(), 57790, None, move |cmd_tx, event| {
        let mut handler = handler.lock().unwrap();
        handler.handle(cmd_tx, event)
    });

    let handler = request_handler.clone();
    let _receiver2 = Node::spawn("127.0.0.1".into(), 57791, None, move |cmd_tx, event| {
        let mut handler = handler.lock().unwrap();
        handler.handle(cmd_tx, event)
    });

    let handler = request_handler.clone();
    let _receiver3 = Node::spawn("127.0.0.1".into(), 57792, None, move |cmd_tx, event| {
        let mut handler = handler.lock().unwrap();
        handler.handle(cmd_tx, event)
    });

    let mut sender = Node::spawn(
        "127.0.0.1".into(),
        57784,
        Some(vec![
            "/ip4/127.0.0.1/tcp/57790".into(),
            "/ip4/127.0.0.1/tcp/57791".into(),
            "/ip4/127.0.0.1/tcp/57792".into(),
        ]),
        |_, _| (),
    );

    block_on(async { sender.wait_peers(3).await });

    let (response_tx, response_rx) = oneshot::channel();
    block_on(async move {
        sender
            .send_cmd(AdexBehaviorCmd::RequestAnyPeer {
                req: b"test request".to_vec(),
                response_tx,
            })
            .await;

        let res = response_rx.await;
        assert_eq!(
            res,
            Ok(AdexResponse::Ok {
                response: b"success 3 request".to_vec()
            })
        );
    });
}
