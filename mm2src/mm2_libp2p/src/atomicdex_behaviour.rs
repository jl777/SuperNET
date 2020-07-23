use atomicdex_gossipsub::{Gossipsub, GossipsubConfigBuilder, GossipsubEvent, GossipsubMessage, MessageId, Topic,
                          TopicHash};
use futures::{channel::{mpsc::{unbounded, UnboundedReceiver, UnboundedSender},
                        oneshot},
              future::poll_fn,
              Future, SinkExt, StreamExt};
use libp2p::{identity, swarm::NetworkBehaviourEventProcess, NetworkBehaviour, PeerId};
use std::{collections::hash_map::{DefaultHasher, HashMap},
          hash::{Hash, Hasher},
          net::IpAddr,
          sync::Arc,
          task::{Context, Poll}};

pub type AdexCmdTx = UnboundedSender<AdexBehaviorCmd>;

async fn is_subscribed(mut cmd_tx: AdexCmdTx, topic: String) -> bool {
    let (tx, rx) = oneshot::channel();
    let cmd = AdexBehaviorCmd::IsSubscribed { topic, result_tx: tx };
    cmd_tx.send(cmd).await.expect("Rx should be present");
    rx.await.expect("Tx should be present")
}

#[derive(Debug)]
pub enum AdexBehaviorCmd {
    Subscribe {
        /// Subscribe to this topic
        topic: String,
    },
    IsSubscribed {
        topic: String,
        result_tx: oneshot::Sender<bool>,
    },
    PublishMsg {
        topic: String,
        msg: Vec<u8>,
    },
    SendToPeers {
        msgs: Vec<(String, Vec<u8>)>,
        peers: Vec<String>,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub enum AdexNodeType {
    Standard,
    Relayer,
}

/// AtomicDEX libp2p Network behaviour implementation
#[derive(NetworkBehaviour)]
pub struct AtomicDexBehavior {
    #[behaviour(ignore)]
    node_type: AdexNodeType,
    #[behaviour(ignore)]
    event_tx: UnboundedSender<GossipsubEvent>,
    #[behaviour(ignore)]
    spawn_fn: fn(Box<dyn Future<Output = ()>>) -> (),
    #[behaviour(ignore)]
    cmd_rx: UnboundedReceiver<AdexBehaviorCmd>,
    gossipsub: Gossipsub,
}

impl AtomicDexBehavior {
    fn notify_on_event(&self, event: GossipsubEvent) {
        let mut tx = self.event_tx.clone();
        (self.spawn_fn)(Box::new(async move {
            if let Err(e) = tx.send(event).await {
                println!("{}", e);
            }
        }))
    }

    fn process_cmd(&mut self, cmd: AdexBehaviorCmd) {
        match cmd {
            AdexBehaviorCmd::Subscribe { topic } => {
                let topic = Topic::new(topic);
                self.gossipsub.subscribe(topic);
            },
            AdexBehaviorCmd::IsSubscribed { topic, result_tx } => {
                let topic = TopicHash::from_raw(topic);
                let is_subscribed = self.gossipsub.is_subscribed(&topic);
                (self.spawn_fn)(Box::new(async move {
                    if let Err(_) = result_tx.send(is_subscribed) {
                        println!("Result rx is dropped");
                    }
                }))
            },
            AdexBehaviorCmd::PublishMsg { topic, msg } => {
                self.gossipsub.publish(&Topic::new(topic), msg);
            },
            AdexBehaviorCmd::SendToPeers { msgs, peers } => {
                let mut peer_ids = Vec::with_capacity(peers.len());
                for peer in peers {
                    let peer_id: PeerId = match peer.parse() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    peer_ids.push(peer_id);
                }

                self.gossipsub.send_messages_to_peers(msgs, peer_ids);
            },
        }
    }
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for AtomicDexBehavior {
    fn inject_event(&mut self, event: GossipsubEvent) { self.notify_on_event(event); }
}

/// Creates and spawns new AdexBehavior Swarm returning tx to send control commands
pub fn new_and_spawn(
    node_type: AdexNodeType,
    ip: IpAddr,
    port: u16,
    spawn_fn: fn(Box<dyn Future<Output = ()>>) -> (),
    to_dial: Option<Vec<String>>,
) -> (UnboundedSender<AdexBehaviorCmd>, UnboundedReceiver<GossipsubEvent>) {
    // Create a random PeerId
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

    // Set up an encrypted TCP Transport over the Mplex and Yamux protocols
    let transport = libp2p::build_development_transport(local_key).unwrap();
    let (cmd_tx, cmd_rx) = unbounded();
    let (event_tx, event_rx) = unbounded();

    // Create a Swarm to manage peers and events
    let mut swarm = {
        // to set default parameters for gossipsub use:
        // let gossipsub_config = gossipsub::GossipsubConfig::default();

        // To content-address message, we can take the hash of message and use it as an ID.
        let message_id_fn = |message: &GossipsubMessage| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            MessageId(s.finish().to_string())
        };

        // set custom gossipsub
        let gossipsub_config = GossipsubConfigBuilder::new()
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the
            // same content will be propagated.
            .mesh_n(5)
            .mesh_n_high(5)
            .build();
        // build a gossipsub network behaviour
        let gossipsub = Gossipsub::new(local_peer_id.clone(), gossipsub_config);
        let adex_behavior = AtomicDexBehavior {
            node_type,
            event_tx,
            spawn_fn,
            cmd_rx,
            gossipsub,
        };
        libp2p::Swarm::new(transport, adex_behavior, local_peer_id.clone())
    };
    let addr = format!("/ip4/{}/tcp/{}", ip, port);
    libp2p::Swarm::listen_on(&mut swarm, addr.parse().unwrap()).unwrap();

    if let Some(relayers) = to_dial.as_ref() {
        for relayer in relayers {
            let addr = format!("/ip4/{}/tcp/{}", relayer, port).parse().unwrap();
            match libp2p::Swarm::dial_addr(&mut swarm, addr) {
                Ok(_) => println!("Dialed {}", relayer),
                Err(e) => println!("Dial {:?} failed: {:?}", relayer, e),
            }
        }
    }

    let polling_fut = poll_fn(move |cx: &mut Context| {
        loop {
            match swarm.cmd_rx.poll_next_unpin(cx) {
                Poll::Ready(Some(cmd)) => swarm.process_cmd(cmd),
                Poll::Ready(None) => panic!("Cmd tx was dropped"),
                Poll::Pending => break,
            }
        }

        loop {
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => println!("{:?}", event),
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => break,
            }
        }
        Poll::Pending
    });

    spawn_fn(Box::new(polling_fut));

    (cmd_tx, event_rx)
}

#[test]
fn test_will_compile() {}
