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
          task::{Context, Poll}};

pub type AdexCmdTx = UnboundedSender<AdexBehaviorCmd>;
pub type GossipEventRx = UnboundedReceiver<GossipsubEvent>;

#[allow(dead_code)]
async fn is_subscribed(mut cmd_tx: AdexCmdTx, topic: String) -> bool {
    let (tx, rx) = oneshot::channel();
    let cmd = AdexBehaviorCmd::IsSubscribed { topic, result_tx: tx };
    cmd_tx.send(cmd).await.expect("Rx should be present");
    rx.await.expect("Tx should be present")
}

#[allow(dead_code)]
async fn get_mesh_and_total_peers_num(mut cmd_tx: AdexCmdTx, topic: String) -> (usize, usize) {
    let (tx, rx) = oneshot::channel();
    let cmd = AdexBehaviorCmd::GetMeshAndTotalPeersNum { topic, result_tx: tx };
    cmd_tx.send(cmd).await.expect("Rx should be present");
    rx.await.expect("Tx should be present")
}

#[derive(Debug)]
pub enum AdexBehaviorCmd {
    Subscribe {
        /// Subscribe to this topic
        topic: String,
        mesh_update_tx: oneshot::Sender<()>,
    },
    IsSubscribed {
        topic: String,
        result_tx: oneshot::Sender<bool>,
    },
    GetMeshAndTotalPeersNum {
        topic: String,
        result_tx: oneshot::Sender<(usize, usize)>,
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

/// AtomicDEX libp2p Network behaviour implementation
#[derive(NetworkBehaviour)]
pub struct AtomicDexBehavior {
    #[behaviour(ignore)]
    event_tx: UnboundedSender<GossipsubEvent>,
    #[behaviour(ignore)]
    mesh_update_txs: HashMap<TopicHash, Vec<oneshot::Sender<()>>>,
    #[behaviour(ignore)]
    spawn_fn: fn(Box<dyn Future<Output = ()> + Send + Unpin + 'static>) -> (),
    #[behaviour(ignore)]
    cmd_rx: UnboundedReceiver<AdexBehaviorCmd>,
    gossipsub: Gossipsub,
}

impl AtomicDexBehavior {
    fn notify_on_event(&self, event: GossipsubEvent) {
        let mut tx = self.event_tx.clone();
        (self.spawn_fn)(Box::new(Box::pin(async move {
            if let Err(e) = tx.send(event).await {
                println!("{}", e);
            }
        })))
    }

    fn process_cmd(&mut self, cmd: AdexBehaviorCmd) {
        match cmd {
            AdexBehaviorCmd::Subscribe { topic, mesh_update_tx } => {
                let topic = Topic::new(topic);
                let topic_hash = topic.no_hash();
                self.gossipsub.subscribe(topic);
                if !self.gossipsub.get_mesh_peers(&topic_hash).is_empty() || self.gossipsub.get_num_peers() == 0 {
                    if mesh_update_tx.send(()).is_err() {
                        println!("Result rx is dropped");
                    }
                } else {
                    self.mesh_update_txs
                        .entry(topic_hash)
                        .or_insert_with(Vec::new)
                        .push(mesh_update_tx);
                }
            },
            AdexBehaviorCmd::IsSubscribed { topic, result_tx } => {
                let topic = TopicHash::from_raw(topic);
                let is_subscribed = self.gossipsub.is_subscribed(&topic);
                if result_tx.send(is_subscribed).is_err() {
                    println!("Result rx is dropped");
                }
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
            AdexBehaviorCmd::GetMeshAndTotalPeersNum { topic, result_tx } => {
                let topic = TopicHash::from_raw(topic);
                let tuple = (
                    self.gossipsub.get_mesh_peers(&topic).len(),
                    self.gossipsub.get_num_peers(),
                );
                if result_tx.send(tuple).is_err() {
                    println!("Result rx is dropped");
                }
            },
        }
    }
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for AtomicDexBehavior {
    fn inject_event(&mut self, event: GossipsubEvent) {
        if let GossipsubEvent::MeshUpdated { topic, .. } = &event {
            if let Some(txs) = self.mesh_update_txs.remove(&topic) {
                for tx in txs {
                    if tx.send(()).is_err() {
                        println!("Receiver is dropped");
                    }
                }
            }
        }
        self.notify_on_event(event);
    }
}

/// Creates and spawns new AdexBehavior Swarm returning:
/// 1. tx to send control commands
/// 2. rx emitting gossip events to processing side
/// 3. our peer_id
pub fn start_gossipsub(
    ip: IpAddr,
    port: u16,
    spawn_fn: fn(Box<dyn Future<Output = ()> + Send + Unpin + 'static>) -> (),
    to_dial: Option<Vec<String>>,
) -> (
    UnboundedSender<AdexBehaviorCmd>,
    UnboundedReceiver<GossipsubEvent>,
    PeerId,
) {
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
            event_tx,
            spawn_fn,
            cmd_rx,
            gossipsub,
            mesh_update_txs: HashMap::new(),
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

    (cmd_tx, event_rx, local_peer_id)
}

#[test]
fn test_will_compile() {}
