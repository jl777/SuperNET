use atomicdex_gossipsub::{Gossipsub, GossipsubConfigBuilder, GossipsubEvent, GossipsubMessage, MessageId, Topic,
                          TopicHash};
use futures::{channel::{mpsc::{unbounded, UnboundedReceiver, UnboundedSender},
                        oneshot},
              future::poll_fn,
              Future, SinkExt, StreamExt};
use libp2p::core::{ConnectedPoint, Multiaddr, Transport};
use libp2p::{identity, swarm::NetworkBehaviourEventProcess, NetworkBehaviour, PeerId};
use std::{collections::hash_map::{DefaultHasher, HashMap},
          hash::{Hash, Hasher},
          net::IpAddr,
          task::{Context, Poll}};

pub type AdexCmdTx = UnboundedSender<AdexBehaviorCmd>;
pub type GossipEventRx = UnboundedReceiver<GossipsubEvent>;

/// Returns info about connected peers
pub async fn get_peers_info(mut cmd_tx: AdexCmdTx) -> HashMap<String, Vec<String>> {
    let (result_tx, rx) = oneshot::channel();
    let cmd = AdexBehaviorCmd::GetPeersInfo { result_tx };
    cmd_tx.send(cmd).await.expect("Rx should be present");
    rx.await.expect("Tx should be present")
}

/// Returns current gossipsub mesh state
pub async fn get_gossip_mesh(mut cmd_tx: AdexCmdTx) -> HashMap<String, Vec<String>> {
    let (result_tx, rx) = oneshot::channel();
    let cmd = AdexBehaviorCmd::GetGossipMesh { result_tx };
    cmd_tx.send(cmd).await.expect("Rx should be present");
    rx.await.expect("Tx should be present")
}

pub async fn get_gossip_peer_topics(mut cmd_tx: AdexCmdTx) -> HashMap<String, Vec<String>> {
    let (result_tx, rx) = oneshot::channel();
    let cmd = AdexBehaviorCmd::GetGossipPeerTopics { result_tx };
    cmd_tx.send(cmd).await.expect("Rx should be present");
    rx.await.expect("Tx should be present")
}

pub async fn get_gossip_topic_peers(mut cmd_tx: AdexCmdTx) -> HashMap<String, Vec<String>> {
    let (result_tx, rx) = oneshot::channel();
    let cmd = AdexBehaviorCmd::GetGossipTopicPeers { result_tx };
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
    PublishMsg {
        topic: String,
        msg: Vec<u8>,
    },
    SendToPeers {
        msgs: Vec<(String, Vec<u8>)>,
        peers: Vec<String>,
    },
    GetPeersInfo {
        result_tx: oneshot::Sender<HashMap<String, Vec<String>>>,
    },
    GetGossipMesh {
        result_tx: oneshot::Sender<HashMap<String, Vec<String>>>,
    },
    GetGossipPeerTopics {
        result_tx: oneshot::Sender<HashMap<String, Vec<String>>>,
    },
    GetGossipTopicPeers {
        result_tx: oneshot::Sender<HashMap<String, Vec<String>>>,
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
            AdexBehaviorCmd::GetPeersInfo { result_tx } => {
                let result = self
                    .gossipsub
                    .get_peers_connections()
                    .into_iter()
                    .map(|(peer_id, connected_points)| {
                        let peer_id = peer_id.to_base58();
                        let connected_points = connected_points
                            .into_iter()
                            .map(|point| match point {
                                ConnectedPoint::Dialer { address } => address.to_string(),
                                ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr.to_string(),
                            })
                            .collect();
                        (peer_id, connected_points)
                    })
                    .collect();
                if result_tx.send(result).is_err() {
                    println!("Result rx is dropped");
                }
            },
            AdexBehaviorCmd::GetGossipMesh { result_tx } => {
                let result = self
                    .gossipsub
                    .get_mesh()
                    .iter()
                    .map(|(topic, peers)| {
                        let topic = topic.to_string();
                        let peers = peers.iter().map(|peer| peer.to_string()).collect();
                        (topic, peers)
                    })
                    .collect();
                if result_tx.send(result).is_err() {
                    println!("Result rx is dropped");
                }
            },
            AdexBehaviorCmd::GetGossipPeerTopics { result_tx } => {
                let result = self
                    .gossipsub
                    .get_all_peer_topics()
                    .iter()
                    .map(|(peer, topics)| {
                        let peer = peer.to_string();
                        let topics = topics.iter().map(|topic| topic.to_string()).collect();
                        (peer, topics)
                    })
                    .collect();
                if result_tx.send(result).is_err() {
                    println!("Result rx is dropped");
                }
            },
            AdexBehaviorCmd::GetGossipTopicPeers { result_tx } => {
                let result = self
                    .gossipsub
                    .get_all_topic_peers()
                    .iter()
                    .map(|(topic, peers)| {
                        let topic = topic.to_string();
                        let peers = peers.iter().map(|peer| peer.to_string()).collect();
                        (topic, peers)
                    })
                    .collect();
                if result_tx.send(result).is_err() {
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
    my_privkey: &mut [u8],
) -> (
    UnboundedSender<AdexBehaviorCmd>,
    UnboundedReceiver<GossipsubEvent>,
    PeerId,
) {
    // Create a random PeerId
    let privkey = identity::secp256k1::SecretKey::from_bytes(my_privkey).unwrap();
    let local_key = identity::Keypair::Secp256k1(privkey.into());
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

    // Set up an encrypted TCP Transport over the Mplex protocol
    let transport = {
        let tcp = libp2p::tcp::TcpConfig::new().nodelay(true);
        let transport = libp2p::dns::DnsConfig::new(tcp).unwrap();
        let trans_clone = transport.clone();
        transport.or_transport(libp2p::websocket::WsConfig::new(trans_clone))
    };

    let transport = transport
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(libp2p::secio::SecioConfig::new(local_key))
        .multiplex(libp2p::mplex::MplexConfig::new())
        .map(|(peer, muxer), _| (peer, libp2p::core::muxing::StreamMuxerBox::new(muxer)))
        .timeout(std::time::Duration::from_secs(20));

    let (cmd_tx, cmd_rx) = unbounded();
    let (event_tx, event_rx) = unbounded();

    let relayers: Vec<Multiaddr> = to_dial
        .unwrap_or_default()
        .into_iter()
        .map(|addr| format!("/ip4/{}/tcp/{}", addr, port).parse().unwrap())
        .collect();

    // Create a Swarm to manage peers and events
    let mut swarm = {
        // to set default parameters for gossipsub use:
        // let gossipsub_config = gossipsub::GossipsubConfig::default();

        // To content-address message, we can take the hash of message and use it as an ID.
        let message_id_fn = |message: &GossipsubMessage| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            message.sequence_number.hash(&mut s);
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
        let gossipsub = Gossipsub::new(local_peer_id.clone(), gossipsub_config, relayers.clone());
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
    for relayer in &relayers {
        match libp2p::Swarm::dial_addr(&mut swarm, relayer.clone()) {
            Ok(_) => println!("Dialed {}", relayer),
            Err(e) => println!("Dial {:?} failed: {:?}", relayer, e),
        }
    }

    let polling_fut = poll_fn(move |cx: &mut Context| {
        loop {
            match swarm.cmd_rx.poll_next_unpin(cx) {
                Poll::Ready(Some(cmd)) => swarm.process_cmd(cmd),
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => break,
            }
        }

        loop {
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => println!("Swarm event {:?}", event),
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => break,
            }
        }

        Poll::Pending
    });

    spawn_fn(Box::new(polling_fut));

    (cmd_tx, event_rx, local_peer_id)
}
