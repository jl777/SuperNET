use async_std::future::timeout;
use common::{block_on,
             executor::spawn,
             mm_ctx::{from_ctx, MmArc, MmWeak, P2PCommand}};
use futures::{channel::mpsc, lock::Mutex as AsyncMutex, prelude::*, select, FutureExt};
use libp2p::{identity, PeerId};
use libp2p_gossipsub::protocol::MessageId;
use std::{collections::hash_map::{DefaultHasher, HashMap},
          hash::{Hash, Hasher},
          net::IpAddr,
          ops::Deref,
          sync::Arc,
          time::Duration};

pub trait GossipsubEventHandler {
    fn peer_subscribed(&self, peer: &str, topic: &str);

    fn message_received(&self, peer: String, topics: &[&str], msg: &[u8]);

    fn peer_disconnected(&self, peer: &str);
}

pub struct GossipsubContext(AsyncMutex<GossipsubContextImpl>);

impl Deref for GossipsubContext {
    type Target = AsyncMutex<GossipsubContextImpl>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl GossipsubContext {
    /// Obtains a reference to this crate context, creating it if necessary.
    fn from_ctx(ctx: &MmArc) -> Result<Arc<GossipsubContext>, String> {
        Ok(try_s!(from_ctx(&ctx.gossipsub_ctx, move || {
            Ok(GossipsubContext(AsyncMutex::new(GossipsubContextImpl {
                event_handlers: vec![],
            })))
        })))
    }

    /// Obtains a reference to this crate context, creating it if necessary.
    #[allow(dead_code)]
    fn from_ctx_weak(ctx_weak: &MmWeak) -> Result<Arc<GossipsubContext>, String> {
        let ctx = try_s!(MmArc::from_weak(ctx_weak).ok_or("Context expired"));
        Self::from_ctx(&ctx)
    }
}

pub struct GossipsubContextImpl {
    event_handlers: Vec<Box<dyn GossipsubEventHandler + Send + Sync>>,
}

pub async fn add_gossipsub_event_handler(ctx: &MmArc, new_handler: Box<dyn GossipsubEventHandler + Send + Sync>) {
    let gossipsub_ctx = unwrap!(GossipsubContext::from_ctx(ctx));
    gossipsub_ctx.lock().await.add_event_handler(new_handler);
}

impl GossipsubContextImpl {
    pub fn add_event_handler(&mut self, new_handler: Box<dyn GossipsubEventHandler + Send + Sync>) {
        self.event_handlers.push(new_handler);
    }
}

impl GossipsubEventHandler for GossipsubContextImpl {
    fn peer_subscribed(&self, peer: &str, topic: &str) {
        for handler in self.event_handlers.iter() {
            handler.peer_subscribed(peer, topic);
        }
    }

    fn message_received(&self, peer: String, topics: &[&str], msg: &[u8]) {
        for handler in self.event_handlers.iter() {
            handler.message_received(peer.clone(), topics, msg);
        }
    }

    fn peer_disconnected(&self, peer: &str) {
        for handler in self.event_handlers.iter() {
            handler.peer_disconnected(peer);
        }
    }
}

pub type TopicPrefix = &'static str;
pub const TOPIC_SEPARATOR: char = '/';

pub fn pub_sub_topic(prefix: TopicPrefix, topic: &str) -> String {
    let mut res = prefix.to_owned();
    res.push(TOPIC_SEPARATOR);
    res.push_str(topic);
    res
}

pub fn relayer_node(
    ctx: MmArc,
    ip: IpAddr,
    port: u16,
    other_relayers: Option<Vec<String>>,
) -> (mpsc::UnboundedSender<P2PCommand>, String) {
    // Set up an encrypted TCP Transport over the Mplex and Yamux protocols
    let transport = libp2p::build_development_transport(local_key).unwrap();

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
        libp2p::Swarm::new(transport, gossipsub, local_peer_id.clone())
    };
    let addr = format!("/ip4/{}/tcp/{}", ip, port);
    libp2p::Swarm::listen_on(&mut swarm, addr.parse().unwrap()).unwrap();

    if let Some(relayers) = other_relayers.as_ref() {
        for relayer in relayers {
            let to_dial = format!("/ip4/{}/tcp/{}", relayer, port).parse().unwrap();
            match libp2p::Swarm::dial_addr(&mut swarm, to_dial) {
                Ok(_) => println!("Dialed {}", relayer),
                Err(e) => println!("Dial {:?} failed: {:?}", relayer, e),
            }
        }
    }

    let mut listening = false;
    let (tx, mut rx) = mpsc::unbounded();
    let mut subscription_tx = HashMap::new();

    spawn(async move {
        loop {
            let mut gossip_event_fut = Box::pin(swarm.next().fuse());
            let mut rx_fut = rx.next().fuse();
            let never = future::pending::<()>();
            let tick_fut = timeout(Duration::from_millis(500), never)
                .fuse()
                .then(|_| futures::future::ready(()));

            let mut tick_fut = Box::pin(tick_fut);
            select! {
                gossip_event = gossip_event_fut => {
                    drop(gossip_event_fut);
                    match gossip_event {
                        GossipsubEvent::Message(peer_id, id, message) => {
                            println!(
                                "Got message: {} with id: {} from peer: {:?}",
                                String::from_utf8_lossy(&message.data),
                                id,
                                peer_id
                            );
                            let topics: Vec<&str> = message.topics.iter().map(|topic| topic.as_str()).collect();
                            gossipsub_ctx.lock().await.message_received(peer_id.to_base58(), &topics, &message.data);
                        },
                        GossipsubEvent::Subscribed { peer_id, topic } => {
                            let topic_str = topic.into_string();
                            gossipsub_ctx.lock().await.peer_subscribed(&peer_id.to_base58(), &topic_str);
                            swarm.subscribe(Topic::new(topic_str));
                        },
                        GossipsubEvent::PeerDisconnected(peer_id) => {
                            gossipsub_ctx.lock().await.peer_disconnected(&peer_id.to_base58());
                        },
                        _ => println!("{:?}", gossip_event),
                    };
                },
                recv = rx_fut => {
                    drop(gossip_event_fut);
                    if let Some(cmd) = recv {
                        match cmd {
                            P2PCommand::Subscribe(topic, tx) => {
                                swarm.subscribe(Topic::new(topic.clone()));
                                subscription_tx.entry(topic)
                                    .or_insert(vec![])
                                    .push(tx);
                            },
                            P2PCommand::Publish(msgs) => {
                                for (topic, msg) in msgs {
                                    swarm.publish(&Topic::new(topic), msg);
                                }
                            },
                            P2PCommand::SendToPeers(msgs, peers) => {
                                let mut peer_ids = Vec::with_capacity(peers.len());
                                for peer in peers {
                                    let peer_id: PeerId = match peer.parse() {
                                        Ok(p) => p,
                                        Err(_) => continue,
                                    };
                                    peer_ids.push(peer_id);
                                }

                                swarm.send_messages_to_peers(msgs, peer_ids);
                            }
                        }
                    }
                },
                tick = tick_fut => {
                    drop(gossip_event_fut);
                    subscription_tx = subscription_tx.drain().filter_map(|(topic, senders)| {
                        let topic_hash = TopicHash::from_raw(topic.clone());
                        if swarm.get_mesh_peers(&topic_hash).len() > 0 || swarm.get_num_peers() == 0 || swarm.get_topic_peers(&topic_hash).len() == 0 {
                            for tx in senders {
                                tx.send(()).unwrap();
                            }
                            None
                        } else {
                            Some((topic, senders))
                        }
                    }).collect();
                },
            }
            if !listening {
                for addr in libp2p::Swarm::listeners(&swarm) {
                    println!("libp2p gossipsub node listening on {:?}", addr);
                    listening = true;
                }
            }
        }
    });
    (tx, local_peer_id.to_base58())
}

pub fn clientnode(
    ctx: MmArc,
    relayers: Vec<String>,
    seednode_port: u16,
) -> (mpsc::UnboundedSender<P2PCommand>, String) {
    // Create a random PeerId
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);
    let gossipsub_ctx = unwrap!(GossipsubContext::from_ctx(&ctx));

    // Set up an encrypted TCP Transport over the Mplex and Yamux protocols
    let transport = libp2p::build_development_transport(local_key).unwrap();

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
            //same content will be propagated.
            .build();
        // build a gossipsub network behaviour
        let gossipsub = Gossipsub::new(local_peer_id.clone(), gossipsub_config);
        libp2p::Swarm::new(transport, gossipsub, local_peer_id.clone())
    };

    for relayer in relayers {
        let to_dial = format!("/ip4/{}/tcp/{}", relayer, seednode_port).parse().unwrap();
        match libp2p::Swarm::dial_addr(&mut swarm, to_dial) {
            Ok(_) => println!("Dialed {}", relayer),
            Err(e) => println!("Dial {:?} failed: {:?}", relayer, e),
        }
    }
    let (tx, mut rx) = mpsc::unbounded();
    spawn(async move {
        let mut subscription_tx = HashMap::new();
        loop {
            let mut gossip_event_fut = Box::pin(swarm.next().fuse());
            let mut rx_fut = rx.next().fuse();
            let never = future::pending::<()>();
            let mut tick_fut = Box::pin(
                timeout(Duration::from_millis(500), never)
                    .fuse()
                    .then(|_| futures::future::ready(())),
            );

            select! {
                gossip_event = gossip_event_fut => {
                    drop(gossip_event_fut);
                    match gossip_event {
                        GossipsubEvent::Message(peer_id, id, message) => {
                            println!(
                                "Got message: {} with id: {} from peer: {:?}",
                                String::from_utf8_lossy(&message.data),
                                id,
                                peer_id
                            );
                            let topics: Vec<&str> = message.topics.iter().map(|topic| topic.as_str()).collect();
                            gossipsub_ctx.lock().await.message_received(peer_id.to_base58(), &topics, &message.data);
                        },
                        GossipsubEvent::PeerDisconnected(peer_id) => {
                            gossipsub_ctx.lock().await.peer_disconnected(&peer_id.to_base58());
                        },
                        _ => println!("{:?}", gossip_event),
                    };
                },
                recv = rx_fut => {
                    drop(gossip_event_fut);
                    if let Some(cmd) = recv {
                        match cmd {
                            P2PCommand::Subscribe(topic, tx) => {
                                swarm.subscribe(Topic::new(topic.clone()));
                                subscription_tx.entry(topic)
                                    .or_insert(vec![])
                                    .push(tx);
                            },
                            P2PCommand::Publish(msgs) => {
                                for (topic, msg) in msgs {
                                    swarm.publish(&Topic::new(topic), msg);
                                }
                            },
                            P2PCommand::SendToPeers(msgs, peers) => {
                                let mut peer_ids = Vec::with_capacity(peers.len());
                                for peer in peers {
                                    let peer_id: PeerId = match peer.parse() {
                                        Ok(p) => p,
                                        Err(_) => continue,
                                    };
                                    peer_ids.push(peer_id);
                                }

                                swarm.send_messages_to_peers(msgs, peer_ids);
                            }
                        }
                    }
                },
                tick = tick_fut => {
                    drop(gossip_event_fut);
                    subscription_tx = subscription_tx.drain().filter_map(|(topic, senders)| {
                        let topic_hash = TopicHash::from_raw(topic.clone());
                        if swarm.get_mesh_peers(&topic_hash).len() > 0 || swarm.get_num_peers() == 0 {
                            for tx in senders {
                                tx.send(()).unwrap();
                            }
                            None
                        } else {
                            Some((topic, senders))
                        }
                    }).collect();
                },
            }
        }
    });
    (tx, local_peer_id.to_base58())
}
