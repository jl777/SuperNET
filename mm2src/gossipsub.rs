use async_std::{io, task};
use async_std::future::timeout;
use common::{
    now_ms,
    executor::spawn,
    mm_ctx::{MmArc, P2PCommand},
};
use crate::mm2::{
    lp_network::lp_process_p2p_message,
    lp_ordermatch::broadcast_my_maker_orders,
};
use futures::{
    select, FutureExt,
    channel::mpsc,
    future::Either,
    prelude::*
};
use libp2p::gossipsub::protocol::MessageId;
use libp2p::gossipsub::{GossipsubEvent, GossipsubMessage, Topic, TopicHash};
use libp2p::{
    gossipsub, identity,
    PeerId,
};
use serde_json::{self as json, Value as Json};
use std::{
    collections::hash_map::{DefaultHasher, HashMap},
    error::Error,
    hash::{Hash, Hasher},
    net::IpAddr,
    task::{Context, Poll},
    time::Duration,
};

pub type TopicPrefix = &'static str;
pub const TOPIC_SEPARATOR: char = '/';

pub fn pub_sub_topic(prefix: TopicPrefix, topic: &str) -> String {
    let mut res = prefix.to_owned();
    res.push(TOPIC_SEPARATOR);
    res.push_str(topic);
    res
}

pub fn relayer_node(ctx: MmArc, ip: IpAddr, port: u16, other_relayers: Option<Vec<String>>) -> mpsc::UnboundedSender<P2PCommand> {
    // Create a random PeerId
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

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
        let gossipsub_config = gossipsub::GossipsubConfigBuilder::new()
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the
            // same content will be propagated.
            .mesh_n(5)
            .mesh_n_high(5)
            .build();
        // build a gossipsub network behaviour
        let gossipsub = gossipsub::Gossipsub::new(local_peer_id.clone(), gossipsub_config);
        libp2p::Swarm::new(transport, gossipsub, local_peer_id)
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
            let tick_fut = timeout(Duration::from_millis(500), never).fuse().then(|_| futures::future::ready(()));

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
                            let topics = message.topics.iter().map(|topic| topic.as_str().to_owned()).collect();
                            lp_process_p2p_message(&ctx, topics, &message.data).await;
                        },
                        GossipsubEvent::Subscribed { peer_id, topic } => {
                            swarm.subscribe(Topic::new(topic.into_string()));
                            broadcast_my_maker_orders(&ctx).await.unwrap();
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
                                subscription_tx.insert(topic, tx);
                            },
                            P2PCommand::Publish(msgs) => {
                                for (topic, msg) in msgs {
                                    swarm.publish(&Topic::new(topic), msg);
                                }
                            }
                        }
                    }
                },
                tick = tick_fut => {
                    drop(gossip_event_fut);
                    subscription_tx = subscription_tx.drain().filter_map(|(topic, tx)| {
                        let topic_hash = TopicHash::from_raw(topic.clone());
                        if swarm.get_mesh_peers(&topic_hash).len() > 0 || swarm.get_num_peers() == 0 || swarm.get_topic_peers(&topic_hash).len() == 0 {
                            tx.send(()).unwrap();
                            None
                        } else {
                            Some((topic, tx))
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
    tx
}

pub fn clientnode(ctx: MmArc, relayers: Vec<String>, seednode_port: u16) -> mpsc::UnboundedSender<P2PCommand> {
    // Create a random PeerId
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

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
        let gossipsub_config = gossipsub::GossipsubConfigBuilder::new()
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the
            //same content will be propagated.
            .build();
        // build a gossipsub network behaviour
        let gossipsub = gossipsub::Gossipsub::new(local_peer_id.clone(), gossipsub_config);
        libp2p::Swarm::new(transport, gossipsub, local_peer_id)
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
            let mut tick_fut = Box::pin(timeout(Duration::from_millis(500), never).fuse().then(|_| futures::future::ready(())));

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
                            let topics = message.topics.iter().map(|topic| topic.as_str().to_owned()).collect();
                            lp_process_p2p_message(&ctx, topics, &message.data).await;
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
                                subscription_tx.insert(topic, tx);
                            },
                            P2PCommand::Publish(msgs) => {
                                for (topic, msg) in msgs {
                                    swarm.publish(&Topic::new(topic), msg);
                                }
                            }
                        }
                    }
                },
                tick = tick_fut => {
                    drop(gossip_event_fut);
                    subscription_tx = subscription_tx.drain().filter_map(|(topic, tx)| {
                        let topic_hash = TopicHash::from_raw(topic.clone());
                        if swarm.get_mesh_peers(&topic_hash).len() > 0 || swarm.get_num_peers() == 0 {
                            tx.send(()).unwrap();
                            None
                        } else {
                            Some((topic, tx))
                        }
                    }).collect();
                },
            }
        }
    });
    tx
}
