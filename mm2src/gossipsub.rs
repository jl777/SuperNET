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
use libp2p::gossipsub::{GossipsubEvent, GossipsubMessage, Topic};
use libp2p::{
    gossipsub, identity,
    PeerId,
};
use serde_json::{self as json, Value as Json};
use std::{
    collections::hash_map::DefaultHasher,
    error::Error,
    hash::{Hash, Hasher},
    net::IpAddr,
    task::{Context, Poll},
    time::Duration,
};

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
            .mesh_n(5)
            .mesh_n_high(5)
            //same content will be propagated.
            .build();
        // build a gossipsub network behaviour
        let topic = Topic::new("ETHJST".into());
        let mut gossipsub = gossipsub::Gossipsub::new(local_peer_id.clone(), gossipsub_config);
        // gossipsub.subscribe(topic.clone());
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

    spawn(async move {
        loop {
            let mut gossip_event_fut = Box::pin(swarm.next().fuse());
            let mut rx_fut = rx.next().fuse();
            let never = future::pending::<()>();
            let tick_fut = if listening {
                Either::Left(never.fuse())
            } else {
                Either::Right(timeout(Duration::from_millis(500), never).fuse().then(|_| futures::future::ready(())))
            };

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
                            lp_process_p2p_message(&ctx, &message.data).await;
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
                            P2PCommand::Subscribe(topics) => {
                                for topic in topics {
                                    swarm.subscribe(Topic::new(topic));
                                }
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
        let mut gossipsub = gossipsub::Gossipsub::new(local_peer_id.clone(), gossipsub_config);
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
        let mut ticks = 0u64;
        loop {
            let mut gossip_event_fut = Box::pin(swarm.next().fuse());
            let mut rx_fut = rx.next().fuse();
            let never = future::pending::<()>();
            let mut tick_fut = Box::pin(timeout(Duration::from_secs(1), never).fuse().then(|_| futures::future::ready(())));
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
                            lp_process_p2p_message(&ctx, &message.data).await;
                        },
                        _ => println!("{:?}", gossip_event),
                    };
                },
                recv = rx_fut => {
                    drop(gossip_event_fut);
                    if let Some(cmd) = recv {
                        match cmd {
                            P2PCommand::Subscribe(topics) => {
                                for topic in topics {
                                    swarm.subscribe(Topic::new(topic));
                                }
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
                    ticks += 1;
                    drop(gossip_event_fut);
                    if ticks == 5 {
                        let topic = Topic::new("ETHJST".into());
                        swarm.subscribe(topic);
                    }
                },
            }
        }
    });
    tx
}
