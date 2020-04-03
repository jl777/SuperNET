use async_std::{io, task};
use async_std::future::timeout;
use common::{
    now_ms,
    executor::spawn,
    mm_ctx::MmArc,
};
use crate::mm2::lp_ordermatch::lp_post_price_recv;
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


pub fn relayer_node(ip: IpAddr, port: u16, other_relayers: Option<Vec<String>>) -> mpsc::UnboundedSender<Vec<u8>> {
    // Create a random PeerId
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

    // Set up an encrypted TCP Transport over the Mplex and Yamux protocols
    let transport = libp2p::build_development_transport(local_key).unwrap();

    // Create a Gossipsub topic
    let topic = Topic::new("test-net".into());

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
    let (mut tx, mut rx) = mpsc::unbounded::<Vec<u8>>();
    let res = tx.clone();

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
                        GossipsubEvent::Message(peer_id, id, message) => println!(
                            "Got message: {} with id: {} from peer: {:?}",
                            String::from_utf8_lossy(&message.data),
                            id,
                            peer_id
                        ),
                        GossipsubEvent::Subscribed { peer_id, topic } => {
                            swarm.subscribe(Topic::new(topic.into_string()));
                        }
                        _ => println!("{:?}", gossip_event),
                    };
                },
                recv = rx_fut => {
                    drop(gossip_event_fut);
                    if let Some(recv) = recv {
                        swarm.publish(&topic, recv);
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
    res
}

pub fn clientnode(ctx: MmArc, relayers: Vec<String>, seednode_port: u16) {
    // Create a random PeerId
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

    // Set up an encrypted TCP Transport over the Mplex and Yamux protocols
    let transport = libp2p::build_development_transport(local_key).unwrap();

    // Create a Gossipsub topic
    let topic = Topic::new("test-net".into());

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
        gossipsub.subscribe(topic.clone());
        libp2p::Swarm::new(transport, gossipsub, local_peer_id)
    };

    for relayer in relayers {
        let to_dial = format!("/ip4/{}/tcp/{}", relayer, seednode_port).parse().unwrap();
        match libp2p::Swarm::dial_addr(&mut swarm, to_dial) {
            Ok(_) => println!("Dialed {}", relayer),
            Err(e) => println!("Dial {:?} failed: {:?}", relayer, e),
        }
    }

    spawn(async move {
        loop {
            match swarm.next().await {
                GossipsubEvent::Message(peer_id, id, message) => {
                    println!(
                        "Got message: {} with id: {} from peer: {:?}",
                        String::from_utf8_lossy(&message.data),
                        id,
                        peer_id
                    );
                    match json::from_slice::<Json>(&message.data) {
                        Ok(msg) => {
                            lp_post_price_recv(&ctx, msg);
                        },
                        Err(_) => (),
                    }
                },
                _ => {}
            }
        }
    })
}
