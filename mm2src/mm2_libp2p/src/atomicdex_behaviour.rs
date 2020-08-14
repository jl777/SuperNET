use crate::request_response::{build_request_response_behaviour, AdexRequestResponse, AdexRequestResponseEvent,
                              AdexResponseChannel, PeerRequest, PeerResponse};
use atomicdex_gossipsub::{Gossipsub, GossipsubConfigBuilder, GossipsubEvent, GossipsubMessage, MessageId, Topic,
                          TopicHash};
use futures::{channel::{mpsc::{unbounded, UnboundedReceiver, UnboundedSender},
                        oneshot},
              future::poll_fn,
              Future, FutureExt, SinkExt, StreamExt};
use libp2p::core::{ConnectedPoint, Multiaddr, Transport};
use libp2p::request_response::{RequestId, RequestResponseMessage};
use libp2p::{identity, swarm::NetworkBehaviourEventProcess, NetworkBehaviour, PeerId};
use std::{collections::hash_map::{DefaultHasher, HashMap},
          hash::{Hash, Hasher},
          net::IpAddr,
          task::{Context, Poll}};

pub type AdexCmdTx = UnboundedSender<AdexBehaviorCmd>;
pub type AdexEventRx = UnboundedReceiver<AdexBehaviourEvent>;
use log::{debug, error};

#[cfg(test)] mod tests;

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
    /// Request peers until a response is received.
    /// Note the request will be sent to relays only because they subscribe on all topics.
    RequestAnyPeer {
        req: Vec<u8>,
        response_tx: oneshot::Sender<AdexResponse>,
    },
    GetPeersInfo {
        result_tx: oneshot::Sender<HashMap<String, Vec<String>>>,
    },
    GetGossipMesh {
        result_tx: oneshot::Sender<HashMap<String, Vec<String>>>,
    },
}

/// The structure is the same as `PeerResponse`,
/// but is used to prevent `PeerResponse` from being used outside the network implementation.
#[derive(Debug, Eq, PartialEq)]
pub enum AdexResponse {
    Ok { response: Vec<u8> },
    None,
    Err { error: String },
}

impl From<PeerResponse> for AdexResponse {
    fn from(res: PeerResponse) -> Self {
        match res {
            PeerResponse::Ok { res } => AdexResponse::Ok { response: res },
            PeerResponse::None => AdexResponse::None,
            PeerResponse::Err { err } => AdexResponse::Err { error: err },
        }
    }
}

impl From<AdexResponse> for PeerResponse {
    fn from(res: AdexResponse) -> Self {
        match res {
            AdexResponse::Ok { response } => PeerResponse::Ok { res: response },
            AdexResponse::None => PeerResponse::None,
            AdexResponse::Err { error } => PeerResponse::Err { err: error },
        }
    }
}

/// The structure consists of some GossipsubEvent and RequestResponse events.
/// It is used to prevent the network events from being used outside the network implementation.
#[derive(Debug)]
pub enum AdexBehaviourEvent {
    /// A message has been received.
    /// Derived from GossipsubEvent.
    Message(PeerId, MessageId, GossipsubMessage),
    /// A remote subscribed to a topic.
    /// Derived from GossipsubEvent.
    Subscribed {
        /// Remote that has subscribed.
        peer_id: PeerId,
        /// The topic it has subscribed to.
        topic: TopicHash,
    },
    /// A remote peer sent a request and waits for a response.
    PeerRequest {
        /// Remote that sent this request.
        peer_id: PeerId,
        /// The serialized data.
        request: Vec<u8>,
        /// A response should be passed through the oneshot channel.
        response_tx: oneshot::Sender<AdexResponse>,
    },
}

/// AtomicDEX libp2p Network behaviour implementation
#[derive(NetworkBehaviour)]
pub struct AtomicDexBehavior {
    #[behaviour(ignore)]
    event_tx: UnboundedSender<AdexBehaviourEvent>,
    #[behaviour(ignore)]
    mesh_update_txs: HashMap<TopicHash, Vec<oneshot::Sender<()>>>,
    #[behaviour(ignore)]
    spawn_fn: fn(Box<dyn Future<Output = ()> + Send + Unpin + 'static>) -> (),
    #[behaviour(ignore)]
    cmd_rx: UnboundedReceiver<AdexBehaviorCmd>,
    #[behaviour(ignore)]
    pending_requests: HashMap<RequestId, oneshot::Sender<AdexResponse>>,
    #[behaviour(ignore)]
    pending_responses: PendingResponses,
    gossipsub: Gossipsub,
    request_response: AdexRequestResponse,
}

/// Vector of pair:
/// first - a receiver that is used to receive a response from the business logic.
/// second - a channel for sending a response to an inbound request.
type PendingResponses = Vec<(oneshot::Receiver<AdexResponse>, AdexResponseChannel)>;

impl AtomicDexBehavior {
    fn notify_on_event<T: Send + 'static>(&self, mut tx: UnboundedSender<T>, event: T) {
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
            AdexBehaviorCmd::RequestAnyPeer { req, response_tx } => {
                // temporary get a first peer to send to him the request
                if let Some(peer_id) = self
                    .gossipsub
                    .get_peers_connections()
                    .into_iter()
                    .next()
                    .map(|(peer_id, _connection_points)| peer_id)
                {
                    let request = PeerRequest { req };
                    debug!("Send request {:?} to {:?}", request, peer_id);
                    let request_id = self.request_response.send_request(&peer_id, request);
                    // send_request() must return a unique request id that cannot be in the pending_requests
                    assert!(self.pending_requests.insert(request_id, response_tx).is_none());
                }
                // else the response_tx will be dropped
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
        }
    }

    fn process_request(&mut self, peer_id: PeerId, request: PeerRequest, channel: AdexResponseChannel) {
        debug!("Process request {:?} from {:?}", request, channel);
        // The response_tx is used by the request handler to send a response to `AtomicDexBehavior`
        // and the response_rx is used by the `AtomicDexBehavior` to forward a response through the network.
        let (response_tx, response_rx) = oneshot::channel();

        self.pending_responses.push((response_rx, channel));
        let event = AdexBehaviourEvent::PeerRequest {
            peer_id,
            request: request.req,
            response_tx,
        };
        self.notify_on_event(self.event_tx.clone(), event)
    }

    fn process_response(&mut self, request_id: RequestId, response: PeerResponse) {
        debug!("Process response {:?} on request {:?}", response, request_id);
        if let Some(tx) = self.pending_requests.remove(&request_id) {
            if tx.send(response.into()).is_err() {
                error!("Receiver is dropped");
            }
        }
    }

    fn poll_pending_responses(&mut self, cx: &mut Context) {
        // TODO optimize this
        let mut pending_responses = PendingResponses::new();
        std::mem::swap(&mut self.pending_responses, &mut pending_responses);

        for (mut response_rx, channel) in pending_responses.into_iter() {
            match response_rx.poll_unpin(cx) {
                // received a response, forward it through the network
                Poll::Ready(Ok(response)) => self.request_response.send_response(channel, response.into()),
                // the channel was closed, send an error through the network
                Poll::Ready(Err(e)) => {
                    println!("Error on poll channel {:?}. Send an error to {:?}", e, channel);
                    let response = PeerResponse::Err { err: e.to_string() };
                    self.request_response.send_response(channel, response)
                },
                // push the pending response info back to the self container
                Poll::Pending => self.pending_responses.push((response_rx, channel)),
            }
        }
    }
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for AtomicDexBehavior {
    fn inject_event(&mut self, event: GossipsubEvent) {
        let adex_event = match event {
            GossipsubEvent::Message(peer_id, message_id, message) => {
                AdexBehaviourEvent::Message(peer_id, message_id, message)
            },
            GossipsubEvent::Subscribed { peer_id, topic } => AdexBehaviourEvent::Subscribed { peer_id, topic },
            GossipsubEvent::MeshUpdated { topic, .. } => {
                if let Some(txs) = self.mesh_update_txs.remove(&topic) {
                    for tx in txs {
                        if tx.send(()).is_err() {
                            println!("Receiver is dropped");
                        }
                    }
                }
                return;
            },
            _ => return,
        };
        self.notify_on_event(self.event_tx.clone(), adex_event);
    }
}

impl NetworkBehaviourEventProcess<AdexRequestResponseEvent> for AtomicDexBehavior {
    fn inject_event(&mut self, event: AdexRequestResponseEvent) {
        debug!("inject_event");
        let (peer_id, message) = match event {
            AdexRequestResponseEvent::Message { peer, message } => (peer, message),
            AdexRequestResponseEvent::InboundFailure { error, .. } => {
                error!("Error on inbound {:?}", error);
                return;
            },
            AdexRequestResponseEvent::OutboundFailure { error, .. } => {
                error!("Error on outbound {:?}", error);
                return;
            },
        };

        debug!("Receive the message {:?}", message);
        match message {
            RequestResponseMessage::Request { request, channel } => self.process_request(peer_id, request, channel),
            RequestResponseMessage::Response { request_id, response } => self.process_response(request_id, response),
        }
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
) -> (UnboundedSender<AdexBehaviorCmd>, AdexEventRx, PeerId) {
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
        .map(|addr| parse_relay_address(addr, port))
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

        // build a request-response network behaviour
        let request_response = build_request_response_behaviour();

        let pending_requests = HashMap::new();
        let pending_responses = Vec::new();

        let adex_behavior = AtomicDexBehavior {
            event_tx,
            mesh_update_txs: HashMap::new(),
            spawn_fn,
            cmd_rx,
            pending_requests,
            pending_responses,
            gossipsub,
            request_response,
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

        swarm.poll_pending_responses(cx);

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

/// The addr is expected to be in "/ip{X}/{IP}/{PORT}" format
#[cfg(test)]
fn parse_relay_address(addr: String, _port: u16) -> Multiaddr { addr.parse().unwrap() }

/// The addr is expected to be an IP of the relay
#[cfg(not(test))]
fn parse_relay_address(addr: String, port: u16) -> Multiaddr { format!("/ip4/{}/tcp/{}", addr, port).parse().unwrap() }
