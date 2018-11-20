#[macro_use]
extern crate common;
#[macro_use]
extern crate fomat_macros;
extern crate futures;
extern crate fxhash;
#[macro_use]
extern crate gstuff;
extern crate lazy_static;
extern crate serde;
//extern crate serde_derive;
#[macro_use]
extern crate serde_json;
extern crate serde_bencode;
#[macro_use]
extern crate unwrap;

#[doc(hidden)]
pub mod tests;

use common::bits256;
use common::mm_ctx::{from_ctx, MmArc};
use serde::Serialize;
use std::sync::{Arc};

/// The peer-to-peer and connectivity information local to the MM2 instance.
pub struct PeersContext {
}

impl PeersContext {
    /// Obtains a reference to this crate context, creating it if necessary.
    pub fn from_ctx (ctx: &MmArc) -> Result<Arc<PeersContext>, String> {
        Ok (try_s! (from_ctx (&ctx.peers_ctx, move || {
            Ok (PeersContext {})
        })))
    }
}

/// * `netid` - We ignore the peers not matching the `netid`. Usually 0.
/// * `our_public_key` - Aka `LP_mypub25519`. This is our ID, allowing us to be different from other peers
///                      and to prove our identity (ownership of the corresponding private key) to a peer.
/// * `preferred_port` - We'll try to open an UDP endpoint on this port,
///                      which might help if the user configured this port in firewall and forwarding rules.
///                      We're not limited to this port though and might try other ports as well.
/// * `session_id` - Identifies our incarnation, allowing other peers to know if they're talking with the same instance.
pub fn initialize (_ctx: &MmArc, netid: u16, our_public_key: bits256, preferred_port: u16, _session_id: u32) -> Result<(), String> {
    log! ("initialize] netid " (netid) " public key " (our_public_key) " preferred port " (preferred_port));
    if !our_public_key.nonz() {return ERR! ("No public key")}
    Ok(())
}

/// Try to reach a peer and establish connectivity with it while knowing no more than its port and IP.
/// 
/// * `ip` - The public IP where the peer is supposedly listens for incoming connections.
/// * `preferred_port` - The preferred port of the peer.
pub fn investigate_peer (_ctx: &MmArc, ip: &str, preferred_port: u16) -> Result<(), String> {
    log! ("investigate_peer] ip " (ip) " preferred port " (preferred_port));
    Ok(())
}

/// Leave a message for the peer.
/// 
/// The message might be sent across a number of different delivery methods.
/// As of now we're going to send it via the Bittorrent DHT.
/// 
/// Delivery is not guaranteed (to check delivery we should manually get a reply from the peer).
/// 
/// * `to` - Recipient of the message (`LP_mypub25519` of the receiving MM2 instance).
/// * `payload` - Contents of the message.
pub fn send<T: Serialize> (_ctx: &MmArc, _to: bits256, _payload: &T) -> Result<(), String> {
    ERR! ("TBD")
}
