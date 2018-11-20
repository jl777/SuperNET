#[macro_use]
extern crate common;
#[macro_use]
extern crate fomat_macros;
extern crate futures;
extern crate fxhash;
#[macro_use]
extern crate gstuff;
extern crate lazy_static;
extern crate serde_derive;
extern crate serde_json;
#[macro_use]
extern crate unwrap;

#[doc(hidden)]
pub mod tests;

use common::bits256;
use common::mm_ctx::{from_ctx, MmArc};
use std::any::Any;
use std::sync::{Arc, Mutex};

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
pub fn initialize (ctx: &MmArc, netid: u16, our_public_key: bits256, preferred_port: u16, _session_id: u32) -> Result<(), String> {
    log! ("initialize] netid " (netid) " public key " (our_public_key) " preferred port " (preferred_port));
    if !our_public_key.nonz() {return ERR! ("No public key")}
    Ok(())
}

/// Try to reach a peer and establish connectivity with it while knowing no more than its port and IP.
/// 
/// * `ip` - The public IP where the peer is supposedly listens for incoming connections.
/// * `preferred_port` - The preferred port of the peer.
pub fn investigate_peer (ctx: &MmArc, ip: &str, preferred_port: u16) -> Result<(), String> {
    log! ("investigate_peer] ip " (ip) " preferred port " (preferred_port));
    Ok(())
}
