use base64;
use crdts::{CvRDT, CmRDT, Map, Orswot};
use futures::{self, Future};
use gstuff::{netstring, now_float};
use hashbrown::hash_map::{Entry, HashMap};
use hyper::{Request, Body};
use hyper::rt::{Stream};
use hyper::service::Service;
use serde_bytes::ByteBuf;
use serde_json::{self as json, Value as Json};
use std::io::Write;
use std::net::{SocketAddr};
use std::sync::{Arc, Mutex};
use std::str::from_utf8_unchecked;
use tokio_core::net::TcpListener;

use crate::common::{bits256, rpc_response, slurp_req, HyRes, CORE, HTTP};
use crate::common::mm_ctx::{from_ctx, MmArc, MmWeak};

/// Data belonging to this module and owned by the MM2 instance.
pub struct HttpFallbackContext {
    maps: Mutex<HashMap<Vec<u8>, RepStrMap>>
}

impl HttpFallbackContext {
    /// Obtains a reference to this mod context, creating it if necessary.
    pub fn from_ctx (ctx: &MmArc) -> Result<Arc<HttpFallbackContext>, String> {
        Ok (try_s! (from_ctx (&ctx.http_fallback_ctx, move || {
            Ok (HttpFallbackContext {
                maps: Mutex::new (HashMap::new())
            })
        })))
    }
}

fn fetch_map_impl (ctx: MmWeak, req: Request<Body>) -> HyRes {
    let f = req.into_body().concat2().then (move |body| -> HyRes {
        let body = try_fus! (body);
        let id = body.to_vec();

        let ctx = try_fus! (MmArc::from_weak (&ctx) .ok_or ("MM stopping"));
        let hfctx = try_fus! (HttpFallbackContext::from_ctx (&ctx));
        let maps = try_fus! (hfctx.maps.lock());
        if let Some (mapʰ) = maps.get (&id) {
            let mapʳ = try_fus! (json::to_string (&mapʰ));
            rpc_response (200, mapʳ)
        } else {
            let map = RepStrMap::new();
            let map = try_fus! (json::to_string (&map));
            rpc_response (200, map)
        }
    });
    Box::new (f)
}

fn merge_map_impl (ctx: MmWeak, req: Request<Body>) -> HyRes {
    let f = req.into_body().concat2().then (move |body| -> HyRes {
        let body = try_fus! (body);
        let buf = body.to_vec();
        let (id, mapˢ) = try_fus! (netstring (&buf));
        let map: RepStrMap = try_fus! (json::from_slice (mapˢ));

        let ctx = try_fus! (MmArc::from_weak (&ctx) .ok_or ("MM stopping"));
        let hfctx = try_fus! (HttpFallbackContext::from_ctx (&ctx));
        let mut maps = try_fus! (hfctx.maps.lock());
        if let Some (mapʰ) = maps.get_mut (id) {
            // NB: Diverging clocks coming from the same actor might lead to an empty map.
            // cf. https://github.com/rust-crdt/rust-crdt/blob/86c7c5601b6b4c4451e1c6840dc1481716ae1433/src/traits.rs#L14
            mapʰ.merge (map);
            let mapʳ = try_fus! (json::to_string (&mapʰ));
            rpc_response (200, mapʳ)
        } else {
            maps.insert (id.into(), map);
            rpc_response (200, mapˢ.to_vec())
        }
    });
    Box::new (f)
}

/// Creates a Hyper Future that would run the HTTP fallback server.
pub fn new_http_fallback (ctx: MmWeak, addr: SocketAddr) -> Result<Box<Future<Item=(), Error=()>+Send>, String> {
    let listener = try_s! (TcpListener::bind2 (&addr));

    struct RpcService {ctx: MmWeak}
    impl Service for RpcService {
        type ReqBody = Body; type ResBody = Body; type Error = String; type Future = HyRes;
        fn call (&mut self, req: Request<Body>) -> HyRes {
            let path = req.uri().path();
            if path == "/fallback/fetch_map" {
                fetch_map_impl (self.ctx.clone(), req)
            } else if path == "/fallback/merge_map" {
                merge_map_impl (self.ctx.clone(), req)
            } else if path == "/test_ip" {  // Helps `fn test_ip` to check the IP availability.
                rpc_response (200, "k")
            } else {
                rpc_response (404, "unknown path")
            }
        }
    }
    let server = listener.incoming().for_each (move |(socket, _my_sock)| {
        let ctx = ctx.clone();
        CORE.spawn (move |_| HTTP
                .serve_connection (socket, RpcService {ctx})
                .map(|_| ())
                .map_err (|err| log! ({"{}", err})));
        Ok(())
    }) .map_err (|err| log! ({"accept error: {}", err}));

    Ok (Box::new (server))
}

/// CRDT clocks are tracked separately for each actor ID.  
/// If two different clients with the same actor ID are trying simultaneously to change a map
/// then one of the change sets might be ignored due to the clock being in the past.
pub type UniqueActorId = u64;

/// CRDT map from string to string.  
/// (The keys and values must be strings in order for the JSON seriazliation to work).
pub type RepStrMap = Map<String, Orswot<String, UniqueActorId>, UniqueActorId>;

/// As of today the replicated map doesn't provide an entries API,
/// but we can get the list of entries from the JSON representation.
pub fn rep_keys (rep_map: &RepStrMap) -> Result<Vec<String>, String> {
    let jsmap = try_s! (json::to_string (rep_map));
    let jsmap: Json = try_s! (json::from_str (&jsmap));
    if let Some (entries) = jsmap["entries"].as_object() {
        Ok (entries.keys().cloned().collect())
    } else {Ok (Vec::new())}
}

fn fallback_url (addr: &SocketAddr, method: &str) -> String {
    fomat! (
        "http" if addr.port() == 443 {'s'} "://"
        (addr.ip())
        if addr.port() != 80 && addr.port() != 443 {':' (addr.port())}
        "/fallback/" (method)
    )
}

/// Fetches a CRDT map stored on the HTTP fallback server.
/// 
/// * `addr` - The address of the HTTP fallback server.
///            The port should be 80 or 443 as this should help the server to function
///            even with the most restrictive internet operators.
pub fn fetch_map (addr: &SocketAddr, id: Vec<u8>) -> Box<Future<Item=RepStrMap, Error=String> + Send> {
    let url = fallback_url (addr, "fetch_map");
    let request = try_fus! (Request::builder()
        .method("POST")
        .uri (url)
        .body (Body::from (id)));
    let f = slurp_req (request);
    let f = f.and_then (|(status, _headers, body)| -> Result<RepStrMap, String> {
        if status.as_u16() != 200 {return ERR! ("fetch_map not 200")}
        let map: RepStrMap = try_s! (json::from_slice (&body));
        Ok (map)
    });
    Box::new (f)
}

/// Merges a CRDT map with the version stored on the HTTP fallback server.
/// 
/// * `addr` - The address of the HTTP fallback server.
///            The port should be 80 or 443 as this should help the server to function
///            even with the most restrictive internet operators.
/// 
/// Returns a fresh version of the map which is provided by the server after the merge.
pub fn merge_map (addr: &SocketAddr, id: Vec<u8>, map: &RepStrMap)
-> Box<Future<Item=RepStrMap, Error=String> + Send> {
    let url = fallback_url (addr, "merge_map");
    let mut map = try_fus! (json::to_vec (map));

    let mut buf = Vec::with_capacity (id.len() + map.len() + 9);
    try_fus! (write! (&mut buf, "{}:{},", id.len(), unsafe {from_utf8_unchecked (&id)}));
    buf.append (&mut map);

    let request = try_fus! (Request::builder()
        .method("POST")
        .uri (url)
        .body (Body::from (buf)));
    let f = slurp_req (request);
    let f = f.and_then (|(status, _headers, body)| -> Result<RepStrMap, String> {
        if status.as_u16() != 200 {return ERR! ("merge_map not 200")}
        let map: RepStrMap = try_s! (json::from_slice (&body));
        Ok (map)
    });
    Box::new (f)
}

/// Several things should be tracked whenever we are using HTTP fallback to reach a target node.
#[derive(Default)]
pub struct HttpFallbackTargetTrack {
    /// Keeping the previous versions of the HTTP fallback maps
    /// in order for the consequent map updates to maintain the total ordering of our clock.
    /// cf. https://github.com/rust-crdt/rust-crdt/blob/86c7c5601b6b4c4451e1c6840dc1481716ae1433/src/traits.rs#L16
    rep_map: RepStrMap,
    /// Time when the latest store operation started.
    pub last_store: f64
}

/// Plugged into `fn transmit` to send the chunks via HTTP fallback when necessary.
pub fn hf_transmit (pctx: &super::PeersContext, hf_addr: Option<SocketAddr>, our_public_key: bits256,
                    seed: bits256, package: &mut super::Package) -> Result<(), String> {
    let hf_addr = match hf_addr {Some (a) => a, None => return Ok(())};

    let mut deliver_to_seed = HashMap::new();  // Things we want delivered as of now.
    let now = now_float();
    for (payload, meta) in package.payloads.iter_mut() {
        let fallback = match package.fallback {Some (sec) => sec, None => continue};
        if now - package.scheduled_at < fallback.get() as f64 {continue}
        let salt = if let Some (ref salt) = payload.salt {salt.clone()} else {continue};
        if payload.chunk.is_none() {continue}
        deliver_to_seed.insert (salt, (payload, meta));
    }
    let mut http_fallback_maps = try_s! (pctx.http_fallback_maps.lock());
    let mut trackⁱ = http_fallback_maps.entry (seed);
    let track = match trackⁱ {
        Entry::Occupied (ref mut oe) => oe.get_mut(),
        Entry::Vacant (ve) => {
            if deliver_to_seed.is_empty() {
                return Ok(())
            } else {
                ve.insert (HttpFallbackTargetTrack::default())
            }
        }
    };

    // Synchronize the replicated map with the `deliver_to_seed`.

    let unique_actor_id = 1;
    let mut changed = false;

    let rep_keys = try_s! (rep_keys (&track.rep_map));
    for key in rep_keys {
        let salt = ByteBuf::from (try_s! (base64::decode_config (&key, base64::STANDARD_NO_PAD)));
        if !deliver_to_seed.contains_key (&salt) {
            track.rep_map.apply (track.rep_map.rm (key, track.rep_map.len().derive_rm_ctx()));
            changed = true;
        }
    }

    for (salt, (payload, _meta)) in deliver_to_seed {
        // We're only sending our own packages here.
        assert_eq! (&payload.from[..], unsafe {&our_public_key.bytes[..]});

        let salt = base64::encode_config (&salt, base64::STANDARD_NO_PAD);
        let chunk = if let Some (ref chunk) = payload.chunk {
            base64::encode_config (chunk, base64::STANDARD_NO_PAD)
        } else {continue};
        let has_chunk = match track.rep_map.get (&salt) .val.map (|v| v.read().val) {
            None => false,
            Some (set) => set.contains (&chunk)
        };

        if !has_chunk {
            track.rep_map.apply (
                track.rep_map.update (
                    salt,
                    track.rep_map.len().derive_add_ctx (unique_actor_id),
                    |set, ctx| set.add (chunk, ctx)
                )
            );
            changed = true
        }
    }

    // We should keep storing the map even if we have stored it before, to account for server restarts.
    let now = now_float();
    let refresh = if track.last_store > 0. {now - track.last_store > 10.} else {false};
    if !changed && !refresh {return Ok(())}

log! ("transmit] TBD, time to use the HTTP fallback...");

    let mut hf_id = Vec::with_capacity (unsafe {seed.bytes.len() + 1 + our_public_key.bytes.len()});
    hf_id.extend_from_slice (unsafe {&seed.bytes});
    hf_id.push (b'<');
    hf_id.extend_from_slice (unsafe {&our_public_key.bytes});
    let merge_f = merge_map (&hf_addr, hf_id, &track.rep_map);
    let merge_f = merge_f.then (|r| -> Result<(), ()> {
        let _merged_rep_map = match r {
            Ok (r) => r,
            Err (err) => {log! ("manage_http_fallback] merge_map error: " (err)); return Err(())}
        };
        Ok(())
    });
    CORE.spawn (|_| merge_f);
    track.last_store = now;

    Ok(())
}
