use bitcoin_rpc::v1::types::{H256 as H256Json};
use bytes::{BufMut, BytesMut};
use common::{CORE, Timeout};
use futures::{Async, Future, Poll, Sink};
use futures::sync::mpsc;
use hashbrown::HashMap;
use serde_json::{self as json, Value as Json};
use std::{io, thread};
use std::net::{ToSocketAddrs, SocketAddr};
use std::sync::{Mutex, Arc};
use std::time::Duration;
use tokio::codec::{Encoder, Decoder};
use tokio::net::TcpStream;
use tokio::prelude::*;

#[derive(Debug, Deserialize)]
struct ElectrumUnspent {
    height: Option<u64>,
    tx_hash: H256Json,
    tx_pos: u32,
    value: u64,
}

/// Serializable RPC request
#[derive(Serialize, Debug, Clone)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: String,
    pub method: String,
    pub params: Vec<Json>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: String,
    pub result: Option<Json>,
    pub error: Option<Json>,
}

pub fn spawn_electrum(
    addr: &str,
    arc: Arc<Mutex<HashMap<String, RpcResponse>>>,
) -> Box<Future<Item=mpsc::Sender<Vec<u8>>, Error=String>> {
    let mut addr = try_fus!(addr.to_socket_addrs());

    Box::new(electrum_connect(&addr.next().unwrap(), arc).map_err(|e| ERRL!("{}", e)))
}

pub struct ElectrumClient {
    pub results: Arc<Mutex<HashMap<String, RpcResponse>>>,
    pub senders: Vec<mpsc::Sender<Vec<u8>>>,
}

impl ElectrumClient {
    pub fn new() -> ElectrumClient {
        ElectrumClient {
            results: Arc::new(Mutex::new(HashMap::new())),
            senders: vec![],
        }
    }

    pub fn add_server(&mut self, addr: &str) -> Result<(), String> {
        // TODO Have to implement this function as synchronous using .wait to avoid wrapping senders in Mutex/Arc.
        // Consider refactoring when async/await is released.
        let sender = try_s!(spawn_electrum(addr, self.results.clone()).wait());
        self.senders.push(sender);
        Ok(())
    }

    pub fn send_request(&self, request: RpcRequest) -> impl Future<Item=RpcResponse, Error=String> {
        electrum_request_multi(request, self.senders.clone(), self.results.clone())
    }
}

fn rx_to_stream(rx: mpsc::Receiver<Vec<u8>>) -> impl Stream<Item = Vec<u8>, Error = io::Error> {
    rx.map_err(|_| panic!("errors not possible on rx"))
}

fn electrum_connect(
    addr: &SocketAddr,
    arc: Arc<Mutex<HashMap<String, RpcResponse>>>,
) -> impl Future<Item=mpsc::Sender<Vec<u8>>, Error=String> {
    let tcp = TcpStream::connect(addr);

    let (tx, rx) = mpsc::channel(0);
    let rx = rx_to_stream(rx);

    tcp
        .map(move |stream| {
            let (sink, stream) = Bytes.framed(stream).split();

            thread::spawn(|| {
                CORE.spawn(|_| {
                    rx.forward(sink).then(|result| {
                        if let Err(e) = result {
                            log!("failed to write to socket " [e])
                        }
                        Ok(())
                    })
                })
            });

            thread::spawn(||
                CORE.spawn(|_| {
                    stream
                        .for_each(move |chunk| {
                            match json::from_slice::<RpcResponse>(&chunk) {
                                Ok(json) => {
                                    (*arc.lock().unwrap()).insert(json.id.clone(), json);
                                },
                                Err(e) => {
                                    log!([e])
                                }
                            };
                            futures::future::ok(())
                        })
                        .map_err(|e| {
                            log!([e]);
                            ()
                        })
                })
            );
            tx
        })
        .map_err(|e| ERRL!("{}", e))
}

/// A simple `Codec` implementation that reads buffer until newline according to Electrum protocol specification:
/// https://electrumx.readthedocs.io/en/latest/protocol-basics.html#message-stream
///
/// Implementation adopted from https://github.com/tokio-rs/tokio/blob/master/examples/connect.rs#L84
pub struct Bytes;

impl Decoder for Bytes {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<BytesMut>> {
        let len = buf.len();
        if len > 0 && buf[len - 1] == '\n' as u8 {
            Ok(Some(buf.split_to(len)))
        } else {
            Ok(None)
        }
    }
}

impl Encoder for Bytes {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn encode(&mut self, data: Vec<u8>, buf: &mut BytesMut) -> io::Result<()> {
        buf.extend_from_slice(&data);
        Ok(())
    }
}

struct ElectrumRequestFut {
    context: Arc<Mutex<HashMap<String, RpcResponse>>>,
    request_id: String,
}

impl Future for ElectrumRequestFut {
    type Item = RpcResponse;
    type Error = String;

    fn poll(&mut self) -> Poll<RpcResponse, String> {
        loop {
            let elem = try_s!(self.context.lock()).remove(&self.request_id);
            if let Some(res) = elem {
                return Ok(Async::Ready(res))
            } else {
                let task = futures::task::current();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(200));
                    task.notify();
                });
                return Ok(Async::NotReady)
            }
        }
    }
}

fn electrum_request(
    request: RpcRequest,
    tx: mpsc::Sender<Vec<u8>>,
    context: Arc<Mutex<HashMap<String, RpcResponse>>>
) -> Box<Future<Item=RpcResponse, Error=String>> {
    let mut json = try_fus!(json::to_string(&request));
    // Electrum request and responses must end with \n
    // https://electrumx.readthedocs.io/en/latest/protocol-basics.html#message-stream
    json.push('\n');

    let request_id = request.id.clone();
    let send_fut = Box::new(tx.send(json.into_bytes())
        .map_err(|e| ERRL!("{}", e))
        .and_then(move |res| -> ElectrumRequestFut {
            ElectrumRequestFut {
                request_id,
                context,
            }
        }));

    // 5 seconds should be enough to detect that there is some issue with connection
    Box::new(Timeout::new(send_fut, Duration::from_secs(5)))
}

fn electrum_request_multi(
    request: RpcRequest,
    senders: Vec<mpsc::Sender<Vec<u8>>>,
    ctx: Arc<Mutex<HashMap<String, RpcResponse>>>
) -> impl Future<Item=RpcResponse, Error=String> {
    let futures = senders.iter().map(|sender| electrum_request(request.clone(), sender.clone(), ctx.clone()));

    futures::future::select_ok(futures)
        .map(|(result, _)| {
            result
        })
        .map_err(|e| ERRL!("{:?}", e))
}

#[test]
fn test_electrum_ping() {
    let mut client = ElectrumClient::new();
    client.add_server("electrum1.cipig.net:10022").unwrap();
    client.add_server("electrum2.cipig.net:10022").unwrap();
    client.add_server("electrum3.cipig.net:10022").unwrap();

    let request = RpcRequest {
        jsonrpc: "2.0".into(),
        id: "1".into(),
        method: "server.ping".into(),
        params: vec![]
    };
    client.send_request(request).wait().unwrap();
}
