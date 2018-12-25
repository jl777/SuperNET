use bitcoin_rpc::v1::types::{H256 as H256Json};
use bytes::{BufMut, BytesMut};
use common::{CORE, Timeout};
use common::jsonrpc_client::{JsonRpcClient, JsonRpcResponseFut, JsonRpcRequest, JsonRpcResponse, RpcRes};
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

pub fn spawn_electrum(
    addr: &str,
    arc: Arc<Mutex<HashMap<String, JsonRpcResponse>>>,
) -> Box<Future<Item=mpsc::Sender<Vec<u8>>, Error=String>> {
    let mut addr = try_fus!(addr.to_socket_addrs());

    Box::new(electrum_connect(&addr.next().unwrap(), arc).map_err(|e| ERRL!("{}", e)))
}

pub struct ElectrumClient {
    results: Arc<Mutex<HashMap<String, JsonRpcResponse>>>,
    senders: Vec<mpsc::Sender<Vec<u8>>>,
    next_id: Mutex<u64>,
}

impl JsonRpcClient for ElectrumClient {
    fn version(&self) -> &'static str { "2.0" }

    fn next_id(&self) -> String {
        let mut next = unwrap!(self.next_id.lock());
        *next += 1;
        next.to_string()
    }

    fn transport(&self, request: JsonRpcRequest) -> JsonRpcResponseFut {
        Box::new(electrum_request_multi(request, self.senders.clone(), self.results.clone()))
    }
}

impl ElectrumClient {
    pub fn new() -> ElectrumClient {
        ElectrumClient {
            results: Arc::new(Mutex::new(HashMap::new())),
            senders: vec![],
            next_id: Mutex::new(0),
        }
    }

    pub fn add_server(&mut self, addr: &str) -> Result<(), String> {
        // TODO Have to implement this function as synchronous using .wait to avoid wrapping senders in Mutex/Arc.
        // Consider refactoring when async/await is released.
        let sender = try_s!(spawn_electrum(addr, self.results.clone()).wait());
        self.senders.push(sender);
        Ok(())
    }

    pub fn server_ping(&self) -> RpcRes<()> {
        rpc_func!(self, "server.ping")
    }
}

fn rx_to_stream(rx: mpsc::Receiver<Vec<u8>>) -> impl Stream<Item = Vec<u8>, Error = io::Error> {
    rx.map_err(|_| panic!("errors not possible on rx"))
}

fn electrum_connect(
    addr: &SocketAddr,
    arc: Arc<Mutex<HashMap<String, JsonRpcResponse>>>,
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
                            match json::from_slice::<JsonRpcResponse>(&chunk) {
                                Ok(json) => {
                                    (*arc.lock().unwrap()).insert(json.get_id().to_string(), json);
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
    context: Arc<Mutex<HashMap<String, JsonRpcResponse>>>,
    request_id: String,
}

impl Future for ElectrumRequestFut {
    type Item = JsonRpcResponse;
    type Error = String;

    fn poll(&mut self) -> Poll<JsonRpcResponse, String> {
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
    request: JsonRpcRequest,
    tx: mpsc::Sender<Vec<u8>>,
    context: Arc<Mutex<HashMap<String, JsonRpcResponse>>>
) -> JsonRpcResponseFut {
    let mut json = try_fus!(json::to_string(&request));
    // Electrum request and responses must end with \n
    // https://electrumx.readthedocs.io/en/latest/protocol-basics.html#message-stream
    json.push('\n');

    let request_id = request.get_id().to_string();
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
    request: JsonRpcRequest,
    senders: Vec<mpsc::Sender<Vec<u8>>>,
    ctx: Arc<Mutex<HashMap<String, JsonRpcResponse>>>
) -> JsonRpcResponseFut {
    let futures = senders.iter().map(|sender| electrum_request(request.clone(), sender.clone(), ctx.clone()));

    Box::new(futures::future::select_ok(futures)
        .map(|(result, _)| {
            result
        })
        .map_err(|e| ERRL!("{:?}", e)))
}

#[test]
fn test_electrum_ping() {
    let mut client = ElectrumClient::new();
    client.add_server("electrum1.cipig.net:10022").unwrap();
    client.add_server("electrum2.cipig.net:10022").unwrap();
    client.add_server("electrum3.cipig.net:10022").unwrap();

    client.server_ping().wait().unwrap();
}
