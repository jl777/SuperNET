use crate::{decode_message, encode_message};
use async_trait::async_trait;
use core::iter;
use futures::io::{AsyncRead, AsyncWrite};
use libp2p::core::upgrade::{read_one, write_one};
use libp2p::request_response::{ProtocolName, ProtocolSupport, RequestResponse, RequestResponseCodec,
                               RequestResponseConfig, RequestResponseEvent, ResponseChannel};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io;

pub type AdexRequestResponse = RequestResponse<Codec>;
pub type AdexRequestResponseEvent = RequestResponseEvent<PeerRequest, PeerResponse>;
pub type AdexResponseChannel = ResponseChannel<PeerResponse>;

/// Build a request-response network behaviour.
pub fn build_request_response_behaviour() -> AdexRequestResponse {
    let config = RequestResponseConfig::default();
    let protocol = iter::once((Protocol::Version1, ProtocolSupport::Full));
    RequestResponse::new(Codec, protocol, config)
}

#[derive(Clone)]
pub struct Codec;

#[derive(Debug, Clone)]
pub enum Protocol {
    Version1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeerRequest {
    pub req: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum PeerResponse {
    Ok { res: Vec<u8> },
    None,
    Err { err: String },
}

macro_rules! try_io {
    ($e: expr) => {
        match $e {
            Ok(ok) => ok,
            Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidData, err)),
        }
    };
}

impl ProtocolName for Protocol {
    fn protocol_name(&self) -> &[u8] {
        match self {
            Protocol::Version1 => b"/request-response/1",
        }
    }
}

#[async_trait]
impl RequestResponseCodec for Codec {
    type Protocol = Protocol;
    type Request = PeerRequest;
    type Response = PeerResponse;

    async fn read_request<T>(&mut self, _protocol: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_to_end(io).await
    }

    async fn read_response<T>(&mut self, _protocol: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_to_end(io).await
    }

    async fn write_request<T>(&mut self, _protocol: &Self::Protocol, io: &mut T, req: Self::Request) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_all(io, &req).await
    }

    async fn write_response<T>(&mut self, _protocol: &Self::Protocol, io: &mut T, res: Self::Response) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_all(io, &res).await
    }
}

async fn read_to_end<T, M>(io: &mut T) -> io::Result<M>
where
    T: AsyncRead + Unpin + Send,
    M: DeserializeOwned,
{
    match read_one(io, 1024).await {
        Ok(data) => Ok(try_io!(decode_message(&data))),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    }
}

async fn write_all<T, M>(io: &mut T, msg: &M) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    M: Serialize,
{
    let data = try_io!(encode_message(msg));
    write_one(io, data).await
}
