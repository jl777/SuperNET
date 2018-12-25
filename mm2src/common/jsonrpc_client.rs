use futures::Future;
use serde::de::DeserializeOwned;
use serde_json::{self as json, Value as Json};

/// Macro generating functions for RPC requests.
/// Args must implement/derive Serialize trait.
/// Generates params vector from input args, builds the request and sends it.
#[macro_export]
macro_rules! rpc_func {
    ($selff:ident, $method:expr $(, $arg_name:ident)*) => {{
        let mut params = vec![];
        $(
            params.push(try_fus!(json::value::to_value($arg_name)));
        )*
        let request = JsonRpcRequest {
            jsonrpc: $selff.version().into(),
            id: $selff.next_id(),
            method: $method.into(),
            params
        };
        $selff.send_request(request)
    }}
}

/// Serializable RPC request
#[derive(Serialize, Debug, Clone)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: String,
    pub method: String,
    pub params: Vec<Json>,
}

impl JsonRpcRequest {
    pub fn get_id(&self) -> &str {
        &self.id
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct JsonRpcResponse {
    jsonrpc: String,
    id: String,
    #[serde(default)]
    result: Json,
    #[serde(default)]
    error: Json,
}

impl JsonRpcResponse {
    pub fn get_id(&self) -> &str {
        &self.id
    }
}

pub type JsonRpcResponseFut = Box<Future<Item=JsonRpcResponse, Error=String> + Send>;
pub type RpcRes<T> = Box<Future<Item=T, Error=String>>;

pub trait JsonRpcClient {
    fn version(&self) -> &'static str;

    fn next_id(&self) -> String;

    fn transport(&self, request: JsonRpcRequest) -> JsonRpcResponseFut;

    fn send_request<T: DeserializeOwned + Send + 'static>(&self, request: JsonRpcRequest) -> RpcRes<T> {
        Box::new(self.transport(request.clone()).and_then(move |response| -> Result<T, String> {
            if !response.error.is_null() {
                return ERR!("Rpc request {:?} failed with error, response: {:?}",
                        request, response);
            }
            Ok(try_s!(json::from_value(response.result)))
        }))
    }
}
