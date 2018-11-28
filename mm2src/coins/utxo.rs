/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/
//
//  utxo.rs
//  marketmaker
//
//  Copyright © 2017-2018 SuperNET. All rights reserved.
//

use base64::{encode_config as base64_encode, URL_SAFE};
use bitcoin_rpc::v1::types::{H256 as H256Json, Bytes as BytesJson, Transaction as RpcTransaction};
use bitcrypto::{dhash160};
use byteorder::{LittleEndian, WriteBytesExt};
use chain::{TransactionOutput, TransactionInput, OutPoint, Transaction as UtxoTransaction};
use chain::constants::{SEQUENCE_FINAL};
use common::{slurp_req, dstr};
use common::log::{LogState, StatusHandle};
use futures::{Async, Future, Poll, Stream};
use gstuff::now_ms;
use hex::FromHex;
use hyper::{Body, Request, StatusCode};
use hyper::header::{AUTHORIZATION};
use keys::{KeyPair, Network, Private, Public, Address, Secret, Type};
use keys::bytes::Bytes;
use keys::generator::{Random, Generator};
use primitives::hash::H256;
use script::{Opcode, Builder, Script, TransactionInputSigner, UnsignedTransactionInput, SignatureVersion};
use serialization::serialize;
use serde::de::DeserializeOwned;
use serde_json::{self as json, Value as Json};
use sha2::{Sha256, Digest};
use std::any::Any;
use std::cmp::Ordering;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use super::{Transaction, ExchangeableCoin, BoxedTx, BoxedTxFut};
use tokio_timer::{Interval, Timer};

#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct UnspentOutput {
    pub txid: H256Json,
    pub vout: u32,
    pub address: String,
    pub account: String,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: BytesJson,
    pub amount: f64,
    pub confirmations: u64,
    pub spendable: bool
}

#[derive(Clone, Deserialize, Debug)]
pub struct ValidateAddressRes {
    #[serde(rename = "isvalid")]
    pub is_valid: bool,
    pub address: String,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: BytesJson,
    #[serde(rename = "segid")]
    pub seg_id: Option<u32>,
    #[serde(rename = "ismine")]
    pub is_mine: bool,
    #[serde(rename = "iswatchonly")]
    pub is_watch_only: bool,
    #[serde(rename = "isscript")]
    pub is_script: bool,
    pub account: Option<String>,
}

/// Extended UTXO transaction, contains redeem script to spend p2sh output
/// Every transaction should contain separate redeem script for every p2sh output
/// However as MM creates only 1 p2sh output per every swap transaction
/// we can use single redeem script at least for now.
#[derive(Debug)]
struct ExtendedUtxoTx {
    transaction: UtxoTransaction,
    redeem_script: Bytes,
}

impl ExtendedUtxoTx {
    fn new() -> Self {
        ExtendedUtxoTx {
            transaction: UtxoTransaction {
                version: 1,
                lock_time: 0,
                inputs: vec![],
                outputs: vec![]
            },
            redeem_script: vec![].into(),
        }
    }
}

/// Serializable RPC request
#[derive(Serialize, Debug)]
struct UtxoRpcRequest {
    jsonrpc: String,
    id: String,
    method: String,
    params: Vec<Json>,
}

impl UtxoRpcRequest {
    /// JSON RPC v1 request
    pub fn new_v1(method: String, params: Vec<Json>) -> UtxoRpcRequest {
        UtxoRpcRequest {
            jsonrpc: "1.0".to_owned(),
            id: "test".to_owned(),
            method,
            params,
        }
    }
}

type RpcRes<T> = Box<Future<Item=T, Error=String> + Send>;

/// Sends RPC request, returns a Future.
/// Errors in case of non-200 HTTP status code or if JSON rpc response has non-null error.
fn json_rpc_v1_request<T: DeserializeOwned + Send + 'static>(
    uri: &str,
    auth: &str,
    request: UtxoRpcRequest
) -> RpcRes<T> {
    let request_body = try_fus!(json::to_string(&request));
    let http_request = try_fus!(
        Request::builder()
                .method("POST")
                .header(
                    AUTHORIZATION,
                    auth.clone()
                )
                .uri(uri)
                .body(Body::from(request_body))
    );
    Box::new(slurp_req(http_request).then(move |result| -> Result<T, String> {
        let res = try_s!(result);
        let body = try_s!(std::str::from_utf8(&res.2));
        if res.0 != StatusCode::OK {
            return ERR!("Rpc request {:?} failed with HTTP status code {}, response body: {}",
                        request, res.0, body);
        }
        let json_body: Json = try_s!(json::from_str(body));
        if !json_body["error"].is_null() {
            return ERR!("Rpc request {:?} failed with error, response body: {}",
                        request, json_body);
        }
        Ok(try_s!(json::from_value(json_body["result"].clone())))
    }))
}

/// Macro generating functions for RPC v1 requests.
/// Args must implement/derive Serialize trait.
/// Generates params vector from input args, builds the request and sends it.
macro_rules! rpc_func {
    (pub fn $method:ident(&$selff:ident $(, $arg_name:ident: $arg_ty:ty)*) -> $return_ty:ty) => {
        pub fn $method(&$selff $(, $arg_name: $arg_ty)*) -> $return_ty {
            let mut params = vec![];
            $(
                params.push(try_fus!(json::value::to_value($arg_name)));
            )*
            let request = UtxoRpcRequest::new_v1(stringify!($method).replace("_", ""), params);
            json_rpc_v1_request(&$selff.uri, &$selff.auth, request)
        }
    }
}

/// RPC client for UTXO based coins
/// https://bitcoin.org/en/developer-reference#rpc-quick-reference - Bitcoin RPC API reference
/// Other coins have additional methods or miss some of these
/// This description will be updated with more info
#[derive(Clone)]
struct UtxoRpcClient {
    /// The uri to send requests to
    uri: String,
    /// Value of Authorization header, e.g. "Basic base64(user:password)"
    auth: String,
}

impl UtxoRpcClient {
    /// https://bitcoin.org/en/developer-reference#listunspent
    rpc_func!(pub fn list_unspent(&self, min_conf: u64, max_conf: u64, addresses: Vec<String>)
        -> RpcRes<Vec<UnspentOutput>>);

    pub fn list_unspent_ordered(
        &self,
        min_conf: u64,
        max_conf: u64,
        addresses: Vec<String>
    ) -> RpcRes<Vec<UnspentOutput>> {
        Box::new(self.list_unspent(min_conf, max_conf, addresses).and_then(move |mut unspents| {
            unspents.sort_unstable_by(|a, b| {
                if a.amount < b.amount {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            });
            futures::future::ok(unspents)
        }))
    }

    /// https://bitcoin.org/en/developer-reference#importaddress
    rpc_func!(pub fn import_address(&self, address: String, label: String, rescan: bool)
        -> RpcRes<()>);

    /// https://bitcoin.org/en/developer-reference#getblockcount
    rpc_func!(pub fn get_block_count(&self) -> RpcRes<u64>);

    /// https://bitcoin.org/en/developer-reference#sendrawtransaction
    rpc_func!(pub fn send_raw_transaction(&self, tx: BytesJson) -> RpcRes<H256Json>);

    /// https://bitcoin.org/en/developer-reference#validateaddress
    rpc_func!(pub fn validate_address(&self, address: String) -> RpcRes<ValidateAddressRes>);

    /// https://bitcoin.org/en/developer-reference#getrawtransaction
    /// It expects that verbose param is always 1 to get deserialized transaction
    rpc_func!(pub fn get_raw_transaction(&self, txid: H256Json, verbose: u32) -> RpcRes<RpcTransaction>);
}

pub struct UtxoCoin {
    /// https://en.bitcoin.it/wiki/List_of_address_prefixes
    /// https://github.com/jl777/coins/blob/master/coins
    pub_type: u8,
    p2sh_type: u8,
    wif_type: u8,
    wif_t_addr: u8,
    t_addr: u8,
    /// True if coins uses Proof of Stake consensus algo
    /// Proof of Work is expected by default
    /// https://en.bitcoin.it/wiki/Proof_of_Stake
    /// https://en.bitcoin.it/wiki/Proof_of_work
    is_pos: bool,
    /// Special field for Zcash and it's forks
    /// Defines if Overwinter network upgrade was activated
    /// https://z.cash/upgrade/overwinter/
    overwintered: bool,
    /// The tx version used to detect the transaction ser/de/signing algo
    /// For now it's mostly used for Zcash and forks because they changed the algo in
    /// Overwinter and then Sapling upgrades
    /// https://github.com/zcash/zips/blob/master/zip-0243.rst
    tx_version: u32,
    /// If true - use Segwit protocol
    /// https://en.bitcoin.it/wiki/Segregated_Witness
    segwit: bool,
    /// Default decimals amount is 8 (BTC and almost all other UTXO coins)
    /// But there are forks which have different decimals:
    /// Peercoin has 6
    /// Emercoin has 6
    /// Bitcoin Diamond has 7
    decimals: u8,
    /// Is coin protected by Komodo dPoW?
    /// https://komodoplatform.com/security-delayed-proof-of-work-dpow/
    notarized: bool,
    /// RPC port
    rpc_port: u16,
    /// RPC username
    rpc_user: String,
    /// RPC password
    rpc_password: String,
    /// RPC client
    rpc_client: UtxoRpcClient,
    /// ECDSA key pair
    key_pair: KeyPair,
    /// Lock the mutex when we deal with address utxos
    utxo_mutex: Mutex<()>,
    my_address: Address
}

/// Only ETH and ERC20 tokens are supported currently
/// It's planned to support another ERC token standards
enum EthTokenType {
    /// The Ethereum itself or it's forks: ETC and others
    Base,
    /// ERC20 token: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
    /// The string param defines to what base coin the token belongs (ETH, ETC or another fork)
    Erc20(String)
}

struct EthCoin {
    /// Default ETH decimals is 18 but tokens can have any number (even zero or > 18)
    decimals: u8,
    token_type: EthTokenType,
    /// The address of Smart contract representing Alice side. Raw bytes form
    alice_contract_address: Vec<u8>,
    /// The address of Smart contract representing Bob side. Raw bytes form
    bob_contract_address: Vec<u8>,
}

impl Transaction for ExtendedUtxoTx {

}

/// Generates unsigned transaction (TransactionInputSigner) from specified utxos and outputs.
/// This function expects that utxos are sorted by amounts in ascending order
/// Consider sorting before calling this function
fn generate_transaction(
    utxos: Vec<UnspentOutput>,
    mut outputs: Vec<TransactionOutput>,
    lock_time: u32,
    version: i32,
    tx_fee: u64,
    decimals: u8,
    change_script_pubkey: Bytes,
) -> Result<TransactionInputSigner, String> {
    if utxos.is_empty() {
        return ERR!("Couldn't generate tx from empty utxos set");
    }

    if outputs.is_empty() {
        return ERR!("Couldn't generate tx from empty outputs set");
    }

    let mut target_value = 0;
    for output in outputs.iter() {
        target_value += output.value;
    }

    if target_value == 0 {
        return ERR!("Total target value calculated from outputs {:?} is zero", outputs);
    }
    target_value += tx_fee;

    let mut value_to_spend = 0;
    let mut inputs = vec![];
    for utxo in utxos.iter() {
        value_to_spend += f64_to_sat(utxo.amount, decimals);
        inputs.push(UnsignedTransactionInput {
            previous_output: OutPoint {
                hash: utxo.txid.reversed().into(),
                index: utxo.vout,
            },
            sequence: SEQUENCE_FINAL
        });
        if value_to_spend >= target_value { break; }
    }

    if value_to_spend < target_value {
        return ERR!("Couldn't collect enough value from utxos {:?} to create tx with outputs {:?}", utxos, outputs);
    }

    if value_to_spend > target_value {
        outputs.push({
            TransactionOutput {
                value: value_to_spend - target_value,
                script_pubkey: change_script_pubkey
            }
        });
    }

    Ok(TransactionInputSigner {
        inputs,
        outputs,
        lock_time,
        version
    })
}

fn f64_to_sat(amount: f64, decimals: u8) -> u64 {
    (amount * 10u64.pow(decimals as u32) as f64) as u64
}

fn bob_deposit_script(
    time_lock: u32,
    priv_bn_hash: Vec<u8>,
    priv_am_hash: Vec<u8>,
    pub_b0: &Public,
    pub_a0: &Public
) -> Result<Script, String> {
    let builder = Builder::default();
    let mut wtr = vec![];
    try_s!(wtr.write_u32::<LittleEndian>(time_lock));
    Ok(builder
        .push_opcode(Opcode::OP_IF)
        .push_bytes(&wtr)
        .push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY)
        .push_opcode(Opcode::OP_DROP)
        .push_opcode(Opcode::OP_SIZE)
        .push_bytes(&[32])
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_opcode(Opcode::OP_HASH160)
        .push_bytes(&priv_am_hash)
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_bytes(pub_a0)
        .push_opcode(Opcode::OP_CHECKSIG)
        .push_opcode(Opcode::OP_ELSE)
        .push_opcode(Opcode::OP_SIZE)
        .push_bytes(&[32])
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_opcode(Opcode::OP_HASH160)
        .push_bytes(&priv_bn_hash)
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_bytes(pub_b0)
        .push_opcode(Opcode::OP_CHECKSIG)
        .push_opcode(Opcode::OP_ENDIF)
        .into_script())
}

/// Creates p2sh 2 of 2 multisig script
fn p2sh_2_of_2_multisig_script(pub_am: &Public, pub_bn: &Public) -> Script {
    let builder = Builder::default();
    builder
        .push_opcode(Opcode::OP_2)
        .push_data(pub_am)
        .push_data(pub_bn)
        .push_opcode(Opcode::OP_2)
        .push_opcode(Opcode::OP_CHECKMULTISIG)
        .into_script()
}

fn bob_payment_script(
    time_lock: u32,
    priv_am_hash: Vec<u8>,
    pub_b1: &Public,
    pub_a0: &Public
) -> Result<Script, String> {
    let builder = Builder::default();
    let mut wtr = vec![];
    try_s!(wtr.write_u32::<LittleEndian>(time_lock));
    Ok(builder
        .push_opcode(Opcode::OP_IF)
        .push_bytes(&wtr)
        .push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY)
        .push_opcode(Opcode::OP_DROP)
        .push_bytes(pub_b1)
        .push_opcode(Opcode::OP_CHECKSIG)
        .push_opcode(Opcode::OP_ELSE)
        .push_opcode(Opcode::OP_SIZE)
        .push_bytes(&[32])
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_opcode(Opcode::OP_HASH160)
        .push_bytes(&priv_am_hash)
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_bytes(pub_a0)
        .push_opcode(Opcode::OP_CHECKSIG)
        .push_opcode(Opcode::OP_ENDIF)
        .into_script())
}

fn script_sig(message: &H256, key_pair: &KeyPair) -> Result<Bytes, String> {
    let signature = try_s!(key_pair.private().sign(message));

    let mut sig_script = Bytes::default();
    sig_script.append(&mut Bytes::from((*signature).to_vec()));
    // Using SIGHASH_ALL only for now
    sig_script.append(&mut Bytes::from(vec![1]));

    Ok(sig_script)
}

fn script_sig_with_pub(message: &H256, key_pair: &KeyPair) -> Result<Bytes, String> {
    let sig_script = try_s!(script_sig(message, key_pair));

    let builder = Builder::default();

    Ok(builder
        .push_data(&sig_script)
        .push_data(&key_pair.public().to_vec())
        .into_bytes())
}

/// Creates signed input spending p2sh 2of2 multisig output
fn p2sh_2_of_2_multisig_spend(
    signer: &TransactionInputSigner,
    input_index: usize,
    key_pair0: &KeyPair,
    key_pair1: &KeyPair,
    redeem_script: Script
) -> Result<TransactionInput, String> {
    let script = p2sh_2_of_2_multisig_script(&key_pair0.public(), &key_pair1.public());
    if script != redeem_script {
        return ERR!("Resulting 2of2 script {} doesn't match expected redeem script {}", script, redeem_script);
    }
    let sighash = signer.signature_hash(input_index, 0, &script, SignatureVersion::Base, 1);

    let sig0 = try_s!(script_sig(&sighash, &key_pair0));
    let sig1 = try_s!(script_sig(&sighash, &key_pair1));

    let builder = Builder::default();
    let spend_script = builder
        .push_opcode(Opcode::OP_0)
        .push_bytes(&sig0)
        .push_bytes(&sig1)
        .push_bytes(&script.to_vec())
        .into_bytes();

    Ok(TransactionInput {
        script_sig: spend_script,
        sequence: signer.inputs[input_index].sequence,
        script_witness: vec![],
        previous_output: signer.inputs[input_index].previous_output.clone()
    })
}

/// Creates signed input spending p2pkh output
fn p2pkh_spend(
    signer: &TransactionInputSigner,
    input_index: usize,
    key_pair: &KeyPair,
    prev_script: &Script
) -> Result<TransactionInput, String> {
    let script = Builder::build_p2pkh(&key_pair.public().address_hash());
    if script != *prev_script {
        return ERR!("p2pkh script {} built from input key pair doesn't match expected prev script {}", script, prev_script);
    }
    let sighash = signer.signature_hash(input_index, 0, &script, SignatureVersion::Base, 1);

    let script_sig = try_s!(script_sig_with_pub(&sighash, key_pair));

    Ok(TransactionInput {
        script_sig,
        sequence: signer.inputs[input_index].sequence,
        script_witness: vec![],
        previous_output: signer.inputs[input_index].previous_output.clone()
    })
}

/// Creates signed input spending p2sh output
fn p2sh_spend(
    signer: &TransactionInputSigner,
    input_index: usize,
    key_pair: &KeyPair,
    script_data: Script,
    redeem_script: Script,
) -> Result<TransactionInput, String> {
    let sighash = signer.signature_hash(input_index, 0, &redeem_script, SignatureVersion::Base, 1);

    let sig = try_s!(script_sig(&sighash, &key_pair));

    let mut resulting_script = Builder::default().push_data(&sig).into_bytes();
    if !script_data.is_empty() {
        resulting_script.extend_from_slice(&script_data);
    }

    let redeem_part = Builder::default().push_data(&redeem_script).into_bytes();
    resulting_script.extend_from_slice(&redeem_part);

    Ok(TransactionInput {
        script_sig: resulting_script.into(),
        sequence: signer.inputs[input_index].sequence,
        script_witness: vec![],
        previous_output: signer.inputs[input_index].previous_output.clone()
    })
}

fn p2sh_spending_tx(
    prev_transaction: ExtendedUtxoTx,
    outputs: Vec<TransactionOutput>,
    script_data: Script,
    key_pair: &KeyPair,
    lock_time: u32,
    sequence: u32,
) -> Result<UtxoTransaction, String> {
    let unsigned = TransactionInputSigner {
        lock_time,
        version: 1,
        inputs: vec![UnsignedTransactionInput {
            sequence,
            previous_output: OutPoint {
                hash: prev_transaction.transaction.hash(),
                index: 0,
            }
        }],
        outputs: outputs.clone(),
    };
    let signed_input = try_s!(
        p2sh_spend(&unsigned, 0, key_pair, script_data, prev_transaction.redeem_script.into())
    );
    Ok(UtxoTransaction {
        version: unsigned.version,
        lock_time: unsigned.lock_time,
        inputs: vec![signed_input],
        outputs,
    })
}

fn p2sh_2_of_2_spending_tx(
    prev_transaction: ExtendedUtxoTx,
    outputs: Vec<TransactionOutput>,
    key_pair0: &KeyPair,
    key_pair1: &KeyPair,
) -> Result<UtxoTransaction, String> {
    let unsigned = TransactionInputSigner {
        lock_time: 0,
        version: 1,
        inputs: vec![UnsignedTransactionInput {
            sequence: SEQUENCE_FINAL,
            previous_output: OutPoint {
                hash: prev_transaction.transaction.hash(),
                index: 0,
            }
        }],
        outputs: outputs.clone(),
    };
    let signed_input = try_s!(
        p2sh_2_of_2_multisig_spend(&unsigned, 0, key_pair0, key_pair1, prev_transaction.redeem_script.into())
    );
    Ok(UtxoTransaction {
        version: 1,
        lock_time: 0,
        inputs: vec![signed_input],
        outputs,
    })
}

fn address_from_raw_pubkey(pub_key: Vec<u8>) -> Result<Address, String> {
    Ok(Address {
        kind: Type::P2PKH,
        hash: try_s!(Public::from_slice(&pub_key)).address_hash(),
        network: Network::Komodo
    })
}

fn sign_tx(
    unsigned: TransactionInputSigner,
    key_pair: &KeyPair,
    prev_script: Script
) -> Result<UtxoTransaction, String> {
    let mut signed_inputs = vec![];
    for (i, _) in unsigned.inputs.iter().enumerate() {
        signed_inputs.push(
            try_s!(p2pkh_spend(&unsigned, i, key_pair, &prev_script))
        );
    }
    Ok(UtxoTransaction {
        inputs: signed_inputs,
        outputs: unsigned.outputs.clone(),
        version: unsigned.version,
        lock_time: unsigned.lock_time
    })
}

pub struct UtxoCoinArc(Arc<UtxoCoin>);
impl Deref for UtxoCoinArc {type Target = UtxoCoin; fn deref (&self) -> &UtxoCoin {&*self.0}}
impl Clone for UtxoCoinArc {fn clone (&self) -> UtxoCoinArc {UtxoCoinArc (self.0.clone())}}

impl UtxoCoinArc {
    fn send_outputs_from_my_address(&self, outputs: Vec<TransactionOutput>, redeem_script: Bytes) -> BoxedTxFut {
        let change_script_pubkey = Builder::build_p2pkh(&self.key_pair.public().address_hash()).to_bytes();
        let arc = self.clone();
        let unspent_fut = self.rpc_client.list_unspent_ordered(0, 999999, vec![self.my_address.to_string()]);
        Box::new(unspent_fut.then(move |unspents| -> BoxedTxFut {
            let unspents = try_fus!(unspents);
            let unsigned = try_fus!(generate_transaction(
                unspents,
                outputs,
                0,
                1,
                1000,
                arc.decimals,
                change_script_pubkey.clone()
            ));
            let signed = try_fus!(sign_tx(unsigned, &arc.key_pair, change_script_pubkey.into()));
            let tx = Box::new(ExtendedUtxoTx {
                transaction: signed,
                redeem_script
            });
            arc.send_raw_tx(tx)
        }))
    }
}

fn compressed_key_pair_from_bytes(raw: Vec<u8>) -> Result<KeyPair, String> {
    if raw.len() != 32 {
        return ERR!("Invalid raw priv key len {}", raw.len());
    }

    let private = Private {
        network: Network::Komodo,
        compressed: true,
        secret: Secret::from(raw.as_slice())
    };
    Ok(try_s!(KeyPair::from_private(private)))
}

impl ExchangeableCoin for UtxoCoinArc {
    fn send_alice_fee(&self, fee_pub_key: Vec<u8>, amount: f64) -> BoxedTxFut {
        let address = try_fus!(address_from_raw_pubkey(fee_pub_key));
        let output = TransactionOutput {
            value: f64_to_sat(amount, self.decimals),
            script_pubkey: Builder::build_p2pkh(&address.hash).to_bytes()
        };
        self.send_outputs_from_my_address(vec![output], vec![].into())
    }

    fn send_alice_payment(&self, pub_am: Vec<u8>, pub_bn: Vec<u8>, amount: f64) -> BoxedTxFut {
        let redeem_script = p2sh_2_of_2_multisig_script(
            &try_fus!(Public::from_slice(&pub_am)),
            &try_fus!(Public::from_slice(&pub_bn)),
        );
        let output = TransactionOutput {
            value: f64_to_sat(amount, self.decimals),
            script_pubkey: Builder::build_p2sh(&dhash160(&redeem_script)).into(),
        };
        self.send_outputs_from_my_address(vec![output], redeem_script.into())
    }

    fn send_bob_deposit(
        &self,
        time_lock: u32,
        priv_bn_hash: Vec<u8>,
        priv_am_hash: Vec<u8>,
        pub_b0: Vec<u8>,
        pub_a0: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        let redeem_script = try_fus!(bob_deposit_script(
            time_lock,
            priv_bn_hash,
            priv_am_hash,
            &try_fus!(Public::from_slice(&pub_b0)),
            &try_fus!(Public::from_slice(&pub_a0)),
        ));
        let output = TransactionOutput {
            value: f64_to_sat(amount, self.decimals),
            script_pubkey: Builder::build_p2sh(&dhash160(&redeem_script)).into(),
        };
        self.send_outputs_from_my_address(vec![output], redeem_script.into())
    }

    fn send_bob_payment(
        &self,
        time_lock: u32,
        priv_am_hash: Vec<u8>,
        pub_b1: Vec<u8>,
        pub_a0: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        let redeem_script = try_fus!(bob_payment_script(
            time_lock,
            priv_am_hash,
            &try_fus!(Public::from_slice(&pub_b1)),
            &try_fus!(Public::from_slice(&pub_a0)),
        ));
        let output = TransactionOutput {
            value: f64_to_sat(amount, self.decimals),
            script_pubkey: Builder::build_p2sh(&dhash160(&redeem_script)).into(),
        };
        self.send_outputs_from_my_address(vec![output], redeem_script.into())
    }

    fn send_bob_spends_alice_payment(
        &self,
        a_payment_tx: BoxedTx,
        a_priv_m: Vec<u8>,
        b_priv_n: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        let prev_tx: Box<ExtendedUtxoTx> = downcast_fus!(a_payment_tx);
        let key_pair0 = try_fus!(compressed_key_pair_from_bytes(a_priv_m));
        let key_pair1 = try_fus!(compressed_key_pair_from_bytes(b_priv_n));
        let output = TransactionOutput {
            value: prev_tx.transaction.outputs[0].value - 1000,
            script_pubkey: Builder::build_p2pkh(&self.key_pair.public().address_hash()).to_bytes()
        };
        let transaction = try_fus!(
            p2sh_2_of_2_spending_tx(*prev_tx, vec![output], &key_pair0, &key_pair1)
        );
        self.send_raw_tx(Box::new(ExtendedUtxoTx {
            transaction,
            redeem_script: vec![].into()
        }))
    }

    fn send_alice_reclaims_payment(
        &self,
        a_payment_tx: BoxedTx,
        a_priv_m: Vec<u8>,
        b_priv_n: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        let prev_tx: Box<ExtendedUtxoTx> = downcast_fus!(a_payment_tx);
        let key_pair0 = try_fus!(compressed_key_pair_from_bytes(a_priv_m));
        let key_pair1 = try_fus!(compressed_key_pair_from_bytes(b_priv_n));
        let output = TransactionOutput {
            value: prev_tx.transaction.outputs[0].value - 1000,
            script_pubkey: Builder::build_p2pkh(&self.key_pair.public().address_hash()).to_bytes()
        };
        let transaction = try_fus!(
            p2sh_2_of_2_spending_tx(*prev_tx, vec![output], &key_pair0, &key_pair1)
        );
        self.send_raw_tx(Box::new(ExtendedUtxoTx {
            transaction,
            redeem_script: vec![].into()
        }))
    }

    fn send_bob_reclaims_payment(
        &self,
        b_payment_tx: BoxedTx,
        b_priv_1: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        let prev_tx: Box<ExtendedUtxoTx> = downcast_fus!(b_payment_tx);
        let key_pair = try_fus!(compressed_key_pair_from_bytes(b_priv_1));
        let output = TransactionOutput {
            value: prev_tx.transaction.outputs[0].value - 1000,
            script_pubkey: Builder::build_p2pkh(&self.key_pair.public().address_hash()).to_bytes()
        };
        let script_data = Builder::default().push_opcode(Opcode::OP_1).into_script();
        let transaction = try_fus!(p2sh_spending_tx(
            *prev_tx,
            vec![output],
            script_data,
            &key_pair,
            (now_ms() / 1000) as u32,
            SEQUENCE_FINAL - 1
        ));
        self.send_raw_tx(Box::new(ExtendedUtxoTx {
            transaction,
            redeem_script: vec![].into()
        }))
    }

    fn send_alice_spends_bob_payment(
        &self,
        b_payment_tx: BoxedTx,
        a_priv_m: Vec<u8>,
        a_priv_0: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        let prev_tx: Box<ExtendedUtxoTx> = downcast_fus!(b_payment_tx);
        let key_pair = try_fus!(compressed_key_pair_from_bytes(a_priv_0));
        let output = TransactionOutput {
            value: prev_tx.transaction.outputs[0].value - 1000,
            script_pubkey: Builder::build_p2pkh(&self.key_pair.public().address_hash()).to_bytes()
        };
        let script_data = Builder::default()
            .push_data(&a_priv_m)
            .push_opcode(Opcode::OP_0)
            .into_script();
        let transaction = try_fus!(p2sh_spending_tx(
            *prev_tx,
            vec![output],
            script_data,
            &key_pair,
            (now_ms() / 1000) as u32,
            SEQUENCE_FINAL
        ));
        self.send_raw_tx(Box::new(ExtendedUtxoTx {
            transaction,
            redeem_script: vec![].into()
        }))
    }

    fn send_bob_refunds_deposit(
        &self,
        b_deposit_tx: BoxedTx,
        b_priv_n: Vec<u8>,
        b_priv_0: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        let prev_tx: Box<ExtendedUtxoTx> = downcast_fus!(b_deposit_tx);
        let key_pair = try_fus!(compressed_key_pair_from_bytes(b_priv_0));
        let output = TransactionOutput {
            value: prev_tx.transaction.outputs[0].value - 1000,
            script_pubkey: Builder::build_p2pkh(&self.key_pair.public().address_hash()).to_bytes()
        };
        let script_data = Builder::default()
                            .push_data(&b_priv_n)
                            .push_opcode(Opcode::OP_0)
                            .into_script();
        let transaction = try_fus!(p2sh_spending_tx(
            *prev_tx,
            vec![output],
            script_data,
            &key_pair,
            (now_ms() / 1000) as u32,
            SEQUENCE_FINAL
        ));
        self.send_raw_tx(Box::new(ExtendedUtxoTx {
            transaction,
            redeem_script: vec![].into()
        }))
    }

    fn send_alice_claims_deposit(
        &self,
        b_deposit_tx: BoxedTx,
        a_priv_m: Vec<u8>,
        a_priv_0: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        let prev_tx: Box<ExtendedUtxoTx> = downcast_fus!(b_deposit_tx);
        let key_pair = try_fus!(compressed_key_pair_from_bytes(a_priv_0));
        let output = TransactionOutput {
            value: prev_tx.transaction.outputs[0].value - 1000,
            script_pubkey: Builder::build_p2pkh(&self.key_pair.public().address_hash()).to_bytes()
        };
        let script_data = Builder::default()
            .push_data(&a_priv_m)
            .push_opcode(Opcode::OP_1)
            .into_script();
        let transaction = try_fus!(p2sh_spending_tx(
            *prev_tx,
            vec![output],
            script_data,
            &key_pair,
            (now_ms() / 1000) as u32,
            SEQUENCE_FINAL - 1
        ));
        self.send_raw_tx(Box::new(ExtendedUtxoTx {
            transaction,
            redeem_script: vec![].into()
        }))
    }

    fn get_balance(&self) -> f64 {
        0.
    }

    fn send_raw_tx(&self, tx: BoxedTx) -> BoxedTxFut {
        let tx: Box<ExtendedUtxoTx> = downcast_fus!(tx);
        println!("Raw tx {:?}", tx.transaction);
        println!("Hash {}", tx.transaction.hash().reversed());
        let send_fut = self.rpc_client.send_raw_transaction(BytesJson::from(serialize(&tx.transaction)));
        Box::new(
            send_fut.then(move |res| -> Result<BoxedTx, String> {
                let res = try_s!(res);
                Ok(tx)
            })
        )
    }

    fn wait_for_confirmations(&self, tx: BoxedTx) -> Box<dyn Future<Item=(), Error=String>> {
        Box::new(futures::future::ok(()))
    }
}

/*
impl ExchangeableCoin for EthCoin {
    fn send_alice_fee(&self, fee_addr: Vec<u8>, amount: f64) -> BoxedTxFut {
        Box::new(futures::future::ok(ExtendedUtxoTx::new()))
    }

    fn send_alice_payment(&self, pub_am: Vec<u8>, pub_bn: Vec<u8>, amount: f64) -> BoxedTxFut {
        Box::new(ExtendedUtxoTx::new())
    }

    fn send_bob_deposit(
        &self,
        time_lock: u32,
        priv_bn_hash: Vec<u8>,
        priv_am_hash: Vec<u8>,
        pub_b0: Vec<u8>,
        pub_a0: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        Box::new(ExtendedUtxoTx::new())
    }

    fn send_bob_payment(
        &self,
        time_lock: u32,
        priv_am_hash: Vec<u8>,
        pub_b1: Vec<u8>,
        pub_a0: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        Box::new(ExtendedUtxoTx::new())
    }

    fn send_alice_payment_spend(
        &self,
        a_payment_tx: Box<Any>,
        a_priv_m: Vec<u8>,
        b_priv_n: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        Ok(Box::new(ExtendedUtxoTx::new()))
    }

    fn send_bob_reclaims_payment(
        &self,
        b_payment_tx: Box<Any>,
        b_priv_1: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        Ok(Box::new(ExtendedUtxoTx::new()))
    }

    fn send_alice_spends_bob_payment(
        &self,
        b_payment_tx: Box<Any>,
        a_priv_m: Vec<u8>,
        a_priv_0: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        Ok(Box::new(ExtendedUtxoTx::new()))
    }

    fn send_bob_refunds_deposit(
        &self,
        b_deposit_tx: Box<Any>,
        b_priv_n: Vec<u8>,
        b_priv_0: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        Ok(Box::new(ExtendedUtxoTx::new()))
    }

    fn send_alice_claims_deposit(
        &self,
        b_deposit_tx: Box<Any>,
        a_priv_m: Vec<u8>,
        a_priv_0: Vec<u8>,
        amount: f64
    ) -> BoxedTxFut {
        Ok(Box::new(ExtendedUtxoTx::new()))
    }

    fn get_balance(&self) -> f64 {
        0.
    }

    fn send_raw_tx(&self, tx: Box<Any>) -> BoxedTxFut {
        let tx: Box<ExtendedUtxoTx> = downcast_fus!(tx);
        Box::new(
            self.rpc_client.send_raw_transaction(BytesJson::from(serialize(&tx.transaction))).then(move |res| -> Result<ExtendedUtxoTx, String> {
                let res = try_s!(res);
                Ok(*tx)
            })
        )
    }
}
*/
fn random_compressed_key_pair() -> KeyPair {
    let random_key = Random::new(Network::Komodo).generate().unwrap();

    KeyPair::from_private(Private {
        network: Network::Komodo,
        secret: random_key.private().secret.clone(),
        compressed: true,
    }).unwrap()
}

fn key_pair_from_seed(seed: &[u8]) -> KeyPair {
    let mut hasher = Sha256::new();
    hasher.input(seed);
    let mut hash = hasher.result();
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;
    let private = Private {
        network: Network::Komodo,
        secret: H256::from(hash.as_slice()),
        compressed: true,
    };

    KeyPair::from_private(private).unwrap()
}

pub fn coin_from_json() -> Result<Box<UtxoCoinArc>, String> {
    /*    if json["etomic"].is_string() {
        Ok(Box::new(EthCoin {
            decimals: 18,
            alice_contract_address: vec![],
            bob_contract_address: vec![],
            token_type: EthTokenType::Base
        }))
    } else {*/
    let key_pair = key_pair_from_seed("spice describe gravity federal blast come thank unfair canal monkey style afraid".as_bytes());
    let my_address = Address {
        network: Network::Komodo,
        hash: key_pair.public().address_hash(),
        kind: Type::P2PKH
    };
    let coin = UtxoCoin {
        decimals: 8,
        rpc_client: UtxoRpcClient {
            uri: "http://127.0.0.1:10271".to_owned(),
            auth: format!("Basic {}", base64_encode("user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371", URL_SAFE)),
        },
        key_pair,
        is_pos: false,
        notarized: false,
        overwintered: false,
        p2sh_type: 0,
        pub_type: 0,
        rpc_password: "".to_owned(),
        rpc_port: 0,
        rpc_user: "".to_owned(),
        segwit: false,
        t_addr: 0,
        wif_t_addr: 0,
        wif_type: 0,
        tx_version: 1,
        utxo_mutex: Mutex::new(()),
        my_address,
    };

    Ok(Box::new(UtxoCoinArc(Arc::new(coin))))
    //}
}

enum WaitForConfirmationState {
    WaitingForInterval,
    CheckingConfirmations(RpcRes<RpcTransaction>),
}

struct WaitForUtxoTxConfirmations<'a> {
    rpc_client: &'a UtxoRpcClient,
    txid: H256Json,
    interval: Interval,
    wait_until: u64,
    status: StatusHandle<'a>,
    confirmations: u32,
    retries: u8,
    max_retries: u8,
    state: WaitForConfirmationState
}

impl<'a> WaitForUtxoTxConfirmations<'a> {
    pub fn new(
        rpc_client: &'a UtxoRpcClient,
        txid: H256Json,
        poll_interval: u64,
        wait_until: u64,
        status: StatusHandle<'a>,
        confirmations: u32,
        max_retries: u8,
    ) -> Self {
        WaitForUtxoTxConfirmations {
            rpc_client,
            txid,
            interval: Timer::default().interval(Duration::from_secs(poll_interval)),
            wait_until,
            status,
            confirmations,
            retries: 0,
            max_retries,
            state: WaitForConfirmationState::WaitingForInterval,
        }
    }
}

impl<'a> Future for WaitForUtxoTxConfirmations<'a> {
    type Item = ();
    type Error = String;

    fn poll(&mut self) -> Poll<(), String> {
        loop {
            let next_state = match self.state {
                WaitForConfirmationState::WaitingForInterval => {
                    if now_ms() / 1000 > self.wait_until {
                        return ERR!("Waited too long until {}, aborted", self.wait_until);
                    }
                    let _ready = try_ready!(
                        self.interval
                            .poll()
                            .map_err(|e| {
                                ERRL!("{}", e)
                            })
                    );
                    WaitForConfirmationState::CheckingConfirmations(
                        self.rpc_client.get_raw_transaction(self.txid.clone(), 1)
                    )
                },
                WaitForConfirmationState::CheckingConfirmations(ref mut future) => {
                    let tx = future.poll();
                    match tx {
                        Ok(Async::Ready(transaction)) => {
                            if transaction.confirmations >= self.confirmations {
                                self.status.append("Reached required confirmations");
                                return Ok(Async::Ready(()))
                            } else {
                                self.status.append(
                                    &format!(
                                        "Confirmed {} times, target {}..",
                                        transaction.confirmations,
                                        self.confirmations
                                    )
                                );
                            }
                        },
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Err(e) => {
                            self.status.append(&format!("Attempt {}, got error {}..", self.retries, e));
                            self.retries += 1;
                            if self.retries >= self.max_retries {
                                self.status.append("Reached max attempts count, aborting..");
                                return ERR!("Error waiting for tx confirmation {:?}", self.txid)
                            }
                        }
                    }
                    WaitForConfirmationState::WaitingForInterval
                },
            };
            self.state = next_state;
        }
    }
}

#[test]
fn test_alice_payment_script() {
    let expected_script_bytes : Bytes = "522102a80462ede85bddee6b3f6c92fe9380b1b1c2f85ab4dbbb100e8a204c7ce74740210388be77e8919562fee28b4e3d6150c39e3cf6c5b39da043aaa977d7dc432858e252ae".into();

    let pub_am = Public::from_slice(&<[u8; 33]>::from_hex("02a80462ede85bddee6b3f6c92fe9380b1b1c2f85ab4dbbb100e8a204c7ce74740").unwrap()).unwrap();
    let pub_bn = Public::from_slice(&<[u8; 33]>::from_hex("0388be77e8919562fee28b4e3d6150c39e3cf6c5b39da043aaa977d7dc432858e2").unwrap()).unwrap();

    let script = p2sh_2_of_2_multisig_script(&pub_am, &pub_bn);

    assert_eq!(expected_script_bytes, script.to_bytes());
}

#[test]
fn test_send_alice_fee() {
    let coin = coin_from_json().unwrap();
    let tx = coin.send_alice_fee(
        hex::decode("02031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3").unwrap(),
        0.1
    ).wait().unwrap();
    // println!("{:?}", tx);
}

#[test]
fn test_send_and_reclaim_alice_payment() {
    let coin = coin_from_json().unwrap();
    let key_pair0 = random_compressed_key_pair();
    let key_pair1 = random_compressed_key_pair();
    let tx = coin.send_alice_payment(
        key_pair0.public().to_vec(),
        key_pair1.public().to_vec(),
        0.1
    ).wait().unwrap();

    let spending_tx = coin.send_alice_reclaims_payment(
        tx,
        key_pair0.private().secret.to_vec(),
        key_pair1.private().secret.to_vec(),
        0.0999
    ).wait().unwrap();
}

#[test]
fn test_send_and_spend_alice_payment() {
    let coin = coin_from_json().unwrap();
    let key_pair0 = random_compressed_key_pair();
    let key_pair1 = random_compressed_key_pair();
    let tx = coin.send_alice_payment(
        key_pair0.public().to_vec(),
        key_pair1.public().to_vec(),
        0.1
    ).wait().unwrap();

    let spending_tx = coin.send_bob_spends_alice_payment(
        tx,
        key_pair0.private().secret.to_vec(),
        key_pair1.private().secret.to_vec(),
        0.0999
    ).wait().unwrap();
}

#[test]
fn test_send_and_refund_bob_deposit() {
    let coin = coin_from_json().unwrap();
    let priv_bn = random_compressed_key_pair();
    let priv_am = random_compressed_key_pair();
    let priv_b0 = random_compressed_key_pair();
    let priv_a0 = random_compressed_key_pair();
    let tx = coin.send_bob_deposit(
        (now_ms() / 1000) as u32,
        dhash160(&*priv_bn.private().secret).to_vec(),
        dhash160(&*priv_am.private().secret).to_vec(),
        priv_b0.public().to_vec(),
        priv_a0.public().to_vec(),
        0.001
    ).wait().unwrap();

    let refund_tx = coin.send_bob_refunds_deposit(
        tx,
        priv_bn.private().secret.to_vec(),
        priv_b0.private().secret.to_vec(),
        0.0999
    ).wait().unwrap();
}

#[test]
fn test_send_and_claim_bob_deposit() {
    let coin = coin_from_json().unwrap();
    let priv_bn = random_compressed_key_pair();
    let priv_am = random_compressed_key_pair();
    let priv_b0 = random_compressed_key_pair();
    let priv_a0 = random_compressed_key_pair();
    let tx = coin.send_bob_deposit(
        (now_ms() / 1000) as u32,
        dhash160(&*priv_bn.private().secret).to_vec(),
        dhash160(&*priv_am.private().secret).to_vec(),
        priv_b0.public().to_vec(),
        priv_a0.public().to_vec(),
        0.001
    ).wait().unwrap();

    let downcasted: Box<ExtendedUtxoTx> = tx.downcast().unwrap();
    let address = Address {
        kind: Type::P2SH,
        network: Network::Komodo,
        hash: dhash160(&*downcasted.redeem_script)
    };

    println!("Address {}", address.to_string());

    coin.rpc_client.import_address(address.to_string(), address.to_string(), false);

    let refund_tx = coin.send_alice_claims_deposit(
        downcasted,
        priv_am.private().secret.to_vec(),
        priv_a0.private().secret.to_vec(),
        0.0999
    ).wait().unwrap();
}

#[test]
fn test_send_and_claim_bob_payment() {
    let coin = coin_from_json().unwrap();
    let priv_am = random_compressed_key_pair();
    let priv_b1 = random_compressed_key_pair();
    let priv_a0 = random_compressed_key_pair();
    let tx = coin.send_bob_payment(
        (now_ms() / 1000) as u32,
        dhash160(&*priv_am.private().secret).to_vec(),
        priv_b1.public().to_vec(),
        priv_a0.public().to_vec(),
        20.0
    ).wait().unwrap();

    let refund_tx = coin.send_alice_spends_bob_payment(
        tx,
        priv_am.private().secret.to_vec(),
        priv_a0.private().secret.to_vec(),
        20.0
    ).wait().unwrap();
}

#[test]
fn test_send_and_reclaim_bob_payment() {
    let coin = coin_from_json().unwrap();
    let priv_am = random_compressed_key_pair();
    let priv_b1 = random_compressed_key_pair();
    let priv_a0 = random_compressed_key_pair();
    let tx = coin.send_bob_payment(
        (now_ms() / 1000) as u32,
        dhash160(&*priv_am.private().secret).to_vec(),
        priv_b1.public().to_vec(),
        priv_a0.public().to_vec(),
        0.1
    ).wait().unwrap();

    let tx: Box<ExtendedUtxoTx> = tx.downcast().unwrap();
    let log = LogState::in_memory();
    let fut = WaitForUtxoTxConfirmations::new(
        &coin.rpc_client,
        tx.transaction.hash().reversed().into(),
        1,
        (now_ms() / 1000) + 100,
        log.status(&[&"transaction", &(tx.transaction.hash().to_reversed_str(), "waiting")], "Waiting for confirmations..."),
        1,
        20
    );
    println!("{:?}", fut.wait());

    let refund_tx = coin.send_bob_reclaims_payment(
        tx,
        priv_b1.private().secret.to_vec(),
        20.0
    ).wait().unwrap();
}

#[test]
fn test_list_unspent_ordered() {
    let client = UtxoRpcClient {
        uri: "http://127.0.0.1:10271".to_owned(),
        auth: format!("Basic {}", base64_encode("user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371", URL_SAFE)),
    };
    let unspents = client.list_unspent_ordered(0, 999999, vec!["RBs52D7pVq7txo6SCz1Tuyw2WrPmdqU3qw".to_owned()]);
    let unspents = unspents.wait().unwrap();
    println!("Unspents {:?}", unspents);
}

#[test]
fn test_get_raw_transaction() {
    let client = UtxoRpcClient {
        uri: "http://127.0.0.1:10271".to_owned(),
        auth: format!("Basic {}", base64_encode("user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371", URL_SAFE)),
    };
    let tx = client.get_raw_transaction(H256Json::from("d516b3fd1f845aafa08886aaf2243693635a8d1962b233b0843e9685e97736e2"), 1);
    let tx = tx.wait().unwrap();
    println!("{:?}", tx);
}

#[test]
fn test_wait_for_confirmation() {
    let client = UtxoRpcClient {
        uri: "http://127.0.0.1:10271".to_owned(),
        auth: format!("Basic {}", base64_encode("user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371", URL_SAFE)),
    };
    let log = LogState::in_memory();
    let fut = WaitForUtxoTxConfirmations::new(
        &client,
        H256Json::from("d516b3fd1f845aafa08886aaf2243693635a8d1962b233b0843e9685e97736e2"),
        10,
        (now_ms() / 1000) + 1000,
        log.status(&[&"transaction", &("d516b3fd1f845aafa08886aaf2243693635a8d1962b233b0843e9685e97736e2", "waiting")], "Waiting for confirmations..."),
        70,
        2
    );
    fut.wait().unwrap();
}
