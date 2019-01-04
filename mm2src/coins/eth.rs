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
//  eth.rs
//  marketmaker
//
//  Copyright © 2017-2018 SuperNET. All rights reserved.
//
use bitcrypto::dhash160;
use common::{CORE, slurp_url};
use secp256k1::key::PublicKey;
use ethabi::{Contract, Token};
use ethcore_transaction::{ Action, Transaction as UnsignedEthTransaction};
use ethereum_types::{Address, U256, H160, H512};
use ethkey::{ KeyPair, Secret, Public, public_to_address, SECP256K1 };
use futures::Future;
use gstuff::now_ms;
use hyper::StatusCode;
use keys::generator::{Random, Generator};
use rand::Rng;
use serde_json::{self as json};
use std::borrow::Cow;
use std::ops::Deref;
use std::sync::Arc;
use web3::transports::{ Http };
use web3::types::{BlockNumber, Bytes, CallRequest};
use web3::{ self, Web3 };

use super::utxo::compressed_key_pair_from_bytes;
use super::{IguanaInfo, MarketCoinOps, MmCoin, SwapOps, TransactionFut, TransactionEnum, Transaction};

pub use ethcore_transaction::SignedTransaction as SignedEthTransaction;

const SWAP_CONTRACT_ABI: &'static str = r#"[{"constant":false,"inputs":[{"name":"_id","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_secret","type":"bytes32"},{"name":"_tokenAddress","type":"address"},{"name":"_sender","type":"address"}],"name":"receiverSpend","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"bytes32"}],"name":"payments","outputs":[{"name":"paymentHash","type":"bytes20"},{"name":"lockTime","type":"uint64"},{"name":"state","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_id","type":"bytes32"},{"name":"_receiver","type":"address"},{"name":"_secretHash","type":"bytes20"},{"name":"_lockTime","type":"uint64"}],"name":"ethPayment","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":false,"inputs":[{"name":"_id","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_paymentHash","type":"bytes20"},{"name":"_tokenAddress","type":"address"},{"name":"_receiver","type":"address"}],"name":"senderRefund","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_id","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_tokenAddress","type":"address"},{"name":"_receiver","type":"address"},{"name":"_secretHash","type":"bytes20"},{"name":"_lockTime","type":"uint64"}],"name":"erc20Payment","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"name":"id","type":"bytes32"}],"name":"PaymentSent","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"id","type":"bytes32"},{"indexed":false,"name":"secret","type":"bytes32"}],"name":"ReceiverSpent","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"id","type":"bytes32"}],"name":"SenderRefunded","type":"event"}]"#;
const ERC20_ABI: &'static str = r#"[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_subtractedValue","type":"uint256"}],"name":"decreaseApproval","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_addedValue","type":"uint256"}],"name":"increaseApproval","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"},{"indexed":true,"name":"spender","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"}]"#;

lazy_static! {
    static ref SWAP_CONTRACT: Contract = unwrap!(Contract::load(SWAP_CONTRACT_ABI.as_bytes()));

    static ref ERC20_CONTRACT: Contract = unwrap!(Contract::load(ERC20_ABI.as_bytes()));
}

#[derive(Debug)]
enum EthCoinType {
    /// Ethereum itself or it's forks: ETC/others
    Eth,
    /// ERC20 token with smart contract address
    /// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
    Erc20(Address),
}

#[derive(Debug)]
pub struct EthCoinImpl {  // pImpl idiom.
    ticker: String,
    coin_type: EthCoinType,
    key_pair: KeyPair,
    my_address: Address,
    swap_contract_address: Address,
    web3: Web3<Http>,
    decimals: u8,
    gas_station_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EthCoin(Arc<EthCoinImpl>);
impl Deref for EthCoin {type Target = EthCoinImpl; fn deref (&self) -> &EthCoinImpl {&*self.0}}

impl SwapOps for EthCoin {
    fn send_taker_fee(&self, fee_addr: &[u8], amount: u64) -> TransactionFut {
        let address = try_fus!(addr_from_raw_pubkey(fee_addr));

        Box::new(self.send_to_address(
            address,
            u256_denominate_from_satoshis(amount, self.decimals),
        ).map(|tx| TransactionEnum::Eth(tx)))
    }

    fn send_maker_payment(
        &self,
        time_lock: u32,
        _pub_a0: &[u8],
        _pub_b0: &[u8],
        taker_addr: &[u8],
        priv_bn_hash: &[u8],
        amount: u64
    ) -> TransactionFut {
        let taker_addr = try_fus!(addr_from_raw_pubkey(taker_addr));

        Box::new(self.send_hash_time_locked_payment(
            u256_denominate_from_satoshis(amount, self.decimals),
            time_lock,
            priv_bn_hash,
            taker_addr,
        ).map(|tx| TransactionEnum::Eth(tx)))
    }

    fn send_taker_payment(
        &self,
        time_lock: u32,
        _pub_a0: &[u8],
        _pub_b0: &[u8],
        maker_addr: &[u8],
        priv_bn_hash: &[u8],
        amount: u64,
    ) -> TransactionFut {
        let maker_addr = try_fus!(addr_from_raw_pubkey(maker_addr));

        Box::new(self.send_hash_time_locked_payment(
            u256_denominate_from_satoshis(amount, self.decimals),
            time_lock,
            priv_bn_hash,
            maker_addr,
        ).map(|tx| TransactionEnum::Eth(tx)))
    }

    fn send_maker_spends_taker_payment(
        &self,
        taker_payment_tx: TransactionEnum,
        b_priv_0: &[u8],
        b_priv_n: &[u8],
        taker_addr: &[u8],
        amount: u64
    ) -> TransactionFut {
        let tx = match taker_payment_tx {
            TransactionEnum::Eth(t) => t,
            _ => panic!(),
        };

        Box::new(self.spend_hash_time_locked_payment(tx, b_priv_n).map(|t| TransactionEnum::Eth(t)))
    }

    fn send_taker_spends_maker_payment(
        &self,
        maker_payment_tx: TransactionEnum,
        _a_priv_0: &[u8],
        b_priv_n: &[u8],
        maker_addr: &[u8],
        amount: u64
    ) -> TransactionFut {
        let tx = match maker_payment_tx {
            TransactionEnum::Eth(t) => t,
            _ => panic!(),
        };

        Box::new(self.spend_hash_time_locked_payment(tx, b_priv_n).map(|t| TransactionEnum::Eth(t)))
    }

    fn send_taker_refunds_payment(
        &self,
        taker_payment_tx: TransactionEnum,
        a_priv_0: &[u8],
        maker_addr: &[u8],
        amount: u64
    ) -> TransactionFut {
        let tx = match taker_payment_tx {
            TransactionEnum::Eth(t) => t,
            _ => panic!(),
        };

        Box::new(self.refund_hash_time_locked_payment(tx).map(|t| TransactionEnum::Eth(t)))
    }

    fn send_maker_refunds_payment(
        &self,
        maker_payment_tx: TransactionEnum,
        b_priv_0: &[u8],
        taker_addr: &[u8],
        amount: u64
    ) -> TransactionFut {
        let tx = match maker_payment_tx {
            TransactionEnum::Eth(t) => t,
            _ => panic!(),
        };

        Box::new(self.refund_hash_time_locked_payment(tx).map(|t| TransactionEnum::Eth(t)))
    }
}

impl MarketCoinOps for EthCoin {
    fn address(&self) -> Cow<str> {
        format!("{:#02x}", self.my_address).into()
    }

    fn get_balance(&self) -> f64 {
        unimplemented!();
    }

    fn send_raw_tx(&self, tx: TransactionEnum) -> TransactionFut {
        unimplemented!();
    }

    fn wait_for_confirmations(
        &self,
        tx: TransactionEnum,
        confirmations: i32,
    ) -> Box<dyn Future<Item=(), Error=String>> {
        unimplemented!();
    }

    fn wait_for_tx_spend(&self, transaction: TransactionEnum, wait_until: u64) -> TransactionFut {
        unimplemented!();
    }

    fn tx_from_raw_bytes(&self, bytes: &[u8]) -> Result<TransactionEnum, String> {
        unimplemented!();
    }
}

type EthTxFut = Box<Future<Item=SignedEthTransaction, Error=String> + Send + 'static>;

impl EthCoin {
    fn sign_and_send_transaction(
        &self,
        value: U256,
        action: Action,
        data: Vec<u8>,
        gas: U256,
    ) -> EthTxFut {
        let arc = self.clone();
        let nonce_fut = self.web3.eth().parity_next_nonce(self.my_address.clone()).map_err(|e| ERRL!("{}", e));
        Box::new(nonce_fut.then(move |nonce| -> EthTxFut {
            let nonce = try_fus!(nonce);
            let gas_price_fut = if let Some(url) = &arc.gas_station_url {
                GasStationData::get_gas_price(&url.clone())
            } else {
                Box::new(arc.web3.eth().gas_price().map_err(|e| ERRL!("{}", e)))
            };
            Box::new(gas_price_fut.then(move |gas_price| -> EthTxFut {
                let gas_price = try_fus!(gas_price);
                let tx = UnsignedEthTransaction {
                    nonce,
                    value,
                    action,
                    data,
                    gas,
                    gas_price,
                };

                let signed = tx.sign(arc.key_pair.secret(), None);
                let bytes = web3::types::Bytes(rlp::encode(&signed).to_vec());
                let send_fut = arc.web3.eth().send_raw_transaction(bytes).map_err(|e| ERRL!("{}", e));
                Box::new(send_fut.map(move |_res| signed))
            }))
        }))
    }

    fn send_to_address(&self, address: Address, value: U256) -> EthTxFut {
        match self.coin_type {
            EthCoinType::Eth => self.sign_and_send_transaction(value, Action::Call(address), vec![], U256::from(21000)),
            EthCoinType::Erc20(token_addr) => {
                let abi = try_fus!(Contract::load(ERC20_ABI.as_bytes()));
                let function = try_fus!(abi.function("transfer"));
                let data = try_fus!(function.encode_input(&[
                    Token::Address(address),
                    Token::Uint(value)
                ]));
                self.sign_and_send_transaction(0.into(), Action::Call(token_addr), data, U256::from(210000))
            }
        }
    }

    fn send_hash_time_locked_payment(
        &self,
        value: U256,
        time_lock: u32,
        secret_hash: &[u8],
        receiver_addr: Address,
    ) -> EthTxFut {
        let mut rng = rand::thread_rng();
        let id: [u8; 32] = rng.gen();

        match self.coin_type {
            EthCoinType::Eth => {
                let function = try_fus!(SWAP_CONTRACT.function("ethPayment"));
                let data = try_fus!(function.encode_input(&[
                    Token::FixedBytes(id.to_vec()),
                    Token::Address(receiver_addr),
                    Token::FixedBytes(secret_hash.to_vec()),
                    Token::Uint(U256::from(time_lock))
                ]));
                self.sign_and_send_transaction(value, Action::Call(self.swap_contract_address), data, U256::from(150000))
            },
            EthCoinType::Erc20(token_addr) => {
                let allowance_fut = self.allowance(self.swap_contract_address);

                let function = try_fus!(SWAP_CONTRACT.function("erc20Payment"));
                let data = try_fus!(function.encode_input(&[
                    Token::FixedBytes(id.to_vec()),
                    Token::Uint(U256::from(value)),
                    Token::Address(token_addr),
                    Token::Address(receiver_addr),
                    Token::FixedBytes(secret_hash.to_vec()),
                    Token::Uint(U256::from(time_lock))
                ]));

                let arc = self.clone();
                Box::new(allowance_fut.and_then(move |allowed| -> EthTxFut {
                    if allowed < value {
                        let balance_f = arc.my_balance();
                        Box::new(balance_f.and_then(move |balance| {
                            arc.approve(arc.swap_contract_address, balance).and_then(move |_approved| {
                                arc.sign_and_send_transaction(0.into(), Action::Call(arc.swap_contract_address), data, U256::from(150000))
                            })
                        }))
                    } else {
                        Box::new(arc.sign_and_send_transaction(0.into(), Action::Call(arc.swap_contract_address), data, U256::from(150000)))
                    }
                }))
            }
        }
    }

    fn spend_hash_time_locked_payment(
        &self,
        payment: SignedEthTransaction,
        secret: &[u8],
    ) -> EthTxFut {
        let spend_func = try_fus!(SWAP_CONTRACT.function("receiverSpend"));

        match self.coin_type {
            EthCoinType::Eth => {
                let payment_func = try_fus!(SWAP_CONTRACT.function("ethPayment"));
                let decoded = try_fus!(payment_func.decode_input(&payment.data));
                let value = payment.value;
                let data = try_fus!(spend_func.encode_input(&[
                    decoded[0].clone(),
                    Token::Uint(value),
                    Token::FixedBytes(secret.to_vec()),
                    Token::Address(Address::default()),
                    Token::Address(payment.sender()),
                ]));

                self.sign_and_send_transaction(0.into(), Action::Call(self.swap_contract_address), data, U256::from(150000))
            },
            EthCoinType::Erc20(token_addr) => {
                let payment_func = try_fus!(SWAP_CONTRACT.function("erc20Payment"));
                let decoded = try_fus!(payment_func.decode_input(&payment.data));

                let data = try_fus!(spend_func.encode_input(&[
                    decoded[0].clone(),
                    decoded[1].clone(),
                    Token::FixedBytes(secret.to_vec()),
                    Token::Address(token_addr),
                    Token::Address(payment.sender()),
                ]));

                self.sign_and_send_transaction(0.into(), Action::Call(self.swap_contract_address), data, U256::from(150000))
            }
        }
    }

    fn refund_hash_time_locked_payment(
        &self,
        payment: SignedEthTransaction,
    ) -> EthTxFut {
        let refund_func = try_fus!(SWAP_CONTRACT.function("senderRefund"));

        match self.coin_type {
            EthCoinType::Eth => {
                let payment_func = try_fus!(SWAP_CONTRACT.function("ethPayment"));
                let decoded = try_fus!(payment_func.decode_input(&payment.data));
                let value = payment.value;
                let data = try_fus!(refund_func.encode_input(&[
                    decoded[0].clone(),
                    Token::Uint(value),
                    decoded[2].clone(),
                    Token::Address(Address::default()),
                    Token::Address(payment.sender()),
                ]));

                self.sign_and_send_transaction(0.into(), Action::Call(self.swap_contract_address), data, U256::from(150000))
            },
            EthCoinType::Erc20(token_addr) => {
                let payment_func = try_fus!(SWAP_CONTRACT.function("erc20Payment"));
                let decoded = try_fus!(payment_func.decode_input(&payment.data));

                let data = try_fus!(refund_func.encode_input(&[
                    decoded[0].clone(),
                    decoded[1].clone(),
                    decoded[4].clone(),
                    Token::Address(token_addr),
                    Token::Address(payment.sender()),
                ]));

                self.sign_and_send_transaction(0.into(), Action::Call(self.swap_contract_address), data, U256::from(150000))
            }
        }
    }

    fn my_balance(&self) -> Box<Future<Item=U256, Error=String> + Send> {
        match self.coin_type {
            EthCoinType::Eth => Box::new(self.web3.eth().balance(self.my_address, Some(BlockNumber::Pending)).map_err(|e| ERRL!("{:?}", e))),
            EthCoinType::Erc20(token_addr) => {
                let function = try_fus!(ERC20_CONTRACT.function("balanceOf"));
                let data = try_fus!(function.encode_input(&[
                    Token::Address(self.my_address),
                ]));

                let call_fut = self.call_request(token_addr, None, Some(data.into()));

                Box::new(call_fut.and_then(move |res| {
                    let decoded = try_s!(function.decode_output(&res.0));

                    match decoded[0] {
                        Token::Uint(number) => Ok(number),
                        _ => ERR!("Expected U256 as balanceOf result but got {:?}", decoded),
                    }
                }))
            }
        }
    }

    fn call_request(&self, to: Address, value: Option<U256>, data: Option<Bytes>) -> impl Future<Item=Bytes, Error=String> {
        let request = CallRequest {
            from: Some(self.my_address),
            to,
            gas: None,
            gas_price: None,
            value,
            data
        };

        self.web3.eth().call(request, Some(BlockNumber::Pending)).map_err(|e| ERRL!("{:?}", e))
    }

    fn allowance(&self, spender: Address) -> Box<Future<Item=U256, Error=String> + Send + 'static> {
        match self.coin_type {
            EthCoinType::Eth => panic!(),
            EthCoinType::Erc20(token_addr) => {
                let function = try_fus!(ERC20_CONTRACT.function("allowance"));
                let data = try_fus!(function.encode_input(&[
                    Token::Address(self.my_address),
                    Token::Address(spender),
                ]));

                let call_fut = self.call_request(token_addr, None, Some(data.into()));

                Box::new(call_fut.and_then(move |res| {
                    let decoded = try_s!(function.decode_output(&res.0));

                    match decoded[0] {
                        Token::Uint(number) => Ok(number),
                        _ => ERR!("Expected U256 as allowance result but got {:?}", decoded),
                    }
                }))
            }
        }
    }

    fn approve(&self, spender: Address, amount: U256) -> EthTxFut {
        match self.coin_type {
            EthCoinType::Eth => panic!(),
            EthCoinType::Erc20(token_addr) => {
                let function = try_fus!(ERC20_CONTRACT.function("approve"));
                let data = try_fus!(function.encode_input(&[
                    Token::Address(spender),
                    Token::Uint(amount),
                ]));

                self.sign_and_send_transaction(0.into(), Action::Call(token_addr), data, U256::from(150000))
            }
        }
    }
}

impl IguanaInfo for EthCoin {
    fn ticker<'a> (&'a self) -> &'a str {&self.ticker[..]}
}
impl MmCoin for EthCoin {}

fn addr_from_raw_pubkey(pubkey: &[u8]) -> Result<Address, String> {
    let pubkey = try_s!(PublicKey::from_slice(&SECP256K1, &pubkey));
    let eth_public = Public::from(&pubkey.serialize_vec(&SECP256K1, false)[1..65]);
    Ok(public_to_address(&eth_public))
}

fn u256_denominate_from_satoshis(satoshis: u64, decimals: u8) -> U256 {
    if decimals < 8 {
        U256::from(satoshis) / U256::exp10(8 - decimals as usize)
    } else {
        U256::from(satoshis) * U256::exp10(decimals as usize - 8)
    }
}

impl Transaction for SignedEthTransaction {
    fn to_raw_bytes(&self) -> Vec<u8> {
        rlp::encode(self).to_vec()
    }

    fn extract_secret(&self) -> Result<Vec<u8>, String> {
        unimplemented!()
    }
}

#[derive(Deserialize, Debug)]
struct GasStationData {
    fast: f64,
    speed: f64,
    fastest: f64,
    #[serde(rename = "avgWait")]
    avg_wait: f64,
    #[serde(rename = "fastWait")]
    fast_wait: f64,
    #[serde(rename = "blockNum")]
    block_num: u64,
    #[serde(rename = "safeLowWait")]
    safe_low_wait: f64,
    block_time: f64,
    #[serde(rename = "fastestWait")]
    fastest_wait: f64,
    #[serde(rename = "safeLow")]
    safe_low: f64,
    average: f64
}

impl GasStationData {
    fn average_gwei(&self) -> U256 {
        U256::from(self.average as u64 + 10) * U256::exp10(8)
    }

    fn get_gas_price(uri: &str) -> Box<Future<Item=U256, Error=String> + Send> {
        Box::new(slurp_url(uri).and_then(|res| -> Result<U256, String> {
            if res.0 != StatusCode::OK {
                return ERR!("Gas price request failed with status code {}", res.0);
            }

            let result: GasStationData = try_s!(json::from_slice(&res.2));
            Ok(result.average_gwei())
        }))
    }
}

#[test]
fn web3_from_core() {
    let transport = Http::with_remote_reactor("http://195.201.0.6:8555", &CORE, 1).unwrap();

    let web3 = Web3::new(transport);
    log!([web3.eth().gas_price().wait().unwrap()]);
}

#[test]
fn test_send_and_spend_eth_payment() {
    let transport = Http::with_remote_reactor("http://195.201.0.6:8545", &CORE, 1).unwrap();
    let web3 = Web3::new(transport);

    let secret_hex = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair: KeyPair = unwrap!(KeyPair::from_secret_slice(&secret_hex));

    let coin = EthCoin(Arc::new(EthCoinImpl {
        decimals: 18,
        gas_station_url: Some("https://ethgasstation.info/json/ethgasAPI.json".into()),
        web3,
        coin_type: EthCoinType::Eth,
        ticker: "ETH".into(),
        my_address: key_pair.address().clone(),
        key_pair,
        swap_contract_address: Address::from("7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94"),
    }));

    let pubkey = hex::decode("02031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3").unwrap();
    let res = coin.send_taker_payment(
        (now_ms() / 1000) as u32 + 1000,
        &[0],
        &[0],
        &pubkey,
        &dhash160(&secret_hex).to_vec(),
        1000,
    ).wait().unwrap();

    let eth: SignedEthTransaction = match res {
        TransactionEnum::Eth(t) => t,
        _ => panic!()
    };

    log!([eth.hash()]);

    let refund = coin.send_taker_spends_maker_payment(
        TransactionEnum::Eth(eth),
        &[0],
        &secret_hex,
        &pubkey,
        1000,
    ).wait().unwrap();

    let eth: SignedEthTransaction = match refund {
        TransactionEnum::Eth(t) => t,
        _ => panic!()
    };

    log!([eth.hash()]);
}

#[test]
fn test_send_and_spend_erc20_payment() {
    let transport = Http::with_remote_reactor("http://195.201.0.6:8545", &CORE, 1).unwrap();
    let web3 = Web3::new(transport);

    let secret_hex = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair: KeyPair = unwrap!(KeyPair::from_secret_slice(&secret_hex));

    let coin = EthCoin(Arc::new(EthCoinImpl {
        decimals: 18,
        gas_station_url: Some("https://ethgasstation.info/json/ethgasAPI.json".into()),
        web3,
        coin_type: EthCoinType::Erc20(Address::from("c0eb7aed740e1796992a08962c15661bdeb58003")),
        ticker: "ETH".into(),
        my_address: key_pair.address().clone(),
        key_pair,
        swap_contract_address: Address::from("7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94"),
    }));

    let pubkey = hex::decode("02031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3").unwrap();
    let res = coin.send_maker_payment(
        (now_ms() / 1000) as u32 + 1000,
        &[0],
        &[0],
        &pubkey,
        &dhash160(&secret_hex).to_vec(),
        1000,
    ).wait().unwrap();

    let eth: SignedEthTransaction = match res {
        TransactionEnum::Eth(t) => t,
        _ => panic!()
    };

    log!([eth.hash()]);

    let refund = coin.send_taker_spends_maker_payment(
        TransactionEnum::Eth(eth),
        &[0],
        &secret_hex,
        &pubkey,
        1000,
    ).wait().unwrap();

    let eth: SignedEthTransaction = match refund {
        TransactionEnum::Eth(t) => t,
        _ => panic!()
    };

    log!([eth.hash()]);
}

#[test]
fn test_addr_from_raw_pubkey() {
    let pubkey = hex::decode("03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06").unwrap();
    let address = addr_from_raw_pubkey(&pubkey).unwrap();
    assert_eq!(format!("{:#02x}", address), "0xd8997941dd1346e9231118d5685d866294f59e5b");

    let pubkey = hex::decode("02031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3").unwrap();
    let address = addr_from_raw_pubkey(&pubkey).unwrap();
    assert_eq!(format!("{:#02x}", address), "0xbab36286672fbdc7b250804bf6d14be0df69fa29");

    let pubkey = hex::decode("04031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f34bfe18b698c3d8ebff1e240fb52f38b44326c534eb2064968f873772baab789e").unwrap();
    let address = addr_from_raw_pubkey(&pubkey).unwrap();
    assert_eq!(format!("{:#02x}", address), "0xbab36286672fbdc7b250804bf6d14be0df69fa29");
}

#[test]
fn test_gas_price_from_station() {
    let res = log!([GasStationData::get_gas_price("https://ethgasstation.info/json/ethgasAPI.json").wait().unwrap()]);
}

#[test]
fn test_send_buyer_fee_eth() {
    let transport = Http::with_remote_reactor("http://195.201.0.6:8545", &CORE, 1).unwrap();
    let web3 = Web3::new(transport);

    let secret_hex = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair: KeyPair = unwrap!(KeyPair::from_secret_slice(&secret_hex));

    let coin = EthCoin(Arc::new(EthCoinImpl {
        decimals: 18,
        gas_station_url: Some("https://ethgasstation.info/json/ethgasAPI.json".into()),
        web3,
        coin_type: EthCoinType::Eth,
        ticker: "ETH".into(),
        my_address: key_pair.address().clone(),
        key_pair,
        swap_contract_address: Address::from("7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94"),
    }));

    let pubkey = hex::decode("02031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3").unwrap();
    let res = coin.send_taker_fee(&pubkey, 1000).wait().unwrap();

    let eth: SignedEthTransaction = match res {
        TransactionEnum::Eth(t) => t,
        _ => panic!()
    };

    log!([eth.hash()]);
}

#[test]
fn test_send_buyer_fee_erc20() {
    let transport = Http::with_remote_reactor("http://195.201.0.6:8545", &CORE, 1).unwrap();
    let web3 = Web3::new(transport);

    let secret_hex = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair: KeyPair = unwrap!(KeyPair::from_secret_slice(&secret_hex));

    let coin = EthCoin(Arc::new(EthCoinImpl {
        decimals: 18,
        gas_station_url: Some("https://ethgasstation.info/json/ethgasAPI.json".into()),
        web3,
        coin_type: EthCoinType::Erc20(Address::from("c0eb7aed740e1796992a08962c15661bdeb58003")),
        ticker: "ETH".into(),
        my_address: key_pair.address().clone(),
        key_pair,
        swap_contract_address: Address::from("7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94"),
    }));

    let pubkey = hex::decode("02031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3").unwrap();
    let res = coin.send_taker_fee(&pubkey, 1000).wait().unwrap();

    let eth: SignedEthTransaction = match res {
        TransactionEnum::Eth(t) => t,
        _ => panic!()
    };

    log!([eth.hash()]);
}

#[test]
fn test_get_allowance_erc20() {
    let transport = Http::with_remote_reactor("http://195.201.0.6:8545", &CORE, 1).unwrap();
    let web3 = Web3::new(transport);

    let secret_hex = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair: KeyPair = unwrap!(KeyPair::from_secret_slice(&secret_hex));

    let coin = EthCoin(Arc::new(EthCoinImpl {
        decimals: 18,
        gas_station_url: Some("https://ethgasstation.info/json/ethgasAPI.json".into()),
        web3,
        coin_type: EthCoinType::Erc20(Address::from("c0eb7aed740e1796992a08962c15661bdeb58003")),
        ticker: "ETH".into(),
        my_address: key_pair.address().clone(),
        key_pair,
        swap_contract_address: Address::from("7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94"),
    }));

    log!([coin.allowance(coin.swap_contract_address).wait().unwrap()]);
}

#[test]
fn test_my_balance_erc20() {
    let transport = Http::with_remote_reactor("http://195.201.0.6:8545", &CORE, 1).unwrap();
    let web3 = Web3::new(transport);

    let secret_hex = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair: KeyPair = unwrap!(KeyPair::from_secret_slice(&secret_hex));
    log!([key_pair.address()]);

    let coin = EthCoin(Arc::new(EthCoinImpl {
        decimals: 18,
        gas_station_url: Some("https://ethgasstation.info/json/ethgasAPI.json".into()),
        web3,
        coin_type: EthCoinType::Erc20(Address::from("c0eb7aed740e1796992a08962c15661bdeb58003")),
        ticker: "ETH".into(),
        my_address: key_pair.address().clone(),
        key_pair,
        swap_contract_address: Address::from("7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94"),
    }));

    log!([coin.my_balance().wait().unwrap()]);
}


#[test]
fn test_send_and_refund_erc20_payment() {
    let transport = Http::with_remote_reactor("http://195.201.0.6:8545", &CORE, 1).unwrap();
    let web3 = Web3::new(transport);

    let secret_hex = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair: KeyPair = unwrap!(KeyPair::from_secret_slice(&secret_hex));

    let coin = EthCoin(Arc::new(EthCoinImpl {
        decimals: 18,
        gas_station_url: Some("https://ethgasstation.info/json/ethgasAPI.json".into()),
        web3,
        coin_type: EthCoinType::Erc20(Address::from("c0eb7aed740e1796992a08962c15661bdeb58003")),
        ticker: "ETH".into(),
        my_address: key_pair.address().clone(),
        key_pair,
        swap_contract_address: Address::from("7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94"),
    }));

    let pubkey = hex::decode("02031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3").unwrap();
    let res = coin.send_maker_payment(
        (now_ms() / 1000) as u32 - 1000,
        &[0],
        &[0],
        &pubkey,
        &dhash160(&secret_hex).to_vec(),
        1000,
    ).wait().unwrap();

    let eth: SignedEthTransaction = match res {
        TransactionEnum::Eth(t) => t,
        _ => panic!()
    };

    log!([eth.hash()]);

    let refund = coin.send_taker_refunds_payment(
        TransactionEnum::Eth(eth),
        &[0],
        &pubkey,
        1000,
    ).wait().unwrap();

    let eth: SignedEthTransaction = match refund {
        TransactionEnum::Eth(t) => t,
        _ => panic!()
    };

    log!([eth.hash()]);
}

#[test]
fn test_send_and_refund_eth_payment() {
    let transport = Http::with_remote_reactor("http://195.201.0.6:8545", &CORE, 1).unwrap();
    let web3 = Web3::new(transport);

    let secret_hex = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair: KeyPair = unwrap!(KeyPair::from_secret_slice(&secret_hex));

    let coin = EthCoin(Arc::new(EthCoinImpl {
        decimals: 18,
        gas_station_url: None,
        web3,
        coin_type: EthCoinType::Eth,
        ticker: "ETH".into(),
        my_address: key_pair.address().clone(),
        key_pair,
        swap_contract_address: Address::from("7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94"),
    }));

    let pubkey = hex::decode("02031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3").unwrap();
    let res = coin.send_maker_payment(
        (now_ms() / 1000) as u32 - 1000,
        &[0],
        &[0],
        &pubkey,
        &dhash160(&secret_hex).to_vec(),
        1000,
    ).wait().unwrap();

    let eth: SignedEthTransaction = match res {
        TransactionEnum::Eth(t) => t,
        _ => panic!()
    };

    log!([eth.hash()]);

    let refund = coin.send_taker_refunds_payment(
        TransactionEnum::Eth(eth),
        &[0],
        &pubkey,
        1000,
    ).wait().unwrap();

    let eth: SignedEthTransaction = match refund {
        TransactionEnum::Eth(t) => t,
        _ => panic!()
    };

    log!([eth.hash()]);
}