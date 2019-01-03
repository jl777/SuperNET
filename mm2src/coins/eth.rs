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
use common::CORE;
use secp256k1::key::PublicKey;
use ethabi::{Contract, Token};
use ethcore_transaction::{ Action, Transaction };
use ethereum_types::{Address, U256, H160, H512};
use ethkey::{ KeyPair, Secret, Public, public_to_address, SECP256K1 };
use futures::Future;
use gstuff::now_ms;
use keys::generator::{Random, Generator};
use std::borrow::Cow;
use std::ops::Deref;
use std::sync::Arc;
use web3::transports::{ Http };
use web3::{ self, Web3 };

use super::utxo::compressed_key_pair_from_bytes;
use super::{IguanaInfo, MarketCoinOps, MmCoin, SwapOps, TransactionFut, TransactionEnum};

const SWAP_CONTRACT_ABI: &'static str = r#"[{"constant":false,"inputs":[{"name":"_id","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_secret","type":"bytes32"},{"name":"_tokenAddress","type":"address"},{"name":"_sender","type":"address"}],"name":"receiverSpend","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"bytes32"}],"name":"payments","outputs":[{"name":"paymentHash","type":"bytes20"},{"name":"lockTime","type":"uint64"},{"name":"state","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_id","type":"bytes32"},{"name":"_receiver","type":"address"},{"name":"_secretHash","type":"bytes20"},{"name":"_lockTime","type":"uint64"}],"name":"ethPayment","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":false,"inputs":[{"name":"_id","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_paymentHash","type":"bytes20"},{"name":"_tokenAddress","type":"address"},{"name":"_receiver","type":"address"}],"name":"senderRefund","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_id","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_tokenAddress","type":"address"},{"name":"_receiver","type":"address"},{"name":"_secretHash","type":"bytes20"},{"name":"_lockTime","type":"uint64"}],"name":"erc20Payment","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"name":"id","type":"bytes32"}],"name":"PaymentSent","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"id","type":"bytes32"},{"indexed":false,"name":"secret","type":"bytes32"}],"name":"ReceiverSpent","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"id","type":"bytes32"}],"name":"SenderRefunded","type":"event"}]"#;
const ERC20_ABI: &'static str = r#"[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_subtractedValue","type":"uint256"}],"name":"decreaseApproval","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_addedValue","type":"uint256"}],"name":"increaseApproval","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"},{"indexed":true,"name":"spender","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"}]"#;

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
}

#[derive(Clone, Debug)]
pub struct EthCoin(Arc<EthCoinImpl>);
impl Deref for EthCoin {type Target = EthCoinImpl; fn deref (&self) -> &EthCoinImpl {&*self.0}}

impl SwapOps for EthCoin {
    fn send_taker_fee(&self, fee_addr: &[u8], amount: f64) -> TransactionFut {
        unimplemented!();
    }

    fn send_seller_payment(
        &self,
        time_lock: u32,
        pub_a0: &[u8],
        pub_b0: &[u8],
        taker_addr: &[u8],
        priv_bn_hash: &[u8],
        amount: f64
    ) -> TransactionFut {
        unimplemented!();
    }

    fn send_taker_payment(
        &self,
        time_lock: u32,
        pub_a0: &[u8],
        pub_b0: &[u8],
        maker_addr: &[u8],
        priv_bn_hash: &[u8],
        amount: f64,
    ) -> TransactionFut {
        unimplemented!();
    }

    fn send_seller_spends_taker_payment(
        &self,
        taker_payment_tx: TransactionEnum,
        b_priv_0: &[u8],
        b_priv_n: &[u8],
        taker_addr: &[u8],
        amount: f64
    ) -> TransactionFut {
        unimplemented!();
    }

    fn send_taker_spends_seller_payment(
        &self,
        seller_payment_tx: TransactionEnum,
        a_priv_0: &[u8],
        b_priv_n: &[u8],
        maker_addr: &[u8],
        amount: f64
    ) -> TransactionFut {
        unimplemented!();
    }

    fn send_taker_refunds_payment(
        &self,
        taker_payment_tx: TransactionEnum,
        a_priv_0: &[u8],
        maker_addr: &[u8],
        amount: f64
    ) -> TransactionFut {
        unimplemented!();
    }

    fn send_seller_refunds_payment(
        &self,
        seller_payment_tx: TransactionEnum,
        b_priv_0: &[u8],
        taker_addr: &[u8],
        amount: f64
    ) -> TransactionFut {
        unimplemented!();
    }
}

impl MarketCoinOps for EthCoin {
    fn address(&self) -> Cow<str> {
        self.my_address.to_string().into()
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

impl IguanaInfo for EthCoin {
    fn ticker<'a> (&'a self) -> &'a str {&self.ticker[..]}
}
impl MmCoin for EthCoin {}

#[test]
fn web3_from_core() {
    let transport = Http::with_remote_reactor("http://195.201.0.6:8545", &CORE, 1).unwrap();

    let web3 = Web3::new(transport);
    log!([web3.eth().block_number().wait().unwrap()]);

    let secret_hex = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair = unwrap!(KeyPair::from_secret_slice(&secret_hex));

    log!([key_pair.address()]);
    let nonce = web3.eth().parity_next_nonce(key_pair.address()).wait().unwrap();
    let gas_price = U256::exp10(10);
    let value = U256::exp10(17);
    let gas = U256::from(21000);
    let action = Action::Call(key_pair.address());
    let data = vec![].into();

    let tx = Transaction {
        nonce,
        value,
        action,
        data,
        gas,
        gas_price,
    };

    let signed = tx.sign(key_pair.secret(), None);
    log!([web3.eth().send_raw_transaction(web3::types::Bytes(rlp::encode(&signed).to_vec())).wait().unwrap()]);
}

#[test]
fn test_send_and_refund_eth_payment() {
    let contract_address = Address::from("7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94");

    let transport = Http::with_remote_reactor("http://195.201.0.6:8545", &CORE, 1).unwrap();
    let id = Random::new(0).generate().unwrap();

    let web3 = Web3::new(transport);
    log!([web3.eth().block_number().wait().unwrap()]);

    let secret_hex = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair = unwrap!(KeyPair::from_secret_slice(&secret_hex));

    log!([key_pair.address()]);

    let abi = Contract::load(SWAP_CONTRACT_ABI.as_bytes()).unwrap();
    let function = abi.function("ethPayment").unwrap();
    let data = function.encode_input(&[
        Token::FixedBytes(id.private().secret.to_vec()),
        Token::Address(key_pair.address()),
        Token::FixedBytes(dhash160(&secret_hex).to_vec()),
        Token::Uint(U256::from(now_ms() / 1000 + 1000))
    ]).unwrap();

    let nonce = web3.eth().parity_next_nonce(key_pair.address()).wait().unwrap();
    let gas_price = U256::exp10(10);
    let value = U256::exp10(17);
    let gas = U256::from(150000);
    let action = Action::Call(contract_address.clone());

    let tx = Transaction {
        nonce,
        value,
        action,
        data,
        gas,
        gas_price,
    };

    let signed = tx.sign(key_pair.secret(), None);
    log!([web3.eth().send_raw_transaction(web3::types::Bytes(rlp::encode(&signed).to_vec())).wait().unwrap()]);

    let function = abi.function("receiverSpend").unwrap();
    let nonce = web3.eth().parity_next_nonce(key_pair.address()).wait().unwrap();
    let gas_price = U256::exp10(10);
    let value = U256::exp10(17);
    let gas = U256::from(150000);
    let action = Action::Call(contract_address.clone());

    let data = function.encode_input(&[
        Token::FixedBytes(id.private().secret.to_vec()),
        Token::Uint(value),
        Token::FixedBytes(secret_hex.clone()),
        Token::Address(H160::default()),
        Token::Address(key_pair.address()),
    ]).unwrap();

    let tx = Transaction {
        nonce,
        value: U256::from(0),
        action,
        data,
        gas,
        gas_price,
    };
    let signed = tx.sign(key_pair.secret(), None);
    log!([web3.eth().send_raw_transaction(web3::types::Bytes(rlp::encode(&signed).to_vec())).wait().unwrap()]);
}

#[test]
fn fee_addr_from_compressed_pubkey() {
    let secret_hex = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let private = compressed_key_pair_from_bytes(&secret_hex, 0).unwrap();
    log!([private]);
    let pubkey = private.public();
    let pubkey = hex::decode("03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06").unwrap();
    let pubkey = PublicKey::from_slice(&SECP256K1, &pubkey).unwrap();
    let eth_public = Public::from(&pubkey.serialize_vec(&SECP256K1, false)[1..65]);
    log!([public_to_address(&eth_public)]);
}
