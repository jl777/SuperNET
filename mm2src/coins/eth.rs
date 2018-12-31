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
use common::CORE;
use ethereum_types::Address;
use ethkey::{ KeyPair, Secret, Public, public_to_address };
use futures::Future;
use std::borrow::Cow;
use std::ops::Deref;
use std::sync::Arc;
use web3::transports::{ Http };
use web3::{ self, Web3 };

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
    fn send_buyer_fee(&self, fee_addr: &[u8], amount: f64) -> TransactionFut {
        unimplemented!();
    }

    fn send_seller_payment(
        &self,
        time_lock: u32,
        pub_a0: &[u8],
        pub_b0: &[u8],
        priv_bn_hash: &[u8],
        amount: f64
    ) -> TransactionFut {
        unimplemented!();
    }

    fn send_buyer_payment(
        &self,
        time_lock: u32,
        pub_a0: &[u8],
        pub_b0: &[u8],
        priv_bn_hash: &[u8],
        amount: f64,
    ) -> TransactionFut {
        unimplemented!();
    }

    fn send_seller_spends_buyer_payment(
        &self,
        buyer_payment_tx: TransactionEnum,
        b_priv_0: &[u8],
        b_priv_n: &[u8],
        amount: f64
    ) -> TransactionFut {
        unimplemented!();
    }

    fn send_buyer_spends_seller_payment(
        &self,
        seller_payment_tx: TransactionEnum,
        a_priv_0: &[u8],
        b_priv_n: &[u8],
        amount: f64
    ) -> TransactionFut {
        unimplemented!();
    }

    fn send_buyer_refunds_payment(
        &self,
        buyer_payment_tx: TransactionEnum,
        a_priv_0: &[u8],
        amount: f64
    ) -> TransactionFut {
        unimplemented!();
    }

    fn send_seller_refunds_payment(
        &self,
        seller_payment_tx: TransactionEnum,
        b_priv_0: &[u8],
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
}
