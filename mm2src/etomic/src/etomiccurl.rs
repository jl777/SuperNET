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
//  etomiccurl.rs
//  marketmaker
//
//  Copyright © 2017-2018 SuperNET. All rights reserved.
//

#![allow(non_camel_case_types)]

use std::os::raw::{ c_char };
use etomic::EthClient;
use std::ffi::{ CStr, CString };
use ethereum_types::{ U256, H256 };
use hex;
use libc;
use serde_json;
use helpers::{ post_json, fetch_json };
use std::str::FromStr;
use web3::{ Transport };
use tokio_timer::{ Interval, Timer };
use futures::{ Future, Poll, Stream, Async };
use web3::types::{
    Transaction as Web3Transaction,
    TransactionReceipt,
    TransactionId
};
use web3::helpers::CallResult;
use std::time::Duration;
use web3::transports::{ Http };

include!("../c_headers/etomiclib.rs");

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
    pub average: f64
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum EtomicFaucetResult {
    String(String),
    Vector(Vec<String>)
}

#[derive(Deserialize, Debug)]
struct EtomicFaucetResponse {
    result: Option<EtomicFaucetResult>,
    error: Option<String>
}

#[derive(Serialize, Debug)]
struct EtomicFaucetRequest {
    #[serde(rename = "etomicAddress")]
    etomic_address: String
}

enum WaitForReceiptState<T>
    where T: Transport
{
    WaitingForInterval,
    GettingReceipt(CallResult<Option<TransactionReceipt>, T::Out>),
    GettingData(CallResult<Option<Web3Transaction>, T::Out>),
}

struct WaitForReceipt<'a> {
    interval: Interval,
    eth_client: &'a EthClient,
    state: WaitForReceiptState<Http>,
    tx_id: H256,
    retries: u8,
    max_retries: u8
}

impl<'a> WaitForReceipt<'a> {
    fn new(eth_client: &'a EthClient, tx_id: H256, max_retries: u8, poll_interval: u64) -> Self {
        WaitForReceipt {
            interval: Timer::default().interval(Duration::from_secs(poll_interval)),
            eth_client,
            state: WaitForReceiptState::WaitingForInterval,
            tx_id,
            retries: 0,
            max_retries
        }
    }
}

impl<'a> Future for WaitForReceipt<'a> {
    type Item = TransactionReceipt;
    type Error = String;

    fn poll(&mut self) -> Poll<TransactionReceipt, String> {
        loop {
            let next_state = match self.state {
                WaitForReceiptState::WaitingForInterval => {
                    let _ready = try_ready!(
                        self.interval
                            .poll()
                            .map_err(|_| "Error occurred")
                    );
                    WaitForReceiptState::GettingReceipt(self.eth_client.web3.eth().transaction_receipt(self.tx_id))
                },
                WaitForReceiptState::GettingReceipt(ref mut future) => {
                    let ready = future.poll();
                    match ready {
                        Ok(Async::Ready(tx_receipt)) => {
                            match tx_receipt {
                                Some(receipt) => return Ok(Async::Ready(receipt)),
                                None => {
                                    println!("Could not find receipt of {:?} yet, checking tx existence", self.tx_id);
                                    WaitForReceiptState::GettingData(
                                        self.eth_client.web3.eth().transaction(TransactionId::Hash(self.tx_id))
                                    )
                                }
                            }
                        },
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Err(_e) => {
                            println!("Could not find receipt of {:?} yet, checking tx existence", self.tx_id);
                            WaitForReceiptState::GettingData(
                                self.eth_client.web3.eth().transaction(TransactionId::Hash(self.tx_id))
                            )
                        }
                    }
                },
                WaitForReceiptState::GettingData(ref mut future) => {
                    let _ready = try_ready!(
                        future.poll()
                            .map_err(|e| {
                                println!("Got error {:?}", e);
                                "Error occurred"
                            })
                    );
                    match _ready {
                        Some(_data) => {
                            println!("Transaction 0x{:02x} exists, but not confirmed yet", self.tx_id);
                            self.retries = self.retries + 1;
                            if self.retries >= self.max_retries {
                                return Err(format!("Waiting too long for tx 0x{:02x} confirmation!", self.tx_id))
                            }
                            WaitForReceiptState::WaitingForInterval
                        },
                        None => {
                            println!("Could not find tx data 0x{:02x}!", self.tx_id);
                            return Err("Tx is not found!".to_string())
                        }
                    }
                },
            };
            self.state = next_state;
        }
    }
}

#[no_mangle]
pub extern "C" fn get_eth_tx_receipt(
    tx_id: *const c_char,
    eth_client: *mut EthClient
) -> EthTxReceipt {
    let mut result = EthTxReceipt {
        confirmations: 0,
        block_number: 0,
        status: 0
    };
    unsafe {
        let slice = CStr::from_ptr(tx_id).to_str().unwrap();
        let request = (*eth_client).get_tx_receipt(H256::from_str(&slice[2..]).unwrap());
        match request {
            Ok((receipt, confirmations)) => {
                match receipt {
                    Some(res) => {
                        result.block_number = res.block_number.into();
                        result.confirmations = confirmations.into();
                        result.status = unwrap!(
                            res.status,
                            "Could not unwrap ETH tx receipt status"
                        ).as_u64();
                    },
                    None => println!("Tx receipt of {:?} is None", tx_id)
                }
            },
            Err(e) => println!("Got error trying to get tx receipt: {:?} {}", tx_id, e)
        }
    }
    result
}

#[no_mangle]
pub extern "C" fn get_eth_tx_data(
    tx_id: *const c_char,
    eth_client: *mut EthClient
) -> EthTxData {
    let mut result = EthTxData {
        from: [0; 50],
        to: [0; 50],
        input: [0; 1000],
        value: 0,
        exists: 0
    };
    unsafe {
        let slice = CStr::from_ptr(tx_id).to_str().unwrap();
        let request = (*eth_client).get_tx(H256::from_str(&slice[2..]).unwrap());
        match request {
            Ok(data) => {
                match data {
                    Some(tx) => {
                        result.exists = 1;
                        result.value = (tx.value / U256::exp10(10)).into();
                        let from_str = format!("0x{:02x}", tx.from);
                        let to_str = format!("0x{:02x}", tx.to.unwrap());
                        let input_str = format!("0x{}", hex::encode(tx.input.0));
                        libc::strcpy(result.from.as_mut_ptr(), CString::new(from_str).unwrap().as_ptr());
                        libc::strcpy(result.to.as_mut_ptr(), CString::new(to_str).unwrap().as_ptr());
                        libc::strcpy(result.input.as_mut_ptr(), CString::new(input_str).unwrap().as_ptr());
                    },
                    None => println!("Tx data of {:?} is None", tx_id)
                }
            },
            Err(e) => println!("Got error trying to get tx data: {:?} {}", tx_id, e)
        }
    }
    result
}

#[no_mangle]
pub extern "C" fn get_gas_price_from_station(
    default_on_err: u8
) -> u64 {
    let fetch_result = fetch_json::<GasStationData>(
        "https://ethgasstation.info/json/ethgasAPI.json").wait();
    match fetch_result {
        // dividing by 10 because gas station returns not exactly gwei amount for some reason:
        // e.g. 30 means 3 gwei actually
        // adding 1 to have has price slightly higher decreasing possibility of ETH tx
        // to get stuck unconfirmed
        Ok(data) => (data.average as u64) / 10 + 1,
        Err(e) => {
            println!("Got error fetching gas price from station: {:?}", e);
            match default_on_err {
                1 => 10,
                _ => 0
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn get_etomic_from_faucet(etomic_addr: *const c_char) -> u8 {
    unsafe {
        let request = EtomicFaucetRequest {
            etomic_address: CStr::from_ptr(etomic_addr).to_string_lossy().into_owned()
        };
        let json = serde_json::to_string(&request).unwrap();
        println!("Etomic faucet request: {:?}", json);
        let post = post_json::<EtomicFaucetResponse>(
            "http://195.201.116.176:8000/getEtomic",
            json
        ).wait();
        match post {
            Ok(result) => {
                if result.error.is_some() {
                    println!("Got error from Etomic faucet: {:?}", result.error.unwrap());
                    0
                } else {
                    println!("Got result from Etomic faucet: {:?}", result.result.unwrap());
                    1
                }
            },
            Err(e) => {
                println!("Etomic faucet request failed: {:?}", e);
                0
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn wait_for_confirmation(
    tx_id: *const c_char,
    eth_client: *mut EthClient
)-> i32 {
    unsafe {
        let slice = CStr::from_ptr(tx_id).to_str().unwrap();
        let wait = WaitForReceipt::new(
            &(*eth_client),
            H256::from_str(&slice[2..]).unwrap(),
            30,
            15
        );
        let receipt = wait.wait();
        match receipt {
            Ok(_tx_receipt) => 1,
            Err(e) => {
                println!("Got error waiting for ETH tx receipt: {:?}", e);
                -1
            }
        }
    }
}

#[cfg(test)]
#[test]
fn test_gas_price_from_station() {
    let res = get_gas_price_from_station(0);
    assert!(res > 0);
}

#[cfg(test)]
#[test]
fn test_get_etomic_from_faucet() {
    let res = get_etomic_from_faucet(CString::new("R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW").unwrap().as_ptr());
    assert_eq!(res, 1);
}
