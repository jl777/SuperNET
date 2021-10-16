use super::{CoinBalance, HistorySyncState, MarketCoinOps, MmCoin, SwapOps, TradeFee, TransactionEnum, TransactionFut};
use crate::solana::{AccountError, SolanaFeeDetails};
use crate::{BalanceError, BalanceFut, FeeApproxStage, FoundSwapTxSpend, NegotiateSwapContractAddrErr, SolanaCoin,
            TradePreimageFut, TradePreimageValue, TransactionDetails, ValidateAddressResult, WithdrawError,
            WithdrawFut, WithdrawRequest, WithdrawResult};
use bigdecimal::{BigDecimal, ToPrimitive};
use bincode::serialize;
use common::mm_error::prelude::MapToMmResult;
use common::{mm_ctx::MmArc, mm_error::MmError, mm_number::MmNumber, now_ms};
use futures::{compat::Future01CompatExt, FutureExt, TryFutureExt};
use futures01::Future;
use mocktopus::macros::*;
use rpc::v1::types::Bytes as BytesJson;
use serde_json::Value as Json;
use solana_client::{rpc_client::RpcClient, rpc_request::TokenAccountsFilter};
use solana_sdk::hash::Hash;
use solana_sdk::message::Message;
use solana_sdk::native_token::lamports_to_sol;
use solana_sdk::transaction::Transaction;
use solana_sdk::{pubkey::Pubkey, signature::Signer};
use spl_associated_token_account::{create_associated_token_account, get_associated_token_address};
use std::{convert::TryFrom,
          fmt::{Debug, Formatter, Result as FmtResult},
          str::FromStr,
          sync::atomic::AtomicU64,
          sync::Arc};

#[derive(Debug)]
pub struct SplTokenConf {
    pub decimals: u8,
    pub ticker: String,
    pub token_contract_address: Pubkey,
    pub required_confirmations: AtomicU64,
}

#[derive(Clone)]
pub struct SplToken {
    pub conf: Arc<SplTokenConf>,
    pub platform_coin: SolanaCoin,
}

impl Debug for SplToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult { f.write_str(self.conf.ticker.to_string().as_str()) }
}

async fn check_sufficient_balance(
    coin: &SplToken,
    req: &WithdrawRequest,
) -> Result<(BigDecimal, BigDecimal), MmError<WithdrawError>> {
    let my_balance = coin.my_balance().compat().await?.spendable;
    let to_send = if req.max {
        my_balance.clone()
    } else {
        req.amount.clone()
    };
    if to_send > my_balance {
        return MmError::err(WithdrawError::NotSufficientBalance {
            coin: coin.conf.ticker.clone(),
            available: my_balance.clone(),
            required: &to_send - &my_balance,
        });
    }
    Ok((to_send, my_balance))
}

async fn check_amount_too_low(coin: &SplToken) -> Result<(BigDecimal, Hash), MmError<WithdrawError>> {
    let base_balance = coin.platform_coin.base_coin_balance().compat().await?;
    let (hash, fee_calculator) = coin.rpc().get_recent_blockhash()?;
    let sol_required = BigDecimal::from(lamports_to_sol(fee_calculator.lamports_per_signature));
    if base_balance < sol_required {
        return MmError::err(WithdrawError::AmountTooLow {
            amount: base_balance.clone(),
            threshold: &sol_required - &base_balance,
        });
    }
    Ok((sol_required, hash))
}

async fn withdraw_spl_token_impl(coin: SplToken, req: WithdrawRequest) -> WithdrawResult {
    let (to_send, my_balance) = check_sufficient_balance(&coin, &req).await?;
    let (sol_required, hash) = check_amount_too_low(&coin).await?;
    let system_destination_pubkey = solana_sdk::pubkey::Pubkey::try_from(req.to.as_str())?;
    let contract_key = coin.get_underlying_contract_pubkey();
    let auth_key = coin.platform_coin.key_pair.pubkey();
    let funding_address = coin.get_pubkey()?;
    let dest_token_address = get_associated_token_address(&system_destination_pubkey, &contract_key);
    let mut instructions = Vec::with_capacity(1);
    let account_info = coin.rpc().get_account(&dest_token_address);
    if account_info.is_err() {
        let instruction_creation = create_associated_token_account(&auth_key, &dest_token_address, &contract_key);
        instructions.push(instruction_creation);
    }
    let raw_amount = req.amount.to_f64().unwrap_or_default();
    let amount = spl_token::ui_amount_to_amount(raw_amount, coin.conf.decimals);
    let instruction_transfer = spl_token::instruction::transfer(
        &spl_token::id(),
        &funding_address,
        &dest_token_address,
        &auth_key,
        &[],
        amount,
    )?;
    instructions.push(instruction_transfer);
    let msg = Message::new(&instructions, Some(&auth_key));
    let signers = vec![&coin.platform_coin.key_pair];
    let tx = Transaction::new(&signers, msg, hash);
    let serialized_tx = serialize(&tx).map_to_mm(|e| WithdrawError::InternalError(e.to_string()))?;
    let encoded_tx = hex::encode(&serialized_tx);
    let received_by_me = if req.to == coin.platform_coin.my_address {
        to_send.clone()
    } else {
        0.into()
    };
    Ok(TransactionDetails {
        tx_hex: encoded_tx.as_bytes().into(),
        tx_hash: tx.signatures[0].as_ref().into(),
        from: vec![coin.platform_coin.my_address.clone()],
        to: vec![req.to],
        total_amount: to_send.clone(),
        spent_by_me: to_send.clone(),
        received_by_me,
        my_balance_change: &my_balance - &to_send,
        block_height: 0,
        timestamp: now_ms() / 1000,
        fee_details: Some(SolanaFeeDetails { amount: sol_required }.into()),
        coin: coin.conf.ticker.clone(),
        internal_id: vec![].into(),
        kmd_rewards: None,
    })
}

async fn withdraw_impl(coin: SplToken, req: WithdrawRequest) -> WithdrawResult {
    let validate_address_result = coin.validate_address(req.to.as_str());
    if !validate_address_result.is_valid {
        return MmError::err(WithdrawError::InvalidAddress(
            validate_address_result.reason.unwrap_or_else(|| "Unknown".to_string()),
        ));
    }
    withdraw_spl_token_impl(coin, req).await
}

impl SplToken {
    fn rpc(&self) -> &RpcClient { &self.platform_coin.client }
    fn get_underlying_contract_pubkey(&self) -> Pubkey {
        let key = self.conf.token_contract_address.clone();
        println!("{}", key.to_string());
        key
    }

    fn get_pubkey(&self) -> Result<Pubkey, MmError<AccountError>> {
        let coin = self.clone();
        let token_accounts = coin.rpc().get_token_accounts_by_owner(
            &coin.platform_coin.key_pair.pubkey(),
            TokenAccountsFilter::Mint(coin.get_underlying_contract_pubkey()),
        )?;
        if token_accounts.is_empty() {
            return MmError::err(AccountError::NotFundedError("account_not_funded".to_string()));
        }
        Ok(Pubkey::from_str(token_accounts[0].pubkey.as_str())?)
    }

    fn my_balance_impl(&self) -> BalanceFut<f64> {
        let coin = self.clone();
        let fut = async move {
            let token_accounts = coin.rpc().get_token_accounts_by_owner(
                &coin.platform_coin.key_pair.pubkey(),
                TokenAccountsFilter::Mint(coin.get_underlying_contract_pubkey()),
            )?;
            if token_accounts.is_empty() {
                return Ok(0.0);
            }
            let actual_token_pubkey = Pubkey::from_str(token_accounts[0].pubkey.as_str())
                .map_err(|e| BalanceError::Internal(format!("{:?}", e)))?;
            let amount = coin.rpc().get_token_account_balance(&actual_token_pubkey)?;
            Ok(amount.ui_amount.unwrap_or(0.0))
        };
        Box::new(fut.boxed().compat())
    }
}

#[mockable]
#[allow(clippy::forget_ref, clippy::forget_copy, clippy::cast_ref_to_mut)]
impl MarketCoinOps for SplToken {
    fn ticker(&self) -> &str { &self.conf.ticker.as_str() }

    fn my_address(&self) -> Result<String, String> { Ok(self.platform_coin.my_address.clone()) }

    fn my_balance(&self) -> BalanceFut<CoinBalance> {
        let fut = self.my_balance_impl().and_then(move |result| {
            Ok(CoinBalance {
                spendable: BigDecimal::from(result),
                unspendable: BigDecimal::from(0),
            })
        });
        Box::new(fut)
    }

    fn base_coin_balance(&self) -> BalanceFut<BigDecimal> { self.platform_coin.base_coin_balance() }

    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> {
        self.platform_coin.send_raw_tx(tx)
    }

    fn wait_for_confirmations(
        &self,
        _tx: &[u8],
        _confirmations: u64,
        _requires_nota: bool,
        _wait_until: u64,
        _check_every: u64,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        unimplemented!()
    }

    fn wait_for_tx_spend(
        &self,
        _transaction: &[u8],
        _wait_until: u64,
        _from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn tx_enum_from_bytes(&self, _bytes: &[u8]) -> Result<TransactionEnum, String> { unimplemented!() }

    fn current_block(&self) -> Box<dyn Future<Item = u64, Error = String> + Send> { self.platform_coin.current_block() }

    fn display_priv_key(&self) -> String { self.platform_coin.display_priv_key() }

    fn min_tx_amount(&self) -> BigDecimal { BigDecimal::from(0) }

    fn min_trading_vol(&self) -> MmNumber { MmNumber::from("0.00777") }
}

#[mockable]
#[allow(clippy::forget_ref, clippy::forget_copy, clippy::cast_ref_to_mut)]
impl SwapOps for SplToken {
    fn send_taker_fee(&self, _fee_addr: &[u8], amount: BigDecimal, _uuid: &[u8]) -> TransactionFut { unimplemented!() }

    fn send_maker_payment(
        &self,
        _time_lock: u32,
        _taker_pub: &[u8],
        _secret_hash: &[u8],
        _amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_taker_payment(
        &self,
        _time_lock: u32,
        _maker_pub: &[u8],
        _secret_hash: &[u8],
        _amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_maker_spends_taker_payment(
        &self,
        _taker_payment_tx: &[u8],
        _time_lock: u32,
        _taker_pub: &[u8],
        _secret: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_taker_spends_maker_payment(
        &self,
        _maker_payment_tx: &[u8],
        _time_lock: u32,
        _maker_pub: &[u8],
        _secret: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_taker_refunds_payment(
        &self,
        _taker_payment_tx: &[u8],
        _time_lock: u32,
        _maker_pub: &[u8],
        _secret_hash: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_maker_refunds_payment(
        &self,
        _maker_payment_tx: &[u8],
        _time_lock: u32,
        _taker_pub: &[u8],
        _secret_hash: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn validate_fee(
        &self,
        _fee_tx: &TransactionEnum,
        _expected_sender: &[u8],
        _fee_addr: &[u8],
        _amount: &BigDecimal,
        _min_block_number: u64,
        _uuid: &[u8],
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        unimplemented!()
    }

    fn validate_maker_payment(
        &self,
        _payment_tx: &[u8],
        _time_lock: u32,
        _maker_pub: &[u8],
        _priv_bn_hash: &[u8],
        _amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        unimplemented!()
    }

    fn validate_taker_payment(
        &self,
        _payment_tx: &[u8],
        _time_lock: u32,
        _taker_pub: &[u8],
        _priv_bn_hash: &[u8],
        _amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        unimplemented!()
    }

    fn check_if_my_payment_sent(
        &self,
        _time_lock: u32,
        _other_pub: &[u8],
        _secret_hash: &[u8],
        _search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = Option<TransactionEnum>, Error = String> + Send> {
        unimplemented!()
    }

    fn search_for_swap_tx_spend_my(
        &self,
        _time_lock: u32,
        _other_pub: &[u8],
        _secret_hash: &[u8],
        _tx: &[u8],
        _search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        unimplemented!()
    }

    fn search_for_swap_tx_spend_other(
        &self,
        _time_lock: u32,
        _other_pub: &[u8],
        _secret_hash: &[u8],
        _tx: &[u8],
        _search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        unimplemented!()
    }

    fn extract_secret(&self, secret_hash: &[u8], spend_tx: &[u8]) -> Result<Vec<u8>, String> { unimplemented!() }

    fn negotiate_swap_contract_addr(
        &self,
        _other_side_address: Option<&[u8]>,
    ) -> Result<Option<BytesJson>, MmError<NegotiateSwapContractAddrErr>> {
        unimplemented!()
    }
}

#[mockable]
#[allow(clippy::forget_ref, clippy::forget_copy, clippy::cast_ref_to_mut)]
impl MmCoin for SplToken {
    fn is_asset_chain(&self) -> bool { false }

    fn withdraw(&self, req: WithdrawRequest) -> WithdrawFut {
        Box::new(Box::pin(withdraw_impl(self.clone(), req)).compat())
    }

    fn decimals(&self) -> u8 { self.conf.decimals }

    fn convert_to_address(&self, _from: &str, _to_address_format: Json) -> Result<String, String> { unimplemented!() }

    fn validate_address(&self, address: &str) -> ValidateAddressResult { self.platform_coin.validate_address(address) }

    fn process_history_loop(&self, _ctx: MmArc) -> Box<dyn Future<Item = (), Error = ()> + Send> { unimplemented!() }

    fn history_sync_status(&self) -> HistorySyncState { unimplemented!() }

    /// Get fee to be paid per 1 swap transaction
    fn get_trade_fee(&self) -> Box<dyn Future<Item = TradeFee, Error = String> + Send> { unimplemented!() }

    fn get_sender_trade_fee(&self, _value: TradePreimageValue, _stage: FeeApproxStage) -> TradePreimageFut<TradeFee> {
        unimplemented!()
    }

    fn get_receiver_trade_fee(&self, _stage: FeeApproxStage) -> TradePreimageFut<TradeFee> { unimplemented!() }

    fn get_fee_to_send_taker_fee(
        &self,
        _dex_fee_amount: BigDecimal,
        _stage: FeeApproxStage,
    ) -> TradePreimageFut<TradeFee> {
        unimplemented!()
    }

    fn required_confirmations(&self) -> u64 { 1 }

    fn requires_notarization(&self) -> bool { false }

    fn set_required_confirmations(&self, _confirmations: u64) { unimplemented!() }

    fn set_requires_notarization(&self, _requires_nota: bool) { unimplemented!() }

    fn swap_contract_address(&self) -> Option<BytesJson> { unimplemented!() }

    fn mature_confirmations(&self) -> Option<u32> { unimplemented!() }

    fn coin_protocol_info(&self) -> Vec<u8> { Vec::new() }

    fn is_coin_protocol_supported(&self, _info: &Option<Vec<u8>>) -> bool { true }
}
