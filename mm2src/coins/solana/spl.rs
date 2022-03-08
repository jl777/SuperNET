use super::{CoinBalance, HistorySyncState, MarketCoinOps, MmCoin, SwapOps, TradeFee, TransactionEnum, TransactionFut};
use crate::common::Future01CompatExt;
use crate::solana::solana_common::{lamports_to_sol, ui_amount_to_amount, SufficientBalanceError};
use crate::solana::{solana_common, AccountError, SolanaAsyncCommonOps, SolanaCommonOps, SolanaFeeDetails};
use crate::{BalanceError, BalanceFut, FeeApproxStage, FoundSwapTxSpend, NegotiateSwapContractAddrErr, SolanaCoin,
            TradePreimageFut, TradePreimageResult, TradePreimageValue, TransactionDetails, TransactionType,
            ValidateAddressResult, ValidatePaymentInput, WithdrawError, WithdrawFut, WithdrawRequest, WithdrawResult};
use async_trait::async_trait;
use bigdecimal::BigDecimal;
use bincode::serialize;
use common::mm_error::prelude::MapToMmResult;
use common::{mm_ctx::MmArc, mm_error::MmError, mm_number::MmNumber, now_ms};
use futures::{FutureExt, TryFutureExt};
use futures01::Future;
use keys::KeyPair;
use rpc::v1::types::Bytes as BytesJson;
use serde_json::Value as Json;
use solana_client::{nonblocking::rpc_client::RpcClient, rpc_request::TokenAccountsFilter};
use solana_sdk::message::Message;
use solana_sdk::transaction::Transaction;
use solana_sdk::{pubkey::Pubkey, signature::Signer};
use spl_associated_token_account::{create_associated_token_account, get_associated_token_address};
use std::{convert::TryFrom,
          fmt::{Debug, Formatter, Result as FmtResult},
          str::FromStr,
          sync::Arc};

#[derive(Debug)]
pub struct SplTokenConf {
    pub decimals: u8,
    pub ticker: String,
    pub token_contract_address: Pubkey,
}

#[derive(Clone, Debug)]
pub struct SplTokenInfo {
    pub token_contract_address: Pubkey,
    pub decimals: u8,
}

#[derive(Debug)]
pub struct SplProtocolConf {
    pub platform_coin_ticker: String,
    pub decimals: u8,
    pub token_contract_address: Pubkey,
}

#[derive(Clone)]
pub struct SplToken {
    pub conf: Arc<SplTokenConf>,
    pub platform_coin: SolanaCoin,
}

impl Debug for SplToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult { f.write_str(self.conf.ticker.to_string().as_str()) }
}

impl SplToken {
    pub fn new(decimals: u8, ticker: String, token_address: Pubkey, platform_coin: SolanaCoin) -> SplToken {
        let conf = Arc::new(SplTokenConf {
            decimals,
            ticker,
            token_contract_address: token_address,
        });
        SplToken { conf, platform_coin }
    }

    pub fn get_info(&self) -> SplTokenInfo {
        SplTokenInfo {
            token_contract_address: self.conf.token_contract_address,
            decimals: self.decimals(),
        }
    }
}

async fn withdraw_spl_token_impl(coin: SplToken, req: WithdrawRequest) -> WithdrawResult {
    let (to_send, my_balance) = coin.check_sufficient_balance(req.max, req.amount.clone()).await?;
    let hash = coin.rpc().get_latest_blockhash().await?;
    let system_destination_pubkey = solana_sdk::pubkey::Pubkey::try_from(req.to.as_str())?;
    let contract_key = coin.get_underlying_contract_pubkey();
    let auth_key = coin.platform_coin.key_pair.pubkey();
    let funding_address = coin.get_pubkey().await?;
    let dest_token_address = get_associated_token_address(&system_destination_pubkey, &contract_key);
    let mut instructions = Vec::with_capacity(1);
    let account_info = coin.rpc().get_account(&dest_token_address).await;
    if account_info.is_err() {
        let instruction_creation = create_associated_token_account(&auth_key, &dest_token_address, &contract_key);
        instructions.push(instruction_creation);
    }
    let amount = ui_amount_to_amount(req.amount, coin.conf.decimals)?;
    let instruction_transfer_checked = spl_token::instruction::transfer_checked(
        &spl_token::id(),
        &funding_address,
        &contract_key,
        &dest_token_address,
        &auth_key,
        &[&auth_key],
        amount,
        coin.conf.decimals,
    )?;
    instructions.push(instruction_transfer_checked);
    let msg = Message::new(&instructions, Some(&auth_key));
    let signers = vec![&coin.platform_coin.key_pair];
    let tx = Transaction::new(&signers, msg, hash);
    let fees = coin.rpc().get_fee_for_message(tx.message()).await?;
    let sol_required = lamports_to_sol(fees);
    let base_balance = coin.base_coin_balance().compat().await?;
    if base_balance < sol_required {
        return MmError::err(WithdrawError::AmountTooLow {
            amount: base_balance.clone(),
            threshold: &sol_required - &base_balance,
        });
    }
    let serialized_tx = serialize(&tx).map_to_mm(|e| WithdrawError::InternalError(e.to_string()))?;
    let encoded_tx = hex::encode(&serialized_tx);
    let received_by_me = if req.to == coin.platform_coin.my_address {
        to_send.clone()
    } else {
        0.into()
    };
    Ok(TransactionDetails {
        tx_hex: encoded_tx.as_bytes().into(),
        tx_hash: tx.signatures[0].to_string(),
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
        transaction_type: TransactionType::StandardTransfer,
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

impl SolanaCommonOps for SplToken {
    fn rpc(&self) -> &RpcClient { &self.platform_coin.client }
}

#[async_trait]
impl SolanaAsyncCommonOps for SplToken {
    async fn check_sufficient_balance(
        &self,
        max: bool,
        amount: BigDecimal,
    ) -> Result<(BigDecimal, BigDecimal), MmError<SufficientBalanceError>> {
        solana_common::check_sufficient_balance(self, max, amount).await
    }
}

impl SplToken {
    fn get_underlying_contract_pubkey(&self) -> Pubkey { self.conf.token_contract_address }

    async fn get_pubkey(&self) -> Result<Pubkey, MmError<AccountError>> {
        let coin = self.clone();
        let token_accounts = coin
            .rpc()
            .get_token_accounts_by_owner(
                &coin.platform_coin.key_pair.pubkey(),
                TokenAccountsFilter::Mint(coin.get_underlying_contract_pubkey()),
            )
            .await?;
        if token_accounts.is_empty() {
            return MmError::err(AccountError::NotFundedError("account_not_funded".to_string()));
        }
        Ok(Pubkey::from_str(token_accounts[0].pubkey.as_str())?)
    }

    fn my_balance_impl(&self) -> BalanceFut<BigDecimal> {
        let coin = self.clone();
        let fut = async move {
            let token_accounts = coin
                .rpc()
                .get_token_accounts_by_owner(
                    &coin.platform_coin.key_pair.pubkey(),
                    TokenAccountsFilter::Mint(coin.get_underlying_contract_pubkey()),
                )
                .await?;
            if token_accounts.is_empty() {
                return Ok(0.0.into());
            }
            let actual_token_pubkey = Pubkey::from_str(token_accounts[0].pubkey.as_str())
                .map_err(|e| BalanceError::Internal(format!("{:?}", e)))?;
            let amount = coin.rpc().get_token_account_balance(&actual_token_pubkey).await?;
            let balance = BigDecimal::from_str(amount.ui_amount_string.as_str())
                .map_to_mm(|e| BalanceError::Internal(e.to_string()))?;
            Ok(balance)
        };
        Box::new(fut.boxed().compat())
    }
}

impl MarketCoinOps for SplToken {
    fn ticker(&self) -> &str { &self.conf.ticker }

    fn my_address(&self) -> Result<String, String> { Ok(self.platform_coin.my_address.clone()) }

    fn my_balance(&self) -> BalanceFut<CoinBalance> {
        let fut = self.my_balance_impl().and_then(move |result| {
            Ok(CoinBalance {
                spendable: result,
                unspendable: 0.into(),
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

    fn display_priv_key(&self) -> Result<String, String> { self.platform_coin.display_priv_key() }

    fn min_tx_amount(&self) -> BigDecimal { BigDecimal::from(0) }

    fn min_trading_vol(&self) -> MmNumber { MmNumber::from("0.00777") }
}

#[allow(clippy::forget_ref, clippy::forget_copy, clippy::cast_ref_to_mut)]
#[async_trait]
impl SwapOps for SplToken {
    fn send_taker_fee(&self, _fee_addr: &[u8], amount: BigDecimal, _uuid: &[u8]) -> TransactionFut { unimplemented!() }

    fn send_maker_payment(
        &self,
        time_lock: u32,
        maker_pub: &[u8],
        taker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
        swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_taker_payment(
        &self,
        time_lock: u32,
        taker_pub: &[u8],
        maker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
        swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_maker_spends_taker_payment(
        &self,
        taker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret: &[u8],
        htlc_privkey: &[u8],
        swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_taker_spends_maker_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret: &[u8],
        htlc_privkey: &[u8],
        swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_taker_refunds_payment(
        &self,
        taker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret_hash: &[u8],
        htlc_privkey: &[u8],
        swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_maker_refunds_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret_hash: &[u8],
        htlc_privkey: &[u8],
        swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        todo!()
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

    fn validate_maker_payment(&self, input: ValidatePaymentInput) -> Box<dyn Future<Item = (), Error = String> + Send> {
        unimplemented!()
    }

    fn validate_taker_payment(&self, input: ValidatePaymentInput) -> Box<dyn Future<Item = (), Error = String> + Send> {
        unimplemented!()
    }

    fn check_if_my_payment_sent(
        &self,
        time_lock: u32,
        my_pub: &[u8],
        other_pub: &[u8],
        secret_hash: &[u8],
        search_from_block: u64,
        swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = Option<TransactionEnum>, Error = String> + Send> {
        unimplemented!()
    }

    async fn search_for_swap_tx_spend_my(
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

    async fn search_for_swap_tx_spend_other(
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

    fn get_htlc_key_pair(&self) -> KeyPair { todo!() }
}

#[allow(clippy::forget_ref, clippy::forget_copy, clippy::cast_ref_to_mut)]
#[async_trait]
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

    async fn get_sender_trade_fee(
        &self,
        _value: TradePreimageValue,
        _stage: FeeApproxStage,
    ) -> TradePreimageResult<TradeFee> {
        unimplemented!()
    }

    fn get_receiver_trade_fee(&self, _stage: FeeApproxStage) -> TradePreimageFut<TradeFee> { unimplemented!() }

    async fn get_fee_to_send_taker_fee(
        &self,
        _dex_fee_amount: BigDecimal,
        _stage: FeeApproxStage,
    ) -> TradePreimageResult<TradeFee> {
        unimplemented!()
    }

    fn required_confirmations(&self) -> u64 { 1 }

    fn requires_notarization(&self) -> bool { false }

    fn set_required_confirmations(&self, _confirmations: u64) { unimplemented!() }

    fn set_requires_notarization(&self, _requires_nota: bool) { unimplemented!() }

    fn swap_contract_address(&self) -> Option<BytesJson> { unimplemented!() }

    fn mature_confirmations(&self) -> Option<u32> { Some(1) }

    fn coin_protocol_info(&self) -> Vec<u8> { Vec::new() }

    fn is_coin_protocol_supported(&self, _info: &Option<Vec<u8>>) -> bool { true }
}
