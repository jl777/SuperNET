use super::{CoinBalance, HistorySyncState, MarketCoinOps, MmCoin, SwapOps, TradeFee, TransactionEnum, TransactionFut};
use crate::{BalanceError, BalanceFut, FeeApproxStage, FoundSwapTxSpend, NegotiateSwapContractAddrErr,
            TradePreimageFut, TradePreimageValue, TransactionDetails, ValidateAddressResult, WithdrawError,
            WithdrawFut, WithdrawRequest, WithdrawResult};
use base58::ToBase58;
use bigdecimal::{BigDecimal, ToPrimitive};
use bincode::{deserialize, serialize};
use common::mm_error::prelude::MapToMmResult;
use common::{mm_ctx::MmArc, mm_ctx::MmWeak, mm_error::MmError, mm_number::MmNumber, now_ms};
use futures::{compat::Future01CompatExt, FutureExt, TryFutureExt};
use futures01::{future::result, Future};
use mocktopus::macros::*;
use rpc::v1::types::Bytes as BytesJson;
use serde_json::Value as Json;
use solana_client::{client_error::{ClientError, ClientErrorKind},
                    rpc_client::RpcClient,
                    rpc_request::TokenAccountsFilter};
use solana_sdk::hash::Hash;
use solana_sdk::message::Message;
use solana_sdk::native_token::{lamports_to_sol, sol_to_lamports};
use solana_sdk::program_error::ProgramError;
use solana_sdk::pubkey::ParsePubkeyError;
use solana_sdk::transaction::Transaction;
use solana_sdk::{pubkey::Pubkey,
                 signature::{Keypair, Signer}};
use spl_associated_token_account::{create_associated_token_account, get_associated_token_address};
use std::{convert::TryFrom,
          fmt::{Debug, Formatter, Result as FmtResult},
          ops::Deref,
          str::FromStr,
          sync::atomic::AtomicU64,
          sync::Arc};

#[cfg(test)] mod solana_tests;
mod solana_transaction_transfer;

impl From<ClientError> for BalanceError {
    fn from(e: ClientError) -> Self {
        match e.kind {
            ClientErrorKind::Io(e) => BalanceError::Transport(e.to_string()),
            ClientErrorKind::Reqwest(e) => BalanceError::Transport(e.to_string()),
            ClientErrorKind::RpcError(e) => BalanceError::Transport(format!("{:?}", e)),
            ClientErrorKind::SerdeJson(e) => BalanceError::InvalidResponse(e.to_string()),
            ClientErrorKind::Custom(e) => BalanceError::Internal(e),
            ClientErrorKind::SigningError(_)
            | ClientErrorKind::TransactionError(_)
            | ClientErrorKind::FaucetError(_) => BalanceError::Internal("not_reacheable".to_string()),
        }
    }
}

impl From<ParsePubkeyError> for WithdrawError {
    fn from(e: ParsePubkeyError) -> Self { WithdrawError::InvalidAddress(format!("{:?}", e)) }
}

impl From<ProgramError> for WithdrawError {
    fn from(e: ProgramError) -> Self { WithdrawError::InvalidAddress(format!("{:?}", e)) }
}

#[derive(Debug)]
pub enum AccountError {
    NotFundedError(String),
    ParsePubKeyError(String),
    ClientError(ClientErrorKind),
}

impl From<ClientError> for AccountError {
    fn from(e: ClientError) -> Self { AccountError::ClientError(e.kind) }
}

impl From<AccountError> for WithdrawError {
    fn from(e: AccountError) -> Self {
        match e {
            AccountError::NotFundedError(_) => WithdrawError::ZeroBalanceToWithdrawMax,
            AccountError::ParsePubKeyError(err) => WithdrawError::InternalError(err),
            AccountError::ClientError(e) => WithdrawError::Transport(format!("{:?}", e)),
        }
    }
}

/// pImpl idiom.
pub struct SolanaCoinImpl {
    ticker: String,
    coin_type: SolanaCoinType,
    key_pair: Keypair,
    client: RpcClient,
    decimals: u8,
    _required_confirmations: AtomicU64,
    _ctx: MmWeak,
    my_address: String,
}

impl Debug for SolanaCoinImpl {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult { f.write_str(self.ticker.to_string().as_str()) }
}

#[derive(Clone, Debug)]
pub struct SolanaCoin(Arc<SolanaCoinImpl>);
impl Deref for SolanaCoin {
    type Target = SolanaCoinImpl;
    fn deref(&self) -> &SolanaCoinImpl { &*self.0 }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SolanaFeeDetails {
    pub amount: BigDecimal,
}

async fn check_sufficient_balance(
    coin: &SolanaCoin,
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
            coin: coin.ticker.clone(),
            available: my_balance.clone(),
            required: &to_send - &my_balance,
        });
    }
    Ok((to_send, my_balance))
}

async fn check_amount_too_low(coin: &SolanaCoin) -> Result<(BigDecimal, Hash), MmError<WithdrawError>> {
    let base_balance = coin.base_coin_balance().compat().await?;
    let (hash, fee_calculator) = coin
        .client
        .get_recent_blockhash()
        .map_to_mm(|e| WithdrawError::Transport(format!("{:?}", e)))?;
    let sol_required = BigDecimal::from(lamports_to_sol(fee_calculator.lamports_per_signature));
    if base_balance < sol_required {
        return MmError::err(WithdrawError::AmountTooLow {
            amount: base_balance.clone(),
            threshold: &sol_required - &base_balance,
        });
    }
    Ok((sol_required, hash))
}

async fn withdraw_spl_token_impl(coin: SolanaCoin, req: WithdrawRequest) -> WithdrawResult {
    let (to_send, my_balance) = check_sufficient_balance(&coin, &req).await?;
    let (sol_required, hash) = check_amount_too_low(&coin).await?;
    let system_destination_pubkey = solana_sdk::pubkey::Pubkey::try_from(req.to.as_str())?;
    let contract_key = coin.get_underlying_contract_pubkey();
    let auth_key = coin.key_pair.pubkey();
    let funding_address = coin.get_pubkey()?;
    let dest_token_address = get_associated_token_address(&system_destination_pubkey, &contract_key);
    let mut instructions = Vec::with_capacity(1);
    let account_info = coin.client.get_account(&dest_token_address);
    if account_info.is_err() {
        let instruction_creation = create_associated_token_account(&auth_key, &dest_token_address, &contract_key);
        instructions.push(instruction_creation);
    }
    let raw_amount = req.amount.to_f64().unwrap_or_default();
    let amount = spl_token::ui_amount_to_amount(raw_amount, coin.decimals);
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
    let signers = vec![&coin.key_pair];
    let tx = Transaction::new(&signers, msg, hash);
    let serialized_tx = serialize(&tx).map_to_mm(|e| WithdrawError::InternalError(e.to_string()))?;
    let encoded_tx = hex::encode(&serialized_tx);
    let received_by_me = if req.to == coin.my_address {
        to_send.clone()
    } else {
        0.into()
    };
    Ok(TransactionDetails {
        tx_hex: encoded_tx.as_bytes().into(),
        tx_hash: tx.signatures[0].as_ref().into(),
        from: vec![coin.my_address.clone()],
        to: vec![req.to],
        total_amount: to_send.clone(),
        spent_by_me: to_send.clone(),
        received_by_me,
        my_balance_change: &my_balance - &to_send,
        block_height: 0,
        timestamp: now_ms() / 1000,
        fee_details: Some(SolanaFeeDetails { amount: sol_required }.into()),
        coin: coin.ticker.clone(),
        internal_id: vec![].into(),
        kmd_rewards: None,
    })
}

async fn withdraw_base_coin_impl(coin: SolanaCoin, req: WithdrawRequest) -> WithdrawResult {
    let (to_send, my_balance) = check_sufficient_balance(&coin, &req).await?;
    let (sol_required, hash) = check_amount_too_low(&coin).await?;
    let to = solana_sdk::pubkey::Pubkey::try_from(req.to.as_str())?;
    let tx = solana_sdk::system_transaction::transfer(
        &coin.key_pair,
        &to,
        sol_to_lamports(to_send.to_f64().unwrap_or_default()),
        hash,
    );
    let serialized_tx = serialize(&tx).map_to_mm(|e| WithdrawError::InternalError(e.to_string()))?;
    let encoded_tx = hex::encode(&serialized_tx);
    let received_by_me = if req.to == coin.my_address {
        to_send.clone()
    } else {
        0.into()
    };
    Ok(TransactionDetails {
        tx_hex: encoded_tx.as_bytes().into(),
        tx_hash: tx.signatures[0].as_ref().into(),
        from: vec![coin.my_address.clone()],
        to: vec![req.to],
        total_amount: to_send.clone(),
        spent_by_me: to_send.clone(),
        received_by_me,
        my_balance_change: &my_balance - &to_send,
        block_height: 0,
        timestamp: now_ms() / 1000,
        fee_details: Some(SolanaFeeDetails { amount: sol_required }.into()),
        coin: coin.ticker.clone(),
        internal_id: vec![].into(),
        kmd_rewards: None,
    })
}

async fn withdraw_impl(coin: SolanaCoin, req: WithdrawRequest) -> WithdrawResult {
    let validate_address_result = coin.validate_address(req.to.as_str());
    if !validate_address_result.is_valid {
        return MmError::err(WithdrawError::InvalidAddress(
            validate_address_result.reason.unwrap_or_else(|| "Unknown".to_string()),
        ));
    }
    match coin.coin_type {
        SolanaCoinType::Solana => withdraw_base_coin_impl(coin, req).await,
        SolanaCoinType::Spl { .. } => withdraw_spl_token_impl(coin, req).await,
    }
}

impl SolanaCoin {
    fn get_underlying_contract_pubkey(&self) -> Pubkey {
        let coin = self.clone();
        match coin.coin_type {
            SolanaCoinType::Solana => coin.key_pair.pubkey(),
            SolanaCoinType::Spl { token_addr, .. } => token_addr,
        }
    }

    fn get_pubkey(&self) -> Result<Pubkey, MmError<AccountError>> {
        let coin = self.clone();
        match coin.coin_type {
            SolanaCoinType::Solana => Ok(coin.key_pair.pubkey()),
            SolanaCoinType::Spl { .. } => {
                let token_accounts = coin.client.get_token_accounts_by_owner(
                    &coin.key_pair.pubkey(),
                    TokenAccountsFilter::Mint(coin.get_underlying_contract_pubkey()),
                )?;
                if token_accounts.is_empty() {
                    return MmError::err(AccountError::NotFundedError("account_not_funded".to_string()));
                }
                Ok(Pubkey::from_str(token_accounts[0].pubkey.as_str())
                    .map_to_mm(|e| AccountError::ParsePubKeyError(format!("{:?}", e)))?)
            },
        }
    }

    fn my_balance_impl(&self, force_base_coin: bool) -> BalanceFut<f64> {
        let coin = self.clone();
        let base_coin_balance_functor = |coin: SolanaCoin| {
            let res = coin.client.get_balance(&coin.key_pair.pubkey())?;
            Ok(solana_sdk::native_token::lamports_to_sol(res))
        };
        if force_base_coin {
            let fut = async move { base_coin_balance_functor(coin) };
            return Box::new(fut.boxed().compat());
        }
        let fut = async move {
            match coin.coin_type {
                SolanaCoinType::Solana => base_coin_balance_functor(coin),
                SolanaCoinType::Spl { .. } => {
                    let token_accounts = coin.client.get_token_accounts_by_owner(
                        &coin.key_pair.pubkey(),
                        TokenAccountsFilter::Mint(coin.get_underlying_contract_pubkey()),
                    )?;
                    if token_accounts.is_empty() {
                        return Ok(0.0);
                    }
                    let actual_token_pubkey = Pubkey::from_str(token_accounts[0].pubkey.as_str())
                        .map_err(|e| BalanceError::Internal(format!("{:?}", e)))?;
                    let amount = coin.client.get_token_account_balance(&actual_token_pubkey)?;
                    Ok(amount.ui_amount.unwrap_or(0.0))
                },
            }
        };
        Box::new(fut.boxed().compat())
    }
}

// TODO: construct the variant later.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
enum SolanaCoinType {
    /// Solana itself or it's forks
    Solana,
    /// SPL token with smart contract address
    /// https://spl.solana.com/
    Spl {
        platform: String,
        token_addr: solana_sdk::pubkey::Pubkey,
    },
}

#[mockable]
#[allow(clippy::forget_ref, clippy::forget_copy, clippy::cast_ref_to_mut)]
impl MarketCoinOps for SolanaCoin {
    fn ticker(&self) -> &str { &self.ticker }

    fn my_address(&self) -> Result<String, String> { Ok(self.my_address.clone()) }

    fn my_balance(&self) -> BalanceFut<CoinBalance> {
        let fut = self.my_balance_impl(false).and_then(move |result| {
            Ok(CoinBalance {
                spendable: BigDecimal::from(result),
                unspendable: BigDecimal::from(0),
            })
        });
        Box::new(fut)
    }

    fn base_coin_balance(&self) -> BalanceFut<BigDecimal> {
        let fut = self
            .my_balance_impl(true)
            .and_then(move |result| Ok(BigDecimal::from(result)));
        Box::new(fut)
    }

    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> {
        let decoded = try_fus!(hex::decode(tx));
        let deserialized_tx: Transaction = try_fus!(deserialize(&*decoded));
        let closure = |signature: solana_sdk::signature::Signature| Ok(signature.to_string());
        Box::new(result(
            self.client
                .send_transaction(&deserialized_tx)
                .map_err(|e| ERRL!("{}", e))
                .and_then(closure),
        ))
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

    fn current_block(&self) -> Box<dyn Future<Item = u64, Error = String> + Send> {
        Box::new(result(self.client.get_block_height()).map_err(|e| ERRL!("{}", e)))
    }

    fn display_priv_key(&self) -> String { self.key_pair.secret().to_bytes()[..].to_base58() }

    fn min_tx_amount(&self) -> BigDecimal { BigDecimal::from(0) }

    fn min_trading_vol(&self) -> MmNumber { MmNumber::from("0.00777") }
}

#[mockable]
#[allow(clippy::forget_ref, clippy::forget_copy, clippy::cast_ref_to_mut)]
impl SwapOps for SolanaCoin {
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
impl MmCoin for SolanaCoin {
    fn is_asset_chain(&self) -> bool { false }

    fn withdraw(&self, req: WithdrawRequest) -> WithdrawFut {
        Box::new(Box::pin(withdraw_impl(self.clone(), req)).compat())
    }

    fn decimals(&self) -> u8 { self.decimals }

    fn convert_to_address(&self, _from: &str, _to_address_format: Json) -> Result<String, String> { unimplemented!() }

    fn validate_address(&self, address: &str) -> ValidateAddressResult {
        if address.len() != 44 {
            return ValidateAddressResult {
                is_valid: false,
                reason: Some("Invalid address length".to_string()),
            };
        }
        let result = solana_sdk::pubkey::Pubkey::try_from(address);
        match result {
            Ok(pubkey) => {
                if pubkey.is_on_curve() {
                    ValidateAddressResult {
                        is_valid: true,
                        reason: None,
                    }
                } else {
                    ValidateAddressResult {
                        is_valid: false,
                        reason: Some("not_on_curve".to_string()),
                    }
                }
            },
            Err(err) => ValidateAddressResult {
                is_valid: false,
                reason: Some(format!("{:?}", err)),
            },
        }
    }

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
