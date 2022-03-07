use super::{CoinBalance, HistorySyncState, MarketCoinOps, MmCoin, SwapOps, TradeFee, TransactionEnum, TransactionFut};
use crate::common::Future01CompatExt;
use crate::solana::solana_common::{lamports_to_sol, sol_to_lamports};
use crate::{BalanceError, BalanceFut, FeeApproxStage, FoundSwapTxSpend, NegotiateSwapContractAddrErr,
            TradePreimageFut, TradePreimageResult, TradePreimageValue, TransactionDetails, TransactionType,
            ValidateAddressResult, ValidatePaymentInput, WithdrawError, WithdrawFut, WithdrawRequest, WithdrawResult};
use async_trait::async_trait;
use base58::ToBase58;
use bigdecimal::BigDecimal;
use bincode::{deserialize, serialize};
use common::mm_error::prelude::MapToMmResult;
use common::{mm_ctx::MmArc, mm_error::MmError, mm_number::MmNumber, now_ms};
use derive_more::Display;
use futures::{FutureExt, TryFutureExt};
use futures01::Future;
use keys::KeyPair;
use rpc::v1::types::Bytes as BytesJson;
use serde_json::{self as json, Value as Json};
use solana_client::{client_error::{ClientError, ClientErrorKind},
                    nonblocking::rpc_client::RpcClient};
use solana_sdk::commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_sdk::program_error::ProgramError;
use solana_sdk::pubkey::ParsePubkeyError;
use solana_sdk::transaction::Transaction;
use solana_sdk::{pubkey::Pubkey,
                 signature::{Keypair, Signer}};
use std::sync::atomic::Ordering as AtomicOrdering;
use std::{convert::TryFrom,
          fmt::{Debug, Formatter, Result as FmtResult},
          ops::Deref,
          sync::atomic::AtomicU64,
          sync::Arc};

pub mod solana_common;
#[cfg(test)] mod solana_common_tests;
mod solana_decode_tx_helpers;
#[cfg(test)] mod solana_tests;
pub mod spl;
#[cfg(test)] mod spl_tests;

pub trait SolanaCommonOps {
    fn rpc(&self) -> &RpcClient;
}

#[async_trait]
pub trait SolanaAsyncCommonOps {
    async fn check_sufficient_balance(
        &self,
        req: &WithdrawRequest,
    ) -> Result<(BigDecimal, BigDecimal), MmError<WithdrawError>>;
}

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

impl From<ParsePubkeyError> for BalanceError {
    fn from(e: ParsePubkeyError) -> Self { BalanceError::Internal(format!("{:?}", e)) }
}

impl From<ClientError> for WithdrawError {
    fn from(e: ClientError) -> Self {
        match e.kind {
            ClientErrorKind::Io(e) => WithdrawError::Transport(e.to_string()),
            ClientErrorKind::Reqwest(e) => WithdrawError::Transport(e.to_string()),
            ClientErrorKind::RpcError(e) => WithdrawError::Transport(format!("{:?}", e)),
            ClientErrorKind::SerdeJson(e) => WithdrawError::InternalError(e.to_string()),
            ClientErrorKind::Custom(e) => WithdrawError::InternalError(e),
            ClientErrorKind::SigningError(_)
            | ClientErrorKind::TransactionError(_)
            | ClientErrorKind::FaucetError(_) => WithdrawError::InternalError("not_reacheable".to_string()),
        }
    }
}

impl From<ParsePubkeyError> for WithdrawError {
    fn from(e: ParsePubkeyError) -> Self { WithdrawError::InvalidAddress(format!("{:?}", e)) }
}

impl From<ProgramError> for WithdrawError {
    fn from(e: ProgramError) -> Self { WithdrawError::InternalError(format!("{:?}", e)) }
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

impl From<ParsePubkeyError> for AccountError {
    fn from(e: ParsePubkeyError) -> Self { AccountError::ParsePubKeyError(format!("{:?}", e)) }
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

#[derive(Debug, Deserialize, Serialize)]
pub struct SolanaActivationParams {
    confirmation_commitment: CommitmentLevel,
    client_url: String,
}

#[derive(Debug, Display)]
pub enum SolanaFromLegacyReqErr {
    InvalidCommitmentLevel(String),
    InvalidClientParsing(json::Error),
    ClientNoAvailableNodes(String),
}

impl SolanaActivationParams {
    pub fn from_legacy_req(req: &Json) -> Result<Self, MmError<SolanaFromLegacyReqErr>> {
        let solana_commitment =
            json::from_value::<String>(req["commitment_level"].clone()).unwrap_or_else(|_| "Finalized".to_string());
        let solana_client_urls = json::from_value::<Vec<String>>(req["urls"].clone())
            .map_to_mm(SolanaFromLegacyReqErr::InvalidClientParsing)?;
        if solana_client_urls.is_empty() {
            return MmError::err(SolanaFromLegacyReqErr::ClientNoAvailableNodes(
                "Enable request for SOLANA coin must have at least 1 node URL".to_string(),
            ));
        }
        let commitment_level = match solana_commitment.as_str() {
            "Finalized" => solana_sdk::commitment_config::CommitmentLevel::Finalized,
            "Confirmed" => solana_sdk::commitment_config::CommitmentLevel::Confirmed,
            "Processed" => solana_sdk::commitment_config::CommitmentLevel::Processed,
            _ => {
                return MmError::err(SolanaFromLegacyReqErr::InvalidCommitmentLevel(
                    "Invalid commitment".to_string(),
                ))
            },
        };
        Ok(SolanaActivationParams {
            confirmation_commitment: commitment_level,
            client_url: solana_client_urls[0].clone(),
        })
    }
}

fn generate_keypair_from_slice(priv_key: &[u8]) -> Keypair {
    let secret_key = ed25519_dalek::SecretKey::from_bytes(priv_key).unwrap();
    let public_key = ed25519_dalek::PublicKey::from(&secret_key);
    let key_pair = ed25519_dalek::Keypair {
        secret: secret_key,
        public: public_key,
    };
    solana_sdk::signature::keypair_from_seed(key_pair.to_bytes().as_ref()).unwrap()
}

pub async fn solana_coin_from_conf_and_params(
    ctx: &MmArc,
    ticker: &str,
    conf: &Json,
    params: SolanaActivationParams,
    priv_key: &[u8],
) -> Result<SolanaCoin, String> {
    let client = solana_client::nonblocking::rpc_client::RpcClient::new_with_commitment(
        params.client_url.clone(),
        CommitmentConfig {
            commitment: params.confirmation_commitment,
        },
    );
    let decimals = conf["decimals"].as_u64().unwrap_or(8) as u8;
    let key_pair = generate_keypair_from_slice(priv_key);
    let my_address = key_pair.pubkey().to_string();
    let solana_coin = SolanaCoin(Arc::new(SolanaCoinImpl {
        my_address,
        key_pair,
        ticker: ticker.to_string(),
        required_confirmations: 1.into(),
        client,
        decimals,
    }));
    Ok(solana_coin)
}

/// pImpl idiom.
pub struct SolanaCoinImpl {
    ticker: String,
    key_pair: Keypair,
    client: RpcClient,
    decimals: u8,
    required_confirmations: AtomicU64,
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

impl SolanaCommonOps for SolanaCoin {
    fn rpc(&self) -> &RpcClient { &self.client }
}

#[async_trait]
impl SolanaAsyncCommonOps for SolanaCoin {
    async fn check_sufficient_balance(
        &self,
        req: &WithdrawRequest,
    ) -> Result<(BigDecimal, BigDecimal), MmError<WithdrawError>> {
        solana_common::check_sufficient_balance(self, req).await
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SolanaFeeDetails {
    pub amount: BigDecimal,
}

async fn withdraw_base_coin_impl(coin: SolanaCoin, req: WithdrawRequest) -> WithdrawResult {
    let (to_send, my_balance) = coin.check_sufficient_balance(&req).await?;
    let base_balance = coin.base_coin_balance().compat().await?;
    let hash = coin.rpc().get_latest_blockhash().await?;
    let to = solana_sdk::pubkey::Pubkey::try_from(req.to.as_str())?;
    let tx = solana_sdk::system_transaction::transfer(&coin.key_pair, &to, sol_to_lamports(&to_send)?, hash);
    let fees = coin.rpc().get_fee_for_message(tx.message()).await?;
    let sol_required = lamports_to_sol(fees);
    if base_balance < sol_required {
        return MmError::err(WithdrawError::AmountTooLow {
            amount: base_balance.clone(),
            threshold: &sol_required - &base_balance,
        });
    }
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
        transaction_type: TransactionType::StandardTransfer,
    })
}

async fn withdraw_impl(coin: SolanaCoin, req: WithdrawRequest) -> WithdrawResult {
    let validate_address_result = coin.validate_address(req.to.as_str());
    if !validate_address_result.is_valid {
        return MmError::err(WithdrawError::InvalidAddress(
            validate_address_result.reason.unwrap_or_else(|| "Unknown".to_string()),
        ));
    }
    withdraw_base_coin_impl(coin, req).await
}

impl SolanaCoin {
    fn my_balance_impl(&self) -> BalanceFut<BigDecimal> {
        let coin = self.clone();
        let fut = async move {
            let res = coin.rpc().get_balance(&coin.key_pair.pubkey()).await?;
            Ok(lamports_to_sol(res))
        };
        Box::new(fut.boxed().compat())
    }
}

impl MarketCoinOps for SolanaCoin {
    fn ticker(&self) -> &str { &self.ticker }

    fn my_address(&self) -> Result<String, String> { Ok(self.my_address.clone()) }

    fn my_balance(&self) -> BalanceFut<CoinBalance> {
        // bigdecimal-0.1.2/src/lib.rs:2396 (precision is decimals - 1)
        let decimals = (self.decimals + 1) as u64;
        let fut = self.my_balance_impl().and_then(move |result| {
            Ok(CoinBalance {
                spendable: result.with_prec(decimals),
                unspendable: 0.into(),
            })
        });
        Box::new(fut)
    }

    fn base_coin_balance(&self) -> BalanceFut<BigDecimal> {
        let decimals = (self.decimals + 1) as u64;
        let fut = self
            .my_balance_impl()
            .and_then(move |result| Ok(result.with_prec(decimals)));
        Box::new(fut)
    }

    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> {
        let coin = self.clone();
        let tx = tx.to_owned();
        let fut = async move {
            let bytes = hex::decode(tx).map_to_mm(|e| e).map_err(|e| format!("{:?}", e))?;
            let tx: Transaction = deserialize(bytes.as_slice())
                .map_to_mm(|e| e)
                .map_err(|e| format!("{:?}", e))?;
            let signature = coin.rpc().send_transaction(&tx).await.map_err(|e| format!("{:?}", e))?;
            Ok(signature.to_string())
        };
        Box::new(fut.boxed().compat())
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
        let coin = self.clone();
        let fut = async move { coin.rpc().get_block_height().await.map_err(|e| format!("{:?}", e)) };
        Box::new(fut.boxed().compat())
    }

    fn display_priv_key(&self) -> Result<String, String> { Ok(self.key_pair.secret().to_bytes()[..].to_base58()) }

    fn min_tx_amount(&self) -> BigDecimal { BigDecimal::from(0) }

    fn min_trading_vol(&self) -> MmNumber { MmNumber::from("0.00777") }
}

#[allow(clippy::forget_ref, clippy::forget_copy, clippy::cast_ref_to_mut)]
#[async_trait]
impl SwapOps for SolanaCoin {
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
        let result = Pubkey::try_from(address);
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

    async fn get_sender_trade_fee(
        &self,
        value: TradePreimageValue,
        stage: FeeApproxStage,
    ) -> TradePreimageResult<TradeFee> {
        unimplemented!()
    }

    fn get_receiver_trade_fee(&self, _stage: FeeApproxStage) -> TradePreimageFut<TradeFee> { unimplemented!() }

    async fn get_fee_to_send_taker_fee(
        &self,
        dex_fee_amount: BigDecimal,
        stage: FeeApproxStage,
    ) -> TradePreimageResult<TradeFee> {
        unimplemented!()
    }

    fn required_confirmations(&self) -> u64 { self.required_confirmations.load(AtomicOrdering::Relaxed) }

    fn requires_notarization(&self) -> bool { false }

    fn set_required_confirmations(&self, _confirmations: u64) { unimplemented!() }

    fn set_requires_notarization(&self, _requires_nota: bool) { unimplemented!() }

    fn swap_contract_address(&self) -> Option<BytesJson> { unimplemented!() }

    fn mature_confirmations(&self) -> Option<u32> { None }

    fn coin_protocol_info(&self) -> Vec<u8> { Vec::new() }

    fn is_coin_protocol_supported(&self, _info: &Option<Vec<u8>>) -> bool { true }
}
