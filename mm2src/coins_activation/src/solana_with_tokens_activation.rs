use crate::platform_coin_with_tokens::{GetPlatformBalance, PlatformWithTokensActivationOps, RegisterTokenInfo,
                                       TokenActivationParams, TokenActivationRequest, TokenAsMmCoinInitializer,
                                       TokenInitializer, TokenOf};
use crate::prelude::*;
use crate::prelude::{CoinAddressInfo, TokenBalances, TryFromCoinProtocol, TxHistoryEnabled};
use crate::spl_token_activation::SplActivationRequest;
use async_trait::async_trait;
use coins::my_tx_history_v2::TxHistoryStorage;
use coins::solana::spl::SplProtocolConf;
use coins::{solana_coin_from_conf_and_params, BalanceError, CoinBalance, CoinProtocol, MarketCoinOps,
            SolanaActivationParams, SolanaCoin, SplToken};
use common::mm_ctx::MmArc;
use common::mm_error::prelude::MapToMmResult;
use common::mm_error::MmError;
use common::mm_metrics::MetricsArc;
use common::mm_number::BigDecimal;
use common::Future01CompatExt;
use futures::future::AbortHandle;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value as Json;
use std::collections::HashMap;

pub struct SplTokenInitializer {
    platform_coin: SolanaCoin,
}

impl TokenOf for SplToken {
    type PlatformCoin = SolanaCoin;
}

#[async_trait]
impl TokenInitializer for SplTokenInitializer {
    type Token = SplToken;
    type TokenActivationRequest = SplActivationRequest;
    type TokenProtocol = SplProtocolConf;
    type InitTokensError = std::convert::Infallible;

    fn tokens_requests_from_platform_request(
        platform_params: &SolanaWithTokensActivationRequest,
    ) -> Vec<TokenActivationRequest<Self::TokenActivationRequest>> {
        platform_params.slp_tokens_requests.clone()
    }

    async fn enable_tokens(
        &self,
        activation_params: Vec<TokenActivationParams<SplActivationRequest, SplProtocolConf>>,
    ) -> Result<Vec<SplToken>, MmError<std::convert::Infallible>> {
        let tokens = activation_params
            .into_iter()
            .map(|params| {
                SplToken::new(
                    params.protocol.decimals,
                    params.ticker,
                    params.protocol.token_contract_address,
                    self.platform_coin.clone(),
                )
            })
            .collect();

        Ok(tokens)
    }

    fn platform_coin(&self) -> &SolanaCoin { &self.platform_coin }
}

impl RegisterTokenInfo<SplToken> for SolanaCoin {
    fn register_token_info(&self, token: &SplToken) { self.add_spl_token_info(token.ticker().into(), token.get_info()) }
}

#[derive(Clone, Debug, Deserialize)]
pub struct SolanaWithTokensActivationRequest {
    #[serde(flatten)]
    platform_request: SolanaActivationParams,
    slp_tokens_requests: Vec<TokenActivationRequest<SplActivationRequest>>,
}

impl TxHistoryEnabled for SolanaWithTokensActivationRequest {
    fn tx_history_enabled(&self) -> bool { false }
}

#[derive(Debug, Serialize)]
pub struct SolanaWithTokensActivationResult {
    current_block: u64,
    solana_addresses_infos: HashMap<String, CoinAddressInfo<CoinBalance>>,
    spl_addresses_infos: HashMap<String, CoinAddressInfo<TokenBalances>>,
}

impl GetPlatformBalance for SolanaWithTokensActivationResult {
    fn get_platform_balance(&self) -> BigDecimal {
        self.solana_addresses_infos
            .iter()
            .fold(BigDecimal::from(0), |total, (_, addr_info)| {
                &total + &addr_info.balances.get_total()
            })
    }
}

#[derive(Debug)]
pub enum SolanaWithTokensActivationError {
    PlatformCoinCreationError { ticker: String, error: String },
    UnableToRetrieveMyAddress(String),
    GetBalanceError(BalanceError),
    Transport(String),
    Internal(String),
}

impl From<BalanceError> for SolanaWithTokensActivationError {
    fn from(e: BalanceError) -> Self { SolanaWithTokensActivationError::GetBalanceError(e) }
}

pub struct SolanaProtocolInfo {}

impl TryFromCoinProtocol for SolanaProtocolInfo {
    fn try_from_coin_protocol(proto: CoinProtocol) -> Result<Self, MmError<CoinProtocol>>
    where
        Self: Sized,
    {
        match proto {
            CoinProtocol::SOLANA {} => Ok(SolanaProtocolInfo {}),
            protocol => MmError::err(protocol),
        }
    }
}

#[async_trait]
impl PlatformWithTokensActivationOps for SolanaCoin {
    type ActivationRequest = SolanaWithTokensActivationRequest;
    type PlatformProtocolInfo = SolanaProtocolInfo;
    type ActivationResult = SolanaWithTokensActivationResult;
    type ActivationError = SolanaWithTokensActivationError;

    async fn enable_platform_coin(
        ctx: MmArc,
        ticker: String,
        platform_conf: Json,
        activation_request: Self::ActivationRequest,
        _protocol_conf: Self::PlatformProtocolInfo,
        priv_key: &[u8],
    ) -> Result<Self, MmError<Self::ActivationError>> {
        let platform_coin = solana_coin_from_conf_and_params(
            &ctx,
            &ticker,
            &platform_conf,
            activation_request.platform_request,
            priv_key,
        )
        .await
        .map_to_mm(|error| SolanaWithTokensActivationError::PlatformCoinCreationError { ticker, error })?;
        Ok(platform_coin)
    }

    fn token_initializers(
        &self,
    ) -> Vec<Box<dyn TokenAsMmCoinInitializer<PlatformCoin = Self, ActivationRequest = Self::ActivationRequest>>> {
        vec![Box::new(SplTokenInitializer {
            platform_coin: self.clone(),
        })]
    }

    async fn get_activation_result(&self) -> Result<Self::ActivationResult, MmError<Self::ActivationError>> {
        let my_address = self
            .my_address()
            .map_to_mm(Self::ActivationError::UnableToRetrieveMyAddress)?;
        let current_block = self
            .current_block()
            .compat()
            .await
            .map_to_mm(Self::ActivationError::Internal)?;
        let solana_balance = self
            .my_balance()
            .compat()
            .await
            .map_err(|e| Self::ActivationError::GetBalanceError(e.into_inner()))?;
        let mut token_balances = HashMap::new();
        let token_infos = self.get_spl_tokens_infos();
        for (token_ticker, info) in token_infos.into_iter() {
            let balance = self.my_balance_spl(&info.clone()).await?;
            token_balances.insert(token_ticker.to_owned(), balance);
        }
        let mut result = SolanaWithTokensActivationResult {
            current_block,
            solana_addresses_infos: HashMap::new(),
            spl_addresses_infos: HashMap::new(),
        };
        result
            .solana_addresses_infos
            .insert(my_address.clone(), CoinAddressInfo {
                derivation_method: DerivationMethod::Iguana,
                pubkey: self.my_pubkey(),
                balances: solana_balance,
            });

        result.spl_addresses_infos.insert(my_address, CoinAddressInfo {
            derivation_method: DerivationMethod::Iguana,
            pubkey: self.my_pubkey(),
            balances: token_balances,
        });
        Ok(result)
    }

    fn start_history_background_fetching(
        &self,
        _metrics: MetricsArc,
        _storage: impl TxHistoryStorage + Send + 'static,
        _initial_balance: BigDecimal,
    ) -> AbortHandle {
        todo!()
    }
}
