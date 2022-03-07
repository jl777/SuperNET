use crate::prelude::{TryFromCoinProtocol, TryPlatformCoinFromMmCoinEnum};
use crate::token::{TokenActivationOps, TokenProtocolParams};
use async_trait::async_trait;
use coins::solana::spl::SplProtocolConf;
use coins::{BalanceError, CoinBalance, CoinProtocol, MarketCoinOps, MmCoinEnum, SolanaCoin, SplToken};
use common::mm_error::prelude::MapToMmResult;
use common::mm_error::MmError;
use common::Future01CompatExt;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

impl TryPlatformCoinFromMmCoinEnum for SolanaCoin {
    fn try_from_mm_coin(coin: MmCoinEnum) -> Option<Self>
    where
        Self: Sized,
    {
        match coin {
            MmCoinEnum::SolanaCoin(coin) => Some(coin),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct SplActivationRequest {}

impl TryFromCoinProtocol for SplProtocolConf {
    fn try_from_coin_protocol(proto: CoinProtocol) -> Result<Self, MmError<CoinProtocol>>
    where
        Self: Sized,
    {
        match proto {
            CoinProtocol::SPLTOKEN {
                platform,
                token_address,
                decimals,
            } => {
                let token_contract_address =
                    solana_sdk::pubkey::Pubkey::from_str(token_address.as_str()).map_to_mm(|_e| {
                        CoinProtocol::SPLTOKEN {
                            platform: platform.clone(),
                            token_address: token_address.clone(),
                            decimals,
                        }
                    })?;
                Ok(SplProtocolConf {
                    platform_coin_ticker: platform,
                    decimals,
                    token_contract_address,
                })
            },
            proto => MmError::err(proto),
        }
    }
}

impl TokenProtocolParams for SplProtocolConf {
    fn platform_coin_ticker(&self) -> &str { &self.platform_coin_ticker }
}

#[derive(Debug, Serialize)]
pub struct SplInitResult {
    balances: HashMap<String, CoinBalance>,
    token_contract_address: solana_sdk::pubkey::Pubkey,
    platform_coin: String,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SplInitError {
    GetBalanceError(BalanceError),
    MyAddressError(String),
}

#[async_trait]
impl TokenActivationOps for SplToken {
    type PlatformCoin = SolanaCoin;
    type ActivationParams = SplActivationRequest;
    type ProtocolInfo = SplProtocolConf;
    type ActivationResult = SplInitResult;
    type ActivationError = SplInitError;

    async fn enable_token(
        ticker: String,
        platform_coin: Self::PlatformCoin,
        _activation_params: Self::ActivationParams,
        protocol_conf: Self::ProtocolInfo,
    ) -> Result<(Self, Self::ActivationResult), MmError<Self::ActivationError>> {
        let token = Self::new(
            protocol_conf.decimals,
            ticker,
            protocol_conf.token_contract_address,
            platform_coin,
        );
        let balance = token
            .my_balance()
            .compat()
            .await
            .map_err(|e| SplInitError::GetBalanceError(e.into_inner()))?;
        let my_address = token.my_address().map_to_mm(SplInitError::MyAddressError)?;
        let mut balances = HashMap::new();
        balances.insert(my_address, balance);
        let init_result = SplInitResult {
            balances,
            token_contract_address: token.conf.token_contract_address,
            platform_coin: token.platform_coin.ticker().to_owned(),
        };
        Ok((token, init_result))
    }
}
