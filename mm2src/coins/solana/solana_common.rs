use crate::solana::{SolanaAsyncCommonOps, SolanaCommonOps};
use crate::{BalanceError, DerivationMethodNotSupported, MarketCoinOps, NumConversError, WithdrawError};
use bigdecimal::ToPrimitive;
use common::mm_error::MmError;
use common::mm_number::BigDecimal;
use derive_more::Display;
use futures::compat::Future01CompatExt;
use solana_sdk::native_token::LAMPORTS_PER_SOL;

#[derive(Debug, Display)]
pub enum SufficientBalanceError {
    #[display(
        fmt = "Not enough {} to withdraw: available {}, required at least {}",
        coin,
        available,
        required
    )]
    NotSufficientBalance {
        coin: String,
        available: BigDecimal,
        required: BigDecimal,
    },
    #[display(fmt = "{}", _0)]
    DerivationMethodNotSupported(DerivationMethodNotSupported),
    #[display(fmt = "Invalid response: {}", _0)]
    InvalidResponse(String),
    #[display(fmt = "Transport: {}", _0)]
    Transport(String),
    #[display(fmt = "Internal: {}", _0)]
    Internal(String),
}

impl From<BalanceError> for SufficientBalanceError {
    fn from(e: BalanceError) -> Self {
        match e {
            BalanceError::Transport(e) => SufficientBalanceError::Transport(e),
            BalanceError::InvalidResponse(e) => SufficientBalanceError::InvalidResponse(e),
            BalanceError::DerivationMethodNotSupported(e) => SufficientBalanceError::DerivationMethodNotSupported(e),
            BalanceError::Internal(e) => SufficientBalanceError::Internal(e),
        }
    }
}
impl From<SufficientBalanceError> for WithdrawError {
    fn from(e: SufficientBalanceError) -> Self {
        match e {
            SufficientBalanceError::NotSufficientBalance {
                coin,
                available,
                required,
            } => WithdrawError::NotSufficientBalance {
                coin,
                available,
                required,
            },
            SufficientBalanceError::DerivationMethodNotSupported(e) => WithdrawError::from(e),
            SufficientBalanceError::InvalidResponse(e) | SufficientBalanceError::Transport(e) => {
                WithdrawError::Transport(e)
            },
            SufficientBalanceError::Internal(e) => WithdrawError::InternalError(e),
        }
    }
}

pub fn lamports_to_sol(lamports: u64) -> BigDecimal { BigDecimal::from(lamports) / BigDecimal::from(LAMPORTS_PER_SOL) }

pub fn sol_to_lamports(sol: &BigDecimal) -> Result<u64, MmError<NumConversError>> {
    let maybe_lamports = (sol * BigDecimal::from(LAMPORTS_PER_SOL)).to_u64();
    match maybe_lamports {
        None => MmError::err(NumConversError("Error when converting sol to lamports".to_string())),
        Some(lamports) => Ok(lamports),
    }
}

pub fn ui_amount_to_amount(ui_amount: BigDecimal, decimals: u8) -> Result<u64, MmError<NumConversError>> {
    let maybe_amount = (ui_amount * BigDecimal::from(10_u64.pow(decimals as u32))).to_u64();
    match maybe_amount {
        None => MmError::err(NumConversError("Error when converting ui amount to amount".to_string())),
        Some(amount) => Ok(amount),
    }
}

pub fn amount_to_ui_amount(amount: u64, decimals: u8) -> BigDecimal {
    BigDecimal::from(amount) / BigDecimal::from(10_u64.pow(decimals as u32))
}

pub async fn check_sufficient_balance<T>(
    coin: &T,
    max: bool,
    amount: BigDecimal,
) -> Result<(BigDecimal, BigDecimal), MmError<SufficientBalanceError>>
where
    T: SolanaCommonOps + SolanaAsyncCommonOps + MarketCoinOps,
{
    let my_balance = coin.my_balance().compat().await?.spendable;
    let to_send = if max { my_balance.clone() } else { amount.clone() };
    if to_send > my_balance {
        return MmError::err(SufficientBalanceError::NotSufficientBalance {
            coin: coin.ticker().to_string(),
            available: my_balance.clone(),
            required: &to_send - &my_balance,
        });
    }
    Ok((to_send, my_balance))
}
