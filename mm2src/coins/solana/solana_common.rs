use crate::solana::{SolanaAsyncCommonOps, SolanaCommonOps};
use crate::{MarketCoinOps, NumConversError, WithdrawError, WithdrawRequest};
use bigdecimal::ToPrimitive;
use common::mm_error::MmError;
use common::mm_number::BigDecimal;
use futures::compat::Future01CompatExt;
use solana_sdk::native_token::LAMPORTS_PER_SOL;

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
    req: &WithdrawRequest,
) -> Result<(BigDecimal, BigDecimal), MmError<WithdrawError>>
where
    T: SolanaCommonOps + SolanaAsyncCommonOps + MarketCoinOps,
{
    let my_balance = coin.my_balance().compat().await?.spendable;
    let to_send = if req.max {
        my_balance.clone()
    } else {
        req.amount.clone()
    };
    if to_send > my_balance {
        return MmError::err(WithdrawError::NotSufficientBalance {
            coin: coin.ticker().to_string(),
            available: my_balance.clone(),
            required: &to_send - &my_balance,
        });
    }
    Ok((to_send, my_balance))
}
