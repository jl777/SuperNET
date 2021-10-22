use crate::solana::{SolanaAsyncCommonOps, SolanaCommonOps};
use crate::{MarketCoinOps, WithdrawError, WithdrawRequest};
use bigdecimal::ToPrimitive;
use common::mm_error::MmError;
use common::mm_number::BigDecimal;
use futures::compat::Future01CompatExt;
use solana_sdk::hash::Hash;
use solana_sdk::native_token::LAMPORTS_PER_SOL;

pub fn lamports_to_sol(lamports: u64) -> BigDecimal { BigDecimal::from(lamports) / BigDecimal::from(LAMPORTS_PER_SOL) }

pub fn sol_to_lamports(sol: &BigDecimal) -> Option<u64> { (sol * BigDecimal::from(LAMPORTS_PER_SOL)).to_u64() }

pub fn ui_amount_to_amount(ui_amount: BigDecimal, decimals: u8) -> Option<u64> {
    (ui_amount * BigDecimal::from(10_u64.pow(decimals as u32))).to_u64()
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

pub async fn check_amount_too_low<T>(coin: &T) -> Result<(BigDecimal, Hash), MmError<WithdrawError>>
where
    T: SolanaCommonOps + SolanaAsyncCommonOps + MarketCoinOps,
{
    let base_balance = coin.base_coin_balance().compat().await?;
    let (hash, fee_calculator) = coin.rpc().get_recent_blockhash()?;
    let sol_required = lamports_to_sol(fee_calculator.lamports_per_signature);
    if base_balance < sol_required {
        return MmError::err(WithdrawError::AmountTooLow {
            amount: base_balance.clone(),
            threshold: &sol_required - &base_balance,
        });
    }
    Ok((sol_required, hash))
}
