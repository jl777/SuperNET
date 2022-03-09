use crate::docker_tests::docker_tests_common::*;
use common::for_tests::enable_solana_with_tokens;
use num_traits::Zero;
use serde_json::{self as json};

#[test]
fn test_solana_and_spl_balance_enable_spl_v2() {
    let mm = solana_supplied_node();
    let tx_history = false;
    let enable_solana_with_tokens = block_on(enable_solana_with_tokens(
        &mm,
        "SOL-DEVNET",
        &["USDC-SOL-DEVNET", "ADEX-SOL-DEVNET"],
        "https://api.devnet.solana.com",
        tx_history,
    ));
    let enable_solana_with_tokens: RpcV2Response<EnableSolanaWithTokensResponse> =
        json::from_value(enable_solana_with_tokens).unwrap();

    let (_, solana_balance) = enable_solana_with_tokens
        .result
        .solana_addresses_infos
        .into_iter()
        .next()
        .unwrap();
    assert!(solana_balance.balances.spendable > 0.into());

    let (_, spl_balances) = enable_solana_with_tokens
        .result
        .spl_addresses_infos
        .into_iter()
        .next()
        .unwrap();
    let actual_spl = spl_balances.balances.get("ADEX-SOL-DEVNET").unwrap();
    assert!(actual_spl.spendable > 0.into());
    let usdc_spl = spl_balances.balances.get("USDC-SOL-DEVNET").unwrap();
    assert!(usdc_spl.spendable.is_zero())
}
