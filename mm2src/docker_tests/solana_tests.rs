use crate::docker_tests::docker_tests_common::*;
use common::for_tests::{enable_solana_with_tokens, enable_spl};
use num_traits::Zero;
use serde_json::{self as json};

#[test]
fn test_solana_and_spl_balance_enable_spl_v2() {
    let mm = solana_supplied_node();
    let tx_history = false;
    let enable_solana_with_tokens = block_on(enable_solana_with_tokens(
        &mm,
        "SOL-DEVNET",
        &["USDC-SOL-DEVNET"],
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
    let usdc_spl = spl_balances.balances.get("USDC-SOL-DEVNET").unwrap();
    assert!(usdc_spl.spendable.is_zero());

    let enable_spl = block_on(enable_spl(&mm, "ADEX-SOL-DEVNET"));
    let enable_spl: RpcV2Response<EnableSplResponse> = json::from_value(enable_spl).unwrap();
    assert_eq!(1, enable_spl.result.balances.len());

    let (_, balance) = enable_spl.result.balances.into_iter().next().unwrap();
    assert!(balance.spendable > 0.into());
}
