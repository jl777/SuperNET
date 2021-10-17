use super::*;
use crate::{solana::solana_common_tests::solana_coin_for_test,
            solana::solana_common_tests::{spl_coin_for_test, SolanaNet}};
use std::{str::from_utf8, str::FromStr};

mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn spl_coin_creation() {
        let passphrase = "federal stay trigger hour exist success game vapor become comfort action phone bright ill target wild nasty crumble dune close rare fabric hen iron".to_string();
        let (_, sol_coin) = solana_coin_for_test(passphrase.clone(), SolanaNet::Testnet);
        let sol_spl_usdc_coin = spl_coin_for_test(
            sol_coin.clone(),
            "USDC".to_string(),
            6,
            solana_sdk::pubkey::Pubkey::from_str("CpMah17kQEL2wqyMKt3mZBdTnZbkbfx4nqmQMFDP5vwp").unwrap(),
        );

        println!("address: {}", sol_spl_usdc_coin.my_address().unwrap());
        assert_eq!(
            sol_spl_usdc_coin.my_address().unwrap(),
            "FJktmyjV9aBHEShT4hfnLpr9ELywdwVtEL1w1rSWgbVf"
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn spl_my_balance() {
        let passphrase = "federal stay trigger hour exist success game vapor become comfort action phone bright ill target wild nasty crumble dune close rare fabric hen iron".to_string();
        let (_, sol_coin) = solana_coin_for_test(passphrase.clone(), SolanaNet::Testnet);
        let sol_spl_usdc_coin = spl_coin_for_test(
            sol_coin.clone(),
            "USDC".to_string(),
            6,
            solana_sdk::pubkey::Pubkey::from_str("CpMah17kQEL2wqyMKt3mZBdTnZbkbfx4nqmQMFDP5vwp").unwrap(),
        );

        let res = sol_spl_usdc_coin.my_balance().wait().unwrap();
        assert_ne!(res.spendable, BigDecimal::from(0.0));

        let sol_spl_wsol_coin = spl_coin_for_test(
            sol_coin.clone(),
            "WSOL".to_string(),
            8,
            solana_sdk::pubkey::Pubkey::from_str("So11111111111111111111111111111111111111112").unwrap(),
        );
        let res = sol_spl_wsol_coin.my_balance().wait().unwrap();
        assert_eq!(res.spendable, BigDecimal::from(0.0));
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_spl_transactions() {
        let passphrase = "federal stay trigger hour exist success game vapor become comfort action phone bright ill target wild nasty crumble dune close rare fabric hen iron".to_string();
        let (_, sol_coin) = solana_coin_for_test(passphrase.clone(), SolanaNet::Testnet);
        let usdc_sol_coin = spl_coin_for_test(
            sol_coin.clone(),
            "USDC".to_string(),
            6,
            solana_sdk::pubkey::Pubkey::from_str("CpMah17kQEL2wqyMKt3mZBdTnZbkbfx4nqmQMFDP5vwp").unwrap(),
        );
        let valid_tx_details = usdc_sol_coin
            .withdraw(WithdrawRequest {
                coin: "USDC".to_string(),
                to: "AYJmtzc9D4KU6xsDzhKShFyYKUNXY622j9QoQEo4LfpX".to_string(),
                amount: BigDecimal::from_str("0.0001").unwrap(),
                max: false,
                fee: None,
            })
            .wait()
            .unwrap();
        assert_eq!(valid_tx_details.total_amount, BigDecimal::from(0.0001));
        assert_eq!(valid_tx_details.coin, "USDC".to_string());
        assert_ne!(valid_tx_details.timestamp, 0);
        let tx_str = from_utf8(&*valid_tx_details.tx_hex.0).unwrap();
        let res = usdc_sol_coin.send_raw_tx(tx_str).wait();
        assert_eq!(res.is_err(), false);
        println!("{:?}", res);
    }
}
