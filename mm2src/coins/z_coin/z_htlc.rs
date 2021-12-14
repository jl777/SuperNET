// historical milestone, first performed RICK/ZOMBIE swap
// dex fee - https://zombie.explorer.lordofthechains.com/tx/40bec29f268c349722a3228743e5c5b461cf16d124cddcfd2fc624fe895a0bdd
// maker payment - https://rick.explorer.dexstats.info/tx/9d36e95e5147450399895f0f248ac2e2de13382401c2986e134cc3d62bda738e
// taker payment - https://zombie.explorer.lordofthechains.com/tx/b248992e064fab579774c0479b04043091cf62f3975cb1664ea7d4f857ebe6f8
// taker payment spend - https://zombie.explorer.lordofthechains.com/tx/af6bb0f99f9a5a070a0c1f53d69e4189b0e9b68f9d66e69f201a6b6d9f93897e
// maker payment spend - https://rick.explorer.dexstats.info/tx/6a2dcc866ad75cebecb780a02320073a88bcf5e57ddccbe2657494e7747d591e

use super::ZCoin;
use crate::utxo::rpc_clients::{UtxoRpcClientEnum, UtxoRpcError};
use crate::utxo::utxo_common::payment_script;
use crate::utxo::{sat_from_big_decimal, UtxoAddressFormat};
use crate::z_coin::{ARRRConsensusParams, SendOutputsErr, ZOutput, DEX_FEE_OVK};
use crate::NumConversError;
use bigdecimal::BigDecimal;
use bitcrypto::dhash160;
use chain::Transaction as UtxoTx;
use common::mm_error::prelude::*;
use derive_more::Display;
use futures::compat::Future01CompatExt;
use keys::{Address, Public};
use script::{Builder as ScriptBuilder, Opcode, Script};
use secp256k1::SecretKey;
use serialization::deserialize;
use zcash_primitives::consensus;
use zcash_primitives::legacy::Script as ZCashScript;
use zcash_primitives::memo::MemoBytes;
use zcash_primitives::transaction::builder::{Builder as ZTxBuilder, Error as ZTxBuilderError};
use zcash_primitives::transaction::components::{Amount, OutPoint as ZCashOutpoint, TxOut};
use zcash_primitives::transaction::Transaction as ZTransaction;

/// Sends HTLC output from the coin's my_z_addr
pub async fn z_send_htlc(
    coin: &ZCoin,
    time_lock: u32,
    other_pub: &Public,
    secret_hash: &[u8],
    amount: BigDecimal,
) -> Result<ZTransaction, MmError<SendOutputsErr>> {
    let payment_script = payment_script(time_lock, secret_hash, coin.utxo_arc.key_pair.public(), &other_pub);
    let script_hash = dhash160(&payment_script);
    let htlc_address = Address {
        prefix: coin.utxo_arc.conf.p2sh_addr_prefix,
        t_addr_prefix: coin.utxo_arc.conf.p2sh_t_addr_prefix,
        hash: script_hash.into(),
        checksum_type: coin.utxo_arc.conf.checksum_type,
        addr_format: UtxoAddressFormat::Standard,
        hrp: None,
    };

    let amount_sat = sat_from_big_decimal(&amount, coin.utxo_arc.decimals)?;
    let address = htlc_address.to_string();
    if let UtxoRpcClientEnum::Native(native) = coin.rpc_client() {
        native.import_address(&address, &address, false).compat().await.unwrap();
    }

    let htlc_script = ScriptBuilder::build_p2sh(&script_hash.into()).to_bytes().take();
    let htlc_output = TxOut {
        value: Amount::from_u64(amount_sat).map_err(|_| NumConversError::new("Invalid ZCash amount".into()))?,
        script_pubkey: ZCashScript(htlc_script),
    };

    let opret_script = ScriptBuilder::default()
        .push_opcode(Opcode::OP_RETURN)
        .push_data(&payment_script)
        .into_bytes()
        .take();
    let op_return_out = TxOut {
        value: Amount::zero(),
        script_pubkey: ZCashScript(opret_script),
    };
    let mm_tx = coin.send_outputs(vec![htlc_output, op_return_out], vec![]).await?;

    Ok(mm_tx)
}

/// Sends HTLC output from the coin's my_z_addr
pub async fn z_send_dex_fee(
    coin: &ZCoin,
    amount: BigDecimal,
    uuid: &[u8],
) -> Result<ZTransaction, MmError<SendOutputsErr>> {
    let dex_fee_amount = sat_from_big_decimal(&amount, coin.utxo_arc.decimals)?;
    let dex_fee_out = ZOutput {
        to_addr: coin.z_fields.dex_fee_addr.clone(),
        amount: Amount::from_u64(dex_fee_amount).map_err(|_| NumConversError::new("Invalid ZCash amount".into()))?,
        viewing_key: Some(DEX_FEE_OVK),
        memo: Some(MemoBytes::from_bytes(uuid).expect("uuid length < 512")),
    };

    let tx = coin.send_outputs(vec![], vec![dex_fee_out]).await?;

    Ok(tx)
}

#[derive(Debug, Display)]
#[allow(clippy::large_enum_variant, clippy::upper_case_acronyms)]
pub enum ZP2SHSpendError {
    ZTxBuilderError(ZTxBuilderError),
    Rpc(UtxoRpcError),
}

impl From<ZTxBuilderError> for ZP2SHSpendError {
    fn from(tx_builder: ZTxBuilderError) -> ZP2SHSpendError { ZP2SHSpendError::ZTxBuilderError(tx_builder) }
}

impl From<UtxoRpcError> for ZP2SHSpendError {
    fn from(rpc: UtxoRpcError) -> ZP2SHSpendError { ZP2SHSpendError::Rpc(rpc) }
}

/// Spends P2SH output 0 to the coin's my_z_addr
pub async fn z_p2sh_spend(
    coin: &ZCoin,
    p2sh_tx: ZTransaction,
    tx_locktime: u32,
    input_sequence: u32,
    redeem_script: Script,
    script_data: Script,
) -> Result<UtxoTx, MmError<ZP2SHSpendError>> {
    let current_block = coin.utxo_arc.rpc_client.get_block_count().compat().await? as u32;
    let mut tx_builder = ZTxBuilder::new(ARRRConsensusParams {}, current_block.into());
    tx_builder.set_lock_time(tx_locktime);

    let secp_secret =
        SecretKey::from_slice(&*coin.utxo_arc.key_pair.private().secret).expect("Keypair contains a valid secret key");

    let outpoint = ZCashOutpoint::new(p2sh_tx.txid().0, 0);
    let tx_out = TxOut {
        value: p2sh_tx.vout[0].value,
        script_pubkey: ZCashScript(redeem_script.to_vec()),
    };
    tx_builder
        .add_transparent_input(
            secp_secret,
            outpoint,
            input_sequence,
            ZCashScript(script_data.to_vec()),
            tx_out,
        )
        .map_to_mm(ZP2SHSpendError::from)?;
    tx_builder
        .add_sapling_output(
            None,
            coin.z_fields.my_z_addr.clone(),
            // TODO use fee from coin here
            p2sh_tx.vout[0].value - Amount::from_i64(1000).expect("1000 will always succeed"),
            None,
        )
        .map_to_mm(ZP2SHSpendError::from)?;

    let (zcash_tx, _) = tx_builder
        .build(consensus::BranchId::Sapling, &coin.z_fields.z_tx_prover)
        .map_to_mm(ZP2SHSpendError::from)?;

    let mut tx_buffer = Vec::with_capacity(1024);
    zcash_tx.write(&mut tx_buffer).unwrap();
    let refund_tx: UtxoTx = deserialize(tx_buffer.as_slice()).expect("librustzcash should produce a valid tx");

    coin.rpc_client()
        .send_raw_transaction(tx_buffer.into())
        .compat()
        .await?;

    Ok(refund_tx)
}