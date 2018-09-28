
/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/
//
//  LP_etomic.c
//  marketmaker
//

//
// Created by artem on 24.01.18.
//
#include "LP_etomic.h"
#define ALICE_PAYMENT_SENT 1
#define BOB_DEPOSIT_SENT 1
#define BOB_PAYMENT_SENT 1

// The pointer to ETH client created by Rust code
void *LP_eth_client;

int32_t LP_etomic_wait_for_confirmation(char *txId)
{
    return(wait_for_confirmation(txId, LP_eth_client));
}

void LP_etomic_pubkeystr_to_addr(char *pubkey, char *output)
{
    printf("Got pubkey: %s\n", pubkey);
    char *address = pub_key_2_addr(pubkey);
    strcpy(output, address);
    free(address);
}

char *LP_etomicalice_send_fee(struct basilisk_swap *swap)
{
    swap->myfee.I.eth_amount = LP_DEXFEE(swap->I.alicerealsat);
    if (strcmp(swap->I.alicestr,"ETH") == 0 ) {
        return(send_eth(INSTANTDEX_ETH_ADDR, (uint64_t)LP_DEXFEE(swap->I.alicerealsat), 0, 0, 1, LP_eth_client));
    } else {
        struct iguana_info *alicecoin = LP_coinfind(swap->I.alicestr);

        return(send_erc20(swap->I.alicetomic, INSTANTDEX_ETH_ADDR, (uint64_t)LP_DEXFEE(swap->I.alicerealsat), 0, 0, 1, alicecoin->decimals, LP_eth_client));
    }
}

uint8_t LP_etomic_verify_alice_fee(struct basilisk_swap *swap)
{
    if (wait_for_confirmation(swap->otherfee.I.ethTxid, LP_eth_client) < 0) {
        printf("Alice fee tx %s does not exist", swap->otherfee.I.ethTxid);
        return(0);
    }
    EthTxData data = get_eth_tx_data(swap->otherfee.I.ethTxid, LP_eth_client);
    if (compare_addresses(data.from, swap->I.etomicdest) == 0) {
        printf("Alice fee tx %s was sent from wrong address %s\n", swap->otherfee.I.ethTxid, data.from);
        return(0);
    }

    if ( strcmp(swap->I.alicestr,"ETH") == 0 ) {
        if (compare_addresses(data.to, INSTANTDEX_ETH_ADDR) == 0) {
            printf("Alice fee %s was sent to wrong address %s\n", swap->otherfee.I.ethTxid, data.to);
            return(0);
        }
        if (data.value != LP_DEXFEE(swap->I.alicerealsat)) {
            printf("Alice fee %s amount %" PRIu64 " is not equal to expected %" PRId64 "\n", swap->otherfee.I.ethTxid, data.value, LP_DEXFEE(swap->I.alicerealsat));
            return(0);
        }
        return(1);
    } else {
        struct iguana_info *alicecoin = LP_coinfind(swap->I.alicestr);

        if (compare_addresses(data.to, swap->I.alicetomic) == 0) {
            printf("Alice ERC20 fee %s token address %s is not equal to expected %s\n", swap->otherfee.I.ethTxid, data.to, swap->I.alicetomic);
            return(0);
        }
        return(verify_alice_erc20_fee_data(INSTANTDEX_ETH_ADDR, (uint64_t)LP_DEXFEE(swap->I.alicerealsat), data.input, alicecoin->decimals));
    }
}

char *LP_etomicalice_send_payment(struct basilisk_swap *swap)
{
    AliceSendsEthPaymentInput input; AliceSendsErc20PaymentInput input20;
    swap->alicepayment.I.eth_amount = swap->I.alicerealsat;
    // set input and txData fields from the swap data structure
    if ( strcmp(swap->I.alicestr,"ETH") == 0 )
    {
        memset(&input,0,sizeof(input));
        strcpy(input.bob_address, swap->I.etomicsrc);
        uint8arrayToHex(input.bob_hash, swap->I.secretBn, 20);
        uint8arrayToHex(input.alice_hash, swap->I.secretAm, 20);
        uint8arrayToHex(input.deal_id, swap->alicepayment.I.actualtxid.bytes, 32);
        input.amount = (uint64_t) swap->I.alicerealsat;

        return(alice_sends_eth_payment(input,LP_eth_client));
    }
    else
    {
        struct iguana_info *alicecoin = LP_coinfind(swap->I.alicestr);

        memset(&input20,0,sizeof(input20));
        strcpy(input20.bob_address, swap->I.etomicsrc);
        uint8arrayToHex(input20.bob_hash, swap->I.secretBn, 20);
        uint8arrayToHex(input20.alice_hash, swap->I.secretAm, 20);
        uint8arrayToHex(input20.deal_id, swap->alicepayment.I.actualtxid.bytes, 32);
        strcpy(input20.token_address, swap->I.alicetomic);
        input20.amount = swap->I.alicerealsat;
        input20.decimals = alicecoin->decimals;

        uint64_t allowance = get_erc20_allowance(swap->I.etomicdest, LP_alice_contract, swap->I.alicetomic, alicecoin->decimals, LP_eth_client);
        if (allowance < swap->I.alicerealsat) {
            printf("Alice token allowance is too low, setting new allowance\n");
            ApproveErc20Input approveErc20Input;
            strcpy(approveErc20Input.token_address, swap->I.alicetomic);
            strcpy(approveErc20Input.spender, LP_alice_contract);

            int error = 0;
            approveErc20Input.amount = get_erc20_balance(swap->I.etomicdest, swap->I.alicetomic, alicecoin->decimals, &error, LP_eth_client);
            approveErc20Input.decimals = alicecoin->decimals;
            char *allowTxId = approve_erc20(approveErc20Input, LP_eth_client);
            LP_etomic_wait_for_confirmation(allowTxId);
            free(allowTxId);
        }

        return(alice_sends_erc20_payment(input20,LP_eth_client));
    }
}

uint8_t LP_etomic_verify_alice_payment(struct basilisk_swap *swap, char *txId)
{
    if (wait_for_confirmation(txId, LP_eth_client) < 0) {
        printf("Alice payment %s does not exist\n", txId);
        return(0);
    }
    EthTxData data = get_eth_tx_data(txId, LP_eth_client);
    if (compare_addresses(data.to, LP_alice_contract) == 0) {
        printf("Alice payment %s was sent to wrong address %s\n", txId, data.to);
        return(0);
    }
    if (compare_addresses(data.from, swap->I.etomicdest) == 0) {
        printf("Alice payment %s was done from wrong address %s\n", txId, data.from);
        return(0);
    }
    AliceSendsEthPaymentInput input; AliceSendsErc20PaymentInput input20;
    if ( strcmp(swap->I.alicestr,"ETH") == 0 ) {
        if (data.value != swap->I.alicerealsat) {
            printf("Alice payment amount %" PRIu64 " does not match expected %" PRIu64 "\n", data.value, swap->I.alicerealsat);
            return(0);
        }
        memset(&input,0,sizeof(input));
        strcpy(input.bob_address, swap->I.etomicsrc);
        uint8arrayToHex(input.bob_hash, swap->I.secretBn, 20);
        uint8arrayToHex(input.alice_hash, swap->I.secretAm, 20);
        uint8arrayToHex(input.deal_id, swap->alicepayment.I.actualtxid.bytes, 32);
        input.amount = (uint64_t) swap->I.alicerealsat;

        return(verify_alice_eth_payment_data(input, data.input));
    } else {
        struct iguana_info *alicecoin = LP_coinfind(swap->I.alicestr);

        memset(&input20,0,sizeof(input20));
        strcpy(input20.bob_address, swap->I.etomicsrc);
        uint8arrayToHex(input20.bob_hash, swap->I.secretBn, 20);
        uint8arrayToHex(input20.alice_hash, swap->I.secretAm, 20);
        uint8arrayToHex(input20.deal_id, swap->alicepayment.I.actualtxid.bytes, 32);
        strcpy(input20.token_address, swap->I.alicetomic);
        input20.amount = swap->I.alicerealsat;
        input20.decimals = alicecoin->decimals;

        return(verify_alice_erc20_payment_data(input20, data.input));
    }
}

char *LP_etomicalice_reclaims_payment(struct LP_swap_remember *swap)
{
    if (wait_for_confirmation(swap->eth_tx_ids[BASILISK_ALICEPAYMENT], LP_eth_client) < 0) {
        printf("Alice ETH payment %s is not found, can't reclaim\n", swap->eth_tx_ids[BASILISK_ALICEPAYMENT]);
        return NULL;
    }
    EthTxReceipt receipt = get_eth_tx_receipt(swap->eth_tx_ids[BASILISK_ALICEPAYMENT], LP_eth_client);
    if (receipt.status != 1) {
        printf("Alice payment receipt status failed, can't reclaim\n");
        return NULL;
    }
    AliceReclaimsPaymentInput input;
    memset(&input,0,sizeof(input));

    struct iguana_info *alice_coin = LP_coinfind(swap->dest);

    uint8arrayToHex(input.deal_id, swap->txids[BASILISK_ALICEPAYMENT].bytes, 32);
    if (alice_payment_status(input.deal_id, LP_eth_client) != ALICE_PAYMENT_SENT) {
        printf("Alice payment smart contract status check failed, can't spend\n");
        return NULL;
    }
    input.amount = swap->alicerealsat;

    if (swap->alicetomic[0] != 0) {
        strcpy(input.token_address, swap->alicetomic);
    } else {
        strcpy(input.token_address, "0x0000000000000000000000000000000000000000");
    }
    strcpy(input.bob_address, swap->etomicsrc);
    uint8arrayToHex(input.alice_hash, swap->secretAm, 20);
    bits256 invertedSecret;
    int32_t i;
    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privBn.bytes[31 - i];
    }
    uint8arrayToHex(input.bob_secret, invertedSecret.bytes, 32);

    input.decimals = alice_coin->decimals;
    return alice_reclaims_payment(input, LP_eth_client);
}

char *LP_etomicbob_spends_alice_payment(struct LP_swap_remember *swap)
{
    if (wait_for_confirmation(swap->eth_tx_ids[BASILISK_ALICEPAYMENT], LP_eth_client) < 0) {
        printf("Alice ETH payment %s is not found, can't spend\n", swap->eth_tx_ids[BASILISK_ALICEPAYMENT]);
        return NULL;
    }
    EthTxReceipt receipt = get_eth_tx_receipt(swap->eth_tx_ids[BASILISK_ALICEPAYMENT], LP_eth_client);
    if (receipt.status != 1) {
        printf("Alice payment receipt status failed, can't spend\n");
        return NULL;
    }
    BobSpendsAlicePaymentInput input;

    memset(&input,0,sizeof(input));

    struct iguana_info *ecoin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    uint8arrayToHex(input.deal_id, swap->txids[BASILISK_ALICEPAYMENT].bytes, 32);
    if (alice_payment_status(input.deal_id, LP_eth_client) != ALICE_PAYMENT_SENT) {
        printf("Alice payment smart contract status check failed, can't spend\n");
        return NULL;
    }

    input.amount = swap->alicerealsat;

    if (swap->alicetomic[0] != 0) {
        strcpy(input.token_address, swap->alicetomic);
    } else {
        strcpy(input.token_address, "0x0000000000000000000000000000000000000000");
    }

    strcpy(input.alice_address, swap->etomicdest);
    bits256 invertedSecret; int32_t i;
    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privAm.bytes[31 - i];
    }
    uint8arrayToHex(input.alice_secret, invertedSecret.bytes, 32);
    uint8arrayToHex(input.bob_hash, swap->secretBn, 20);
    struct iguana_info *alice_coin = LP_coinfind(swap->dest);
    input.decimals = alice_coin->decimals;

    return bob_spends_alice_payment(input, LP_eth_client);
}

char *LP_etomicbob_sends_deposit(struct basilisk_swap *swap)
{
    BobSendsEthDepositInput input;
    BobSendsErc20DepositInput input20;
    memset(&input,0,sizeof(input));
    memset(&input20,0,sizeof(input20));
    if ( strcmp(swap->I.bobstr,"ETH") == 0 ) {
        uint8arrayToHex(input.deposit_id, swap->bobdeposit.I.actualtxid.bytes, 32);
        strcpy(input.alice_address, swap->I.etomicdest);
        uint8arrayToHex(input.bob_hash, swap->I.secretBn, 20);
        uint8arrayToHex(input.alice_hash, swap->I.secretAm, 20);
        input.lock_time = swap->bobdeposit.I.locktime;
        input.amount = LP_DEPOSITSATOSHIS(swap->I.bobrealsat);

        return bob_sends_eth_deposit(input, LP_eth_client);
    } else {
        struct iguana_info *bobcoin = LP_coinfind(swap->I.bobstr);

        uint8arrayToHex(input20.deposit_id, swap->bobdeposit.I.actualtxid.bytes, 32);
        strcpy(input20.alice_address, swap->I.etomicdest);
        uint8arrayToHex(input20.bob_hash, swap->I.secretBn, 20);
        uint8arrayToHex(input20.alice_hash, swap->I.secretAm, 20);
        input20.amount = LP_DEPOSITSATOSHIS(swap->I.bobrealsat);
        strcpy(input20.token_address, swap->I.bobtomic);
        input20.lock_time = swap->bobdeposit.I.locktime;
        input20.decimals = bobcoin->decimals;

        uint64_t allowance = get_erc20_allowance(swap->I.etomicsrc, LP_bob_contract, swap->I.bobtomic, bobcoin->decimals, LP_eth_client);
        if (allowance < LP_DEPOSITSATOSHIS(swap->I.bobrealsat)) {
            printf("Bob token allowance is too low, setting new allowance\n");
            ApproveErc20Input approveErc20Input;
            strcpy(approveErc20Input.token_address, swap->I.bobtomic);
            strcpy(approveErc20Input.spender, LP_bob_contract);

            int error = 0;
            approveErc20Input.amount = get_erc20_balance(swap->I.etomicsrc, swap->I.bobtomic, bobcoin->decimals, &error, LP_eth_client);
            approveErc20Input.decimals = bobcoin->decimals;

            char *allowTxId = approve_erc20(approveErc20Input, LP_eth_client);
            LP_etomic_wait_for_confirmation(allowTxId);
            free(allowTxId);
        }

        return bob_sends_erc20_deposit(input20, LP_eth_client);
    }
}

uint8_t LP_etomic_verify_bob_deposit(struct basilisk_swap *swap, char *txId)
{
    if (wait_for_confirmation(txId, LP_eth_client) < 0) {
        printf("Bob deposit txid %s does not exist\n", txId);
        return(0);
    }
    EthTxData data = get_eth_tx_data(txId, LP_eth_client);
    if (compare_addresses(data.to, LP_bob_contract) == 0) {
        printf("Bob deposit txid %s was sent to wrong address %s\n", txId, data.to);
        return(0);
    }
    if (compare_addresses(data.from, swap->I.etomicsrc) == 0) {
        printf("Bob deposit txid %s was sent from wrong address %s\n", txId, data.from);
        return(0);
    }
    BobSendsEthDepositInput input;
    BobSendsErc20DepositInput input20;
    memset(&input,0,sizeof(input));
    memset(&input20,0,sizeof(input20));
    if ( strcmp(swap->I.bobstr,"ETH") == 0 ) {
        if (data.value != LP_DEPOSITSATOSHIS(swap->I.bobrealsat)) {
            printf("Bob deposit %s amount %" PRIu64 " != expected %" PRIu64 "\n", txId, data.value, LP_DEPOSITSATOSHIS(swap->I.bobrealsat));
            return(0);
        }
        uint8arrayToHex(input.deposit_id, swap->bobdeposit.I.actualtxid.bytes, 32);
        strcpy(input.alice_address, swap->I.etomicdest);
        uint8arrayToHex(input.bob_hash, swap->I.secretBn, 20);
        uint8arrayToHex(input.alice_hash, swap->I.secretAm, 20);
        input.lock_time = swap->bobdeposit.I.locktime;

        return verify_bob_eth_deposit_data(input, data.input);
    } else {
        struct iguana_info *bobcoin = LP_coinfind(swap->I.bobstr);

        uint8arrayToHex(input20.deposit_id, swap->bobdeposit.I.actualtxid.bytes, 32);
        strcpy(input20.alice_address, swap->I.etomicdest);
        uint8arrayToHex(input20.bob_hash, swap->I.secretBn, 20);
        uint8arrayToHex(input20.alice_hash, swap->I.secretAm, 20);
        input20.amount = LP_DEPOSITSATOSHIS(swap->I.bobrealsat);
        strcpy(input20.token_address, swap->I.bobtomic);
        input20.lock_time = swap->bobdeposit.I.locktime;
        input20.decimals = bobcoin->decimals;

        return verify_bob_erc20_deposit_data(input20, data.input);
    }
}

char *LP_etomicbob_refunds_deposit(struct LP_swap_remember *swap)
{
    if (wait_for_confirmation(swap->eth_tx_ids[BASILISK_BOBDEPOSIT], LP_eth_client) < 0) {
        printf("Bob deposit %s is not found, can't refund\n", swap->eth_tx_ids[BASILISK_BOBDEPOSIT]);
        return NULL;
    }
    BobRefundsDepositInput input;
    memset(&input,0,sizeof(input));

    struct iguana_info *bobcoin = LP_coinfind(swap->src);

    EthTxReceipt receipt = get_eth_tx_receipt(swap->eth_tx_ids[BASILISK_BOBDEPOSIT], LP_eth_client);
    if (receipt.status != 1) {
        printf("Bob deposit %s receipt status failed, can't refund\n", swap->eth_tx_ids[BASILISK_BOBDEPOSIT]);
        return NULL;
    }
    uint8arrayToHex(input.deposit_id, swap->txids[BASILISK_BOBDEPOSIT].bytes, 32);
    if (bob_deposit_status(input.deposit_id, LP_eth_client) != BOB_DEPOSIT_SENT) {
        printf("Bob deposit smart contract status check failed, can't claim\n");
        return NULL;
    }

    strcpy(input.alice_address, swap->etomicdest);

    bits256 invertedSecret;
    int32_t i;
    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privBn.bytes[31 - i];
    }
    uint8arrayToHex(input.bob_secret, invertedSecret.bytes, 32);
    uint8arrayToHex(input.alice_hash, swap->secretAm, 20);

    if (swap->bobtomic[0] != 0) {
        strcpy(input.token_address, swap->bobtomic);
    } else {
        strcpy(input.token_address, "0x0000000000000000000000000000000000000000");
    }
    input.amount = LP_DEPOSITSATOSHIS(swap->bobrealsat);
    input.decimals = bobcoin->decimals;

    return bob_refunds_deposit(input, LP_eth_client);
}

char *LP_etomicbob_sends_payment(struct basilisk_swap *swap)
{
    BobSendsEthPaymentInput input;
    BobSendsErc20PaymentInput input20;
    memset(&input,0,sizeof(input));
    memset(&input20,0,sizeof(input20));

    if ( strcmp(swap->I.bobstr,"ETH") == 0 ) {
        uint8arrayToHex(input.payment_id, swap->bobpayment.I.actualtxid.bytes, 32);
        strcpy(input.alice_address, swap->I.etomicdest);
        uint8arrayToHex(input.alice_hash, swap->I.secretAm, 20);
        input.lock_time = swap->bobpayment.I.locktime;
        input.amount = swap->I.bobrealsat;

        return bob_sends_eth_payment(input, LP_eth_client);
    } else {
        struct iguana_info *bobcoin = LP_coinfind(swap->I.bobstr);

        uint8arrayToHex(input20.payment_id, swap->bobpayment.I.actualtxid.bytes, 32);
        strcpy(input20.alice_address, swap->I.etomicdest);
        uint8arrayToHex(input20.alice_hash, swap->I.secretAm, 20);
        input20.amount = swap->I.bobrealsat;
        strcpy(input20.token_address, swap->I.bobtomic);
        input20.lock_time = swap->bobpayment.I.locktime;
        input20.decimals = bobcoin->decimals;

        uint64_t allowance = get_erc20_allowance(swap->I.etomicsrc, LP_bob_contract, swap->I.bobtomic, bobcoin->decimals, LP_eth_client);
        if (allowance < swap->I.bobrealsat) {
            printf("Bob token allowance is too low, setting new allowance\n");
            ApproveErc20Input approveErc20Input;
            strcpy(approveErc20Input.token_address, swap->I.bobtomic);
            strcpy(approveErc20Input.spender, LP_bob_contract);

            int error = 0;
            approveErc20Input.amount = get_erc20_balance(swap->I.etomicsrc, swap->I.bobtomic, bobcoin->decimals, &error, LP_eth_client);
            approveErc20Input.decimals = bobcoin->decimals;

            char *allowTxId = approve_erc20(approveErc20Input, LP_eth_client);
            LP_etomic_wait_for_confirmation(allowTxId);
            free(allowTxId);
        }

        return bob_sends_erc20_payment(input20, LP_eth_client);
    }
}

uint8_t LP_etomic_verify_bob_payment(struct basilisk_swap *swap, char *txId)
{
    if (wait_for_confirmation(txId, LP_eth_client) < 0) {
        printf("Bob payment %s is not found\n", txId);
        return 0;
    }
    EthTxData data = get_eth_tx_data(txId, LP_eth_client);
    if (compare_addresses(data.to, LP_bob_contract) == 0) {
        printf("Bob payment %s was sent to wrong address %s\n", txId, data.to);
    }
    if (compare_addresses(data.from, swap->I.etomicsrc) == 0) {
        printf("Bob payment %s was sent from wrong address %s\n", txId, data.from);
    }
    BobSendsEthPaymentInput input;
    BobSendsErc20PaymentInput input20;
    memset(&input,0,sizeof(input));
    memset(&input20,0,sizeof(input20));
    if ( strcmp(swap->I.bobstr,"ETH") == 0 ) {
        if (data.value != swap->I.bobrealsat) {
            printf("Bob payment %s amount %" PRIu64 " != expected %" PRIu64 "\n", txId, data.value, swap->I.bobrealsat);
            return(0);
        }
        uint8arrayToHex(input.payment_id, swap->bobpayment.I.actualtxid.bytes, 32);
        strcpy(input.alice_address, swap->I.etomicdest);
        uint8arrayToHex(input.alice_hash, swap->I.secretAm, 20);
        input.lock_time = swap->bobpayment.I.locktime;

        return verify_bob_eth_payment_data(input, data.input);
    } else {
        struct iguana_info *bobcoin = LP_coinfind(swap->I.bobstr);

        uint8arrayToHex(input20.payment_id, swap->bobpayment.I.actualtxid.bytes, 32);
        strcpy(input20.alice_address, swap->I.etomicdest);
        uint8arrayToHex(input20.alice_hash, swap->I.secretAm, 20);
        input20.amount = swap->I.bobrealsat;
        strcpy(input20.token_address, swap->I.bobtomic);
        input20.lock_time = swap->bobpayment.I.locktime;
        input20.decimals = bobcoin->decimals;

        return verify_bob_erc20_payment_data(input20, data.input);
    }
}

char *LP_etomicbob_reclaims_payment(struct LP_swap_remember *swap)
{
    if (wait_for_confirmation(swap->eth_tx_ids[BASILISK_BOBPAYMENT], LP_eth_client) < 0) {
        printf("Bob payment %s is not found, can't reclaim\n", swap->eth_tx_ids[BASILISK_BOBPAYMENT]);
        return NULL;
    }
    BobReclaimsBobPaymentInput input;
    memset(&input,0,sizeof(input));

    struct iguana_info *bobcoin = LP_coinfind(swap->src);

    EthTxReceipt receipt = get_eth_tx_receipt(swap->eth_tx_ids[BASILISK_BOBPAYMENT], LP_eth_client);
    if (receipt.status != 1) {
        printf("Bob payment receipt status failed, can't reclaim\n");
        return NULL;
    }

    uint8arrayToHex(input.payment_id, swap->txids[BASILISK_BOBPAYMENT].bytes, 32);
    if (bob_payment_status(input.payment_id, LP_eth_client) != BOB_PAYMENT_SENT) {
        printf("Bob payment smart contract status check failed, can't spend\n");
        return NULL;
    }
    strcpy(input.alice_address, swap->etomicdest);
    uint8arrayToHex(input.alice_hash, swap->secretAm, 20);

    if (swap->bobtomic[0] != 0) {
        strcpy(input.token_address, swap->bobtomic);
    } else {
        strcpy(input.token_address, "0x0000000000000000000000000000000000000000");
    }
    input.amount = swap->bobrealsat;
    input.decimals = bobcoin->decimals;

    return bob_reclaims_bob_payment(input, LP_eth_client);
}

char *LP_etomicalice_spends_bob_payment(struct LP_swap_remember *swap)
{
    if (wait_for_confirmation(swap->eth_tx_ids[BASILISK_BOBPAYMENT], LP_eth_client) < 0) {
        printf("Bob payment %s is not found, can't spend\n", swap->eth_tx_ids[BASILISK_BOBPAYMENT]);
        return NULL;
    }
    AliceSpendsBobPaymentInput input;

    memset(&input,0,sizeof(input));
    EthTxReceipt receipt = get_eth_tx_receipt(swap->eth_tx_ids[BASILISK_BOBPAYMENT], LP_eth_client);
    if (receipt.status != 1) {
        printf("Bob payment %s receipt status failed, can't spend\n", swap->eth_tx_ids[BASILISK_BOBPAYMENT]);
        return NULL;
    }
    struct iguana_info *bobcoin = LP_coinfind(swap->src);

    uint8arrayToHex(input.payment_id, swap->txids[BASILISK_BOBPAYMENT].bytes, 32);
    if (bob_payment_status(input.payment_id, LP_eth_client) != BOB_PAYMENT_SENT) {
        printf("Bob payment smart contract status check failed, can't spend\n");
        return NULL;
    }

    input.amount = swap->bobrealsat;

    if (swap->bobtomic[0] != 0) {
        strcpy(input.token_address, swap->bobtomic);
    } else {
        strcpy(input.token_address, "0x0000000000000000000000000000000000000000");
    }

    strcpy(input.bob_address, swap->etomicsrc);
    bits256 invertedSecret; int32_t i;

    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privAm.bytes[31 - i];
    }
    uint8arrayToHex(input.alice_secret, invertedSecret.bytes, 32);
    input.decimals = bobcoin->decimals;

    return alice_spends_bob_payment(input, LP_eth_client);
}

char *LP_etomicalice_claims_bob_deposit(struct LP_swap_remember *swap)
{
    if (wait_for_confirmation(swap->eth_tx_ids[BASILISK_BOBDEPOSIT], LP_eth_client) < 0) {
        printf("Bob deposit %s is not found, can't claim\n", swap->eth_tx_ids[BASILISK_BOBDEPOSIT]);
        return NULL;
    }
    AliceClaimsBobDepositInput input;

    memset(&input,0,sizeof(input));
    EthTxReceipt receipt = get_eth_tx_receipt(swap->eth_tx_ids[BASILISK_BOBDEPOSIT], LP_eth_client);
    if (receipt.status != 1) {
        printf("Bob deposit receipt status failed, can't claim\n");
        return NULL;
    }

    struct iguana_info *bobcoin = LP_coinfind(swap->src);

    uint8arrayToHex(input.deposit_id, swap->txids[BASILISK_BOBDEPOSIT].bytes, 32);

    if (bob_deposit_status(input.deposit_id, LP_eth_client) != BOB_DEPOSIT_SENT) {
        printf("Bob deposit smart contract status check failed, can't claim\n");
        return NULL;
    }

    input.amount = LP_DEPOSITSATOSHIS(swap->bobrealsat);

    if (swap->bobtomic[0] != 0) {
        strcpy(input.token_address, swap->bobtomic);
    } else {
        strcpy(input.token_address, "0x0000000000000000000000000000000000000000");
    }

    strcpy(input.bob_address, swap->etomicsrc);
    uint8arrayToHex(input.bob_hash, swap->secretBn, 20);

    bits256 invertedSecret; int32_t i;

    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privAm.bytes[31 - i];
    }
    uint8arrayToHex(input.alice_secret, invertedSecret.bytes, 32);

    input.decimals = bobcoin->decimals;

    return alice_claims_bob_deposit(input, LP_eth_client);
}

char *sendEthTx(struct basilisk_swap *swap, struct basilisk_rawtx *rawtx)
{
    if (rawtx == &swap->alicepayment && swap->I.alicetomic[0] != 0) {
        return LP_etomicalice_send_payment(swap);
    } else if (rawtx == &swap->bobdeposit && swap->I.bobtomic[0] != 0) {
        return LP_etomicbob_sends_deposit(swap);
    } else if (rawtx == &swap->bobpayment && swap->I.bobtomic[0] != 0) {
        return LP_etomicbob_sends_payment(swap);
    } else if (swap->I.iambob == 0 && rawtx == &swap->myfee && swap->I.alicetomic[0] != 0) {
        return LP_etomicalice_send_fee(swap);
    } else {
        char *result = malloc(67);
        strcpy(result, EMPTY_ETH_TX_ID);
        return result;
    }
}

int32_t LP_etomic_priv2addr(char *coinaddr,bits256 privkey)
{
    char str[65],*addrstr;
    bits256_str(str,privkey);
    if ( (addrstr= priv_key_2_addr(str)) != 0 )
    {
        strcpy(coinaddr,addrstr);
        free(addrstr);
        return(0);
    }
    return(-1);
}

int32_t LP_etomic_priv2pub(uint8_t *pub64,bits256 privkey)
{
    char *pubstr,str[72]; int32_t retval = -1;
    bits256_str(str,privkey);
    if ( (pubstr= priv_key_2_pub_key(str)) != 0 )
    {
        if ( strlen(pubstr) == 128 )
        {
            decode_hex(pub64,64,pubstr);
            retval = 0;
        }
        free(pubstr);
    }
    return(retval);
}

int32_t LP_etomic_pub2addr(char *coinaddr,uint8_t pub64[64])
{
    char pubkeystr[131],*addrstr;
    init_hexbytes_noT(pubkeystr,pub64,64);
    if ( (addrstr= pub_key_2_addr(pubkeystr)) != 0 )
    {
        strcpy(coinaddr,addrstr);
        free(addrstr);
        return(0);
    }
    return(-1);
}

uint8_t LP_etomic_is_empty_tx_id(char *txId)
{
    if (txId[0] == 0 || strcmp(txId, EMPTY_ETH_TX_ID) == 0) {
        return 1;
    }
    return 0;
}

uint64_t LP_etomic_get_balance(struct iguana_info *coin, char *coinaddr, int *error)
{
    if (coin->etomic[0] == 0) {
        printf("Trying to get etomic balance for non-etomic coin %s!", coin->symbol);
        return 0;
    }

    if (strcmp(coin->symbol, "ETH") == 0) {
        return get_eth_balance(coinaddr, error, LP_eth_client);
    } else {
        return get_erc20_balance(coinaddr, coin->etomic, coin->decimals, error, LP_eth_client);
    }
}


void uint8arrayToHex(char *dest, uint8_t *input, int len)
{
    strcpy(dest, "0x");
    for (int i = 0; i < len; i++)
    {
        sprintf(dest + (i + 1) * 2, "%02x", input[i]);
    }
    dest[(len + 1) * 2] = '\0';
}

void satoshisToWei(char *dest, uint64_t input)
{
    sprintf(dest, "%" PRIu64, input);
    strcat(dest, "0000000000");
}
