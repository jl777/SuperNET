
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

int32_t LP_etomic_wait_for_confirmation(char *txId)
{
    return(waitForConfirmation(txId));
}

void LP_etomic_pubkeystr_to_addr(char *pubkey, char *output)
{
    char *address = pubKey2Addr(pubkey);
    strcpy(output, address);
    free(address);
}

char *LP_etomicalice_send_fee(struct basilisk_swap *swap)
{
    char amount[100], secretKey[70], dexaddr[50];
    satoshisToWei(amount, LP_DEXFEE(swap->I.alicerealsat));
    swap->myfee.I.eth_amount = LP_DEXFEE(swap->I.alicerealsat);
    uint8arrayToHex(secretKey, swap->persistent_privkey.bytes, 32);
    LP_etomic_pubkeystr_to_addr(INSTANTDEX_PUBKEY, dexaddr);
    if (strcmp(swap->I.alicestr,"ETH") == 0 ) {
        return(sendEth(dexaddr, amount, secretKey, 1, 0, 0, 1));
    } else {
        struct iguana_info *alicecoin = LP_coinfind(swap->I.alicestr);

        return(sendErc20(swap->I.alicetomic, dexaddr, amount, secretKey, 1, 0, 0, 1, alicecoin->decimals));
    }
}

uint8_t LP_etomic_verify_alice_fee(struct basilisk_swap *swap)
{
    if (waitForConfirmation(swap->otherfee.I.ethTxid) < 0) {
        printf("Alice fee tx %s does not exist", swap->otherfee.I.ethTxid);
        return(0);
    }
    EthTxData data = getEthTxData(swap->otherfee.I.ethTxid);
    if (compareAddresses(data.from, swap->I.etomicdest) == 0) {
        printf("Alice fee tx %s was sent from wrong address %s\n", swap->otherfee.I.ethTxid, data.from);
        return(0);
    }

    char dexaddr[50];
    LP_etomic_pubkeystr_to_addr(INSTANTDEX_PUBKEY, dexaddr);
    if ( strcmp(swap->I.alicestr,"ETH") == 0 ) {
        if (compareAddresses(data.to, dexaddr) == 0) {
            printf("Alice fee %s was sent to wrong address %s\n", swap->otherfee.I.ethTxid, data.to);
            return(0);
        }
        uint64_t txValue = weiToSatoshi(data.valueHex);
        if (txValue != LP_DEXFEE(swap->I.alicerealsat)) {
            printf("Alice fee %s amount %" PRIu64 " is not equal to expected %" PRId64 "\n", swap->otherfee.I.ethTxid, txValue, LP_DEXFEE(swap->I.alicerealsat));
            return(0);
        }
        return(1);
    } else {
        struct iguana_info *alicecoin = LP_coinfind(swap->I.alicestr);

        if (compareAddresses(data.to, swap->I.alicetomic) == 0) {
            printf("Alice ERC20 fee %s token address %s is not equal to expected %s\n", swap->otherfee.I.ethTxid, data.to, swap->I.alicetomic);
            return(0);
        }
        char weiAmount[70];
        satoshisToWei(weiAmount, LP_DEXFEE(swap->I.alicerealsat));
        return(verifyAliceErc20FeeData(swap->I.alicetomic, dexaddr, weiAmount, data.input, alicecoin->decimals));
    }
}

char *LP_etomicalice_send_payment(struct basilisk_swap *swap)
{
    AliceSendsEthPaymentInput input; AliceSendsErc20PaymentInput input20; BasicTxData txData;
    swap->alicepayment.I.eth_amount = swap->I.alicerealsat;
    // set input and txData fields from the swap data structure
    memset(&txData,0,sizeof(txData));
    if ( strcmp(swap->I.alicestr,"ETH") == 0 )
    {
        memset(&input,0,sizeof(input));
        strcpy(input.bobAddress, swap->I.etomicsrc);
        uint8arrayToHex(input.bobHash, swap->I.secretBn, 20);
        uint8arrayToHex(input.aliceHash, swap->I.secretAm, 20);
        uint8arrayToHex(input.dealId, swap->alicepayment.I.actualtxid.bytes, 32);

        strcpy(txData.from, swap->I.etomicdest);
        strcpy(txData.to, ETOMIC_ALICECONTRACT);
        satoshisToWei(txData.amount, swap->I.alicerealsat);
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);

        return(aliceSendsEthPayment(input,txData));
    }
    else
    {
        struct iguana_info *alicecoin = LP_coinfind(swap->I.alicestr);

        memset(&input20,0,sizeof(input20));
        strcpy(input20.bobAddress, swap->I.etomicsrc);
        uint8arrayToHex(input20.bobHash, swap->I.secretBn, 20);
        uint8arrayToHex(input20.aliceHash, swap->I.secretAm, 20);
        uint8arrayToHex(input20.dealId, swap->alicepayment.I.actualtxid.bytes, 32);
        strcpy(input20.tokenAddress, swap->I.alicetomic);
        satoshisToWei(input20.amount, swap->I.alicerealsat);
        input20.decimals = alicecoin->decimals;

        strcpy(txData.from, swap->I.etomicdest);
        strcpy(txData.to, ETOMIC_ALICECONTRACT);
        strcpy(txData.amount, "0");
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);

        uint64_t allowance = getErc20Allowance(swap->I.etomicdest, ETOMIC_ALICECONTRACT, swap->I.alicetomic, alicecoin->decimals);
        if (allowance < swap->I.alicerealsat) {
            printf("Alice token allowance is too low, setting new allowance\n");
            ApproveErc20Input approveErc20Input;
            strcpy(approveErc20Input.tokenAddress, swap->I.alicetomic);
            strcpy(approveErc20Input.owner, swap->I.etomicdest);
            strcpy(approveErc20Input.spender, ETOMIC_ALICECONTRACT);

            char *tokenBalance = getErc20BalanceHexWei(swap->I.etomicdest, swap->I.alicetomic);
            strcpy(approveErc20Input.amount, tokenBalance);
            free(tokenBalance);
            strcpy(approveErc20Input.secret, txData.secretKey);

            char *allowTxId = approveErc20(approveErc20Input);
            LP_etomic_wait_for_confirmation(allowTxId);
            free(allowTxId);
        }

        return(aliceSendsErc20Payment(input20,txData));
    }
}

uint8_t LP_etomic_verify_alice_payment(struct basilisk_swap *swap, char *txId)
{
    if (waitForConfirmation(txId) < 0) {
        printf("Alice payment %s does not exist\n", txId);
        return(0);
    }
    EthTxData data = getEthTxData(txId);
    if (compareAddresses(data.to, ETOMIC_ALICECONTRACT) == 0) {
        printf("Alice payment %s was sent to wrong address %s\n", txId, data.to);
        return(0);
    }
    if (compareAddresses(data.from, swap->I.etomicdest) == 0) {
        printf("Alice payment %s was done from wrong address %s\n", txId, data.from);
        return(0);
    }
    AliceSendsEthPaymentInput input; AliceSendsErc20PaymentInput input20;
    if ( strcmp(swap->I.alicestr,"ETH") == 0 ) {
        uint64_t paymentAmount = weiToSatoshi(data.valueHex);
        if (paymentAmount != swap->I.alicerealsat) {
            printf("Alice payment amount %" PRIu64 " does not match expected %" PRIu64 "\n", paymentAmount, swap->I.alicerealsat);
            return(0);
        }
        memset(&input,0,sizeof(input));
        strcpy(input.bobAddress, swap->I.etomicsrc);
        uint8arrayToHex(input.bobHash, swap->I.secretBn, 20);
        uint8arrayToHex(input.aliceHash, swap->I.secretAm, 20);
        uint8arrayToHex(input.dealId, swap->alicepayment.I.actualtxid.bytes, 32);

        return(verifyAliceEthPaymentData(input, data.input));
    } else {
        struct iguana_info *alicecoin = LP_coinfind(swap->I.alicestr);

        memset(&input20,0,sizeof(input20));
        strcpy(input20.bobAddress, swap->I.etomicsrc);
        uint8arrayToHex(input20.bobHash, swap->I.secretBn, 20);
        uint8arrayToHex(input20.aliceHash, swap->I.secretAm, 20);
        uint8arrayToHex(input20.dealId, swap->alicepayment.I.actualtxid.bytes, 32);
        strcpy(input20.tokenAddress, swap->I.alicetomic);
        satoshisToWei(input20.amount, swap->I.alicerealsat);
        input20.decimals = alicecoin->decimals;

        return(verifyAliceErc20PaymentData(input20, data.input));
    }
}

char *LP_etomicalice_reclaims_payment(struct LP_swap_remember *swap)
{
    if (waitForConfirmation(swap->eth_tx_ids[BASILISK_ALICEPAYMENT]) < 0) {
        printf("Alice ETH payment %s is not found, can't reclaim\n", swap->eth_tx_ids[BASILISK_ALICEPAYMENT]);
        return NULL;
    }
    EthTxReceipt receipt = getEthTxReceipt(swap->eth_tx_ids[BASILISK_ALICEPAYMENT]);
    if (strcmp(receipt.status, "0x1") != 0) {
        printf("Alice payment receipt status failed, can't reclaim\n");
        return NULL;
    }
    AliceReclaimsAlicePaymentInput input;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    struct iguana_info *ecoin, *alice_coin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    alice_coin = LP_coinfind(swap->dest);
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    uint8arrayToHex(input.dealId, swap->txids[BASILISK_ALICEPAYMENT].bytes, 32);
    if (alicePaymentStatus(input.dealId + 2) != ALICE_PAYMENT_SENT) {
        printf("Alice payment smart contract status check failed, can't spend\n");
        return NULL;
    }
    satoshisToWei(input.amount, swap->alicerealsat);

    if (swap->alicetomic[0] != 0) {
        strcpy(input.tokenAddress, swap->alicetomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }
    strcpy(input.bobAddress, swap->etomicsrc);
    uint8arrayToHex(input.aliceHash, swap->secretAm, 20);
    bits256 invertedSecret;
    int32_t i;
    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privBn.bytes[31 - i];
    }
    uint8arrayToHex(input.bobSecret, invertedSecret.bytes, 32);

    input.decimals = alice_coin->decimals;

    strcpy(txData.from, swap->etomicdest);
    strcpy(txData.to, ETOMIC_ALICECONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, privkey.bytes, 32);
    return aliceReclaimsAlicePayment(input, txData);
}

char *LP_etomicbob_spends_alice_payment(struct LP_swap_remember *swap)
{
    if (waitForConfirmation(swap->eth_tx_ids[BASILISK_ALICEPAYMENT]) < 0) {
        printf("Alice ETH payment %s is not found, can't spend\n", swap->eth_tx_ids[BASILISK_ALICEPAYMENT]);
        return NULL;
    }
    EthTxReceipt receipt = getEthTxReceipt(swap->eth_tx_ids[BASILISK_ALICEPAYMENT]);
    if (strcmp(receipt.status, "0x1") != 0) {
        printf("Alice payment receipt status failed, can't spend\n");
        return NULL;
    }
    BobSpendsAlicePaymentInput input;
    BasicTxData txData;

    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    struct iguana_info *ecoin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    uint8arrayToHex(input.dealId, swap->txids[BASILISK_ALICEPAYMENT].bytes, 32);
    if (alicePaymentStatus(input.dealId + 2) != ALICE_PAYMENT_SENT) {
        printf("Alice payment smart contract status check failed, can't spend\n");
        return NULL;
    }

    satoshisToWei(input.amount, swap->alicerealsat);

    if (swap->alicetomic[0] != 0) {
        strcpy(input.tokenAddress, swap->alicetomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }

    strcpy(input.aliceAddress, swap->etomicdest);
    bits256 invertedSecret; int32_t i;
    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privAm.bytes[31 - i];
    }
    uint8arrayToHex(input.aliceSecret, invertedSecret.bytes, 32);
    uint8arrayToHex(input.bobHash, swap->secretBn, 20);
    struct iguana_info *alice_coin = LP_coinfind(swap->dest);
    input.decimals = alice_coin->decimals;

    strcpy(txData.from, swap->etomicsrc);
    strcpy(txData.to, ETOMIC_ALICECONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, privkey.bytes, 32);
    return bobSpendsAlicePayment(input, txData);
}

char *LP_etomicbob_sends_deposit(struct basilisk_swap *swap)
{
    BobSendsEthDepositInput input;
    BobSendsErc20DepositInput input20;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));
    memset(&input20,0,sizeof(input20));
    if ( strcmp(swap->I.bobstr,"ETH") == 0 ) {
        uint8arrayToHex(input.depositId, swap->bobdeposit.I.actualtxid.bytes, 32);
        strcpy(input.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input.bobHash, swap->I.secretBn, 20);
        input.lockTime = swap->bobdeposit.I.locktime;

        strcpy(txData.from, swap->I.etomicsrc);
        strcpy(txData.to, ETOMIC_BOBCONTRACT);
        satoshisToWei(txData.amount, LP_DEPOSITSATOSHIS(swap->I.bobrealsat));
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);
        return bobSendsEthDeposit(input, txData);
    } else {
        struct iguana_info *bobcoin = LP_coinfind(swap->I.bobstr);

        uint8arrayToHex(input20.depositId, swap->bobdeposit.I.actualtxid.bytes, 32);
        strcpy(input20.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input20.bobHash, swap->I.secretBn, 20);
        satoshisToWei(input20.amount, LP_DEPOSITSATOSHIS(swap->I.bobrealsat));
        strcpy(input20.tokenAddress, swap->I.bobtomic);
        input20.lockTime = swap->bobdeposit.I.locktime;
        input20.decimals = bobcoin->decimals;

        strcpy(txData.from, swap->I.etomicsrc);
        strcpy(txData.to, ETOMIC_BOBCONTRACT);
        strcpy(txData.amount, "0");
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);

        uint64_t allowance = getErc20Allowance(swap->I.etomicsrc, ETOMIC_BOBCONTRACT, swap->I.bobtomic, bobcoin->decimals);
        if (allowance < LP_DEPOSITSATOSHIS(swap->I.bobrealsat)) {
            printf("Bob token allowance is too low, setting new allowance\n");
            ApproveErc20Input approveErc20Input;
            strcpy(approveErc20Input.tokenAddress, swap->I.bobtomic);
            strcpy(approveErc20Input.owner, swap->I.etomicsrc);
            strcpy(approveErc20Input.spender, ETOMIC_BOBCONTRACT);

            char *tokenBalance = getErc20BalanceHexWei(swap->I.etomicsrc, swap->I.bobtomic);
            strcpy(approveErc20Input.amount, tokenBalance);
            free(tokenBalance);
            strcpy(approveErc20Input.secret, txData.secretKey);

            char *allowTxId = approveErc20(approveErc20Input);
            LP_etomic_wait_for_confirmation(allowTxId);
            free(allowTxId);
        }

        return bobSendsErc20Deposit(input20, txData);
    }
}

uint8_t LP_etomic_verify_bob_deposit(struct basilisk_swap *swap, char *txId)
{
    if (waitForConfirmation(txId) < 0) {
        printf("Bob deposit txid %s does not exist\n", txId);
        return(0);
    }
    EthTxData data = getEthTxData(txId);
    if (compareAddresses(data.to, ETOMIC_BOBCONTRACT) == 0) {
        printf("Bob deposit txid %s was sent to wrong address %s\n", txId, data.to);
        return(0);
    }
    if (compareAddresses(data.from, swap->I.etomicsrc) == 0) {
        printf("Bob deposit txid %s was sent from wrong address %s\n", txId, data.from);
        return(0);
    }
    BobSendsEthDepositInput input;
    BobSendsErc20DepositInput input20;
    memset(&input,0,sizeof(input));
    memset(&input20,0,sizeof(input20));
    if ( strcmp(swap->I.bobstr,"ETH") == 0 ) {
        uint64_t depositAmount = weiToSatoshi(data.valueHex);
        if (depositAmount != LP_DEPOSITSATOSHIS(swap->I.bobrealsat)) {
            printf("Bob deposit %s amount %" PRIu64 " != expected %" PRIu64 "\n", txId, depositAmount, LP_DEPOSITSATOSHIS(swap->I.bobrealsat));
            return(0);
        }
        uint8arrayToHex(input.depositId, swap->bobdeposit.I.actualtxid.bytes, 32);
        strcpy(input.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input.bobHash, swap->I.secretBn, 20);
        input.lockTime = swap->bobdeposit.I.locktime;

        return verifyBobEthDepositData(input, data.input);
    } else {
        struct iguana_info *bobcoin = LP_coinfind(swap->I.bobstr);

        uint8arrayToHex(input20.depositId, swap->bobdeposit.I.actualtxid.bytes, 32);
        strcpy(input20.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input20.bobHash, swap->I.secretBn, 20);
        satoshisToWei(input20.amount, LP_DEPOSITSATOSHIS(swap->I.bobrealsat));
        strcpy(input20.tokenAddress, swap->I.bobtomic);
        input20.lockTime = swap->bobdeposit.I.locktime;
        input20.decimals = bobcoin->decimals;

        return verifyBobErc20DepositData(input20, data.input);
    }
}

char *LP_etomicbob_refunds_deposit(struct LP_swap_remember *swap)
{
    if (waitForConfirmation(swap->eth_tx_ids[BASILISK_BOBDEPOSIT]) < 0) {
        printf("Bob deposit %s is not found, can't refund\n", swap->eth_tx_ids[BASILISK_BOBDEPOSIT]);
        return NULL;
    }
    BobRefundsDepositInput input;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    struct iguana_info *ecoin, *bobcoin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    bobcoin = LP_coinfind(swap->src);
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    EthTxReceipt receipt = getEthTxReceipt(swap->eth_tx_ids[BASILISK_BOBDEPOSIT]);
    if (strcmp(receipt.status, "0x1") != 0) {
        printf("Bob deposit %s receipt status failed, can't refund\n", swap->eth_tx_ids[BASILISK_BOBDEPOSIT]);
        return NULL;
    }
    uint8arrayToHex(input.depositId, swap->txids[BASILISK_BOBDEPOSIT].bytes, 32);
    if (bobDepositStatus(input.depositId + 2) != BOB_DEPOSIT_SENT) {
        printf("Bob deposit smart contract status check failed, can't claim\n");
        return NULL;
    }

    strcpy(input.aliceAddress, swap->etomicdest);

    bits256 invertedSecret;
    int32_t i;
    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privBn.bytes[31 - i];
    }
    uint8arrayToHex(input.bobSecret, invertedSecret.bytes, 32);

    if (swap->bobtomic[0] != 0) {
        strcpy(input.tokenAddress, swap->bobtomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }
    satoshisToWei(input.amount, LP_DEPOSITSATOSHIS(swap->bobrealsat));
    input.decimals = bobcoin->decimals;

    strcpy(txData.from, swap->etomicsrc);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, privkey.bytes, 32);
    return bobRefundsDeposit(input, txData);
}

char *LP_etomicbob_sends_payment(struct basilisk_swap *swap)
{
    BobSendsEthPaymentInput input;
    BobSendsErc20PaymentInput input20;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));
    memset(&input20,0,sizeof(input20));

    if ( strcmp(swap->I.bobstr,"ETH") == 0 ) {
        uint8arrayToHex(input.paymentId, swap->bobpayment.I.actualtxid.bytes, 32);
        strcpy(input.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input.aliceHash, swap->I.secretAm, 20);
        input.lockTime = swap->bobpayment.I.locktime;

        strcpy(txData.from, swap->I.etomicsrc);
        strcpy(txData.to, ETOMIC_BOBCONTRACT);
        satoshisToWei(txData.amount, swap->I.bobrealsat);
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);
        return bobSendsEthPayment(input, txData);
    } else {
        struct iguana_info *bobcoin = LP_coinfind(swap->I.bobstr);

        uint8arrayToHex(input20.paymentId, swap->bobpayment.I.actualtxid.bytes, 32);
        strcpy(input20.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input20.aliceHash, swap->I.secretAm, 20);
        satoshisToWei(input20.amount, swap->I.bobrealsat);
        strcpy(input20.tokenAddress, swap->I.bobtomic);
        input20.lockTime = swap->bobpayment.I.locktime;
        input20.decimals = bobcoin->decimals;

        strcpy(txData.from, swap->I.etomicsrc);
        strcpy(txData.to, ETOMIC_BOBCONTRACT);
        strcpy(txData.amount, "0");
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);

        uint64_t allowance = getErc20Allowance(swap->I.etomicsrc, ETOMIC_BOBCONTRACT, swap->I.bobtomic, bobcoin->decimals);
        if (allowance < swap->I.bobrealsat) {
            printf("Bob token allowance is too low, setting new allowance\n");
            ApproveErc20Input approveErc20Input;
            strcpy(approveErc20Input.tokenAddress, swap->I.bobtomic);
            strcpy(approveErc20Input.owner, swap->I.etomicsrc);
            strcpy(approveErc20Input.spender, ETOMIC_BOBCONTRACT);

            char *tokenBalance = getErc20BalanceHexWei(swap->I.etomicsrc, swap->I.bobtomic);
            strcpy(approveErc20Input.amount, tokenBalance);
            free(tokenBalance);
            strcpy(approveErc20Input.secret, txData.secretKey);

            char *allowTxId = approveErc20(approveErc20Input);
            LP_etomic_wait_for_confirmation(allowTxId);
            free(allowTxId);
        }

        return bobSendsErc20Payment(input20, txData);
    }
}

uint8_t LP_etomic_verify_bob_payment(struct basilisk_swap *swap, char *txId)
{
    if (waitForConfirmation(txId) < 0) {
        printf("Bob payment %s is not found\n", txId);
        return 0;
    }
    EthTxData data = getEthTxData(txId);
    if (compareAddresses(data.to, ETOMIC_BOBCONTRACT) == 0) {
        printf("Bob payment %s was sent to wrong address %s\n", txId, data.to);
    }
    if (compareAddresses(data.from, swap->I.etomicsrc) == 0) {
        printf("Bob payment %s was sent from wrong address %s\n", txId, data.from);
    }
    BobSendsEthPaymentInput input;
    BobSendsErc20PaymentInput input20;
    memset(&input,0,sizeof(input));
    memset(&input20,0,sizeof(input20));
    if ( strcmp(swap->I.bobstr,"ETH") == 0 ) {
        uint64_t paymentAmount = weiToSatoshi(data.valueHex);
        if (paymentAmount != swap->I.bobrealsat) {
            printf("Bob payment %s amount %" PRIu64 " != expected %" PRIu64 "\n", txId, paymentAmount, swap->I.bobrealsat);
            return(0);
        }
        uint8arrayToHex(input.paymentId, swap->bobpayment.I.actualtxid.bytes, 32);
        strcpy(input.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input.aliceHash, swap->I.secretAm, 20);
        input.lockTime = swap->bobpayment.I.locktime;

        return verifyBobEthPaymentData(input, data.input);
    } else {
        struct iguana_info *bobcoin = LP_coinfind(swap->I.bobstr);

        uint8arrayToHex(input20.paymentId, swap->bobpayment.I.actualtxid.bytes, 32);
        strcpy(input20.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input20.aliceHash, swap->I.secretAm, 20);
        satoshisToWei(input20.amount, swap->I.bobrealsat);
        strcpy(input20.tokenAddress, swap->I.bobtomic);
        input20.lockTime = swap->bobpayment.I.locktime;
        input20.decimals = bobcoin->decimals;

        return verifyBobErc20PaymentData(input20, data.input);
    }
}

char *LP_etomicbob_reclaims_payment(struct LP_swap_remember *swap)
{
    if (waitForConfirmation(swap->eth_tx_ids[BASILISK_BOBPAYMENT]) < 0) {
        printf("Bob payment %s is not found, can't reclaim\n", swap->eth_tx_ids[BASILISK_BOBPAYMENT]);
        return NULL;
    }
    BobReclaimsBobPaymentInput input;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    struct iguana_info *ecoin, *bobcoin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    bobcoin = LP_coinfind(swap->src);
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    EthTxReceipt receipt = getEthTxReceipt(swap->eth_tx_ids[BASILISK_BOBPAYMENT]);
    if (strcmp(receipt.status, "0x1") != 0) {
        printf("Bob payment receipt status failed, can't reclaim\n");
        return NULL;
    }
    uint8arrayToHex(input.paymentId, swap->txids[BASILISK_BOBPAYMENT].bytes, 32);
    if (bobPaymentStatus(input.paymentId + 2) != BOB_PAYMENT_SENT) {
        printf("Bob payment smart contract status check failed, can't spend\n");
        return NULL;
    }
    strcpy(input.aliceAddress, swap->etomicdest);
    uint8arrayToHex(input.aliceHash, swap->secretAm, 20);

    if (swap->bobtomic[0] != 0) {
        strcpy(input.tokenAddress, swap->bobtomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }
    satoshisToWei(input.amount, swap->bobrealsat);
    input.decimals = bobcoin->decimals;

    strcpy(txData.from, swap->etomicsrc);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, privkey.bytes, 32);
    return bobReclaimsBobPayment(input, txData);
}

char *LP_etomicalice_spends_bob_payment(struct LP_swap_remember *swap)
{
    if (waitForConfirmation(swap->eth_tx_ids[BASILISK_BOBPAYMENT]) < 0) {
        printf("Bob payment %s is not found, can't spend\n", swap->eth_tx_ids[BASILISK_BOBPAYMENT]);
        return NULL;
    }
    AliceSpendsBobPaymentInput input;
    BasicTxData txData;

    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));
    EthTxReceipt receipt = getEthTxReceipt(swap->eth_tx_ids[BASILISK_BOBPAYMENT]);
    if (strcmp(receipt.status, "0x1") != 0) {
        printf("Bob payment %s receipt status failed, can't spend\n", swap->eth_tx_ids[BASILISK_BOBPAYMENT]);
        return NULL;
    }
    struct iguana_info *ecoin, *bobcoin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    bobcoin = LP_coinfind(swap->src);
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    uint8arrayToHex(input.paymentId, swap->txids[BASILISK_BOBPAYMENT].bytes, 32);
    if (bobPaymentStatus(input.paymentId + 2) != BOB_PAYMENT_SENT) {
        printf("Bob payment smart contract status check failed, can't spend\n");
        return NULL;
    }
    satoshisToWei(input.amount, swap->bobrealsat);

    if (swap->bobtomic[0] != 0) {
        strcpy(input.tokenAddress, swap->bobtomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }

    strcpy(input.bobAddress, swap->etomicsrc);
    bits256 invertedSecret; int32_t i;

    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privAm.bytes[31 - i];
    }
    uint8arrayToHex(input.aliceSecret, invertedSecret.bytes, 32);
    input.decimals = bobcoin->decimals;

    strcpy(txData.from, swap->etomicdest);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, privkey.bytes, 32);
    return aliceSpendsBobPayment(input, txData);
}

char *LP_etomicalice_claims_bob_deposit(struct LP_swap_remember *swap)
{
    if (waitForConfirmation(swap->eth_tx_ids[BASILISK_BOBDEPOSIT]) < 0) {
        printf("Bob deposit %s is not found, can't claim\n", swap->eth_tx_ids[BASILISK_BOBDEPOSIT]);
        return NULL;
    }
    AliceClaimsBobDepositInput input;
    BasicTxData txData;

    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));
    EthTxReceipt receipt = getEthTxReceipt(swap->eth_tx_ids[BASILISK_BOBDEPOSIT]);
    if (strcmp(receipt.status, "0x1") != 0) {
        printf("Bob deposit receipt status failed, can't claim\n");
        return NULL;
    }

    struct iguana_info *ecoin, *bobcoin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    bobcoin = LP_coinfind(swap->src);
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    uint8arrayToHex(input.depositId, swap->txids[BASILISK_BOBDEPOSIT].bytes, 32);
    if (bobDepositStatus(input.depositId + 2) != BOB_DEPOSIT_SENT) {
        printf("Bob deposit smart contract status check failed, can't claim\n");
        return NULL;
    }

    satoshisToWei(input.amount, LP_DEPOSITSATOSHIS(swap->bobrealsat));

    if (swap->bobtomic[0] != 0) {
        strcpy(input.tokenAddress, swap->bobtomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }

    strcpy(input.bobAddress, swap->etomicsrc);
    uint8arrayToHex(input.bobHash, swap->secretBn, 20);
    input.decimals = bobcoin->decimals;

    strcpy(txData.from, swap->etomicdest);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, privkey.bytes, 32);
    return aliceClaimsBobDeposit(input, txData);
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
    if ( (addrstr= privKey2Addr(str)) != 0 )
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
    if ( (pubstr= getPubKeyFromPriv(str)) != 0 )
    {
        if ( strlen(pubstr) == 130 && pubstr[0] == '0' && pubstr[1] == 'x' )
        {
            decode_hex(pub64,64,pubstr+2);
            retval = 0;
        }
        free(pubstr);
    }
    return(retval);
}

int32_t LP_etomic_pub2addr(char *coinaddr,uint8_t pub64[64])
{
    char pubkeystr[131],*addrstr;
    strcpy(pubkeystr,"0x");
    init_hexbytes_noT(pubkeystr+2,pub64,64);
    if ( (addrstr= pubKey2Addr(pubkeystr)) != 0 )
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
        return getEthBalance(coinaddr, error);
    } else {
        return getErc20BalanceSatoshi(coinaddr, coin->etomic, coin->decimals, error);
    }
}
