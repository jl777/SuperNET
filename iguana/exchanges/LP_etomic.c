
/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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
#include "etomicswap/etomiclib.h"
#include "etomicswap/etomiccurl.h"
#include <inttypes.h>

#define ETOMIC_ALICECONTRACT "0xe1D4236C5774D35Dc47dcc2E5E0CcFc463A3289c"
#define ETOMIC_BOBCONTRACT "0x9387Fd3a016bB0205e4e131Dde886B9d2BC000A2"
#define ETOMIC_SATOSHICAT "0000000000"

int32_t LP_etomicsymbol(char *activesymbol,char *etomic,char *symbol)
{
    struct iguana_info *coin;
    etomic[0] = activesymbol[0] = 0;
    if ( (coin= LP_coinfind(symbol)) != 0 )
    {
        strcpy(etomic,coin->etomic);
        if ( etomic[0] != 0 )
            strcpy(activesymbol,"ETOMIC");
        else strcpy(activesymbol,symbol);
    }
    return(etomic[0] != 0);
}

char *LP_etomicalice_send_payment(struct basilisk_swap *swap)
{
    AliceSendsEthPaymentInput input; AliceSendsErc20PaymentInput input20; BasicTxData txData;
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
        satoshisToWei(txData.amount, swap->I.alicesatoshis);
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);

        return(aliceSendsEthPayment(input,txData));
    }
    else
    {
        memset(&input20,0,sizeof(input20));
        strcpy(input20.bobAddress, swap->I.etomicdest);
        uint8arrayToHex(input20.bobHash, swap->I.secretBn, 20);
        uint8arrayToHex(input20.aliceHash, swap->I.secretAm, 20);
        uint8arrayToHex(input20.dealId, swap->alicepayment.utxotxid.bytes, 32);
        strcpy(input20.tokenAddress, swap->I.alicetomic);
        satoshisToWei(input20.amount, swap->I.alicesatoshis);

        strcpy(txData.from, swap->I.etomicsrc);
        strcpy(txData.to, ETOMIC_ALICECONTRACT);
        strcpy(txData.amount, "0");
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);
        return(aliceSendsErc20Payment(input20,txData));
    }
}

char *LP_etomicalice_reclaims_payment(struct LP_swap_remember *swap)
{
    AliceReclaimsAlicePaymentInput input;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    uint8arrayToHex(input.dealId, swap->txids[BASILISK_ALICEPAYMENT].bytes, 32);
    satoshisToWei(input.amount, swap->values[BASILISK_ALICEPAYMENT]);

    if (swap->alicetomic[0] != 0) {
        strcpy(input.tokenAddress, swap->alicetomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }
    strcpy(input.bobAddress, swap->etomicdest);
    uint8arrayToHex(input.aliceHash, swap->secretAm, 20);
    bits256 invertedSecret;
    int32_t i;
    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privBn.bytes[31 - i];
    }
    uint8arrayToHex(input.bobSecret, invertedSecret.bytes, 32);

    strcpy(txData.from, swap->etomicsrc);
    strcpy(txData.to, ETOMIC_ALICECONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, swap->persistentPrivKey.bytes, 32);
    return aliceReclaimsAlicePayment(input, txData);
}

char *LP_etomicbob_spends_alice_payment(struct LP_swap_remember *swap)
{
    BobSpendsAlicePaymentInput input;
    BasicTxData txData;

    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    uint8arrayToHex(input.dealId, swap->txids[BASILISK_ALICEPAYMENT].bytes, 32);
    satoshisToWei(input.amount, swap->destamount);

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

    strcpy(txData.from, swap->etomicsrc);
    strcpy(txData.to, ETOMIC_ALICECONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, swap->persistentPrivKey.bytes, 32);
    return bobSpendsAlicePayment(input, txData);
}

char *LP_etomicbob_sends_deposit(struct basilisk_swap *swap)
{
    BobSendsEthDepositInput input;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    uint8arrayToHex(input.depositId, swap->bobdeposit.I.actualtxid.bytes, 32);
    strcpy(input.aliceAddress, swap->I.etomicdest);
    uint8arrayToHex(input.bobHash, swap->I.secretBn, 20);

    strcpy(txData.from, swap->I.etomicsrc);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    satoshisToWei(txData.amount, swap->bobdeposit.I.amount);
    uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);
    return bobSendsEthDeposit(input, txData);
}

char *LP_etomicbob_refunds_deposit(struct LP_swap_remember *swap)
{
    BobRefundsDepositInput input;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    EthTxReceipt receipt = getEthTxReceipt(swap->bobDepositEthTx);
    uint8arrayToHex(input.depositId, swap->txids[BASILISK_BOBDEPOSIT].bytes, 32);
    strcpy(input.aliceAddress, swap->etomicdest);
    sprintf(input.aliceCanClaimAfter, "%" PRIu64, receipt.blockNumber + 960);

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
    satoshisToWei(input.amount, swap->values[BASILISK_BOBDEPOSIT]);

    strcpy(txData.from, swap->etomicsrc);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, swap->persistentPrivKey.bytes, 32);
    return bobRefundsDeposit(input, txData);
}

char *LP_etomicbob_sends_payment(struct basilisk_swap *swap)
{
    BobSendsEthPaymentInput input;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    uint8arrayToHex(input.paymentId, swap->bobpayment.I.actualtxid.bytes, 32);
    strcpy(input.aliceAddress, swap->I.etomicdest);
    uint8arrayToHex(input.aliceHash, swap->I.secretAm, 20);

    strcpy(txData.from, swap->I.etomicsrc);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    satoshisToWei(txData.amount, swap->bobpayment.I.amount);
    uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);
    return bobSendsEthPayment(input, txData);
}

char *LP_etomicbob_reclaims_payment(struct LP_swap_remember *swap)
{
    BobReclaimsBobPaymentInput input;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    EthTxReceipt receipt = getEthTxReceipt(swap->bobPaymentEthTx);
    uint8arrayToHex(input.paymentId, swap->txids[BASILISK_BOBPAYMENT].bytes, 32);
    strcpy(input.aliceAddress, swap->etomicdest);
    sprintf(input.bobCanClaimAfter, "%" PRIu64, receipt.blockNumber + 480);
    uint8arrayToHex(input.aliceHash, swap->secretAm, 20);

    if (swap->bobtomic[0] != 0) {
        strcpy(input.tokenAddress, swap->bobtomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }
    satoshisToWei(input.amount, swap->values[BASILISK_BOBPAYMENT]);

    strcpy(txData.from, swap->etomicsrc);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, swap->persistentPrivKey.bytes, 32);
    return bobReclaimsBobPayment(input, txData);
}

char *LP_etomicalice_spends_bob_payment(struct LP_swap_remember *swap)
{
    AliceSpendsBobPaymentInput input;
    BasicTxData txData;

    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));
    EthTxReceipt receipt = getEthTxReceipt(swap->bobPaymentEthTx);

    uint8arrayToHex(input.paymentId, swap->txids[BASILISK_BOBPAYMENT].bytes, 32);
    satoshisToWei(input.amount, swap->values[BASILISK_BOBPAYMENT]);
    sprintf(input.bobCanClaimAfter, "%" PRIu64, receipt.blockNumber + 480);

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

    strcpy(txData.from, swap->etomicdest);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, swap->persistentPrivKey.bytes, 32);
    return aliceSpendsBobPayment(input, txData);
}

char *LP_etomicalice_claims_bob_deposit(struct LP_swap_remember *swap)
{
    AliceClaimsBobDepositInput input;
    BasicTxData txData;

    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));
    EthTxReceipt receipt = getEthTxReceipt(swap->bobDepositEthTx);

    uint8arrayToHex(input.depositId, swap->txids[BASILISK_BOBDEPOSIT].bytes, 32);
    satoshisToWei(input.amount, swap->values[BASILISK_BOBDEPOSIT]);
    sprintf(input.aliceCanClaimAfter, "%" PRIu64, receipt.blockNumber + 960);

    if (swap->bobtomic[0] != 0) {
        strcpy(input.tokenAddress, swap->bobtomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }

    strcpy(input.bobAddress, swap->etomicsrc);
    uint8arrayToHex(input.bobHash, swap->secretBn, 20);

    strcpy(txData.from, swap->etomicdest);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, swap->persistentPrivKey.bytes, 32);
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
    } else {
        char *result = malloc(67);
        strcpy(result, "0x0000000000000000000000000000000000000000000000000000000000000000");
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
