
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
        uint8arrayToHex(input.dealId, swap->alicepayment.utxotxid.bytes, 32);

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

char *LP_etomicalice_reclaims_payment(struct basilisk_swap *swap)
{
    AliceReclaimsAlicePaymentInput input;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));
    uint8arrayToHex(input.dealId, swap->alicepayment.utxotxid.bytes, 32);
    satoshisToWei(input.amount, swap->I.alicesatoshis);
    strcpy(input.tokenAddress, swap->I.alicetomic);
    strcpy(input.bobAddress, swap->I.etomicdest);
    uint8arrayToHex(input.aliceHash, swap->I.secretAm, 20);
    uint8arrayToHex(input.bobSecret, swap->I.secretBn256, 32);

    strcpy(txData.from, swap->I.etomicsrc);
    strcpy(txData.to, ETOMIC_ALICECONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);
}

char *LP_etomicbob_spends_alice_payment(struct LP_swap_remember *swap)
{
    BobSpendsAlicePaymentInput input;
    BasicTxData txData;

    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    uint8arrayToHex(input.dealId, swap->txids[BASILISK_ALICEPAYMENT].bytes, 32);
    satoshisToWei(input.amount, swap->destamount);

    if (swap->alicetomic[0] != 0)
        strcpy(input.tokenAddress, swap->alicetomic);
    else
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");

    strcpy(input.aliceAddress, swap->etomicdest);
    uint8arrayToHex(input.aliceSecret, swap->secretAm256, 32);
    uint8arrayToHex(input.bobHash, swap->secretBn, 20);

    strcpy(txData.from, swap->etomicsrc);
    strcpy(txData.to, ETOMIC_ALICECONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, swap->persistentPrivKey.bytes, 32);
    return bobSpendsAlicePayment(input, txData);
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
