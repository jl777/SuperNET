
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
#include <cpp-ethereum/etomicswap/etomiclib.h>

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

char *LP_etomicalice_start(struct basilisk_swap *swap)
{
    AliceSendsEthPaymentInput input; AliceSendsErc20PaymentInput input20; BasicTxData txData;
    // set input and txData fields from the swap data structure
    memset(&txData,0,sizeof(txData));
    if ( strcmp(swap->I.alicestr,"ETH") == 0 )
    {
        memset(&input,0,sizeof(input));
        return(aliceSendsEthPayment(input,txData));
    }
    else
    {
        memset(&input20,0,sizeof(input20));
        return(aliceSendsErc20Payment(input20,txData));
    }
    return(0);
}

int32_t LP_etomic_priv2addr(char *coinaddr,bits256 privkey)
{
    char str[65],*addrstr;
    bits256_str(str,privkey);
    if ( (addrstr= privKey2Addr(str)) != 0 )
    {
        printf("priv2addr got %s\n",addrstr);
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
            retval = 64;
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
        return((int32_t)strlen(coinaddr));
    }
    return(-1);
}
