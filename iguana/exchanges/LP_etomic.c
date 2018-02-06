
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
