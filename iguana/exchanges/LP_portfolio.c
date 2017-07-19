
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
//  LP_portfolio.c
//  marketmaker
//

cJSON *LP_portfolio_entry(struct iguana_info *coin,uint64_t kmdsum)
{
    cJSON *item = cJSON_CreateObject();
    jaddstr(item,"coin",coin->symbol);
    jaddnum(item,"amount",dstr(coin->maxamount));
    jaddnum(item,"price",coin->price_kmd);
    jaddnum(item,"kmd_equiv",dstr(coin->kmd_equiv));
    jaddnum(item,"kmdsum",dstr(kmdsum));
    jaddnum(item,"goal",dstr(coin->goal));
    if ( kmdsum > 0 )
        jaddnum(item,"perc",100. * (double)coin->kmd_equiv/ kmdsum);
    jaddnum(item,"balanceA",dstr(coin->balanceA));
    jaddnum(item,"valuesumA",dstr(coin->valuesumA));
    jaddnum(item,"aliceutil",100. * (double)coin->balanceA/coin->valuesumA);
    jaddnum(item,"balanceB",dstr(coin->balanceB));
    jaddnum(item,"valuesumB",dstr(coin->valuesumB));
    jaddnum(item,"bobutil",100. * (double)coin->balanceB/coin->valuesumB);
    return(item);
}

uint64_t LP_balance(uint64_t *valuep,int32_t iambob,char *symbol,char *coinaddr)
{
    cJSON *array,*item; int32_t i,n; uint64_t valuesum,satoshisum;
    valuesum = satoshisum = 0;
    if ( (array= LP_inventory(symbol,iambob)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 && is_cJSON_Array(array) != 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                valuesum += j64bits(item,"value") + j64bits(item,"value2");
                satoshisum += j64bits(item,"satoshis");
            }
        }
        free_json(array);
    }
    *valuep = valuesum;
    return(satoshisum);
}

char *LP_portfolio()
{
    uint64_t kmdsum = 0; int32_t iter; cJSON *retjson,*array; struct iguana_info *coin,*tmp;
    array = cJSON_CreateArray();
    retjson = cJSON_CreateObject();
    for (iter=0; iter<2; iter++)
    {
        HASH_ITER(hh,LP_coins,coin,tmp)
        {
            if ( coin->inactive != 0 )
                continue;
            if ( iter == 0 )
            {
                coin->balanceA = LP_balance(&coin->valuesumA,0,coin->symbol,coin->smartaddr);
                coin->balanceB = LP_balance(&coin->valuesumB,1,coin->symbol,coin->smartaddr);
                if ( strcmp(coin->symbol,"KMD") != 0 )
                    coin->price_kmd = LP_price(coin->symbol,"KMD");
                else coin->price_kmd = 1.;
                coin->maxamount = coin->valuesumA;
                if ( coin->valuesumB > coin->maxamount )
                    coin->maxamount = coin->valuesumB;
                coin->kmd_equiv = coin->maxamount * coin->price_kmd;
                kmdsum += coin->kmd_equiv;
            }
            else if ( coin->maxamount > 0 )
                jaddi(array,LP_portfolio_entry(coin,kmdsum));
        }
    }
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"kmd_equiv",dstr(kmdsum));
    jadd(retjson,"portfolio",array);
    return(jprint(retjson,1));
}


