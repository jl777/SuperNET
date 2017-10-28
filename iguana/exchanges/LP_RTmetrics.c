
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
//  LP_RTmetrics.c
//  marketmaker
//

cJSON *LP_RTmetrics_sort(cJSON *rawasks,int32_t numasks,double maxprice,double relvolume)
{
    cJSON *array,*item,*statsjson,*swaps=0; int32_t i,numswaps=0; bits256 zero; uint32_t futuretime; double price; char *retstr;
    futuretime = (uint32_t)time(NULL) + 3600*100;
    memset(zero.bytes,0,sizeof(zero));
    if ( (retstr= LP_statslog_disp(100,futuretime,futuretime,"",zero)) != 0 )
    {
        if ( (statsjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (swaps= jarray(&numswaps,statsjson,"swaps")) != 0 )
            {
                if ( numswaps > 0 )
                    swaps = jduplicate(swaps);
                else swaps = 0;
            }
            free_json(statsjson);
        }
        free(retstr);
    }
    //if ( numswaps == 0 || swaps == 0 )
        return(0);
    printf("calc RTmetrics for (%s)\n",jprint(swaps,0));
    /*jadd64bits(item,"aliceid",sp->aliceid);
    jaddbits256(item,"src",sp->Q.srchash);
    jaddstr(item,"base",sp->Q.srccoin);
    jaddnum(item,"basevol",dstr(sp->Q.satoshis));
    jaddbits256(item,"dest",sp->Q.desthash);
    jaddstr(item,"rel",sp->Q.destcoin);
    jaddnum(item,"relvol",dstr(sp->Q.destsatoshis));
    jaddnum(item,"price",sp->qprice);
    jaddnum(item,"requestid",sp->Q.R.requestid);
    jaddnum(item,"quoteid",sp->Q.R.quoteid);
    */
    array = cJSON_CreateArray();
    for (i=0; i<numasks; i++)
    {
        item = jitem(rawasks,i);
        price = jdouble(item,"price");
        if ( price > maxprice )
            break;
        jaddi(array,jduplicate(item));
    }
    free_json(swaps);
    return(array);
}
