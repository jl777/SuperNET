
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
//  LP_prices.c
//  marketmaker
//

double LP_kmdbtc;

// very, very simple for now

void LP_priceupdate(char *base,char *rel,double price,double avebid,double aveask,double highbid,double lowask,double PAXPRICES[32])
{
    if ( avebid > SMALLVAL && aveask > SMALLVAL && strcmp(base,"KMD") == 0 && strcmp(rel,"BTC") == 0 )
        LP_kmdbtc = (avebid + aveask) * 0.5;
}

double LP_price(char *base,char *rel)
{
    if ( LP_kmdbtc != 0. )
    {
        if ( strcmp(base,"KMD") == 0 && strcmp(rel,"BTC") == 0 )
            return(LP_kmdbtc);
        else if ( strcmp(rel,"KMD") == 0 && strcmp(base,"BTC") == 0 )
            return(1. / LP_kmdbtc);
    }
    return(0.);
}
