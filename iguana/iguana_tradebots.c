/******************************************************************************
 * Copyright © 2014-2016 The SuperNET Developers.                             *
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

#include "exchanges777.h"


#include "../includes/iguana_apidefs.h"

THREE_STRINGS_AND_DOUBLE(tradebot,monitor,exchange,base,rel,commission)
{
    int32_t allfields = 1,depth = 50; struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
            return(exchanges777_Qprices(ptr,base,rel,30,allfields,depth,json,1,commission * .01));
        else return(clonestr("{\"error\":\"couldnt find/create exchange info\"}"));
    } else return(clonestr("{\"error\":\"tradebots only local usage!\"}"));
}

THREE_STRINGS(tradebot,unmonitor,exchange,base,rel)
{
    struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
            return(exchanges777_unmonitor(ptr,base,rel));
        else return(clonestr("{\"error\":\"couldnt find/create exchange info\"}"));
    } else return(clonestr("{\"error\":\"tradebots only local usage!\"}"));
}

THREE_STRINGS_AND_THREE_DOUBLES(tradebot,accumulate,exchange,base,rel,price,volume,duration)
{
    if ( remoteaddr == 0 )
    {
        return(clonestr("{\"result\":\"start accumulating\"}"));
    } else return(clonestr("{\"error\":\"tradebots only local usage!\"}"));
}

THREE_STRINGS_AND_THREE_DOUBLES(tradebot,divest,exchange,base,rel,price,volume,duration)
{
    if ( remoteaddr == 0 )
    {
        return(clonestr("{\"result\":\"start divesting\"}"));
    } else return(clonestr("{\"error\":\"tradebots only local usage!\"}"));
}

#include "../includes/iguana_apiundefs.h"

