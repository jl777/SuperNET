/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
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

#include "iguana777.h"
#include "SuperNET.h"

char *iguana_getrawchangeaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *account)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}

char *iguana_settxfee(struct supernet_info *myinfo,struct iguana_info *coin,double amount)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_listtransactions(struct supernet_info *myinfo,struct iguana_info *coin,char *account,int32_t count,int32_t from)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_listunspent(struct supernet_info *myinfo,struct iguana_info *coin,int32_t minconf,int32_t maxconf)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_lockunspent(struct supernet_info *myinfo,struct iguana_info *coin,int32_t flag,cJSON *array)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_listlockunspent(struct supernet_info *myinfo,struct iguana_info *coin)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_gettxout(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid,int32_t vout,int32_t mempool)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_gettxoutsetinfo(struct supernet_info *myinfo,struct iguana_info *coin)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_getrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid,int32_t verbose)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_createrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *vins,cJSON *vouts)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_decoderawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_decodescript(struct supernet_info *myinfo,struct iguana_info *coin,char *script)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_signrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx,cJSON *vins,cJSON *privkeys)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_sendrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_sendtoaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address,double amount,char *comment,char *comment2)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_getreceivedbyaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address,int32_t minconf)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_listreceivedbyaddress(struct supernet_info *myinfo,struct iguana_info *coin,int32_t minconf,int32_t includeempty)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


