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

#define EXCHANGE_NAME "instaforex"
#define UPDATE instaforex ## _price
#define SUPPORTS instaforex ## _supports
#define SIGNPOST instaforex ## _signpost
#define TRADE instaforex ## _trade
#define ORDERSTATUS instaforex ## _orderstatus
#define CANCELORDER instaforex ## _cancelorder
#define OPENORDERS instaforex ## _openorders
#define TRADEHISTORY instaforex ## _tradehistory
#define BALANCES instaforex ## _balances
#define PARSEBALANCE instaforex ## _parsebalance
#define WITHDRAW instaforex ## _withdraw
#define CHECKBALANCE instaforex ## _checkbalance
#define ALLPAIRS instaforex ## _allpairs
#define FUNCS instaforex ## _funcs
#define BASERELS instaforex ## _baserels

static char *BASERELS[][2] = { {"btc","nxt"}, {"btc","btcd"}, {"btc","ltc"}, {"btc","vrc"}, {"btc","doge"} };
#include "exchange_supports.h"

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *quotes,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert)
{
    char url[1024],lrel[16],lbase[16];
    strcpy(lrel,rel), strcpy(lbase,base);
    tolowercase(lrel), tolowercase(lbase);
    sprintf(url,"http://api.quadrigacx.com/v2/order_book?book=%s_%s",lbase,lrel);
    return(exchanges777_standardprices(exchange,commission,base,rel,url,quotes,0,0,maxdepth,0,invert));
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *payload,char *path)
{
    if ( retstrp != 0 )
        *retstrp = clonestr("{\"error\":\"instaforex is readonly data source\"}");
    return(cJSON_Parse("{}"));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"instaforex is readonly data source\"}"));
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    return(cJSON_Parse("{\"error\":\"instaforex is readonly data source\"}"));
}

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    return(0);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"instaforex is readonly data source\"}"));
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"instaforex is readonly data source\"}"));
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"instaforex is readonly data source\"}"));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"instaforex is readonly data source\"}"));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"instaforex is readonly data source\"}"));
}

struct exchange_funcs instaforex_funcs = EXCHANGE_FUNCS(instaforex,EXCHANGE_NAME);

#include "exchange_undefs.h"
