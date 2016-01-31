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

#define EXCHANGE_NAME "yahoo"
#define UPDATE yahoo ## _price
#define SUPPORTS yahoo ## _supports
#define SIGNPOST yahoo ## _signpost
#define TRADE yahoo ## _trade
#define ORDERSTATUS yahoo ## _orderstatus
#define CANCELORDER yahoo ## _cancelorder
#define OPENORDERS yahoo ## _openorders
#define TRADEHISTORY yahoo ## _tradehistory
#define BALANCES yahoo ## _balances
#define PARSEBALANCE yahoo ## _parsebalance
#define WITHDRAW yahoo ## _withdraw
#define CHECKBALANCE yahoo ## _checkbalance
#define ALLPAIRS yahoo ## _allpairs
#define FUNCS yahoo ## _funcs
#define BASERELS yahoo ## _baserels

static char *BASERELS[][2] = { {"EUR","USD"},{"USD","JPY"},{"GBP","USD"},{"EUR","GBP"},{"USD","CHF"},{"AUD","NZD"},{"CAD","CHF"},{"CHF","JPY"},{"EUR","AUD"},{"EUR","CAD"},{"EUR","JPY"},{"EUR","CHF"},{"USD","CAD"},{"AUD","USD"},{"GBP","JPY"},{"AUD","CAD"},{"AUD","CHF"},{"AUD","JPY"},{"EUR","NOK"},{"EUR","NZD"},{"GBP","CAD"},{"GBP","CHF"},{"NZD","JPY"},{"NZD","USD"},{"USD","NOK"},{"USD","SEK"} };
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
        *retstrp = clonestr("{\"error\":\"yahoo is readonly data source\"}");
    return(cJSON_Parse("{}"));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"yahoo is readonly data source\"}"));
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    return(cJSON_Parse("{\"error\":\"yahoo is readonly data source\"}"));
}

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    return(0);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"yahoo is readonly data source\"}"));
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"yahoo is readonly data source\"}"));
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"yahoo is readonly data source\"}"));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"yahoo is readonly data source\"}"));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"yahoo is readonly data source\"}"));
}

struct exchange_funcs yahoo_funcs = EXCHANGE_FUNCS(yahoo,EXCHANGE_NAME);

#include "exchange_undefs.h"
