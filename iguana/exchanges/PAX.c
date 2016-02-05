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

#define EXCHANGE_NAME "PAX"
#define UPDATE PAX ## _price
#define SUPPORTS PAX ## _supports
#define SIGNPOST PAX ## _signpost
#define TRADE PAX ## _trade
#define ORDERSTATUS PAX ## _orderstatus
#define CANCELORDER PAX ## _cancelorder
#define OPENORDERS PAX ## _openorders
#define TRADEHISTORY PAX ## _tradehistory
#define BALANCES PAX ## _balances
#define PARSEBALANCE PAX ## _parsebalance
#define WITHDRAW PAX ## _withdraw
#define CHECKBALANCE PAX ## _checkbalance
#define ALLPAIRS PAX ## _allpairs
#define FUNCS PAX ## _funcs
#define BASERELS PAX ## _baserels

#include "../peggy.h"

char *peggy_bases[64] =
{
    "BTCD", "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK",
    "BTCUSD", "NXTBTC", "SuperNET", "ETHBTC", "LTCBTC", "XMRBTC", "BTSBTC", "XCPBTC",  // BTC priced
    "XAUUSD", "XAGUSD", "XPTUSD", "XPDUSD", "COPPER", "NGAS", "UKOIL", "USOIL", // USD priced
    "BUND", "NAS100", "SPX500", "US30", "EUSTX50", "UK100", "JPN225", "GER30", "SUI30", "AUS200", "HKG33", "XAUUSD", "BTCRUB", "BTCCNY", "BTCUSD" // abstract
};

char *ALLPAIRS(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"PAX is not yet\"}"));
}

int32_t SUPPORTS(struct exchange_info *exchange,char *base,char *rel,cJSON *argjson)
{
    return(0);
}

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *quotes,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert)
{
    return(0);
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *payload,char *path)
{
    if ( retstrp != 0 )
        *retstrp = clonestr("{\"error\":\"PAX signing is not yet\"}");
    return(cJSON_Parse("{}"));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"PAX parsebalance is not yet\"}"));
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    return(cJSON_Parse("{\"error\":\"PAX balances is not yet\"}"));
}

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    return(0);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"PAX orderstatus is not yet\"}"));
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"PAX cancel order is not yet\"}"));
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"PAX open orders is not yet\"}"));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"PAX tradehistory is not yet\"}"));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"PAX redeem is not yet\"}"));
}

struct exchange_funcs PAX_funcs = EXCHANGE_FUNCS(PAX,EXCHANGE_NAME);

#include "exchange_undefs.h"


