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

#define EXCHANGE_NAME "poloniex"
#define UPDATE poloniex ## _price
#define SUPPORTS poloniex ## _supports
#define SIGNPOST poloniex ## _signpost
#define TRADE poloniex ## _trade
#define ORDERSTATUS poloniex ## _orderstatus
#define CANCELORDER poloniex ## _cancelorder
#define OPENORDERS poloniex ## _openorders
#define TRADEHISTORY poloniex ## _tradehistory
#define BALANCES poloniex ## _balances
#define PARSEBALANCE poloniex ## _parsebalance
#define WITHDRAW poloniex ## _withdraw
#define EXCHANGE_AUTHURL "https://poloniex.com/tradingApi"
#define CHECKBALANCE poloniex ## _checkbalance

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *quotes,int32_t maxdepth,cJSON *argjson)
{
    char market[128],url[1024];
    sprintf(market,"%s_%s",rel,base);
    sprintf(url,"https://poloniex.com/public?command=returnOrderBook&currencyPair=%s&depth=%d",market,maxdepth);
    return(exchanges777_standardprices(exchange,base,rel,url,quotes,0,0,maxdepth,0));
}

int32_t SUPPORTS(struct exchange_info *exchange,char *base,char *rel,cJSON *argjson)
{
    //char *baserels[][2] = { {"btc","usd"} };
    //return(baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel));
    if ( strlen(base) > 5 || strlen(rel) > 5 || strcmp(rel,"CNY") == 0 || strcmp(base,"CNY") == 0 || strcmp(rel,"USD") == 0 || strcmp(base,"USD") == 0 )
        return(0);
    if ( strcmp(rel,"BTC") == 0 )
        return(1);
    else if ( strcmp(base,"BTC") == 0 )
        return(-1);
    else return(0);
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *url,char *payload)
{
    char dest[(512>>3)*2+1],hdr1[512],hdr2[512],hdr3[512],hdr4[512],*data,*sig; cJSON *json;
    hdr1[0] = hdr2[0] = hdr3[0] = hdr4[0] = 0;
    json = 0;
    if ( (sig= hmac_sha512_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),payload)) != 0 )
        sprintf(hdr1,"Sign:%s",sig);
    else hdr1[0] = 0;
    sprintf(hdr2,"Key:%s",exchange->apikey);
    if ( dotrade == 0 )
        data = exchange_would_submit(payload,hdr1,hdr2,hdr3,hdr4);
    else if ( (data= curl_post(&exchange->cHandle,url,0,payload,hdr1,hdr2,hdr3,hdr4)) != 0 )
        json = cJSON_Parse(data);
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(json);
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024];
    sprintf(payload,"command=returnCompleteBalances&nonce=%llu",(long long)exchange_nonce(exchange));
    return(SIGNPOST(&exchange->cHandle,1,0,exchange,EXCHANGE_AUTHURL,payload));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    char *itemstr = 0; cJSON *item,*obj; double onorders,btcvalue;
    *balancep = 0.;
    if ( argjson != 0 && (item= jobj(argjson,coinstr)) != 0 )
    {
        itemstr = jprint(item,0);
        *balancep = jdouble(item,"available");
        onorders = jdouble(item,"onOrders");
        btcvalue = jdouble(item,"btcValue");
        if ( (obj= cJSON_Parse(itemstr)) != 0 )
        {
            free(itemstr);
            jaddstr(obj,"base",coinstr);
            jaddnum(obj,"balance",*balancep);
            jaddnum(obj,"onOrders",onorders);
            jaddnum(obj,"btcvalue",btcvalue);
            itemstr = jprint(obj,1);
        }
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

#include "checkbalance.c"

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    char payload[1024],pairstr[64],*extra,*typestr; cJSON *json; uint64_t nonce,txid = 0;
    nonce = exchange_nonce(exchange);
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    dir = flip_for_exchange(pairstr,"%s_%s","BTC",dir,&price,&volume,base,rel);
    if ( extra != 0 && strcmp(extra,"margin") == 0 )
        typestr = (dir > 0) ? "marginBuy":"marginSell";
    else typestr = (dir > 0) ? "buy":"sell";
    sprintf(payload,"command=%s&nonce=%lld&currencyPair=%s&rate=%.8f&amount=%.8f",typestr,(long long)nonce,pairstr,price,volume);
    if ( CHECKBALANCE(retstrp,dotrade,exchange,dir,base,rel,price,volume,argjson) == 0 && (json= SIGNPOST(&exchange->cHandle,dotrade,retstrp,exchange,EXCHANGE_AUTHURL,payload)) != 0 )
    {
        txid = (get_API_nxt64bits(cJSON_GetObjectItem(json,"orderNumber")) << 32) | get_API_nxt64bits(cJSON_GetObjectItem(json,"tradeID"));
        free_json(json);
    }
    return(txid);
}

void poloniex_setpair(char *pair,cJSON *argjson)
{
    char *base,*rel;
    base = jstr(argjson,"base");
    rel = jstr(argjson,"rel");
    if ( base == 0 || rel == 0 )
        strcpy(pair,"all");
    else sprintf(pair,"%s_%s",rel,base);
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char payload[1024],*retstr = 0; cJSON *json;
    sprintf(payload,"command=cancelOrder&nonce=%llu&orderNumber=%llu",(long long)exchange_nonce(exchange),(long long)quoteid);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,EXCHANGE_AUTHURL,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized cancelorder
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],pair[64],*retstr = 0; cJSON *json;
    poloniex_setpair(pair,argjson);
    sprintf(payload,"command=returnOpenOrders&nonce=%llu&currencyPair=%s",(long long)exchange_nonce(exchange),pair);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,EXCHANGE_AUTHURL,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized open orders
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],pair[64],*retstr = 0; cJSON *json; uint32_t timestamp,endstamp;
    poloniex_setpair(pair,argjson);
    timestamp = juint(argjson,"start");
    endstamp = juint(argjson,"end");
    sprintf(payload,"command=returnTradeHistory&nonce=%llu&currencyPair=%s",(long long)exchange_nonce(exchange),pair);
    if ( timestamp != 0 )
        sprintf(payload + strlen(payload),"&start=%u",timestamp);
    if ( endstamp != 0 )
        sprintf(payload + strlen(payload),"&end=%u",endstamp);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,EXCHANGE_AUTHURL,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized tradehistory
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char *status,*retstr; uint32_t iter;
    for (iter=0; iter<2; iter++)
    {
        if ( iter == 0 )
            status = OPENORDERS(exchange,argjson);
        else status = TRADEHISTORY(exchange,argjson);
        if ( (retstr= exchange_extractorderid(iter,status,quoteid,"orderNumber")) != 0 )
        {
            free(status);
            return(retstr);
        }
        free(status);
    }
    return(clonestr("{\"error\":\"cant find quoteid\"}"));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    char payload[1024],*paymentid,*retstr = 0; cJSON *json;
    if ( base == 0 || base[0] == 0 )
        return(clonestr("{\"error\":\"base not specified\"}"));
    if ( destaddr == 0 || destaddr[0] == 0 )
        return(clonestr("{\"error\":\"destaddr not specified\"}"));
    if ( amount < SMALLVAL )
        return(clonestr("{\"error\":\"amount not specified\"}"));
    paymentid = jstr(argjson,"paymentid");
    sprintf(payload,"command=withdraw&nonce=%llu&currency=%s&amount=%.6f&address=%s",(long long)exchange_nonce(exchange),base,amount,destaddr);
    if ( paymentid != 0 )
        sprintf(payload + strlen(payload),"&paymentId=%s",paymentid);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,EXCHANGE_AUTHURL,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized withdraw
}

struct exchange_funcs poloniex_funcs = EXCHANGE_FUNCS(poloniex,EXCHANGE_NAME);


#undef UPDATE
#undef SUPPORTS
#undef SIGNPOST
#undef TRADE
#undef ORDERSTATUS
#undef CANCELORDER
#undef OPENORDERS
#undef TRADEHISTORY
#undef BALANCES
#undef PARSEBALANCE
#undef WITHDRAW
#undef EXCHANGE_NAME
#undef EXCHANGE_AUTHURL
#undef CHECKBALANCE
