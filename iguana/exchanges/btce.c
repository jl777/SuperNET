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

#define EXCHANGE_NAME "btce"
#define UPDATE btce ## _price
#define SUPPORTS btce ## _supports
#define SIGNPOST btce ## _signpost
#define TRADE btce ## _trade
#define ORDERSTATUS btce ## _orderstatus
#define CANCELORDER btce ## _cancelorder
#define OPENORDERS btce ## _openorders
#define TRADEHISTORY btce ## _tradehistory
#define BALANCES btce ## _balances
#define PARSEBALANCE btce ## _parsebalance
#define WITHDRAW btce ## _withdraw
#define EXCHANGE_AUTHURL "https://btc-e.com/tapi"
#define CHECKBALANCE btce ## _checkbalance

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *quotes,int32_t maxdepth,cJSON *argjson)
{
    char field[64],url[1024],lbase[16],lrel[16];
    strcpy(lrel,rel), strcpy(lbase,base);
    tolowercase(lrel), tolowercase(lbase);
    sprintf(field,"%s_%s",lbase,lrel);
    sprintf(url,"https://btc-e.com/api/3/depth/%s",field);
    return(exchanges777_standardprices(exchange,base,rel,url,quotes,0,0,maxdepth,field));
}

int32_t SUPPORTS(struct exchange_info *exchange,char *base,char *rel,cJSON *argjson)
{
    char *baserels[][2] = { {"btc","usd"}, {"btc","rur"}, {"btc","eur"}, {"ltc","btc"}, {"ltc","usd"}, {"ltc","rur"}, {"ltc","eur"}, {"nmc","btc"}, {"nmc","usd"}, {"nvc","btc"}, {"nvc","usd"}, {"eur","usd"}, {"eur","rur"}, {"ppc","btc"}, {"ppc","usd"} };
    return(baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel));
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
    sprintf(payload,"method=getInfo&nonce=%llu",(long long)exchange_nonce(exchange));
    return(SIGNPOST(&exchange->cHandle,1,0,exchange,EXCHANGE_AUTHURL,payload));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    //btce.({"success":1,"return":{"funds":{"usd":73.02571846,"btc":0,"ltc":0,"nmc":0,"rur":0,"eur":0,"nvc":0.0000322,"trc":0,"ppc":0.00000002,"ftc":0,"xpm":2.28605349,"cnh":0,"gbp":0},"rights":{"info":1,"trade":1,"withdraw":0},"transaction_count":0,"open_orders":3,"server_time":1441918649}})
    char field[128],*itemstr = 0; cJSON *obj,*item;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    if ( argjson != 0 && (obj= jobj(argjson,"return")) != 0 && (item= jobj(obj,"funds")) != 0 )
    {
        *balancep = jdouble(item,field);
        obj = cJSON_CreateObject();
        touppercase(field);
        jaddstr(obj,"base",field);
        jaddnum(obj,"balance",*balancep);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

#include "checkbalance.c"

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    char payload[1024],pairstr[512],*extra; cJSON *json,*resultobj; uint64_t txid = 0;
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s_%s",dir,&price,&volume,base,rel,argjson)) == 0 )
    {
        printf("cant find baserel (%s/%s)\n",base,rel);
        return(0);
    }
    sprintf(payload,"method=Trade&nonce=%llu&pair=%s&type=%s&rate=%.3f&amount=%.6f",(long long)exchange_nonce(exchange),pairstr,dir>0?"buy":"sell",price,volume);
    if ( CHECKBALANCE(retstrp,dotrade,exchange,dir,base,rel,price,volume,argjson) == 0 && (json= SIGNPOST(&exchange->cHandle,dotrade,retstrp,exchange,EXCHANGE_AUTHURL,payload)) != 0 )
    {
        //{ "success":1, "return":{ "received":0.1, "remains":0, "order_id":0, "funds":{ "usd":325, "btc":2.498,  } } }
        if ( juint(json,"success") > 0 && (resultobj= jobj(json,"return")) != 0 )
        {
            if ( (txid= j64bits(resultobj,"order_id")) == 0 )
            {
                if ( j64bits(resultobj,"remains") == 0 )
                    txid = calc_crc32(0,payload,strlen(payload));
            }
        }
        free_json(json);
    }
    return(txid);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char payload[1024],*retstr = 0; cJSON *json;
    sprintf(payload,"method=OrderInfo&nonce=%llu&order_id=%llu",(long long)exchange_nonce(exchange),(long long)quoteid);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,EXCHANGE_AUTHURL,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized orderstatus
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char payload[1024],*retstr = 0; cJSON *json;
    sprintf(payload,"method=CancelOrder&nonce=%llu&order_id=%llu",(long long)exchange_nonce(exchange),(long long)quoteid);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,EXCHANGE_AUTHURL,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized cancelorder
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],market[64],*base,*rel,*retstr = 0; cJSON *json;
    sprintf(payload,"method=ActiveOrders&nonce=%llu",(long long)exchange_nonce(exchange));
    if ( (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 )
    {
        sprintf(market,"%s_%s",base,rel);
        tolowercase(market);
        sprintf(payload + strlen(payload),"&pair=%s",market);
    }
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,EXCHANGE_AUTHURL,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized open orders
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],market[64],*base,*rel,*retstr = 0; cJSON *json; uint32_t starttime,endtime;
    sprintf(payload,"method=TradeHistory&nonce=%llu",(long long)exchange_nonce(exchange));
    if ( (starttime= juint(argjson,"start")) != 0 )
        sprintf(payload + strlen(payload),"&since=%u",starttime);
    if ( (endtime= juint(argjson,"end")) != 0 )
        sprintf(payload + strlen(payload),"&end=%u",endtime);
    if ( (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 )
    {
        sprintf(market,"%s_%s",base,rel);
        tolowercase(market);
        sprintf(payload + strlen(payload),"&pair=%s",market);
    }
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,EXCHANGE_AUTHURL,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized tradehistory
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    char payload[1024],*retstr = 0; cJSON *json;
    if ( base == 0 || base[0] == 0 )
        return(clonestr("{\"error\":\"base not specified\"}"));
    if ( destaddr == 0 || destaddr[0] == 0 )
        return(clonestr("{\"error\":\"destaddr not specified\"}"));
    if ( amount < SMALLVAL )
        return(clonestr("{\"error\":\"amount not specified\"}"));
    sprintf(payload,"method=WithdrawCoin&nonce=%llu&coinName=%s&amount=%.6f&address=%s",(long long)exchange_nonce(exchange),base,amount,destaddr);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,EXCHANGE_AUTHURL,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized withdraw
}

struct exchange_funcs btce_funcs = EXCHANGE_FUNCS(btce,EXCHANGE_NAME);

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
