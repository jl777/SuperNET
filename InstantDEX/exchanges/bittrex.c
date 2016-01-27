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

#define EXCHANGE_NAME "bittrex"
#define UPDATE prices777_ ## bittrex
#define SUPPORTS bittrex ## _supports
#define SIGNPOST bittrex ## _signpost
#define TRADE bittrex ## _trade
#define ORDERSTATUS bittrex ## _orderstatus
#define CANCELORDER bittrex ## _cancelorder
#define OPENORDERS bittrex ## _openorders
#define TRADEHISTORY bittrex ## _tradehistory
#define BALANCES bittrex ## _balances
#define PARSEBALANCE bittrex ## _parsebalance
#define WITHDRAW bittrex ## _withdraw
#define CHECKBALANCE bittrex ## _checkbalance

double UPDATE(struct prices777 *prices,int32_t maxdepth)
{
    cJSON *json,*obj; char *jsonstr,market[128]; double hbla = 0.;
    if ( prices->url[0] == 0 )
    {
        sprintf(market,"%s-%s",prices->rel,prices->base);
        sprintf(prices->url,"https://bittrex.com/api/v1.1/public/getorderbook?market=%s&type=both&depth=%d",market,maxdepth);
    }
    jsonstr = issue_curl(prices->url);
    if ( jsonstr != 0 )
    {
        if ( (json = cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (obj= cJSON_GetObjectItem(json,"success")) != 0 && is_cJSON_True(obj) != 0 )
                hbla = prices777_json_orderbook("bittrex",prices,maxdepth,json,"result","buy","sell","Rate","Quantity");
            free_json(json);
        }
        free(jsonstr);
    }
    return(hbla);
}

int32_t SUPPORTS(char *base,char *rel)
{
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
    char dest[SHA512_DIGEST_SIZE*2+1],hdr1[512],hdr2[512],hdr3[512],hdr4[512],*data,*sig; cJSON *json;
    hdr1[0] = hdr2[0] = hdr3[0] = hdr4[0] = 0;
    json = 0;
    if ( (sig= hmac_sha512_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),payload)) != 0 )
        sprintf(hdr1,"apisign:%s",sig);
    if ( dotrade == 0 )
        data = exchange_would_submit(payload,hdr1,hdr2,hdr3,hdr4);
    else if ( (data= curl_post(cHandlep,url,0,payload,hdr1,hdr2,hdr3,hdr4)) != 0 )
        json = cJSON_Parse(data);
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(json);
}
cJSON *BALANCES(void **cHandlep,struct exchange_info *exchange)
{
    char payload[1024];
    sprintf(payload,"https://bittrex.com/api/v1.1/account/getbalances?apikey=%s&nonce=%llu",exchange->apikey,(long long)exchange_nonce(exchange));
    return(SIGNPOST(cHandlep,1,0,exchange,payload,payload));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    int32_t i,n; char *str,*itemstr = 0; cJSON *item,*array,*obj; double total,pending;
    *balancep = 0.;
    if ( exchange->balancejson != 0 && (array= jarray(&n,exchange->balancejson,"result")) != 0 )
    {
        for (i=0; i<n; i++)
        {
            if ( (item= jitem(array,i)) != 0 )
            {
                if ( (str= jstr(item,"Currency")) != 0 && strcmp(coinstr,str) == 0 )
                {
                    itemstr = jprint(item,0);
                    *balancep = jdouble(item,"Available");
                    total = jdouble(item,"Balance");
                    pending = jdouble(item,"Pending");
                    if ( (obj= cJSON_Parse(itemstr)) != 0 )
                    {
                        jaddnum(obj,"balance",*balancep);
                        jaddnum(obj,"total",total);
                        jaddnum(obj,"pending",pending);
                        if ( (str= jstr(obj,"CryptoAddress")) != 0 )
                            jaddstr(obj,"deposit_address",str);
                        free(itemstr);
                        itemstr = jprint(obj,1);
                    }
                    break;
                }
            }
        }
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance, are you sure it isnt empty account?\"}"));
    return(itemstr);
}

#include "checkbalance.c"

uint64_t TRADE(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    char payload[1024],pairstr[512],*extra; cJSON *json,*resultobj; uint64_t txid = 0; int32_t i,j,n;
    struct destbuf uuidstr; uint8_t databuf[512];
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    if ( (dir= flip_for_exchange(pairstr,"%s-%s","BTC",dir,&price,&volume,base,rel)) == 0 )
    {
        return(0);
    }
    sprintf(payload,"https://bittrex.com/api/v1.1/market/%slimit?apikey=%s&nonce=%llu&market=%s&rate=%.8f&quantity=%.8f",dir>0?"buy":"sell",exchange->apikey,(long long)exchange_nonce(exchange),pairstr,price,volume);
    if ( CHECKBALANCE(retstrp,dotrade,exchange,dir,base,rel,price,volume) == 0 && (json= SIGNPOST(cHandlep,dotrade,retstrp,exchange,payload,payload)) != 0 )
    {
        if ( is_cJSON_True(cJSON_GetObjectItem(json,"success")) != 0 && (resultobj= cJSON_GetObjectItem(json,"result")) != 0 )
        {
            copy_cJSON(&uuidstr,cJSON_GetObjectItem(resultobj,"uuid"));
            for (i=j=0; uuidstr.buf[i]!=0; i++)
                if ( uuidstr.buf[i] != '-' )
                    uuidstr.buf[j++] = uuidstr.buf[i];
            uuidstr.buf[j] = 0;
            n = (int32_t)strlen(uuidstr.buf);
            printf("-> uuidstr.(%s).%d\n",uuidstr.buf,n);
            decode_hex(databuf,n/2,uuidstr.buf);
            if ( n >= 16 )
                for (i=0; i<8; i++)
                    databuf[i] ^= databuf[8 + i];
            memcpy(&txid,databuf,8);
            printf("-> %llx\n",(long long)txid);
        }
        free_json(json);
    }
    return(txid);
}

char *ORDERSTATUS(void **cHandlep,struct exchange_info *exchange,cJSON *argjson,uint64_t quoteid)
{
    char payload[1024],*retstr = 0; cJSON *json;
    sprintf(payload,"https://bittrex.com/api/v1.1/account/getorder?apikey=%s&nonce=%llu&uuid=%llu",exchange->apikey,(long long)exchange_nonce(exchange),(long long)quoteid);
    if ( (json= SIGNPOST(cHandlep,1,&retstr,exchange,payload,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized orderstatus
}

char *CANCELORDER(void **cHandlep,struct exchange_info *exchange,cJSON *argjson,uint64_t quoteid)
{
    char payload[1024],*retstr = 0; cJSON *json;
    sprintf(payload,"https://bittrex.com/api/v1.1/market/cancel?apikey=%s&nonce=%llu&uuid=%llu",exchange->apikey,(long long)exchange_nonce(exchange),(long long)quoteid);
    if ( (json= SIGNPOST(cHandlep,1,&retstr,exchange,payload,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized cancelorder
}

char *OPENORDERS(void **cHandlep,struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],market[64],*base,*rel,*retstr = 0; cJSON *json;
    sprintf(payload,"https://bittrex.com/api/v1.1/market/getopenorders?apikey=%s&nonce=%llu",exchange->apikey,(long long)exchange_nonce(exchange));
    if ( (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 )
    {
        sprintf(market,"%s-%s",rel,base);
        sprintf(payload + strlen(payload),"&market=%s",market);
    }
    if ( (json= SIGNPOST(cHandlep,1,&retstr,exchange,payload,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized open orders
}

char *TRADEHISTORY(void **cHandlep,struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],market[64],*base,*rel,*retstr = 0; cJSON *json;
    sprintf(payload,"https://bittrex.com/api/v1.1/account/getorderhistory?apikey=%s&nonce=%llu",exchange->apikey,(long long)exchange_nonce(exchange));
    if ( (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 )
    {
        sprintf(market,"%s-%s",rel,base);
        sprintf(payload + strlen(payload),"&market=%s",market);
    }
    if ( (json= SIGNPOST(cHandlep,1,&retstr,exchange,payload,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized tradehistory
}

char *WITHDRAW(void **cHandlep,struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],*destaddr,*paymentid,*base,*retstr = 0; cJSON *json; double amount;
    if ( (base= jstr(argjson,"base")) == 0 )
        return(clonestr("{\"error\":\"base not specified\"}"));
    if ( (destaddr= jstr(argjson,"destaddr")) == 0 )
        return(clonestr("{\"error\":\"destaddr not specified\"}"));
    if ( (amount= jdouble(argjson,"amount")) < SMALLVAL )
        return(clonestr("{\"error\":\"amount not specified\"}"));
    paymentid = jstr(argjson,"paymentid");
    sprintf(payload,"https://bittrex.com/api/v1.1/account/withdraw?apikey=%s&nonce=%llu&currency=%s&amount=%.4f&address=%s",exchange->apikey,(long long)exchange_nonce(exchange),base,amount,destaddr);
    if ( paymentid != 0 )
        sprintf(payload + strlen(payload),"&paymentid=%s",paymentid);
    if ( (json= SIGNPOST(cHandlep,1,&retstr,exchange,payload,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized withdraw
}

struct exchange_funcs bittrex_funcs = EXCHANGE_FUNCS(bittrex,EXCHANGE_NAME);

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
#undef CHECKBALANCE
