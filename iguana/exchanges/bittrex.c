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
#define UPDATE bittrex ## _price
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
#define ALLPAIRS bittrex ## _allpairs
#define FUNCS bittrex ## _funcs

static char *(*bittrex_baserels)[][2];

char *ALLPAIRS(struct exchange_info *exchange,cJSON *argjson)
{
    static int32_t num;
    char *jsonstr,*base,*rel; int32_t i; cJSON *json,*array,*item;
    if ( num == 0 || (*bittrex_baserels) == 0 )
    {
        jsonstr = issue_curl("https://bittrex.com/api/v1.1/public/getmarkets");
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (array= jarray(&num,json,"result")) != 0 )
            {
                bittrex_baserels = calloc(num,sizeof(char *) * 2);
                for (i=0; i<num; i++)
                {
                    item = jitem(array,i);
                    base = jstr(item,"MarketCurrency");
                    rel = jstr(item,"BaseCurrency");
                    if ( base != 0 && rel != 0 )
                    {
                        (*bittrex_baserels)[i][0] = clonestr(base);
                        (*bittrex_baserels)[i][1] = clonestr(rel);
                    }
                }
            }
            free_json(json);
        }
        free(jsonstr);
    }
    return(jprint(exchanges777_allpairs((*bittrex_baserels),num),1));
}

int32_t SUPPORTS(struct exchange_info *exchange,char *base,char *rel,cJSON *argjson)
{
    if ( strlen(base) > 5 || strlen(rel) > 5 || strcmp(rel,"CNY") == 0 || strcmp(base,"CNY") == 0 || strcmp(rel,"USD") == 0 || strcmp(base,"USD") == 0 )
        return(0);
    if ( strcmp(rel,"BTC") == 0 )
        return(1);
    else if ( strcmp(base,"BTC") == 0 )
        return(-1);
    else return(0);
}

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *quotes,int32_t maxdepth,double commission,cJSON *argjson)
{
    cJSON *json,*obj; char *jsonstr,market[128],url[1024]; double hbla = 0.;
    sprintf(market,"%s-%s",rel,base);
    sprintf(url,"https://bittrex.com/api/v1.1/public/getorderbook?market=%s&type=both&depth=%d",market,maxdepth);
    jsonstr = issue_curl(url);
    if ( jsonstr != 0 )
    {
        if ( (json = cJSON_Parse(jsonstr)) != 0 )
        {
           if ( (obj= cJSON_GetObjectItem(json,"success")) != 0 && is_cJSON_True(obj) != 0 )
                hbla = exchanges777_json_orderbook(exchange,commission,base,rel,quotes,maxdepth,json,"result","buy","sell","Rate","Quantity");
            free_json(json);
        }
        free(jsonstr);
    }
    return(hbla);
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *url,char *payload)
{
    char dest[(512>>3)*2+1],hdr1[512],hdr2[512],hdr3[512],hdr4[512],*data,*sig; cJSON *json;
    hdr1[0] = hdr2[0] = hdr3[0] = hdr4[0] = 0;
    json = 0;
    if ( (sig= hmac_sha512_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),payload)) != 0 )
        sprintf(hdr1,"apisign:%s",sig);
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
    sprintf(payload,"https://bittrex.com/api/v1.1/account/getbalances?apikey=%s&nonce=%llu",exchange->apikey,(long long)exchange_nonce(exchange));
    return(SIGNPOST(&exchange->cHandle,1,0,exchange,payload,payload));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    int32_t i,n; char *str,*itemstr = 0; cJSON *item,*array,*obj; double total,pending;
    *balancep = 0.;
    if ( argjson != 0 && (array= jarray(&n,argjson,"result")) != 0 )
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

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
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
    if ( CHECKBALANCE(retstrp,dotrade,exchange,dir,base,rel,price,volume,argjson) == 0 && (json= SIGNPOST(&exchange->cHandle,dotrade,retstrp,exchange,payload,payload)) != 0 )
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

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char payload[1024],*retstr = 0; cJSON *json;
    sprintf(payload,"https://bittrex.com/api/v1.1/account/getorder?apikey=%s&nonce=%llu&uuid=%llu",exchange->apikey,(long long)exchange_nonce(exchange),(long long)quoteid);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized orderstatus
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char payload[1024],*retstr = 0; cJSON *json;
    sprintf(payload,"https://bittrex.com/api/v1.1/market/cancel?apikey=%s&nonce=%llu&uuid=%llu",exchange->apikey,(long long)exchange_nonce(exchange),(long long)quoteid);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized cancelorder
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],market[64],*base,*rel,*retstr = 0; cJSON *json;
    sprintf(payload,"https://bittrex.com/api/v1.1/market/getopenorders?apikey=%s&nonce=%llu",exchange->apikey,(long long)exchange_nonce(exchange));
    if ( (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 )
    {
        sprintf(market,"%s-%s",rel,base);
        sprintf(payload + strlen(payload),"&market=%s",market);
    }
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized open orders
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],market[64],*base,*rel,*retstr = 0; cJSON *json;
    sprintf(payload,"https://bittrex.com/api/v1.1/account/getorderhistory?apikey=%s&nonce=%llu",exchange->apikey,(long long)exchange_nonce(exchange));
    if ( (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 )
    {
        sprintf(market,"%s-%s",rel,base);
        sprintf(payload + strlen(payload),"&market=%s",market);
    }
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized tradehistory
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
    sprintf(payload,"https://bittrex.com/api/v1.1/account/withdraw?apikey=%s&nonce=%llu&currency=%s&amount=%.4f&address=%s",exchange->apikey,(long long)exchange_nonce(exchange),base,amount,destaddr);
    if ( paymentid != 0 )
        sprintf(payload + strlen(payload),"&paymentid=%s",paymentid);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,payload)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized withdraw
}

struct exchange_funcs bittrex_funcs = EXCHANGE_FUNCS(bittrex,EXCHANGE_NAME);

#include "exchange_undefs.h"
