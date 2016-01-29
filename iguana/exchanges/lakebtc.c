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

#define EXCHANGE_NAME "lakebtc"
#define UPDATE lakebtc ## _price
#define SUPPORTS lakebtc ## _supports
#define SIGNPOST lakebtc ## _signpost
#define TRADE lakebtc ## _trade
#define ORDERSTATUS lakebtc ## _orderstatus
#define CANCELORDER lakebtc ## _cancelorder
#define OPENORDERS lakebtc ## _openorders
#define TRADEHISTORY lakebtc ## _tradehistory
#define BALANCES lakebtc ## _balances
#define PARSEBALANCE lakebtc ## _parsebalance
#define WITHDRAW lakebtc ## _withdraw
#define CHECKBALANCE lakebtc ## _checkbalance

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *quotes,int32_t maxdepth,cJSON *argjson)
{
    char url[1024];
    if ( strcmp(rel,"USD") == 0 )
        sprintf(url,"https://www.LakeBTC.com/api_v1/bcorderbook");
    else if ( strcmp(rel,"CNY") == 0 )
        sprintf(url,"https://www.LakeBTC.com/api_v1/bcorderbook_cny");
    else printf("illegal lakebtc pair.(%s/%s)\n",base,rel);
    return(exchanges777_standardprices(exchange,base,rel,url,quotes,0,0,maxdepth,0));
}

int32_t SUPPORTS(struct exchange_info *exchange,char *base,char *rel,cJSON *argjson)
{
    char *baserels[][2] = { {"btc","usd"}, {"btc","cny"} };
    int32_t polarity;
    polarity = baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel);
    printf("lakebtc.(%s %s) polarity.%d\n",base,rel,polarity);
    return(polarity);
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *payload,char *hdr1,uint64_t tonce)
{
    char hdr2[512],cmdbuf[1024],buf64[1024],hdr3[512],dest[1025],hdr4[512],*sig,*data = 0; cJSON *json;
    hdr2[0] = hdr3[0] = hdr4[0] = 0;
    json = 0;
    if ( (sig= hmac_sha1_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),hdr1)) != 0 )
    {
        sprintf(cmdbuf,"%s:%s",exchange->userid,sig);
        nn_base64_encode((void *)cmdbuf,strlen(cmdbuf),buf64,sizeof(buf64));
        sprintf(hdr1,"Authorization:Basic %s",buf64);
        sprintf(hdr2,"Json-Rpc-Tonce: %llu",(long long)tonce);
        if ( dotrade == 0 )
            data = exchange_would_submit(payload,hdr1,hdr2,hdr3,hdr4);
        else if ( (data= curl_post(&exchange->cHandle,"https://www.LakeBTC.com/api_v1",0,payload,hdr1,hdr2,hdr3,hdr4)) != 0 )
            json = cJSON_Parse(data);
    }
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(json);
}

/* LakeBTC provides trading JSON-RPC API interface. HMAC (Hash-based Message Authentication Code) is employed as our authentication mechanisms. You need at 0.1 BTC in your account to retrieve your private key.
 
 Besides your private key, the client needs to prepare the following attributes
 tonce (timestamp in microseconds, i.e., unixtime × 1000000, make sure your clock is correctly adjusted)
 accesskey (your registered email address at LakeBTC)
 requestmethod (post)
 id (JSON-RPC request id, an integer)
 method (JSON-RPC method)
 params (JSON-RPC parameters)
 Concatenate the above parameters with &, in that order. Parameters can be blank. For example, $signature =
 tonce=1389067414466757&accesskey=foo@bar.com&requestmethod=post&id=123&method=ticker&params=
 Create HMAC signature with your private key by using SHA1. $hash =
 hash_hmac('sha1', $signature, $privatetkey) #php
 Join your email and the hash signature with colon (:), and sign with Base64. $b64 =
 base64_encode("foo@bar.com:<hash>") #php YXRjQHF3amlhbi5jb206ZmEzM2UzYzg5MDZjg5MzdiYzFiYw==
 Set HTTP Header. Note tonce is the same as that in Step 2.
 Json-Rpc-Tonce: 1389067414466757 #HTTP HEADER
 Authorization: Basic YXRjQHF3amlhbi5jb206ZmEzM2UzYzg5MDZjg5MzdiYzFiYw== #HTTP HEADER
 POST params data in JSON format to this url:
 https://www.LakeBTC.com/api_v1
 API Methods
 getAccountInfo
 method=getAccountInfo
 params= (i.e., blank)

static CURL *cHandle;
char *data,*method,buf64[4096],paramstr[128],jsonbuf[1024],base[64],rel[64],pairstr[64],params[1024],dest[512],url[1024],cmdbuf[8192],*sig,hdr1[4096],hdr2[4096],buf[4096]; cJSON *json; uint64_t tonce,nonce,txid = 0;
*retstrp = 0;
params[0] = 0;
nonce = exchange_nonce(exchange);
tonce = (nonce * 1000000 + ((uint64_t)milliseconds() % 1000) * 1000);
if ( dir == 0 )
{
    method = "getAccountInfo";
    sprintf(buf,"tonce=%llu&accesskey=%s&requestmethod=post&id=1&method=%s&params=",(long long)tonce,exchange->userid,method);
    sprintf(jsonbuf,"{\"method\":\"%s\",\"params\":[\"%s\"],\"id\":1}",method,params);
}
else
{
    if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s_%s",dir,&price,&volume,base,rel)) == 0 )
    {
        printf("cant find baserel (%s/%s)\n",base,rel);
        return(0);
    }
    method = (dir > 0) ? "buyOrder" : "sellOrder";
    touppercase(rel);
    sprintf(paramstr,"%.2f,%.4f,%s",price,volume,rel);
    sprintf(buf,"tonce=%llu&accesskey=%s&requestmethod=post&id=1&method=%s&params=%s",(long long)tonce,exchange->userid,method,paramstr);
    sprintf(jsonbuf,"{\"method\":\"%s\",\"params\":[\"%s\"],\"id\":1}",method,paramstr);
}
if ( (sig= hmac_sha1_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),buf)) != 0 )
{
    sprintf(cmdbuf,"%s:%s",exchange->userid,sig);
    nn_base64_encode((void *)cmdbuf,strlen(cmdbuf),buf64,sizeof(buf64));
    sprintf(url,"https://www.lakebtc.com/api_v1");
    sprintf(hdr1,"Authorization:Basic %s",buf64);
    sprintf(hdr2,"Json-Rpc-Tonce: %llu",(long long)tonce);
    if ( (data= curl_post(&cHandle,url,0,jsonbuf,hdr1,hdr2,0,0)) != 0 )
    {
        //printf("submit cmd.(%s) [%s]\n",jsonbuf,data);
        if ( (json= cJSON_Parse(data)) != 0 )
        {
            txid = j64bits(json,"order_id");
            free_json(json);
        }
    } else fprintf(stderr,"submit err cmd.(%s)\n",cmdbuf);
        if ( retstrp != 0 )
            *retstrp = data;
            else if ( data != 0 )
                free(data);
                }
*/

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    //lakebtc.({"balance":{"BTC":0.1},"locked":{"BTC":0.0},"profile":{"email":"jameslee777@yahoo.com","id":"U137561934","btc_deposit_addres":"1RyKrNJjezeFfvYaicnJEozHfhWfYzbuh"}})
    char field[128],*str,*itemstr = 0; cJSON *obj=0,*item=0,*prof=0; double locked = 0;
    *balancep = 0.;
    strcpy(field,coinstr);
    touppercase(field);
    if ( argjson != 0 && (obj= jobj(argjson,"balance")) != 0 && (item= jobj(argjson,"locked")) != 0 && (prof= jobj(argjson,"profile")) != 0 )
    {
        *balancep = jdouble(obj,field);
        locked = jdouble(item,field);
        obj = cJSON_CreateObject();
        jaddstr(obj,"base",field);
        jaddnum(obj,"balance",*balancep);
        jaddnum(obj,"locked",locked);
        if ( (str= jstr(prof,"btc_deposit_addres")) != 0 )
            jaddstr(obj,"deposit_address",str);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],jsonbuf[1024],*method; uint64_t tonce;
    method = "getAccountInfo";
    tonce = (exchange_nonce(exchange) * 1000000 + ((uint64_t)OS_milliseconds() % 1000) * 1000);
    sprintf(payload,"tonce=%llu&accesskey=%s&requestmethod=post&id=1&method=%s&params=",(long long)tonce,exchange->userid,method);
    sprintf(jsonbuf,"{\"method\":\"%s\",\"params\":[\"%s\"],\"id\":1}",method,"");
    return(SIGNPOST(&exchange->cHandle,1,0,exchange,jsonbuf,payload,tonce));
}

#include "checkbalance.c"

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    char payload[1024],jsonbuf[1024],pairstr[64],paramstr[512],*extra,*method;
    cJSON *json; uint64_t tonce,txid = 0;
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    tonce = (exchange_nonce(exchange) * 1000000 + ((uint64_t)OS_milliseconds() % 1000) * 1000);
    if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s_%s",dir,&price,&volume,base,rel,argjson)) == 0 )
    {
        printf("cant find baserel (%s/%s)\n",base,rel);
        return(0);
    }
    method = (dir > 0) ? "buyOrder" : "sellOrder";
    touppercase(rel);
    sprintf(paramstr,"%.2f,%.4f,%s",price,volume,rel);
    sprintf(payload,"tonce=%llu&accesskey=%s&requestmethod=post&id=1&method=%s&params=%s",(long long)tonce,exchange->userid,method,paramstr);
    sprintf(jsonbuf,"{\"method\":\"%s\",\"params\":[\"%s\"],\"id\":1}",method,paramstr);
    if ( CHECKBALANCE(retstrp,dotrade,exchange,dir,base,rel,price,volume,argjson) == 0 && (json= SIGNPOST(&exchange->cHandle,dotrade,retstrp,exchange,jsonbuf,payload,tonce)) != 0 )
    {
        txid = j64bits(json,"order_id");
        free_json(json);
    }
    return(txid);
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char payload[1024],jsonbuf[1024],*method,*retstr = 0; cJSON *json; uint64_t tonce;
    method = "cancelOrder";
    tonce = (exchange_nonce(exchange) * 1000000 + ((uint64_t)OS_milliseconds() % 1000) * 1000);
    sprintf(jsonbuf,"{\"method\":\"%s\",\"params\":[\"%llu\"],\"id\":1}",method,(long long)quoteid);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,jsonbuf,tonce)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized cancelorder
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],jsonbuf[1024],*method,*retstr = 0; cJSON *json; uint64_t tonce;
    method = "getOrders";
    tonce = (exchange_nonce(exchange) * 1000000 + ((uint64_t)OS_milliseconds() % 1000) * 1000);
    sprintf(jsonbuf,"{\"method\":\"%s\",\"params\":[\"%s\"],\"id\":1}",method,"");
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,jsonbuf,tonce)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized open orders
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],jsonbuf[1024],timestr[64],*method,*retstr = 0;
    cJSON *json; uint64_t tonce; uint32_t starttime;
    method = "getTrades";
    if ( (starttime= juint(argjson,"start")) != 0 )
        sprintf(timestr,"%u",starttime);
    else timestr[0] = 0;
    tonce = (exchange_nonce(exchange) * 1000000 + ((uint64_t)OS_milliseconds() % 1000) * 1000);
    sprintf(jsonbuf,"{\"method\":\"%s\",\"params\":[%s],\"id\":1}",method,timestr);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,jsonbuf,tonce)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized tradehistory
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char *status,*retstr;
    status = OPENORDERS(exchange,argjson);
    if ( (retstr= exchange_extractorderid(0,status,quoteid,"id")) != 0 )
    {
        free(status);
        return(retstr);
    }
    free(status);
    return(clonestr("{\"error\":\"cant find quoteid\"}"));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"lakebtc doesnt seem to have withdraw api!\"}"));
}

struct exchange_funcs lakebtc_funcs = EXCHANGE_FUNCS(lakebtc,EXCHANGE_NAME);

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

