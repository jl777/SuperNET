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

#define EXCHANGE_NAME "bitfinex"
#define UPDATE bitfinex ## _price
#define SUPPORTS bitfinex ## _supports
#define SIGNPOST bitfinex ## _signpost
#define TRADE bitfinex ## _trade
#define ORDERSTATUS bitfinex ## _orderstatus
#define CANCELORDER bitfinex ## _cancelorder
#define OPENORDERS bitfinex ## _openorders
#define TRADEHISTORY bitfinex ## _tradehistory
#define BALANCES bitfinex ## _balances
#define PARSEBALANCE bitfinex ## _parsebalance
#define WITHDRAW bitfinex ## _withdraw
#define CHECKBALANCE bitfinex ## _checkbalance

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *quotes,int32_t maxdepth,cJSON *argjson)
{
    char url[1024];
    sprintf(url,"https://api.bitfinex.com/v1/book/%s%s",base,rel);
    return(exchanges777_standardprices(exchange,base,rel,url,quotes,"price","amount",maxdepth,0));
}

int32_t SUPPORTS(struct exchange_info *exchange,char *base,char *rel,cJSON *argjson)
{
    char *baserels[][2] = { {"btc","usd"}, {"ltc","usd"}, {"ltc","btc"} };
    return(baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    //[[{"type":"deposit","currency":"btc","amount":"0.0","available":"0.0"},{"type":"deposit","currency":"usd","amount":"0.0","available":"0.0"},{"type":"exchange","currency":"btc","amount":"0.01065851","available":"0.01065851"},{"type":"exchange","currency":"usd","amount":"23386.37278962","available":"0.00378962"},{"type":"trading","currency":"btc","amount":"0.0","available":"0.0"},{"type":"trading","currency":"usd","amount":"0.0","available":"0.0"}]]
    int32_t i,n,ind; char field[64],*str,*typestr,*itemstr = 0; cJSON *item,*obj,*array; double amounts[3],avail[3],val0,val1;
    *balancep = 0.;
    strcpy(field,coinstr), tolowercase(field);
    memset(amounts,0,sizeof(amounts));
    memset(avail,0,sizeof(avail));
    if ( argjson != 0 && is_cJSON_Array(argjson) != 0 && (n= cJSON_GetArraySize(argjson)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            if ( (item= jitem(argjson,i)) != 0 )
            {
                if ( (str= jstr(item,"currency")) != 0 && strcmp(field,str) == 0 )
                {
                    val0 = jdouble(item,"amount");
                    val1 = jdouble(item,"available");
                    if ( (typestr= jstr(item,"type")) != 0 )
                    {
                        if ( strcmp(typestr,"deposit") == 0 )
                            ind = 0;
                        else if ( strcmp(typestr,"exchange") == 0 )
                            ind = 1;
                        else if ( strcmp(typestr,"trading") == 0 )
                            ind = 2;
                        else ind = -1;
                        if ( ind >= 0 )
                        {
                            amounts[ind] = val0;
                            avail[ind] = val1;
                        }
                    }
                }
            }
        }
        if ( (obj= cJSON_CreateObject()) != 0 )
        {
            touppercase(field);
            *balancep = avail[0] + avail[1] + avail[2];
            jaddstr(obj,"base",field);
            jaddnum(obj,"balance",*balancep);
            jaddnum(obj,"total",amounts[0]+amounts[1]+amounts[2]);
            array = cJSON_CreateArray(), jaddinum(array,avail[0]), jaddinum(array,amounts[0]), jadd(obj,"deposit",array);
            array = cJSON_CreateArray(), jaddinum(array,avail[1]), jaddinum(array,amounts[1]), jadd(obj,"exchange",array);
            array = cJSON_CreateArray(), jaddinum(array,avail[2]), jaddinum(array,amounts[2]), jadd(obj,"trading",array);
            itemstr = jprint(obj,1);
        }
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *payload,char *method)
{
    char dest[1025],url[1024],hdr1[512],hdr2[512],hdr3[512],hdr4[512],req[1024],*sig,*data = 0; cJSON *json;
    hdr1[0] = hdr2[0] = hdr3[0] = hdr4[0] = 0;
    json = 0;
    nn_base64_encode((void *)payload,strlen(payload),req,sizeof(req));
    if ( (sig= hmac_sha384_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),req)) != 0 )
    {
        sprintf(hdr1,"X-BFX-APIKEY:%s",exchange->apikey);
        sprintf(hdr2,"X-BFX-PAYLOAD:%s",req);
        sprintf(hdr3,"X-BFX-SIGNATURE:%s",sig);
        //printf("req.(%s) H0.(%s) H1.(%s) H2.(%s)\n",req,hdr1,hdr2,hdr3);
        sprintf(url,"https://api.bitfinex.com/v1/%s",method);
        if ( dotrade == 0 )
            data = exchange_would_submit(req,hdr1,hdr2,hdr3,hdr4);
        else if ( (data= curl_post(&exchange->cHandle,url,0,req,hdr1,hdr2,hdr3,hdr4)) != 0 )
            json = cJSON_Parse(data);
        if ( retstrp != 0 )
            *retstrp = data;
        else if ( data != 0 )
            free(data);
    }
    return(json);
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],*method;
    method = "balances";
    sprintf(payload,"{\"request\":\"/v1/%s\",\"nonce\":\"%llu\"}",method,(long long)exchange_nonce(exchange));
    return(SIGNPOST(&exchange->cHandle,1,0,exchange,payload,method));
}

#include "checkbalance.c"

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    char payload[1024],pairstr[512],*typestr,*method,*extra; cJSON *json; uint64_t txid = 0;
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s%s",dir,&price,&volume,base,rel,argjson)) == 0 )
    {
        printf("cant find baserel (%s/%s)\n",base,rel);
        return(0);
    }
    method = "order/new";
    //Either "market" / "limit" / "stop" / "trailing-stop" / "fill-or-kill" / "exchange market" / "exchange limit" / "exchange stop" / "exchange trailing-stop" / "exchange fill-or-kill". (type starting by "exchange " are exchange orders, others are margin trading orders)
    if ( (typestr= extra) == 0 )
        typestr = "exchange limit";
    sprintf(payload,"{\"request\":\"/v1/%s\",\"nonce\":\"%llu\",\"exchange\":\"bitfinex\",\"side\":\"%s\",\"type\":\"%s\",\"price\":\"%.8f\",\"amount\":\"%.8f\",\"symbol\":\"%s\"}",method,(long long)exchange_nonce(exchange),dir>0?"buy":"sell",typestr,price,volume,pairstr);
    if ( CHECKBALANCE(retstrp,dotrade,exchange,dir,base,rel,price,volume,argjson) == 0 && (json= SIGNPOST(&exchange->cHandle,dotrade,retstrp,exchange,payload,method)) != 0 )
    {
        if ( (txid= j64bits(json,"order_id")) == 0 )
        {
            if ( dir != 0 )
                printf("bitfinex: no txid error\n");
        }
        free_json(json);
    }
    return(txid);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char payload[1024],*method,*retstr = 0; cJSON *json;
    method = "order/status";
    sprintf(payload,"{\"request\":\"/v1/%s\",\"nonce\":\"%llu\",\"order_id\":%llu}",method,(long long)exchange_nonce(exchange),(long long)quoteid);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,method)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized orderstatus
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char payload[1024],*method,*retstr = 0; cJSON *json;
    method = "order/cancel";
    sprintf(payload,"{\"request\":\"/v1/%s\",\"nonce\":\"%llu\",\"order_id\":%llu}",method,(long long)exchange_nonce(exchange),(long long)quoteid);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,method)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized cancelorder
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],*method,*retstr = 0; cJSON *json;
    method = "orders";
    sprintf(payload,"{\"request\":\"/v1/%s\",\"nonce\":\"%llu\"}",method,(long long)exchange_nonce(exchange));
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,method)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized open orders
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],baserel[16],*method,*base,*rel,*retstr = 0; uint32_t timestamp; cJSON *json;
    method = "mytrades";
    base = jstr(argjson,"base");
    rel = jstr(argjson,"rel");
    if ( base == 0 || rel == 0 )
    {
        base = "BTC";
        rel = "USD";
    }
    sprintf(baserel,"%s%s",base,rel);
    timestamp = juint(argjson,"start");
    sprintf(payload,"{\"request\":\"/v1/%s\",\"nonce\":\"%llu\",\"symbol\":\"%s\",\"timestamp\":%u}",method,(long long)exchange_nonce(exchange),baserel,timestamp);
    //printf("TRADEHISTORY.(%s)\n",payload);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,method)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized tradehistory
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    char payload[1024],*method,*type,*retstr = 0; cJSON *json;
    if ( base == 0 || base[0] == 0 )
        return(clonestr("{\"error\":\"base not specified\"}"));
    if ( destaddr == 0 || destaddr[0] == 0 )
        return(clonestr("{\"error\":\"destaddr not specified\"}"));
    if ( amount < SMALLVAL )
        return(clonestr("{\"error\":\"amount not specified\"}"));
    if ( base == 0 )
        base = "bitcoin";
    else if ( strcmp(base,"BTC") == 0 )
        base = "bitcoin";
    else if ( strcmp(base,"LTC") == 0 )
        base = "litecoin";
    else if ( strcmp(base,"DRK") == 0 )
        base = "darkcoin";
    else return(clonestr("{\"error\":\"invalid base specified\"}"));
    if ( (type= jstr(argjson,"extra")) == 0 )
        type = "exchange";
    else if ( strcmp(type,"exchange") != 0 && strcmp(type,"trading") != 0 && strcmp(type,"deposit") != 0 )
        return(clonestr("{\"error\":\"invalid wallet type specified\"}"));
    method = "withdraw";
    sprintf(payload,"{\"request\":\"/v1/%s\",\"nonce\":\"%llu\",\"amount\":\"%.6f\",\"withdraw_type\":\"%s\",\"walletselected\":\"%s\",\"address\":\"%s\"}",method,(long long)exchange_nonce(exchange),amount,base,type,destaddr);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,method)) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized withdraw
}

struct exchange_funcs bitfinex_funcs = EXCHANGE_FUNCS(bitfinex,EXCHANGE_NAME);

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
