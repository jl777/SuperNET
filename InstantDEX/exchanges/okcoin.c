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

#define EXCHANGE_NAME "okcoin"
#define UPDATE prices777_ ## okcoin
#define SUPPORTS okcoin ## _supports
#define SIGNPOST okcoin ## _signpost
#define TRADE okcoin ## _trade
#define ORDERSTATUS okcoin ## _orderstatus
#define CANCELORDER okcoin ## _cancelorder
#define OPENORDERS okcoin ## _openorders
#define TRADEHISTORY okcoin ## _tradehistory
#define BALANCES okcoin ## _balances
#define PARSEBALANCE okcoin ## _parsebalance
#define WITHDRAW okcoin ## _withdraw
#define EXCHANGE_AUTHURL "https://www.okcoin.com/api/v1"
#define CHECKBALANCE okcoin ## _checkbalance

double UPDATE(struct prices777 *prices,int32_t maxdepth)
{
    if ( prices->url[0] == 0 )
        sprintf(prices->url,"https://www.okcoin.com/api/v1/depth.do?symbol=%s_%s",prices->lbase,prices->lrel);
    if ( strcmp(prices->rel,"USD") != 0 && strcmp(prices->rel,"BTC") != 0 )
    {
        fprintf(stderr,">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> FATAL ERROR OKCOIN.(%s) only supports USD\n",prices->url);
        printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> FATAL ERROR OKCOIN.(%s) only supports USD\n",prices->url);
        exit(-1);
        return(0);
    }
    return(prices777_standard("okcoin",prices->url,prices,0,0,maxdepth,0));
}

int32_t SUPPORTS(char *base,char *rel)
{
    char *baserels[][2] = { {"btc","usd"}, {"ltc","usd"} };
    return(baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel));
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *url,char *payload)
{
    char hdr1[512],hdr2[512],hdr3[512],hdr4[512],*data; cJSON *json;
    hdr1[0] = hdr2[0] = hdr3[0] = hdr4[0] = 0;
    json = 0;
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
/*
static CURL *cHandle;
char *data,*path,*typestr,*extra,pricestr[64],base[64],rel[64],pairstr[64],url[1024],cmdbuf[8192],buf[512],digest[33]; cJSON *json; uint64_t nonce,txid = 0;
nonce = exchange_nonce(exchange);
if ( (extra= *retstrp) != 0 )
*retstrp = 0;
if ( dir == 0 )
{
    path = "userinfo.do";
    sprintf(buf,"api_key=%s&secret_key=%s",exchange->apikey,exchange->apisecret);
    calc_md5(digest,buf,(int32_t)strlen(buf));
    touppercase(digest);
    sprintf(cmdbuf,"api_key=%s&sign=%s",exchange->apikey,digest);
}
else
{
    path = "trade.do";
    if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s_%s",dir,&price,&volume,base,rel)) == 0 )
    {
        printf("cant find baserel (%s/%s)\n",base,rel);
        return(0);
    }
    if ( extra != 0 && strcmp(extra,"market") == 0 )
        typestr = (dir > 0) ? "buy_market" : "sell_market", sprintf(pricestr,"&price=%.2f",price); // docs say market orders put volume in price
        else typestr = (dir > 0) ? "buy" : "sell", sprintf(pricestr,"&price=%.2f",price);
            sprintf(buf,"amount=%.4f&api_key=%s%ssymbol=%s&type=%s&secret_key=%s",volume,exchange->apikey,pricestr,pairstr,typestr,exchange->apisecret);
            calc_md5(digest,buf,(int32_t)strlen(buf));
            touppercase(digest);
            sprintf(cmdbuf,"amount=%.4f&api_key=%s%s&symbol=%s&type=%s&sign=%s",volume,exchange->apikey,pricestr,pairstr,typestr,digest);
            }
//printf("MD5.(%s)\n",buf);
sprintf(url,"https://www.okcoin.com/api/v1/%s",path);
if ( (data= curl_post(&cHandle,url,0,cmdbuf,0,0,0,0)) != 0 ) // "{\"Content-type\":\"application/x-www-form-urlencoded\"}","{\"User-Agent\":\"OKCoin Javascript API Client\"}"
{
    //printf("submit cmd.(%s) [%s]\n",cmdbuf,data);
    if ( (json= cJSON_Parse(data)) != 0 )
    {
        txid = j64bits(json,"order_id");
        free_json(json);
    }
} else fprintf(stderr,"submit err cmd.(%s)\n",cmdbuf);
*/

cJSON *okcoin_issue_auth(void **cHandlep,struct exchange_info *exchange,char *method,char *buf)
{
    char payload[1024],tmp[1024],digest[512],url[512];
    sprintf(tmp,"api_key=%s%s",exchange->apikey,buf);
    
    sprintf(payload,"%s&secret_key=%s",tmp,exchange->apisecret);
    //printf("tmp.(%s) payload.(%s)\n",tmp,payload);
    calc_md5(digest,payload,(int32_t)strlen(payload));
    touppercase(digest);
    sprintf(payload,"%s&sign=%s",tmp,digest);
    sprintf(url,"%s/%s",EXCHANGE_AUTHURL,method);
    return(SIGNPOST(cHandlep,1,0,exchange,url,payload));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    //okcoin.({"info":{"funds":{"asset":{"net":"0","total":"0"},"free":{"btc":"0","ltc":"0","usd":"0"},"freezed":{"btc":"0","ltc":"0","usd":"0"}}},"result":true})
    char field[128],*itemstr = 0; cJSON *obj,*item,*avail,*locked; double lockval = 0;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    if ( exchange->balancejson != 0 && (obj= jobj(exchange->balancejson,"info")) != 0 && (item= jobj(obj,"funds")) != 0 )
    {
        if ( (avail= jobj(item,"free")) != 0 )
            *balancep = jdouble(avail,field);
        if ( (locked= jobj(item,"freezed")) != 0 )
            lockval = jdouble(locked,field);
        obj = cJSON_CreateObject();
        touppercase(field);
        jaddstr(obj,"base",field);
        jaddnum(obj,"balance",*balancep);
        jaddnum(obj,"locked",lockval);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

cJSON *BALANCES(void **cHandlep,struct exchange_info *exchange)
{
    return(okcoin_issue_auth(cHandlep,exchange,"userinfo.do",""));
}

#include "checkbalance.c"

uint64_t TRADE(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    char payload[1024],buf[1024],url[1024],digest[512],pairstr[512],pricestr[64],*extra,*typestr;
    cJSON *json; uint64_t txid = 0;
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s_%s",dir,&price,&volume,base,rel)) == 0 )
    {
        printf("cant find baserel (%s/%s)\n",base,rel);
        return(0);
    }
    if ( extra != 0 && strcmp(extra,"market") == 0 )
        typestr = (dir > 0) ? "buy_market" : "sell_market", sprintf(pricestr,"&price=%.2f",price); // docs say market orders put volume in price
    else typestr = (dir > 0) ? "buy" : "sell";
    sprintf(pricestr,"&price=%.2f",price);
    sprintf(buf,"amount=%.4f&api_key=%s%ssymbol=%s&type=%s&secret_key=%s",volume,exchange->apikey,pricestr,pairstr,typestr,exchange->apisecret);
    calc_md5(digest,buf,(int32_t)strlen(buf));
    touppercase(digest);
    sprintf(payload,"amount=%.4f&api_key=%s%s&symbol=%s&type=%s&sign=%s",volume,exchange->apikey,pricestr,pairstr,typestr,digest);
    sprintf(url,"%s/%s",EXCHANGE_AUTHURL,"trade.do");
    if ( CHECKBALANCE(retstrp,dotrade,exchange,dir,base,rel,price,volume) == 0 && (json= SIGNPOST(cHandlep,dotrade,retstrp,exchange,url,payload)) != 0 )
    {
        txid = j64bits(json,"order_id");
        free_json(json);
    }
    return(txid);
}

char *ORDERSTATUS(void **cHandlep,struct exchange_info *exchange,cJSON *argjson,uint64_t quoteid)
{
    char buf[64];
    sprintf(buf,"&symbol=btc_usd&order_id=%llu",(long long)quoteid);
    return(jprint(okcoin_issue_auth(cHandlep,exchange,"order_info.do",buf),1));
}

char *CANCELORDER(void **cHandlep,struct exchange_info *exchange,cJSON *argjson,uint64_t quoteid)
{
    char buf[64];
    sprintf(buf,"&symbol=btc_usd&order_id=%llu",(long long)quoteid);
    return(jprint(okcoin_issue_auth(cHandlep,exchange,"cancel_order.do",buf),1));
}

char *OPENORDERS(void **cHandlep,struct exchange_info *exchange,cJSON *argjson)
{
    return(jprint(okcoin_issue_auth(cHandlep,exchange,"orders_info.do",""),1));
}

char *TRADEHISTORY(void **cHandlep,struct exchange_info *exchange,cJSON *argjson)
{
    return(jprint(okcoin_issue_auth(cHandlep,exchange,"orders_history.do","&status=1&symbol=btc_usd&current_page=0&page_length=200"),1));
}

char *WITHDRAW(void **cHandlep,struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],*base,*destaddr,*method,*tradepassword; double amount;
    if ( (base= jstr(argjson,"base")) == 0 || strcmp(base,"BTC") != 0 )
        return(clonestr("{\"error\":\"base not specified or base != BTC\"}"));
    if ( (destaddr= jstr(argjson,"destaddr")) == 0 )
        return(clonestr("{\"error\":\"destaddr not specified\"}"));
    if ( (amount= jdouble(argjson,"amount")) < SMALLVAL )
        return(clonestr("{\"error\":\"amount not specified\"}"));
    if ( (tradepassword= jstr(argjson,"tradepassword")) == 0 )
        return(clonestr("{\"error\":\"tradepassword not specified\"}"));
    method = "withdraw_coin";
    sprintf(payload,"&symbol=btc_usd&chargefee=0.0001&withdraw_address=%s&withdraw_amount=%.4f&trade_pwd=%s",destaddr,amount,tradepassword);
    return(jprint(okcoin_issue_auth(cHandlep,exchange,method,payload),1));
}

struct exchange_funcs okcoin_funcs = EXCHANGE_FUNCS(okcoin,EXCHANGE_NAME);

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

