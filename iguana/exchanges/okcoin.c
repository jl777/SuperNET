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

#define EXCHANGE_NAME "okcoin"
#define UPDATE okcoin ## _price
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

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *quotes,int32_t maxdepth,double commission,cJSON *argjson)
{
    char url[1024],lrel[16],lbase[16];
    strcpy(lrel,rel), strcpy(lbase,base);
    tolowercase(lrel), tolowercase(lbase);
    sprintf(url,"https://www.okcoin.com/api/v1/depth.do?symbol=%s_%s",lbase,lrel);
    if ( strcmp(rel,"USD") != 0 && strcmp(rel,"BTC") != 0 )
    {
        fprintf(stderr,">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> FATAL ERROR OKCOIN.(%s) only supports USD\n",url);
        printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> FATAL ERROR OKCOIN.(%s) only supports USD\n",url);
        exit(-1);
        return(0);
    }
    return(exchanges777_standardprices(exchange,commission,base,rel,url,quotes,0,0,maxdepth,0));
}

int32_t SUPPORTS(struct exchange_info *exchange,char *base,char *rel,cJSON *argjson)
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
    else if ( (data= curl_post(&exchange->cHandle,url,0,payload,hdr1,hdr2,hdr3,hdr4)) != 0 )
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
    return(SIGNPOST(&exchange->cHandle,1,0,exchange,url,payload));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    //okcoin.({"info":{"funds":{"asset":{"net":"0","total":"0"},"free":{"btc":"0","ltc":"0","usd":"0"},"freezed":{"btc":"0","ltc":"0","usd":"0"}}},"result":true})
    char field[128],*itemstr = 0; cJSON *obj,*item,*avail,*locked; double lockval = 0;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    if ( argjson != 0 && (obj= jobj(argjson,"info")) != 0 && (item= jobj(obj,"funds")) != 0 )
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

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    return(okcoin_issue_auth(&exchange->cHandle,exchange,"userinfo.do",""));
}

#include "checkbalance.c"

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    char payload[1024],buf[1024],url[1024],digest[512],pairstr[512],pricestr[64],*extra,*typestr;
    cJSON *json; uint64_t txid = 0;
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s_%s",dir,&price,&volume,base,rel,argjson)) == 0 )
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
    if ( CHECKBALANCE(retstrp,dotrade,exchange,dir,base,rel,price,volume,argjson) == 0 && (json= SIGNPOST(&exchange->cHandle,dotrade,retstrp,exchange,url,payload)) != 0 )
    {
        txid = j64bits(json,"order_id");
        free_json(json);
    }
    return(txid);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char buf[64];
    sprintf(buf,"&symbol=btc_usd&order_id=%llu",(long long)quoteid);
    return(jprint(okcoin_issue_auth(&exchange->cHandle,exchange,"order_info.do",buf),1));
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char buf[64];
    sprintf(buf,"&symbol=btc_usd&order_id=%llu",(long long)quoteid);
    return(jprint(okcoin_issue_auth(&exchange->cHandle,exchange,"cancel_order.do",buf),1));
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    return(jprint(okcoin_issue_auth(&exchange->cHandle,exchange,"orders_info.do",""),1));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    return(jprint(okcoin_issue_auth(&exchange->cHandle,exchange,"orders_history.do","&status=1&symbol=btc_usd&current_page=0&page_length=200"),1));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    char payload[1024],*method,*tradepassword;
    if ( base == 0 || base[0] == 0 )
        return(clonestr("{\"error\":\"base not specified\"}"));
    if ( destaddr == 0 || destaddr[0] == 0 )
        return(clonestr("{\"error\":\"destaddr not specified\"}"));
    if ( amount < SMALLVAL )
        return(clonestr("{\"error\":\"amount not specified\"}"));
    if ( (tradepassword= jstr(argjson,"tradepassword")) == 0 )
        tradepassword = exchange->tradepassword;
    if ( tradepassword == 0 || tradepassword[0] == 0 )
        return(clonestr("{\"error\":\"tradepassword not specified\"}"));
    method = "withdraw_coin";
    sprintf(payload,"&symbol=btc_usd&chargefee=0.0001&withdraw_address=%s&withdraw_amount=%.4f&trade_pwd=%s",destaddr,amount,tradepassword);
    return(jprint(okcoin_issue_auth(&exchange->cHandle,exchange,method,payload),1));
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

