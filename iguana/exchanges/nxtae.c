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

#define EXCHANGE_NAME "nxtae"
#define UPDATE nxtae ## _price
#define SUPPORTS nxtae ## _supports
#define SIGNPOST nxtae ## _signpost
#define TRADE nxtae ## _trade
#define ORDERSTATUS nxtae ## _orderstatus
#define CANCELORDER nxtae ## _cancelorder
#define OPENORDERS nxtae ## _openorders
#define TRADEHISTORY nxtae ## _tradehistory
#define BALANCES nxtae ## _balances
#define PARSEBALANCE nxtae ## _parsebalance
#define WITHDRAW nxtae ## _withdraw
#define CHECKBALANCE nxtae ## _checkbalance
#define ALLPAIRS nxtae ## _allpairs
#define FUNCS nxtae ## _funcs
#define BASERELS nxtae ## _baserels

static char *BASERELS[][2] = { {"btc","nxt"}, {"btc","btcd"}, {"btc","ltc"}, {"btc","vrc"}, {"btc","doge"} };
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
    char url[1024],req[1024],md5secret[128],tmp[1024],dest[1025],hdr1[512],hdr2[512],hdr3[512],hdr4[512],*sig,*data = 0;
    cJSON *json; uint64_t nonce;
    hdr1[0] = hdr2[0] = hdr3[0] = hdr4[0] = 0;
    json = 0;
    nonce = exchange_nonce(exchange) * 1000 + ((uint64_t)OS_milliseconds() % 1000);
    sprintf(tmp,"%llu%s%s",(long long)nonce,exchange->userid,exchange->apikey);
    calc_md5(md5secret,exchange->apisecret,(int32_t)strlen(exchange->apisecret));
    if ( (sig= hmac_sha256_str(dest,md5secret,(int32_t)strlen(md5secret),tmp)) != 0 )
    {
        sprintf(req,"{\"key\":\"%s\",%s\"nonce\":%llu,\"signature\":\"%s\"}",exchange->apikey,payload,(long long)nonce,sig);
        sprintf(hdr1,"Content-Type:application/json");
        sprintf(hdr2,"charset=utf-8");
        sprintf(hdr3,"Content-Length:%ld",(long)strlen(req));
        sprintf(url,"https://api.quadrigacx.com/v2/%s",path);
        if ( dotrade == 0 )
            data = exchange_would_submit(req,hdr1,hdr2,hdr3,hdr4);
        else if ( (data= curl_post(&exchange->cHandle,url,0,req,hdr1,hdr2,hdr3,hdr4)) != 0 )
            json = cJSON_Parse(data);
    }
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(json);
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    //[{"btc_available":"0.00000000","btc_reserved":"0.00000000","btc_balance":"0.00000000","cad_available":"0.00","cad_reserved":"0.00","cad_balance":"0.00","usd_available":"0.00","usd_reserved":"0.00","usd_balance":"0.00","xau_available":"0.000000","xau_reserved":"0.000000","xau_balance":"0.000000","fee":"0.5000"}]
    char field[128],*str,*itemstr = 0; cJSON *obj; double reserv,total;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    strcat(field,"_available");
    if ( argjson != 0 && (str= jstr(argjson,field)) != 0 )
    {
        *balancep = jdouble(argjson,field);
        strcpy(field,coinstr), tolowercase(field), strcat(field,"_reserved");
        reserv = jdouble(argjson,field);
        strcpy(field,coinstr), tolowercase(field), strcat(field,"_balance");
        total = jdouble(argjson,field);
        obj = cJSON_CreateObject();
        jaddnum(obj,"balance",*balancep);
        jaddnum(obj,"locked_balance",reserv);
        jaddnum(obj,"total",total);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    return(SIGNPOST(&exchange->cHandle,1,0,exchange,"","balance"));
}

#include "checkbalance.c"

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    char payload[1024],pairstr[64],*extra,*path; cJSON *json; uint64_t txid = 0;
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s_%s",dir,&price,&volume,base,rel,argjson)) == 0 )
    {
        printf("cant find baserel (%s/%s)\n",base,rel);
        return(0);
    }
    path = (dir > 0) ? "buy" : "sell";
    //key - API key
    //signature - signature
    //nonce - nonce
    //amount - amount of major currency
    //price - price to buy at
    //book - optional, if not specified, will default to btc_cad
    sprintf(payload,"\"amount\":%.6f,\"price\":%.3f,\"book\":\"%s_%s\",",volume,price,base,rel);
    if ( CHECKBALANCE(retstrp,dotrade,exchange,dir,base,rel,price,volume,argjson) == 0 && (json= SIGNPOST(&exchange->cHandle,dotrade,retstrp,exchange,payload,path)) != 0 )
    {
        // parse json and set txid
        free_json(json);
    }
    return(txid);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char buf[64];
    sprintf(buf,"\"id\":%llu,",(long long)quoteid);
    return(jprint(SIGNPOST(&exchange->cHandle,1,0,exchange,buf,"lookup_order"),1));
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char buf[64];
    sprintf(buf,"\"id\":%llu,",(long long)quoteid);
    return(jprint(SIGNPOST(&exchange->cHandle,1,0,exchange,buf,"cancel_order"),1));
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    return(jprint(SIGNPOST(&exchange->cHandle,1,0,exchange,"","open_orders"),1));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    return(jprint(SIGNPOST(&exchange->cHandle,1,0,exchange,"","user_transactions"),1));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    uint64_t txid,assetid,assetoshis; cJSON *retjson = cJSON_CreateObject();
    if ( is_validNXT(destaddr) < 0 )
        jaddstr(retjson,"error","invalid NXT address");
    else if ( (assetid= is_MGW_asset(base)) == 0 )
        jaddstr(retjson,"error","invalid MGW asset");
    else if ( is_validNXT_amount(base) < 0 )
        jaddstr(retjson,"error","invalid NXT asset");
    else if ( (txid= MGW_redeem(passphrase,assetid,assetoshis,destaddr)) != 0 )
    {
        jaddstr(retjson,"result","success");
        jadd64bits(retjson,"redeemtxid",txid);
    } else jaddstr(retjson,"error","couldnt submit MGW redeem");
    return(jprint(retjson,1));
}

struct exchange_funcs nxtae_funcs = EXCHANGE_FUNCS(nxtae,EXCHANGE_NAME);

#include "exchange_undefs.h"
