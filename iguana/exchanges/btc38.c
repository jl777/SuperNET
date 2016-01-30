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

#define EXCHANGE_NAME "btc38"
#define UPDATE btc38 ## _price
#define SUPPORTS btc38 ## _supports
#define SIGNPOST btc38 ## _signpost
#define TRADE btc38 ## _trade
#define ORDERSTATUS btc38 ## _orderstatus
#define CANCELORDER btc38 ## _cancelorder
#define OPENORDERS btc38 ## _openorders
#define TRADEHISTORY btc38 ## _tradehistory
#define BALANCES btc38 ## _balances
#define PARSEBALANCE btc38 ## _parsebalance
#define WITHDRAW btc38 ## _withdraw
#define EXCHANGE_AUTHURL "http://www.btc38.com/trade/t_api"
#define CHECKBALANCE btc38 ## _checkbalance
#define ALLPAIRS btc38 ## _allpairs
#define FUNCS btc38 ## _funcs

char *btc38_cnypairs[] = { "BTC", "LTC", "DOGE", "XRP", "BTS", "XLM", "NXT", "BLK", "BC", "VPN", "BILS", "BOST", "PPC", "APC", "ZCC", "XPM", "DGC", "MEC", "WDC", "QRK", "BEC", "ANC", "UNC", "RIC", "SRC", "TAG" };
char *btc38_btcpairs[] = { "TMC", "LTC", "DOGE", "XRP", "BTS", "XEM", "XCN", "VOOT", "SYS", "NRS", "NAS", "SYNC", "MED", "EAC" };

char *ALLPAIRS(struct exchange_info *exchange,cJSON *argjson)
{
    int32_t i; char str[65]; cJSON *json,*item,*array = cJSON_CreateArray();
    for (i=0; i<sizeof(btc38_btcpairs)/sizeof(*btc38_btcpairs); i++)
    {
        item = cJSON_CreateArray();
        jaddistr(item,uppercase_str(str,btc38_btcpairs[i]));
        jaddistr(item,"BTC");
        jaddi(array,item);
    }
    for (i=0; i<sizeof(btc38_cnypairs)/sizeof(*btc38_cnypairs); i++)
    {
        item = cJSON_CreateArray();
        jaddistr(item,uppercase_str(str,btc38_cnypairs[i]));
        jaddistr(item,"CNY");
        jaddi(array,item);
    }
    json = cJSON_CreateObject();
    jadd(json,"result",array);
    return(jprint(json,1));
}

int32_t SUPPORTS(struct exchange_info *exchange,char *_base,char *_rel,cJSON *argjson)
{
    int32_t i; char base[64],rel[64];
    strcpy(base,_base), strcpy(rel,_rel);
    touppercase(base), touppercase(rel);
    if ( strlen(base) > 5 || strlen(rel) > 5 )
        return(0);
    if ( strcmp(base,"BTC") == 0 && strcmp(rel,"CNY") == 0 )
        return(1);
    else if ( strcmp(base,"CNY") == 0 && strcmp(rel,"BTC") == 0 )
        return(-1);
    else if ( strcmp(base,"BTC") == 0 )
    {
        for (i=0; i<sizeof(btc38_btcpairs)/sizeof(*btc38_btcpairs); i++)
            if ( strcmp(btc38_btcpairs[i],rel) == 0 )
                return(-1);
    }
    else if ( strcmp(rel,"BTC") == 0 )
    {
        for (i=0; i<sizeof(btc38_btcpairs)/sizeof(*btc38_btcpairs); i++)
            if ( strcmp(btc38_btcpairs[i],base) == 0 )
                return(1);
    }
    else if ( strcmp(base,"CNY") == 0 )
    {
        for (i=0; i<sizeof(btc38_cnypairs)/sizeof(*btc38_cnypairs); i++)
            if ( strcmp(btc38_cnypairs[i],rel) == 0 )
                return(-1);
    }
    else if ( strcmp(rel,"CNY") == 0 )
    {
        for (i=0; i<sizeof(btc38_cnypairs)/sizeof(*btc38_cnypairs); i++)
            if ( strcmp(btc38_cnypairs[i],base) == 0 )
                return(1);
    }
    printf("BTC38 doesnt support (%s/%s)\n",base,rel);
    return(0);
}

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *quotes,int32_t maxdepth,double commission,cJSON *argjson)
{
    char url[1024],lrel[16],lbase[16];
    strcpy(lrel,rel), strcpy(lbase,base);
    tolowercase(lrel), tolowercase(lbase);
    if ( strcmp(lbase,"cny") == 0 && strcmp(lrel,"btc") == 0 )
        sprintf(url,"http://api.btc38.com/v1/depth.php?c=%s&mk_type=%s","btc","cny");
    else sprintf(url,"http://api.btc38.com/v1/depth.php?c=%s&mk_type=%s",lbase,lrel);
    return(exchanges777_standardprices(exchange,commission,base,rel,url,quotes,0,0,maxdepth,0));
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *payload,char *path)
{
    char cmdbuf[2048],url[1024],buf[1024],hdr1[512],hdr2[512],hdr3[512],hdr4[512],digest[33],*data;
    cJSON *json; uint64_t nonce;
    hdr1[0] = hdr2[0] = hdr3[0] = hdr4[0] = 0;
    json = 0;
    nonce = exchange_nonce(exchange);
    sprintf(buf,"%s_%s_%s_%llu",exchange->apikey,exchange->userid,exchange->apisecret,(long long)nonce);
    //printf("MD5.(%s)\n",buf);
    calc_md5(digest,buf,(int32_t)strlen(buf));
    sprintf(cmdbuf,"key=%s&time=%llu&md5=%s%s",exchange->apikey,(long long)nonce,digest,payload);
    sprintf(url,"%s/%s",EXCHANGE_AUTHURL,path);
    if ( dotrade == 0 )
        data = exchange_would_submit(payload,hdr1,hdr2,hdr3,hdr4);
    else if ( (data= curl_post(&exchange->cHandle,url,0,cmdbuf,hdr1,hdr2,hdr3,hdr4)) != 0 )
        json = cJSON_Parse(data);
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(json);
}

/* $ Stamp = $ date-> getTimestamp ();
 type, 1 for the purchase of Entry, 2 entry order to sell, can not be empty / the type of the order
 
 $ Mdt = "_ public here to write here write here to write user ID_ private _" $ stamp.;
 $ Mdt = md5 ($ mdt);
 
 $ Data = array ("key" => "here to write public", "time" => $ stamp, "md5" => $ mdt, "type" => 1, "mk_type" => "cny",
 "Price" => "0.0001", "amount" => "100", "coinname" => "XRP");
 // $ Data_string = json_encode ($ data);
 $ Ch = curl_init ();
 curl_setopt ($ ch, CURLOPT_URL, 'http://www.btc38.com/trade/t_api/submitOrder.php');
 curl_setopt ($ ch, CURLOPT_POST, 1);
 curl_setopt ($ ch, CURLOPT_POSTFIELDS, $ data);
 curl_setopt ($ ch, CURLOPT_RETURNTRANSFER, 1);
 curl_setopt ($ ch, CURLOPT_HEADER, 0);  */
/*
static CURL *cHandle;
char *data,*path,url[1024],cmdbuf[8192],buf[512],digest[33],market[16],base[64],rel[64],coinname[16],fmtstr[512],*pricefmt,*volfmt = "%.3f";
cJSON *json,*resultobj; uint64_t nonce,txid = 0;
if ( _base != 0 && _rel != 0 )
{
    strcpy(base,_base), strcpy(rel,_rel);
    touppercase(base), touppercase(rel);
    if ( btc38_supports(base,rel) == 0 )
    {
        *retstrp = clonestr("{\"error\":\"invalid contract pair\"}");
        return(0);
    }
}
nonce = exchange_nonce(exchange);
sprintf(buf,"%s_%s_%s_%llu",exchange->apikey,exchange->userid,exchange->apisecret,(long long)nonce);
//printf("MD5.(%s)\n",buf);
calc_md5(digest,buf,(int32_t)strlen(buf));
*retstrp = 0;
if ( dir == 0 )
{
    path = "getMyBalance.php";
    sprintf(cmdbuf,"key=%s&time=%llu&md5=%s",exchange->apikey,(long long)nonce,digest);
}
else
{
if ( (data= curl_post(&cHandle,url,0,cmdbuf,0,0,0,0)) != 0 )
{
    //printf("submit cmd.(%s) [%s]\n",cmdbuf,data);
    if ( (json= cJSON_Parse(data)) != 0 )
    {
        if ( juint(json,"success") > 0 && (resultobj= cJSON_GetObjectItem(json,"return")) != 0 )
        {
            if ( (txid= get_API_nxt64bits(cJSON_GetObjectItem(resultobj,"order_id"))) == 0 )
            {
                if ( get_API_nxt64bits(cJSON_GetObjectItem(resultobj,"remains")) == 0 )
                    txid = _crc32(0,cmdbuf,strlen(cmdbuf));
            }
        }
        free_json(json);
    }
} else fprintf(stderr,"submit err cmd.(%s)\n",cmdbuf);
if ( retstrp != 0 && data != 0 )
{
    if ( (json= cJSON_Parse(data)) == 0 )
    {
        json = cJSON_CreateObject();
        jaddstr(json,"result",data);
        data = jprint(json,1);
    } else free_json(json);
        //printf("btc38 returning.(%s) in %p\n",data,data);
        *retstrp = data;
        }
else if ( data != 0 )
free(data);
return(txid);
*/

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    return(SIGNPOST(&exchange->cHandle,1,0,exchange,"","getMyBalance.php"));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    char field[128],*str,*itemstr = 0; cJSON *obj; double lockbalance,imma;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    strcat(field,"_balance");
    if ( argjson != 0 && (str= jstr(argjson,field)) != 0 )
    {
        *balancep = jdouble(argjson,field);
        strcpy(field,coinstr), tolowercase(field), strcat(field,"_balance_lock");
        lockbalance = jdouble(argjson,field);
        strcpy(field,coinstr), tolowercase(field), strcat(field,"_balance_imma");
        imma = jdouble(argjson,field);
        obj = cJSON_CreateObject();
        jaddnum(obj,"balance",*balancep);
        jaddnum(obj,"locked_balance",lockbalance);
        jaddnum(obj,"imma_balance",imma);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

#include "checkbalance.c"

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    char payload[1024],market[16],coinname[16],fmtstr[512],*pricefmt,*extra,*volfmt = "%.3f";
    cJSON *json,*resultobj; uint64_t txid = 0;
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    if ( (dir= cny_flip(market,coinname,base,rel,dir,&price,&volume)) == 0 )
    {
        fprintf(stderr,"btc38_trade illegal base.(%s) or rel.(%s)\n",base,rel);
        return(0);
    }
    if ( strcmp(market,"cny") == 0 )
        pricefmt = "%.5f";
    else pricefmt = "%.6f";
    //sprintf(fmtstr,"key=%%s&time=%%llu&md5=%%s&type=%%s&mk_type=%%s&coinname=%%s&price=%s&amount=%s",pricefmt,volfmt);
    //sprintf(payload,fmtstr,exchange->apikey,(long long)nonce,digest,dir>0?"1":"2",market,coinname,price,volume);
    sprintf(fmtstr,"&type=%%s&mk_type=%%s&coinname=%%s&price=%s&amount=%s",pricefmt,volfmt);
    sprintf(payload,fmtstr,dir>0?"1":"2",market,coinname,price,volume);
    if ( CHECKBALANCE(retstrp,dotrade,exchange,dir,base,rel,price,volume,argjson) == 0 && (json= SIGNPOST(&exchange->cHandle,dotrade,retstrp,exchange,payload,"submitOrder.php")) != 0 )
    {
        if ( juint(json,"success") > 0 && (resultobj= jobj(json,"return")) != 0 )
        {
            if ( (txid= j64bits(resultobj,"order_id")) == 0 )
            {
                if ( j64bits(resultobj,"remains") == 0 )
                    txid = calc_crc32(0,payload,strlen(payload));
            }
        }
        free_json(json);
        if ( retstrp != 0 && *retstrp != 0 )
        {
            if ( (json= cJSON_Parse(*retstrp)) == 0 )
            {
                json = cJSON_CreateObject();
                jaddstr(json,"result",*retstrp);
                free(*retstrp);
                *retstrp = jprint(json,1);
            } else free_json(json);
        }
    }
    return(txid);
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char payload[1024],*rel,*retstr = 0; cJSON *json;
    if ( (rel= jstr(argjson,"rel")) == 0 )
        rel = "cny";
    sprintf(payload,"&mk_type=%s&order_id=%llu",rel,(long long)quoteid);
   if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,"cancelOrder.php")) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized cancelorder
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    char payload[1024],*base,*rel,*retstr = 0; cJSON *json;
    if ( (rel= jstr(argjson,"rel")) == 0 )
        rel = "cny";
    sprintf(payload,"&mk_type=%s",rel);
    if ( (base= jstr(argjson,"base")) != 0 )
        sprintf(payload + strlen(payload),"&coinname=%s",base);
    if ( (json= SIGNPOST(&exchange->cHandle,1,&retstr,exchange,payload,"getOrderList.php")) != 0 )
    {
        free_json(json);
    }
    return(retstr); // return standardized open orders
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"btc38 doesnt seem to have trade history api!\"}"));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"btc38 doesnt seem to have withdraw api!\"}"));
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    char *status,*retstr;
    status = OPENORDERS(exchange,argjson);
    if ( (retstr= exchange_extractorderid(0,status,quoteid,"order_id")) != 0 )
    {
        free(status);
        return(retstr);
    }
    free(status);
    return(clonestr("{\"result\":\"order not pending\"}"));
}

struct exchange_funcs btc38_funcs = EXCHANGE_FUNCS(btc38,EXCHANGE_NAME);

#include "exchange_undefs.h"
