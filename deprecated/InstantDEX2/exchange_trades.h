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


#ifndef xcode_exchanges_h
#define xcode_exchanges_h

#define SHA512_DIGEST_SIZE (512 / 8)
void *curl_post(void **cHandlep,char *url,char *userpass,char *postfields,char *hdr0,char *hdr1,char *hdr2,char *hdr3);

char *exchange_would_submit(char *postreq,char *hdr1,char *hdr2,char *hdr3, char *hdr4)
{
    char *data; cJSON *json;
    json = cJSON_CreateObject();
    jaddstr(json,"post",postreq);
    if ( hdr1[0] != 0 )
        jaddstr(json,"hdr1",hdr1);
    if ( hdr2[0] != 0 )
        jaddstr(json,"hdr2",hdr2);
    if ( hdr3[0] != 0 )
        jaddstr(json,"hdr3",hdr3);
    if ( hdr4[0] != 0 )
        jaddstr(json,"hdr4",hdr4);
    data = jprint(json,1);
    json = 0;
    return(data);
}

uint64_t exchange_nonce(struct exchange_info *exchange)
{
    uint64_t nonce;
    nonce = time(NULL);
    if ( nonce < exchange->lastnonce )
        nonce = exchange->lastnonce + 1;
    exchange->lastnonce = nonce;
    return(nonce);
}

int32_t flip_for_exchange(char *pairstr,char *fmt,char *refstr,int32_t dir,double *pricep,double *volumep,char *base,char *rel)
{
    if ( strcmp(rel,refstr) == 0 )
        sprintf(pairstr,fmt,rel,base);
    else
    {
        if ( strcmp(base,refstr) == 0 )
        {
            sprintf(pairstr,fmt,base,rel);
            dir = -dir;
            *volumep *= *pricep;
            *pricep = (1. / *pricep);
        }
        else sprintf(pairstr,fmt,rel,base);
    }
    return(dir);
}

int32_t flipstr_for_exchange(struct exchange_info *exchange,char *pairstr,char *fmt,int32_t dir,double *pricep,double *volumep,char *_base,char *_rel)
{
    int32_t polarity; char base[64],rel[64];
    strcpy(base,_base), strcpy(rel,_rel);
    tolowercase(base), tolowercase(rel);
    polarity = (*exchange->issue.supports)(base,rel);
    if ( dir > 0 )
        sprintf(pairstr,fmt,base,rel);
    else if ( dir < 0 )
    {
        *volumep *= *pricep;
        *pricep = (1. / *pricep);
        sprintf(pairstr,fmt,rel,base);
    }
    return(dir);
}

int32_t cny_flip(char *market,char *coinname,char *base,char *rel,int32_t dir,double *pricep,double *volumep)
{
    char pairstr[512],lbase[16],lrel[16],*refstr=0;
    strcpy(lbase,base), tolowercase(lbase), strcpy(lrel,rel), tolowercase(lrel);
    if ( strcmp(lbase,"cny") == 0 || strcmp(lrel,"cny") == 0 )
    {
        dir = flip_for_exchange(pairstr,"%s_%s","cny",dir,pricep,volumep,lbase,lrel);
        refstr = "cny";
    }
    else if ( strcmp(lbase,"btc") == 0 || strcmp(lrel,"btc") == 0 )
    {
        dir = flip_for_exchange(pairstr,"%s_%s","btc",dir,pricep,volumep,lbase,lrel);
        refstr = "btc";
    }
    if ( market != 0 && coinname != 0 && refstr != 0 )
    {
        strcpy(market,refstr);
        if ( strcmp(lbase,"refstr") != 0 )
            strcpy(coinname,lbase);
        else strcpy(coinname,lrel);
        touppercase(coinname);
    }
    return(dir);
}

char *exchange_extractorderid(int32_t historyflag,char *status,uint64_t quoteid,char *quoteid_field)
{
    cJSON *array,*item,*json; int32_t i,n; uint64_t txid;
    if ( status != 0 )
    {
        if ( (array= cJSON_Parse(status)) != 0 && is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                if ( (txid= juint(item,quoteid_field)) == quoteid )
                {
                    json = cJSON_CreateObject();
                    jaddstr(json,"result",historyflag == 0 ? "order still pending" : "order completed");
                    jadd(json,"order",cJSON_Duplicate(item,1));
                    free_json(array);
                    return(jprint(json,1));
                }
            }
        }
        if ( array != 0 )
            free_json(array);
    }
    return(0);
}

#ifdef notnow
uint64_t bittrex_trade(char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    static CURL *cHandle;
 	char *sig,*data,urlbuf[2048],hdr[1024],pairstr[512],dest[SHA512_DIGEST_SIZE*2 + 1]; struct destbuf uuidstr;
    uint8_t databuf[512];
    uint64_t nonce,txid = 0;
    cJSON *json,*resultobj;
    int32_t i,j,n;
    nonce = exchange_nonce(exchange);
    
// https://bittrex.com/api/v1.1/market/selllimit?apikey=API_KEY&market=BTC-LTC&quantity=1.2&rate=1.3
    if ( dir == 0 )
        sprintf(urlbuf,"https://bittrex.com/api/v1.1/account/getbalances?apikey=%s&nonce=%llu",exchange->apikey,(long long)nonce);
    else
    {
        dir = flip_for_exchange(pairstr,"%s-%s","BTC",dir,&price,&volume,base,rel);
        sprintf(urlbuf,"https://bittrex.com/api/v1.1/market/%slimit?apikey=%s&nonce=%llu&market=%s&rate=%.8f&quantity=%.8f",dir>0?"buy":"sell",exchange->apikey,(long long)nonce,pairstr,price,volume);
    }
    if ( (sig = hmac_sha512_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),urlbuf)) != 0 )
        sprintf(hdr,"apisign:%s",sig);
    else hdr[0] = 0;
    //printf("cmdbuf.(%s) h1.(%s)\n",urlbuf,hdr);
    if ( (data= curl_post(&cHandle,urlbuf,0,0,hdr,0,0,0)) != 0 )
    {
        //printf("cmd.(%s) [%s]\n",urlbuf,data);
        if ( (json= cJSON_Parse(data)) != 0 )
        {
            // { "success" : true, "message" : "", "result" : { "uuid" : "e606d53c-8d70-11e3-94b5-425861b86ab6"  } }
            if ( dir == 0 )
            {
                //printf("got balances.(%s)\n",data);
            }
            else if ( is_cJSON_True(cJSON_GetObjectItem(json,"success")) != 0 && (resultobj= cJSON_GetObjectItem(json,"result")) != 0 )
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
    }
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(txid);
}

uint64_t poloniex_trade(char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    static CURL *cHandle;
 	char *sig,*data,*extra,*typestr,cmdbuf[8192],hdr1[4096],hdr2[4096],pairstr[512],dest[SHA512_DIGEST_SIZE*2 + 1]; cJSON *json; uint64_t nonce,txid = 0;
    nonce = exchange_nonce(exchange);
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    if ( dir == 0 )
        sprintf(cmdbuf,"command=returnCompleteBalances&nonce=%llu",(long long)nonce);
    else
    {
        dir = flip_for_exchange(pairstr,"%s_%s","BTC",dir,&price,&volume,base,rel);
        if ( extra != 0 && strcmp(extra,"margin") == 0 )
            typestr = (dir > 0) ? "marginBuy":"marginSell";
        else typestr = (dir > 0) ? "buy":"sell";
        sprintf(cmdbuf,"command=%s&nonce=%ld&currencyPair=%s&rate=%.8f&amount=%.8f",typestr,(long)time(NULL),pairstr,price,volume);
    }
    if ( (sig= hmac_sha512_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),cmdbuf)) != 0 )
        sprintf(hdr2,"Sign:%s",sig);
    else hdr2[0] = 0;
    sprintf(hdr1,"Key:%s",exchange->apikey);
    //printf("cmdbuf.(%s) h1.(%s) h2.(%s)\n",cmdbuf,hdr2,hdr1);
    if ( (data= curl_post(&cHandle,"https://poloniex.com/tradingApi",0,cmdbuf,hdr2,hdr1,0,0)) != 0 )
    {
        //printf("cmd.(%s) [%s]\n",cmdbuf,data);
        if ( (json= cJSON_Parse(data)) != 0 )
        {
            txid = (get_API_nxt64bits(cJSON_GetObjectItem(json,"orderNumber")) << 32) | get_API_nxt64bits(cJSON_GetObjectItem(json,"tradeID"));
            free_json(json);
        }
    }
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(txid);
}

/*uint64_t bter_trade(char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    static CURL *cHandle;
 	char *sig,*data,buf[512],cmdbuf[8192],hdr1[1024],hdr2[1024],pairstr[512],dest[SHA512_DIGEST_SIZE*2 + 1];
    cJSON *json; uint64_t txid = 0;
    dir = cny_flip(0,0,base,rel,dir,&price,&volume);
    sprintf(cmdbuf,"type=%s&nonce=%ld&pair=%s&rate=%.8f&amount=%.8f",dir>0?"BUY":"SELL",(long)time(NULL),pairstr,price,volume);
    if ( (sig = hmac_sha512_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),cmdbuf)) != 0 )
        sprintf(hdr2,"SIGN:%s",sig);
    else hdr2[0] = 0;
    sprintf(hdr1,"KEY:%s",exchange->apikey);
    printf("cmdbuf.(%s) h1.(%s) h2.(%s)\n",cmdbuf,hdr2,hdr1);
    if ( (data= curl_post(&cHandle,"https://bter.com/api/1/private/placeorder",0,cmdbuf,hdr2,hdr1,0)) != 0 )
    {
        printf("cmd.(%s) [%s]\n",cmdbuf,data);
        //{ "result":"true", "order_id":"123456", "msg":"Success" }
        if ( (json= cJSON_Parse(data)) != 0 )
        {
            copy_cJSON(buf,cJSON_GetObjectItem(json,"result"));
            if ( strcmp(buf,"true") != 0 )
            {
                copy_cJSON(buf,cJSON_GetObjectItem(json,"msg"));
                if ( strcmp(buf,"Success") != 0 )
                    txid = get_API_nxt64bits(cJSON_GetObjectItem(json,"order_id"));
            }
            free_json(json);
        }
    }
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(txid);
}*/

uint64_t btce_trade(char **retstrp,struct exchange_info *exchange,char *_base,char *_rel,int32_t dir,double price,double volume)
{
    /*Authentication is made by sending the following HTTP headers:
    Key — API key. API key examples: 46G9R9D6-WJ77XOIP-XH9HH5VQ-A3XN3YOZ-8T1R8I8T
    API keys are created in the Profile in the API keys section.
    Sign — Signature. POST-parameters (?nonce=1&param0=val0), signed with a Secret key using HMAC-SHA512*/
    static CURL *cHandle;
    
    char *sig,*data,base[64],rel[64],payload[8192],hdr1[4096],hdr2[4096],pairstr[512],dest[SHA512_DIGEST_SIZE*2 + 1]; cJSON *json,*resultobj; uint64_t nonce,txid = 0;
    sprintf(hdr1,"Key:%s",exchange->apikey);
    nonce = exchange_nonce(exchange);
    if ( dir == 0 )
        sprintf(payload,"method=getInfo&nonce=%llu",(long long)nonce);
    else
    {
        if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s_%s",dir,&price,&volume,base,rel)) == 0 )
        {
            printf("cant find baserel (%s/%s)\n",base,rel);
            return(0);
        }
        sprintf(payload,"method=Trade&nonce=%ld&pair=%s&type=%s&rate=%.3f&amount=%.6f",(long)time(NULL),pairstr,dir>0?"buy":"sell",price,volume);
    }
    if ( (sig= hmac_sha512_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),payload)) != 0 )
        sprintf(hdr2,"Sign:%s",sig);
    else hdr2[0] = 0;
    //printf("cmdbuf.(%s) h1.(%s) h2.(%s)\n",payload,hdr2,hdr1);
    if ( (data= curl_post(&cHandle,"https://btc-e.com/tapi",0,payload,hdr2,hdr1,0,0)) != 0 )
    {
        //printf("cmd.(%s) [%s]\n",payload,data);
        //{ "success":1, "return":{ "received":0.1, "remains":0, "order_id":0, "funds":{ "usd":325, "btc":2.498,  } } }
        if ( (json= cJSON_Parse(data)) != 0 )
        {
            if ( juint(json,"success") > 0 && (resultobj= cJSON_GetObjectItem(json,"return")) != 0 )
            {
                if ( (txid= get_API_nxt64bits(cJSON_GetObjectItem(resultobj,"order_id"))) == 0 )
                {
                    if ( get_API_nxt64bits(cJSON_GetObjectItem(resultobj,"remains")) == 0 )
                        txid = _crc32(0,payload,strlen(payload));
                }
            }
            free_json(json);
        }
    }
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(txid);
}

uint64_t kraken_trade(char **retstrp,struct exchange_info *exchange,char *_base,char *_rel,int32_t dir,double price,double volume)
{
    //API-Key = API key
    //API-Sign = Message signature using HMAC-SHA512 of (URI path + SHA256(nonce + POST data)) and base64 decoded secret API key
    
    static CURL *cHandle;
    char *sig,*data,url[512],base[64],rel[64],buf[8192],postbuf[1024],payload[8192],sha256[65],hdr1[4096],hdr2[4096],encode64[4096],decode64[4096],dest[SHA512_DIGEST_SIZE*2 + 1];
    cJSON *json,*resultobj; uint8_t hash[32]; uint64_t nonce,txid = 0; int32_t n;
    if ( _base != 0 && _rel != 0 )
    {
        strcpy(base,_base), strcpy(rel,_rel);
        touppercase(base), touppercase(rel);
        if ( strcmp(base,"BTC") == 0 )
            strcpy(base,"XBT");
        if ( strcmp(rel,"BTC") == 0 )
            strcpy(rel,"XBT");
        if ( strcmp(base,"DOGE") == 0 )
            strcpy(base,"XDG");
        if ( strcmp(rel,"DOGE") == 0 )
            strcpy(rel,"XDG");
    }
    sprintf(hdr1,"API-Key:%s",exchange->apikey);
    n = nn_base64_decode((void *)exchange->apisecret,strlen(exchange->apisecret),(void *)decode64,sizeof(decode64));
    nonce = exchange_nonce(exchange);
    if ( dir == 0 )
    {
        sprintf(postbuf,"nonce=%llu",(long long)nonce);
        sprintf(url,"https://api.kraken.com/0/private/Balance");
    }
    else
    {
        /*
         if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s_%s",dir,&price,&volume,base,rel) == 0 )
        {
            printf("cant find baserel (%s/%s)\n",base,rel);
            return(0);
        }
        //dir = flip_for_exchange(pairstr,"%s_%s","BTC",dir,&price,&volume,base,rel);
        sprintf(payload,"method=Trade&nonce=%ld&pair=%s&type=%s&rate=%.6f&amount=%.6f",(long)time(NULL),pairstr,dir>0?"buy":"sell",price,volume);*/
    }
    sprintf(buf,"%s",postbuf);
    calc_sha256(sha256,hash,(uint8_t *)buf,(int32_t)strlen(buf));
    sprintf(payload,"%s%s",url,sha256);
    //memset(payload,0,sizeof(payload));
    //sprintf(payload,"%s",url);
    //memcpy(payload+strlen(payload),hash,sizeof(hash));
    if ( (sig= hmac_sha512_str(dest,decode64,n,payload)) != 0 )
    {
        n = nn_base64_encode((void *)sig,n,(void *)encode64,sizeof(encode64));
        sprintf(hdr2,"API-Sign:%s",encode64);
    }
    else hdr2[0] = 0;
    //printf("cmdbuf.(%s) h1.(%s) h2.(%s)\n",postbuf,hdr2,hdr1);
    if ( (data= curl_post(&cHandle,url,0,postbuf,hdr1,hdr2,0,0)) != 0 )
    {
        //printf("cmd.(%s) [%s]\n",payload,data);
        //{ "success":1, "return":{ "received":0.1, "remains":0, "order_id":0, "funds":{ "usd":325, "btc":2.498,  } } }
        if ( (json= cJSON_Parse(data)) != 0 )
        {
            if ( juint(json,"success") > 0 && (resultobj= cJSON_GetObjectItem(json,"return")) != 0 )
            {
                if ( (txid= get_API_nxt64bits(cJSON_GetObjectItem(resultobj,"order_id"))) == 0 )
                {
                    if ( get_API_nxt64bits(cJSON_GetObjectItem(resultobj,"remains")) == 0 )
                        txid = _crc32(0,payload,strlen(payload));
                }
            }
            free_json(json);
        }
    }
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(txid);
}

uint64_t bitfinex_trade(char **retstrp,struct exchange_info *exchange,char *_base,char *_rel,int32_t dir,double price,double volume)
{
    /* POST https://api.bitfinex.com/v1/order/new
     void *curl_post(CURL **cHandlep,char *url,char *userpass,char *postfields,char *hdr0,char *hdr1,char *hdr2)
     With a payload of
    
    {
        "request": "/v1/order/new",
        "nonce": "1234",
        "option1": ...
    }
    The nonce provided must be strictly increasing.
    
    To authenticate a request, use the following:
    
    payload = parameters-dictionary -> JSON encode -> base64
    signature = HMAC-SHA384(payload, api-secret) as hexadecimal
    send (api-key, payload, signature)
    These are encoded as HTTP headers named:
    
    X-BFX-APIKEY
    X-BFX-PAYLOAD
    X-BFX-SIGNATURE
    */
   /* POST /order/new
    Request
    Key	Type	Description
    symbol	[string]	The name of the symbol (see `/symbols`).
    amount	[decimal]	Order size: how much to buy or sell.
    price	[price]	Price to buy or sell at. Must be positive. Use random number for market orders.
        exchange	[string]	"bitfinex"
        side	[string]	Either "buy" or "sell".
        type	[string]	Either "market" / "limit" / "stop" / "trailing-stop" / "fill-or-kill" / "exchange market" / "exchange limit" / "exchange stop" / "exchange trailing-stop" / "exchange fill-or-kill". (type starting by "exchange " are exchange orders, others are margin trading orders)
        is_hidden	[bool]	true if the order should be hidden. Default is false.*/
            
    static CURL *cHandle;
 	char *sig,*data,hdr3[4096],url[512],*extra,*typestr,*method,req[4096],base[16],rel[16],payload[4096],hdr1[4096],hdr2[4096],pairstr[512],dest[1024 + 1];
    cJSON *json; uint64_t nonce,txid = 0;
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    memset(req,0,sizeof(req));
    nonce = exchange_nonce(exchange);
    if ( dir == 0 )
    {
        method = "balances";
        sprintf(req,"{\"request\":\"/v1/%s\",\"nonce\":\"%llu\"}",method,(long long)nonce);
    }
    else
    {
        if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s%s",dir,&price,&volume,base,rel)) == 0 )
        {
            printf("cant find baserel (%s/%s)\n",base,rel);
            return(0);
        }
        method = "order/new";
        //Either "market" / "limit" / "stop" / "trailing-stop" / "fill-or-kill" / "exchange market" / "exchange limit" / "exchange stop" / "exchange trailing-stop" / "exchange fill-or-kill". (type starting by "exchange " are exchange orders, others are margin trading orders)
        if ( (typestr= extra) == 0 )
            typestr = "exchange limit";
        sprintf(req,"{\"request\":\"/v1/%s\",\"nonce\":\"%llu\",\"exchange\":\"bitfinex\",\"side\":\"%s\",\"type\":\"%s\",\"price\":\"%.8f\",\"amount\":\"%.8f\",\"symbol\":\"%s\"}",method,(long long)nonce,dir>0?"buy":"sell",typestr,price,volume,pairstr);
    }
    nn_base64_encode((void *)req,strlen(req),payload,sizeof(payload));
    if ( (sig= hmac_sha384_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),payload)) != 0 )
    {
        sprintf(hdr1,"X-BFX-APIKEY:%s",exchange->apikey);
        sprintf(hdr2,"X-BFX-PAYLOAD:%s",payload);
        sprintf(hdr3,"X-BFX-SIGNATURE:%s",sig);
        sprintf(url,"https://api.bitfinex.com/v1/%s",method);
        //printf("bitfinex req.(%s) -> (%s) [%s %s %s]\n",req,payload,hdr1,hdr2,hdr3);
        if ( (data= curl_post(&cHandle,url,0,req,hdr1,hdr2,hdr3,0)) != 0 )
        {
            //printf("[%s]\n",data);
            if ( (json= cJSON_Parse(data)) != 0 )
            {
                if ( (txid= j64bits(json,"order_id")) == 0 )
                {
                    if ( dir != 0 )
                        printf("bitfinex: no txid error\n");
                }
                free_json(json);
            }
        }
        if ( retstrp != 0 )
            *retstrp = data;
        else if ( data != 0 )
            free(data);
    }
    return(txid);
}

uint64_t btc38_trade(char **retstrp,struct exchange_info *exchange,char *_base,char *_rel,int32_t dir,double price,double volume)
{
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
        if ( (dir= cny_flip(market,coinname,base,rel,dir,&price,&volume)) == 0 )
        {
            fprintf(stderr,"btc38_trade illegal base.(%s) or rel.(%s)\n",base,rel);
            return(0);
        }
        if ( strcmp(market,"cny") == 0 )
            pricefmt = "%.5f";
        else pricefmt = "%.6f";
        sprintf(fmtstr,"key=%%s&time=%%llu&md5=%%s&type=%%s&mk_type=%%s&coinname=%%s&price=%s&amount=%s",pricefmt,volfmt);
        sprintf(cmdbuf,fmtstr,exchange->apikey,(long long)nonce,digest,dir>0?"1":"2",market,coinname,price,volume);
        path = "submitOrder.php";
    }
    sprintf(url,"http://www.btc38.com/trade/t_api/%s",path);
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
}

uint64_t huobi_trade(char **retstrp,struct exchange_info *exchange,char *_base,char *_rel,int32_t dir,double price,double volume)
{
    static CURL *cHandle;
    char *data,*extra,*method,pricestr[64],pairstr[64],base[64],rel[64],url[1024],cmdbuf[8192],buf[512],digest[33]; cJSON *json; uint64_t nonce,txid = 0; int32_t type;
    nonce = exchange_nonce(exchange);
    pricestr[0] = 0;
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    if ( dir == 0 )
    {
        method = "get_account_info";
        sprintf(buf,"access_key=%s&created=%llu&method=%s&secret_key=%s",exchange->apikey,(long long)nonce,method,exchange->apisecret);
        calc_md5(digest,buf,(int32_t)strlen(buf));
        sprintf(cmdbuf,"access_key=%s&created=%llu&method=%s&sign=%s",exchange->apikey,(long long)nonce,method,digest);
    }
    else
    {
        if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s%s",dir,&price,&volume,base,rel)) == 0 )
        {
            printf("cant find baserel (%s/%s)\n",base,rel);
            return(0);
        }
        if ( extra != 0 && strcmp(extra,"market") == 0 )
            method = (dir > 0) ? "buy_market" : "sell_market";
        else method = (dir > 0) ? "buy" : "sell", sprintf(pricestr,"&price=%.2f",price);
        if ( strcmp(pairstr,"btccny") == 0 )
            type = 1;
        else if ( strcmp(pairstr,"ltccny") == 0 )
            type = 2;
        else
        {
            printf("cant find baserel (%s/%s)\n",base,rel);
            return(0);
        }
        sprintf(buf,"access_key=%s&amount=%.4f&coin_type=%d&created=%llu&method=%s%s&secret_key=%s",exchange->apikey,volume,type,(long long)nonce,method,pricestr,exchange->apisecret);
        calc_md5(digest,buf,(int32_t)strlen(buf));
        sprintf(cmdbuf,"access_key=%s&amount=%.4f&coin_type=%d&created=%llu&method=%s%s&sign=%s",exchange->apikey,volume,type,(long long)nonce,method,pricestr,digest);
    }
    sprintf(url,"https://api.huobi.com/apiv3");
    if ( (data= curl_post(&cHandle,url,0,cmdbuf,"Content-Type:application/x-www-form-urlencoded",0,0,0)) != 0 )
    {
        //printf("submit cmd.(%s) [%s]\n",cmdbuf,data);
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
    return(txid);
}

uint64_t bityes_trade(char **retstrp,struct exchange_info *exchange,char *_base,char *_rel,int32_t dir,double price,double volume)
{
    static CURL *cHandle;
    char *data,*extra,*method,pricestr[64],pairstr[64],base[64],rel[64],url[1024],cmdbuf[8192],buf[512],digest[33]; cJSON *json; uint64_t nonce,txid = 0; int32_t type;
    nonce = exchange_nonce(exchange);
    pricestr[0] = 0;
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    if ( dir == 0 )
    {
        method = "get_account_info";
        sprintf(buf,"access_key=%s&created=%llu&method=%s&secret_key=%s",exchange->apikey,(long long)nonce,method,exchange->apisecret);
        calc_md5(digest,buf,(int32_t)strlen(buf));
        sprintf(cmdbuf,"access_key=%s&created=%llu&method=%s&sign=%s",exchange->apikey,(long long)nonce,method,digest);
    }
    else
    {
        if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s%s",dir,&price,&volume,base,rel)) == 0 )
        {
            printf("cant find baserel (%s/%s)\n",base,rel);
            return(0);
        }
        if ( extra != 0 && strcmp(extra,"market") == 0 )
            method = (dir > 0) ? "buy_market" : "sell_market";
        else method = (dir > 0) ? "buy" : "sell", sprintf(pricestr,"&price=%.2f",price);
        if ( strcmp(pairstr,"btcusd") == 0 )
            type = 1;
        else if ( strcmp(pairstr,"ltcusd") == 0 )
            type = 2;
        else
        {
            printf("cant find baserel (%s/%s)\n",base,rel);
            return(0);
        }
        /* access_key	Required	Access Key
         amount	Required	Order Amount
         coin_type	Required	Type 1 -BTC 2 -LTC
         created	Required	Submit 10 digits timestamp
         method	Required	Request method:  buy_market
         sign	Required	MD5 Signature
         Encryption Instance	sign=md5(access_key=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx&amount=10&coin_type=1&created=1386844119&method=buy_market&secret_key=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx)
         trade_password	Optional	No sign signature, payment password is required.
         */
        sprintf(buf,"access_key=%s&amount=%.4f&coin_type=%d&created=%llu&method=%s%s&secret_key=%s",exchange->apikey,volume,type,(long long)nonce,method,pricestr,exchange->apisecret);
        calc_md5(digest,buf,(int32_t)strlen(buf));
        sprintf(cmdbuf,"access_key=%s&amount=%.4f&coin_type=%d&created=%llu&method=%s%s&sign=%s",exchange->apikey,volume,type,(long long)nonce,method,pricestr,digest);
    }
    sprintf(url,"https://api.bityes.com/apiv2");
    if ( (data= curl_post(&cHandle,url,0,cmdbuf,"Content-Type:application/x-www-form-urlencoded",0,0,0)) != 0 )
    {
        //printf("submit cmd.(%s) [%s]\n",cmdbuf,data);
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
    return(txid);
}

uint64_t okcoin_trade(char **retstrp,struct exchange_info *exchange,char *_base,char *_rel,int32_t dir,double price,double volume)
{
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
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(txid);
}

uint64_t lakebtc_trade(char **retstrp,struct exchange_info *exchange,char *_base,char *_rel,int32_t dir,double price,double volume)
{
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
     params= (i.e., blank)*/
    
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
    return(txid);
}

uint64_t quadriga_trade(char **retstrp,struct exchange_info *exchange,char *_base,char *_rel,int32_t dir,double price,double volume)
{
    /* You need to POST 3 fields as a JSON payload to the API in order to perform authentication.
     
     key – The API Key as shown above
     nonce – an integer that must be unique for each API call (we recommend using a UNIX timestamp)
     signature – HMAC_SHA256 encrypted string
     Signature
     
     The signature has to be created using a concatenation of the nonce, your client id, the API key and using the MD5 hash of the API Secret as key. The pseudo-algorithm is shown below and you will find code examples in the Appendix.
     
     HMAC_SHA256 ( nonce + client + key, MD5 ( secret ) )
     Please note the HMAC_SHA256 and MD5 strings are both lower case.
     
     Using the API shown in Figure 2, the JSON payload will be:
     
     {
     key: "JJHlXeDcFM",
     nonce: 1391683499,
     signature: "cdbf5cc64c70e1485fcf976cdf367960c2b28cfc28080973ce677cebb6db9681"
     }
     The signature being calculated using:
     
     HMAC_SHA256 ( 1391683499 + 3 + JJHlXeDcFM , MD5 ( *9q(;5]necq[otcCTfBeiI_Ug;ErCt]Ywjgg^G;t ) )
     HMAC_SHA256 ( 13916834993JJHlXeDcFM , 230664ae53cbe5a07c6c389910540729 )
     = cdbf5cc64c70e1485fcf976cdf367960c2b28cfc28080973ce677cebb6db9681
     
     curl_setopt($ch, CURLOPT_POSTFIELDS, $data_string);
     curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
     curl_setopt($ch, CURLOPT_HTTPHEADER, array(
     'Content-Type: application/json; charset=utf-8',
     'Content-Length: ' . strlen($data_string))
     );
     
     */
    static CURL *cHandle;
	char *extra,*sig,*data,*path,pairstr[64],base[64],rel[64],hdr3[4096],url[512],md5secret[128],req[4096],payload[4096],hdr1[4096],hdr2[4096],dest[1024 + 1];
    cJSON *json; uint64_t nonce,txid = 0;
    memset(payload,0,sizeof(payload));
    if ( (extra= *retstrp) != 0 )
        *retstrp = 0;
    nonce = exchange_nonce(exchange);
    sprintf(payload,"%llu%s%s",(long long)nonce,exchange->userid,exchange->apikey);
    calc_md5(md5secret,exchange->apisecret,(int32_t)strlen(exchange->apisecret));
    if ( (sig= hmac_sha256_str(dest,md5secret,(int32_t)strlen(md5secret),payload)) != 0 )
    {
        if ( dir == 0 )
        {
            path = "balance";
            sprintf(req,"{\"key\":\"%s\",\"nonce\":%llu,\"signature\":\"%s\"}",exchange->apikey,(long long)nonce,sig);
        }
        else
        {
            if ( (dir= flipstr_for_exchange(exchange,pairstr,"%s_%s",dir,&price,&volume,base,rel)) == 0 )
            {
                printf("cant find baserel (%s/%s)\n",base,rel);
                return(0);
            }
            path = (dir > 0) ? "buy" : "sell";
            /*key - API key
             signature - signature
             nonce - nonce
             amount - amount of major currency
             price - price to buy at
             book - optional, if not specified, will default to btc_cad*/
            sprintf(req,"{\"key\":\"%s\",\"amount\":%.6f,\"price\":%.3f,\"book\":\"%s_%s\",\"nonce\":%llu,\"signature\":\"%s\"}",exchange->apikey,volume,price,base,rel,(long long)nonce,sig);

            //dir = flip_for_exchange(pairstr,"%s_%s","BTC",dir,&price,&volume,base,rel);
        }
        sprintf(hdr1,"Content-Type:application/json"), sprintf(hdr2,"charset=utf-8"), sprintf(hdr3,"Content-Length:%ld",(long)strlen(req));
        printf("quadriga req.(%s) -> (%s) [%s %s sig.%s]\n",req,payload,md5secret,payload,sig);
        sprintf(url,"https://api.quadrigacx.com/v2/%s",path);
        if ( (data= curl_post(&cHandle,url,0,req,hdr1,hdr2,hdr3,0)) != 0 )
        {
            printf("[%s]\n",data);
            if ( (json= cJSON_Parse(data)) != 0 )
            {
                free_json(json);
            }
        }
        if ( retstrp != 0 )
            *retstrp = data;
        else if ( data != 0 )
            free(data);
    }
    return(txid);
}

uint64_t bitstamp_trade(char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    /*signature is a HMAC-SHA256 encoded message containing: nonce, customer ID (can be found here) and API key. The HMAC-SHA256 code must be generated using a secret key that was generated with your API key. This code must be converted to it's hexadecimal representation (64 uppercase characters).Example (Python):
     message = nonce + customer_id + api_key
     signature = hmac.new(API_SECRET, msg=message, digestmod=hashlib.sha256).hexdigest().upper()
     
     key - API key
     signature - signature
     nonce - nonce
     */
    
    static CURL *cHandle;
 	char *sig,*data,*path,url[512],req[4096],payload[2048],dest[1024 + 1]; cJSON *json; uint64_t nonce,txid = 0;
    memset(payload,0,sizeof(payload));
    nonce = exchange_nonce(exchange);
    sprintf(payload,"%llu%s%s",(long long)nonce,exchange->userid,exchange->apikey);
    if ( dir == 0 )
        path = "balance";
    else
    {
        //dir = flip_for_exchange(pairstr,"%s_%s","BTC",dir,&price,&volume,base,rel);
    }
    if ( (sig= hmac_sha256_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),payload)) != 0 )
    {
        touppercase(sig);
        sprintf(req,"{\"key\":\"%s\",\"signature\":\"%s\",\"nonce\":%llu}",exchange->apikey,sig,(long long)nonce);
        sprintf(url,"https://www.bitstamp.net/api/%s/",path);
        printf("bitstamp.(%s) ->\n",req);
        if ( (data= curl_post(&cHandle,url,0,req,0,0,0,0)) != 0 )
        {
            printf("[%s]\n",data);
            if ( (json= cJSON_Parse(data)) != 0 )
            {
                free_json(json);
            }
        }
        if ( retstrp != 0 )
            *retstrp = data;
        else if ( data != 0 )
            free(data);
    }
    return(txid);
}

uint64_t coinbase_trade(char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    /*All REST requests must contain the following headers:
    
    CB-ACCESS-KEY The api key as a string.
    CB-ACCESS-SIGN The base64-encoded signature (see Signing a Message).
    CB-ACCESS-TIMESTAMP A timestamp for your request.
        CB-ACCESS-PASSPHRASE The passphrase you specified when creating the API key.
        All request bodies should have content type application/json and be valid JSON.
        
        Signing a Message
    The CB-ACCESS-SIGN header is generated by creating a sha256 HMAC using the base64-decoded 
     secret key on the prehash string timestamp + method + requestPath + body (where + represents string concatenation) 
     and base64-encode the output. The timestamp value is the same as the CB-ACCESS-TIMESTAMP header.
    
    The body is the request body string or omitted if there is no request body (typically for GET requests).
        
        The method should be UPPER CASE
        Remember to first base64-decode the alphanumeric secret string (resulting in 64 bytes) before using it as the key for HMAC. Also, base64-encode the digest output before sending in the header.
            */
    static CURL *cHandle;
 	char *sig,*data,*path,sig64[1024],body[4096],method[64],prehash64[512],prehash[512],cmdbuf[8192],url[1024],decodedsecret[128],hdr1[4096],hdr2[4096],hdr3[4096],hdr4[4096],pairstr[512],dest[SHA512_DIGEST_SIZE*2 + 1]; cJSON *json; int32_t n; uint64_t nonce,txid = 0;
    nonce = exchange_nonce(exchange);
    cmdbuf[0] = 0;
    body[0] = 0;
    n = nn_base64_decode((void *)exchange->apisecret,strlen(exchange->apisecret),(void *)decodedsecret,sizeof(decodedsecret));
    if ( dir == 0 )
        path = "accounts", strcpy(method,"GET");
    else
    {
        path = "trade", strcpy(method,"POST");
        dir = flip_for_exchange(pairstr,"%s_%s","BTC",dir,&price,&volume,base,rel);
        sprintf(cmdbuf,"method=Trade&nonce=%ld&pair=%s&type=%s&rate=%.6f&amount=%.6f",(long)time(NULL),pairstr,dir>0?"buy":"sell",price,volume);
    }
    touppercase(method);
    sprintf(prehash,"%llu%s/%s%s",(long long)nonce,method,path,body);
    nn_base64_encode((void *)prehash,strlen(prehash),prehash64,sizeof(prehash64));
    if ( (sig= hmac_sha256_str(dest,decodedsecret,n,prehash64)) != 0 )
    {
        nn_base64_encode((void *)sig,strlen(sig),sig64,sizeof(sig64));
    }
    //CB-ACCESS-KEY The api key as a string.
    //CB-ACCESS-SIGN The base64-encoded signature (see Signing a Message).
    //CB-ACCESS-TIMESTAMP A timestamp for your request.
    //CB-ACCESS-PASSPHRASE The passphrase you specified when creating the API key.
    sprintf(hdr1,"CB-ACCESS-KEY:%s",exchange->apikey);
    sprintf(hdr2,"CB-ACCESS-SIGN:%s",sig64);
    sprintf(hdr3,"CB-ACCESS-TIMESTAMP:%llu",(long long)nonce);
    //sprintf(hdr4,"CB-ACCESS-PASSPHRASE:%s; content-type:application/json; charset=utf-8",exchange->userid);
    sprintf(hdr4,"CB-ACCESS-PASSPHRASE:%s",exchange->userid);
    sprintf(url,"https://api.exchange.coinbase.com/%s",path);
    if ( (data= curl_post(&cHandle,url,0,cmdbuf,hdr1,hdr2,hdr3,hdr4)) != 0 )
    {
        printf("cmd.(%s) prehash.(%s) n.%d [%s]\n",cmdbuf,prehash,n,data);
        //{ "success":1, "return":{ "received":0.1, "remains":0, "order_id":0, "funds":{ "usd":325, "btc":2.498,  } } }
        if ( (json= cJSON_Parse(data)) != 0 )
        {
            free_json(json);
        }
    }
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(txid);
}

#ifdef enable_exmo
uint64_t exmo_trade(char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    /* $req['nonce'] = $NONCE;
     
     // generate the POST data string
     $post_data = http_build_query($req, '', '&');
     
     $sign = hash_hmac('sha512', $post_data, $secret);
     
     // generate the extra headers
     $headers = array(
     'Sign: ' . $sign,
     'Key: ' . $key,
     );
     */
    static CURL *cHandle;
 	char *sig,*method,*data,url[512],cmdbuf[8192],hdr1[4096],hdr2[4096],pairstr[512],dest[SHA512_DIGEST_SIZE*2 + 1]; cJSON *json; uint64_t nonce,txid = 0;
    nonce = exchange_nonce(exchange);
    if ( dir == 0 )
    {
        sprintf(cmdbuf,"nonce=%llu?method=get_info",(long long)nonce);
        method = "get_info";
    }
    else
    {
        method = "notyet";
        dir = flip_for_exchange(pairstr,"%s_%s","BTC",dir,&price,&volume,base,rel);
        sprintf(cmdbuf,"method=Trade&nonce=%ld&pair=%s&type=%s&rate=%.6f&amount=%.6f",(long)time(NULL),pairstr,dir>0?"buy":"sell",price,volume);
        //printf("cmdbuf.(%s) h1.(%s) h2.(%s)\n",cmdbuf,hdr2,hdr1);
    }
    if ( (sig= hmac_sha512_str(dest,exchange->apisecret,(int32_t)strlen(exchange->apisecret),cmdbuf)) != 0 )
        sprintf(hdr2,"Sign:%s",sig);
    else hdr2[0] = 0;
    sprintf(hdr1,"Key:%s",exchange->apikey);
    sprintf(url,"https://api.exmo.com/api_v2/%s",method);
    sprintf(cmdbuf,"{\"method\":\"get_info\"}");
    if ( (data= curl_post(&cHandle,url,0,cmdbuf,hdr1,hdr2,0,0)) != 0 )
    {
        printf("cmd.(%s) [%s]\n",cmdbuf,data);
        if ( (json= cJSON_Parse(data)) != 0 )
        {
            free_json(json);
        }
    }
    if ( retstrp != 0 )
        *retstrp = data;
    else if ( data != 0 )
        free(data);
    return(txid);
}
#endif
#endif

uint64_t submit_triggered_nxtae(int32_t dotrade,char **retjsonstrp,int32_t is_MS,char *bidask,uint64_t nxt64bits,char *NXTACCTSECRET,uint64_t assetid,uint64_t qty,uint64_t NXTprice,char *triggerhash,char *comment,uint64_t otherNXT,uint32_t triggerheight)
{
    int32_t deadline = 1 + 20; uint64_t txid = 0; struct destbuf errstr; char cmd[4096],secret[8192],*jsonstr; cJSON *json;
    if ( retjsonstrp != 0 )
        *retjsonstrp = 0;
    if ( triggerheight != 0 )
        deadline = DEFAULT_NXT_DEADLINE;
    escape_code(secret,NXTACCTSECRET);
    if ( dotrade == 0 )
        strcpy(secret,"<secret>");
    sprintf(cmd,"requestType=%s&secretPhrase=%s&feeNQT=%llu&deadline=%d",bidask,secret,(long long)MIN_NQTFEE,deadline);
    sprintf(cmd+strlen(cmd),"&%s=%llu&%s=%llu",is_MS!=0?"units":"quantityQNT",(long long)qty,is_MS!=0?"currency":"asset",(long long)assetid);
    if ( NXTprice != 0 )
    {
        if ( is_MS != 0 )
            sprintf(cmd+strlen(cmd),"&rateNQT=%llu",(long long)NXTprice);
        else sprintf(cmd+strlen(cmd),"&priceNQT=%llu",(long long)NXTprice);
    }
    if ( otherNXT != 0 )
        sprintf(cmd+strlen(cmd),"&recipient=%llu",(long long)otherNXT);
    if ( triggerhash != 0 && triggerhash[0] != 0 )
    {
        if ( triggerheight == 0 )
            sprintf(cmd+strlen(cmd),"&referencedTransactionFullHash=%s",triggerhash);
        else sprintf(cmd+strlen(cmd),"&referencedTransactionFullHash=%s&phased=true&phasingFinishHeight=%u&phasingVotingModel=4&phasingQuorum=1&phasingLinkedFullHash=%s",triggerhash,triggerheight,triggerhash);
    }
    if ( comment != 0 && comment[0] != 0 )
        sprintf(cmd+strlen(cmd),"&message=%s",comment);
    if ( dotrade == 0 )
    {
        if ( retjsonstrp != 0 )
        {
            json = cJSON_CreateObject();
            jaddstr(json,"submit",cmd);
            *retjsonstrp = jprint(json,1);
        }
        return(0);
    }
    if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
    {
        _stripwhite(jsonstr,' ');
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            copy_cJSON(&errstr,cJSON_GetObjectItem(json,"error"));
            if ( errstr.buf[0] == 0 )
                copy_cJSON(&errstr,cJSON_GetObjectItem(json,"errorDescription"));
            if ( errstr.buf[0] != 0 )
            {
                printf("submit_triggered_bidask.(%s) -> (%s)\n",cmd,jsonstr);
                if ( retjsonstrp != 0 )
                    *retjsonstrp = clonestr(errstr.buf);
            }
            else txid = get_API_nxt64bits(cJSON_GetObjectItem(json,"transaction"));
        }
        free(jsonstr);
    }
    return(txid);
}

int32_t get_assettype(int32_t *numdecimalsp,char *assetidstr)
{
    cJSON *json; char name[64],*jsonstr; uint64_t assetid; int32_t ap_type = -1; //struct assethash *ap,A;
    *numdecimalsp = -1;
    name[0] = 0;
    if ( is_native_crypto(name,calc_nxt64bits(assetidstr)) > 0 )
    {
        //printf("found native crypto.(%s) name.(%s)\n",assetidstr,name);
        ap_type = 0;
        *numdecimalsp = 8;
        return(0);
    }
    if ( (assetid= calc_nxt64bits(assetidstr)) == NXT_ASSETID )
    {
        //printf("found NXT_ASSETID.(%s)\n",assetidstr);
        ap_type = 0;
        *numdecimalsp = 8;
        return(0);
    }
    /*if ( (ap= find_asset(assetid)) != 0 )
     {
     *numdecimalsp = ap->decimals;
     return(ap->type);
     }*/
    memset(name,0,sizeof(name));
    if ( (jsonstr= _issue_getAsset(assetidstr)) != 0 )
    {
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( get_cJSON_int(json,"errorCode") == 0 )
            {
                //printf("assetstr.(%s)\n",jsonstr);
                if ( extract_cJSON_str(name,16,json,"name") <= 0 )
                    *numdecimalsp = -1;
                else *numdecimalsp = (int32_t)get_cJSON_int(json,"decimals");
                ap_type = 2;
            } //else printf("errorcode.%lld (%s)\n",(long long)get_cJSON_int(json,"errorCode"),jsonstr);
            free_json(json);
        } else printf("cant parse.(%s)\n",jsonstr);
        free(jsonstr);
    } else printf("couldnt getAsset.(%s)\n",assetidstr);
    if ( ap_type < 0 )
    {
        if ( (jsonstr= _issue_getCurrency(assetidstr)) != 0 )
        {
            if ( (json= cJSON_Parse(jsonstr)) != 0 )
            {
                if ( get_cJSON_int(json,"errorCode") == 0 )
                {
                    if ( extract_cJSON_str(name,16,json,"name") <= 0 )
                        *numdecimalsp = -1;
                    else *numdecimalsp = (int32_t)get_cJSON_int(json,"decimals");
                    ap_type = 5;
                }
                free_json(json);
            }
            free(jsonstr);
        }
    }
    /*memset(&A,0,sizeof(A));
     A.assetid = assetid;
     A.minvol = A.mult = calc_decimals_mult(*numdecimalsp);
     A.decimals = *numdecimalsp;
     A.type = ap_type;
     strcpy(A.name,name);
     create_asset(assetid,&A);*/
    return(ap_type);
}

uint64_t assetmult(char *assetidstr)
{
    int32_t ap_type,decimals; uint64_t mult = 0;
    ap_type = get_assettype(&decimals,assetidstr);
    if ( decimals >= 0 && decimals <= 8 )
        mult = calc_decimals_mult(decimals);
    return(mult);
}

int32_t assetdecimals(char *assetidstr)
{
    int32_t ap_type,decimals = 0;
    ap_type = get_assettype(&decimals,assetidstr);
    if ( ap_type == 0 )
        return(8);
    return(decimals);
}

uint64_t min_asset_amount(uint64_t assetid)
{
    char assetidstr[64];
    if ( assetid == NXT_ASSETID )
        return(1);
    expand_nxt64bits(assetidstr,assetid);
    return(assetmult(assetidstr));
}

int32_t get_assetdecimals(uint64_t assetid)
{
    char assetidstr[64];
    if ( assetid == NXT_ASSETID )
        return(8);
    expand_nxt64bits(assetidstr,assetid);
    return(assetdecimals(assetidstr));
}

uint64_t get_assetmult(uint64_t assetid)
{
    char assetidstr[64];
    expand_nxt64bits(assetidstr,assetid);
    return(assetmult(assetidstr));
}

double get_minvolume(uint64_t assetid)
{
    return(dstr(get_assetmult(assetid)));
}

int64_t get_asset_quantity(int64_t *unconfirmedp,char *NXTaddr,char *assetidstr)
{
    char cmd[2*MAX_JSON_FIELD],*jsonstr; struct destbuf assetid; int32_t i,n,iter; cJSON *array,*item,*obj,*json; int64_t quantity,qty = 0;
    uint64_t assetidbits = calc_nxt64bits(assetidstr);
    quantity = *unconfirmedp = 0;
    if ( assetidbits == NXT_ASSETID )
    {
        sprintf(cmd,"requestType=getBalance&account=%s",NXTaddr);
        if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
        {
            //printf("(%s) -> (%s)\n",cmd,jsonstr);
            if ( (json= cJSON_Parse(jsonstr)) != 0 )
            {
                qty = get_API_nxt64bits(cJSON_GetObjectItem(json,"balanceNQT"));
                *unconfirmedp = get_API_nxt64bits(cJSON_GetObjectItem(json,"unconfirmedBalanceNQT"));
                printf("(%s)\n",jsonstr);
                free_json(json);
            }
            free(jsonstr);
        }
        return(qty);
    }
    sprintf(cmd,"requestType=getAccount&account=%s",NXTaddr);
    if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
    {
        //printf("(%s) -> (%s)\n",cmd,jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            for (iter=0; iter<2; iter++)
            {
                qty = 0;
                array = cJSON_GetObjectItem(json,iter==0?"assetBalances":"unconfirmedAssetBalances");
                if ( is_cJSON_Array(array) != 0 )
                {
                    n = cJSON_GetArraySize(array);
                    for (i=0; i<n; i++)
                    {
                        item = cJSON_GetArrayItem(array,i);
                        obj = cJSON_GetObjectItem(item,"asset");
                        copy_cJSON(&assetid,obj);
                        //printf("i.%d of %d: %s(%s)\n",i,n,assetid,cJSON_Print(item));
                        if ( strcmp(assetid.buf,assetidstr) == 0 )
                        {
                            qty = get_cJSON_int(item,iter==0?"balanceQNT":"unconfirmedBalanceQNT");
                            break;
                        }
                    }
                }
                if ( iter == 0 )
                    quantity = qty;
                else *unconfirmedp = qty;
            }
            free_json(json);
        }
        free(jsonstr);
    }
    return(quantity);
}

uint64_t calc_asset_qty(uint64_t *availp,uint64_t *priceNQTp,char *NXTaddr,int32_t checkflag,uint64_t assetid,double price,double vol)
{
    char assetidstr[64];
    uint64_t ap_mult,priceNQT,quantityQNT = 0;
    int64_t unconfirmed,balance;
    *priceNQTp = *availp = 0;
    if ( assetid != NXT_ASSETID )
    {
        expand_nxt64bits(assetidstr,assetid);
        if ( (ap_mult= get_assetmult(assetid)) != 0 )
        {
            //price = (double)get_satoshi_obj(srcitem,"priceNQT") / ap_mult;
            //vol = (double)get_satoshi_obj(srcitem,"quantityQNT") * ((double)ap_mult / SATOSHIDEN);
            priceNQT = (price * ap_mult + (ap_mult/2)/SATOSHIDEN);
            quantityQNT = (vol * SATOSHIDEN) / ap_mult;
            balance = get_asset_quantity(&unconfirmed,NXTaddr,assetidstr);
            //printf("%s balance %.8f unconfirmed %.8f vs price %llu qty %llu for asset.%s | price_vol.(%f * %f) * (%lld / %llu)\n",NXTaddr,dstr(balance),dstr(unconfirmed),(long long)priceNQT,(long long)quantityQNT,assetidstr,price,vol,(long long)SATOSHIDEN,(long long)ap_mult);
            //getchar();
            if ( checkflag != 0 && (balance < quantityQNT || unconfirmed < quantityQNT) )
            {
                printf("balance %.8f < qty %.8f || unconfirmed %.8f < qty %llu\n",dstr(balance),dstr(quantityQNT),dstr(unconfirmed),(long long)quantityQNT);
                return(0);
            }
            *priceNQTp = priceNQT;
            *availp = unconfirmed;
        } else printf("%llu null apmult\n",(long long)assetid);
    }
    else
    {
        *priceNQTp = price * SATOSHIDEN;
        quantityQNT = vol;
    }
    return(quantityQNT);
}

char *fill_nxtae(int32_t dotrade,uint64_t *txidp,uint64_t nxt64bits,char *secret,int32_t dir,double price,double volume,uint64_t baseid,uint64_t relid)
{
    uint64_t txid,assetid,avail,qty,priceNQT,ap_mult; char retbuf[512],*errstr;
    if ( nxt64bits != IGUANA_MY64BITS )
        return(clonestr("{\"error\":\"must use your NXT address\"}"));
    else if ( baseid == NXT_ASSETID )
        dir = -dir, assetid = relid;
    else if ( relid == NXT_ASSETID )
        assetid = baseid;
    else return(clonestr("{\"error\":\"NXT AE order without NXT\"}"));
    if ( (ap_mult= get_assetmult(assetid)) == 0 )
        return(clonestr("{\"error\":\"assetid not found\"}"));
    qty = calc_asset_qty(&avail,&priceNQT,secret,0,assetid,price,volume);
    txid = submit_triggered_nxtae(dotrade,&errstr,0,dir > 0 ? "placeBidOrder" : "placeAskOrder",nxt64bits,secret,assetid,qty,priceNQT,0,0,0,0);
    if ( errstr != 0 )
        sprintf(retbuf,"{\"error\":\"%s\"}",errstr), free(errstr);
    else sprintf(retbuf,"{\"result\":\"success\",\"txid\":\"%llu\"}",(long long)txid);
    if ( txidp != 0 )
        *txidp = txid;
    return(clonestr(retbuf));
}

uint64_t submit_to_exchange(void **cHandlep,int32_t dotrade,int32_t exchangeid,char **jsonstrp,uint64_t assetid,uint64_t qty,uint64_t priceNQT,int32_t dir,uint64_t nxt64bits,char *NXTACCTSECRET,char *triggerhash,char *comment,uint64_t otherNXT,char *base,char *rel,double price,double volume,uint32_t triggerheight)
{
    uint64_t txid = 0;
    char assetidstr[64],*cmd,*retstr = 0;
    int32_t ap_type,decimals;
    struct exchange_info *exchange;
    *jsonstrp = 0;
    expand_nxt64bits(assetidstr,assetid);
    ap_type = get_assettype(&decimals,assetidstr);
    if ( dir == 0 || priceNQT == 0 )
        cmd = (ap_type == 2 ? "transferAsset" : "transferCurrency"), priceNQT = 0;
    else cmd = ((dir > 0) ? (ap_type == 2 ? "placeBidOrder" : "currencyBuy") : (ap_type == 2 ? "placeAskOrder" : "currencySell")), otherNXT = 0;
    if ( exchangeid == INSTANTDEX_NXTAEID || exchangeid == INSTANTDEX_UNCONFID )
    {
        if ( assetid != NXT_ASSETID && qty != 0 && (dir == 0 || priceNQT != 0) )
        {
            printf("submit to exchange.%s (%s) dir.%d\n",Exchanges[exchangeid].name,comment,dir);
            txid = submit_triggered_nxtae(dotrade,jsonstrp,ap_type == 5,cmd,nxt64bits,NXTACCTSECRET,assetid,qty,priceNQT,triggerhash,comment,otherNXT,triggerheight);
            if ( *jsonstrp != 0 )
                txid = 0;
        }
    }
    else if ( exchangeid < MAX_EXCHANGES && (exchange= &Exchanges[exchangeid]) != 0 && exchange->exchangeid == exchangeid && exchange->issue.trade != 0 )
    {
        printf("submit_to_exchange.(%d) dir.%d price %f vol %f | inv %f %f (%s)\n",exchangeid,dir,price,volume,1./price,price*volume,comment);
        if ( (txid= (*exchange->issue.trade)(cHandlep,dotrade,&retstr,exchange,base,rel,dir,price,volume)) == 0 )
            printf("error trading (%s/%s) dir.%d price %f vol %f ret.(%s)\n",base,rel,dir,price,volume,retstr!=0?retstr:"");
        if ( jsonstrp != 0 )
            *jsonstrp = retstr;
    }
    return(txid);
}

uint64_t InstantDEX_tradestub(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    printf("this is just a InstantDEX_tradestub\n");
    return(0);
}

uint64_t NXT_tradestub(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    printf("this is just a NXT_tradestub\n");
    return(0);
}

#endif
