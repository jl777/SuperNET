/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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
//
//  main.c
//  marketmaker
//
//  Copyright © 2017 SuperNET. All rights reserved.
//

void PNACL_message(char *arg,...)
{
    
}
#define FROM_MARKETMAKER
#include <stdio.h>
#include <stdint.h>
#ifndef NATIVE_WINDOWS
#include "OS_portable.h"
#else
#include "../../crypto777/OS_portable.h"
#endif // !_WIN_32


#define MAX(a,b) ((a) > (b) ? (a) : (b))
char *stats_JSON(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,char *remoteaddr,uint16_t port);
#include "stats.c"
void LP_priceupdate(char *base,char *rel,double price,double avebid,double aveask,double highbid,double lowask,double PAXPRICES[32]);

//defined(__APPLE__) ||
#ifdef FROM_JS // defined(WIN32) || defined(USE_STATIC_NANOMSG)
#include "../../crypto777/nanosrc/nn.h"
#include "../../crypto777/nanosrc/bus.h"
#include "../../crypto777/nanosrc/pubsub.h"
#include "../../crypto777/nanosrc/pipeline.h"
#include "../../crypto777/nanosrc/reqrep.h"
#include "../../crypto777/nanosrc/tcp.h"
#include "../../crypto777/nanosrc/pair.h"
#else
#if defined(WIN32) || defined(USE_STATIC_NANOMSG)
	#include "../../crypto777/nanosrc/nn.h"
	#include "../../crypto777/nanosrc/bus.h"
	#include "../../crypto777/nanosrc/pubsub.h"
	#include "../../crypto777/nanosrc/pipeline.h"
	#include "../../crypto777/nanosrc/reqrep.h"
	#include "../../crypto777/nanosrc/tcp.h"
	#include "../../crypto777/nanosrc/pair.h"
#else
	#include "/usr/local/include/nanomsg/nn.h"
	#include "/usr/local/include/nanomsg/bus.h"
	#include "/usr/local/include/nanomsg/pubsub.h"
	#include "/usr/local/include/nanomsg/pipeline.h"
	#include "/usr/local/include/nanomsg/reqrep.h"
	#include "/usr/local/include/nanomsg/tcp.h"
	#include "/usr/local/include/nanomsg/pair.h"
#endif
#endif

char DEX_baseaddr[64],DEX_reladdr[64];
struct mmpending_order
{
    double price,volume;
    int32_t dir;
    uint32_t pending,completed,canceled,cancelstarted,reported;
    cJSON *errorjson;
    char exchange[16],base[16],rel[16],orderid[64];
} *Pending_orders;
int32_t Num_Pending;

#define IGUANA_URL "http://127.0.0.1:7778"

/*char CURRENCIES[][8] = { "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK", // end of currencies
};*/
double PAXPRICES[sizeof(CURRENCIES)/sizeof(*CURRENCIES)];
uint32_t PAXACTIVE;

char *DEX_swapstatus()
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"getswaplist\"}");
    return(bitcoind_RPC(0,"InstantDEX",url,0,"getswaplist",postdata,0));
}

char *DEX_amlp(char *blocktrail)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"tradebot\",\"method\":\"amlp\",\"blocktrail\":\"%s\"}",blocktrail);
    return(bitcoind_RPC(0,"tradebot",url,0,"amlp",postdata,0));
}

char *DEX_openorders(char *exchange)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"openorders\",\"exchange\":\"%s\"}",exchange);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"openorders",postdata,0));
}

char *DEX_tradehistory(char *exchange)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"tradehistory\",\"exchange\":\"%s\"}",exchange);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"tradehistory",postdata,0));
}

char *DEX_orderstatus(char *exchange,char *orderid)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"orderstatus\",\"exchange\":\"%s\",\"orderid\":\"%s\"}",exchange,orderid);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"orderstatus",postdata,0));
}

char *DEX_cancelorder(char *exchange,char *orderid)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"cancelorder\",\"exchange\":\"%s\",\"orderid\":\"%s\"}",exchange,orderid);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"cancelorder",postdata,0));
}

char *DEX_balance(char *exchange,char *base,char *coinaddr)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    if ( strcmp(exchange,"DEX") == 0 )
    {
        sprintf(postdata,"{\"agent\":\"dex\",\"method\":\"getbalance\",\"address\":\"%s\",\"symbol\":\"%s\"}",coinaddr,base);
        return(bitcoind_RPC(0,"dex",url,0,"getbalance",postdata,0));
    }
    else
    {
        sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"balance\",\"exchange\":\"%s\",\"base\":\"%s\"}",exchange,base);
        return(bitcoind_RPC(0,"InstantDEX",url,0,"balance",postdata,0));
    }
}

char *DEX_apikeypair(char *exchange,char *apikey,char *apisecret)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"apikeypair\",\"exchange\":\"%s\",\"apikey\":\"%s\",\"apisecret\":\"%s\"}",exchange,apikey,apisecret);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"apikeypair",postdata,0));
}

char *DEX_setuserid(char *exchange,char *userid,char *tradepassword)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"setuserid\",\"exchange\":\"%s\",\"userid\":\"%s\",\"tradepassword\":\"%s\"}",exchange,userid,tradepassword);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"setuserid",postdata,0));
}

char *DEX_trade(char *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"%s\",\"exchange\":\"%s\",\"base\":\"%s\",\"rel\":\"%s\",\"price\":%.8f,\"volume\":%.8f,\"dotrade\":1}",dir>0?"buy":"sell",exchange,base,rel,price,volume);
    //printf("DEX_trade.(%s)\n",postdata);
    return(bitcoind_RPC(0,"InstantDEX",url,0,dir>0?"buy":"sell",postdata,0));
}

char *DEX_withdraw(char *exchange,char *base,char *destaddr,double amount)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"withdraw\",\"exchange\":\"%s\",\"destaddr\":\"%s\",\"amount\":%.8f}",exchange,destaddr,amount);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"withdraw",postdata,0));
}

char *iguana_walletpassphrase(char *passphrase,int32_t timeout)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/coin=KMD&agent=bitcoinrpc&method=walletpassphrase?",IGUANA_URL);
    sprintf(postdata,"[\"%s\", %d]",passphrase,timeout);
    return(bitcoind_RPC(0,"",url,0,"walletpassphrase",postdata,0));
}

/*char *iguana_listunspent(char *coin,char *coinaddr)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/coin=%s&agent=bitcoinrpc&method=listunspent?",IGUANA_URL,coin);
    sprintf(postdata,"[\"%s\"]",coinaddr);
    return(bitcoind_RPC(0,"",url,0,"listunspent",postdata));
}*/

/*char *issue_LP_intro(char *destip,uint16_t destport,char *ipaddr,uint16_t port,int32_t numpeers)
{
    char url[512];
    sprintf(url,"http://%s:%u/api/stats/intro?ipaddr=%s&port=%u&numpeers=%d",destip,destport,ipaddr,port,numpeers);
    printf("(%s)\n",url);
    return(issue_curl(url));
}*/

//
// http://127.0.0.1:7779/api/stats/getpeers

char *DEX_listunspent(char *coin,char *coinaddr)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"dex\",\"method\":\"listunspent\",\"address\":\"%s\",\"symbol\":\"%s\",\"timeout\":60000}",coinaddr,coin);
    return(bitcoind_RPC(0,"dex",url,0,"listunspent",postdata,0));
}

bits256 iguana_wif2privkey(char *wifstr)
{
    char url[512],postdata[1024],*retstr,*privstr; bits256 privkey; cJSON *retjson;
    memset(privkey.bytes,0,sizeof(privkey));
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"SuperNET\",\"method\":\"wif2priv\",\"wif\":\"%s\"}",wifstr);
    if ( (retstr= bitcoind_RPC(0,"SuperNET",url,0,"wif2priv",postdata,0)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (privstr= jstr(retjson,"privkey")) != 0 )
            {
                if ( strlen(privstr) == 64 )
                    decode_hex(privkey.bytes,32,privstr);
            }
            free_json(retjson);
        }
        free(retstr);
    }
    return(privkey);
}

double bittrex_balance(char *base,char *coinaddr)
{
    char *retstr; cJSON *retjson; double balance = 0.;
    if ( (retstr= DEX_balance("bittrex",base,coinaddr)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            balance = jdouble(retjson,"balance");
            free_json(retjson);
        }
        free(retstr);
    }
    return(balance);
}

double dex_balance(char *base,char *coinaddr)
{
    char *retstr; cJSON *retjson; double balance = 0.;
    if ( (retstr= DEX_balance("DEX",base,coinaddr)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            balance = jdouble(retjson,"balance");
            free_json(retjson);
        }
        free(retstr);
    }
    return(balance);
}

int32_t komodo_baseid(char *base)
{
    int32_t i;
    for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
        if ( strcmp(base,CURRENCIES[i]) == 0 )
            return(i);
    return(-1);
}

cJSON *yahoo_allcurrencies()
{
    char *retstr; cJSON *retjson = 0;
    if ( (retstr= issue_curl("http://finance.yahoo.com/webservice/v1/symbols/allcurrencies/quote?format=json")) != 0 )
    {
        retjson = cJSON_Parse(retstr);
        free(retstr);
    }
    return(retjson);
}

void _marketmaker_fiatupdate(int32_t baseid,double price)
{
    PAXPRICES[baseid] = price * PAXPRICES[0];
    printf("%.6f %s per USD, %.8f %s per KMD\n",price,CURRENCIES[baseid],PAXPRICES[baseid],CURRENCIES[baseid]);
}

uint32_t marketmaker_fiatupdate(cJSON *fiatjson)
{
    int32_t i,n,baseid; cJSON *item,*array; double price; char *name; uint64_t mask = 0;
    fiatjson = jobj(fiatjson,"list");
    if ( fiatjson != 0 && (array= jarray(&n,fiatjson,"resources")) > 0 )
    {
        for (i=0; i<n; i++)
        {
            /*
            "resource" : {
                "classname" : "Quote",
                "fields" : {
                    "name" : "USD/BRX",
                    "price" : "3.063200",
                    "symbol" : "BRX=X",
                    "ts" : "1487866204",
                    "type" : "currency",
                    "utctime" : "2017-02-23T16:10:04+0000",
                    "volume" : "0"
                }
           */
            item = jitem(array,i);
            if ( (item= jobj(item,"resource")) != 0 )
                item = jobj(item,"fields");
            if ( item != 0 )
            {
                price = jdouble(item,"price");
                if ( price > SMALLVAL && (name= jstr(item,"name")) != 0 && strncmp(name,"USD/",4) == 0 )
                {
                    if ( (baseid= komodo_baseid(name+4)) >= 0 && baseid < 32 )
                    {
                        if ( ((1LL << baseid) & mask) == 0 )
                        {
                            _marketmaker_fiatupdate(baseid,price);
                            mask |= (1LL << baseid);
                        } else if ( fabs(price*PAXPRICES[0] - PAXPRICES[baseid]) > SMALLVAL )
                            printf("DUPLICATE PRICE? %s %.8f vs %.8f\n",name+4,price*PAXPRICES[0],PAXPRICES[baseid]);
                    }
                }
            }
        }
    }
    printf("pax mask.%x\n",(uint32_t)mask);
    return((uint32_t)mask);
}

void marketmaker_cancel(struct mmpending_order *ptr)
{
    char *retstr; cJSON *retjson;
    if ( ptr->pending != 0 && ptr->cancelstarted == 0 )
    {
        ptr->cancelstarted = (uint32_t)time(NULL);
        if ( (retstr= DEX_cancelorder(ptr->exchange,ptr->orderid)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                printf("cancel %s (%s/%s) %.8f vol %.8f dir.%d -> (%s)\n",ptr->exchange,ptr->base,ptr->rel,ptr->price,ptr->volume,ptr->dir,jprint(retjson,0));
                free_json(retjson);
                ptr->pending = 0;
                ptr->canceled = (uint32_t)time(NULL);
            }
            free(retstr);
        }
    }
}

void marketmaker_queue(char *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *retjson)
{
    struct mmpending_order *ptr; char *orderid;
    //DEX_trade.({"success":true,"message":"","result":{"uuid":"d5faa9e4-660d-436f-a257-2c6a40442d8c"},"tag":"11271578410079391025"}
    if ( is_cJSON_True(jobj(retjson,"success")) != 0 && jobj(retjson,"result") != 0 )
        retjson = jobj(retjson,"result");
    printf("QUEUE.%s %s/%s dir.%d %.8f %.6f (%s)\n",exchange,base,rel,dir,price,volume,jprint(retjson,0));
    Pending_orders = realloc(Pending_orders,(1 + Num_Pending) * sizeof(*Pending_orders));
    ptr = &Pending_orders[Num_Pending++];
    memset(ptr,0,sizeof(*ptr));
    ptr->price = price;
    ptr->volume = volume;
    ptr->dir = dir;
    ptr->pending = (uint32_t)time(NULL);
    strcpy(ptr->exchange,exchange);
    strcpy(ptr->base,base);
    strcpy(ptr->rel,rel);
    if ( (orderid= jstr(retjson,"OrderUuid")) != 0 || (orderid= jstr(retjson,"uuid")) != 0 )
        strcpy(ptr->orderid,orderid);
    else strcpy(ptr->orderid,"0");
}

void marketmaker_pendingupdate(char *exchange,char *base,char *rel)
{
    char *retstr; cJSON *retjson,*obj; int32_t i; struct mmpending_order *ptr;
    for (i=0; i<Num_Pending; i++)
    {
        ptr = &Pending_orders[i];
        if ( strcmp(exchange,ptr->exchange) != 0 || strcmp(base,ptr->base) != 0 || strcmp(rel,ptr->rel) != 0 )
            continue;
        if ( ptr->completed == 0 && (retstr= DEX_orderstatus(exchange,ptr->orderid)) != 0 )
        {
            //printf("%s status.(%s)\n",ptr->orderid,retstr);
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                obj = jobj(retjson,"result");
                if ( is_cJSON_Array(obj) != 0 )
                    obj = jitem(retjson,0);
                if ( jdouble(obj,"QuantityRemaining") == 0. || is_cJSON_True(jobj(obj,"IsOpen")) == 0 )
                {
//{"Uuid":null,"OrderUuid":"e7b0789c-0c4e-413b-a768-3d5734d9cbe5","Exchange":"BTC-KMD","OrderType":"LIMIT_SELL","Quantity":877.77700000,"QuantityRemaining":462.50512234,"Limit":0.00011770,"CommissionPaid":0.00012219,"Price":0.04887750,"PricePerUnit":0.00011769,"Opened":"2017-02-20T13:16:22.29","Closed":null,"CancelInitiated":false,"ImmediateOrCancel":false,"IsConditional":false,"Condition":"NONE","ConditionTarget":null}                    printf("uuid.(%s) finished.(%s)\n",ptr->orderid,jprint(retjson,0));
                    ptr->completed = (uint32_t)time(NULL);
                    ptr->pending = 0;
                }
                free_json(retjson);
            }
            free(retstr);
        }
    }
}

void marketmaker_pendinginit(char *exchange,char *base,char *rel)
{
    char *retstr,*orderid,*pairstr,relbase[64]; cJSON *retjson,*array,*item; int32_t i,j,n,dir; struct mmpending_order *ptr;
    sprintf(relbase,"%s-%s",rel,base);
    if ( (retstr= DEX_openorders(exchange)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            //printf("%s\n",jprint(retjson,0));
            if ( is_cJSON_True(jobj(retjson,"success")) != 0 && (array= jarray(&n,retjson,"result")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (pairstr= jstr(item,"Exchange")) == 0 )
                        continue;
                    if ( strcmp(pairstr,relbase) != 0 )
                    {
                        printf("skip %s when %s\n",pairstr,relbase);
                        continue;
                    }
                    //printf("(%s)\n",jprint(item,0));
                    //{"success":true,"message":"","result":[{"Uuid":null,"OrderUuid":"81ad3e37-65d4-4fee-9c29-03b050f5192b","Exchange":"BTC-KMD","OrderType":"LIMIT_BUY","Quantity":885.19934578,"QuantityRemaining":885.19934578,"Limit":0.00011184,"CommissionPaid":0,"Price":0,"PricePerUnit":null,"Opened":"2017-02-19T19:14:02.94","Closed":null,"CancelInitiated":false,"ImmediateOrCancel":false,"IsConditional":false,"Condition":"NONE","ConditionTarget":null}],"tag":"10056789044100011414"}
                    if ( (orderid= jstr(item,"OrderUuid")) != 0 && is_cJSON_Null(jobj(item,"Closed")) != 0 && is_cJSON_False(jobj(item,"CancelInitiated")) != 0 )
                    {
                        for (j=0; j<Num_Pending; j++)
                        {
                            ptr = &Pending_orders[j];
                            if ( strcmp(exchange,ptr->exchange) != 0 || strcmp(base,ptr->base) != 0 || strcmp(rel,ptr->rel) != 0 )
                                continue;
                            if ( strcmp(ptr->orderid,orderid) == 0 )
                            {
                                ptr->pending = (uint32_t)time(NULL);
                                ptr->completed = 0;
                                printf("%s pending\n",orderid);
                                break;
                            }
                        }
                        if ( j == Num_Pending )
                        {
                            if ( jstr(item,"OrderType") != 0 )
                            {
                                if ( strcmp(jstr(item,"OrderType"),"LIMIT_BUY") == 0 )
                                    dir = 1;
                                else if ( strcmp(jstr(item,"OrderType"),"LIMIT_SELL") == 0 )
                                    dir = -1;
                                else dir = 0;
                                if ( dir != 0 )
                                    marketmaker_queue(exchange,base,rel,dir,jdouble(item,"Limit"),jdouble(item,"QuantityRemaining"),item);
                                else printf("no dir (%s) (%s)\n",jprint(item,0),jstr(item,"OrderType"));
                            }
                        }
                    }
                }
            }
            free_json(retjson);
        }
        free(retstr);
    }
}

double marketmaker_filled(char *exchange,char *base,char *rel,double *buyvolp,double *sellvolp,double *pendingbidsp,double *pendingasksp)
{
    double pricesum = 0.,volsum = 0.; struct mmpending_order *ptr; int32_t i;
    *pendingbidsp = *pendingasksp = 0.;
    for (i=0; i<Num_Pending; i++)
    {
        ptr = &Pending_orders[i];
        if ( strcmp(exchange,ptr->exchange) != 0 || strcmp(base,ptr->base) != 0 || strcmp(rel,ptr->rel) != 0 )
            continue;
        if ( ptr->completed != 0 )
        {
            if ( ptr->reported == 0 )
            {
                if ( ptr->dir > 0 )
                    (*buyvolp) += ptr->volume;
                else if ( ptr->dir < 0 )
                    (*sellvolp) += ptr->volume;
                pricesum += ptr->volume * ptr->price;
                volsum += ptr->volume;
                ptr->reported = (uint32_t)time(NULL);
                printf("REPORT dir.%d vol %.8f\n",ptr->dir,ptr->volume);
            }
        }
        else if ( ptr->pending != 0 ) // alternative is error or cancelled
        {
            if ( ptr->dir > 0 )
                (*pendingbidsp) += ptr->volume;
            else if ( ptr->dir < 0 )
                (*pendingasksp) += ptr->volume;
        }
    }
    if ( volsum != 0. )
        pricesum /= volsum;
    return(pricesum);
}

int32_t marketmaker_prune(char *exchange,char *base,char *rel,int32_t polarity,double bid,double ask,double separation)
{
    int32_t i,n = 0; struct mmpending_order *ptr;
    for (i=0; i<Num_Pending; i++)
    {
        ptr = &Pending_orders[i];
        if ( strcmp(exchange,ptr->exchange) != 0 || strcmp(base,ptr->base) != 0 || strcmp(rel,ptr->rel) != 0 )
            continue;
        if ( ptr->pending != 0 && ptr->cancelstarted == 0 )
        {
            if ( polarity != 0 )
            {
                if ( ((ptr->dir*polarity > 0 && ptr->price < bid-separation) || (ptr->dir*polarity < 0 && ptr->price > ask+separation)) )
                {
                    printf("polarity.%d dir.%d price.%f bid.%f ask.%f\n",polarity,ptr->dir,ptr->price,bid,ask);
                    marketmaker_cancel(ptr), n++;
                }
            }
            /*else
            {,*prunebid=0,*pruneask=0; double lowbid=0.,highask=0.
                if ( ptr->dir > 0 && (lowbid == 0. || ptr->price < lowbid) )
                {
                    lowbid = ptr->price;
                    prunebid = ptr;
                }
                else if ( ptr->dir < 0 && (highask == 0. || ptr->price > highask) )
                {
                    highask = ptr->price;
                    pruneask = ptr;
                }
            }*/
        }
    }
    /*if ( polarity == 0 )
    {
        if ( prunebid != 0 && fabs(prunebid->price - bid) > separation )
            marketmaker_cancel(prunebid), n++;
        if ( pruneask != 0 && fabs(pruneask->price - ask) > separation )
            marketmaker_cancel(pruneask), n++;
    }*/
    return(n);
}

void marketmaker_volumeset(double *bidincrp,double *askincrp,double incr,double buyvol,double pendingbids,double sellvol,double pendingasks,double maxexposure)
{
    *bidincrp = *askincrp = incr;
    //if ( pendingbids >= pendingasks+maxexposure )
    //    *bidincrp = 0.;
    //else if ( pendingasks >= pendingbids+maxexposure )
    //    *askincrp = 0.;
    if ( *bidincrp > 0. && pendingbids + *bidincrp > maxexposure )
        *bidincrp = (maxexposure - *bidincrp);
    if ( *askincrp > 0. && pendingasks + *askincrp > maxexposure )
        *askincrp = (maxexposure - *askincrp);
    if ( *bidincrp < 0. )
        *bidincrp = 0.;
    if ( *askincrp < 0. )
        *askincrp = 0.;
}

int32_t marketmaker_spread(char *exchange,char *base,char *rel,double bid,double bidvol,double ask,double askvol,double separation)
{
    int32_t nearflags[2],i,n = 0; struct mmpending_order *ptr; cJSON *retjson,*vals; char *retstr,postdata[1024],url[128]; double vol,spread_ratio;
    memset(nearflags,0,sizeof(nearflags));
    if ( strcmp("DEX",exchange) != 0 )
    {
        for (i=0; i<Num_Pending; i++)
        {
            ptr = &Pending_orders[i];
            if ( strcmp(exchange,ptr->exchange) != 0 || strcmp(base,ptr->base) != 0 || strcmp(rel,ptr->rel) != 0 )
                continue;
            if ( ptr->pending != 0 && ptr->cancelstarted == 0 )
            {
                if ( bid > SMALLVAL && bidvol > SMALLVAL && ptr->dir > 0 && fabs(bid - ptr->price) < separation )
                {
                    //printf("bid %.8f near %.8f\n",bid,ptr->price);
                    nearflags[0]++;
                }
                if ( ask > SMALLVAL && askvol > SMALLVAL && ptr->dir < 0 && fabs(ask - ptr->price) < separation )
                {
                    //printf("%.8f near %.8f\n",ask,ptr->price);
                    nearflags[1]++;
                }
            }
        }
    }
    //printf("spread.%s (%.8f %.6f) (%.8f %.6f)\n",exchange,bid,bidvol,ask,askvol);
    if ( bid > SMALLVAL && bidvol > SMALLVAL && nearflags[0] == 0 )
    {
        if ( strcmp("DEX",exchange) == 0 && strcmp(base,"KMD") == 0 && strcmp(rel,"BTC") == 0 )
        {
            if ( ask > SMALLVAL && askvol > SMALLVAL )
            {
                /*li.profit = jdouble(vals,"profit");
                 li.refprice = jdouble(vals,"refprice");
                 li.bid = jdouble(vals,"bid");
                 li.ask = jdouble(vals,"ask");
                 if ( (li.minvol= jdouble(vals,"minvol")) <= 0. )
                 li.minvol = (strcmp("BTC",base) == 0) ? 0.0001 : 0.001;
                 if ( (li.maxvol= jdouble(vals,"maxvol")) < li.minvol )
                 li.maxvol = li.minvol;*/
                //curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"tradebot\",\"method\":\"liquidity\",\"targetcoin\":\"MVP\",\"vals\":{\"rel\":\"USD\",\"bid\":0.09,\"ask\":0.11,\"maxvol\":100}}"
                vals = cJSON_CreateObject();
                jaddstr(vals,"rel","BTC");
                jaddnum(vals,"bid",bid);
                jaddnum(vals,"ask",ask);
                vol = bidvol > askvol ? askvol : bidvol;
                jaddnum(vals,"maxvol",vol);
                jaddnum(vals,"minvol",vol*0.1 > 100 ? 100 : vol * 0.1);
                sprintf(url,"%s/?",IGUANA_URL);
                sprintf(postdata,"{\"agent\":\"tradebot\",\"method\":\"liquidity\",\"targetcoin\":\"%s\",\"vals\":%s}",base,jprint(vals,1));
                //printf("(%s)\n",postdata);
                if ( (retstr= bitcoind_RPC(0,"tradebot",url,0,"liqudity",postdata,0)) != 0 )
                {
                    //printf("(%s) -> (%s)\n",postdata,retstr);
                    free(retstr);
                }
                spread_ratio = .5 * ((ask - bid) / (bid + ask));
                for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
                {
                    if ( (PAXACTIVE & (1<<i)) == 0 )
                        continue;
                    if ( PAXPRICES[i] > SMALLVAL )
                    {
                        vals = cJSON_CreateObject();
                        jaddstr(vals,"rel",CURRENCIES[i]);
                        jaddnum(vals,"bid",PAXPRICES[i] * (1. - spread_ratio));
                        jaddnum(vals,"ask",PAXPRICES[i] * (1. + spread_ratio));
                        jaddnum(vals,"maxvol",vol * PAXPRICES[i]);
                        jaddnum(vals,"minvol",MAX(1,(int32_t)(vol * 0.01 * PAXPRICES[i])));
                        sprintf(url,"%s/?",IGUANA_URL);
                        sprintf(postdata,"{\"agent\":\"tradebot\",\"method\":\"liquidity\",\"targetcoin\":\"%s\",\"vals\":%s}","KMD",jprint(vals,1));
                        if ( (retstr= bitcoind_RPC(0,"tradebot",url,0,"liqudity",postdata,0)) != 0 )
                        {
                            //printf("(%s) -> (%s)\n",postdata,retstr);
                            free(retstr);
                        }
                    }
//break;
                }
            } else printf("unsupported ask only for DEX %s/%s\n",base,rel);
        }
        else if ( (retstr= DEX_trade(exchange,base,rel,1,bid,bidvol)) != 0 )
        {
            //printf("DEX_trade.(%s)\n",retstr);
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                marketmaker_queue(exchange,base,rel,1,bid,bidvol,retjson);
                free_json(retjson);
            }
            free(retstr);
        } //else printf("skip bid %s %.8f vol %f\n",exchange,bid,bidvol);
    }
    if ( ask > SMALLVAL && askvol > SMALLVAL && nearflags[1] == 0 && strcmp("DEX",exchange) != 0 )
    {
        if ( (retstr= DEX_trade(exchange,base,rel,-1,ask,askvol)) != 0 )
        {
            //printf("DEX_trade.(%s)\n",retstr);
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                marketmaker_queue(exchange,base,rel,-1,ask,askvol,retjson);
                free_json(retjson);
            }
            free(retstr);
        }
    } //else printf("skip ask %s %.8f vol %f\n",exchange,bid,bidvol);
    return(n);
}

double marketmaker_updateprice(char *name,char *base,char *rel,double theoretical,double *incrp)
{
    static uint32_t counter;
    cJSON *fiatjson; double USD_average=0.,usdprice=0.,CMC_average=0.,avebid=0.,aveask=0.,val,changes[3],highbid=0.,lowask=0.;
    if ( (val= get_theoretical(&avebid,&aveask,&highbid,&lowask,&CMC_average,changes,name,base,rel,&USD_average)) != 0. )
    {
        if ( theoretical == 0. )
        {
            theoretical = val;
            if ( *incrp > 2 )
            {
                *incrp = (int32_t)*incrp;
                *incrp += 0.777;
            }
        } else theoretical = (theoretical + val) * 0.5;
        if ( (counter++ % 12) == 0 )
        {
            if ( USD_average > SMALLVAL && CMC_average > SMALLVAL && theoretical > SMALLVAL )
            {
                usdprice = USD_average * (theoretical / CMC_average);
                printf("USD %.4f <- (%.6f * (%.8f / %.8f))\n",usdprice,USD_average,theoretical,CMC_average);
                PAXPRICES[0] = usdprice;
                if ( (fiatjson= yahoo_allcurrencies()) != 0 )
                {
                    marketmaker_fiatupdate(fiatjson);
                    free_json(fiatjson);
                }
            }
        }
        LP_priceupdate(base,rel,theoretical,avebid,aveask,highbid,lowask,PAXPRICES);
    }
    return(theoretical);
}

void marketmaker(double minask,double maxbid,char *baseaddr,char *reladdr,double start_BASE,double start_REL,double profitmargin,double maxexposure,double ratioincr,char *exchange,char *name,char *base,char *rel)
{
    char *retstr; double bid,ask,start_DEXbase,start_DEXrel,DEX_base = 0.,DEX_rel = 0.,balance_base=0.,balance_rel=0.,mmbid,mmask,aveprice,incr,pendingbids,pendingasks,buyvol,sellvol,bidincr,askincr,filledprice,avebid=0.,aveask=0.,highbid=0.,lowask=0.,theoretical = 0.; uint32_t lasttime = 0;
    incr = maxexposure * ratioincr;
    buyvol = sellvol = 0.;
    start_DEXbase = dex_balance(base,baseaddr);
    start_DEXrel = dex_balance(rel,reladdr);
    while ( 1 )
    {
        if ( time(NULL) > lasttime+60 )
        {
            if ( (theoretical= marketmaker_updateprice(name,base,rel,theoretical,&incr)) != 0. )
            {
                if ( lasttime == 0 )
                    maxexposure /= theoretical;
            }
            if ( strcmp(exchange,"bittrex") == 0 )
            {
                balance_base = bittrex_balance(base,"");
                balance_rel = bittrex_balance(rel,"");
                DEX_base = dex_balance(base,baseaddr);
                DEX_rel = dex_balance(rel,reladdr);
            } else printf("add support for %s balance\n",exchange);
            lasttime = (uint32_t)time(NULL);
        }
        marketmaker_pendingupdate(exchange,base,rel);
        if ( theoretical > SMALLVAL && avebid > SMALLVAL && aveask > SMALLVAL )
        {
            aveprice = (avebid + aveask) * 0.5;
            // if order is filled, theoretical <- filled (theoretical + price)/2
            if ( (filledprice= marketmaker_filled(exchange,base,rel,&buyvol,&sellvol,&pendingbids,&pendingasks)) != 0. )
                theoretical = (theoretical + filledprice) * 0.5;
            buyvol = sellvol = 0;
            if ( (balance_base + DEX_base) < (start_BASE + start_DEXbase) )
                sellvol += ((start_BASE + start_DEXbase) - (balance_base + DEX_base));
            else buyvol += ((balance_base + DEX_base) - (start_BASE + start_DEXbase));
            if ( (balance_rel + DEX_rel) < (start_REL + start_DEXrel) )
                buyvol += ((start_REL + start_DEXrel) - (balance_rel + DEX_rel)) / theoretical;
            else sellvol += ((balance_rel + DEX_rel) - (start_REL + start_DEXrel)) / theoretical;
            mmbid = theoretical - theoretical*profitmargin;
            mmask = theoretical + theoretical*profitmargin;
            // if any existing order exceeds double margin distance, cancel
            marketmaker_prune(exchange,base,rel,1,mmbid - theoretical*profitmargin,mmask + theoretical*profitmargin,0.);
            // if new prices crosses existing order, cancel old order first
            marketmaker_prune(exchange,base,rel,-1,mmbid,mmask,0.);
            //printf("(%.8f %.8f) ",mmbid,mmask);
            if ( (1) )
            {
                if ( mmbid >= lowask || (maxbid > SMALLVAL && mmbid > maxbid) ) //mmbid < highbid ||
                {
                    printf("clear mmbid %.8f lowask %.8f maxbid %.8f\n",mmbid,lowask,maxbid);
                    mmbid = 0.;
                }
                if ( mmask <= highbid || (minask > SMALLVAL && mmask < minask) ) // mmask > lowask ||
                    mmask = 0.;
            }
            marketmaker_volumeset(&bidincr,&askincr,incr,buyvol,pendingbids,sellvol,pendingasks,maxexposure);
            printf("AVE.(%.8f %.8f) hbla %.8f %.8f bid %.8f ask %.8f theory %.8f buys.(%.6f %.6f) sells.(%.6f %.6f) incr.(%.6f %.6f) balances.(%.8f + %.8f, %.8f + %.8f) test %f\n",avebid,aveask,highbid,lowask,mmbid,mmask,theoretical,buyvol,pendingbids,sellvol,pendingasks,bidincr,askincr,balance_base,DEX_base,balance_rel,DEX_rel,(aveask - avebid)/aveprice);
            if ( (retstr= DEX_swapstatus()) != 0 )
                printf("%s\n",retstr), free(retstr);
            printf("%s %s %s, %s %s %s\n",base,DEX_baseaddr,DEX_balance("DEX",base,DEX_baseaddr),rel,DEX_reladdr,DEX_balance("DEX",rel,DEX_reladdr));
            if ( (aveask - avebid)/aveprice > profitmargin )
                bid = highbid * (1 - profitmargin), ask = lowask *  (1 + profitmargin);
            else bid = avebid - profitmargin*aveprice, ask = avebid + profitmargin*aveprice;
            marketmaker_spread("DEX",base,rel,bid,incr,ask,incr,profitmargin*aveprice*0.5);
            if ( (pendingbids + buyvol) > (pendingasks + sellvol) && (pendingbids + buyvol) > bidincr )
            {
                bidincr *= ((double)(pendingasks + sellvol) / ((pendingbids + buyvol) + (pendingasks + sellvol)));
                printf("bidincr %f buy.(%f + %f) sell.(%f + %f)\n",bidincr,pendingbids,buyvol,pendingasks,sellvol);
                if ( bidincr < 0.1*incr )
                    bidincr = 0.1*incr;
                if ( bidincr > 1. )
                    bidincr = (int32_t)bidincr + 0.777;
            }
            if ( (pendingbids + buyvol) < (pendingasks + sellvol) && (pendingasks + sellvol) > askincr )
            {
                askincr *= (double)(pendingbids + buyvol) / ((pendingbids + buyvol) + (pendingasks + sellvol));
                if ( askincr < 0.1*incr )
                    askincr = 0.1*incr;
                if ( askincr > 1. )
                    askincr = (int32_t)askincr + 0.777;
            }
            //printf("mmbid %.8f %.6f, mmask %.8f %.6f\n",mmbid,bidincr,mmask,askincr);
            marketmaker_spread(exchange,base,rel,mmbid,bidincr,mmask,askincr,profitmargin*aveprice*0.5);
            sleep(60);
        }
    }
}

#include "LP_nativeDEX.c"

/*MERK d6071f9b03d1428b648d51ae1268f1605d97f44422ed55ad0335b13fa655f61a ht.518777 -> {"pos":1,"merkle":["526f8be81718beccc16a541a2c550b612123218d80fa884d9f080f18284e2bd8", "f68b03a7b6e418c9b306d8d8b21917ae5a584696f9b0b8cb0741733d7097fdfd"],"block_height":518777} root.(0000000000000000000000000000000000000000000000000000000000000000)
 MERK c007e9c1881a83be453cb6ed3d1bd3bda85efd3b5ce60532c2e20ae3f8a82543 ht.518777 -> {"pos":2,"merkle":["fdff0962fb95120a86a07ddf1ec784fcc5554a2d0a3791a8db2083d593920501", "8c116e974c842ad3ad8b3ddbd71da3debb150e3fe692f5bd628381bc167311a7"],"block_height":518777} root.(0000000000000000000000000000000000000000000000000000000000000000)*/
/*526f8be81718beccc16a541a2c550b612123218d80fa884d9f080f18284e2bd8
d6071f9b03d1428b648d51ae1268f1605d97f44422ed55ad0335b13fa655f61a
c007e9c1881a83be453cb6ed3d1bd3bda85efd3b5ce60532c2e20ae3f8a82543
fdff0962fb95120a86a07ddf1ec784fcc5554a2d0a3791a8db2083d593920501*/

/*0: 526f8be81718beccc16a541a2c550b612123218d80fa884d9f080f18284e2bd8
1: d6071f9b03d1428b648d51ae1268f1605d97f44422ed55ad0335b13fa655f61a
2: c007e9c1881a83be453cb6ed3d1bd3bda85efd3b5ce60532c2e20ae3f8a82543
3: fdff0962fb95120a86a07ddf1ec784fcc5554a2d0a3791a8db2083d593920501
4: 8c116e974c842ad3ad8b3ddbd71da3debb150e3fe692f5bd628381bc167311a7
5: f68b03a7b6e418c9b306d8d8b21917ae5a584696f9b0b8cb0741733d7097fdfd
6: a87ee259560f20b20182760c0e7cc7896d44381f0ad58a2e755a2b6b895b01ec*/

/*
0 1 2 3
 4   5
   6

1 -> [0, 5]
2 -> [3, 4]

if odd -> right, else left
then /= 2
*/

/*void testmerk()
{
    bits256 tree[256],roothash,txid; int32_t i; char str[65];
    memset(tree,0,sizeof(tree));
    decode_hex(tree[0].bytes,32,"526f8be81718beccc16a541a2c550b612123218d80fa884d9f080f18284e2bd8");
    decode_hex(tree[1].bytes,32,"d6071f9b03d1428b648d51ae1268f1605d97f44422ed55ad0335b13fa655f61a");
    decode_hex(tree[2].bytes,32,"c007e9c1881a83be453cb6ed3d1bd3bda85efd3b5ce60532c2e20ae3f8a82543");
    decode_hex(tree[3].bytes,32,"fdff0962fb95120a86a07ddf1ec784fcc5554a2d0a3791a8db2083d593920501");
    roothash = iguana_merkle(tree,4);
    for (i=0; i<256; i++)
    {
        if ( bits256_nonz(tree[i]) == 0 )
            break;
        printf("%d: %s\n",i,bits256_str(str,tree[i]));
    }
    memset(tree,0,sizeof(tree));
    decode_hex(tree[0].bytes,32,"526f8be81718beccc16a541a2c550b612123218d80fa884d9f080f18284e2bd8");
    decode_hex(tree[1].bytes,32,"f68b03a7b6e418c9b306d8d8b21917ae5a584696f9b0b8cb0741733d7097fdfd");
    decode_hex(txid.bytes,32,"d6071f9b03d1428b648d51ae1268f1605d97f44422ed55ad0335b13fa655f61a");
    roothash = validate_merkle(1,txid,tree,2);
    printf("validate 1: %s\n",bits256_str(str,roothash));
    memset(tree,0,sizeof(tree));
    decode_hex(tree[0].bytes,32,"fdff0962fb95120a86a07ddf1ec784fcc5554a2d0a3791a8db2083d593920501");
    decode_hex(tree[1].bytes,32,"8c116e974c842ad3ad8b3ddbd71da3debb150e3fe692f5bd628381bc167311a7");
    decode_hex(txid.bytes,32,"c007e9c1881a83be453cb6ed3d1bd3bda85efd3b5ce60532c2e20ae3f8a82543");
    roothash = validate_merkle(2,txid,tree,2);
    printf("validate 2: %s\n",bits256_str(str,roothash));
}*/

void LP_main(void *ptr)
{
    char *passphrase; double profitmargin; uint16_t port; cJSON *argjson = ptr;
    if ( (passphrase= jstr(argjson,"passphrase")) != 0 )
    {
        profitmargin = jdouble(argjson,"profitmargin");
        LP_profitratio += profitmargin;
        if ( (port= juint(argjson,"rpcport")) < 1000 )
            port = LP_RPCPORT;
        LPinit(port,LP_RPCPORT+1,LP_RPCPORT+2,LP_RPCPORT+3,passphrase,jint(argjson,"client"),jstr(argjson,"userhome"),argjson);
    }
}

int main(int argc, const char * argv[])
{
    char dirname[512],*base,*rel,*name,*exchange,*apikey,*apisecret,*blocktrail,*retstr,*baseaddr,*reladdr,*passphrase; 
    double profitmargin,maxexposure,incrratio,start_rel,start_base,minask,maxbid,incr;
    cJSON *retjson,*loginjson; int32_t i;
    OS_init();
    sprintf(dirname,"%s",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/SWAPS",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/PRICES",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/UNSPENTS",GLOBAL_DBDIR), OS_ensure_directory(dirname);
#ifdef FROM_JS
    argc = 2;
    retjson = cJSON_Parse("{\"client\":1,\"passphrase\":\"test\"}");
    printf("calling LP_main(%s)\n",jprint(retjson,0));
    LP_main(retjson);
    emscripten_set_main_loop(LP_fromjs_iter,1,0);
#else
    if ( argc == 1 )
    {
        LP_NXT_redeems();
        sleep(3);
        return(0);
    }
    if ( argc > 1 && (retjson= cJSON_Parse(argv[1])) != 0 )
    {
        if ( (passphrase= jstr(retjson,"passphrase")) == 0 )
            jaddstr(retjson,"passphrase","test");
        if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_main,(void *)retjson) != 0 )
        {
            printf("error launching LP_main (%s)\n",jprint(retjson,0));
            exit(-1);
        } //else printf("(%s) launched.(%s)\n",argv[1],passphrase);
        incr = 100.;
        while ( (1) )
            sleep(100000);
        profitmargin = jdouble(retjson,"profitmargin");
        minask = jdouble(retjson,"minask");
        maxbid = jdouble(retjson,"maxbid");
        maxexposure = jdouble(retjson,"maxexposure");
        incrratio = jdouble(retjson,"lotratio");
        start_base = jdouble(retjson,"start_base");
        start_rel = jdouble(retjson,"start_rel");
        apikey = jstr(retjson,"apikey");
        apisecret = jstr(retjson,"apisecret");
        base = jstr(retjson,"base");
        name = jstr(retjson,"name");
        rel = jstr(retjson,"rel");
        blocktrail = jstr(retjson,"blocktrail");
        exchange = jstr(retjson,"exchange");
        PAXACTIVE = juint(retjson,"paxactive");
        if ( profitmargin < 0. || maxexposure <= 0. || incrratio <= 0. || apikey == 0 || apisecret == 0 || base == 0 || name == 0 || rel == 0 || exchange == 0 || blocktrail == 0 )
        {
            printf("illegal parameter (%s)\n",jprint(retjson,0));
            exit(-1);
        }
        if ( (retstr= iguana_walletpassphrase(passphrase,999999)) != 0 )
        {
            printf("(%s/%s) login.(%s)\n",base,rel,retstr);
            if ( (loginjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( PAXACTIVE != 0 )
                {
                    for (i=0; i<32; i++)
                    {
                        if ( ((1<<i) & PAXACTIVE) != 0 )
                        {
                            if ( jstr(loginjson,CURRENCIES[i]) == 0 )
                                PAXACTIVE &= ~(1 << i);
                        }
                    }
                }
                if ( (baseaddr= jstr(loginjson,base)) == 0 || (reladdr= jstr(loginjson,rel)) == 0 )
                {
                    printf("Need to activate both %s and %s before marketmaker\n",base,rel);
                    exit(1);
                }
                printf("%s\n",DEX_apikeypair(exchange,apikey,apisecret));
                marketmaker_pendinginit(exchange,base,rel);
                if ( baseaddr != 0 && reladdr != 0 )
                {
                    printf("PAXACTIVE.%08x %s\n",PAXACTIVE,DEX_amlp(blocktrail));
                    strncpy(DEX_baseaddr,baseaddr,sizeof(DEX_baseaddr)-1);
                    strncpy(DEX_reladdr,reladdr,sizeof(DEX_reladdr)-1);
                    printf("%s.%s %s\n",base,baseaddr,DEX_balance("DEX",base,baseaddr));
                    printf("%s.%s %s\n",rel,reladdr,DEX_balance("DEX",rel,reladdr));
                    // initialize state using DEX_pendingorders, etc.
                    marketmaker(minask,maxbid,baseaddr,reladdr,start_base,start_rel,profitmargin,maxexposure,incrratio,exchange,name,base,rel);
                }
                free_json(loginjson);
            } else printf("ERROR parsing.(%s)\n",retstr);
            free(retstr);
        }
        free_json(retjson);
    }
#endif
    return 0;
}
