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

#include <stdio.h>
#include <stdint.h>
#include "OS_portable.h"

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

char *DEX_amlp(char *blocktrail)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"tradebot\",\"method\":\"amlp\",\"blocktrail\":\"%s\"}",blocktrail);
    return(bitcoind_RPC(0,"tradebot",url,0,"amlp",postdata));
}

char *DEX_openorders(char *exchange)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"openorders\",\"exchange\":\"%s\"}",exchange);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"openorders",postdata));
}

char *DEX_tradehistory(char *exchange)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"tradehistory\",\"exchange\":\"%s\"}",exchange);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"tradehistory",postdata));
}

char *DEX_orderstatus(char *exchange,char *orderid)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"orderstatus\",\"exchange\":\"%s\",\"orderid\":\"%s\"}",exchange,orderid);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"orderstatus",postdata));
}

char *DEX_cancelorder(char *exchange,char *orderid)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"cancelorder\",\"exchange\":\"%s\",\"orderid\":\"%s\"}",exchange,orderid);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"cancelorder",postdata));
}

char *DEX_balance(char *exchange,char *base,char *coinaddr)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    if ( strcmp(exchange,"DEX") == 0 )
    {
        sprintf(postdata,"{\"agent\":\"dex\",\"method\":\"getbalance\",\"address\":\"%s\",\"symbol\":\"%s\"}",coinaddr,base);
        return(bitcoind_RPC(0,"dex",url,0,"getbalance",postdata));
    }
    else
    {
        sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"balance\",\"exchange\":\"%s\",\"base\":\"%s\"}",exchange,base);
        return(bitcoind_RPC(0,"InstantDEX",url,0,"balance",postdata));
    }
}

char *DEX_apikeypair(char *exchange,char *apikey,char *apisecret)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"apikeypair\",\"exchange\":\"%s\",\"apikey\":\"%s\",\"apisecret\":\"%s\"}",exchange,apikey,apisecret);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"apikeypair",postdata));
}

char *DEX_setuserid(char *exchange,char *userid,char *tradepassword)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"setuserid\",\"exchange\":\"%s\",\"userid\":\"%s\",\"tradepassword\":\"%s\"}",exchange,userid,tradepassword);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"setuserid",postdata));
}

char *DEX_trade(char *exchange,char *base,char *rel,int32_t dir,double price,double volume)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"%s\",\"exchange\":\"%s\",\"base\":\"%s\",\"rel\":\"%s\",\"price\":%.8f,\"volume\":%.8f,\"dotrade\":1}",dir>0?"buy":"sell",exchange,base,rel,price,volume);
    //printf("DEX_trade.(%s)\n",postdata);
    return(bitcoind_RPC(0,"InstantDEX",url,0,dir>0?"buy":"sell",postdata));
}

char *DEX_withdraw(char *exchange,char *base,char *destaddr,double amount)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/?",IGUANA_URL);
    sprintf(postdata,"{\"agent\":\"InstantDEX\",\"method\":\"withdraw\",\"exchange\":\"%s\",\"destaddr\":\"%s\",\"amount\":%.8f}",exchange,destaddr,amount);
    return(bitcoind_RPC(0,"InstantDEX",url,0,"withdraw",postdata));
}

char *iguana_walletpassphrase(char *passphrase,int32_t timeout)
{
    char url[512],postdata[1024];
    sprintf(url,"%s/coin=KMD&agent=bitcoinrpc&method=walletpassphrase?",IGUANA_URL);
    sprintf(postdata,"[\"%s\", %d]",passphrase,timeout);
    return(bitcoind_RPC(0,"",url,0,"walletpassphrase",postdata));
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
    char *retstr,*orderid; cJSON *retjson,*array,*item; int32_t i,j,n,dir; struct mmpending_order *ptr;
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
    int32_t nearflags[2],i,n = 0; struct mmpending_order *ptr; cJSON *retjson,*vals; char *retstr,postdata[1024],url[128];
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
                    nearflags[0]++;
                if ( ask > SMALLVAL && askvol > SMALLVAL && ptr->dir < 0 && fabs(ask - ptr->price) < separation )
                    nearflags[1]++;
            }
        }
    }
    //printf("spread.%s (%.8f %.6f) (%.8f %.6f)\n",exchange,bid,bidvol,ask,askvol);
    if ( bid > SMALLVAL && bidvol > SMALLVAL && nearflags[0] == 0 )
    {
        if ( strcmp("DEX",exchange) == 0 )
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
                jaddnum(vals,"maxvol",bidvol > askvol ? askvol : bidvol);
                jaddnum(vals,"minvol",(bidvol > askvol ? askvol : bidvol) * 0.1);
                sprintf(url,"%s/?",IGUANA_URL);
                sprintf(postdata,"{\"agent\":\"tradebot\",\"method\":\"liquidity\",\"targetcoin\":\"%s\",\"vals\":%s}",base,jprint(vals,1));
                printf("call liquidity\n");
                if ( (retstr= bitcoind_RPC(0,"tradebot",url,0,"liqudity",postdata)) != 0 )
                {
                    //printf("(%s) -> (%s)\n",postdata,retstr);
                    free(retstr);
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
        }
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
    }
    return(n);
}

void marketmaker(char *baseaddr,char *reladdr,double start_BASE,double start_REL,double profitmargin,double maxexposure,double ratioincr,char *exchange,char *name,char *base,char *rel)
{
    double start_DEXbase,start_DEXrel,DEX_base = 0.,DEX_rel = 0.,balance_base=0.,balance_rel=0.,mmbid,mmask,CMC_average,aveprice,incr,pendingbids,pendingasks,buyvol,sellvol,bidincr,askincr,filledprice,avebid=0.,aveask=0.,val,changes[3],highbid=0.,lowask=0.,theoretical = 0.; uint32_t lasttime = 0;
    incr = maxexposure * ratioincr;
    buyvol = sellvol = 0.;
    start_DEXbase = dex_balance(base,baseaddr);
    start_DEXrel = dex_balance(rel,reladdr);
    while ( 1 )
    {
        if ( time(NULL) > lasttime+60 )
        {
            if ( (val= get_theoretical(&avebid,&aveask,&highbid,&lowask,&CMC_average,changes,name,base,rel)) != 0. )
            {
                if ( theoretical == 0. )
                {
                    theoretical = val;
                    incr /= theoretical;
                    maxexposure /= theoretical;
                    if ( incr > 2 )
                    {
                        incr = (int32_t)incr;
                        incr += 0.777;
                    }
                } else theoretical = (theoretical + val) * 0.5;
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
            printf("(%.8f %.8f) ",mmbid,mmask);
            if ( (1) )
            {
                if ( mmbid >= lowask ) //mmbid < highbid ||
                    mmbid = 0.;
                if ( mmask <= highbid ) // mmask > lowask ||
                    mmask = 0.;
            }
            marketmaker_volumeset(&bidincr,&askincr,incr,buyvol,pendingbids,sellvol,pendingasks,maxexposure);
            printf("AVE.(%.8f %.8f) hbla %.8f %.8f bid %.8f ask %.8f theory %.8f buys.(%.6f %.6f) sells.(%.6f %.6f) incr.(%.6f %.6f) balances.(%.8f + %.8f, %.8f + %.8f)\n",avebid,aveask,highbid,lowask,mmbid,mmask,theoretical,buyvol,pendingbids,sellvol,pendingasks,bidincr,askincr,balance_base,DEX_base,balance_rel,DEX_rel);
            marketmaker_spread("DEX",base,rel,avebid - profitmargin*aveprice,incr,aveask + profitmargin*aveprice,incr,profitmargin*aveprice*0.5);
            if ( (pendingbids + buyvol) > (pendingasks + sellvol) )
            {
                bidincr *= (double)(pendingasks + sellvol) / ((pendingbids + buyvol) + (pendingasks + sellvol));
                if ( bidincr > 1. )
                    bidincr = (int32_t)bidincr + 0.777;
            }
            if ( (pendingbids + buyvol) < (pendingasks + sellvol) )
            {
                askincr *= (double)(pendingbids + buyvol) / ((pendingbids + buyvol) + (pendingasks + sellvol));
                if ( askincr > 1. )
                    askincr = (int32_t)askincr + 0.777;
            }
            marketmaker_spread(exchange,base,rel,mmbid,bidincr,mmask,askincr,profitmargin*aveprice*0.5);
            sleep(60);
        }
    }
}

int main(int argc, const char * argv[])
{
    char *base,*rel,*name,*exchange,*apikey,*apisecret,*blocktrail;
    double profitmargin,maxexposure,incrratio,start_rel,start_base;
    cJSON *retjson,*addrjson; char *retstr,*baseaddr,*reladdr,*passphrase;
    if ( argc > 1 && (retjson= cJSON_Parse(argv[1])) != 0 )
    {
        profitmargin = jdouble(retjson,"profitmargin");
        maxexposure = jdouble(retjson,"maxexposure");
        incrratio = jdouble(retjson,"lotratio");
        start_base = jdouble(retjson,"start_base");
        start_rel = jdouble(retjson,"start_rel");
        passphrase = jstr(retjson,"passphrase");
        apikey = jstr(retjson,"apikey");
        apisecret = jstr(retjson,"apisecret");
        base = jstr(retjson,"base");
        name = jstr(retjson,"name");
        rel = jstr(retjson,"rel");
        blocktrail = jstr(retjson,"blocktrail");
        exchange = jstr(retjson,"exchange");
        if ( profitmargin < 0. || maxexposure <= 0. || incrratio <= 0. || apikey == 0 || apisecret == 0 || base == 0 || name == 0 || rel == 0 || exchange == 0 || blocktrail == 0 )
        {
            printf("illegal parameter (%s)\n",jprint(retjson,0));
            exit(-1);
        }
        if ( (retstr= iguana_walletpassphrase(passphrase,999999)) != 0 )
        {
            printf("%s\n",DEX_apikeypair(exchange,apikey,apisecret));
            printf("%s %s\n",base,DEX_balance(exchange,base,""));
            printf("%s %s\n",rel,DEX_balance(exchange,rel,""));
            marketmaker_pendinginit(exchange,base,rel);
            if ( (addrjson= cJSON_Parse(retstr)) != 0 )
            {
                baseaddr = jstr(addrjson,base);
                reladdr = jstr(addrjson,rel);
                if ( baseaddr != 0 && reladdr != 0 )
                {
                    printf("%s\n",DEX_amlp(blocktrail));
                    printf("%s.%s %s\n",base,baseaddr,DEX_balance("DEX",base,baseaddr));
                    printf("%s.%s %s\n",rel,reladdr,DEX_balance("DEX",rel,reladdr));
                    // initialize state using DEX_pendingorders, etc.
                    marketmaker(baseaddr,reladdr,start_base,start_rel,profitmargin,maxexposure,incrratio,exchange,name,base,rel);
                }
                free_json(addrjson);
            }
            free(retstr);
        }
        free_json(retjson);
    }
    return 0;
}
