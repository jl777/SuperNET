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

#include "exchanges777.h"

#define TRADEBOTS_GAPTIME 60

struct tradebot_trade
{
    double price,volume;
    uint64_t orderid;
    uint32_t started,finished,dir;
    char exchangestr[32],base[32],rel[32];
};

struct tradebot_info
{
    struct queueitem DL;
    struct supernet_info *myinfo;
    char name[128],exchangestr[32],base[32],rel[32];
    int32_t dir,numtrades,estimatedtrades;
    double price,volume,pricesum,totalvolume;
    uint32_t dead,pause,started,expiration;
    struct tradebot_trade trades[];
};

cJSON *tradebot_json(struct supernet_info *myinfo,struct exchange_info *exchange,struct tradebot_info *bot)
{
    char str[64]; int32_t i,numpending; double pendsum,pendvolume,vol; cJSON *json,*array,*item;
    json = cJSON_CreateObject();
    jaddstr(json,"exchange",exchange->name);
    jaddstr(json,"started",utc_str(str,bot->started));
    if ( bot->pause != 0 )
        jaddstr(json,"paused",utc_str(str,bot->pause));
    if ( bot->dead != 0 )
        jaddstr(json,"stopped",utc_str(str,bot->dead));
    jaddstr(json,"base",bot->base);
    jaddstr(json,"rel",bot->rel);
    jaddstr(json,"type",bot->dir > 0 ? "buy" : "sell");
    jaddnum(json,"price",bot->price);
    jaddnum(json,"volume",bot->volume);
    if ( (vol= bot->totalvolume) > SMALLVAL )
    {
        jaddnum(json,"aveprice",bot->pricesum/vol);
        jaddnum(json,"totalvolume",vol);
    }
    array = cJSON_CreateArray();
    for (pendsum=pendvolume=numpending=i=0; i<bot->numtrades; i++)
    {
        item = cJSON_CreateObject();
        jadd64bits(item,"orderid",bot->trades[i].orderid);
        jaddstr(item,"type",bot->trades[i].dir > 0 ? "buy" : "sell");
        jaddstr(item,"base",bot->trades[i].base);
        jaddstr(item,"rel",bot->trades[i].rel);
        jaddnum(item,"price",bot->trades[i].price);
        jaddnum(item,"volume",bot->trades[i].volume);
        jaddstr(item,"started",utc_str(str,bot->trades[i].started));
        if ( bot->trades[i].finished == 0 )
        {
            jaddnum(item,"elapsed",time(NULL) - bot->trades[i].started);
            pendsum += bot->trades[i].price * bot->trades[i].volume;
            pendvolume += bot->trades[i].volume;
            numpending++;
        } else jaddnum(item,"duration",bot->trades[i].finished - bot->trades[i].started);
        jaddi(array,item);
    }
    jadd(json,"trades",array);
    if ( (vol= pendvolume) > SMALLVAL )
    {
        jaddnum(json,"pending",numpending);
        jaddnum(json,"pendingprice",pendsum/vol);
        jaddnum(json,"pendingvolume",vol);
    }
    return(json);
}

struct tradebot_info *tradebot_find(struct supernet_info *myinfo,struct exchange_info *exchange,char *botname,cJSON *array,char *base,char *rel)
{
    struct tradebot_info PAD,*bot,*retbot = 0;
    memset(&PAD,0,sizeof(PAD));
    queue_enqueue("tradebotsQ",&exchange->tradebotsQ,&PAD.DL,0);
    while ( (bot= queue_dequeue(&exchange->tradebotsQ,0)) != 0 && bot != &PAD )
    {
        if ( botname != 0 && strcmp(botname,bot->name) == 0 )
            retbot = bot;
        if ( array != 0 )
            jaddi(array,tradebot_json(myinfo,exchange,bot));
        if ( base != 0 && rel != 0 && strcmp(base,bot->base) == 0 && strcmp(rel,bot->rel) == 0 )
            retbot = bot;
        queue_enqueue("tradebotsQ",&exchange->tradebotsQ,&bot->DL,0);
    }
    return(retbot);
}

struct tradebot_info *tradebot_create(struct supernet_info *myinfo,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,int32_t duration)
{
    struct tradebot_info *bot;
    if ( (bot= calloc(1,sizeof(*bot))) != 0 )
    {
        bot->myinfo = myinfo;
        safecopy(bot->exchangestr,exchange->name,sizeof(bot->exchangestr));
        safecopy(bot->base,base,sizeof(bot->base));
        safecopy(bot->rel,rel,sizeof(bot->rel));
        bot->dir = dir, bot->price = price, bot->volume = volume;
        bot->started = (uint32_t)time(NULL);
        if ( duration < 1 )
            duration = 1;
        bot->expiration = bot->started + duration;
        bot->estimatedtrades = (duration / TRADEBOTS_GAPTIME) + 1;
        sprintf(bot->name,"%s_%s_%s.%d",exchange->name,base,rel,bot->started);
        queue_enqueue("tradebotsQ",&exchange->tradebotsQ,&bot->DL,0);
    }
    return(bot);
}

struct tradebot_trade *tradebot_issuetrade(struct exchange_info *exchange,struct tradebot_info *bot,char *base,char *rel,double price,double volume,int32_t dir)
{
    struct tradebot_trade *tr; char *str; int32_t maxseconds = 30,dotrade = 1;
    bot = realloc(bot,sizeof(*bot) + (bot->numtrades + 1) * sizeof(bot->trades[0]));
    tr = &bot->trades[bot->numtrades++];
    memset(tr,0,sizeof(*tr));
    tr->price = price, tr->volume = volume, tr->dir = dir;
    safecopy(tr->exchangestr,exchange->name,sizeof(tr->exchangestr));
    safecopy(tr->base,base,sizeof(tr->base));
    safecopy(tr->rel,rel,sizeof(tr->rel));
    if ( (str= exchanges777_Qtrade(exchange,base,rel,maxseconds,dotrade,dir,price,volume,0)) != 0 )
        free(str);
    return(tr);
}

void tradebot_timeslice(struct exchange_info *exchange,void *_bot)
{
    double volume; struct tradebot_info *bot = _bot;
    if ( time(NULL) < bot->expiration && bot->dead == 0 )
    {
        if ( bot->pause == 0 )
        {
            if ( bot->numtrades == 0 || bot->trades[bot->numtrades-1].finished != 0 || time(NULL) > bot->trades[bot->numtrades-1].started+60 )
            {
                if ( bot->estimatedtrades > 0 )
                {
                    volume = bot->volume / bot->estimatedtrades;
                    tradebot_issuetrade(exchange,bot,bot->base,bot->rel,bot->price,volume,bot->dir);
                }
            }
        }
        queue_enqueue("tradebotsQ",&exchange->tradebotsQ,&bot->DL,0);
    } else free(bot);
}

char *tradebot_launch(struct supernet_info *myinfo,char *exchangestr,char *base,char *rel,int32_t dir,double price,double volume,int32_t duration,char *remoteaddr,cJSON *json)
{
    struct exchange_info *exchange; char retbuf[1024]; struct tradebot_info *bot;
    if ( remoteaddr == 0 )
    {
        if ( (exchange= exchanges777_info(exchangestr,1,json,remoteaddr)) != 0 )
        {
            if ( (bot= tradebot_create(myinfo,exchange,base,rel,1,price,fabs(volume),duration)) != 0 )
            {
                sprintf(retbuf,"{\"result\":\"tradebot created\",\"botid\":\"%s\"}",bot->name);
                return(clonestr(retbuf));
            }
            else return(clonestr("{\"error\":\"couldnt create exchange tradebot\"}"));
        } else return(clonestr("{\"error\":\"couldnt find/create exchange info\"}"));
    } else return(clonestr("{\"error\":\"tradebots only local usage!\"}"));
}

char *tradebot_control(struct supernet_info *myinfo,char *exchangestr,char *botid,int32_t control,char *remoteaddr,cJSON *json)
{
    struct tradebot_info *bot; struct exchange_info *exchange;
    if ( remoteaddr == 0 )
    {
        if ( (exchange= exchanges777_info(exchangestr,1,json,remoteaddr)) != 0 )
        {
            if ( (bot= tradebot_find(myinfo,exchange,botid,0,0,0)) != 0 )
            {
                if ( control > 1 )
                    bot->pause = (uint32_t)time(NULL);
                else if ( control == 0 )
                    bot->pause = 0;
                else bot->dead = (uint32_t)time(NULL);
                return(clonestr("{\"result\":\"ask bot to pause\"}"));
            } else return(clonestr("{\"error\":\"cant find tradebot\"}"));
        }
        else return(clonestr("{\"error\":\"couldnt find/create exchange info\"}"));
    } else return(clonestr("{\"error\":\"tradebots only local usage!\"}"));
}

#include "../includes/iguana_apidefs.h"

THREE_STRINGS_AND_DOUBLE(tradebot,monitor,exchange,base,rel,commission)
{
    int32_t allfields = 1,depth = 50; struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
            return(exchanges777_Qprices(ptr,base,rel,30,allfields,depth,json,1,commission * .01));
        else return(clonestr("{\"error\":\"couldnt find/create exchange info\"}"));
    } else return(clonestr("{\"error\":\"tradebots only local usage!\"}"));
}

THREE_STRINGS(tradebot,unmonitor,exchange,base,rel)
{
    struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
            return(exchanges777_unmonitor(ptr,base,rel));
        else return(clonestr("{\"error\":\"couldnt find/create exchange info\"}"));
    } else return(clonestr("{\"error\":\"tradebots only local usage!\"}"));
}

THREE_STRINGS_AND_THREE_DOUBLES(tradebot,accumulate,exchange,base,rel,price,volume,duration)
{
    return(tradebot_launch(myinfo,exchange,base,rel,1,price,volume,duration,remoteaddr,json));
}

THREE_STRINGS_AND_THREE_DOUBLES(tradebot,divest,exchange,base,rel,price,volume,duration)
{
    return(tradebot_launch(myinfo,exchange,base,rel,-1,price,volume,duration,remoteaddr,json));
}

TWO_STRINGS(tradebot,status,exchange,botid)
{
    struct tradebot_info *bot; struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
        {
            if ( (bot= tradebot_find(myinfo,ptr,botid,0,0,0)) != 0 )
                return(jprint(tradebot_json(myinfo,ptr,bot),1));
        }
    }
    return(clonestr("{\"error\":\"tradebots only local usage!\"}"));
}

STRING_ARG(tradebot,activebots,exchange)
{
    struct exchange_info *ptr; cJSON *retjson,*array = cJSON_CreateArray();
    if ( remoteaddr == 0 )
    {
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
        {
            tradebot_find(myinfo,ptr,0,array,0,0);
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"result","success");
            jadd(retjson,"tradebots",array);
            return(jprint(retjson,1));
        }
    }
    return(clonestr("{\"error\":\"tradebots only local usage!\"}"));
}

TWO_STRINGS(tradebot,pause,exchange,botid)
{
    return(tradebot_control(myinfo,exchange,botid,1,remoteaddr,json));
}

TWO_STRINGS(tradebot,stop,exchange,botid)
{
    return(tradebot_control(myinfo,exchange,botid,-1,remoteaddr,json));
}

TWO_STRINGS(tradebot,resume,exchange,botid)
{
    return(tradebot_control(myinfo,exchange,botid,0,remoteaddr,json));
}
#include "../includes/iguana_apiundefs.h"

