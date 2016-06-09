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


#ifndef xcode_tradebots_h
#define xcode_tradebots_h

#define TRADEBOT_DEFAULT_DURATION (600)
struct tradebot_info
{
    char buf[512],name[64],*prevobookstr,NXTADDR[64],NXTACCTSECRET[64];
    uint32_t starttime,expiration,finishtime,startedtrades,apitag;
    int32_t numtrades,havetrade,numlinks;
    double price,volume;
    struct prices777_order trades[256]; void *cHandles[256]; int32_t curlings[256];
    struct tradebot_info *linkedbots[8];
    struct apitag_info *api;
    struct tradebot_info *oppo;
    struct InstantDEX_quote iQ;
};

// ./SNapi  "{\"allfields\":1,\"agent\":\"InstantDEX\",\"method\":\"orderbook\",\"exchange\":\"active\",\"base\":\"NXT\",\"rel\":\"BTC\"}"

// test balance verifier
// test tradeleg verifier
// test pass through quotes
// user lockin addrs
// atomic swaps using 2of3 msig
// broadcast request to all marketmakers
// pick best response and do BTC <-> NXT and NXT <-> ABC

int32_t tradebot_havealltrades(struct tradebot_info *bot)
{
    int32_t i;
    if ( bot->havetrade != 0 )
    {
        if ( bot->numlinks > 0 )
        {
            for (i=0; i<bot->numlinks; i++)
                if ( bot->linkedbots[i] == 0 || bot->linkedbots[i]->havetrade == 0 )
                    return(0);
        }
        return(1);
    }
    return(0);
}

struct tradebot_info *tradebot_compile(cJSON *argjson,struct InstantDEX_quote *iQ,struct apitag_info *api)
{
    static uint64_t lastmonce;
    uint64_t monce; char *name,*tmp,*tmp2; int32_t duration; struct tradebot_info *bot = calloc(1,sizeof(*bot));
    monce = (long long)(1000*time(NULL) + milliseconds());
    if ( monce == lastmonce )
        monce++;
    lastmonce = monce;
    bot->iQ = *iQ;
    bot->api = api;
    if ( (duration= juint(argjson,"duration")) == 0 )
        duration = TRADEBOT_DEFAULT_DURATION;
    bot->expiration = (uint32_t)time(NULL) + duration;
    if ( (name= jstr(argjson,"name")) != 0 )
        safecopy(bot->name,name,sizeof(bot->name));
    else sprintf(bot->name,"bot.%llu",monce);
    if ( (tmp= jstr(argjson,"botnxt")) == 0 || (tmp2= jstr(argjson,"secret")) == 0 )
    {
        safecopy(bot->NXTADDR,SUPERNET.NXTADDR,sizeof(bot->NXTADDR));
        safecopy(bot->NXTACCTSECRET,SUPERNET.NXTACCTSECRET,sizeof(bot->NXTACCTSECRET));
    }
    else
    {
        safecopy(bot->NXTADDR,tmp,sizeof(bot->NXTADDR));
        safecopy(bot->NXTACCTSECRET,tmp2,sizeof(bot->NXTACCTSECRET));
    }
    //bot->arbmargin = jdouble(argjson,"arbmargin");
    return(bot);
}

int32_t tradebot_acceptable(struct tradebot_info *bot,cJSON *item)
{
    double price,volume; int32_t dir,i,n; cJSON *trades,*trade;
    if ( bot->iQ.s.isask != 0 )
        dir = -1;
    else dir = 1;
    bot->price = price = jdouble(item,"price");
    bot->volume = volume = jdouble(item,"volume");
    if ( (trades= jarray(&n,item,"trades")) != 0 )
    {
        /*{
            "plugin": "InstantDEX",
            "method": "tradesequence",
            "dotrade": 1,
            "price": 0.00001858,
            "volume": 484.39181916,
            "trades": [
                       {
                           "basket": "bid",
                           "price": 0.00001858,
                           "volume": 484.39181916,
                           "group": 0,
                           "exchange": "bittrex",
                           "base": "NXT",
                           "rel": "BTC",
                           "trade": "sell",
                           "name": "NXT/BTC",
                           "orderprice": 0.00001858,
                           "ordervolume": 484.39181916
                       }
                       ]
        }*/
        if ( n == 1 && is_cJSON_Array(jitem(trades,0)) != 0 )
        {
            //printf("NESTED ARRAY DETECTED\n");
            trades = jitem(trades,0);
            n = cJSON_GetArraySize(trades);
        }
        sprintf(bot->buf,"[%s %s%s %.8f %.4f] <- ",bot->iQ.s.isask != 0 ? "sell" : "buy ",bot->iQ.base,bot->iQ.rel,price,volume);
        for (i=0; i<n; i++)
        {
            trade = jitem(trades,i);
            sprintf(bot->buf+strlen(bot->buf),"[%s %s %.8f %.4f] ",jstr(trade,"exchange"),jstr(trade,"trade"),jdouble(trade,"orderprice"),jdouble(trade,"ordervolume"));
        }
        sprintf(bot->buf+strlen(bot->buf),"n.%d\n",n);
        if ( bot->iQ.s.isask == 0 && bot->oppo != 0 && bot->price > 0. && bot->oppo->price > 0 )
        {
            //if ( bot->price < bot->oppo->price )
            {
                printf("%s%s%.8f -> %.8f = gain %.3f%%\n\n",bot->buf,bot->oppo->buf,bot->price,bot->oppo->price,(bot->oppo->price/bot->price - 1)*100);
            }
        }
    }
    //printf("%s: dir.%d price %.8f vol %f vs bot price %.8f vol %f\n",bot->name,dir,price,volume,bot->iQ.s.price,bot->iQ.s.vol);
    //if ( (dir > 0 && price < bot->iQ.s.price) || (dir < 0 && price >= bot->iQ.s.price) )
        return(1);
    return(0);
}

int32_t tradebot_isvalidtrade(struct tradebot_info *bot,struct prices777_order *order,cJSON *retjson)
{
    cJSON *array,*item; char *resultval; double balance,required; int32_t i,n,valid = 0;
    if ( (array= jarray(&n,retjson,"traderesults")) != 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( jstr(item,"error") == 0 && (resultval= jstr(item,"success")) != 0 )
            {
                balance = jdouble(item,"balance");
                required = jdouble(item,"required");
                printf("[%s %f R%f] ",resultval,balance,required);
                valid++;
            }
        }
        //printf("valid.%d of %d\n",valid,n);
        if ( valid == n )
            return(0);
    }
    return(-1);
}

int32_t tradebot_tradedone(struct tradebot_info *bot,struct prices777_order *order)
{
    struct pending_trade *pend;
    if ( (pend= order->pend) != 0 && pend->finishtime != 0 )
        return(1);
    else return(0);
}

int32_t tradebot_haspending(struct tradebot_info *bot)
{
    int32_t i,finished;
    for (i=finished=0; i<bot->numtrades; i++)
    {
        if ( tradebot_tradedone(bot,&bot->trades[i]) > 0 )
            finished++;
    }
    return(finished < bot->numtrades);
}

void tradebot_free(struct tradebot_info *bot)
{
    int32_t i; struct pending_trade *pend;
    for (i=0; i<bot->numtrades; i++)
    {
        if ( (pend= bot->trades[i].pend) != 0 )
            free_pending(pend);
        if ( bot->trades[i].retitem != 0 )
            free_json(bot->trades[i].retitem);
        if ( bot->cHandles[i] != 0 )
        {
            while ( bot->curlings[i] != 0 )
            {
                fprintf(stderr,"%s: wait for curlrequest[%d] to finish\n",bot->name,i);
                sleep(3);
            }
            curlhandle_free(bot->cHandles[i]);
        }
    }
    if ( bot->prevobookstr != 0 )
        free(bot->prevobookstr);
    free(bot);
}

void Tradebot_loop(void *ptr)
{
    int32_t i,n,dotrade; char *obookstr,*retstr; cJSON *json,*array,*item,*retjson,*submit;
    char jsonstr[1024]; struct tradebot_info *bot = ptr;
    printf("START Tradebot.(%s)\n",bot->name);
    while ( bot->finishtime == 0 && time(NULL) < bot->expiration )
    {
        if ( bot->startedtrades == 0 )
        {
            sprintf(jsonstr,"{\"allfields\":1,\"agent\":\"InstantDEX\",\"method\":\"orderbook\",\"exchange\":\"active\",\"base\":\"%s\",\"rel\":\"%s\"}",bot->iQ.base,bot->iQ.rel);
            if ( (json= cJSON_Parse(jsonstr)) == 0 )
            {
                printf("cant parse.(%s)\n",jsonstr);
                exit(-1);
            }
            obookstr = SuperNET_SNapi(bot->api,json,0,1);
            //printf("GOT.(%s)\n",obookstr);
            free_json(json);
            if ( bot->prevobookstr == 0 || strcmp(obookstr,bot->prevobookstr) != 0 )
            {
                if ( bot->prevobookstr != 0 )
                    free(bot->prevobookstr);
                bot->prevobookstr = obookstr;
                //printf("UPDATE.(%s)\n",obookstr);
                submit = 0;
                if ( (json= cJSON_Parse(obookstr)) != 0 )
                {
                    array = (bot->iQ.s.isask != 0) ? jarray(&n,json,"bids") : jarray(&n,json,"asks");
                    if ( array != 0 && n > 0 )
                    {
                        dotrade = 0;
                        for (i=0; i<1; i++)
                        {
                            item = jitem(array,i);
                            if ( tradebot_acceptable(bot,item) > 0 )
                            {
                                submit = cJSON_Duplicate(item,1);
                                if ( jobj(submit,"dotrade") == 0 )
                                    jaddnum(submit,"dotrade",0);
                                else cJSON_ReplaceItemInObject(submit,"dotrade",cJSON_CreateNumber(0));
                                retstr = SuperNET_SNapi(bot->api,submit,0,1);
                                free_json(submit);
                                //retstr = InstantDEX_tradesequence(bot->curlings,bot,bot->cHandles,&bot->numtrades,bot->trades,(int32_t)( sizeof(bot->trades)/sizeof(*bot->trades)),dotrade,bot->NXTADDR,bot->NXTACCTSECRET,item);
                                if ( retstr != 0 )
                                {
                                    if ( (retjson= cJSON_Parse(retstr)) != 0 )
                                    {
                                        if ( tradebot_isvalidtrade(bot,&bot->trades[i],retjson) > 0 )
                                            bot->havetrade = 1;
                                        free_json(retjson);
                                    }
                                    free(retstr);
                                    if ( bot->havetrade == 0 )
                                        continue;
                                }
                            }
                            break;
                        }
                        if ( 0 && submit != 0 && tradebot_havealltrades(bot) != 0 )
                        {
                            dotrade = 1;
                            cJSON_ReplaceItemInObject(submit,"dotrade",cJSON_CreateNumber(1));
                            bot->startedtrades = (uint32_t)time(NULL);
                            retstr = InstantDEX_tradesequence(bot->curlings,bot,bot->cHandles,&bot->numtrades,bot->trades,(int32_t)(sizeof(bot->trades)/sizeof(*bot->trades)),dotrade,bot->NXTADDR,bot->NXTACCTSECRET,item);
                            printf("TRADE RESULT.(%s)\n",retstr);
                            break;
                        }
                    }
                    free_json(json);
                }
            }
        }
        else if ( bot->startedtrades != 0 )
        {
             if ( tradebot_haspending(bot) > 0 && bot->finishtime == 0 )
                 bot->finishtime = (uint32_t)time(NULL);
        }
        usleep(5000000);
    }
    while ( tradebot_haspending(bot) != 0 )
        sleep(60);
    printf("FINISHED Tradebot.(%s) at %u finishtime.%u expiration.%u\n",bot->name,(uint32_t)time(NULL),bot->finishtime,bot->expiration);
    tradebot_free(bot);
}

char *Tradebot_parser(cJSON *argjson,struct InstantDEX_quote *iQ,struct apitag_info *api)
{
    char *submethod,*exchange; struct tradebot_info *bot,*oppobot;
    printf("InstantDEX_tradebot.(%s) (%s/%s)\n",jprint(argjson,0),iQ->base,iQ->rel);
    if ( (submethod= jstr(argjson,"submethod")) != 0 && (exchange= jstr(argjson,"exchange")) != 0 && strcmp(exchange,"active") == 0 && iQ != 0 )
    {
        if ( strcmp(submethod,"simplebot") == 0 )
        {
            if ( (bot= tradebot_compile(argjson,iQ,api)) == 0 )
                return(clonestr("{\"error\":\"tradebot compiler error\"}"));
            iQ->s.isask ^= 1;
            if ( (oppobot= tradebot_compile(argjson,iQ,api)) == 0 )
                return(clonestr("{\"error\":\"tradebot compiler error\"}"));
            bot->oppo = oppobot;
            oppobot->oppo = bot;
            iguana_launch("bot",(void *)Tradebot_loop,bot);
            iguana_launch("oppobot",(void *)Tradebot_loop,oppobot);
            return(clonestr("{\"result\":\"tradebot started\"}"));
        } else return(clonestr("{\"error\":\"unrecognized tradebot command\"}"));
        return(clonestr("{\"result\":\"tradebot command processed\"}"));
    } else return(clonestr("{\"error\":\"no prices777 or no tradebot submethod or not active exchange\"}"));
}

#endif
