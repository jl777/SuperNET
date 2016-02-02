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

#define EXCHANGE_NAME "instaforex"
#define UPDATE instaforex ## _price
#define SUPPORTS instaforex ## _supports
#define SIGNPOST instaforex ## _signpost
#define TRADE instaforex ## _trade
#define ORDERSTATUS instaforex ## _orderstatus
#define CANCELORDER instaforex ## _cancelorder
#define OPENORDERS instaforex ## _openorders
#define TRADEHISTORY instaforex ## _tradehistory
#define BALANCES instaforex ## _balances
#define PARSEBALANCE instaforex ## _parsebalance
#define WITHDRAW instaforex ## _withdraw
#define CHECKBALANCE instaforex ## _checkbalance
#define ALLPAIRS instaforex ## _allpairs
#define FUNCS instaforex ## _funcs
#define BASERELS instaforex ## _baserels

static char *BASERELS[][2] = { {"NZD","USD"},{"NZD","CHF"},{"NZD","CAD"},{"NZD","JPY"},{"GBP","NZD"},{"EUR","NZD"},{"AUD","NZD"},{"CAD","JPY"},{"CAD","CHF"},{"USD","CAD"},{"EUR","CAD"},{"GBP","CAD"},{"AUD","CAD"},{"USD","CHF"},{"CHF","JPY"},{"EUR","CHF"},{"GBP","CHF"},{"AUD","CHF"},{"EUR","USD"},{"EUR","AUD"},{"EUR","JPY"},{"EUR","GBP"},{"GBP","USD"},{"GBP","JPY"},{"GBP","AUD"},{"USD","JPY"},{"AUD","JPY"},{"AUD","USD"},{"XAU","USD"} };
#include "exchange_supports.h"
#define NUM_INSTAFOREX ((int32_t)(sizeof(BASERELS)/sizeof(*BASERELS)))

void prices777_instaforex(uint32_t timestamps[NUM_INSTAFOREX],double bids[NUM_INSTAFOREX],double asks[NUM_INSTAFOREX])
{
    //{"NZDUSD":{"symbol":"NZDUSD","lasttime":1437580206,"digits":4,"change":"-0.0001","bid":"0.6590","ask":"0.6593"},
    char contract[32],*jsonstr; cJSON *json,*item; int32_t i;
    memset(timestamps,0,sizeof(*timestamps) * NUM_INSTAFOREX);
    memset(bids,0,sizeof(*bids) * NUM_INSTAFOREX);
    memset(asks,0,sizeof(*asks) * NUM_INSTAFOREX);
    jsonstr = issue_curl("https://quotes.instaforex.com/get_quotes.php?q=NZDUSD,NZDCHF,NZDCAD,NZDJPY,GBPNZD,EURNZD,AUDNZD,CADJPY,CADCHF,USDCAD,EURCAD,GBPCAD,AUDCAD,USDCHF,CHFJPY,EURCHF,GBPCHF,AUDCHF,EURUSD,EURAUD,EURJPY,EURGBP,GBPUSD,GBPJPY,GBPAUD,USDJPY,AUDJPY,AUDUSD,XAUUSD&m=json");
    if ( jsonstr != 0 )
    {
        // printf("(%s)\n",jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            for (i=0; i<NUM_INSTAFOREX; i++)
            {
                sprintf(contract,"%s%s",BASERELS[i][0],BASERELS[i][1]);
                if ( (item= jobj(json,contract)) != 0 )
                {
                    timestamps[i] = juint(item,"lasttime");
                    bids[i] = jdouble(item,"bid");
                    asks[i] = jdouble(item,"ask");
                 }
            }
            free_json(json);
        }
        free(jsonstr);
    }
}

double UPDATE(struct exchange_info *exchange,char *_base,char *_rel,struct exchange_quote *bidasks,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert)
{
    uint32_t timestamps[NUM_INSTAFOREX]; double bids[NUM_INSTAFOREX],asks[NUM_INSTAFOREX];
    char base[32],rel[32]; int32_t numbids,numasks,i; double bid,ask;
    strcpy(base,_base), touppercase(base);
    strcpy(rel,_rel), touppercase(rel);
    for (i=0; i<NUM_INSTAFOREX; i++)
    {
        if ( strcmp(base,BASERELS[i][0]) == 0 && strcmp(rel,BASERELS[i][1]) == 0 )
        {
            prices777_instaforex(timestamps,bids,asks);
            numbids = numasks = 0;
            bid = exchange_setquote(bidasks,&numbids,&numasks,0,invert,bids[i],1,commission,0,timestamps[i],0);
            ask = exchange_setquote(bidasks,&numbids,&numasks,1,invert,asks[i],1,commission,0,timestamps[i],0);
            if ( bid > SMALLVAL && ask > SMALLVAL )
                return((bid + ask) * .5);
            else return(0.);
        }
    }
    return(0);
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *payload,char *path)
{
    if ( retstrp != 0 )
        *retstrp = clonestr("{\"error\":\"instaforex is readonly data source\"}");
    return(cJSON_Parse("{}"));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"instaforex is readonly data source\"}"));
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    return(cJSON_Parse("{\"error\":\"instaforex is readonly data source\"}"));
}

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    return(0);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"instaforex is readonly data source\"}"));
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"instaforex is readonly data source\"}"));
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"instaforex is readonly data source\"}"));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"instaforex is readonly data source\"}"));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"instaforex is readonly data source\"}"));
}

struct exchange_funcs instaforex_funcs = EXCHANGE_FUNCS(instaforex,EXCHANGE_NAME);

#include "exchange_undefs.h"
