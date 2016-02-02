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

#define EXCHANGE_NAME "truefx"
#define UPDATE truefx ## _price
#define SUPPORTS truefx ## _supports
#define SIGNPOST truefx ## _signpost
#define TRADE truefx ## _trade
#define ORDERSTATUS truefx ## _orderstatus
#define CANCELORDER truefx ## _cancelorder
#define OPENORDERS truefx ## _openorders
#define TRADEHISTORY truefx ## _tradehistory
#define BALANCES truefx ## _balances
#define PARSEBALANCE truefx ## _parsebalance
#define WITHDRAW truefx ## _withdraw
#define CHECKBALANCE truefx ## _checkbalance
#define ALLPAIRS truefx ## _allpairs
#define FUNCS truefx ## _funcs
#define BASERELS truefx ## _baserels

static char *BASERELS[][2] = { {"EUR","USD"},{"USD","JPY"},{"GBP","USD"},{"EUR","GBP"},{"USD","CHF"},{"AUD","NZD"},{"CAD","CHF"},{"CHF","JPY"},{"EUR","AUD"},{"EUR","CAD"},{"EUR","JPY"},{"EUR","CHF"},{"USD","CAD"},{"AUD","USD"},{"GBP","JPY"},{"AUD","CAD"},{"AUD","CHF"},{"AUD","JPY"},{"EUR","NOK"},{"EUR","NZD"},{"GBP","CAD"},{"GBP","CHF"},{"NZD","JPY"},{"NZD","USD"},{"USD","NOK"},{"USD","SEK"} };
#include "exchange_supports.h"

uint64_t prices777_truefx(char *reqbase,char *reqrel,uint64_t *millistampp,double *bidp,double *askp,double *openp,double *highp,double *lowp,double *closep,char *username,char *password,uint64_t sessionid)
{
   // static uint32_t lasttime; static char *laststr;
    char *truefxfmt = "http://webrates.truefx.com/rates/connect.html?f=csv&id=%s:%s:poll:%llu&c=EUR/USD,USD/JPY,GBP/USD,EUR/GBP,USD/CHF,AUD/NZD,CAD/CHF,CHF/JPY,EUR/AUD,EUR/CAD,EUR/JPY,EUR/CHF,USD/CAD,AUD/USD,GBP/JPY,AUD/CAD,AUD/CHF,AUD/JPY,EUR/NOK,EUR/NZD,GBP/CAD,GBP/CHF,NZD/JPY,NZD/USD,USD/NOK,USD/SEK";
    // EUR/USD,1437569931314,1.09,034,1.09,038,1.08922,1.09673,1.09384 USD/JPY,1437569932078,123.,778,123.,781,123.569,123.903,123.860 GBP/USD,1437569929008,1.56,332,1.56,337,1.55458,1.56482,1.55538 EUR/GBP,1437569931291,0.69,742,0.69,750,0.69710,0.70383,0.70338 USD/CHF,1437569932237,0.96,142,0.96,153,0.95608,0.96234,0.95748 EUR/JPY,1437569932237,134.,960,134.,972,134.842,135.640,135.476 EUR/CHF,1437569930233,1.04,827,1.04,839,1.04698,1.04945,1.04843 USD/CAD,1437569929721,1.30,231,1.30,241,1.29367,1.30340,1.29466 AUD/USD,1437569931700,0.73,884,0.73,890,0.73721,0.74395,0.74200 GBP/JPY,1437569931924,193.,500,193.,520,192.298,193.670,192.649
    char url[1024],userpass[1024],buf[128],base[64],rel[64],*str=0; cJSON *array;
    int32_t jpyflag,i,n=0; double pre,pre2,bid,ask,openval,high,low; long millistamp;
    millistamp = pre = pre2 = bid = ask = openval = high = low = 0;
    //printf("truefx.(%s)(%s).%llu\n",username,password,(long long)idnum);
    url[0] = 0;
    if ( username[0] != 0 && password[0] != 0 )
    {
        if ( sessionid == 0 )
        {
            sprintf(userpass,"http://webrates.truefx.com/rates/connect.html?f=csv&s=y&u=%s&p=%s&q=poll",username,password);
            if ( (str= issue_curl(userpass)) != 0 )
            {
                _stripwhite(str,0);
                printf("(%s) -> (%s)\n",userpass,str);
                sprintf(userpass,"%s:%s:poll:",username,password);
                sessionid = calc_nxt64bits(str + strlen(userpass));
                free(str);
                //printf("idnum.%llu\n",(long long)sessionid);
            }
        }
        if ( sessionid != 0 )
            sprintf(url,truefxfmt,username,password,(long long)sessionid);
    }
    if ( url[0] == 0 )
        sprintf(url,"http://webrates.truefx.com/rates/connect.html?f=csv&s=y");
    /*if ( laststr != 0 && time(NULL) > lasttime )
    {
        //printf("free laststr.%p lag.%d\n",laststr,(int32_t)(time(NULL) - lasttime));
        free(laststr);
        laststr = 0;
    } else str = laststr;
    if ( str == 0 )
    {
        str = issue_curl(url);
        lasttime = (uint32_t)time(NULL);
        laststr = str;
    }*/
    str = issue_curl(url);
    if ( str != 0 )
    {
        //printf("(%s) -> (%s)\n",url,str);
        /*EUR/USD,1454354222037,1.08,997,1.09,000,1.08142,1.09130,1.08333
        USD/JPY,1454354221120,121.,049,121.,053,120.676,121.496,121.289
        GBP/USD,1454354221048,1.44,242,1.44,254,1.42280,1.44305,1.42483
        EUR/GBP,1454354220966,0.75,561,0.75,567,0.75517,0.76238,0.76031
        USD/CHF,1454354221288,1.01,866,1.01,876,1.01553,1.02514,1.02209
        EUR/JPY,1454354221693,131.,937,131.,944,131.224,132.003,131.381
        EUR/CHF,1454354221028,1.11,027,1.11,032,1.10542,1.11173,1.10705
        USD/CAD,1454354221764,1.39,473,1.39,479,1.39437,1.40627,1.39729
        AUD/USD,1454354221515,0.70,955,0.70,961,0.70421,0.70970,0.70817
        GBP/JPY,1454354221581,174.,602,174.,621,172.408,174.730,172.805
        
*/
        while ( str[n + 0] != 0 && str[n] != '\n' && str[n] != '\r' )
        {
            for (i=jpyflag=0; str[n + i]!=' '&&str[n + i]!='\n'&&str[n + i]!='\r'&&str[n + i]!=0; i++)
            {
                if ( i > 0 && str[n+i] == ',' && str[n+i-1] == '.' )
                    str[n+i-1] = ' ', jpyflag = 1;
                else if ( i > 0 && str[n+i-1] == ',' && str[n+i] == '0' && str[n+i+1+2] == ',' )
                {
                    str[n+i] = ' ';
                    if ( str[n+i+1] == '0' )
                        str[n+i+1] = ' ', i++;
                }
            }
            memcpy(base,str+n,3), base[3] = 0;
            memcpy(rel,str+n+4,3), rel[3] = 0;
            str[n + i] = 0;
            sprintf(buf,"[%s]",str+n+7+1);
            //printf("str.(%s) (%s/%s) %d n.%d i.%d |%s|\n",str+n,base,rel,str[n],n,i,buf);
            n += i + 1;
            if ( (array= cJSON_Parse(buf)) != 0 )
            {
                if ( is_cJSON_Array(array) != 0 )
                {
                    millistamp = j64bits(jitem(array,0),0);
                    pre = jdouble(jitem(array,1),0);
                    bid = jdouble(jitem(array,2),0);
                    pre2 = jdouble(jitem(array,3),0);
                    ask = jdouble(jitem(array,4),0);
                    openval = jdouble(jitem(array,5),0);
                    high = jdouble(jitem(array,6),0);
                    low = jdouble(jitem(array,7),0);
                    if ( jpyflag != 0 )
                        bid = pre + (bid / 1000.), ask = pre2 + (ask / 1000.);
                    else bid = pre + (bid / 100000.), ask = pre2 + (ask / 100000.);
                    if ( strcmp(base,reqbase) == 0 && strcmp(rel,reqrel) == 0 )
                    {
                        *bidp = bid, *askp = ask, *openp = openval, *highp = high, *lowp = low;
                        *closep = 0;
                        *millistampp = millistamp;
                        //printf("(%f %f)\n ",bid,ask);
                        break;
                    }
                }
                free_json(array);
            } else printf("cant parse.(%s)\n",buf);
        }
        free(str);
    }
    return(sessionid);
}

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *bidasks,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert)
{
    int32_t numbids,numasks; double bid,ask,openval,high,low,closeval,volume=1; uint64_t millistamp;
    char *username = "",*password = "";
    if ( exchange->apikey[0] != 0 && exchange->apisecret[0] != 0 )
        username = exchange->apikey, password = exchange->apisecret;
    else if ( exchange->userid[0] != 0 && exchange->tradepassword[0] != 0 )
        username = exchange->userid, password = exchange->tradepassword;
    exchange->lastnonce = prices777_truefx(base,rel,&millistamp,&bid,&ask,&openval,&high,&low,&closeval,username,password,exchange->lastnonce);
    numbids = numasks = 0;
    bid = exchange_setquote(bidasks,&numbids,&numasks,0,invert,bid,volume,commission,0,(uint32_t)(millistamp/1000),0);
    ask = exchange_setquote(bidasks,&numbids,&numasks,1,invert,ask,volume,commission,0,(uint32_t)(millistamp/1000),0);
    if ( bid > SMALLVAL && ask > SMALLVAL )
        return((bid + ask) * .5);
    else return(0);
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *payload,char *path)
{
    if ( retstrp != 0 )
        *retstrp = clonestr("{\"error\":\"truefx is readonly data source\"}");
    return(cJSON_Parse("{}"));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"truefx is readonly data source\"}"));
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    return(cJSON_Parse("{\"error\":\"truefx is readonly data source\"}"));
}

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    return(0);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"truefx is readonly data source\"}"));
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"truefx is readonly data source\"}"));
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"truefx is readonly data source\"}"));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"truefx is readonly data source\"}"));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"truefx is readonly data source\"}"));
}

struct exchange_funcs truefx_funcs = EXCHANGE_FUNCS(truefx,EXCHANGE_NAME);

#include "exchange_undefs.h"
