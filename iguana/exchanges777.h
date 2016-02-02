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

#ifndef EXCHANGES777_H
#define EXCHANGES777_H
#include "iguana777.h"

#include <curl/curl.h>
#include <curl/easy.h>

#define EXCHANGES777_MINPOLLGAP 3
#define EXCHANGES777_MAXDEPTH 200
#define EXCHANGES777_DEFAULT_TIMEOUT 30

struct exchange_info;

struct exchange_funcs
{
    char name[32];
    double (*price)(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *quotes,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert);
    int32_t (*supports)(struct exchange_info *exchange,char *base,char *rel,cJSON *argjson);
    char *(*parsebalance)(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson);
    cJSON *(*balances)(struct exchange_info *exchange,cJSON *argjson);
    uint64_t (*trade)(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson);
    char *(*orderstatus)(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson);
    char *(*cancelorder)(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson);
    char *(*openorders)(struct exchange_info *exchange,cJSON *argjson);
    char *(*tradehistory)(struct exchange_info *exchange,cJSON *argjson);
    char *(*withdraw)(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson);
    char *(*allpairs)(struct exchange_info *exchange,cJSON *argjson);
};
#define EXCHANGE_FUNCS(xchg,name) { name, xchg ## _price, xchg ## _supports, xchg ## _parsebalance, xchg ## _balances, xchg ## _trade, xchg ## _orderstatus, xchg ## _cancelorder, xchg ## _openorders, xchg ## _tradehistory, xchg ## _withdraw, xchg ## _allpairs }

struct exchange_info
{
    struct exchange_funcs issue;
    char name[16],apikey[MAX_JSON_FIELD],apisecret[MAX_JSON_FIELD],tradepassword[MAX_JSON_FIELD],userid[MAX_JSON_FIELD];
    uint32_t exchangeid,pollgap,lastpoll;
    uint64_t lastnonce,exchangebits; double commission;
    void *privatedata;
    CURL *cHandle; queue_t requestQ,pricesQ,pendingQ[2],tradebotsQ;
};

struct instantdex_msghdr
{
    struct acct777_sig sig __attribute__((packed));
    char cmd[8];
    uint8_t serialized[];
} __attribute__((packed));

struct exchange_request
{
    struct queueitem DL;
    cJSON *argjson; char **retstrp; struct exchange_info *exchange;
    double price,volume,hbla,lastbid,lastask,commission;
    uint64_t orderid; uint32_t timedout,expiration,dead,timestamp;
    int32_t dir,depth,func,numbids,numasks;
    char base[32],rel[32],destaddr[64],invert,allflag,dotrade;
    struct exchange_quote bidasks[];
};

void *curl_post(void **cHandlep,char *url,char *userpass,char *postfields,char *hdr0,char *hdr1,char *hdr2,char *hdr3);
char *InstantDEX_hexmsg(struct supernet_info *myinfo,void *data,int32_t len,char *remoteaddr);
char *instantdex_sendcmd(struct supernet_info *myinfo,cJSON *argjson,char *cmdstr,char *ipaddr,int32_t hops);
char *exchanges777_Qprices(struct exchange_info *exchange,char *base,char *rel,int32_t maxseconds,int32_t allfields,int32_t depth,cJSON *argjson,int32_t monitor,double commission);
struct exchange_info *exchanges777_info(char *exchangestr,int32_t sleepflag,cJSON *json,char *remoteaddr);
char *exchanges777_unmonitor(struct exchange_info *exchange,char *base,char *rel);
void tradebot_timeslice(struct exchange_info *exchange,void *bot);
char *exchanges777_Qtrade(struct exchange_info *exchange,char *base,char *rel,int32_t maxseconds,int32_t dotrade,int32_t dir,double price,double volume,cJSON *argjson);
struct exchange_request *exchanges777_baserelfind(struct exchange_info *exchange,char *base,char *rel,int32_t func);
struct exchange_info *exchanges777_find(char *exchangestr);

void prices777_processprice(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *bidasks,int32_t maxdepth);

double truefx_price(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *bidasks,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert);
double fxcm_price(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *bidasks,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert);
double instaforex_price(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *bidasks,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert);

#endif
