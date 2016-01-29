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

#define EXCHANGES777_MAXDEPTH 200
#define EXCHANGES777_DEFAULT_TIMEOUT 30

struct exchange_info;
struct exchange_quote { double price,volume; uint64_t orderid,offerNXT; uint32_t timestamp; };

struct exchange_request
{
    struct queueitem DL;
    cJSON *argjson; char **retstrp;
    double price,volume,hbla,lastbid,lastask;
    uint64_t orderid;
    int32_t dir,depth,func,numbids,numasks;
    char base[16],rel[16],destaddr[64],invert,allflag,dotrade;
    struct exchange_quote bidasks[];
};

struct exchange_funcs
{
    char name[32];
    double (*price)(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *quotes,int32_t maxdepth,cJSON *argjson);
    int32_t (*supports)(struct exchange_info *exchange,char *base,char *rel,cJSON *argjson);
    char *(*parsebalance)(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson);
    cJSON *(*balances)(struct exchange_info *exchange,cJSON *argjson);
    uint64_t (*trade)(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson);
    char *(*orderstatus)(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson);
    char *(*cancelorder)(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson);
    char *(*openorders)(struct exchange_info *exchange,cJSON *argjson);
    char *(*tradehistory)(struct exchange_info *exchange,cJSON *argjson);
    char *(*withdraw)(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson);
};
#define EXCHANGE_FUNCS(xchg,name) { name, xchg ## _price, xchg ## _supports, xchg ## _parsebalance, xchg ## _balances, xchg ## _trade, xchg ## _orderstatus, xchg ## _cancelorder, xchg ## _openorders, xchg ## _tradehistory, xchg ## _withdraw }

struct exchange_info
{
    struct exchange_funcs issue;
    char name[16],apikey[MAX_JSON_FIELD],apisecret[MAX_JSON_FIELD],tradepassword[MAX_JSON_FIELD],userid[MAX_JSON_FIELD];
    uint32_t exchangeid,pollgap,lastpoll;
    uint64_t lastnonce; double commission;
    CURL *cHandle; queue_t requestQ,pricesQ,pendingQ[2];
};

void *curl_post(void **cHandlep,char *url,char *userpass,char *postfields,char *hdr0,char *hdr1,char *hdr2,char *hdr3);

void prices777_processprice(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *bidasks,int32_t maxdepth);
#endif
