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

#ifndef H_BASILISK_H
#define H_BASILISK_H

#include "../iguana/iguana777.h"

#define BASILISK_TIMEOUT 30000
#define BASILISK_MINFANOUT 8
#define BASILISK_MAXFANOUT 64

struct basilisk_value { bits256 txid; int64_t value; int32_t height; int16_t vout; char coinaddr[64]; };

struct basilisk_item
{
    struct queueitem DL; UT_hash_handle hh; struct basilisk_item *parent; void *dependents;
    uint32_t submit,finished,basilisktag,numresults,numexact,uniqueflag,numrequired,childrendone,numchildren;
    char symbol[32]; double expiration; cJSON *vals; int32_t metricdir; void *metricfunc;
    char *retstr,*results[BASILISK_MAXFANOUT]; double metrics[BASILISK_MAXFANOUT];
};

struct basilisk_info
{
    queue_t resultsQ,submitQ; void *launched; //portable_mutex_t *mutex; 
    struct basilisk_item *issued;
    struct basilisk_value values[8192]; int32_t numvalues;
};

struct basilisk_item *basilisk_issueremote(struct supernet_info *myinfo,char *methodstr,char *symbol,cJSON *vals,int32_t timeoutmillis,int32_t fanout,int32_t minresults,uint32_t basilisktag,void *metricfunc,char *retstr);
void basilisks_init(struct supernet_info *myinfo);

#endif
