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

struct basilisk_item *basilisk_issueremote(struct supernet_info *myinfo,char *type,cJSON *vals,int32_t fanout,int32_t minresults,uint32_t basilisktag,int32_t timeoutmillis,void *metricfunc,char *retstr);
void basilisks_init(struct supernet_info *myinfo);
int32_t basilisk_sendcmd(struct supernet_info *myinfo,char *destipaddr,char *type,uint32_t basilisktag,int32_t encryptflag,int32_t delaymillis,uint8_t *data,int32_t datalen,int32_t fanout); // data must be offset by sizeof(iguana_msghdr)
void basilisk_p2p(void *myinfo,void *_addr,int32_t *delaymillisp,char *ipaddr,uint8_t *data,int32_t datalen,char *type,int32_t encrypted);
uint8_t *basilisk_jsondata(void **ptrp,uint8_t *space,int32_t spacesize,int32_t *datalenp,cJSON *sendjson,uint32_t basilisktag);

uint8_t *SuperNET_ciphercalc(void **ptrp,int32_t *cipherlenp,bits256 *privkeyp,bits256 *destpubkeyp,uint8_t *data,int32_t datalen,uint8_t *space2,int32_t space2size);
void *SuperNET_deciphercalc(void **ptrp,int32_t *msglenp,bits256 privkey,bits256 srcpubkey,uint8_t *cipher,int32_t cipherlen,uint8_t *buf,int32_t bufsize);

#endif
