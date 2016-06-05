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

#define BASILISK_MAXFUTUREBLOCK 60
#define BASILISK_MAXBLOCKLAG 600
#define BASILISK_MAXBTCGAP 9
#define BASILISK_MAXBTCDGAP 18

#define BASILISK_DEFAULTVERSION 1
#define BASILISK_DEFAULTDIFF 0x1effffff
#define BASILISK_DEFAULTDIFFSTR "1effffff"

#define BASILISK_FIRSTPOSSIBLEBTC 414000
#define BASILISK_FIRSTPOSSIBLEBTCD 1100000
#define BASILISK_MAXNAMELEN 64

struct hashstamp { bits256 hash2; uint32_t timestamp; int32_t height; };
struct basilisk_sequence { struct hashstamp *stamps; int32_t lastupdate,maxstamps,numstamps,lasti,longestchain; };
struct basilisk_sequences { struct basilisk_sequence BTC,BTCD; };

struct basilisk_value { bits256 txid; int64_t value; int32_t height; int16_t vout; char coinaddr[64]; };

struct basilisk_item
{
    struct queueitem DL; UT_hash_handle hh; struct basilisk_item *parent; void *dependents;
    uint32_t submit,finished,basilisktag,numresults,numsent,numexact,uniqueflag,numrequired,childrendone,numchildren,nBits;
    char symbol[32],CMD[4]; double expiration; cJSON *vals; int32_t metricdir; void *metricfunc;
    char *retstr,*results[BASILISK_MAXFANOUT]; double metrics[BASILISK_MAXFANOUT];
};

struct basilisk_info
{
    queue_t resultsQ,submitQ; void *launched; //portable_mutex_t *mutex; 
    struct basilisk_item *issued;
    struct basilisk_value values[8192]; int32_t numvalues;
};

void basilisk_msgprocess(struct supernet_info *myinfo,void *addr,uint32_t senderipbits,char *type,uint32_t basilisktag,uint8_t *data,int32_t datalen,bits256 pubkey);

void basilisks_init(struct supernet_info *myinfo);
void basilisk_p2p(void *myinfo,void *_addr,int32_t *delaymillisp,char *ipaddr,uint8_t *data,int32_t datalen,char *type,int32_t encrypted);
uint8_t *basilisk_jsondata(void **ptrp,uint8_t *space,int32_t spacesize,int32_t *datalenp,char *symbol,cJSON *sendjson,uint32_t basilisktag);

uint8_t *SuperNET_ciphercalc(void **ptrp,int32_t *cipherlenp,bits256 *privkeyp,bits256 *destpubkeyp,uint8_t *data,int32_t datalen,uint8_t *space2,int32_t space2size);
void *SuperNET_deciphercalc(void **ptrp,int32_t *msglenp,bits256 privkey,bits256 srcpubkey,uint8_t *cipher,int32_t cipherlen,uint8_t *buf,int32_t bufsize);
uint8_t *get_dataptr(uint8_t **ptrp,int32_t *datalenp,uint8_t *space,int32_t spacesize,char *hexstr);
char *basilisk_addhexstr(char **ptrp,cJSON *valsobj,char *strbuf,int32_t strsize,uint8_t *data,int32_t datalen);
char *basilisk_standardservice(char *CMD,struct supernet_info *myinfo,bits256 hash,cJSON *valsobj,char *hexstr,int32_t blockflag); // client side

char *basilisk_respond_hashstamps(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk);
char *basilisk_respond_newprivatechain(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk);
char *basilisk_respond_privatetx(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk);
char *basilisk_respond_privateblock(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk);

void basilisk_request_goodbye(struct supernet_info *myinfo);
int32_t basilisk_update(char *symbol,uint32_t reftimestamp);
void basilisk_seqresult(struct supernet_info *myinfo,char *retstr);

#endif
