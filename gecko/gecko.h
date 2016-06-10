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

#ifndef H_GECKO_H
#define H_GECKO_H

#define GECKO_MAXBTCGAP 9
#define GECKO_MAXBTCDGAP 18

#define GECKO_DEFAULTVERSION 1
#define GECKO_EASIESTDIFF 0x1fffffff
#define GECKO_DEFAULTDIFF 0x1f00ffff
#define GECKO_DEFAULTDIFFSTR "1f00ffff"

#define GECKO_FIRSTPOSSIBLEBTC 414000
#define GECKO_FIRSTPOSSIBLEBTCD 1100000
#define GECKO_MAXNAMELEN 64
#define GECKO_MAXMINERITERS 10000000
#define GECKO_DIFFITERS 3

struct iguana_peer;

struct hashstamp { bits256 hash2; uint32_t timestamp; int32_t height; };
struct gecko_sequence { struct hashstamp *stamps; int32_t lastupdate,maxstamps,numstamps,lasti,longestchain; };
struct gecko_sequences { struct gecko_sequence BTC,BTCD; };

struct gecko_chain
{
    UT_hash_handle hh; queue_t Q;
    char *(*processfunc)(struct supernet_info *myinfo,struct gecko_chain *cat,void *data,int32_t datalen,char *remoteaddr);
    bits256 hash; struct gecko_chain *subchains; struct iguana_info *info;
};

struct gecko_chain *gecko_chain(struct supernet_info *myinfo,char chainname[GECKO_MAXNAMELEN],cJSON *valsobj);

char *basilisk_respond_geckogenesis(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 txid,int32_t from_basilisk);
char *basilisk_respond_hashstamps(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk);
char *basilisk_respond_newgeckochain(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk);
char *basilisk_respond_geckotx(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk);
char *basilisk_respond_geckoblock(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk);
char *basilisk_respond_geckoheaders(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash2,int32_t from_basilisk);
char *basilisk_respond_geckoget(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash2,int32_t from_basilisk);

void gecko_miner(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_info *virt,int32_t maxmillis,char *mineraddr);
void gecko_seqresult(struct supernet_info *myinfo,char *retstr);
int32_t gecko_sequpdate(char *symbol,uint32_t reftimestamp);
char *gecko_blockarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 hash2);
char *gecko_txarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 hash2);
char *gecko_headersarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 hash2);

#endif
