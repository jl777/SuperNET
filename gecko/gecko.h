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
#define GECKO_EASIESTDIFF 0x1f7fffff
#define GECKO_DEFAULTDIFF 0x1f00ffff
#define GECKO_DEFAULTDIFFSTR "1f00ffff"

#define GECKO_FIRSTPOSSIBLEBTC 414000
#define GECKO_FIRSTPOSSIBLEBTCD 1100000
#define GECKO_MAXNAMELEN 64
#define GECKO_MAXMINERITERS 10000000
#define GECKO_DIFFITERS 13
#define GECKO_MAXFUTUREBLOCK 60

struct iguana_peer;

/*struct hashstamp { bits256 hash2; uint32_t timestamp; int32_t height; };
struct gecko_sequence { struct hashstamp *stamps; int32_t lastupdate,maxstamps,numstamps,lasti,longestchain; };
struct gecko_sequences { struct gecko_sequence BTC,BTCD; };*/

//{"genesishash":"633edf349442dea79aa308b286f5368d34f887c898e3c1b4c728679891160000","genesisblock":"010000000000000000000000000000000000000000000000000000000000000000000000413d9e3a8f530415b548973af6545e7a8902d005782478d061295d795f29d68054766a57ffff001f091c070b010100000054766a57011be5d2440c9fb34410947ed9e378478b66d9809f60d17c8d89301ad321ec5912ffffffff050000000000ffffffff0000000000","netmagic":"a1faaa90","symbol":"DEX","name":"InstantDEX","pubval":"00","p2shval":"05","wifval":"80","nBits":"1f00ffff","chain":"InstantDEX","isPoS":1,"geckochain":"InstantDEX","services":128,"blocktime":10,"targetspacing":10,"targettimespan":2450,"result":"success","tag":"10215666446676071864"}

struct gecko_genesis_opreturn
{
    char symbol[6],name[16];
    uint64_t PoSvalue;
    uint32_t netmagic,timestamp,nBits,nonce;
    uint16_t blocktime;
    uint8_t version,pubval,p2shval,wifval,rmd160[20];
};

struct gecko_memtx
{
    double feeperkb;
    bits256 txid;
    int64_t txfee,inputsum,outputsum;
    int32_t pending,numinputs,numoutputs,datalen;
    uint32_t ipbits;
    bits256 data256[];
};

struct gecko_mempool
{
    int32_t numtx; uint32_t ipbits;
    bits256 txids[0xffff];
    struct gecko_memtx **txs;
};

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

void gecko_miner(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_info *virt,int32_t maxmillis,uint8_t *minerpubkey33);
void gecko_seqresult(struct supernet_info *myinfo,char *retstr);
int32_t gecko_sequpdate(struct supernet_info *myinfo,char *symbol,uint32_t reftimestamp);
char *gecko_blockarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 hash2,int32_t verifyonly);
char *gecko_txarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 hash2);
char *gecko_mempoolarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 hash2);
char *gecko_headersarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 hash2);
char *gecko_sendrawtransaction(struct supernet_info *myinfo,char *symbol,uint8_t *data,int32_t datalen,bits256 txid,cJSON *vals,char *signedtx);

struct gecko_mempool *gecko_mempoolfind(struct supernet_info *myinfo,struct iguana_info *virt,int32_t *numotherp,uint32_t ipbits);
void gecko_iteration(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_info *virt,int32_t maxmillis);
int32_t gecko_opreturn_create(uint8_t *serialized,char *symbol,char *name,char *coinaddr,int64_t PoSvalue,uint32_t nBits,uint16_t blocktime,uint8_t p2shval,uint8_t wifval);

#endif
