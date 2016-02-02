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

#ifndef INCLUDE_PAX_H
#define INCLUDE_PAX_H

#define PEGGY_GENESIS "6aef504158ec0014fee05dc20a0006048ed63e523f6d1062feb23622da928cf23ddcc3b53f23566bc6cab5ebd77cfbf8f0bccb34bff73c55d742dd232994bfbffe1cbab7119ab3d653a256b02d5b6f56c05b8817799f0d242f48c26d35c992ebfff14acdefbe253345d394e84d975334cd55f7d6cbad5a7bd9425b1d5db44944d40be5304b7b62ba0dbc20d3323d2b35f05f654bc95a5a2fdb5a30e46c6fd33b5ea078255f7cad9fd0dbd2fa5031ada4474cbba7b2ee64ef35df06bf3fd3eef6cd3f48339f3c0e080158a92862bbf20bc6702018effbaee525502eb463c74f7ca0dff4ae7cb55ee55ef7cb1c915e655649"

#include "iguana777.h"
// CfB "the rule is simple = others can know the redemption day only AFTER the price for that day is set in stone."
#define PEGGY_NUMCOEFFS 539
#define ACCTS777_MAXRAMKVS 8
#define BTCDADDRSIZE 36

#define HASH_SIZE 32
#define PEGGY_MINUTE 60
#define PEGGY_HOURTICKS (PEGGY_MINUTE * 60)
#define PEGGY_DAYTICKS (24 * PEGGY_HOURTICKS)
#define MAX_TIMEFRAME (24 * 3600 * 365)
#define MAX_PEGGYDAYS (365)
#define PEGGY_MINEXTRADAYS 3

#define PEGGY_MAXPRICEDPEGS 64
#define PEGGY_MAXPAIREDPEGS 4096
#define PEGGY_MAXPEGS (PEGGY_MAXPRICEDPEGS + PEGGY_MAXPAIREDPEGS)

#define PEGGY_MAXVOTERS 4096
#define PEGGY_MARGINMAX 100
#define PEGGY_MIXRANGE 7777
#define PEGGY_MARGINLOCKDAYS 30
#define PEGGY_MARGINGAPDAYS 7

#define PEGGY_RATE_777 2052

#define OP_RETURN_OPCODE 0x6a
#define OPRETURNS_CONTEXTS 2

#define MAX_OPRETURNSIZE 4096
#define PEGGY_MAXLOCKDAYS 180
#define PEGGY_PASTSTAMP 3600
#define PEGGY_FUTURESTAMP 60

#define PEGGY_RSTATUS_REDEEMED 0
#define PEGGY_RSTATUS_AUTOPURGED 1
#define PEGGY_RSTATUS_MARGINCALL 2

#define PEGGY_FLAGS_HASFUNDING 1
#define PEGGY_FLAGS_PEGGYBASE 2

#define PEGGY_ADDRBTCD 0
#define PEGGY_ADDRCREATE 1
#define PEGGY_ADDRNXT 2
#define PEGGY_ADDRUNIT 3
#define PEGGY_ADDRPUBKEY 4
#define PEGGY_ADDR777 5
#define PEGGY_ADDRFUNDING 6

#define USD 0
#define EUR 1
#define JPY 2
#define GBP 3
#define AUD 4
#define CAD 5
#define CHF 6
#define NZD 7
#define CNY 8
#define RUB 9

#define NZDUSD 0
#define NZDCHF 1
#define NZDCAD 2
#define NZDJPY 3
#define GBPNZD 4
#define EURNZD 5
#define AUDNZD 6
#define CADJPY 7
#define CADCHF 8
#define USDCAD 9
#define EURCAD 10
#define GBPCAD 11
#define AUDCAD 12
#define USDCHF 13
#define CHFJPY 14
#define EURCHF 15
#define GBPCHF 16
#define AUDCHF 17
#define EURUSD 18
#define EURAUD 19
#define EURJPY 20
#define EURGBP 21
#define GBPUSD 22
#define GBPJPY 23
#define GBPAUD 24
#define USDJPY 25
#define AUDJPY 26
#define AUDUSD 27

#define USDNUM 28
#define EURNUM 29
#define JPYNUM 30
#define GBPNUM 31
#define AUDNUM 32
#define CADNUM 33
#define CHFNUM 34
#define NZDNUM 35

#define NUM_CONTRACTS 28
#define NUM_CURRENCIES 8
#define NUM_COMBINED (NUM_CONTRACTS + NUM_CURRENCIES)
#define MAX_SPLINES 64
#define MAX_LOOKAHEAD 48

#define MAX_EXCHANGES 64
#define MAX_CURRENCIES 32

#define PRICE_RESOLUTION_ROOT ((int64_t)3163)
#define PRICE_RESOLUTION (PRICE_RESOLUTION_ROOT * PRICE_RESOLUTION_ROOT) // 10004569
#define PRICE_RESOLUTION2 (PRICE_RESOLUTION * PRICE_RESOLUTION) // 100091400875761
#define PRICE_RESOLUTION_MAXPVAL ((int64_t)3037000500u)  // 303.5613528178975 vs 64 bits: 4294967295  429.30058206405493,
#define PRICE_RESOLUTION_MAXUNITS ((int16_t)((int64_t)0x7fffffffffffffffLLu / (SATOSHIDEN * PRICE_RESOLUTION)))  // 9219
#define SCALED_PRICE(val,scale) (((scale) * (val)) / PRICE_RESOLUTION)
#define Pval(r) ((double)(r)->Pval / PRICE_RESOLUTION)  // for display only!
#define PERCENTAGE(perc) (((perc) * PRICE_RESOLUTION) / 100)

struct price_resolution { int64_t Pval; };
struct peggy_lock { int16_t peg,denom; uint16_t minlockdays,maxlockdays,clonesmear,mixrange,redemptiongapdays; uint8_t extralockdays,margin; };

struct peggy_newunit { bits256 sha256; struct peggy_lock newlock; };
struct peggy_univaddr { uint8_t addrtype,rmd160[20]; char coin[7]; };
union peggy_addr { struct peggy_univaddr coinaddr; struct peggy_newunit newunit; bits256 sha256; bits384 SaMbits; uint64_t nxt64bits; };
struct peggy_input { uint8_t type,chainlen; union peggy_addr src; uint64_t amount; };
struct peggy_output { uint8_t type,vin; union peggy_addr dest; uint32_t ratio; };

struct peggy_txprices { uint16_t num,maxlockdays; uint32_t timestamp; uint32_t feed[256]; };
struct peggy_txbet { struct price_resolution prediction; char peg[15],binary; };
struct peggy_txmicropay { bits256 claimhash,refundhash; uint32_t expiration; uint8_t chainlen,vin,vout; };
struct peggy_time { uint32_t blocknum,blocktimestamp; };
struct peggy_units { int64_t num,numoppo; };
struct peggy_margin { int64_t deposits,margindeposits,marginvalue; };
struct peggy_description { char name[32],base[16],rel[16]; uint64_t basebits,relbits,assetbits; int16_t id,baseid,relid; int8_t hasprice,enabled; };
struct peggy_pool { struct peggy_margin funds; struct peggy_units liability; uint64_t quorum,decisionthreshold,mainunitsize,mainbits; };
//struct peggy_limits { int64_t scales[MAX_TIMEFRAMES],maxsupply,maxnetbalance; uint32_t timeframes[MAX_TIMEFRAMES],numtimeframes; };

#define PEGGY_MAXSIGS 16
#define PEGGY_MAXINPUTS 15
#define PEGGY_MAXOUTPUTS 16

#define PEGGY_TXNORMAL 0
#define PEGGY_TXBET 1
#define PEGGY_TXPRICES 2
#define PEGGY_TXTUNE 3
#define PEGGY_TXMICROPAY 4
union peggy_bytes8 { uint8_t bytes[8]; uint64_t val; };
struct peggy_txtune { char type,peg[15]; uint64_t val; union peggy_bytes8 B; };

union peggy_txtype
{
    struct peggy_txprices price; struct peggy_txbet bets[64]; struct peggy_txtune tune[64];
    struct peggy_txmicropay micropays[16];
};

struct PAX_sig { bits256 sigbits,pubkey; uint64_t signer64bits; uint32_t timestamp,allocsize; };

struct peggy_tx
{
    uint16_t datalen; uint8_t numinputs,numoutputs,txtype,flags,msglen,numdetails; uint32_t timestamp,activation,expiration;
    struct peggy_input inputs[PEGGY_MAXINPUTS],funding; struct peggy_output outputs[PEGGY_MAXOUTPUTS];
    union peggy_txtype details; char hexstr[512];
    uint8_t data[4096];
    struct PAX_sig sigs[PEGGY_MAXSIGS];
    //uint64_t required;
};

struct peggy_unit
{
    int64_t estimated_interest,costbasis,amount,marginamount; uint32_t timestamp; int16_t dailyrate; uint8_t baseid,relid;
    struct peggy_lock lock; bits256 lockhash;
};

struct peggy
{
    struct peggy_description name; struct peggy_pool pool; struct peggy_lock lockparms; int64_t maxsupply,maxnetbalance;
    struct price_resolution spread,mindenomination,genesisprice,price,dayprice; uint32_t day,genesistime,maxdailyrate,unitincr,peggymils;
    uint32_t dayprices[MAX_PEGGYDAYS],*baseprices,*relprices; int32_t RTminute;
};

struct peggy_pricedpeg
{
    struct peggy PEG;
    uint32_t prices[MAX_PEGGYDAYS * 1440]; // In main currency units
};

union peggy_pair { struct peggy PEG; struct peggy_pricedpeg pricedPEG; };

struct peggy_bet { struct price_resolution prediction; uint64_t distbet,dirbet,payout,shares,dist; uint32_t timestamp,minutes; };
struct peggy_vote { int32_t pval,tolerance; };//struct price_resolution price,tolerance; uint64_t nxt64bits,weight; };
struct peggy_entry
{
    int64_t total,costbasis,satoshis,royalty,fee,estimated_interest,interest_unlocked,interestpaid,supplydiff,denomination;
    int16_t dailyrate,baseid,relid,polarity;
    struct peggy_units supply; struct price_resolution price,oppoprice;
};

struct peggy_balances {  struct peggy_margin funds; int64_t privatebetfees,crypto777_royalty,APRfund,APRfund_reserved; };

struct PAX_data
{
    uint32_t ttimestamps[128]; double tbids[128],tasks[128];
    uint32_t ftimestamps[128]; double fbids[128],fasks[128];
    uint32_t itimestamps[128]; double ibids[128],iasks[128];
    char edate[128]; double ecbmatrix[32][32],dailyprices[MAX_CURRENCIES * MAX_CURRENCIES],metals[4];
    int32_t ecbdatenum,ecbyear,ecbmonth,ecbday; double RTmatrix[32][32],RTprices[128],RTmetals[4];
    double btcusd,btcdbtc,cryptos[8];
};

struct PAX_spline { char name[64]; int32_t splineid,lasti,basenum,num,firstx,dispincr,spline32[MAX_SPLINES][4]; uint32_t utc32[MAX_SPLINES]; int64_t spline64[MAX_SPLINES][4]; double dSplines[MAX_SPLINES][4],pricevals[MAX_SPLINES+MAX_LOOKAHEAD],lastutc,lastval,aveslopeabs; };

struct peggy_info
{
    char maincurrency[16]; uint64_t basebits[256],mainbits,mainunitsize,quorum,decisionthreshold; int64_t hwmbalance,worstbalance,maxdrawdown;
    struct price_resolution default_spread; struct peggy_lock default_lockparms;
    struct peggy_balances bank,basereserves[256];
    int32_t default_dailyrate,interesttenths,posboost,negpenalty,feediv,feemult;
    int32_t numpegs,numpairedpegs,numpricedpegs,numopreturns,numvoters;
    struct accts777_info *accts;
    struct PAX_data data,tmp; double cryptovols[2][8][2],btcusd,btcdbtc,cnyusd;
    char path[512],*genesis; uint32_t genesistime,BTCD_price0,lastupdate;
    struct PAX_spline splines[128];
    struct peggy_vote votes[PEGGY_MAXPRICEDPEGS][PEGGY_MAXVOTERS];
    struct peggy *contracts[PEGGY_MAXPEGS];
    struct peggy pairedpegs[PEGGY_MAXPRICEDPEGS + PEGGY_MAXPAIREDPEGS];
    struct peggy_pricedpeg pricedpegs[PEGGY_MAXPRICEDPEGS];
};

struct txinds777_hdr { int64_t num,nextpos; uint32_t blocknum,timestamp,firstblocknum,lastblocknum; struct sha256_vstate state; bits256 sha256; };
struct txinds777_info
{
    struct txinds777_hdr H;
    FILE *txlogfp,*indexfp,*fp; char path[512],name[64]; int64_t curitem,*blockitems;
};

int64_t txind777_bundle(struct txinds777_info *txinds,uint32_t blocknum,uint32_t timestamp,int64_t *bundle,int32_t numtx);
int64_t txind777_create(struct txinds777_info *txinds,uint32_t blocknum,uint32_t timestamp,void *txdata,uint16_t len);
int32_t txind777_txbuf(uint8_t *txbuf,int32_t len,uint64_t val,int32_t size);
int32_t txinds777_flush(struct txinds777_info *txinds,uint32_t blocknum,uint32_t blocktimestamp);
struct txinds777_info *txinds777_init(char *path,char *name);
int64_t txinds777_seek(struct txinds777_info *txinds,uint32_t blocknum);
void *txinds777_read(int32_t *lenp,uint8_t *buf,struct txinds777_info *txinds);
void txinds777_purge(struct txinds777_info *txinds);

struct ramkv777_item { UT_hash_handle hh; uint16_t valuesize,tbd; uint32_t rawind; uint8_t keyvalue[]; };

struct ramkv777
{
    char name[63],threadsafe;
    portable_mutex_t mutex;
    struct ramkv777_item *table;
    void **list; int32_t listsize,listmax;
    struct sha256_vstate state; bits256 sha256;
    int32_t numkeys,keysize,dispflag; uint8_t kvind;
};

#define ramkv777_itemsize(kv,valuesize) (sizeof(struct ramkv777_item) + (kv)->keysize + valuesize)
#define ramkv777_itemkey(item) (item)->keyvalue
#define ramkv777_itemvalue(kv,item) (&(item)->keyvalue[(kv)->keysize])

struct ramkv777_item *ramkv777_itemptr(struct ramkv777 *kv,void *value);
int32_t ramkv777_clone(struct ramkv777 *clone,struct ramkv777 *kv);
void ramkv777_free(struct ramkv777 *kv);

int32_t ramkv777_delete(struct ramkv777 *kv,void *key);
void *ramkv777_write(struct ramkv777 *kv,void *key,void *value,int32_t valuesize);
void *ramkv777_read(int32_t *valuesizep,struct ramkv777 *kv,void *key);
void *ramkv777_iterate(struct ramkv777 *kv,void *args,void *(*iterator)(struct ramkv777 *kv,void *args,void *key,void *value,int32_t valuesize));
struct ramkv777 *ramkv777_init(int32_t kvind,char *name,int32_t keysize,int32_t threadsafe);

struct acct777 { uint32_t firstblocknum,firsttimestamp; int64_t balance; };

struct accts777_info
{
    queue_t PaymentsQ;
    uint64_t balance;
    struct peggy_unit *units;
    int32_t numunits; uint8_t numkvs;
    struct ramkv777 *bets,*pricefeeds,*hashaddrs,*coinaddrs,*SaMaddrs,*nxtaddrs,*addrkvs[16];
    bits256 peggyhash;
    struct txinds777_info *txinds;
};

struct accts777_info *accts777_init(char *dirname,struct txinds777_info *txinds);

#define YAHOO_METALS "XAU", "XAG", "XPT", "XPD"
extern char *peggy_bases[64],CURRENCIES[][8];
extern int32_t MINDENOMS[],Peggy_inds[],dailyrates[];

struct price_resolution peggy_scaleprice(struct price_resolution price,int64_t peggymils);
char *peggy_tx(char *jsonstr);
void _crypto_update(struct peggy_info *PEGS,double cryptovols[2][8][2],struct PAX_data *dp,int32_t selector,int32_t peggyflag);
int32_t PAX_idle(struct peggy_info *PEGS,int32_t peggyflag,int32_t idlegap);
int32_t PAX_genspline(struct PAX_spline *spline,int32_t splineid,char *name,uint32_t *utc32,double *splinevals,int32_t maxsplines,double *refvals);
int32_t PAX_contractnum(char *base,char *rel);
int32_t PAX_basenum(char *base);
int32_t PAX_ispair(char *base,char *rel,char *contract);
void PAX_init(struct peggy_info *PEGS);
uint32_t peggy_mils(int32_t i);
void calc_smooth_code(int32_t smoothwidth,int32_t _maxprimes);
struct peggy *peggy_find(struct peggy_entry *entry,struct peggy_info *PEGS,char *name,int32_t polarity);
struct price_resolution peggy_priceconsensus(struct peggy_info *PEGS,struct peggy_time T,uint64_t seed,int16_t pricedpeg,struct peggy_vote *votes,uint32_t numvotes,struct peggy_bet *bets,uint32_t numbets);
struct price_resolution peggy_price(struct peggy *PEG,int32_t minute);
struct price_resolution peggy_shortprice(struct peggy *PEG,struct price_resolution price);
void peggy_delete(struct accts777_info *accts,struct peggy_unit *U,int32_t reason);
int32_t peggy_setprice(struct peggy *PEG,struct price_resolution price,int32_t minute);
int32_t peggy_pegstr(char *buf,struct peggy_info *PEGS,char *name);
struct acct777 *accts777_find(int32_t *valuesizep,struct accts777_info *accts,union peggy_addr *addr,int32_t type);
struct acct777 *accts777_create(struct accts777_info *accts,union peggy_addr *addr,int32_t type,uint32_t blocknum,uint32_t blocktimestamp);
int64_t acct777_balance(struct accts777_info *accts,uint32_t blocknum,uint32_t blocktimestamp,union peggy_addr *addr,int32_t type);
uint64_t peggy_redeem(struct peggy_info *PEGS,struct peggy_time T,int32_t readonly,char *name,int32_t polarity,uint64_t nxt64bits,bits256 pubkey,uint16_t lockdays,uint8_t chainlen);
#define accts777_getaddrkv(accts,type) ((accts != 0) ? (accts)->addrkvs[type] : 0)
uint64_t peggy_poolmainunits(struct peggy_entry *entry,int32_t dir,int32_t polarity,struct price_resolution price,struct price_resolution oppoprice,struct price_resolution spread,uint64_t poolincr,int16_t denomunits);
int32_t acct777_pay(struct accts777_info *accts,struct acct777 *srcacct,struct acct777 *acct,int64_t value,uint32_t blocknum,uint32_t blocktimestamp);
struct peggy *peggy_findpeg(struct peggy_entry *entry,struct peggy_info *PEGS,int32_t peg);
void peggy_thanks_you(struct peggy_info *PEGS,int64_t tip);
uint64_t peggy_createunit(struct peggy_info *PEGS,struct peggy_time T,struct peggy_unit *readU,uint64_t seed,char *name,uint64_t nxt64bits,bits256 lockhash,struct peggy_lock *lock,uint64_t amount,uint64_t marginamount);
int32_t peggy_swap(struct accts777_info *accts,uint64_t signerA,uint64_t signerB,bits256 hashA,bits256 hashB);
int32_t peggy_aprpercs(int64_t dailyrate);
int64_t peggy_lockrate(struct peggy_entry *entry,struct peggy_info *PEGS,struct peggy *PEG,uint64_t satoshis,uint16_t numdays);
char *peggy_emitprices(int32_t *nonzp,struct peggy_info *PEGS,uint32_t blocktimestamp,int32_t maxlockdays);
int64_t peggy_compound(int32_t dispflag,int64_t satoshis,int64_t dailyrate,int32_t n);

#define MAX_OPRETURNSIZE 4096
struct opreturn_payment { struct queueitem DL; uint64_t value; char coinaddr[BTCDADDRSIZE]; };
struct opreturn_entry { struct opreturn_payment vout; uint32_t timestamp,blocknum; uint16_t isstaked,txind,v,datalen; uint8_t data[MAX_OPRETURNSIZE]; };

int64_t peggy_process(void *context,int32_t flags,void *fundedcoinaddr,uint64_t fundedvalue,uint8_t *data,int32_t datalen,uint32_t currentblocknum,uint32_t blocktimestamp,uint32_t stakedblock);
int32_t opreturns_gotnewblock(uint32_t blocknum,uint32_t blocktimestamp,char *opreturns[],int32_t numopreturns,char *peggybase_opreturnstr);
char *opreturns_stakinginfo(char opreturnstr[8192],uint32_t blocknum,uint32_t blocktimestamp);

int32_t opreturns_process(int32_t flags,uint32_t currentblocknum,uint32_t blocknum,uint32_t blocktimestamp,struct opreturn_entry *list,int32_t num,uint8_t *peggyopreturn,int32_t peggylen);
int32_t opreturns_queue_payment(queue_t *PaymentsQ,uint32_t blocktimestamp,char *coinaddr,int64_t value);
int32_t opreturns_init(uint32_t blocknum,uint32_t blocktimestamp,char *path);
void *opreturns_context(char *name,int32_t context);
long hdecode_varint(uint64_t *valp,uint8_t *ptr,long offset,long mappedsize);

uint64_t conv_acctstr(char *acctstr);
int32_t serdes777_deserialize(int32_t *signedcountp,struct peggy_tx *Ptx,uint32_t blocktimestamp,uint8_t *data,int32_t totallen);
int32_t serdes777_serialize(struct peggy_tx *Ptx,uint32_t blocktimestamp,bits256 privkey,uint32_t timestamp);
int32_t peggy_univ2addr(char *coinaddr,struct peggy_univaddr *ua);
int32_t peggy_addr2univ(struct peggy_univaddr *ua,char *coinaddr,char *coin);
uint64_t PAX_validate(struct PAX_sig *sig,uint32_t timestamp,uint8_t *data,int32_t datalen);
uint64_t PAX_signtx(struct PAX_sig *sig,bits256 privkey,uint32_t timestamp,uint8_t *data,int32_t datalen);

int64_t peggy_process(void *context,int32_t flags,void *fundedcoinaddr,uint64_t fundedvalue,uint8_t *data,int32_t datalen,uint32_t currentblocknum,uint32_t blocktimestamp,uint32_t stakedblock);
int32_t peggy_emit(void *context,uint8_t opreturndata[MAX_OPRETURNSIZE],struct opreturn_payment *payments,int32_t max,uint32_t currentblocknum,uint32_t blocknum,uint32_t blocktimestamp);
int32_t peggy_flush(void *context,uint32_t currentblocknum,uint32_t blocknum,uint32_t blocktimestamp);
int32_t peggy_init_contexts(struct txinds777_info *opreturns,uint32_t blocknum,uint32_t blocktimestamp,char *path,void *globals[OPRETURNS_CONTEXTS],int32_t lookbacks[OPRETURNS_CONTEXTS],int32_t maxcontexts);
uint32_t peggy_clone(char *path,void *dest,void *src);
void *peggy_replay(char *path,struct txinds777_info *opreturns,void *_PEGS,uint32_t blocknum,char *opreturnstr,uint8_t *data,int32_t datalen);
uint32_t peggy_currentblock(void *globals);

struct peggy_unit *peggy_match(struct accts777_info *accts,int32_t peg,uint64_t nxt64bits,bits256 lockhash,uint16_t lockdays);
int32_t peggy_addunit(struct accts777_info *accts,struct peggy_unit *U,bits256 lockhash);

#endif
