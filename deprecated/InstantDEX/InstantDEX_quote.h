//
//  sha256.h
//  crypto777
//
//  Created by James on 4/9/15.
//  Copyright (c) 2015 jl777. All rights reserved.
//

#ifndef crypto777_InstantDEX_quote_h
#define crypto777_InstantDEX_quote_h

#include <stdint.h>
#include "../includes/uthash.h"

#define NXT_ASSETID ('N' + ((uint64_t)'X'<<8) + ((uint64_t)'T'<<16))    // 5527630
#define MAX_BUYNXT 10
#define MIN_NQTFEE 100000000
#define NXT_TOKEN_LEN 160

#define GENESISACCT "1739068987193023818"  // NXT-MRCC-2YLS-8M54-3CMAJ
#define GENESISPUBKEYSTR "1259ec21d31a30898d7cd1609f80d9668b4778e3d97e941044b39f0c44d2e51b"
#define GENESISPRIVKEYSTR "1259ec21d31a30898d7cd1609f80d9668b4778e3d97e941044b39f0c44d2e51b"
#define GENESIS_SECRET "It was a bright cold day in April, and the clocks were striking thirteen."
#define GENESISBLOCK "2680262203532249785"

#define NXT_GENESISTIME 1385294400

#define DEFAULT_NXT_DEADLINE 720
#define issue_curl(cmdstr) bitcoind_RPC(0,"curl",cmdstr,0,0,0)
#define issue_NXT(cmdstr) bitcoind_RPC(0,"NXT",cmdstr,0,0,0)
#define issue_NXTPOST(cmdstr) bitcoind_RPC(0,"curl",NXTAPIURL,0,0,cmdstr)
#define fetch_URL(url) bitcoind_RPC(0,"fetch",url,0,0,0)

#define INSTANTDEX_TRIGGERDEADLINE 120
#define _issue_curl(curl_handle,label,url) bitcoind_RPC(curl_handle,label,url,0,0,0)

#define ORDERBOOK_EXPIRATION 3600
#define INSTANTDEX_MINVOL 75
#define INSTANTDEX_MINVOLPERC ((double)INSTANTDEX_MINVOL / 100.)
#define INSTANTDEX_PRICESLIPPAGE 0.001

#define INSTANTDEX_TRIGGERDEADLINE 120
#define JUMPTRADE_SECONDS 100
#define INSTANTDEX_ACCT "4383817337783094122"
#define INSTANTDEX_FEE ((long)(2.5 * SATOSHIDEN))

#define INSTANTDEX_NAME "InstantDEX"
#define INSTANTDEX_NXTAENAME "nxtae"
#define INSTANTDEX_NXTAEUNCONF "unconf"
#define INSTANTDEX_BASKETNAME "basket"
#define INSTANTDEX_ACTIVENAME "active"
#define INSTANTDEX_EXCHANGEID 0
#define INSTANTDEX_UNCONFID 1
#define INSTANTDEX_NXTAEID 2
#define MAX_EXCHANGES 64
#define ORDERBOOK_EXPIRATION 3600


#define NXT_ASSETID ('N' + ((uint64_t)'X'<<8) + ((uint64_t)'T'<<16))    // 5527630
#define BTC_ASSETID ('B' + ((uint64_t)'T'<<8) + ((uint64_t)'C'<<16))    // 4412482
#define LTC_ASSETID ('L' + ((uint64_t)'T'<<8) + ((uint64_t)'C'<<16))
#define PPC_ASSETID ('P' + ((uint64_t)'P'<<8) + ((uint64_t)'C'<<16))
#define NMC_ASSETID ('N' + ((uint64_t)'M'<<8) + ((uint64_t)'C'<<16))
#define DASH_ASSETID ('D' + ((uint64_t)'A'<<8) + ((uint64_t)'S'<<16) + ((uint64_t)'H'<<24))
#define BTCD_ASSETID ('B' + ((uint64_t)'T'<<8) + ((uint64_t)'C'<<16) + ((uint64_t)'D'<<24))

#define USD_ASSETID ('U' + ((uint64_t)'S'<<8) + ((uint64_t)'D'<<16))
#define CNY_ASSETID ('C' + ((uint64_t)'N'<<8) + ((uint64_t)'Y'<<16))
#define EUR_ASSETID ('E' + ((uint64_t)'U'<<8) + ((uint64_t)'R'<<16))
#define RUR_ASSETID ('R' + ((uint64_t)'U'<<8) + ((uint64_t)'R'<<16))

struct InstantDEX_shared
{
    double price,vol;
    uint64_t quoteid,offerNXT,basebits,relbits,baseid,relid; int64_t baseamount,relamount;
    uint32_t timestamp;
    uint16_t duration:14,wallet:1,a:1,isask:1,expired:1,closed:1,swap:1,responded:1,matched:1,feepaid:1,automatch:1,pending:1,minperc:7;
    uint16_t minbuyin,maxbuyin;
};

struct InstantDEX_quote
{
    UT_hash_handle hh;
    struct InstantDEX_shared s; // must be here
    char exchangeid,gui[9],base[8],rel[8];
    char walletstr[];
};

struct InstantDEX_quote *delete_iQ(uint64_t quoteid);
struct InstantDEX_quote *find_iQ(uint64_t quoteid);
struct InstantDEX_quote *create_iQ(struct InstantDEX_quote *iQ,char *walletstr);
uint64_t calc_quoteid(struct InstantDEX_quote *iQ);
cJSON *set_walletstr(cJSON *walletitem,char *walletstr,struct InstantDEX_quote *iQ);
cJSON *InstantDEX_specialorders(uint64_t *quoteidp,uint64_t nxt64bits,char *base,char *special,uint64_t baseamount,int32_t addrtype);
int32_t bidask_parse(int32_t localaccess,struct destbuf *exchangestr,struct destbuf *name,struct destbuf *base,struct destbuf *rel,struct destbuf *gui,struct InstantDEX_quote *iQ,cJSON *json);

int32_t coin777_addrtype(uint8_t *p2shtypep,char *coinstr);

struct prices777_order
{
    struct InstantDEX_shared s; cJSON *retitem; struct prices777 *source; struct pending_trade *pend;
    uint64_t id; double wt,ratio; uint16_t slot_ba;
};
struct prices777_basket
{
    struct prices777 *prices; double wt;
    int32_t groupid,groupsize,aski,bidi;
    char base[64],rel[64];
};
struct prices777_orderentry { struct prices777_order bid,ask; };
#define MAX_GROUPS 8
#define _MAX_DEPTH 100

struct prices777_basketinfo
{
    int32_t numbids,numasks; uint32_t timestamp;
    struct prices777_orderentry book[MAX_GROUPS+1][_MAX_DEPTH];
};

struct NXTtx { uint64_t txid; char fullhash[MAX_JSON_FIELD],utxbytes[MAX_JSON_FIELD],utxbytes2[MAX_JSON_FIELD],txbytes[MAX_JSON_FIELD],sighash[MAX_JSON_FIELD]; };

struct pending_trade
{
    struct queueitem DL;
    struct NXTtx trigger; struct prices777_order order;
    uint64_t triggertxid,txid,quoteid,orderid,my64bits;
    struct prices777 *prices; void *cHandlep; struct exchange_info *exchange; void *bot;
    char *triggertx,*txbytes,extra[128]; uint8_t nxtsecret[2048]; cJSON *tradesjson,*item;
    double price,volume; uint32_t timestamp,finishtime,expiration;
    int32_t dir,type,version,size,dotrade,queueflag,*curlingp;
};

struct prices777
{
    char url[512],exchange[64],base[64],rel[64],lbase[64],lrel[64],key[512],oppokey[512],contract[64],origbase[64],origrel[64];
    uint64_t contractnum,ap_mult,baseid,relid,basemult,relmult; double lastupdate,decay,oppodecay,lastprice,lastbid,lastask;
    uint32_t pollnxtblock,exchangeid,numquotes,updated,lasttimestamp,RTflag,disabled,dirty; int32_t keysize,oppokeysize;
    portable_mutex_t mutex;
    char *orderbook_jsonstrs[2][2];
    struct prices777_basketinfo O,O2; double groupwts[MAX_GROUPS + 1];
    uint8_t changed,type; uint8_t **dependents; int32_t numdependents,numgroups,basketsize; double commission;
    void *tradebot;
    struct prices777_basket basket[];
};

struct exchange_info;
struct exchange_funcs
{
    char *exchange;
    double (*update)(struct prices777 *prices,int32_t maxdepth);
    int32_t (*supports)(char *base,char *rel);
    uint64_t (*trade)(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume);
    char *(*orderstatus)(void **cHandlep,struct exchange_info *exchange,cJSON *argjson,uint64_t quoteid);
    char *(*cancelorder)(void **cHandlep,struct exchange_info *exchange,cJSON *argjson,uint64_t quoteid);
    char *(*openorders)(void **cHandlep,struct exchange_info *exchange,cJSON *argjson);
    char *(*tradehistory)(void **cHandlep,struct exchange_info *exchange,cJSON *argjson);
    cJSON *(*balances)(void **cHandlep,struct exchange_info *exchange);
    char *(*parsebalance)(struct exchange_info *exchange,double *balancep,char *coinstr);
    char *(*withdraw)(void **cHandlep,struct exchange_info *exchange,cJSON *argjson);
};
#define EXCHANGE_FUNCS(xchg,name) { name, prices777_ ## xchg, xchg ## _supports, xchg ## _trade, xchg ## _orderstatus, xchg ## _cancelorder, xchg ## _openorders, xchg ## _tradehistory, xchg ## _balances, xchg ## _parsebalance, xchg ## _withdraw }

struct exchange_info
{
    struct exchange_funcs issue;
    char name[16],apikey[MAX_JSON_FIELD],apisecret[MAX_JSON_FIELD],userid[MAX_JSON_FIELD];
    cJSON *balancejson;
    uint32_t num,exchangeid,pollgap,refcount,polling,lastbalancetime;
    uint64_t nxt64bits,lastnonce; double lastupdate,commission;
    void *cHandle;
    portable_mutex_t mutex;
};

#define calc_predisplinex(startweekind,clumpsize,weekind) (((weekind) - (startweekind))/(clumpsize))
#define _extrapolate_Spline(Splines,gap) ((double)(Splines)[0] + ((gap) * ((double)(Splines)[1] + ((gap) * ((double)(Splines)[2] + ((gap) * (double)(Splines)[3]))))))
#define _extrapolate_Slope(Splines,gap) ((double)(Splines)[1] + ((gap) * ((double)(Splines)[2] + ((gap) * (double)(Splines)[3]))))

#define PRICE_BLEND(oldval,newval,decay,oppodecay) ((oldval == 0.) ? newval : ((oldval * decay) + (oppodecay * newval)))
#define PRICE_BLEND64(oldval,newval,decay,oppodecay) ((oldval == 0) ? newval : ((oldval * decay) + (oppodecay * newval) + 0.499))

struct prices777 *prices777_initpair(int32_t needfunc,char *exchange,char *base,char *rel,double decay,char *name,uint64_t baseid,uint64_t relid,int32_t basketsize);
struct exchange_info *get_exchange(int32_t exchangeid);
char *exchange_str(int32_t exchangeid);
struct exchange_info *exchange_find(char *exchangestr);
void prices777_exchangeloop(void *ptr);
uint64_t InstantDEX_name(char *key,int32_t *keysizep,char *exchange,char *name,char *base,uint64_t *baseidp,char *rel,uint64_t *relidp);
struct prices777 *prices777_find(int32_t *invertedp,uint64_t baseid,uint64_t relid,char *exchange);
struct exchange_info *find_exchange(int32_t *exchangeidp,char *exchangestr);
double prices777_InstantDEX(struct prices777 *prices,int32_t maxdepth);
uint64_t prices777_equiv(uint64_t assetid);
char *prices777_trade(int32_t *curlingp,void *bot,struct pending_trade **pendp,void **cHandlep,int32_t dotrade,cJSON *item,char *activenxt,char *secret,struct prices777 *prices,int32_t dir,double price,double volume,struct InstantDEX_quote *iQ,struct prices777_order *order,uint64_t orderid,char *extra);
double prices777_price_volume(double *volumep,uint64_t baseamount,uint64_t relamount);
struct prices777 *prices777_poll(char *exchangestr,char *name,char *base,uint64_t refbaseid,char *rel,uint64_t refrelid);
void set_best_amounts(int64_t *baseamountp,int64_t *relamountp,double price,double volume);
int32_t _set_assetname(uint64_t *multp,char *buf,char *jsonstr,uint64_t assetid);
char *InstantDEX_withdraw(cJSON *argjson);
cJSON *exchanges_json();
char *InstantDEX_tradesequence(int32_t curlings[],void *bot,void *cHandles[],int32_t *nump,struct prices777_order *trades,int32_t maxtrades,int32_t dotrade,char *activenxt,char *secret,cJSON *json);
struct prices777 *prices777_makebasket(char *basketstr,cJSON *_basketjson,int32_t addbasket,char *typestr,struct prices777 *ptrs[],int32_t num);
char *prices777_activebooks(char *name,char *_base,char *_rel,uint64_t baseid,uint64_t relid,int32_t maxdepth,int32_t allflag,int32_t tradeable);
char *prices777_orderbook_jsonstr(int32_t invert,uint64_t nxt64bits,struct prices777 *prices,struct prices777_basketinfo *OB,int32_t maxdepth,int32_t allflag);
int32_t get_assetname(char *name,uint64_t assetid);
int32_t is_mscoin(char *assetidstr);
uint32_t _get_NXTheight(uint32_t *firsttimep);
char *fill_nxtae(int32_t dotrade,uint64_t *txidp,uint64_t nxt64bits,char *secret,int32_t dir,double price,double volume,uint64_t baseid,uint64_t relid);
uint64_t get_assetmult(uint64_t assetid);
int32_t InstantDEX_verify(uint64_t destNXTaddr,uint64_t sendasset,uint64_t sendqty,cJSON *txobj,uint64_t recvasset,uint64_t recvqty);
int32_t verify_NXTtx(cJSON *json,uint64_t refasset,uint64_t qty,uint64_t destNXTbits);
uint64_t assetmult(char *assetidstr);
int64_t get_asset_quantity(int64_t *unconfirmedp,char *NXTaddr,char *assetidstr);
uint64_t calc_asset_qty(uint64_t *availp,uint64_t *priceNQTp,char *NXTaddr,int32_t checkflag,uint64_t assetid,double price,double vol);

cJSON *InstantDEX_orderbook(struct prices777 *prices);
char *hmac_sha512_str(char dest[(512>>3)*2 + 1],char *key,unsigned int key_size,char *message);
char *hmac_sha384_str(char *dest,char *key,int32_t key_size,char *message);
char *hmac_sha1_str(char *dest,char *key,int32_t key_size,char *message);
char *hmac_sha256_str(char *dest,char *key,int32_t key_size,char *message);

extern uint32_t MAX_DEPTH;
extern char NXTAPIURL[],IGUANA_NXTACCTSECRET[],IGUANA_NXTADDR[];
extern int32_t FIRST_EXTERNAL,IGUANA_disableNXT,Debuglevel,prices777_NXTBLOCK;
extern uint64_t IGUANA_MY64BITS;
#endif
