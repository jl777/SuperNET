
/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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
//
//  LP_include.h
//  marketmaker
//

#ifndef LP_INCLUDE_H
#define LP_INCLUDE_H

#ifdef FROM_JS
#include <emscripten.h>
#define sleep(x) emscripten_usleep((x) * 1000000)
void emscripten_usleep(int32_t x); // returns immediate, no sense for sleeping
#define usleep(x) emscripten_usleep(x)
// ./autogen.sh
// emconfigure ./configure CFLAGS="-s PTHREAD_POOL_SIZE=8 -s USE_PTHREADS=1 -O2"
// Edit src/core/sock.c and add here #include <limits.h> for INT_MAX support
// emmake make
// cp .libs/libnanomsg.a ~/SuperNET/OSlibs/js
#endif
//#define LP_STRICTPEERS

#define LP_BARTERDEX_VERSION 0
#define LP_MAGICBITS 8

#define LP_HTTP_TIMEOUT 3 // 1 is too small due to edge cases of time(NULL)
#define LP_AUTOTRADE_TIMEOUT 20
#define ELECTRUM_TIMEOUT 10
#define LP_ELECTRUM_KEEPALIVE 60
#define LP_ELECTRUM_MAXERRORS 777
#define LP_MEMPOOL_TIMEINCR 10

#define LP_MIN_PEERS 8
#define LP_MAX_PEERS 32

#define LP_MAXDESIRED_UTXOS 8
#define LP_MINDESIRED_UTXOS 16

// RTmetrics
#define LP_RTMETRICS_TOPGROUP 1.01
#define LP_MAXPENDING_SWAPS 13

#define LP_COMMAND_SENDSOCK NN_PUSH
#define LP_COMMAND_RECVSOCK NN_PULL

#define DPOW_MIN_ASSETCHAIN_SIGS 11
#define LP_ENCRYPTED_MAXSIZE (4096 + 2 + crypto_box_NONCEBYTES + crypto_box_ZEROBYTES)

#define LP_MAXPUBKEY_ERRORS 10
#define PSOCK_KEEPALIVE 3600
#define MAINLOOP_PERSEC 100
#define MAX_PSOCK_PORT 60000
#define MIN_PSOCK_PORT 10000
#define LP_GETINFO_INCR 30
#define LP_ORDERBOOK_DURATION 180

#define LP_MAXPEER_ERRORS 3
#define LP_MINPEER_GOOD 20
#define LP_PEERGOOD_ERRORDECAY 0.9

#define LP_SWAPSTEP_TIMEOUT 30
#define LP_MIN_TXFEE 10000
#define LP_MINVOL 20
#define LP_MINCLIENTVOL 1000
#define LP_MINSIZE_TXFEEMULT 10
#define LP_REQUIRED_TXFEE 0.8

#define LP_DEXFEE(destsatoshis) ((destsatoshis) / INSTANTDEX_INSURANCEDIV)
#define LP_DEPOSITSATOSHIS(satoshis) ((satoshis) + (satoshis >> 3))

#define INSTANTDEX_DECKSIZE 1000
#define INSTANTDEX_LOCKTIME (3600*2 + 300*2)
#define INSTANTDEX_INSURANCEDIV 777
#define INSTANTDEX_PUBKEY "03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06"
#define INSTANTDEX_RMD160 "ca1e04745e8ca0c60d8c5881531d51bec470743f"
#define JUMBLR_RMD160 "5177f8b427e5f47342a4b8ab5dac770815d4389e"
#define TIERNOLAN_RMD160 "daedddd8dbe7a2439841ced40ba9c3d375f98146"
#define INSTANTDEX_BTC "1KRhTPvoxyJmVALwHFXZdeeWFbcJSbkFPu"
#define INSTANTDEX_BTCD "RThtXup6Zo7LZAi8kRWgjAyi1s4u6U9Cpf"

//#define BASILISK_DISABLEWAITTX
//#define BASILISK_DISABLESENDTX
#define LP_RPCPORT 7783

#define LP_PROPAGATION_SLACK 100 // txid ordering is not enforced, so getting extra recent txid
#define LP_RESERVETIME 60
#define LP_AVETXSIZE 256
#define LP_CACHEDURATION 60
#define BASILISK_DEFAULT_NUMCONFIRMS 1
#define BASILISK_DEFAULT_MAXCONFIRMS 6
#define DEX_SLEEP 3
#define BASILISK_KEYSIZE ((int32_t)(2*sizeof(bits256)+sizeof(uint32_t)*2))

#define LP_IS_ZCASHPROTOCOL 1
#define LP_IS_BITCOINCASH 2

#define SIGHASH_FORKID 0x40
#define ZKSNARK_PROOF_SIZE 296
#define ZCASH_SOLUTION_ELEMENTS 1344

extern char GLOBAL_DBDIR[];
extern int32_t IAMLP;

struct iguana_msgvin { bits256 prev_hash; uint8_t *vinscript,*userdata,*spendscript,*redeemscript; uint32_t prev_vout,sequence; uint16_t scriptlen,p2shlen,userdatalen,spendlen; };

struct iguana_msgvout { uint64_t value; uint32_t pk_scriptlen; uint8_t *pk_script; };

struct iguana_msgtx
{
    uint32_t version,tx_in,tx_out,lock_time;
    struct iguana_msgvin *vins;
    struct iguana_msgvout *vouts;
    bits256 txid;
    int32_t allocsize,timestamp,numinputs,numoutputs;
    int64_t inputsum,outputsum,txfee;
    uint8_t *serialized;
};

struct iguana_msgjoinsplit
{
    uint64_t vpub_old,vpub_new;
    bits256 anchor,nullifiers[2],commitments[2],ephemeralkey;
    bits256 randomseed,vmacs[2];
    uint8_t zkproof[ZKSNARK_PROOF_SIZE];
    uint8_t ciphertexts[2][601];
};

struct vin_signer { bits256 privkey; char coinaddr[64]; uint8_t siglen,sig[80],rmd160[20],pubkey[66]; };

struct vin_info
{
    struct iguana_msgvin vin; uint64_t amount; cJSON *extras; bits256 sigtxid;
    int32_t M,N,validmask,spendlen,type,p2shlen,numpubkeys,numsigs,height,hashtype,userdatalen,suppress_pubkeys,ignore_cltverr;
    uint32_t sequence,unspentind; struct vin_signer signers[16]; char coinaddr[65];
    uint8_t rmd160[20],spendscript[10000],p2shscript[10000],userdata[10000];
};

struct basilisk_swapmessage
{
    bits256 srchash,desthash;
    uint32_t crc32,msgbits,quoteid,datalen;
    uint8_t *data;
};

struct basilisk_swap;

struct basilisk_rawtxinfo
{
    char destaddr[64],coinstr[16];
    bits256 txid,signedtxid,actualtxid;
    uint64_t amount,change,inputsum;
    int32_t redeemlen,datalen,completed,vintype,vouttype,numconfirms,spendlen,secretstart,suppress_pubkeys;
    uint32_t locktime,crcs[2];
    uint8_t addrtype,pubkey33[33],rmd160[20];
};

struct basilisk_request
{
    uint32_t requestid,timestamp,quoteid,quotetime; // 0 to 15
    uint64_t srcamount,unused; // 16 to 31
    bits256 srchash; // 32 to 63
    bits256 desthash;
    char src[8],dest[8];
    uint64_t destamount;
    int32_t optionhours,DEXselector;
};

struct basilisk_rawtx
{
    char name[32];
    struct iguana_msgtx msgtx;
    struct basilisk_rawtxinfo I;
    struct iguana_info *coin;
    char vinstr[8192],p2shaddr[64];
    cJSON *vins;
    bits256 utxotxid; int32_t utxovout;
    uint8_t txbytes[16384],spendscript[512],redeemscript[1024],extraspace[4096],pubkey33[33];
};

struct basilisk_swapinfo
{
    struct basilisk_request req;
    char bobstr[64],alicestr[64];
    bits256 myhash,otherhash,orderhash;
    uint32_t statebits,otherstatebits,started,expiration,finished,dead,reftime,putduration,callduration;
    int32_t bobconfirms,aliceconfirms,iambob,reclaimed,bobspent,alicespent,pad,aliceistrusted,bobistrusted,otheristrusted,otherstrust,alicemaxconfirms,bobmaxconfirms;
    uint64_t alicesatoshis,bobsatoshis,bobinsurance,aliceinsurance,Atxfee,Btxfee;
    
    bits256 myprivs[2],mypubs[2],otherpubs[2],pubA0,pubA1,pubB0,pubB1,privAm,pubAm,privBn,pubBn;
    uint32_t crcs_mypub[2],crcs_mychoosei[2],crcs_myprivs[2],crcs_mypriv[2];
    int32_t choosei,otherchoosei,cutverified,otherverifiedcut,numpubs,havestate,otherhavestate,pad2;
    uint8_t secretAm[20],secretBn[20];
    uint8_t secretAm256[32],secretBn256[32];
    uint8_t userdata_aliceclaim[256],userdata_aliceclaimlen;
    uint8_t userdata_alicereclaim[256],userdata_alicereclaimlen;
    uint8_t userdata_alicespend[256],userdata_alicespendlen;
    uint8_t userdata_bobspend[256],userdata_bobspendlen;
    uint8_t userdata_bobreclaim[256],userdata_bobreclaimlen;
    uint8_t userdata_bobrefund[256],userdata_bobrefundlen;
};

#define BASILISK_ALICESPEND 0
#define BASILISK_BOBSPEND 1
#define BASILISK_BOBPAYMENT 2
#define BASILISK_ALICEPAYMENT 3
#define BASILISK_BOBDEPOSIT 4
#define BASILISK_OTHERFEE 5
#define BASILISK_MYFEE 6
#define BASILISK_BOBREFUND 7
#define BASILISK_BOBRECLAIM 8
#define BASILISK_ALICERECLAIM 9
#define BASILISK_ALICECLAIM 10
//0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0
char *txnames[] = { "alicespend", "bobspend", "bobpayment", "alicepayment", "bobdeposit", "otherfee", "myfee", "bobrefund", "bobreclaim", "alicereclaim", "aliceclaim" };

struct LP_swap_remember
{
    bits256 pubA0,pubB0,pubB1,privAm,privBn,paymentspent,Apaymentspent,depositspent,myprivs[2],txids[sizeof(txnames)/sizeof(*txnames)];
    uint64_t Atxfee,Btxfee,srcamount,destamount,aliceid;
    int64_t values[sizeof(txnames)/sizeof(*txnames)];
    uint32_t tradeid,requestid,quoteid,plocktime,dlocktime,expiration,state,otherstate;
    int32_t iambob,finishedflag,origfinishedflag,Predeemlen,Dredeemlen,sentflags[sizeof(txnames)/sizeof(*txnames)];
    uint8_t secretAm[20],secretAm256[32],secretBn[20],secretBn256[32],Predeemscript[1024],Dredeemscript[1024],pubkey33[33],other33[33];
    char src[64],dest[64],destaddr[64],Adestaddr[64],Sdestaddr[64],alicepaymentaddr[64],bobpaymentaddr[64],bobdepositaddr[64],alicecoin[64],bobcoin[64],*txbytes[sizeof(txnames)/sizeof(*txnames)];
};

struct LP_outpoint { bits256 spendtxid; uint64_t value,interest; int32_t spendvini,spendheight; char coinaddr[64]; };

struct LP_transaction
{
    UT_hash_handle hh;
    bits256 txid; int32_t height,numvouts,numvins,len; //uint32_t timestamp;
    uint8_t *serialized;
    struct LP_outpoint outpoints[];
};

struct iguana_info
{
    UT_hash_handle hh;
    portable_mutex_t txmutex,addrmutex; struct LP_transaction *transactions; struct LP_address *addresses;
    uint64_t txfee;
    int32_t numutxos,longestchain,firstrefht,firstscanht,lastscanht,bussock,height; uint16_t busport;
    uint32_t importedprivkey,lastpushtime,lastutxosync,addr_listunspent_requested,lastutxos,updaterate,counter,inactive,lastmempool,lastgetinfo,ratetime,heighttime,lastmonitor,obooktime;
    uint8_t pubtype,p2shtype,isPoS,wiftype,wiftaddr,taddr,noimportprivkey_flag,userconfirms,isassetchain,maxconfirms;
    char symbol[16],smartaddr[64],userpass[1024],serverport[128];
    // portfolio
    double price_kmd,force,perc,goal,goalperc,relvolume,rate;
    void *electrum; void *ctx;
    uint64_t maxamount,kmd_equiv,balanceA,balanceB,valuesumA,valuesumB;
    uint8_t pubkey33[33],zcash;
    bits256 cachedtxid; uint8_t *cachedtxiddata; int32_t cachedtxidlen;
    bits256 cachedmerkle; int32_t cachedmerkleheight;
};

struct _LP_utxoinfo { bits256 txid; uint64_t value; int32_t vout,height; };

struct LP_utxostats { uint32_t sessionid,lasttime,errors,swappending,spentflag,lastspentcheck,bestflag; };

struct LP_utxobob { struct _LP_utxoinfo utxo,deposit; };

struct LP_utxoalice { struct _LP_utxoinfo utxo,fee; };

struct LP_utxoswap { bits256 otherpubkey; void *swap; uint64_t satoshis; };

struct LP_utxoinfo
{
    UT_hash_handle hh,hh2;
    bits256 pubkey;
    struct _LP_utxoinfo payment,deposit,fee;
    struct LP_utxostats T;
    struct LP_utxoswap S;
    int32_t iambob,iamlp;
    uint8_t key[sizeof(bits256) + sizeof(int32_t)];
    uint8_t key2[sizeof(bits256) + sizeof(int32_t)];
    char coin[16],coinaddr[64],gui[16];//spendscript[256];
};

struct LP_address_utxo
{
    struct LP_address_utxo *next,*prev;
    struct _LP_utxoinfo U;
    int32_t SPV,spendheight;
};

struct LP_address
{
    UT_hash_handle hh;
    struct LP_address_utxo *utxos;
    bits256 pubkey;
    int64_t balance,total;
    uint32_t timestamp,n,unspenttime;
    int32_t unspentheight;
    char coinaddr[40];
    uint8_t pubsecp[33],pad;
};

struct LP_peerinfo
{
    UT_hash_handle hh;
    uint64_t ip_port;
    uint32_t ipbits,errortime,errors,numpeers,needping,lasttime,connected,lastutxos,lastpeers,diduquery,good,sessionid;
    int32_t pushsock,subsock;
    uint16_t port;
    char ipaddr[64];
};

struct LP_quoteinfo
{
    struct basilisk_request R;
    bits256 srchash,desthash,txid,txid2,desttxid,feetxid,privkey;
    uint64_t satoshis,txfee,destsatoshis,desttxfee,aliceid;
    uint32_t timestamp,quotetime,tradeid;
    int32_t vout,vout2,destvout,feevout,pair;
    char srccoin[16],coinaddr[64],destcoin[16],destaddr[64],gui[64];
};

struct LP_endpoint { int32_t pair; char ipaddr[64]; uint16_t port; };

struct basilisk_swap
{
    void *ctx; struct iguana_info bobcoin,alicecoin; struct LP_utxoinfo *utxo;
    struct LP_endpoint N;
    void (*balancingtrade)(struct basilisk_swap *swap,int32_t iambob);
    int32_t subsock,pushsock,connected,aliceunconf,depositunconf,paymentunconf;
    uint32_t lasttime,aborted,tradeid;
    FILE *fp;
    bits256 persistent_privkey,persistent_pubkey;
    struct basilisk_swapinfo I;
    struct basilisk_rawtx bobdeposit,bobpayment,alicepayment,myfee,otherfee,aliceclaim,alicespend,bobreclaim,bobspend,bobrefund,alicereclaim;
    bits256 privkeys[INSTANTDEX_DECKSIZE];
    struct basilisk_swapmessage *messages; int32_t nummessages,sentflag;
    char Bdeposit[64],Bpayment[64];
    uint64_t aliceid,otherdeck[INSTANTDEX_DECKSIZE][2],deck[INSTANTDEX_DECKSIZE][2];
    uint8_t persistent_pubkey33[33],persistent_other33[33],changermd160[20],pad[15],verifybuf[100000];
    
};

#define LP_MAXPRICEINFOS 256
struct LP_pubkeyinfo
{
    UT_hash_handle hh;
    bits256 pubkey;
    float matrix[LP_MAXPRICEINFOS][LP_MAXPRICEINFOS];
    //uint32_t timestamps[LP_MAXPRICEINFOS][LP_MAXPRICEINFOS];
    uint32_t timestamp,numerrors,lasttime;
    int32_t istrusted;
    uint8_t rmd160[20],sig[65],pubsecp[33],siglen;
};

int32_t LP_pubkey_sigcheck(struct LP_pubkeyinfo *pubp,cJSON *item);
int32_t LP_pubkey_sigadd(cJSON *item,uint32_t timestamp,bits256 priv,bits256 pub,uint8_t *rmd160,uint8_t *pubsecp);
int32_t LP_quoteparse(struct LP_quoteinfo *qp,cJSON *argjson);
struct LP_address *LP_address(struct iguana_info *coin,char *coinaddr);
void LP_swap_coinaddr(struct iguana_info *coin,char *coinaddr,uint64_t *valuep,uint8_t *data,int32_t datalen,int32_t vout);
void basilisk_dontforget_update(struct basilisk_swap *swap,struct basilisk_rawtx *rawtx);
uint32_t basilisk_requestid(struct basilisk_request *rp);
uint32_t basilisk_quoteid(struct basilisk_request *rp);
struct basilisk_swap *LP_swapinit(int32_t iambob,int32_t optionduration,bits256 privkey,struct basilisk_request *rp,struct LP_quoteinfo *qp);
char *bitcoind_passthru(char *coinstr,char *serverport,char *userpass,char *method,char *params);
uint32_t LP_swapdata_rawtxsend(int32_t pairsock,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx,uint32_t nextbits,int32_t suppress_swapsend);
//double LP_query(char *method,struct LP_quoteinfo *qp,char *base,char *rel,bits256 mypub);
int32_t LP_rawtx_spendscript(struct basilisk_swap *swap,int32_t height,struct basilisk_rawtx *rawtx,int32_t v,uint8_t *recvbuf,int32_t recvlen,int32_t suppress_pubkeys);
void LP_quotesinit(char *base,char *rel);
int32_t LP_forward(void *ctx,char *myipaddr,int32_t pubsock,bits256 pubkey,char *jsonstr,int32_t freeflag);
int32_t LP_ismine(struct LP_utxoinfo *utxo);
int32_t LP_isavailable(struct LP_utxoinfo *utxo);
struct LP_peerinfo *LP_peerfind(uint32_t ipbits,uint16_t port);
uint64_t LP_value_extract(cJSON *obj,int32_t addinterest);
int32_t LP_swap_getcoinaddr(char *symbol,char *coinaddr,bits256 txid,int32_t vout);
char *LP_command_process(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen);
int64_t LP_komodo_interest(bits256 txid,int64_t value);
void LP_availableset(struct LP_utxoinfo *utxo);
int32_t LP_iseligible(uint64_t *valp,uint64_t *val2p,int32_t iambob,char *symbol,bits256 txid,int32_t vout,uint64_t satoshis,bits256 txid2,int32_t vout2);
int32_t LP_pullsock_check(void *ctx,char **retstrp,char *myipaddr,int32_t pubsock,int32_t pullsock);
void LP_unspents_cache(char *symbol,char *addr,char *arraystr,int32_t updatedflag);
uint16_t LP_psock_get(char *connectaddr,char *publicaddr,int32_t ispaired);
//void LP_utxo_clientpublish(struct LP_utxoinfo *utxo);
int32_t LP_coinbus(uint16_t coin_busport);
int32_t LP_nanomsg_recvs(void *ctx);
uint64_t LP_RTsmartbalance(struct iguana_info *coin);
int32_t LP_getheight(struct iguana_info *coin);
int32_t LP_reserved_msg(int32_t priority,char *base,char *rel,bits256 pubkey,char *msg);
struct iguana_info *LP_coinfind(char *symbol);
int32_t LP_crc32find(int32_t *duplicatep,int32_t ind,uint32_t crc32);
char *LP_pricepings(void *ctx,char *myipaddr,int32_t pubsock,char *base,char *rel,double price);
void LP_tradebot_finished(uint32_t tradeid,uint32_t requestid,uint32_t quoteid);
uint64_t LP_txfeecalc(struct iguana_info *coin,uint64_t txfee,int32_t txlen);
struct LP_address *_LP_address(struct iguana_info *coin,char *coinaddr);
struct LP_address *_LP_addressfind(struct iguana_info *coin,char *coinaddr);
struct LP_address *_LP_addressadd(struct iguana_info *coin,char *coinaddr);
int32_t iguana_signrawtransaction(void *ctx,char *symbol,uint8_t wiftaddr,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,struct iguana_msgtx *msgtx,char **signedtxp,bits256 *signedtxidp,struct vin_info *V,int32_t numinputs,char *rawtx,cJSON *vins,cJSON *privkeysjson,int32_t zcash);
//void LP_butxo_swapfields_set(struct LP_utxoinfo *butxo);
struct LP_address_utxo *LP_address_utxofind(struct iguana_info *coin,char *coinaddr,bits256 txid,int32_t vout);
int32_t LP_destaddr(char *destaddr,cJSON *item);
int32_t LP_waitmempool(char *symbol,char *coinaddr,bits256 txid,int32_t vout,int32_t duration);
char *LP_statslog_disp(int32_t n,uint32_t starttime,uint32_t endtime,char *refgui,bits256 refpubkey);
struct LP_transaction *LP_transactionfind(struct iguana_info *coin,bits256 txid);
cJSON *LP_transactioninit(struct iguana_info *coin,bits256 txid,int32_t iter,cJSON *txobj);
int32_t LP_mempoolscan(char *symbol,bits256 searchtxid);
int32_t LP_txheight(struct iguana_info *coin,bits256 txid);
int32_t LP_numpeers();
char *basilisk_swapentry(uint32_t requestid,uint32_t quoteid);
uint64_t LP_KMDvalue(struct iguana_info *coin,uint64_t balance);
int32_t LP_address_utxoadd(char *debug,struct iguana_info *coin,char *coinaddr,bits256 txid,int32_t vout,uint64_t value,int32_t height,int32_t spendheight);
void LP_smartutxos_push(struct iguana_info *coin);
cJSON *LP_address_utxos(struct iguana_info *coin,char *coinaddr,int32_t electrumret);
cJSON *LP_gettxout(char *symbol,char *coinaddr,bits256 txid,int32_t vout);
void LP_postutxos(char *symbol,char *coinaddr);
int32_t LP_listunspent_both(char *symbol,char *coinaddr,int32_t fullflag);
uint16_t LP_randpeer(char *destip);
cJSON *bitcoin_data2json(uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,bits256 *txidp,struct iguana_msgtx *msgtx,uint8_t *extraspace,int32_t extralen,uint8_t *serialized,int32_t len,cJSON *vins,int32_t suppress_pubkeys,int32_t zcash);
//int32_t LP_butxo_findeither(bits256 txid,int32_t vout);
cJSON *LP_listunspent(char *symbol,char *coinaddr);
int32_t LP_gettx_presence(char *symbol,bits256 expectedtxid);
double LP_getestimatedrate(struct iguana_info *coin);
struct LP_utxoinfo *_LP_utxofind(int32_t iambob,bits256 txid,int32_t vout);
struct LP_utxoinfo *_LP_utxo2find(int32_t iambob,bits256 txid,int32_t vout);

void LP_listunspent_query(char *symbol,char *coinaddr);
int32_t bitcoin_priv2wif(uint8_t wiftaddr,char *wifstr,bits256 privkey,uint8_t addrtype);

#endif
