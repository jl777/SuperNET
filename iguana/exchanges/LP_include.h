
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

#define LP_COMMAND_SENDSOCK NN_PUSH
#define LP_COMMAND_RECVSOCK NN_PULL

#define LP_MAXPUBKEY_ERRORS 3
#define PSOCK_KEEPALIVE 3600
#define MAINLOOP_PERSEC 10
#define MAX_PSOCK_PORT 60000
#define MIN_PSOCK_PORT 10000
#define LP_MEMPOOL_TIMEINCR 10
#define LP_GETINFO_INCR 30

#define LP_HTTP_TIMEOUT 2 // 1 is too small due to edge cases of time(NULL)
#define LP_MAXPEER_ERRORS 3
#define LP_MINPEER_GOOD 20
#define LP_PEERGOOD_ERRORDECAY 0.9

#define LP_SWAPSTEP_TIMEOUT 3
#define LP_AUTOTRADE_TIMEOUT 3
#define LP_MIN_TXFEE 10000
#define LP_MINVOL 3
#define LP_MINCLIENTVOL 6

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

#define LP_PROPAGATION_SLACK 100 // txid ordering is not enforced, so getting extra recent txid
#define LP_RESERVETIME 60
#define LP_AVETXSIZE 200
#define LP_CACHEDURATION 60
#define BASILISK_DEFAULT_NUMCONFIRMS 1
#define DEX_SLEEP 3
#define BASILISK_KEYSIZE ((int32_t)(2*sizeof(bits256)+sizeof(uint32_t)*2))

extern char GLOBAL_DBDIR[],USERPASS[],USERPASS_WIFSTR[];
extern int32_t IAMLP,USERPASS_COUNTER;

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
    int32_t bobconfirms,aliceconfirms,iambob,reclaimed,bobspent,alicespent,pad;
    uint64_t alicesatoshis,bobsatoshis,bobinsurance,aliceinsurance;
    
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

struct LP_outpoint { bits256 spendtxid; uint64_t value,interest; int32_t spendvini,spendheight; };

struct LP_transaction
{
    UT_hash_handle hh;
    bits256 txid; int32_t height,numvouts,numvins; uint32_t timestamp;
    struct LP_outpoint outpoints[];
};

struct iguana_info
{
    UT_hash_handle hh;
    portable_mutex_t txmutex; struct LP_transaction *transactions;
    uint64_t txfee; double estimatedrate,profitmargin;
    int32_t longestchain,firstrefht,firstscanht,lastscanht; uint32_t counter,inactive,lastmempool,lastgetinfo;
    uint8_t pubtype,p2shtype,isPoS,wiftype,taddr;
    char symbol[16],smartaddr[64],userpass[1024],serverport[128];
};

struct _LP_utxoinfo { bits256 txid; uint64_t value; int32_t vout; };

struct LP_utxostats { uint32_t lasttime,errors,swappending,spentflag,lastspentcheck,bestflag; };

struct LP_utxobob { struct _LP_utxoinfo utxo,deposit; };

struct LP_utxoalice { struct _LP_utxoinfo utxo,fee; };

struct LP_utxoswap { bits256 otherpubkey; void *swap; uint64_t satoshis; double profitmargin;  };

struct LP_utxoinfo
{
    UT_hash_handle hh,hh2;
    bits256 pubkey;
    struct _LP_utxoinfo payment,deposit,fee;
    struct LP_utxostats T;
    struct LP_utxoswap S;
    //struct LP_utxonetwork N;
    int32_t iambob,iamlp;
    uint8_t key[sizeof(bits256) + sizeof(int32_t)];
    uint8_t key2[sizeof(bits256) + sizeof(int32_t)];
    char coin[16],coinaddr[64],spendscript[256],gui[16];
};

struct LP_peerinfo
{
    UT_hash_handle hh;
    uint64_t ip_port;
    double profitmargin;
    uint32_t ipbits,errortime,errors,numpeers,numutxos,lasttime,connected,lastutxos,lastpeers,diduquery,good;
    int32_t pushsock,subsock;
    uint16_t port;
    char ipaddr[64];
};

struct LP_quoteinfo
{
    struct basilisk_request R;
    bits256 srchash,desthash,txid,txid2,desttxid,feetxid,privkey;
    uint64_t satoshis,txfee,destsatoshis,desttxfee;
    uint32_t timestamp,quotetime; int32_t vout,vout2,destvout,feevout,pair;
    char srccoin[16],coinaddr[64],destcoin[16],destaddr[64];
};

struct LP_endpoint { int32_t pair; char ipaddr[64]; uint16_t port; };

struct basilisk_swap
{
    void *ctx; struct iguana_info bobcoin,alicecoin; struct LP_utxoinfo *utxo;
    struct LP_endpoint N;
    void (*balancingtrade)(struct basilisk_swap *swap,int32_t iambob);
    int32_t subsock,pushsock,connected,aliceunconf,depositunconf,paymentunconf; uint32_t lasttime,aborted;
    FILE *fp;
    bits256 persistent_privkey,persistent_pubkey;
    struct basilisk_swapinfo I;
    struct basilisk_rawtx bobdeposit,bobpayment,alicepayment,myfee,otherfee,aliceclaim,alicespend,bobreclaim,bobspend,bobrefund,alicereclaim;
    bits256 privkeys[INSTANTDEX_DECKSIZE];
    struct basilisk_swapmessage *messages; int32_t nummessages,sentflag;
    char Bdeposit[64],Bpayment[64];
    uint64_t otherdeck[INSTANTDEX_DECKSIZE][2],deck[INSTANTDEX_DECKSIZE][2];
    uint8_t persistent_pubkey33[33],changermd160[20],pad[15],verifybuf[65536];
    
};

void basilisk_dontforget_update(struct basilisk_swap *swap,struct basilisk_rawtx *rawtx);
uint32_t basilisk_requestid(struct basilisk_request *rp);
uint32_t basilisk_quoteid(struct basilisk_request *rp);
struct basilisk_swap *LP_swapinit(int32_t iambob,int32_t optionduration,bits256 privkey,struct basilisk_request *rp,struct LP_quoteinfo *qp);
char *bitcoind_passthru(char *coinstr,char *serverport,char *userpass,char *method,char *params);
uint32_t LP_swapdata_rawtxsend(int32_t pairsock,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx,uint32_t nextbits,int32_t suppress_swapsend);
//double LP_query(char *method,struct LP_quoteinfo *qp,char *base,char *rel,bits256 mypub);
int32_t LP_rawtx_spendscript(struct basilisk_swap *swap,int32_t height,struct basilisk_rawtx *rawtx,int32_t v,uint8_t *recvbuf,int32_t recvlen,int32_t suppress_pubkeys);
void LP_quotesinit(char *base,char *rel);
int32_t LP_forward(void *ctx,char *myipaddr,int32_t pubsock,double profitmargin,bits256 pubkey,char *jsonstr,int32_t freeflag);
int32_t LP_ismine(struct LP_utxoinfo *utxo);
int32_t LP_isavailable(struct LP_utxoinfo *utxo);
struct LP_peerinfo *LP_peerfind(uint32_t ipbits,uint16_t port);
char *LP_command_process(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen,double profitmargin);
void LP_availableset(struct LP_utxoinfo *utxo);
int32_t LP_iseligible(uint64_t *valp,uint64_t *val2p,int32_t iambob,char *symbol,bits256 txid,int32_t vout,uint64_t satoshis,bits256 txid2,int32_t vout2,bits256 pubkey);
int32_t LP_pullsock_check(void *ctx,char **retstrp,char *myipaddr,int32_t pubsock,int32_t pullsock,double profitmargin);
uint16_t LP_psock_get(char *connectaddr,char *publicaddr,int32_t ispaired);


#endif
