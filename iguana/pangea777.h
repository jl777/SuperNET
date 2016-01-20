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

#ifndef PANGEA777_H
#define PANGEA777_H
#include "iguana777.h"

#define TEST_TRANSPORT "http://"

#define _PANGEA_MAXTHREADS 9
#define PANGEA_MINRAKE_MILLIS 5
#define PANGEA_USERTIMEOUT 60
#define PANGEA_MAX_HOSTRAKE 5
#define PANGEA_BTCMAXRAKE (SATOSHIDEN / 100)
#define PANGEA_MAXRAKE (3 * SATOSHIDEN)
#define PANGEA_HANDGAP 30
#define PANGEA_PAUSE 5

#define CARDS777_MAXCARDS 52
#define CARDS777_MAXPLAYERS 9
#define CARDS777_FOLD -1
#define CARDS777_START 1
#define CARDS777_ANTE 2
#define CARDS777_SMALLBLIND 3
#define CARDS777_BIGBLIND 4
#define CARDS777_CHECK 5
#define CARDS777_CALL 6
#define CARDS777_BET 7
#define CARDS777_RAISE 8
#define CARDS777_FULLRAISE 9
#define CARDS777_SENTCARDS 10
#define CARDS777_ALLIN 11
#define CARDS777_FACEUP 12
#define CARDS777_WINNINGS 13
#define CARDS777_RAKES 14
#define CARDS777_CHANGES 15
#define CARDS777_SNAPSHOT 16

struct cards777_handinfo
{
    bits256 checkprod,*cardpubs,*final,community256[5],cards[CARDS777_MAXPLAYERS][2];
    uint64_t othercardpubs[CARDS777_MAXPLAYERS];
    int64_t havemasks[CARDS777_MAXPLAYERS],betsize,hostrake,pangearake,lastraise,bets[CARDS777_MAXPLAYERS],snapshot[CARDS777_MAXPLAYERS+1],won[CARDS777_MAXPLAYERS];
    uint32_t starttime,handmask,lastbettor,startdecktime,betstarted,finished,encodestarted;
    uint32_t cardi,userinput_starttime,handranks[CARDS777_MAXPLAYERS];
    int8_t betstatus[CARDS777_MAXPLAYERS],actions[CARDS777_MAXPLAYERS],turnis[CARDS777_MAXPLAYERS];
    uint8_t numactions,undergun,community[5],sharenrs[CARDS777_MAXPLAYERS][255],hands[CARDS777_MAXPLAYERS][7];
};

struct cards777_pubdata
{
    int64_t snapshot[CARDS777_MAXPLAYERS];
    uint64_t maxrake,hostrake,bigblind,ante,pangearake,summaries,mismatches;
    uint32_t button,readymask,numhands,rakemillis,minbuyin,maxbuyin,summarysize;
    void *table; struct cards777_handinfo hand;
    char newhand[65536],coinstr[16]; uint8_t M,N,numcards,summary[65536]; bits256 data[];
};

struct cards777_privdata
{
    bits256 holecards[2],*audits,*outcards,*xoverz;
    //,*reconstructed[CARDS777_MAXPLAYERS],*mofn[CARDS777_MAXPLAYERS][CARDS777_MAXPLAYERS];
    uint8_t *myshares[CARDS777_MAXPLAYERS],*allshares,hole[2],cardis[2],automuck,autofold;
    bits256 data[];
};

extern int32_t Debuglevel;
bits256 xoverz_donna(bits256 a);
bits256 crecip_donna(bits256 a);
bits256 fmul_donna(bits256 a,bits256 b);

void calc_shares(unsigned char *shares,unsigned char *secret,int32_t size,int32_t width,int32_t M,int32_t N,unsigned char *sharenrs);
int32_t init_sharenrs(unsigned char sharenrs[255],unsigned char *orig,int32_t m,int32_t n);

struct pangea_info
{
    uint32_t timestamp,numaddrs,minbuyin,maxbuyin;
    int64_t balances[CARDS777_MAXPLAYERS]; uint8_t isbot[CARDS777_MAXPLAYERS]; bits256 playerpubs[CARDS777_MAXPLAYERS];
    uint64_t basebits,bigblind,ante,addrs[CARDS777_MAXPLAYERS],active[CARDS777_MAXPLAYERS],tableid;
    char btcpubkeystr[67],wipstr[64],coinstr[16],multisigaddr[64],scriptPubKey[128],redeemScript[4096];
    uint8_t addrtype,p2shtype,wiftype,btcpub[33];
    int32_t myslot,myind,numactive,buyinvouts[CARDS777_MAXPLAYERS]; uint64_t buyinamounts[CARDS777_MAXPLAYERS];
    char buyintxids[CARDS777_MAXPLAYERS][128],coinaddrs[CARDS777_MAXPLAYERS][67],btcpubkeys[CARDS777_MAXPLAYERS][67];
    struct pangea_thread *tp; struct cards777_privdata *priv; struct cards777_pubdata *dp;
};
extern struct pangea_info *TABLES[100];

//./BitcoinDarkd SuperNET '{"agent":"InstantDEX","method":"orderbook","exchange":"active","base":"NXT","rel":"BTC"}'
// ./SNapi "{\"agent\":\"InstantDEX\",\"method\":\"orderbook\",\"exchange\":\"pangea\",\"base\":\"NXT\"}"

// ./SNapi "{\"agent\":\"InstantDEX\",\"method\":\"placebid\",\"exchange\":\"pangea\",\"base\":\"NXT\"}"

struct pangeanet777_endpoint { char endpoint[128],transport[16],ipaddr[64]; uint16_t port; };
struct pangeanet777_id { bits256 pubkey; uint64_t nxt64bits; void *privdata,*pubdata; int32_t pmsock; uint32_t lastcontact; };
union pangeanet777 { struct pangeanet777_server *server; struct pangeanet777_client *client; };
struct pangeanet777_hdr
{
    queue_t Q; bits256 privkey,pubkey; 
    void *privdata,*pubdata; uint64_t nxt64bits;//,recvhashes[64];
    void (*pollfunc)(union pangeanet777 *hn);
    uint32_t lastping; int32_t slot,done,state,ind;
};

struct pangeanet777_client { struct pangeanet777_hdr H; int32_t subsock; struct pangeanet777_id my; uint64_t balance,tableid; };

struct pangeanet777_server
{
    struct pangeanet777_hdr H;
    int32_t num,max,pubsock; struct pangeanet777_endpoint ep; //queue_t mailboxQ[CARDS777_MAXPLAYERS];
    struct pangeanet777_id clients[];
};

struct pangea_thread
{
    union pangeanet777 hn; uint64_t nxt64bits; int32_t threadid,ishost,M,N,numcards;
};
extern struct pangea_thread *THREADS[_PANGEA_MAXTHREADS];

int32_t SuperNET_copybits(int32_t reverse,uint8_t *dest,uint8_t *src,int32_t len);

int32_t cardstr(char *cardstr,uint8_t card);
uint32_t set_handstr(char *handstr,uint8_t cards[7],int32_t verbose);

struct cards777_pubdata *cards777_allocpub(int32_t M,int32_t numcards,int32_t N);
struct cards777_privdata *cards777_allocpriv(int32_t numcards,int32_t N);
bits256 cards777_initdeck(bits256 *cards,bits256 *cardpubs,int32_t numcards,int32_t N,bits256 *playerpubs,bits256 *playerprivs);
bits256 cards777_pubkeys(bits256 *pubkeys,int32_t numcards,bits256 cmppubkey);
int32_t cards777_checkcard(bits256 *cardprivp,int32_t cardi,int32_t slot,int32_t destplayer,bits256 playerpriv,bits256 *cardpubs,int32_t numcards,bits256 card);
int32_t cards777_validate(bits256 cardpriv,bits256 final,bits256 *cardpubs,int32_t numcards,bits256 *audit,int32_t numplayers,bits256 playerpub);
bits256 cards777_decode(bits256 *seedp,bits256 *xoverz,int32_t destplayer,bits256 cipher,bits256 *outcards,int32_t numcards,int32_t N);
uint8_t *cards777_encode(bits256 *encoded,bits256 *xoverz,uint8_t *allshares,uint8_t *myshares[],uint8_t sharenrs[255],int32_t M,bits256 *ciphers,int32_t numcards,int32_t N);

int32_t pangea_search(struct pangea_info *sp,uint64_t nxt64bits);
int32_t pangea_tableaddr(struct cards777_pubdata *dp,uint64_t destbits);
struct pangea_info *pangea_find64(uint64_t tableid,uint64_t nxt64bits);
struct pangea_info *pangea_find(uint64_t tableid,int32_t threadid);
int32_t pangea_neworder(struct cards777_pubdata *dp,struct pangea_info *sp,uint64_t *active,int32_t numactive);

cJSON *pangea_tablestatus(struct pangea_info *sp);
void pangea_summary(union pangeanet777 *hn,struct cards777_pubdata *dp,uint8_t type,void *arg0,int32_t size0,void *arg1,int32_t size1);
void pangea_startbets(union pangeanet777 *hn,struct cards777_pubdata *dp,int32_t cardi);
void pangea_checkantes(union pangeanet777 *hn,struct cards777_pubdata *dp);
uint64_t pangea_bot(union pangeanet777 *hn,struct cards777_pubdata *dp,int32_t turni,int32_t cardi,uint64_t betsize);
char *pangea_dispsummary(struct pangea_info *sp,int32_t verbose,uint8_t *summary,int32_t summarysize,uint64_t tableid,int32_t handid,int32_t numplayers);
char *_pangea_input(uint64_t my64bits,uint64_t tableid,cJSON *json);
void pangea_finish(union pangeanet777 *hn,struct cards777_pubdata *dp);
void pangea_serverstate(union pangeanet777 *hn,struct cards777_pubdata *dp,struct cards777_privdata *priv);

int32_t pangea_anotherhand(void *hn,struct cards777_pubdata *dp,int32_t sleepflag);
void pangea_clearhand(struct cards777_pubdata *dp,struct cards777_handinfo *hand,struct cards777_privdata *priv);
void pangea_create_newtable(char *retbuf,struct pangea_info *sp,struct cards777_pubdata *dp,uint64_t *isbot);
void pangea_buyins(uint32_t *minbuyinp,uint32_t *maxbuyinp);
int32_t pangea_sidepots(int32_t dispflag,uint64_t sidepots[CARDS777_MAXPLAYERS][CARDS777_MAXPLAYERS],struct cards777_pubdata *dp,int64_t *bets);
int64_t pangea_splitpot(int64_t *won,uint64_t *pangearakep,uint64_t sidepot[CARDS777_MAXPLAYERS],union pangeanet777 *hn,int32_t rakemillis);
int32_t pangea_actives(int32_t *activej,struct cards777_pubdata *dp);
int32_t pangea_bet(union pangeanet777 *hn,struct cards777_pubdata *dp,int32_t player,int64_t bet,int32_t action);
uint64_t pangea_winnings(int32_t player,uint64_t *pangearakep,uint64_t *hostrakep,uint64_t total,int32_t numwinners,int32_t rakemillis,uint64_t maxrake);
int32_t _pangea_addfunds(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind);
void _pangea_chat(uint64_t senderbits,void *buf,int32_t len,int32_t senderind);

void pangea_sendcmd(char *hex,union pangeanet777 *hn,char *cmdstr,int32_t destplayer,uint8_t *data,int32_t datalen,int32_t cardi,int32_t turni);
int32_t pangea_slotA(struct pangea_info *sp);
int32_t pangea_slotB(struct pangea_info *sp);
int32_t pangea_slot(struct pangea_info *sp,int32_t ind);
int32_t pangea_ind(struct pangea_info *sp,int32_t slot);
int32_t pangea_slot(struct pangea_info *sp,int32_t ind);
int32_t pangea_poll(uint64_t *senderbitsp,uint32_t *timestampp,union pangeanet777 *hn);

int32_t pangeanet777_register(struct pangeanet777_server *srv,bits256 clientpub,int32_t slot);
struct pangeanet777_client *pangeanet777_client(bits256 privkey,bits256 pubkey,char *srvendpoint,int32_t slot);
struct pangeanet777_server *pangeanet777_server(bits256 srvprivkey,bits256 srvpubkey,char *transport,char *ipaddr,uint16_t port,int32_t maxclients);
int32_t pangeanet777_idle(union pangeanet777 *hn);
void pangeanet777_msg(uint64_t destbits,bits256 destpub,union pangeanet777 *src,int32_t blindflag,char *jsonstr,int32_t len);
struct pangea_info *pangea_threadtables(int32_t *nump,int32_t threadid,uint64_t tableid);

extern int32_t Debuglevel,PANGEA_MAXTHREADS,Showmode,Autofold;
bits256 issue_getpubkey(int32_t *haspubkeyp,char *acct);

#endif
