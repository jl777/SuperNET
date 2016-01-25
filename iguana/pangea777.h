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

struct cards777_privdata
{
    bits256 holecards[2],mypriv,mypub,*audits,*outcards,*xoverz;
    //,*reconstructed[CARDS777_MAXPLAYERS],*mofn[CARDS777_MAXPLAYERS][CARDS777_MAXPLAYERS];
    uint8_t *myshares[CARDS777_MAXPLAYERS],*allshares;
    uint8_t hole[2],cardis[2],automuck,autofold,myind;
    bits256 data[];
};

struct hand_info
{
    bits256 checkprod,*cardpubs,*final,community256[5],cards[CARDS777_MAXPLAYERS][2];
    bits256 othercardpubs[CARDS777_MAXPLAYERS];
    int64_t betsize,lastraise,betsizesnapshot;
    uint32_t starttime,handmask,lastbettor,startdecktime,betstarted,finished,encodestarted;
    uint32_t readymask,summaries,mismatches,cardi,userinput_starttime,handranks;
    uint8_t button,numactions,undergun,community[5],sharenrs[CARDS777_MAXPLAYERS][255];
};

struct player_info
{
    bits256 playerpub;
    struct iguana_peer *addr;
    uint64_t ipbits,nxt64bits,havemask;
    int64_t balance,buyinamount,bets,won,snapshot;
    uint32_t handrank;
    uint8_t hand[7];
    int8_t ind,action,betstatus,turni;
    char handle[32];
};

struct game_info
{
    bits256 tablehash,gamehash;
    uint8_t M,N,numcards,ismine;
    uint32_t numactive,allocsize,rakemillis,minbuyin,maxbuyin,minplayers,maxplayers,opentime,started,finished;
    uint64_t maxrake,hostrake,bigblind,ante,pangearake,hostipbits,creatorbits;
    struct player_info P[CARDS777_MAXPLAYERS];
};

struct table_info
{
    struct table_info *next,*prev; struct game_info G; // must be at top of table_info
    struct player_info *active[CARDS777_MAXPLAYERS];
    uint32_t numhands,summarysize,timestamp; int64_t hostrake,pangearake;
    struct hand_info hand; int64_t snapshot[CARDS777_MAXPLAYERS];
    uint8_t myind,summary[65536],space[65536*2]; char spacestr[65536*4+1];
    struct cards777_privdata priv;
};

struct tournament_info
{
    struct tournament_info *next,*prev;
    struct table_info *tables;
};

struct pangea_info
{
    struct table_info *tables,*mytable;
    struct tournament_info *tournaments;
};

extern int32_t Debuglevel;
bits256 xoverz_donna(bits256 a);
bits256 crecip_donna(bits256 a);
bits256 fmul_donna(bits256 a,bits256 b);

void calc_shares(unsigned char *shares,unsigned char *secret,int32_t size,int32_t width,int32_t M,int32_t N,unsigned char *sharenrs);
int32_t init_sharenrs(unsigned char sharenrs[255],unsigned char *orig,int32_t m,int32_t n);

struct pangea_msghdr
{
    // sig { bits256 sigbits,pubkey; uint64_t signer64bits; uint32_t timestamp,allocsize; };
    struct acct777_sig sig __attribute__((packed));
    bits256 tablehash;
    char cmd[8];
    int8_t turni,cardi,destplayer,myind; // ALL DATA MUST BE SERIALIZED!!!
    uint8_t serialized[];
} __attribute__((packed));

#define PANGEA_ARGS struct supernet_info *myinfo,struct table_info *tp,cJSON *json
#define PANGEA_CALLARGS myinfo,tp,json

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

void pangea_sendcmd(struct supernet_info *myinfo,struct table_info *tp,char *cmdstr,int32_t destplayer,uint8_t *data,int32_t datalen,int32_t cardi,int32_t turni);
void pangea_summaryadd(struct supernet_info *myinfo,struct table_info *tp,uint8_t type,void *arg0,int32_t size0,void *arg1,int32_t size1);

cJSON *pangea_tablejson(struct supernet_info *myinfo,struct table_info *tp);
cJSON *pangea_lobbyjson(struct supernet_info *myinfo);
cJSON *pangea_tablestatus(struct supernet_info *myinfo,struct table_info *tp);

int64_t pangea_snapshot(struct table_info *tp,int64_t *snapshot);
int32_t pangea_slotA(struct table_info *tp);

char *pangea_dispsummary(struct supernet_info *myinfo,struct table_info *tp,int32_t verbose,uint8_t *summary,int32_t summarysize,bits256 tablehash,int32_t handid,int32_t numplayers);
int32_t pangea_parsesummary(uint8_t *typep,uint64_t *valAp,uint64_t *bits64p,bits256 *cardp,uint8_t *summary,int32_t len);
int32_t pangea_anotherhand(struct supernet_info *myinfo,struct table_info *tp,int32_t sleepflag);

void pangea_gamecreate(struct game_info *gp,uint32_t timestamp,bits256 tablehash,cJSON *json);
int32_t pangea_playerparse(struct player_info *p,cJSON *json);
int32_t pangea_newdeck(struct supernet_info *myinfo,struct table_info *tp);
int32_t pangea_tableismine(struct supernet_info *myinfo,struct table_info *tp);
void pangea_playeradd(struct supernet_info *myinfo,struct table_info *tp,struct player_info *p,cJSON *json);

void pangea_checkantes(struct supernet_info *myinfo,struct table_info *tp);
int32_t pangea_bet(struct supernet_info *myinfo,struct table_info *tp,struct player_info *player,int64_t bet,int32_t action);
int32_t pangea_sidepots(struct supernet_info *myinfo,struct table_info *tp,int32_t dispflag,int64_t sidepots[CARDS777_MAXPLAYERS][CARDS777_MAXPLAYERS],int64_t *bets);
int64_t pangea_splitpot(struct supernet_info *myinfo,struct table_info *tp,uint64_t *pangearakep,int64_t sidepot[CARDS777_MAXPLAYERS],int32_t rakemillis);

#define PANGEA_HANDARGS struct supernet_info *myinfo,struct pangea_msghdr *pm,struct table_info *tp,uint8_t *data,int32_t datalen
#define PANGEA_HANDCALLARGS myinfo,pm,tp,data,datalen

void pangea_tablecreate(PANGEA_HANDARGS);
void pangea_newhand(PANGEA_HANDARGS);
void pangea_gotdeck(PANGEA_HANDARGS);
void pangea_encoded(PANGEA_HANDARGS);
void pangea_decoded(PANGEA_HANDARGS);
void pangea_final(PANGEA_HANDARGS);
void pangea_preflop(PANGEA_HANDARGS);
void pangea_card(PANGEA_HANDARGS);
void pangea_facedown(PANGEA_HANDARGS);
void pangea_faceup(PANGEA_HANDARGS);
void pangea_turn(PANGEA_HANDARGS);
void pangea_confirm(PANGEA_HANDARGS);
void pangea_action(PANGEA_HANDARGS);
void pangea_showdown(PANGEA_HANDARGS);
void pangea_summary(PANGEA_HANDARGS);

extern int32_t Debuglevel,PANGEA_MAXTHREADS,Showmode,Autofold;

#endif
