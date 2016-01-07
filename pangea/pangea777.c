/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
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
#ifdef later

#define BUNDLED
#define PLUGINSTR "pangea"
#define PLUGNAME(NAME) pangea ## NAME
#define STRUCTNAME struct PLUGNAME(_info) 
#define STRINGIFY(NAME) #NAME
#define PLUGIN_EXTRASIZE sizeof(STRUCTNAME)

#include <time.h>

#define DEFINES_ONLY
//#include "../../utils/huffstream.c"
#include "../../common/hostnet777.c"
#include "../../includes/cJSON.h"
#include "../../agents/plugin777.c"
#undef DEFINES_ONLY

#include "../InstantDEX/InstantDEX_quote.h"
#include "../includes/curve25519.h"

#define _PANGEA_MAXTHREADS 9
#define PANGEA_MINRAKE_MILLIS 5
#define PANGEA_USERTIMEOUT 60
#define PANGEA_MAX_HOSTRAKE 5
#define PANGEA_BTCMAXRAKE (SATOSHIDEN / 100)
#define PANGEA_MAXRAKE (3 * SATOSHIDEN)
#define PANGEA_HANDGAP 30
#define PANGEA_PAUSE 5

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
} *TABLES[100];

//./BitcoinDarkd SuperNET '{"agent":"InstantDEX","method":"orderbook","exchange":"active","base":"NXT","rel":"BTC"}'
// ./SNapi "{\"agent\":\"InstantDEX\",\"method\":\"orderbook\",\"exchange\":\"pangea\",\"base\":\"NXT\"}"

// ./SNapi "{\"agent\":\"InstantDEX\",\"method\":\"placebid\",\"exchange\":\"pangea\",\"base\":\"NXT\"}"

struct pangea_thread
{
    union hostnet777 hn; uint64_t nxt64bits; int32_t threadid,ishost,M,N,numcards;
} *THREADS[_PANGEA_MAXTHREADS];

int32_t PANGEA_MAXTHREADS = 0;
int32_t Showmode,Autofold;
//uint64_t Pangea_waiting,Pangea_userinput_betsize; uint32_t Pangea_userinput_starttime; int32_t Pangea_userinput_cardi; char Pangea_userinput[128];

char *clonestr(char *);
uint64_t stringbits(char *str);

uint32_t set_handstr(char *handstr,uint8_t cards[7],int32_t verbose);
int32_t cardstr(char *cardstr,uint8_t card);
int32_t init_hexbytes_noT(char *hexbytes,uint8_t *message,long len);
bits256 issue_getpubkey(int32_t *haspubkeyp,char *acct);
uint64_t set_account_NXTSECRET(void *myprivkey,void *mypubkey,char *NXTacct,char *NXTaddr,char *secret,int32_t max,cJSON *argjson,char *coinstr,char *serverport,char *userpass);
int32_t pangea_anotherhand(union hostnet777 *hn,struct cards777_pubdata *dp,int32_t sleepflag);
void pangea_clearhand(struct cards777_pubdata *dp,struct cards777_handinfo *hand,struct cards777_privdata *priv);
void pangea_create_newtable(char *retbuf,struct pangea_info *sp,struct cards777_pubdata *dp,uint64_t *isbot);


#define PANGEA_COMMANDS "start", "newtable", "status", "turn"

char *PLUGNAME(_methods)[] = { PANGEA_COMMANDS };
char *PLUGNAME(_pubmethods)[] = { PANGEA_COMMANDS };
char *PLUGNAME(_authmethods)[] = { PANGEA_COMMANDS };

uint64_t PLUGNAME(_register)(struct plugin_info *plugin,STRUCTNAME *data,cJSON *argjson)
{
    uint64_t disableflags = 0;
    return(disableflags); // set bits corresponding to array position in _methods[]
}

int32_t PLUGNAME(_shutdown)(struct plugin_info *plugin,int32_t retcode)
{
    if ( retcode == 0 )  // this means parent process died, otherwise _process_json returned negative value
    {
    }
    return(retcode);
}

int32_t pangea_search(struct pangea_info *sp,uint64_t nxt64bits)
{
    int32_t i;
    for (i=0; i<sp->numactive; i++)
        if ( sp->active[i] == nxt64bits )
            return(i);
    for (i=0; i<sp->numactive; i++)
        PostMessage("%llu ",(long long)sp->active[i]);
    PostMessage("active[]\n");
    for (i=0; i<sp->numaddrs; i++)
        PostMessage("%llu ",(long long)sp->addrs[i]);
    PostMessage("addrs[]\n");
    PostMessage("pangea_search: slot.%d ind.%d cant find %llu in active[%d]\n",sp->myslot,sp->myind,(long long)nxt64bits,sp->numactive);
    return(-1);
}

int32_t pangea_tableaddr(struct cards777_pubdata *dp,uint64_t destbits)
{
    int32_t i; struct pangea_info *sp;
    if ( dp != 0 && (sp= dp->table) != 0 )
    {
        for (i=0; i<sp->numaddrs; i++)
            if ( sp->addrs[i] == destbits )
                return(i);
    }
    return(-1);
}

int32_t pangea_slotA(struct pangea_info *sp)
{
    return(0);
}

int32_t pangea_slotB(struct pangea_info *sp)
{
    uint64_t nxt64bits;
    nxt64bits = sp->active[1];
    return(pangea_search(sp,nxt64bits));
}

int32_t pangea_slot(struct pangea_info *sp,int32_t ind)
{
    return(pangea_tableaddr(sp->dp,sp->active[ind]));
}

int32_t pangea_ind(struct pangea_info *sp,int32_t slot)
{
    return(pangea_search(sp,sp->addrs[slot]));
}

int32_t pangea_lastnode(struct pangea_info *sp)
{
    return(pangea_search(sp,sp->active[sp->numactive-1]));
}

int32_t pangea_nextnode(struct pangea_info *sp)
{
    if ( sp->myind < sp->numactive-1 )
        return(sp->myind + 1);
    else
    {
        PostMessage("pangea_nextnode: no next node from last node slot.%d ind.%d of numaddrs.%d numactive.%d\n",sp->myslot,sp->myind,sp->numaddrs,sp->numactive);
        return(-1);
    }
}

int32_t pangea_prevnode(struct pangea_info *sp)
{
    if ( sp->myind > 0 )
        return(sp->myind - 1);
    else
    {
        PostMessage("pangea_prevnode: no prev node from node slot %d, ind.%d\n",sp->myslot,sp->myind);
        return(-1);
    }
}

int32_t pangea_neworder(struct cards777_pubdata *dp,struct pangea_info *sp,uint64_t *active,int32_t numactive)
{
    int32_t slots[CARDS777_MAXPLAYERS],i;
    if ( active == 0 )
        active = sp->active, numactive = sp->numactive;
    memset(slots,0,sizeof(slots));
    if ( active[0] != sp->addrs[0] )
    {
        PostMessage("pangea_neworder: neworder requires host nodeA to be first active node\n");
        return(-1);
    }
    slots[0] = 0;
    for (i=1; i<numactive; i++)
    {
        if ( (slots[i]= pangea_tableaddr(dp,active[i])) < 0 )
        {
            PostMessage("cant find %llu in addrs[%d]\n",(long long)active[i],sp->numaddrs);
            return(-1);
        }
    }
    for (i=0; i<numactive; i++)
    {
        sp->active[i] = active[i];
        //PostMessage("%llu ",(long long)sp->active[i]);
    }
    sp->numactive = dp->N = numactive;
    dp->M = (numactive >> 1) + 1;
    sp->myind = pangea_ind(sp,sp->myslot);
    //PostMessage("T%d neworder.%d -> M.%d N.%d ind.%d\n",sp->myslot,sp->numactive,dp->M,dp->N,sp->myind);
    return(numactive);
}

int32_t pangea_inactivate(struct cards777_pubdata *dp,struct pangea_info *sp,uint64_t nxt64bits)
{
    int32_t i,n; uint64_t active[CARDS777_MAXPLAYERS];
    for (i=n=0; i<sp->numactive; i++)
    {
        if ( sp->active[i] == nxt64bits )
            continue;
        active[n++] = sp->active[i];
    }
    if ( n != sp->numactive-1 )
        PostMessage("pangea_inactivate: cant find %llu\n",(long long)nxt64bits);
    PostMessage("T%d inactivate %llu n.%d\n",sp->myslot,(long long)nxt64bits,n);
    pangea_neworder(dp,sp,active,n);
    return(n);
}

int32_t pangea_addplayer(struct cards777_pubdata *dp,struct pangea_info *sp,bits256 clientpub)
{
    int32_t i,n,openslot = -1; uint64_t nxt64bits = acct777_nxt64bits(clientpub);
    for (i=n=0; i<sp->numaddrs; i++)
    {
        if ( sp->addrs[i] == nxt64bits )
        {
            PostMessage("pangea_addplayer: player %llu already in addrs[%d]\n",(long long)nxt64bits,i);
            return(-1);
        }
        if ( sp->balances[i] <= 0 )
            openslot = i;
    }
    if ( openslot < 0 || sp->numactive >= sp->numaddrs-1 )
    {
        PostMessage("pangea_addplayer: no room to add %llu\n",(long long)nxt64bits);
        return(-1);
    }
    dp->readymask &= ~(1 << openslot);
    sp->addrs[openslot] = nxt64bits;
    sp->playerpubs[openslot] = clientpub;
    sp->active[sp->numactive++] = nxt64bits;
    if ( sp->myslot == 0 )
    {
        uint64_t isbot[CARDS777_MAXPLAYERS]; char *retbuf = malloc(65536);
        if ( retbuf != 0 )
        {
            hostnet777_replace(sp->tp->hn.server,clientpub,openslot);
            for (i=0; i<sp->numactive; i++)
                isbot[i] = sp->isbot[i];
            pangea_create_newtable(retbuf,sp,dp,isbot);
            hostnet777_msg(nxt64bits,clientpub,&sp->tp->hn,0,retbuf,(int32_t)strlen(retbuf)+1);
            free(retbuf);
        }
    }
    pangea_neworder(dp,sp,0,0);
    return(n);
}

void pangea_sendcmd(char *hex,union hostnet777 *hn,char *cmdstr,int32_t destplayer,uint8_t *data,int32_t datalen,int32_t cardi,int32_t turni)
{
    int32_t n,hexlen,blindflag = 0; uint64_t destbits; bits256 destpub; cJSON *json; char hoststr[1024]; struct pangea_info *sp;
    struct cards777_pubdata *dp = hn->client->H.pubdata;
    hoststr[0] = 0;
    sp = dp->table;
    sprintf(hex,"{\"cmd\":\"%s\",\"millitime\":\"%lld\",\"turni\":%d,\"myslot\":%d,\"myind\":%d,\"cardi\":%d,\"dest\":%d,\"sender\":\"%llu\",\"timestamp\":\"%lu\",\"n\":%u,%s\"data\":\"",cmdstr,(long long)hostnet777_convmT(&hn->client->H.mT,0),turni,hn->client->H.slot,pangea_ind(dp->table,hn->client->H.slot),cardi,destplayer,(long long)hn->client->H.nxt64bits,(long)time(NULL),datalen,hoststr);
    n = (int32_t)strlen(hex);
    if ( strcmp(cmdstr,"preflop") == 0 )
    {
        memcpy(&hex[n],data,datalen+1);
        hexlen = (int32_t)strlen(hex)+1;
        PostMessage("P%d HEX.[] hexlen.%d n.%d\n",hn->server->H.slot,hexlen,datalen);
    }
    else if ( data != 0 && datalen != 0 )
        init_hexbytes_noT(&hex[n],data,datalen);
    strcat(hex,"\"}");
    if ( (json= cJSON_Parse(hex)) == 0 )
    {
        PostMessage("error creating json\n");
        return;
    }
    free_json(json);
    hexlen = (int32_t)strlen(hex)+1;
    //PostMessage("HEX.[%s] hexlen.%d n.%d\n",hex,hexlen,datalen);
    if ( destplayer < 0 )//|| ((1LL << destplayer) & dp->pmworks) == 0 )
    {
        destbits = 0;
        memset(destpub.bytes,0,sizeof(destpub));
        //PostMessage("T%d broadcasts %d\n",hn->client->H.slot,hexlen);
    }
    else
    {
        destpub = sp->playerpubs[pangea_slot(sp,destplayer)];
        destbits = acct777_nxt64bits(destpub);
        //PostMessage("T%d sends %d to dest.%d\n",hn->client->H.slot,hexlen,destplayer);
    }
    hostnet777_msg(destbits,destpub,hn,blindflag,hex,hexlen);
}

#include "pangeafunds.c"

bits256 pangea_destpub(uint64_t destbits)
{
    int32_t i,haspubkey; bits256 destpub; char destNXT[64];
    memset(destpub.bytes,0,sizeof(destpub));
    for (i=0; i<sizeof(TABLES)/sizeof(*TABLES); i++)
        if ( TABLES[i] != 0 && TABLES[i]->tp->nxt64bits == destbits )
        {
            destpub = TABLES[i]->tp->hn.client->H.pubkey;
            break;
        }
    if ( i == sizeof(TABLES)/sizeof(*TABLES) )
    {
        expand_nxt64bits(destNXT,destbits);
        destpub = issue_getpubkey(&haspubkey,destNXT);
    }
    return(destpub);
}

struct pangea_info *pangea_find(uint64_t tableid,int32_t threadid)
{
    int32_t i;
    for (i=0; i<sizeof(TABLES)/sizeof(*TABLES); i++)
        if ( TABLES[i] != 0 && tableid == TABLES[i]->tableid && (threadid < 0 || TABLES[i]->tp->threadid == threadid) )
            return(TABLES[i]);
    return(0);
}

struct pangea_info *pangea_find64(uint64_t tableid,uint64_t nxt64bits)
{
    int32_t i,j;
    for (i=0; i<sizeof(TABLES)/sizeof(*TABLES); i++)
    {
        if ( TABLES[i] != 0 && (tableid == 0 || tableid == TABLES[i]->tableid) && TABLES[i]->tp != 0  )
        {
            for (j=0; j<TABLES[i]->numaddrs; j++)
            {
                if ( TABLES[i]->addrs[j] == nxt64bits )
                    return(TABLES[i]);
            }
        }
    }
    return(0);
}

void pangea_free(struct pangea_info *sp)
{
    int32_t i;
    for (i=0; i<sizeof(TABLES)/sizeof(*TABLES); i++)
        if ( TABLES[i] == sp )
        {
            TABLES[i] = 0;
            break;
        }
    PostMessage("PANGEA PURGE %llu\n",(long long)sp->tableid);
    free(sp);
}

void pangea_clearhand(struct cards777_pubdata *dp,struct cards777_handinfo *hand,struct cards777_privdata *priv)
{
    bits256 *final,*cardpubs; int32_t i;
    final = hand->final, cardpubs = hand->cardpubs;
    memset(hand,0,sizeof(*hand));
    hand->final = final, hand->cardpubs = cardpubs;
    memset(final,0,sizeof(*final) * dp->N * dp->numcards);
    memset(cardpubs,0,sizeof(*cardpubs) * (1 + dp->numcards));
    for (i=0; i<5; i++)
        hand->community[i] = 0xff;
    memset(hand->hands,0xff,sizeof(hand->hands));
    priv->hole[0] = priv->hole[1] = priv->cardis[0] = priv->cardis[1] = 0xff;
    memset(priv->holecards,0,sizeof(priv->holecards));
}

void pangea_sendnewdeck(union hostnet777 *hn,struct cards777_pubdata *dp)
{
    int32_t hexlen; bits256 destpub;
    hexlen = (int32_t)strlen(dp->newhand)+1;
    memset(destpub.bytes,0,sizeof(destpub));
    hostnet777_msg(0,destpub,hn,0,dp->newhand,hexlen);
    dp->hand.startdecktime = (uint32_t)time(NULL);
    PostMessage("pangea_sendnewdeck new deck at %u\n",dp->hand.startdecktime);
}

int32_t pangea_newdeck(union hostnet777 *src)
{
    uint8_t data[(CARDS777_MAXCARDS + 1) * sizeof(bits256)]; struct cards777_pubdata *dp; struct cards777_privdata *priv; int32_t i,n,m,len;
    bits256 playerpubs[CARDS777_MAXPLAYERS]; struct pangea_info *sp; uint64_t removelist[CARDS777_MAXPLAYERS]; cJSON *array; char *str;
    dp = src->client->H.pubdata, sp = dp->table;
    priv = src->client->H.privdata;
    pangea_clearhand(dp,&dp->hand,priv);
    for (i=m=0; i<dp->N; i++)
    {
        if ( sp->balances[pangea_slot(sp,i)] <= 0 )
            removelist[m++] = sp->addrs[pangea_slot(sp,i)];
    }
    if ( 0 && m > 0 )
    {
        for (i=0; i<m; i++)
            pangea_inactivate(dp,sp,removelist[i]);
    }
    pangea_neworder(dp,dp->table,0,0);
    array = cJSON_CreateArray();
    for (i=0; i<dp->N; i++)
    {
        playerpubs[i] = sp->playerpubs[pangea_slot(sp,i)];
        jaddi64bits(array,sp->active[i]);
    }
    str = jprint(array,1);
    dp->hand.checkprod = dp->hand.cardpubs[dp->numcards] = cards777_initdeck(priv->outcards,dp->hand.cardpubs,dp->numcards,dp->N,playerpubs,0);
    len = (dp->numcards + 1) * sizeof(bits256);
    sprintf(dp->newhand,"{\"cmd\":\"%s\",\"millitime\":\"%lld\",\"active\":%s,\"sender\":\"%llu\",\"timestamp\":\"%lu\",\"n\":%u,\"data\":\"","newhand",(long long)hostnet777_convmT(&src->server->H.mT,0),str,(long long)src->client->H.nxt64bits,(long)time(NULL),len);
    free(str);
    n = (int32_t)strlen(dp->newhand);
    memcpy(data,dp->hand.cardpubs,len);
    init_hexbytes_noT(&dp->newhand[n],data,len);
    strcat(dp->newhand,"\"}");
    pangea_sendnewdeck(src,dp);
    PostMessage("host sends NEWDECK checkprod.%llx numhands.%d\n",(long long)dp->hand.checkprod.txid,dp->numhands);
    return(0);
}

int32_t pangea_anotherhand(union hostnet777 *hn,struct cards777_pubdata *dp,int32_t sleepflag)
{
    int32_t i,n,activej = -1; uint64_t total = 0; struct pangea_info *sp = dp->table;
    for (i=n=0; i<sp->numaddrs; i++)
    {
        total += sp->balances[i];
        PostMessage("(p%d %.8f) ",i,dstr(sp->balances[i]));
        if ( sp->balances[i] != 0 )
        {
            if ( activej < 0 )
                activej = i;
            n++;
        }
    }
    PostMessage("balances %.8f [%.8f]\n",dstr(total),dstr(total + dp->hostrake + dp->pangearake));
    if ( n == 1 )
    {
        PostMessage("Only player.%d left with %.8f | get sigs and cashout after numhands.%d\n",activej,dstr(sp->balances[pangea_slot(sp,activej)]),dp->numhands);
        msleep(60000);
        return(1);
    }
    else
    {
        if ( sleepflag != 0 )
            msleep(sleepflag * 1000);
        //dp->hand.betstarted = 0;
        pangea_newdeck(hn);
        if ( sleepflag != 0 )
            msleep(sleepflag * 1000);
    }
    return(n);
}

int32_t pangea_newhand(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    char hex[1024]; int32_t handid,m,i; uint64_t active[CARDS777_MAXPLAYERS]; cJSON *array; struct pangea_info *sp = dp->table;
    if ( data == 0 || datalen != (dp->numcards + 1) * sizeof(bits256) )
    {
        PostMessage("pangea_newhand invalid datalen.%d vs %ld\n",datalen,(long)((dp->numcards + 1) * sizeof(bits256)));
        return(-1);
    }
    if ( hn->server->H.slot != 0 )
    {
        pangea_clearhand(dp,&dp->hand,priv);
        if ( (array= jarray(&m,json,"active")) != 0 )
        {
            //PostMessage("T%d (%s)\n",sp->myslot,jprint(array,0));
            for (i=0; i<m; i++)
                active[i] = j64bits(jitem(array,i),0);
            pangea_neworder(dp,dp->table,active,m);
        } else pangea_neworder(dp,dp->table,0,0);
    }
    dp->button = (dp->numhands++ % dp->N);
    memcpy(dp->hand.cardpubs,data,(dp->numcards + 1) * sizeof(bits256));
    PostMessage("player.%d NEWHAND.%llx received numhands.%d button.%d cardi.%d | dp->N %d\n",hn->client->H.slot,(long long)dp->hand.cardpubs[dp->numcards].txid,dp->numhands,dp->button,dp->hand.cardi,dp->N);
    dp->hand.checkprod = cards777_pubkeys(dp->hand.cardpubs,dp->numcards,dp->hand.cardpubs[dp->numcards]);
    memset(dp->summary,0,sizeof(dp->summary));
    dp->summaries = dp->mismatches = dp->summarysize = 0;
    handid = dp->numhands - 1;
    if ( sp->myind >= 0 )
    {
        pangea_summary(hn,dp,CARDS777_START,&handid,sizeof(handid),dp->hand.cardpubs[0].bytes,sizeof(bits256)*(dp->numcards+1));
        pangea_sendcmd(hex,hn,"gotdeck",-1,dp->hand.checkprod.bytes,sizeof(uint64_t),dp->hand.cardi,dp->hand.userinput_starttime);
    }
    return(0);
}

void pangea_checkstart(union hostnet777 *hn,struct cards777_pubdata *dp,struct cards777_privdata *priv)
{
    int32_t i;
    if ( dp->hand.checkprod.txid != 0 && dp->newhand[0] != 0 && dp->hand.encodestarted == 0 )
    {
        for (i=0; i<dp->N; i++)
        {
            if ( dp->hand.othercardpubs[i] != dp->hand.checkprod.txid )
                break;
        }
        if ( i == dp->N )
        {
            if ( PANGEA_PAUSE > 0 )
                msleep(PANGEA_PAUSE * 1000);
            dp->hand.encodestarted = (uint32_t)time(NULL);
            PostMessage("SERVERSTATE issues encoded %llx\n",(long long)dp->hand.checkprod.txid);
            pangea_sendcmd(dp->newhand,hn,"encoded",pangea_slotB(dp->table),priv->outcards[0].bytes,sizeof(bits256)*dp->N*dp->numcards,dp->N*dp->numcards,-1);
        }
    }
}

int32_t pangea_gotdeck(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    int32_t i,slot; uint64_t total = 0; struct pangea_info *sp = dp->table;
    dp->hand.othercardpubs[senderind] = *(uint64_t *)data;
    if ( Debuglevel > 2 )
    {
        for (i=0; i<dp->N; i++)
        {
            slot = pangea_slot(sp,i);
            total += sp->balances[slot];
            PostMessage("(p%d %.8f) ",i,dstr(sp->balances[slot]));
        }
        PostMessage("balances %.8f [%.8f] | ",dstr(total),dstr(total + dp->hostrake + dp->pangearake));
        PostMessage("player.%d pangea_gotdeck from P.%d otherpubs.%llx\n",hn->client->H.slot,senderind,(long long)dp->hand.othercardpubs[senderind]);
    }
    pangea_checkstart(hn,dp,priv);
    return(0);
}

int32_t pangea_ready(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    int32_t create_MofN(uint8_t addrtype,char *redeemScript,char *scriptPubKey,char *p2shaddr,char *pubkeys[],int32_t M,int32_t N);
    char hex[4096],hexstr[67],*pubkeys[CARDS777_MAXPLAYERS]; struct pangea_info *sp = dp->table;
    uint8_t addrtype,p2shtype; int32_t i,slot,retval = -1;
    slot = pangea_slot(sp,senderind);
    dp->readymask |= (1 << slot);
    addrtype = coin777_addrtype(&p2shtype,dp->coinstr);
    if ( datalen == 33 )
    {
        init_hexbytes_noT(hexstr,data,datalen);
        strcpy(sp->btcpubkeys[slot],hexstr);
        btc_coinaddr(sp->coinaddrs[slot],addrtype,hexstr);
    }
    else hexstr[0] = 0;
    for (i=0; i<dp->N; i++)
        if ( GETBIT(&dp->readymask,i) == 0 )
            break;
    if ( i == dp->N )//dp->readymask == ((1 << dp->N) - 1) )
    {
        if ( hn->server->H.slot == pangea_slotA(sp) && senderind != 0 )
            pangea_sendcmd(hex,hn,"ready",-1,sp->btcpub,sizeof(sp->btcpub),0,0);
        for (i=0; i<dp->N; i++)
            pubkeys[i] = sp->btcpubkeys[pangea_slot(sp,i)];
        retval = create_MofN(p2shtype,sp->redeemScript,sp->scriptPubKey,sp->multisigaddr,pubkeys,dp->M,dp->N);
        PostMessage("retval.%d scriptPubKey.(%s) multisigaddr.(%s) redeemScript.(%s)\n",retval,sp->scriptPubKey,sp->multisigaddr,sp->redeemScript);
    }
    PostMessage("player.%d got ready from senderind.%d slot.%d readymask.%x btcpubkey.(%s) (%s) wip.(%s)\n",hn->client->H.slot,senderind,slot,dp->readymask,hexstr,sp->coinaddrs[slot],sp->wipstr);
    /*if ( 0 && hn->client->H.slot == pangea_slotA(dp->table) )
     {
     if ( (dp->pmworks & (1 << senderind)) == 0 )
     {
     PostMessage("send pmtest from %d to %d\n",hn->client->H.slot,senderind);
     pangea_sendcmd(hex,hn,"pmtest",-1,dp->hand.checkprod.bytes,sizeof(uint64_t),-1,-1);
     pangea_sendcmd(hex,hn,"pmtest",senderind,dp->hand.checkprod.bytes,sizeof(uint64_t),-1,senderind);
     }
     }*/
    return(0);
}

void pangea_rwaudit(int32_t saveflag,bits256 *audit,bits256 *audits,int32_t cardi,int32_t destplayer,int32_t N)
{
    int32_t i;
    audits = &audits[(cardi * N + destplayer) * N];
    if ( saveflag != 0 )
    {
        for (i=0; i<N; i++)
            audits[i] = audit[i];
    }
    else
    {
        for (i=0; i<N; i++)
            audit[i] = audits[i];
    }
}

int32_t pangea_card(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t cardi,int32_t senderind)
{
    int32_t destplayer,card,selector,validcard = -1; bits256 cardpriv,audit[CARDS777_MAXPLAYERS]; char hex[1024],cardAstr[8],cardBstr[8]; struct pangea_info *sp = dp->table;
    if ( data == 0 || datalen != sizeof(bits256)*dp->N )
    {
        PostMessage("pangea_card invalid datalen.%d vs %ld\n",datalen,(long)sizeof(bits256)*dp->N);
        return(-1);
    }
    //PostMessage("pangea_card priv.%llx\n",(long long)hn->client->H.privkey.txid);
    destplayer = juint(json,"dest");
    pangea_rwaudit(1,(void *)data,priv->audits,cardi,destplayer,dp->N);
    pangea_rwaudit(0,audit,priv->audits,cardi,destplayer,dp->N);
    //PostMessage("card.%d destplayer.%d [%llx]\n",cardi,destplayer,(long long)audit[0].txid);
    if ( (card= cards777_checkcard(&cardpriv,cardi,pangea_ind(dp->table,hn->client->H.slot),destplayer,hn->client->H.privkey,dp->hand.cardpubs,dp->numcards,audit[0])) >= 0 )
    {
        destplayer = pangea_ind(dp->table,hn->client->H.slot);
        if ( Debuglevel > 2 )
            PostMessage("player.%d got card.[%d]\n",hn->client->H.slot,card);
        //memcpy(&priv->incards[cardi*dp->N + destplayer],cardpriv.bytes,sizeof(bits256));
        selector = (cardi / dp->N);
        priv->holecards[selector] = cardpriv;
        priv->cardis[selector] = cardi;
        dp->hand.hands[destplayer][5 + selector] = priv->hole[selector] = cardpriv.bytes[1];
        validcard = 1;
        cardAstr[0] = cardBstr[0] = 0;
        if ( priv->hole[0] != 0xff )
            cardstr(cardAstr,priv->hole[0]);
        if ( priv->hole[1] != 0xff )
            cardstr(cardBstr,priv->hole[1]);
        PostMessage(">>>>>>>>>> dest.%d priv.%p holecards[%02d] cardi.%d / dp->N %d (%02d %02d) -> (%s %s)\n",destplayer,priv,priv->hole[cardi / dp->N],cardi,dp->N,priv->hole[0],priv->hole[1],cardAstr,cardBstr);
        if ( cards777_validate(cardpriv,dp->hand.final[cardi*dp->N + destplayer],dp->hand.cardpubs,dp->numcards,audit,dp->N,sp->playerpubs[hn->client->H.slot]) < 0 )
            PostMessage("player.%d decoded cardi.%d card.[%02d] but it doesnt validate\n",hn->client->H.slot,cardi,card);
    } else PostMessage("ERROR player.%d got no card %llx\n",hn->client->H.slot,*(long long *)data);
    if ( cardi < dp->N*2 )
        pangea_sendcmd(hex,hn,"facedown",-1,(void *)&cardi,sizeof(cardi),cardi,validcard);
    else pangea_sendcmd(hex,hn,"faceup",-1,cardpriv.bytes,sizeof(cardpriv),cardi,0xff);
    return(0);
}

int32_t pangea_decoded(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    int32_t cardi,destplayer,card,turni; bits256 cardpriv,audit[CARDS777_MAXPLAYERS]; char hex[1024]; struct pangea_info *sp = dp->table;
    if ( data == 0 || datalen != sizeof(bits256)*dp->N )
    {
        PostMessage("pangea_decoded invalid datalen.%d vs %ld\n",datalen,(long)sizeof(bits256));
        return(-1);
    }
    cardi = juint(json,"cardi");
    turni = juint(json,"turni");
    if ( cardi < dp->N*2 || cardi >= dp->N*2 + 5 )
    {
        PostMessage("pangea_decoded invalid cardi.%d\n",cardi);
        return(-1);
    }
    destplayer = pangea_ind(dp->table,0);
    pangea_rwaudit(1,(void *)data,priv->audits,cardi,destplayer,dp->N);
    pangea_rwaudit(0,audit,priv->audits,cardi,destplayer,dp->N);
    //memcpy(&priv->incards[cardi*dp->N + destplayer],data,sizeof(bits256));
    if ( turni == pangea_ind(dp->table,hn->client->H.slot) )
    {
        if ( hn->client->H.slot != pangea_slotA(dp->table) )
        {
            audit[0] = cards777_decode(&audit[sp->myind],priv->xoverz,destplayer,audit[0],priv->outcards,dp->numcards,dp->N);
            pangea_rwaudit(1,audit,priv->audits,cardi,destplayer,dp->N);
            pangea_sendcmd(hex,hn,"decoded",-1,audit[0].bytes,sizeof(bits256)*dp->N,cardi,pangea_prevnode(dp->table));
            //PostMessage("player.%d decoded cardi.%d %llx -> %llx\n",hn->client->H.slot,cardi,(long long)priv->incards[cardi*dp->N + destplayer].txid,(long long)decoded.txid);
        }
        else
        {
            if ( (card= cards777_checkcard(&cardpriv,cardi,pangea_ind(dp->table,hn->client->H.slot),pangea_ind(dp->table,hn->client->H.slot),hn->client->H.privkey,dp->hand.cardpubs,dp->numcards,audit[0])) >= 0 )
            {
                if ( cards777_validate(cardpriv,dp->hand.final[cardi*dp->N + destplayer],dp->hand.cardpubs,dp->numcards,audit,dp->N,sp->playerpubs[hn->client->H.slot]) < 0 )
                    PostMessage("player.%d decoded cardi.%d card.[%d] but it doesnt validate\n",hn->client->H.slot,cardi,card);
                pangea_sendcmd(hex,hn,"faceup",-1,cardpriv.bytes,sizeof(cardpriv),cardi,cardpriv.txid!=0?0xff:-1);
                //PostMessage("-> FACEUP.(%s)\n",hex);
            }
        }
    }
    return(0);
}

int32_t pangea_zbuf(char *zbuf,uint8_t *data,int32_t datalen)
{
    int i,j,n = 0;
    for (i=0; i<datalen; i++)
    {
        if ( data[i] != 0 )
        {
            zbuf[n++] = hexbyte((data[i]>>4) & 0xf);
            zbuf[n++] = hexbyte(data[i] & 0xf);
        }
        else
        {
            for (j=1; j<16; j++)
                if ( data[i+j] != 0 )
                    break;
            i += (j - 1);
            zbuf[n++] = 'Z';
            zbuf[n++] = 'A'+j;
        }
    }
    zbuf[n] = 0;
    return(n);
}

int32_t pangea_unzbuf(uint8_t *buf,char *hexstr,int32_t len)
{
    int32_t i,j,len2;
    for (len2=i=0; i<len; i+=2)
    {
        if ( hexstr[i] == 'Z' )
        {
            for (j=0; j<hexstr[i+1]-'A'; j++)
                buf[len2++] = 0;
        }
        else buf[len2++] = _decode_hex(&hexstr[i]);
    }
    //char *tmp = calloc(1,len*2+1);
    //init_hexbytes_noT(tmp,buf,len2);
    //PostMessage("zlen %d to len2 %d\n",len,len2);
    //free(tmp);
   return(len2);
}

int32_t pangea_preflop(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    char *hex,*zbuf; int32_t i,card,len,iter,cardi,destplayer,maxlen = (int32_t)(2 * CARDS777_MAXPLAYERS * CARDS777_MAXPLAYERS * CARDS777_MAXCARDS * sizeof(bits256));
    bits256 cardpriv,audit[CARDS777_MAXPLAYERS]; struct pangea_info *sp = dp->table;
    if ( data == 0 || datalen != (2 * dp->N) * (dp->N * dp->N * sizeof(bits256)) || (hex= malloc(maxlen)) == 0 )
    {
        PostMessage("pangea_preflop invalid datalen.%d vs %ld\n",datalen,(long)(2 * dp->N) * (dp->N * dp->N * sizeof(bits256)));
        return(-1);
    }
    //PostMessage("preflop player.%d\n",hn->client->H.slot);
    //memcpy(priv->incards,data,datalen);
    memcpy(priv->audits,data,datalen);
    if ( hn->client->H.slot != pangea_slotA(dp->table) && hn->client->H.slot != pangea_slotB(dp->table) )
    {
        //for (i=0; i<dp->numcards*dp->N; i++)
        //    PostMessage("%llx ",(long long)priv->outcards[i].txid);
        //PostMessage("player.%d outcards\n",hn->client->H.slot);
        for (cardi=0; cardi<dp->N*2; cardi++)
            for (destplayer=0; destplayer<dp->N; destplayer++)
            {
                pangea_rwaudit(0,audit,priv->audits,cardi,destplayer,dp->N);
                if ( 0 && (card= cards777_checkcard(&cardpriv,cardi,pangea_ind(dp->table,hn->client->H.slot),destplayer,hn->client->H.privkey,dp->hand.cardpubs,dp->numcards,audit[0])) >= 0 )
                    PostMessage("ERROR: unexpected decode player.%d got card.[%d]\n",hn->client->H.slot,card);
                audit[0] = cards777_decode(&audit[sp->myind],priv->xoverz,destplayer,audit[0],priv->outcards,dp->numcards,dp->N);
                pangea_rwaudit(1,audit,priv->audits,cardi,destplayer,dp->N);
            }
        //PostMessage("issue preflop\n");
        if ( (zbuf= calloc(1,datalen*2+1)) != 0 )
        {
            //init_hexbytes_noT(zbuf,priv->audits[0].bytes,datalen);
            //PostMessage("STARTZBUF.(%s)\n",zbuf);
            len = pangea_zbuf(zbuf,priv->audits[0].bytes,datalen);
            {
                int32_t len2;
                len2 = pangea_unzbuf((void *)hex,zbuf,len);
                if ( len2 != datalen || memcmp(hex,priv->audits[0].bytes,datalen) != 0 )
                {
                    if ( _crc32(0,(void *)hex,datalen) != _crc32(0,priv->audits[0].bytes,datalen) )
                    {
                        PostMessage("zbuf error len2.%d vs datalen.%d crcs %u vs %u\n%s\n",len2,datalen,_crc32(0,(void *)hex,datalen),_crc32(0,priv->audits[0].bytes,datalen),hex);
                        getchar();
                    }
                }
            }
            //PostMessage("datalen.%d -> len.%d zbuf %ld\n",datalen,len,(long)strlen(zbuf));
            pangea_sendcmd(hex,hn,"preflop",pangea_prevnode(dp->table),(void *)zbuf,len,dp->N * 2 * dp->N,-1);
            free(zbuf);
        }
    }
    else
    {
        //PostMessage("sendout cards\n");
        for (iter=cardi=0; iter<2; iter++)
            for (i=0; i<dp->N; i++,cardi++)
            {
                destplayer = (dp->button + i) % dp->N;
                pangea_rwaudit(0,audit,priv->audits,cardi,destplayer,dp->N);
                //PostMessage("audit[0] %llx -> ",(long long)audit[0].txid);
                audit[0] = cards777_decode(&audit[sp->myind],priv->xoverz,destplayer,audit[0],priv->outcards,dp->numcards,dp->N);
                pangea_rwaudit(1,audit,priv->audits,cardi,destplayer,dp->N);
                //PostMessage("[%llx + %llx] ",*(long long *)&audit[0],(long long)&audit[pangea_ind(dp->table,hn->client->H.slot)]);
                if ( destplayer == pangea_ind(dp->table,hn->client->H.slot) )
                    pangea_card(hn,json,dp,priv,audit[0].bytes,sizeof(bits256)*dp->N,cardi,destplayer);
                else pangea_sendcmd(hex,hn,"card",destplayer,audit[0].bytes,sizeof(bits256)*dp->N,cardi,-1);
            }
    }
    free(hex);
    return(0);
}

int32_t pangea_encoded(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    char *hex; bits256 audit[CARDS777_MAXPLAYERS]; int32_t i,iter,cardi,destplayer; struct pangea_info *sp = dp->table;
    if ( data == 0 || datalen != (dp->numcards * dp->N) * sizeof(bits256) )
    {
        PostMessage("pangea_encode invalid datalen.%d vs %ld\n",datalen,(long)((dp->numcards * dp->N) * sizeof(bits256)));
        return(-1);
    }
    cards777_encode(priv->outcards,priv->xoverz,priv->allshares,priv->myshares,dp->hand.sharenrs[pangea_ind(dp->table,hn->client->H.slot)],dp->M,(void *)data,dp->numcards,dp->N);
    //int32_t i; for (i=0; i<dp->numcards*dp->N; i++)
    //    PostMessage("%llx ",(long long)priv->outcards[i].txid);
    PostMessage("player.%d ind.%d encodes into %p %llx -> %llx next.%d dp->N %d\n",hn->client->H.slot,pangea_ind(sp,hn->client->H.slot),priv->outcards,(long long)*(uint64_t *)data,(long long)priv->outcards[0].txid,pangea_nextnode(sp),dp->N);
    if ( pangea_ind(sp,hn->client->H.slot) > 0 && (hex= malloc(65536)) != 0 )
    {
        if ( pangea_ind(sp,hn->client->H.slot) < sp->numactive-1 )
        {
            //PostMessage("send encoded\n");
            pangea_sendcmd(hex,hn,"encoded",pangea_nextnode(sp),priv->outcards[0].bytes,datalen,dp->N*dp->numcards,-1);
        }
        else
        {
            memcpy(dp->hand.final,priv->outcards,sizeof(bits256)*dp->N*dp->numcards);
            pangea_sendcmd(hex,hn,"final",-1,priv->outcards[0].bytes,datalen,dp->N*dp->numcards,-1);
            for (iter=cardi=0; iter<2; iter++)
                for (i=0; i<dp->N; i++,cardi++)
                    for (destplayer=0; destplayer<dp->N; destplayer++)
                    {
                        pangea_rwaudit(0,audit,priv->audits,cardi,destplayer,dp->N);
                        audit[0] = dp->hand.final[cardi*dp->N + destplayer];
                        pangea_rwaudit(1,audit,priv->audits,cardi,destplayer,dp->N);
                    }
            PostMessage("call preflop %ld\n",(long)((2 * dp->N) * (dp->N * dp->N * sizeof(bits256))));
            pangea_preflop(hn,json,dp,priv,priv->audits[0].bytes,(2 * dp->N) * (dp->N * dp->N * sizeof(bits256)),pangea_ind(sp,hn->client->H.slot));
        }
        free(hex);
    }
    return(0);
}

int32_t pangea_final(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    if ( data == 0 || datalen != (dp->numcards * dp->N) * sizeof(bits256) )
    {
        PostMessage("pangea_final invalid datalen.%d vs %ld\n",datalen,(long)((dp->numcards * dp->N) * sizeof(bits256)));
        return(-1);
    }
    if ( Debuglevel > 2 )
        PostMessage("player.%d final into %p\n",hn->client->H.slot,priv->outcards);
    memcpy(dp->hand.final,data,sizeof(bits256) * dp->N * dp->numcards);
    return(0);
}

int32_t pangea_facedown(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t cardi,int32_t senderind)
{
    int32_t i,validcard,n = 0;
    if ( data == 0 || datalen != sizeof(int32_t) )
    {
        PostMessage("pangea_facedown invalid datalen.%d vs %ld\n",datalen,(long)sizeof(bits256));
        return(-1);
    }
    validcard = juint(json,"turni");
    if ( validcard > 0 )
        dp->hand.havemasks[senderind] |= (1LL << cardi);
    for (i=0; i<dp->N; i++)
    {
        if ( Debuglevel > 2 )
            PostMessage("%llx ",(long long)dp->hand.havemasks[i]);
        if ( bitweight(dp->hand.havemasks[i]) == 2 )
            n++;
    }
    if ( Debuglevel > 2 )
        PostMessage(" | player.%d sees that destplayer.%d got cardi.%d valid.%d | %llx | n.%d\n",hn->client->H.slot,senderind,cardi,validcard,(long long)dp->hand.havemasks[senderind],n);
    if ( hn->client->H.slot == pangea_slotA(dp->table) && n == dp->N )
        pangea_startbets(hn,dp,dp->N*2);
    return(0);
}

uint32_t pangea_rank(struct cards777_pubdata *dp,int32_t senderind)
{
    int32_t i; char handstr[128];
    if ( dp->hand.handranks[senderind] != 0 )
        return(dp->hand.handranks[senderind]);
    for (i=0; i<7; i++)
    {
        if ( i < 5 )
            dp->hand.hands[senderind][i] = dp->hand.community[i];
        if ( dp->hand.hands[senderind][i] == 0xff )
            break;
    }
    if ( i == 7 )
    {
        dp->hand.handranks[senderind] = set_handstr(handstr,dp->hand.hands[senderind],0);
        dp->hand.handmask |= (1 << senderind);
        PostMessage("sender.%d (%s) rank.%x handmask.%x\n",senderind,handstr,dp->hand.handranks[senderind],dp->hand.handmask);
    }
    return(dp->hand.handranks[senderind]);
}

int32_t pangea_faceup(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    int32_t cardi,validcard,i; char hexstr[65]; uint16_t tmp;
    if ( data == 0 || datalen != sizeof(bits256) )
    {
        PostMessage("pangea_faceup invalid datalen.%d vs %ld\n",datalen,(long)((dp->numcards + 1) * sizeof(bits256)));
        return(-1);
    }
    init_hexbytes_noT(hexstr,data,sizeof(bits256));
    cardi = juint(json,"cardi");
    validcard = ((int32_t)juint(json,"turni")) >= 0;
    if ( Debuglevel > 2 || hn->client->H.slot == pangea_slotA(dp->table) )
    {
        char *str = jprint(json,0);
        PostMessage("from.%d -> player.%d COMMUNITY.[%d] (%s) cardi.%d valid.%d (%s)\n",senderind,hn->client->H.slot,data[1],hexstr,cardi,validcard,str);
        free(str);
    }
    //PostMessage("got FACEUP.(%s)\n",jprint(json,0));
    if ( validcard > 0 )
    {
        tmp = (cardi << 8);
        tmp |= (juint(json,"turni") & 0xff);
        pangea_summary(hn,dp,CARDS777_FACEUP,&tmp,sizeof(tmp),data,sizeof(bits256));
        if ( cardi >= dp->N*2 && cardi < dp->N*2+5 )
        {
            dp->hand.community[cardi - dp->N*2] = data[1];
            for (i=0; i<dp->N; i++)
                dp->hand.hands[i][cardi - dp->N*2] = data[1];
            memcpy(dp->hand.community256[cardi - dp->N*2].bytes,data,sizeof(bits256));
            
            //PostMessage("set community[%d] <- %d\n",cardi - dp->N*2,data[1]);
            if ( senderind == pangea_ind(dp->table,hn->client->H.slot) )
                pangea_rank(dp,senderind);
            //PostMessage("calc rank\n");
            if ( hn->client->H.slot == pangea_slotA(dp->table) && cardi >= dp->N*2+2 && cardi < dp->N*2+5 )
                pangea_startbets(hn,dp,cardi+1);
            //else PostMessage("dont start bets %d\n",cardi+1);
        }
        else
        {
            //PostMessage("valid.%d cardi.%d vs N.%d\n",validcard,cardi,dp->N);
            if ( cardi < dp->N*2 )
            {
                memcpy(dp->hand.cards[senderind][cardi/dp->N].bytes,data,sizeof(bits256));
                dp->hand.hands[senderind][5 + cardi/dp->N] = data[1];
                pangea_rank(dp,senderind);
            }
        }
    }
    return(0);
}

void pangea_serverstate(union hostnet777 *hn,struct cards777_pubdata *dp,struct cards777_privdata *priv)
{
    int32_t i,j,n; struct pangea_info *sp = dp->table;
    if ( dp->hand.finished != 0 && time(NULL) > dp->hand.finished+PANGEA_HANDGAP )
    {
        PostMessage("HANDGAP\n");
        pangea_anotherhand(hn,dp,3);
    }
    if ( dp->hand.betstarted == 0 && dp->newhand[0] == 0 )
    {
        static uint32_t disptime;
        for (i=n=0; i<dp->N; i++)
        {
            if ( Debuglevel > 2 )
                PostMessage("%llx ",(long long)dp->hand.havemasks[i]);
            if ( bitweight(dp->hand.havemasks[i]) == 2 )
                n++;
        }
        if ( n < dp->N )
        {
            for (i=0; i<dp->N; i++)
            {
                if ( sp->balances[pangea_slot(sp,i)] < dp->minbuyin*dp->bigblind || sp->balances[pangea_slot(sp,i)] > dp->maxbuyin*dp->bigblind )
                    break;
            }
            if ( i == dp->N && dp->numhands < 2 )
            {
                if ( time(NULL) > dp->hand.startdecktime+60 )
                {
                    PostMessage("send newdeck len.%ld\n",(long)strlen(dp->newhand));
                    pangea_newdeck(hn);
                    PostMessage("sent newdeck %ld\n",(long)strlen(dp->newhand));
                }
            }
            else if ( disptime != time(NULL) && (time(NULL) % 60) == 0 )
            {
                disptime = (uint32_t)time(NULL);
                for (j=0; j<dp->N; j++)
                    PostMessage("%.8f ",dstr(sp->balances[pangea_slot(sp,i)]));
                PostMessage("no buyin for %d (%.8f %.8f)\n",i,dstr(dp->minbuyin*dp->bigblind),dstr(dp->maxbuyin*dp->bigblind));
            }
        }
    }
    else pangea_checkstart(hn,dp,priv);
}

/*int32_t pangea_pmtest(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    int32_t turni,cardi; char hex[2048];
    cardi = juint(json,"cardi");
    turni = juint(json,"turni");
    if ( senderind >= 0 && senderind < dp->N )
    {
        if ( cardi < 0 )
        {
            if ( turni >= 0 )
                dp->pmviaworks |= (1 << senderind);
            else dp->broadcastworks |= (1 << senderind);
        }
        else
        {
            if ( turni >= 0 )
                dp->pmworks |= (1 << senderind);
            else dp->pmviaworks |= (1 << senderind);
        }
        if ( dp->pmworks != ((1 << dp->N) - 1) )
        {
            //PostMessage("PMworks: %x %x %x\n",dp->pmworks,dp->pmviaworks,dp->broadcastworks);
        }
    }
    //PostMessage("got pmtest.%d from %d cardi.%d\n",turni,senderind,cardi);
    if ( hn->client->H.slot == 0 )
    {
        if ( dp->pmworks == ((1 << dp->N) - 1) )
        {
            //PostMessage("all pms work\n");
        }
    }
    else
    {
        if ( dp->pmworks != ((1 << dp->N) - 1) )
        {
            pangea_sendcmd(hex,hn,"pmtest",senderind,dp->hand.checkprod.bytes,sizeof(uint64_t),senderind,turni);
            pangea_sendcmd(hex,hn,"pmtest",-1,dp->hand.checkprod.bytes,sizeof(uint64_t),-1,turni);
        }
    }
    return(0);
}*/

int32_t pangea_ping(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    dp->hand.othercardpubs[senderind] = *(uint64_t *)data;
    if ( senderind == 0 )
    {
        /*dp->hand.undergun = juint(json,"turni");
        dp->hand.cardi = juint(json,"cardi");
        if ( (array= jarray(&n,json,"community")) != 0 )
        {
            for (i=0; i<n; i++)
                dp->hand.community[i] = juint(jitem(array,i),0);
        }*/
    }
    //PostMessage("player.%d GOTPING.(%s) %llx\n",hn->client->H.slot,jprint(json,0),(long long)dp->othercardpubs[senderind]);
    return(0);
}

void pangea_chat(uint64_t senderbits,void *buf,int32_t len,int32_t senderind)
{
    PostMessage(">>>>>>>>>>> CHAT FROM.%d %llu: (%s)\n",senderind,(long long)senderbits,(char *)buf);
}

int32_t pangea_poll(uint64_t *senderbitsp,uint32_t *timestampp,union hostnet777 *hn)
{
    char *jsonstr,*hexstr,*cmdstr; cJSON *json; struct cards777_privdata *priv; struct cards777_pubdata *dp; struct pangea_info *sp;
    int32_t len,senderind,maxlen; uint8_t *buf;
    *senderbitsp = 0;
    dp = hn->client->H.pubdata, sp = dp->table;
    priv = hn->client->H.privdata;
    if ( hn == 0 || hn->client == 0 || dp == 0 || priv == 0 )
    {
        if ( Debuglevel > 2 )
            PostMessage("pangea_poll: null hn.%p %p dp.%p priv.%p\n",hn,hn!=0?hn->client:0,dp,priv);
        return(-1);
    }
    maxlen = (int32_t)(sizeof(bits256) * dp->N*dp->N*dp->numcards);
    if ( (buf= malloc(maxlen)) == 0 )
    {
        PostMessage("pangea_poll: null buf\n");
        return(-1);
    }
    if ( dp != 0 && priv != 0 && (jsonstr= queue_dequeue(&hn->client->H.Q,1)) != 0 )
    {
        //pangea_neworder(dp,dp->table,0,0);
        //PostMessage("player.%d GOT.(%s)\n",hn->client->H.slot,jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            *senderbitsp = j64bits(json,"sender");
            if ( (senderind= juint(json,"myind")) < 0 || senderind >= dp->N )
            {
                PostMessage("pangea_poll: illegal senderind.%d cardi.%d turni.%d (%s)\n",senderind,juint(json,"cardi"),juint(json,"turni"),jsonstr);
                goto cleanup;
            }
            *timestampp = juint(json,"timestamp");
            hn->client->H.state = juint(json,"state");
            len = juint(json,"n");
            cmdstr = jstr(json,"cmd");
            if ( sp->myind < 0 )
            {
                // check for reactivation command
                goto cleanup;
            }
            if ( cmdstr != 0 && strcmp(cmdstr,"preflop") == 0 )
            {
                if ( (hexstr= jstr(json,"data")) != 0 )
                    len = pangea_unzbuf(buf,hexstr,len);
            }
            else if ( (hexstr= jstr(json,"data")) != 0 && strlen(hexstr) == (len<<1) )
            {
                if ( len > maxlen )
                {
                    PostMessage("len too big for pangea_poll\n");
                    goto cleanup;
                }
                decode_hex(buf,len,hexstr);
            } else if ( hexstr != 0 )
                PostMessage("len.%d vs hexlen.%ld (%s)\n",len,(long)(strlen(hexstr)>>1),hexstr);
            if ( cmdstr != 0 )
            {
                if ( strcmp(cmdstr,"newhand") == 0 )
                    pangea_newhand(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"ping") == 0 )
                    pangea_ping(hn,json,dp,priv,buf,len,senderind);
                //else if ( strcmp(cmdstr,"pmtest") == 0 )
                //    pangea_pmtest(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"gotdeck") == 0 )
                    pangea_gotdeck(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"ready") == 0 )
                    pangea_ready(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"encoded") == 0 )
                    pangea_encoded(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"final") == 0 )
                    pangea_final(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"addfunds") == 0 )
                    pangea_addfunds(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"preflop") == 0 )
                    pangea_preflop(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"decoded") == 0 )
                    pangea_decoded(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"card") == 0 )
                    pangea_card(hn,json,dp,priv,buf,len,juint(json,"cardi"),senderind);
                else if ( strcmp(cmdstr,"facedown") == 0 )
                    pangea_facedown(hn,json,dp,priv,buf,len,juint(json,"cardi"),senderind);
                else if ( strcmp(cmdstr,"faceup") == 0 )
                    pangea_faceup(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"turn") == 0 )
                    pangea_turn(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"confirmturn") == 0 )
                    pangea_confirmturn(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"chat") == 0 )
                    pangea_chat(*senderbitsp,buf,len,senderind);
                else if ( strcmp(cmdstr,"action") == 0 )
                    pangea_action(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"showdown") == 0 )
                    pangea_showdown(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"summary") == 0 )
                    pangea_gotsummary(hn,json,dp,priv,buf,len,senderind);
            }
cleanup:
            free_json(json);
        }
        free_queueitem(jsonstr);
    }
    free(buf);
    return(hn->client->H.state);
}

char *pangea_status(uint64_t my64bits,uint64_t tableid,cJSON *json)
{
    int32_t i,j,threadid = juint(json,"threadid"); struct pangea_info *sp; cJSON *item,*array=0,*retjson = 0;
    if ( tableid != 0 )
    {
        if ( (sp= pangea_find(tableid,threadid)) != 0 )
        {
            if ( (item= pangea_tablestatus(sp)) != 0 )
            {
                retjson = cJSON_CreateObject();
                jaddstr(retjson,"result","success");
                jadd(retjson,"table",item);
                return(jprint(retjson,1));
            }
        }
    }
    else
    {
        for (i=0; i<sizeof(TABLES)/sizeof(*TABLES); i++)
        {
            if ( (sp= TABLES[i]) != 0 )
            {
                for (j=0; j<sp->numaddrs; j++)
                    if ( sp->addrs[j] == my64bits )
                    {
                        if ( (item= pangea_tablestatus(sp)) != 0 )
                        {
                            if ( array == 0 )
                                array = cJSON_CreateArray();
                            jaddi(array,item);
                        }
                        break;
                    }
            }
        }
    }
    retjson = cJSON_CreateObject();
    if ( array == 0 )
        jaddstr(retjson,"error","no table status");
    else
    {
        jaddstr(retjson,"result","success");
        jadd(retjson,"tables",array);
    }
    jadd64bits(retjson,"nxtaddr",my64bits);
    return(jprint(retjson,1));
}

int32_t pangea_idle(struct plugin_info *plugin)
{
    int32_t i,n,m,pinggap = 1; uint64_t senderbits; uint32_t timestamp; struct pangea_thread *tp; union hostnet777 *hn;
    struct cards777_pubdata *dp; char hex[1024];
    while ( 1 )
    {
        for (i=n=m=0; i<_PANGEA_MAXTHREADS; i++)
        {
            if ( (tp= THREADS[i]) != 0 )
            {
                hn = &tp->hn;
            //PostMessage("pangea idle player.%d\n",hn->client->H.slot);
                if ( hn->client->H.done == 0 )
                {
                    n++;
                    if ( hostnet777_idle(hn) != 0 )
                        m++;
                    pangea_poll(&senderbits,&timestamp,hn);
                    dp = hn->client->H.pubdata;
                    if ( dp != 0 && hn->client->H.slot == pangea_slotA(dp->table) )
                        pinggap = 1;
                    if ( hn->client != 0 && dp != 0 )
                    {
                        if ( time(NULL) > hn->client->H.lastping + pinggap )
                        {
                            if ( 0 && (dp= hn->client->H.pubdata) != 0 )
                            {
                                pangea_sendcmd(hex,hn,"ping",-1,dp->hand.checkprod.bytes,sizeof(uint64_t),dp->hand.cardi,dp->hand.undergun);
                                hn->client->H.lastping = (uint32_t)time(NULL);
                            }
                        }
                        if ( dp->hand.handmask == ((1 << dp->N) - 1) && dp->hand.finished == 0 )//&& dp->hand.pangearake == 0 )
                        {
                            PostMessage("P%d: all players folded or showed cards at %ld | rakemillis %d\n",hn->client->H.slot,(long)time(NULL),dp->rakemillis);
                            pangea_finish(hn,dp);
                        }
                        if ( hn->client->H.slot == pangea_slotA(dp->table) )
                            pangea_serverstate(hn,dp,hn->server->H.privdata);
                    }
                }
            }
        }
        if ( n == 0 )
            break;
        if ( m == 0 )
            msleep(3);
    }
    //for (i=0; i<_PANGEA_MAXTHREADS; i++)
    //    if ( THREADS[i] != 0 && Pangea_waiting != 0 )
    //        pangea_userpoll(&THREADS[i]->hn);
    return(0);
}

void pangea_buyins(uint32_t *minbuyinp,uint32_t *maxbuyinp)
{
    if ( *minbuyinp == 0 && *maxbuyinp == 0 )
    {
        *minbuyinp = 100;
        *maxbuyinp = 1000;
    }
    else
    {
        PostMessage("minbuyin.%d maxbuyin.%d -> ",*minbuyinp,*maxbuyinp);
        if ( *minbuyinp < 20 )
            *minbuyinp = 20;
        if ( *maxbuyinp < *minbuyinp )
            *maxbuyinp = (*minbuyinp * 4);
        if ( *maxbuyinp > 1000 )
            *maxbuyinp = 1000;
        if ( *minbuyinp > *maxbuyinp )
            *minbuyinp = *maxbuyinp;
        PostMessage("(%d %d)\n",*minbuyinp,*maxbuyinp);
    }
}

struct pangea_info *pangea_create(struct pangea_thread *tp,int32_t *createdflagp,char *base,uint32_t timestamp,uint64_t *addrs,int32_t numaddrs,uint64_t bigblind,uint64_t ante,uint64_t *isbot,uint32_t minbuyin,uint32_t maxbuyin,int32_t hostrake)
{
    struct pangea_info *sp = 0; bits256 hash; int32_t i,j,numcards,firstslot = -1; struct cards777_privdata *priv; struct cards777_pubdata *dp;
    if ( createdflagp != 0 )
        *createdflagp = 0;
    for (i=0; i<numaddrs; i++)
        PostMessage("%llu ",(long long)addrs[i]);
    PostMessage("pangea_create numaddrs.%d\n",numaddrs);
    for (i=0; i<numaddrs; i++)
    {
        if ( addrs[i] == tp->nxt64bits )
            break;
    }
    if ( i == numaddrs )
    {
        PostMessage("this node not in addrs\n");
        return(0);
    }
    if ( numaddrs > 0 && (sp= calloc(1,sizeof(*sp))) != 0 )
    {
        sp->tp = tp;
        numcards = CARDS777_MAXCARDS;
        pangea_buyins(&minbuyin,&maxbuyin);
        tp->numcards = numcards, tp->N = numaddrs;
        sp->numactive = numaddrs;
        sp->dp = dp = cards777_allocpub((numaddrs >> 1) + 1,numcards,numaddrs);
        dp->minbuyin = minbuyin, dp->maxbuyin = maxbuyin;
        sp->minbuyin = minbuyin, sp->maxbuyin = maxbuyin;
        dp->rakemillis = hostrake;
        if ( dp->rakemillis > PANGEA_MAX_HOSTRAKE )
            dp->rakemillis = PANGEA_MAX_HOSTRAKE;
        dp->rakemillis += PANGEA_MINRAKE_MILLIS;
        if ( dp == 0 )
        {
            PostMessage("pangea_create: unexpected out of memory pub\n");
            return(0);
        }
        for (j=0; j<5; j++)
            dp->hand.community[j] = 0xff;
        memcpy(sp->addrs,addrs,numaddrs * sizeof(sp->addrs[0]));
        for (j=0; j<numaddrs; j++)
        {
            //if ( balances != 0 )
            //    dp->balances[j] = balances[j];
            //else dp->balances[j] = 100;
            if ( isbot != 0 )
                sp->isbot[j] = isbot[j];
            sp->active[j] = addrs[j];
        }
        sp->priv = priv = cards777_allocpriv(numcards,numaddrs);
        priv->hole[0] = priv->hole[1] = 0xff;
        if ( priv == 0 )
        {
            PostMessage("pangea_create: unexpected out of memory priv\n");
            return(0);
        }
        priv->automuck = Showmode;
        priv->autofold = Autofold;
        btc_priv2pub(sp->btcpub,tp->hn.client->H.privkey.bytes);
        init_hexbytes_noT(sp->btcpubkeystr,sp->btcpub,33);
        strcpy(sp->coinstr,base);
        strcpy(dp->coinstr,base);
        sp->addrtype = coin777_addrtype(&sp->p2shtype,base);
        sp->wiftype = coin777_wiftype(base);
        btc_priv2wip(sp->wipstr,tp->hn.client->H.privkey.bytes,sp->wiftype);
        strcpy(sp->btcpubkeys[sp->myslot],sp->btcpubkeystr);
        PostMessage("T%d: Automuck.%d Autofold.%d rakemillis.%d btcpubkey.(%s) (%s) addrtype.%02x p2sh.%02x wif.%02x\n",tp->hn.client->H.slot,priv->automuck,priv->autofold,dp->rakemillis,sp->btcpubkeystr,dp->coinstr,sp->addrtype,sp->p2shtype,sp->wiftype);
        if ( (sp->timestamp= timestamp) == 0 )
            sp->timestamp = (uint32_t)time(NULL);
        sp->numaddrs = sp->numactive = numaddrs;
        sp->basebits = stringbits(base);
        sp->bigblind = dp->bigblind = bigblind, sp->ante = dp->ante = ante;
        vcalc_sha256(0,hash.bytes,(uint8_t *)sp,numaddrs * sizeof(sp->addrs[0]) + 4*sizeof(uint32_t) + 3*sizeof(uint64_t));
        sp->tableid = hash.txid;
        for (i=0; i<sizeof(TABLES)/sizeof(*TABLES); i++)
        {
            if ( TABLES[i] != 0 )
            {
                if ( sp->tableid == TABLES[i]->tableid && tp->threadid == TABLES[i]->tp->threadid )
                {
                    PostMessage("tableid %llu already exists!\n",(long long)sp->tableid);
                    free(sp);
                    return(TABLES[i]);
                }
            }
            else if ( firstslot < 0 )
                firstslot = i;
        }
        TABLES[firstslot] = sp;
        if ( createdflagp != 0 )
            *createdflagp = 1;
    }
    return(sp);
}

cJSON *pangea_ciphersjson(struct cards777_pubdata *dp,struct cards777_privdata *priv)
{
    int32_t i,j,nonz = 0; char hexstr[65]; cJSON *array = cJSON_CreateArray();
    for (i=0; i<dp->numcards; i++)
        for (j=0; j<dp->N; j++,nonz++)
        {
            init_hexbytes_noT(hexstr,priv->outcards[nonz].bytes,sizeof(bits256));
            jaddistr(array,hexstr);
        }
    return(array);
}

cJSON *pangea_playerpubs(bits256 *playerpubs,int32_t num)
{
    int32_t i; char hexstr[65]; cJSON *array = cJSON_CreateArray();
    for (i=0; i<num; i++)
    {
        init_hexbytes_noT(hexstr,playerpubs[i].bytes,sizeof(bits256));
        //PostMessage("(%llx-> %s) ",(long long)playerpubs[i].txid,hexstr);
        jaddistr(array,hexstr);
    }
    //PostMessage("playerpubs\n");
    return(array);
}

cJSON *pangea_cardpubs(struct cards777_pubdata *dp)
{
    int32_t i; char hexstr[65]; cJSON *array = cJSON_CreateArray();
    for (i=0; i<dp->numcards; i++)
    {
        init_hexbytes_noT(hexstr,dp->hand.cardpubs[i].bytes,sizeof(bits256));
        jaddistr(array,hexstr);
    }
    init_hexbytes_noT(hexstr,dp->hand.checkprod.bytes,sizeof(bits256));
    jaddistr(array,hexstr);
    return(array);
}

cJSON *pangea_sharenrs(uint8_t *sharenrs,int32_t n)
{
    int32_t i; cJSON *array = cJSON_CreateArray();
    for (i=0; i<n; i++)
        jaddinum(array,sharenrs[i]);
    return(array);
}

char *pangea_newtable(int32_t threadid,cJSON *json,uint64_t my64bits,bits256 privkey,bits256 pubkey,char *transport,char *ipaddr,uint16_t port,uint32_t minbuyin,uint32_t maxbuyin,int32_t hostrake)
{
    int32_t createdflag,num,i,myind= -1; uint64_t tableid,addrs[CARDS777_MAXPLAYERS],isbot[CARDS777_MAXPLAYERS];
    struct pangea_info *sp; cJSON *array; struct pangea_thread *tp=0; char *base,*str,*hexstr,*endpoint,hex[1024]; uint32_t timestamp;
    struct cards777_pubdata *dp; struct hostnet777_server *srv=0;
    str = jprint(json,0);
    PostMessage("T%d NEWTABLE.(%s)\n",threadid,str);
    free(str);
    if ( (tableid= j64bits(json,"tableid")) != 0 && (base= jstr(json,"base")) != 0 && (timestamp= juint(json,"timestamp")) != 0 )
    {
        if ( (array= jarray(&num,json,"addrs")) == 0 || num < 2 || num > CARDS777_MAXPLAYERS )
        {
            PostMessage("no address or illegal num.%d\n",num);
            return(clonestr("{\"error\":\"no addrs or illegal numplayers\"}"));
        }
        for (i=0; i<num; i++)
        {
            addrs[i] = j64bits(jitem(array,i),0);
            if ( addrs[i] == my64bits )
            {
                threadid = myind = i;
                if ( (tp= THREADS[threadid]) == 0 )
                {
                    THREADS[threadid] = tp = calloc(1,sizeof(*THREADS[threadid]));
                    if ( i == 0 )
                    {
                        if ( (srv= hostnet777_server(privkey,pubkey,transport,ipaddr,port,num)) == 0 )
                            PostMessage("cant create hostnet777 server\n");
                        else
                        {
                            tp->hn.server = srv;
                            memcpy(srv->H.privkey.bytes,privkey.bytes,sizeof(bits256));
                            memcpy(srv->H.pubkey.bytes,pubkey.bytes,sizeof(bits256));
                        }
                    }
                    else
                    {
                        PANGEA_MAXTHREADS = 1;
                        if ( (endpoint= jstr(json,"pangea_endpoint")) != 0 )
                        {
                            if ( strncmp(endpoint,"tcp://127.0.0.1",strlen("tcp://127.0.0.1")) == 0 || strncmp(endpoint,"ws://127.0.0.1",strlen("ws://127.0.0.1")) == 0 )
                            {
                                PostMessage("ILLEGAL pangea_endpoint.(%s)\n",endpoint);
                                return(clonestr("{\"error\":\"contact pangea host and tell them to add myipaddr to their SuperNET.conf\"}"));
                            }
                            if ( (tp->hn.client= hostnet777_client(privkey,pubkey,endpoint,i)) == 0 )
                            {
                                memcpy(tp->hn.client->H.privkey.bytes,privkey.bytes,sizeof(bits256));
                                memcpy(tp->hn.client->H.pubkey.bytes,pubkey.bytes,sizeof(bits256));
                            }
                        }
                    }
                    tp->nxt64bits = my64bits;
                }
            }
        }
        if ( myind < 0 )
            return(clonestr("{\"error\":\"this table is not for me\"}"));
        /*if ( (array= jarray(&num,json,"balances")) == 0 )
        {
            PostMessage("no balances or illegal num.%d\n",num);
            return(clonestr("{\"error\":\"no balances or illegal numplayers\"}"));
        }
        for (i=0; i<num; i++)
            balances[i] = j64bits(jitem(array,i),0);*/
        if ( (array= jarray(&num,json,"isbot")) != 0 )
        {
            for (i=0; i<num; i++)
                isbot[i] = j64bits(jitem(array,i),0);
        }
        else memset(isbot,0,sizeof(isbot));
        PostMessage("call pangea_create\n");
        if ( (sp= pangea_create(tp,&createdflag,base,timestamp,addrs,num,j64bits(json,"bigblind"),j64bits(json,"ante"),isbot,minbuyin,maxbuyin,hostrake)) == 0 )
        {
            PostMessage("cant create table.(%s) numaddrs.%d\n",base,num);
            return(clonestr("{\"error\":\"cant create table\"}"));
        }
        PostMessage("back from pangea_create\n");
        dp = sp->dp; sp->myslot = sp->myind = myind;
        dp->table = sp;
        tp->numcards = dp->numcards, tp->N = dp->N, tp->M = dp->M;
        if ( threadid == 0 )
        {
            tp->hn.server->clients[0].pubdata = dp;
            tp->hn.server->clients[0].privdata = sp->priv;
            tp->hn.server->H.pubdata = dp;
            tp->hn.server->H.privdata = sp->priv;
        }
        else
        {
            tp->hn.client->my.pubdata = dp;
            tp->hn.client->my.privdata = sp->priv;
            tp->hn.client->H.pubdata = dp;
            tp->hn.client->H.privdata = sp->priv;
            if ( THREADS[0] != 0 )
            {
                THREADS[0]->hn.server->clients[threadid].pubdata = dp;
                THREADS[0]->hn.server->clients[threadid].privdata = sp->priv;
            }
        }
        if ( (array= jarray(&num,json,"playerpubs")) == 0 || num < 2 || num > CARDS777_MAXPLAYERS )
        {
            PostMessage("no address or illegal num.%d\n",num);
            return(clonestr("{\"error\":\"no addrs or illegal numplayers\"}"));
        }
        for (i=0; i<num; i++)
        {
            hexstr = jstr(jitem(array,i),0);
            decode_hex(sp->playerpubs[i].bytes,sizeof(bits256),hexstr);
            PostMessage("set playerpubs.(%s) %llx\n",hexstr,(long long)sp->playerpubs[i].txid);
            if ( sp->playerpubs[i].txid == 0 )
            {
                PostMessage("player.%d has no NXT pubkey\n",i);
                return(clonestr("{\"error\":\"not all players have published NXT pubkeys\"}"));
            }
        }
        if ( myind >= 0 && createdflag != 0 && addrs[myind] == tp->nxt64bits )
        {
            memcpy(sp->addrs,addrs,sizeof(*addrs) * dp->N);
            dp->readymask |= (1 << sp->myslot);
            pangea_sendcmd(hex,&tp->hn,"ready",-1,sp->btcpub,sizeof(sp->btcpub),0,0);
            return(clonestr("{\"result\":\"newtable created\"}"));
        }
        else if ( createdflag == 0 )
        {
            if ( sp->addrs[0] == tp->nxt64bits )
                return(clonestr("{\"result\":\"this is my table\"}"));
            else return(clonestr("{\"result\":\"table already exists\"}"));
        }
    }
    return(clonestr("{\"error\":\"no tableid\"}"));
}

struct pangea_thread *pangea_threadinit(struct plugin_info *plugin,int32_t maxplayers)
{
    struct pangea_thread *tp; struct hostnet777_server *srv;
    PANGEA_MAXTHREADS = 1;
    THREADS[0] = tp = calloc(1,sizeof(*THREADS[0]));
    if ( tp == 0 )
    {
        PostMessage("pangea_threadinit: unexpected out of memory\n");
        return(0);
    }
    tp->nxt64bits = plugin->nxt64bits;
    if ( (srv= hostnet777_server(*(bits256 *)plugin->mypriv,*(bits256 *)plugin->mypub,plugin->transport,plugin->ipaddr,plugin->pangeaport,9)) == 0 )
        PostMessage("cant create hostnet777 server\n");
    else
    {
        tp->hn.server = srv;
        memcpy(srv->H.privkey.bytes,plugin->mypriv,sizeof(bits256));
        memcpy(srv->H.pubkey.bytes,plugin->mypub,sizeof(bits256));
    }
    return(tp);
}

void pangea_create_newtable(char *retbuf,struct pangea_info *sp,struct cards777_pubdata *dp,uint64_t *isbot)
{
    char *addrstr,*ciphers,*playerpubs,*isbotstr;
    isbotstr = jprint(addrs_jsonarray(isbot,dp->N),1);
    //balancestr = jprint(addrs_jsonarray(balances,num),1);
    addrstr = jprint(addrs_jsonarray(sp->addrs,dp->N),1);
    ciphers = jprint(pangea_ciphersjson(dp,sp->priv),1);
    playerpubs = jprint(pangea_playerpubs(sp->playerpubs,dp->N),1);
    dp->readymask |= (1 << sp->myslot);
    sprintf(retbuf,"{\"cmd\":\"newtable\",\"broadcast\":\"allnodes\",\"myind\":%d,\"pangea_endpoint\":\"%s\",\"plugin\":\"relay\",\"destplugin\":\"pangea\",\"method\":\"busdata\",\"submethod\":\"newtable\",\"my64bits\":\"%llu\",\"tableid\":\"%llu\",\"timestamp\":%u,\"M\":%d,\"N\":%d,\"base\":\"%s\",\"bigblind\":\"%llu\",\"minbuyin\":\"%d\",\"maxbuyin\":\"%u\",\"rakemillis\":\"%u\",\"ante\":\"%llu\",\"playerpubs\":%s,\"addrs\":%s,\"isbot\":%s,\"millitime\":\"%lld\"}",sp->myslot,sp->tp->hn.server->ep.endpoint,(long long)sp->tp->nxt64bits,(long long)sp->tableid,sp->timestamp,dp->M,dp->N,sp->coinstr,(long long)sp->bigblind,dp->minbuyin,dp->maxbuyin,dp->rakemillis,(long long)sp->ante,playerpubs,addrstr,isbotstr,(long long)hostnet777_convmT(&sp->tp->hn.server->H.mT,0)); //\"pluginrequest\":\"SuperNET\",
    PostMessage("START.(%s)\n",retbuf);
    //dp->pmworks |= (1 << sp->myind);
    free(addrstr), free(ciphers), free(playerpubs), free(isbotstr);// free(balancestr);
}

int32_t pangea_start(struct plugin_info *plugin,char *retbuf,char *base,uint32_t timestamp,uint64_t bigblind,uint64_t ante,int32_t hostrake,int32_t maxplayers,uint32_t minbuyin,uint32_t maxbuyin,cJSON *json)
{
    char destNXT[64]; struct pangea_thread *tp; struct cards777_pubdata *dp;
    int32_t createdflag,addrtype,haspubkey,i,j,slot,n,myind=-1,r,num=0,threadid=0; uint64_t addrs[512],isbot[512],tmp;
    uint8_t p2shtype; struct pangea_info *sp; cJSON *bids,*walletitem,*item;
    memset(addrs,0,sizeof(addrs));
    PostMessage("pangea_start rakemillis.%d\n",hostrake);
    //memset(balances,0,sizeof(balances));
    pangea_buyins(&minbuyin,&maxbuyin);
    if ( hostrake < 0 || hostrake > PANGEA_MAX_HOSTRAKE )
    {
        PostMessage("illegal hostrake.%d\n",hostrake);
        strcpy(retbuf,"{\"error\":\"illegal hostrake\"}");
        return(-1);
    }
    if ( bigblind == 0 )
        bigblind = SATOSHIDEN;
    if ( (tp= THREADS[threadid]) == 0 )
    {
        pangea_threadinit(plugin,maxplayers);
        if ( (tp=THREADS[0]) == 0 )
        {
            strcpy(retbuf,"{\"error\":\"uinitialized threadid\"}");
            PostMessage("%s\n",retbuf);
            return(-1);
        }
    }
    PostMessage("mynxt64bits.%llu base.(%s) maxplayers.%d minbuyin.%u maxbuyin.%u\n",(long long)tp->nxt64bits,base,maxplayers,minbuyin,maxbuyin);
    if ( base == 0 || base[0] == 0 || maxplayers < 2 || maxplayers > CARDS777_MAXPLAYERS )
    {
        sprintf(retbuf,"{\"error\":\"bad params\"}");
        PostMessage("%s\n",retbuf);
        return(-1);
    }
    addrtype = coin777_addrtype(&p2shtype,base);
    if ( (bids= jarray(&n,json,"bids")) != 0 )
    {
        PostMessage("numbids.%d\n",n);
        for (i=num=0; i<n; i++)
        {
            item = jitem(bids,i);
            if ( (addrs[num]= j64bits(item,"offerNXT")) != 0 && (walletitem= jobj(item,"wallet")) != 0 )
            {
                if ( j64bits(walletitem,"bigblind") == bigblind && j64bits(walletitem,"ante") == ante && juint(walletitem,"rakemillis") == hostrake )
                {
                    //balances[num] = j64bits(walletitem,"balance");
                    isbot[num] = juint(walletitem,"isbot");
                    PostMessage("(i.%d %llu) ",i,(long long)addrs[num]);//,dstr(balances[num]));
                    for (j=0; j<num; j++)
                        if ( addrs[j] == addrs[num] )
                            break;
                    if ( j == num )
                    {
                        if ( addrs[num] == tp->nxt64bits )
                            myind = num;
                        PostMessage("%llu ",(long long)addrs[num]);
                        num++;
                    }
                }
                else PostMessage("%d: %llu mismatched walletitem bigblind %.8f ante %.8f rake %.1f%%\n",i,(long long)addrs[num],dstr(j64bits(walletitem,"bigblind")),dstr(j64bits(walletitem,"ante")),(double)juint(walletitem,"rakemillis")/10.);
            }
        }
    }
    PostMessage("(%llu) pangea_start(%s) threadid.%d myind.%d num.%d maxplayers.%d\n",(long long)tp->nxt64bits,base,tp->threadid,myind,num,maxplayers);
    if ( (i= myind) > 0 )
    {
        addrs[i] = addrs[0];
        addrs[0] = tp->nxt64bits;
        //tmp = balances[i];
        //balances[i] = balances[0];
        //balances[0] = tmp;
        tmp = isbot[i];
        isbot[i] = isbot[0];
        isbot[0] = tmp;
        i = 0;
        strcpy(retbuf,"{\"error\":\"host needs to be locally started and the first entry in addrs\"}");
        return(-1);
    }
    while ( num > maxplayers )
    {
        r = (rand() % (num-1));
        PostMessage("swap out %d of %d\n",r+1,num);
        num--;
        isbot[r + 1] = isbot[num];
        //balances[r + 1] = balances[num];
        addrs[r + 1] = addrs[num];
    }
    PostMessage("pangea numplayers.%d\n",num);
    if ( (sp= pangea_create(tp,&createdflag,base,timestamp,addrs,num,bigblind,ante,isbot,minbuyin,maxbuyin,hostrake)) == 0 )
    {
        PostMessage("cant create table.(%s) numaddrs.%d\n",base,num);
        strcpy(retbuf,"{\"error\":\"cant create table, make sure all players have published NXT pubkeys\"}");
        return(-1);
    }
    PostMessage("back from pangea_create\n");
    dp = sp->dp, dp->table = sp;
    sp->myslot = sp->myind = myind;
    if ( createdflag != 0 && myind == 0 && addrs[myind] == tp->nxt64bits )
    {
        tp->numcards = dp->numcards, tp->N = dp->N, tp->M = dp->M;
        PostMessage("myind.%d: hostrake.%d\n",myind,dp->rakemillis);
        dp->minbuyin = minbuyin, dp->maxbuyin = maxbuyin;
        tp->hn.server->clients[myind].pubdata = dp;
        tp->hn.server->clients[myind].privdata = sp->priv;
        tp->hn.server->H.pubdata = dp;
        tp->hn.server->H.privdata = sp->priv;
        for (j=0; j<dp->N; j++)
        {
            if ( THREADS[j] != 0 )
                sp->playerpubs[j] = THREADS[j]->hn.client->H.pubkey;
            else
            {
                expand_nxt64bits(destNXT,addrs[j]);
                sp->playerpubs[j] = issue_getpubkey(&haspubkey,destNXT);
                if ( (slot= hostnet777_register(THREADS[0]->hn.server,sp->playerpubs[j],-1)) != j )
                    PostMessage("unexpected register slot.%d for j.%d\n",slot,j);
            }
            //PostMessage("thread[%d] pub.%llx priv.%llx\n",j,(long long)dp->playerpubs[j].txid,(long long)THREADS[j]->hn.client->H.privkey.txid);
        }
        pangea_create_newtable(retbuf,sp,dp,isbot);
#ifdef BUNDLED
        if ( 1 )
        {
            char *busdata_sync(uint32_t *noncep,char *jsonstr,char *broadcastmode,char *destNXTaddr);
            char *str; uint32_t nonce;
            if ( (str= busdata_sync(&nonce,retbuf,"allnodes",0)) != 0 )
                free(str);
        }
#endif
    }
    return(0);
}

char *pangea_history(uint64_t my64bits,uint64_t tableid,cJSON *json)
{
    struct pangea_info *sp;
    if ( (sp= pangea_find64(tableid,my64bits)) != 0 && sp->dp != 0 )
    {
        if ( jobj(json,"handid") == 0 )
            return(pangea_dispsummary(sp,juint(json,"verbose"),sp->dp->summary,sp->dp->summarysize,tableid,sp->dp->numhands-1,sp->dp->N));
        else return(pangea_dispsummary(sp,juint(json,"verbose"),sp->dp->summary,sp->dp->summarysize,tableid,juint(json,"handid"),sp->dp->N));
    }
    return(clonestr("{\"error\":\"cant find tableid\"}"));
}

char *pangea_buyin(uint64_t my64bits,uint64_t tableid,cJSON *json)
{
    struct pangea_info *sp; uint32_t buyin,vout; uint64_t amount = 0; char hex[1024],jsonstr[1024],*txidstr,*destaddr;
    if ( (sp= pangea_find64(tableid,my64bits)) != 0 && sp->dp != 0 && sp->tp != 0 && (amount= j64bits(json,"amount")) != 0 )
    {
        buyin = (uint32_t)(amount / sp->dp->bigblind);
        PostMessage("buyin.%u amount %.8f -> %.8f\n",buyin,dstr(amount),dstr(buyin * sp->bigblind));
        if ( buyin >= sp->dp->minbuyin && buyin <= sp->dp->maxbuyin )
        {
            sp->balances[pangea_ind(sp,sp->myslot)] = amount;
            if ( (txidstr= jstr(json,"txidstr")) != 0 && (destaddr= jstr(json,"msigaddr")) != 0 && strcmp(destaddr,sp->multisigaddr) == 0 )
            {
                vout = juint(json,"vout");
                sprintf(jsonstr,"{\"txid\":\"%s\",\"vout\":%u,\"msig\":\"%s\",\"amount\":%.8f}",txidstr,vout,sp->multisigaddr,dstr(amount));
                pangea_sendcmd(hex,&sp->tp->hn,"addfunds",-1,(void *)jsonstr,(int32_t)strlen(jsonstr)+1,pangea_ind(sp,sp->myslot),-1);
            } else pangea_sendcmd(hex,&sp->tp->hn,"addfunds",-1,(void *)&amount,sizeof(amount),pangea_ind(sp,sp->myslot),-1);
            //pangea_sendcmd(hex,&sp->tp->hn,"addfunds",0,(void *)&amount,sizeof(amount),pangea_ind(sp,sp->myslot),-1);
            return(clonestr("{\"result\":\"buyin sent\"}"));
        }
        else
        {
            PostMessage("buyin.%d vs (%d %d)\n",buyin,sp->dp->minbuyin,sp->dp->maxbuyin);
            return(clonestr("{\"error\":\"buyin too small or too big\"}"));
        }
    }
    return(clonestr("{\"error\":\"cant buyin unless you are part of the table\"}"));
}

char *pangea_mode(uint64_t my64bits,uint64_t tableid,cJSON *json)
{
    struct pangea_info *sp; char *chatstr,hex[8192]; int32_t i; uint64_t pm;
    if ( jobj(json,"automuck") != 0 )
    {
        if ( tableid == 0 )
            Showmode = juint(json,"automuck");
        else if ( (sp= pangea_find64(tableid,my64bits)) != 0 && sp->priv != 0 )
            sp->priv->automuck = juint(json,"automuck");
        else return(clonestr("{\"error\":\"automuck not tableid or sp->priv\"}"));
        return(clonestr("{\"result\":\"set automuck mode\"}"));
    }
    else if ( jobj(json,"autofold") != 0 )
    {
        if ( tableid == 0 )
            Autofold = juint(json,"autofold");
        else if ( (sp= pangea_find64(tableid,my64bits)) != 0 && sp->priv != 0 )
            sp->priv->autofold = juint(json,"autofold");
        else return(clonestr("{\"error\":\"autofold not tableid or sp->priv\"}"));
        return(clonestr("{\"result\":\"set autofold mode\"}"));
    }
    else if ( (sp= pangea_find64(tableid,my64bits)) != 0 && (chatstr= jstr(json,"chat")) != 0 && strlen(chatstr) < 256 )
    {
        if ( 0 && (pm= j64bits(json,"pm")) != 0 )
        {
            for (i=0; i<sp->numaddrs; i++)
                if ( sp->addrs[i] == pm )
                    break;
            if ( i == sp->numaddrs )
                return(clonestr("{\"error\":\"specified pm destination not at table\"}"));
        } else i = -1;
        pangea_sendcmd(hex,&sp->tp->hn,"chat",i,(void *)chatstr,(int32_t)strlen(chatstr)+1,pangea_ind(sp,sp->myslot),-1);
        return(clonestr("{\"result\":\"chat message sent\"}"));
    }
    return(clonestr("{\"error\":\"unknown pangea mode\"}"));
}

char *pangea_univ(uint8_t *mypriv,cJSON *json)
{
    char *addrtypes[][3] = { {"BTC","0","80"}, {"LTC","48"}, {"BTCD","60","bc"}, {"DOGE","30"}, {"VRC","70"}, {"OPAL","115"}, {"BITS","25"} };
    char *wipstr,*coin,*coinaddr,pubkeystr[67],rsaddr[64],destaddr[64],wifbuf[128]; uint8_t priv[32],pub[33],addrtype; int32_t i;
    uint64_t nxt64bits; cJSON *retjson,*item;
    PostMessage("inside rosetta\n");
    if ( (coin= jstr(json,"coin")) != 0 )
    {
        if ( (wipstr= jstr(json,"wif")) != 0 || (wipstr= jstr(json,"wip")) != 0 )
        {
            PostMessage("got wip.(%s)\n",wipstr);
            btc_wip2priv(priv,wipstr);
        }
        else if ( (coinaddr= jstr(json,"addr")) != 0 )
        {
            if ( getprivkey(priv,coin,coinaddr) < 0 )
                return(clonestr("{\"error\":\"cant get privkey\"}"));
        }
    } else memcpy(priv,mypriv,sizeof(priv));
    btc_priv2pub(pub,priv);
    init_hexbytes_noT(pubkeystr,pub,33);
    PostMessage("pubkey.%s\n",pubkeystr);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"btcpubkey",pubkeystr);
    for (i=0; i<sizeof(addrtypes)/sizeof(*addrtypes); i++)
    {
        if ( btc_coinaddr(destaddr,atoi(addrtypes[i][1]),pubkeystr) == 0 )
        {
            item = cJSON_CreateObject();
            jaddstr(item,"addr",destaddr);
            if ( addrtypes[i][2] != 0 )
            {
                decode_hex(&addrtype,1,addrtypes[i][2]);
                btc_priv2wip(wifbuf,priv,addrtype);
                jaddstr(item,"wif",wifbuf);
            }
            jadd(retjson,addrtypes[i][0],item);
        }
    }
    nxt64bits = nxt_priv2addr(rsaddr,pubkeystr,priv);
    item = cJSON_CreateObject();
    jaddstr(item,"addressRS",rsaddr);
    jadd64bits(item,"address",nxt64bits);
    jaddstr(item,"pubkey",pubkeystr);
    jadd(retjson,"NXT",item);
    return(jprint(retjson,1));
}

void pangea_test(struct plugin_info *plugin)//,int32_t numthreads,int64_t bigblind,int64_t ante,int32_t rakemillis)
{
    char retbuf[65536]; bits256 privkey,pubkey; int32_t i,slot,threadid; struct pangea_thread *tp; struct hostnet777_client **clients;
    struct hostnet777_server *srv=0; cJSON *item,*bids,*walletitem,*testjson = cJSON_CreateObject();
    //msleep(5000);
    int32_t numthreads; int64_t bigblind,ante; int32_t rakemillis;
    numthreads = 9; bigblind = SATOSHIDEN; ante = 0*SATOSHIDEN/10; rakemillis = PANGEA_MAX_HOSTRAKE;
    //plugin->sleepmillis = 1;
    //if ( PANGEA_MAXTHREADS > 1 && PANGEA_MAXTHREADS <= 9 )
    //    numthreads = PANGEA_MAXTHREADS;
    //else
    PostMessage("pangeatest\n");
    if ( PANGEA_MAXTHREADS == 0 )
        PANGEA_MAXTHREADS = numthreads;
    else numthreads = PANGEA_MAXTHREADS;
    if ( plugin->transport[0] == 0 )
        strcpy(plugin->transport,TEST_TRANSPORT);
    if ( plugin->ipaddr[0] == 0 )
        strcpy(plugin->ipaddr,"127.0.0.1");
    if ( plugin->pangeaport == 0 )
        plugin->pangeaport = 12343;
    PostMessage("pangea numthreads.%d\n",numthreads);
    if ( (clients= calloc(numthreads,sizeof(*clients))) == 0 )
    {
        PostMessage("pangea_test: unexpected out of mem\n");
        return;
    }
    for (threadid=0; threadid<PANGEA_MAXTHREADS; threadid++)
    {
        if ( (tp= calloc(1,sizeof(*THREADS[threadid]))) == 0 )
        {
            PostMessage("pangea_test: unexpected out of mem\n");
            free(clients);
            return;
        }
        tp->threadid = threadid;
        if ( threadid != 0 )
        {
            char hexstr[65]; uint32_t tmp = threadid + 4;
            tp->nxt64bits = conv_NXTpassword(privkey.bytes,pubkey.bytes,(void *)&tmp,sizeof(tmp));
            init_hexbytes_noT(hexstr,pubkey.bytes,sizeof(pubkey));
            printf("NXT.%llu pubkey.%s\n",(long long)tp->nxt64bits,hexstr);
        }
        else
        {
            tp->nxt64bits = plugin->nxt64bits;
            memcpy(privkey.bytes,plugin->mypriv,32);
            memcpy(pubkey.bytes,plugin->mypub,32);
        }
        if ( threadid == 0 )
        {
            if ( (srv= hostnet777_server(privkey,pubkey,0,0,0,numthreads)) == 0 )
            {
                PostMessage("cant create hostnet777 server\n");
                free(tp);
                return;
            }
            tp->hn.server = srv;
            clients[0] = (void *)srv;
            slot = threadid;
            // srv->H.privkey = privkey, srv->H.pubkey = pubkey;
        }
        else
        {
            if ( (slot= hostnet777_register(srv,pubkey,-1)) >= 0 && slot == threadid )
            {
                if ( (clients[threadid]= hostnet777_client(privkey,pubkey,srv->ep.endpoint,slot)) == 0 )
                    PostMessage("error creating clients[%d]\n",threadid);
                else
                {
                    tp->hn.client = clients[threadid];
                    //tp->hn.client->H.privkey = privkey, tp->hn.client->H.pubkey = pubkey;
                    //if ( portable_thread_create((void *)hostnet777_idler,hn) == 0 )
                    //    PostMessage("error launching clients[%d] thread\n",threadid);
                }
            } else PostMessage("error slot.%d != threadid.%d\n",slot,threadid);
        }
        if ( clients[threadid] != 0 )
            PostMessage("%llu: slot.%d client.%p -> %llu pubkey.%llx/%llx privkey.%llx/%llx\n",(long long)tp->nxt64bits,slot,clients[threadid],(long long)clients[threadid]->H.nxt64bits,(long long)clients[threadid]->H.pubkey.txid,(long long)pubkey.txid,(long long)clients[threadid]->H.privkey.txid,(long long)privkey.txid);
        THREADS[threadid] = tp;
    }
    bids = cJSON_CreateArray();
    PostMessage("numthreads.%d notabot.%d\n",numthreads,plugin->notabot);//, getchar();
    for (i=0; i<numthreads; i++)
    {
        item = cJSON_CreateObject();
        walletitem = cJSON_CreateObject();
        if ( plugin->notabot != numthreads )
        {
            if ( i != plugin->notabot )
                jaddnum(walletitem,"isbot",1);
        }
        jadd64bits(walletitem,"bigblind",bigblind);
        jadd64bits(walletitem,"ante",ante);
        jaddnum(walletitem,"rakemillis",rakemillis);
        //jadd64bits(walletitem,"balance",bigblind * 100);
        jadd64bits(item,"offerNXT",THREADS[i]->nxt64bits);
        jadd(item,"wallet",walletitem);
        jaddi(bids,item);
    }
    jadd(testjson,"bids",bids);
    jadd64bits(testjson,"offerNXT",THREADS[0]->nxt64bits);
    jadd64bits(testjson,"bigblind",bigblind);
    jadd64bits(testjson,"ante",ante);
    jaddnum(testjson,"rakemillis",rakemillis);
    PostMessage("TEST.(%s)\n",jprint(testjson,0));
    pangea_start(plugin,retbuf,"BTCD",0,bigblind,ante,rakemillis,i,0,0,testjson);
    free_json(testjson);
    testjson = cJSON_Parse(retbuf);
    //PostMessage("BROADCAST.(%s)\n",retbuf);
    for (threadid=1; threadid<numthreads; threadid++)
        pangea_newtable(threadid,testjson,THREADS[threadid]->nxt64bits,THREADS[threadid]->hn.client->H.privkey,THREADS[threadid]->hn.client->H.pubkey,0,0,0,0,0,rakemillis);
    for (threadid=0; threadid<numthreads; threadid++)
    {
        int32_t j; struct cards777_pubdata *dp; struct pangea_info *sp;
        tp = THREADS[threadid];
        dp = tp->hn.client->H.pubdata;
        if ( (sp= dp->table) == 0 )
            PostMessage("pangea_test: null table\n");
        for (j=0; j<numthreads; j++)
            sp->balances[j] = 1000 * SATOSHIDEN;
        PostMessage("T%d: set balances sp.%p\n",threadid,sp);
    }
    //for (threadid=0; threadid<numthreads; threadid++)
    //    if ( portable_thread_create((void *)hostnet777_idler,&THREADS[threadid]->hn) == 0 )
    //        PostMessage("error launching server thread\n");
    //tp = THREADS[0];
    //pangea_newdeck(&tp->hn);
    free(clients);
}

int32_t PLUGNAME(_process_json)(char *forwarder,char *sender,int32_t valid,struct plugin_info *plugin,uint64_t tag,char *retbuf,int32_t maxlen,char *jsonstr,cJSON *json,int32_t initflag,char *tokenstr)
{
    char *resultstr,*methodstr,*base,*retstr = 0; int32_t maxplayers,tmp; cJSON *argjson;
    retbuf[0] = 0;
    PostMessage("<<<<<<<<<<<< INSIDE PANGEA! process %s (%s) forwarder.(%s) sender.(%s)\n",plugin->name,jsonstr,forwarder,sender);
    if ( initflag > 0 )
    {
        randombytes((uint8_t *)&tmp,sizeof(tmp)), srand(tmp);
        uint64_t conv_NXTpassword(unsigned char *mysecret,unsigned char *mypublic,uint8_t *pass,int32_t passlen);
        //PANGEA.readyflag = 1;
        plugin->sleepmillis = 10;
        plugin->allowremote = 1;
        argjson = cJSON_Parse(jsonstr);
        plugin->nxt64bits = set_account_NXTSECRET(plugin->mypriv,plugin->mypub,plugin->NXTACCT,plugin->NXTADDR,plugin->NXTACCTSECRET,sizeof(plugin->NXTACCTSECRET),argjson,0,0,0);
        free_json(argjson);
        PostMessage("(%s) pangea.my64bits %llu ipaddr.%s mypriv.%02x mypub.%02x\n",jprint(json,0),(long long)plugin->nxt64bits,plugin->ipaddr,plugin->mypriv[0],plugin->mypub[0]);
        PANGEA_MAXTHREADS = juint(json,"pangeatest");
        plugin->notabot = juint(json,"notabot");
        if ( PANGEA_MAXTHREADS != 0 )
        {
            PostMessage("notabot.%d launch pangea_test\n",plugin->notabot);
            //pangea_test(plugin);
            portable_thread_create((void *)pangea_test,plugin);//,9,SATOSHIDEN,SATOSHIDEN/10,10);
        }
        PostMessage("initialized PANGEA\n");
        if ( 0 )
        {
            int32_t i; char str[8];
            for (i=0; i<52; i++)
            {
                cardstr(str,i);
                PostMessage("(%d %s) ",i,str);
            }
            PostMessage("cards\n");
        }
    }
    else
    {
        if ( plugin_result(retbuf,json,tag) > 0 )
            return((int32_t)strlen(retbuf));
        methodstr = jstr(json,"method");
        resultstr = jstr(json,"result");
        if ( methodstr == 0 || methodstr[0] == 0 )
        {
            PostMessage("(%s) has not method\n",jsonstr);
            return(0);
        }
        else if ( resultstr != 0 && strcmp(resultstr,"registered") == 0 )
        {
            plugin->registered = 1;
            strcpy(retbuf,"{\"result\":\"activated\"}");
        }
        else if ( strcmp(methodstr,"newtable") == 0 )
            retstr = pangea_newtable(juint(json,"threadid"),json,plugin->nxt64bits,*(bits256 *)plugin->mypriv,*(bits256 *)plugin->mypub,plugin->transport,plugin->ipaddr,plugin->pangeaport,juint(json,"minbuyin"),juint(json,"maxbuyin"),juint(json,"rakemillis"));
        else if ( sender == 0 || sender[0] == 0 )
        {
            if ( strcmp(methodstr,"start") == 0 )
            {
                strcpy(retbuf,"{\"result\":\"start issued\"}");
                if ( (base= jstr(json,"base")) != 0 )
                {
                    if ( (maxplayers= juint(json,"maxplayers")) < 2 )
                        maxplayers = 2;
                    else if ( maxplayers > CARDS777_MAXPLAYERS )
                        maxplayers = CARDS777_MAXPLAYERS;
                    if ( jstr(json,"resubmit") == 0 )
                        sprintf(retbuf,"{\"resubmit\":[{\"method\":\"start\"}, {\"bigblind\":\"%llu\"}, {\"ante\":\"%llu\"}, {\"rakemillis\":\"%u\"}, {\"maxplayers\":%d}, {\"minbuyin\":%d}, {\"maxbuyin\":%d}],\"pluginrequest\":\"SuperNET\",\"plugin\":\"InstantDEX\",\"method\":\"orderbook\",\"base\":\"%s\",\"exchange\":\"pangea\",\"allfields\":1}",(long long)j64bits(json,"bigblind"),(long long)j64bits(json,"ante"),juint(json,"rakemillis"),maxplayers,juint(json,"minbuyin"),juint(json,"maxbuyin"),jstr(json,"base")!=0?jstr(json,"base"):"BTCD");
                    else if ( pangea_start(plugin,retbuf,base,0,j64bits(json,"bigblind"),j64bits(json,"ante"),juint(json,"rakemillis"),maxplayers,juint(json,"minbuyin"),juint(json,"maxbuyin"),json) < 0 )
                        ;
                } else strcpy(retbuf,"{\"error\":\"no base specified\"}");
            }
            else if ( strcmp(methodstr,"status") == 0 )
                retstr = pangea_status(plugin->nxt64bits,j64bits(json,"tableid"),json);
        }
        //else if ( strcmp(methodstr,"turn") == 0 )
        //    retstr = pangea_input(plugin->nxt64bits,j64bits(json,"tableid"),json);
    }
    return(plugin_copyretstr(retbuf,maxlen,retstr));
}

char *Pangea_bypass(uint64_t my64bits,uint8_t myprivkey[32],cJSON *json)
{
    char *methodstr,*passphrase,*retstr = 0;
    if ( (methodstr= jstr(json,"method")) != 0 )
    {
        if ( strcmp(methodstr,"turn") == 0 )
            retstr = pangea_input(my64bits,j64bits(json,"tableid"),json);
        else if ( strcmp(methodstr,"status") == 0 )
            retstr = pangea_status(my64bits,j64bits(json,"tableid"),json);
        else if ( strcmp(methodstr,"mode") == 0 )
            retstr = pangea_mode(my64bits,j64bits(json,"tableid"),json);
        else if ( strcmp(methodstr,"rosetta") == 0 )
            retstr = pangea_univ(myprivkey,json);
        else if ( strcmp(methodstr,"buyin") == 0 )
            retstr = pangea_buyin(my64bits,j64bits(json,"tableid"),json);
        else if ( strcmp(methodstr,"history") == 0 )
            retstr = pangea_history(my64bits,j64bits(json,"tableid"),json);
        else if ( strcmp(methodstr,"rates") == 0 )
            retstr = peggyrates(0,jstr(json,"name"));
        else if ( strcmp(methodstr,"pangeatest") == 0 )
        {
            int32_t n;
            n = juint(json,"numplayers");
            if ( n >= 2 && n <= 9 )
                retstr = SuperNET_setconf(methodstr,n);
            else return(clonestr("{\"error\":\"invalid numplayers\"}"));
        }
        else if ( strcmp(methodstr,"changenum") == 0 )
        {
            char *fieldstr;
            if ( (fieldstr= jstr(json,"fieldname")) != 0 )
                retstr = SuperNET_setconf(fieldstr,juint(json,"val"));
            else return(clonestr("{\"error\":\"no fieldname\"}"));
        }
        else if ( strcmp(methodstr,"changefield") == 0 )
        {
            char *fieldstr;
            if ( (fieldstr= jstr(json,"fieldname")) != 0 )
                retstr = SuperNET_setconfstr(fieldstr,jstr(json,"valstr"));
            else return(clonestr("{\"error\":\"no fieldname\"}"));
        }
        else if ( strcmp(methodstr,"notabot") == 0 )
        {
            int32_t n;
            n = juint(json,"val");
            if ( n == 0 || n == -1 )
                retstr = SuperNET_setconf(methodstr,n);
            else return(clonestr("{\"error\":\"invalid notabot\"}"));
        }
        else if ( strcmp(methodstr,"clearconf") == 0 )
        {
            if ( SuperNET_saveconf("{\"secret\":\"randvals\"}") == 0 )
                return(clonestr("{\"result\":\"SuperNET.conf restored to defaults\"}"));
            else return(clonestr("{\"error\":\"SuperNET.conf couldnt be cleared\"}"));
        }
        else if ( strcmp(methodstr,"secret") == 0 && (passphrase= jstr(json,"passphrase")) != 0 )
        {
            char buf[1024],rsaddr[64]; uint64_t nxt64bits; bits256 pubkey,privkey;
            sprintf(buf,"{\"secret\":\"%s\"}",passphrase);
            if ( SuperNET_saveconf(buf) == 0 )
            {
                nxt64bits = conv_NXTpassword(privkey.bytes,pubkey.bytes,(void *)passphrase,(int32_t)strlen(passphrase));
                RS_encode(rsaddr,nxt64bits);
                sprintf(buf,"{\"result\":\"success\",\"NXT\":\"%llu\",\"RS\":\"%s\"}",(long long)nxt64bits,rsaddr);
                return(clonestr(buf));
            }
            else return(clonestr("{\"error\":\"couldnt sent new passphrase\"}"));
        }
    }
    // ./BitcoinDarkd SuperNET '{"agent":"pangea","method":"pangeatest","numplayers":2}'
    // ./BitcoinDarkd SuperNET '{"agent":"pangea","method":"notabot","val":-1}'
    // ./BitcoinDarkd SuperNET '{"agent":"pangea","method":"clearconf"}'
    // ./BitcoinDarkd SuperNET '{"agent":"pangea","method":"secret","passphrase":"password"}'
    return(retstr);
}

#endif
