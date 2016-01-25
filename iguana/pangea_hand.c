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

#include "pangea777.h"

#define PANGEA_GOTDECKS 1
#define PANGEA_GOTFINAL 2
struct pangea_queueitem { struct queueitem DL; struct tai start,last; int32_t waitevent; };

struct pangea_queueitem *pangea_queuefind(struct table_info *tp,int32_t waitevent)
{
    int32_t iter; struct pangea_queueitem *ptr;
    for (iter=0; iter<2; iter++)
    {
        while ( (ptr= queue_dequeue(&tp->stateQ[iter],0)) != 0 )
        {
            if ( ptr->waitevent == waitevent )
                return(ptr);
            queue_enqueue("stateQ",&tp->stateQ[iter ^ 1],&ptr->DL,0);
        }
    }
    return(0);
}

void pangea_queuestate(struct table_info *tp,int32_t currentstate,int32_t waitevent)
{
    struct pangea_queueitem *ptr;
    if ( (ptr= pangea_queuefind(tp,currentstate)) == 0 )
        ptr = calloc(1,sizeof(*ptr));
    ptr->last = ptr->start = tai_now();
    ptr->waitevent = waitevent;
    char str[65]; printf("table.%s current.%d -> wait.%d\n",bits256_str(str,tp->G.tablehash),currentstate,waitevent);
    queue_enqueue("stateQ",&tp->stateQ[0],&ptr->DL,0);
}

int32_t pangea_slotA(struct table_info *tp) { return(0); }
int32_t pangea_slotB(struct table_info *tp) { return(1); }
int32_t pangea_lastnode(struct table_info *tp) { return(tp->G.numactive-1); }
int32_t pangea_nextnode(struct table_info *tp) { return(tp->priv.myind+1); }
int32_t pangea_prevnode(struct table_info *tp) { return(tp->priv.myind-1); }

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

int32_t pangea_tableismine(struct supernet_info *myinfo,struct table_info *tp)
{
    int32_t i;
    if ( tp->G.creatorbits == myinfo->myaddr.nxt64bits )
    {
        tp->G.ismine = tp->G.numactive;
        return(tp->G.numactive);
    }
    else
    {
        for (i=0; i<tp->G.numactive; i++)
            if ( tp->G.P[i].nxt64bits == myinfo->myaddr.nxt64bits )
            {
                tp->G.ismine = 1;
                return(i);
            }
    }
    return(-1);
}

int32_t pangea_Pind(struct table_info *tp,bits256 playerpub)
{
    int32_t i;
    for (i=0; i<tp->G.N; i++)
    {
        if ( memcmp(tp->G.P[i].playerpub.bytes,playerpub.bytes,sizeof(playerpub)) == 0 )
            return(i);
    }
    return(-1);
}

int32_t pangea_actives(int32_t *activej,struct table_info *tp)
{
    int32_t i,n; struct player_info *p;
    *activej = -1;
    for (i=n=0; i<tp->G.numactive; i++)
    {
        if ( (p= tp->active[i]) != 0 && p->betstatus != CARDS777_FOLD )
        {
            if ( *activej < 0 )
                *activej = i;
            n++;
        }
    }
    return(n);
}

int32_t pangea_myrank(struct supernet_info *myinfo,struct table_info *tp,struct player_info *p)
{
    int32_t i; uint32_t myrank = p->handrank;
    for (i=0; i<tp->G.numactive; i++)
        if ( tp->active[i] != 0 && tp->active[i] != p && tp->active[i]->handrank > myrank )
            return(-1);
    return(myrank != 0);
}

void pangea_clearhand(struct table_info *tp)
{
    bits256 *final,*cardpubs; int32_t i; struct hand_info *hand = &tp->hand;
    final = hand->final, cardpubs = hand->cardpubs;
    memset(hand,0,sizeof(*hand));
    hand->final = final, hand->cardpubs = cardpubs;
    memset(final,0,sizeof(*final) * tp->G.N * tp->G.numcards);
    memset(cardpubs,0,sizeof(*cardpubs) * (1 + tp->G.numcards));
    for (i=0; i<5; i++)
        hand->community[i] = 0xff;
    for (i=0; i<tp->G.N; i++)
        memset(tp->G.P[i].hand,0xff,sizeof(tp->G.P[i].hand));
    tp->priv.hole[0] = tp->priv.hole[1] = tp->priv.cardis[0] = tp->priv.cardis[1] = 0xff;
    memset(tp->priv.holecards,0,sizeof(tp->priv.holecards));
}

uint32_t pangea_rank(struct supernet_info *myinfo,struct table_info *tp,int32_t senderind)
{
    int32_t i; char handstr[128]; struct player_info *p; struct hand_info *hand = &tp->hand;
    if ( senderind < tp->G.N && (p= tp->active[senderind]) != 0 )
    {
        if ( p->handrank != 0 )
            return(p->handrank);
        for (i=0; i<7; i++)
        {
            if ( i < 5 )
                p->hand[i] = hand->community[i];
            if ( p->hand[i] == 0xff )
                break;
        }
        if ( i == 7 )
        {
            p->handrank = set_handstr(handstr,p->hand,0);
            hand->handmask |= (1 << senderind);
            PNACL_message("sender.%d (%s) rank.%x handmask.%x\n",senderind,handstr,p->handrank,hand->handmask);
        }
        return(p->handrank);
    }
    printf("pangea_rank.%d illegal senderind\n",senderind);
    return(0);
}

// "state machine" funcs
int32_t pangea_newdeck(struct supernet_info *myinfo,struct table_info *tp)
{
    bits256 *playerpubs; int32_t i,j,n,datalen,button; struct hand_info *hand = &tp->hand;
    if ( tp->G.N < tp->G.numactive )
        tp->G.N = tp->G.numactive;
    button = (tp->numhands % tp->G.N);
    pangea_clearhand(tp);
    playerpubs = &hand->cardpubs[tp->G.numcards + 1];
    for (j=n=0; j<tp->G.N; j++)
    {
        i = (j + button) % tp->G.N;
        //if ( tp->G.P[i].balance > 0 )
            playerpubs[n++] = tp->G.P[i].playerpub;
        if ( bits256_cmp(tp->G.P[i].playerpub,myinfo->myaddr.persistent))
        {
            tp->priv.myind = i;
            char str[65],str2[65]; printf("player.%d (%s) vs persistent.(%s) myind.%d\n",i,bits256_str(str,tp->G.P[i].playerpub),bits256_str(str2,myinfo->myaddr.persistent),tp->priv.myind );
        }
    }
    if ( n < tp->G.minplayers )
    {
        printf("pangea_newdeck %d < %d minplayers\n",n,tp->G.minplayers);
        return(-1);
    }
    hand->checkprod = hand->cardpubs[tp->G.numcards] = cards777_initdeck(tp->priv.outcards,hand->cardpubs,tp->G.numcards,n,playerpubs,0);
    hand->othercardpubs[tp->priv.myind] = hand->checkprod;
    datalen = (tp->G.numcards + 1 + n) * sizeof(bits256);
    pangea_sendcmd(myinfo,tp,"newhand",-1,hand->cardpubs[0].bytes,datalen,n,n);
    printf("host sends NEWDECK checkprod.%llx numhands.%d\n",(long long)hand->checkprod.txid,tp->numhands);
    {
        bits256 checkprod; char str[65],str2[65];
        checkprod = cards777_pubkeys(hand->cardpubs,tp->G.numcards,hand->cardpubs[tp->G.numcards]);
        if ( bits256_cmp(checkprod,hand->checkprod) != 0 )
            printf("checkprod err.(%s) != (%s)\n",bits256_str(str,checkprod),bits256_str(str2,hand->checkprod));
        for (i=0; i<tp->G.numcards; i++)
            printf("%d: %s\n",i,bits256_str(str,hand->cardpubs[i]));
        printf("cardpubs.(%s)\n",bits256_str(str,hand->cardpubs[tp->G.numcards]));
    }
    pangea_queuestate(tp,PANGEA_GOTDECKS,PANGEA_GOTDECKS);
    return(0);
}

void pangea_newhand(PANGEA_HANDARGS)
{
    int32_t i,handid,numcards,n,ind; struct hand_info *hand; bits256 *pubkeys; char str[65],str2[65];
    hand = &tp->hand;
    numcards = tp->G.numcards;
    if ( data == 0 || datalen != (numcards + 1 + tp->G.numactive) * sizeof(bits256) )
    {
        PNACL_message("pangea_newhand invalid datalen.%d vs %ld\n",datalen,(long)((numcards + 1) * sizeof(bits256)));
        return;
    }
    pubkeys = (bits256 *)data;
    n = turni;
    tp->priv.myind = -1;
    tp->priv.mypriv = myinfo->persistent_priv, tp->priv.mypub = myinfo->myaddr.persistent;
    tp->G.M = (tp->G.numactive >> 1) + 1;
    for (i=0; i<n; i++)
    {
        if ( (ind= pangea_Pind(tp,pubkeys[numcards + 1 + i])) >= 0 && ind > i )
        {
            tp->G.P[i] = tp->G.P[ind];
            printf("init player[%d] with.%d\n",i,ind);
        }
        ind = i;
        tp->G.P[ind].playerpub = pubkeys[numcards + 1 + i];
        tp->G.P[ind].nxt64bits = acct777_nxt64bits(pubkeys[numcards + 1 + i]);
        tp->active[i] = &tp->G.P[ind];
        if ( i == 0 )
            hand->button = ind;
        if ( bits256_cmp(tp->G.P[ind].playerpub,myinfo->myaddr.persistent))
        {
            tp->priv.myind = i;
            printf("player.%d (%s) vs persistent.(%s) myind.%d\n",i,bits256_str(str,tp->G.P[ind].playerpub),bits256_str(str2,myinfo->myaddr.persistent),tp->priv.myind );
        }
    }
    hand->startdecktime = (uint32_t)time(NULL);//pm->sig.timestamp;
    memcpy(hand->cardpubs,pubkeys,(numcards +1 + tp->G.numactive) * sizeof(bits256));
    PNACL_message("player.%d NEWHAND.%llx received numhands.%d button.%d cardi.%d | N %d numactive.%d\n",tp->priv.myind,(long long)hand->cardpubs[numcards].txid,tp->numhands,hand->button,hand->cardi,tp->G.N,n);
    //printf("check.%s\n",bits256_str(str,hand->cardpubs[numcards]));
    hand->checkprod = cards777_pubkeys(hand->cardpubs,numcards,hand->cardpubs[numcards]);
    //printf("B check.%s\n",bits256_str(str,hand->checkprod));
    //printf("P0.%s\n",bits256_str(str,hand->cardpubs[numcards+1]));
    //printf("P1.%s\n",bits256_str(str,hand->cardpubs[numcards+2]));
    if ( bits256_cmp(hand->checkprod,hand->cardpubs[numcards]) != 0 )
    {
        for (i=0; i<tp->G.numcards; i++)
            printf("%d: %s\n",i,bits256_str(str,hand->cardpubs[i]));
        printf("checkprod mismatch myind.%d %s\n",tp->priv.myind,bits256_str(str,hand->cardpubs[i]));
        return;
    }
    if ( tp->priv.myind >= 0 )
    {
        hand->othercardpubs[tp->priv.myind] = hand->checkprod;
        tp->G.numactive = n;
        memset(tp->summary,0,sizeof(tp->summary));
        hand->summaries = hand->mismatches = tp->summarysize = 0;
        handid = tp->numhands++;
        pangea_summaryadd(myinfo,tp,CARDS777_START,&handid,sizeof(handid),hand->cardpubs[0].bytes,sizeof(bits256) * (numcards + 1));
        pangea_sendcmd(myinfo,tp,"gothand",-1,hand->checkprod.bytes,sizeof(bits256),hand->cardi,hand->button);
        printf("sent gotdeck\n");
    }
}

int32_t pangea_checkstart(struct supernet_info *myinfo,int32_t N,int32_t turni,int32_t cardi,int32_t destplayer,int32_t senderind,struct table_info *tp)
{
    int32_t i,matches = 0; struct hand_info *hand = &tp->hand;
    if ( bits256_nonz(hand->checkprod) > 0 && hand->encodestarted == 0 )
    {
        for (i=0; i<tp->G.numactive; i++)
        {
             if ( bits256_cmp(hand->othercardpubs[i],hand->checkprod) == 0 )
                matches++;
            char str[65],str2[65]; printf("matches.%d (%s vs %s)\n",matches,bits256_str(str,hand->othercardpubs[i]),bits256_str(str2,hand->checkprod));
        }
        if ( matches == tp->G.numactive )
        {
            if ( time(NULL) > (tp->priv.myind + hand->startdecktime) )
            {
                if ( PANGEA_PAUSE > 0 )
                    sleep(PANGEA_PAUSE);
                hand->encodestarted = (uint32_t)time(NULL);
                pangea_queuestate(tp,PANGEA_GOTDECKS,PANGEA_GOTFINAL);
                PNACL_message("start encoded %llx\n",(long long)hand->checkprod.txid);
                if ( destplayer == tp->priv.myind )
                {
                    printf("encode to myself\n");
                    pangea_encoded(myinfo,N,turni,cardi,destplayer,tp->priv.myind,tp,tp->priv.outcards[0].bytes,sizeof(bits256) * tp->G.numactive * tp->G.numcards);
                }
                else pangea_sendcmd(myinfo,tp,"encoded",pangea_slotB(tp),tp->priv.outcards[0].bytes,sizeof(bits256) * tp->G.numactive * tp->G.numcards,tp->G.numactive*tp->G.numcards,-1);
                return(matches);
            }
        } else printf("i.%d != numactive.%d\n",matches,tp->G.numactive);
    } else printf("zero checkprod or encodestarted.%u\n",hand->encodestarted);
    return(-1);
}

void pangea_gothand(PANGEA_HANDARGS)
{
    int32_t i; uint64_t total = 0;
    printf("P%d: gothand from p%d\n",tp->priv.myind,senderind);
    tp->hand.othercardpubs[senderind] = *(bits256 *)data;
    if ( Debuglevel > 2 )
    {
        for (i=0; i<tp->G.N; i++)
        {
            total += tp->G.P[i].balance;
            PNACL_message("(p%d %.8f) ",i,dstr(tp->G.P[i].balance));
        }
        PNACL_message("balances %.8f [%.8f] | ",dstr(total),dstr(total + tp->G.hostrake + tp->G.pangearake));
        PNACL_message("player.%d pangea_gotdeck from P.%d otherpubs.%llx\n",tp->priv.myind,senderind,(long long)tp->hand.othercardpubs[senderind].txid);
    }
    pangea_checkstart(myinfo,N,turni,cardi,destplayer,senderind,tp);
}

void pangea_sentencoded(PANGEA_HANDARGS)
{
    tp->hand.sentencoded |= (1 << senderind);
    printf("P%d: got sentencoded from %d\n",tp->priv.myind,senderind);
}

void pangea_gotfinal(PANGEA_HANDARGS)
{
    tp->hand.gotfinal |= (1 << senderind);
    printf("P%d: gotfinal from %d\n",tp->priv.myind,senderind);
}

void pangea_encoded(PANGEA_HANDARGS)
{
    bits256 audit[CARDS777_MAXPLAYERS]; int32_t i,iter;
    struct hand_info *hand = &tp->hand;
    printf("pangea_encoded\n");
    if ( N <= 1 || data == 0 || datalen != (tp->G.numcards * N) * sizeof(bits256) )
    {
        PNACL_message("pangea_encode invalid datalen.%d vs %ld\n",datalen,(long)((tp->G.numcards * N) * sizeof(bits256)));
        return;
    }
    hand->encodestarted = (uint32_t)time(NULL);//pm->sig.timestamp;
    cards777_encode(tp->priv.outcards,tp->priv.xoverz,tp->priv.allshares,tp->priv.myshares,hand->sharenrs[tp->priv.myind],tp->G.M,(void *)data,tp->G.numcards,N);
    PNACL_message("player.%d ind.%d encodes into %p %llx -> %llx next.%d N %d\n",tp->priv.myind,tp->priv.myind,tp->priv.outcards,(long long)*(uint64_t *)data,(long long)tp->priv.outcards[0].txid,pangea_nextnode(tp),N);
    if ( tp->priv.myind > 0 )
    {
        if ( tp->priv.myind < tp->G.numactive-1 )
        {
            //PNACL_message("send encoded\n");
            pangea_sendcmd(myinfo,tp,"encoded",pangea_nextnode(tp),tp->priv.outcards[0].bytes,datalen,N*tp->G.numcards,-1);
            pangea_sendcmd(myinfo,tp,"sentencoded",-1,0,0,tp->priv.myind,pangea_nextnode(tp));
        }
        else
        {
            memcpy(hand->final,tp->priv.outcards,sizeof(bits256)*N*tp->G.numcards);
            pangea_sendcmd(myinfo,tp,"final",-1,tp->priv.outcards[0].bytes,datalen,N*tp->G.numcards,-1);
            for (iter=cardi=0; iter<2; iter++)
                for (i=0; i<N; i++,cardi++)
                    for (destplayer=0; destplayer<N; destplayer++)
                    {
                        pangea_rwaudit(0,audit,tp->priv.audits,cardi,destplayer,N);
                        audit[0] = hand->final[cardi*N + destplayer];
                        pangea_rwaudit(1,audit,tp->priv.audits,cardi,destplayer,N);
                    }
            PNACL_message("send preflop %ld\n",(long)((2 * N) * (N * N * sizeof(bits256))));
            pangea_preflop(myinfo,N,turni,cardi,destplayer,senderind,tp,tp->priv.audits[0].bytes,(2 * N) * (N * N * sizeof(bits256)));
        }
    }
}

void pangea_final(PANGEA_HANDARGS)
{
    if ( data == 0 || datalen != (tp->G.numcards * tp->G.numactive) * sizeof(bits256) )
    {
        PNACL_message("pangea_final invalid datalen.%d vs %ld\n",datalen,(long)((tp->G.numcards * tp->G.numactive) * sizeof(bits256)));
        return;
    }
    if ( Debuglevel > 2 )
        PNACL_message("player.%d final into %p\n",tp->priv.myind,tp->priv.outcards);
    memcpy(tp->hand.final,data,sizeof(bits256) * tp->G.numactive * tp->G.numcards);
    pangea_sendcmd(myinfo,tp,"gotfinal",-1,0,0,tp->priv.myind,tp->priv.myind);
}

int32_t pangea_queueprocess(struct supernet_info *myinfo,int32_t N,int32_t turni,int32_t cardi,int32_t destplayer,int32_t senderind,struct table_info *tp)
{
    int32_t iter,retval,flag = 0; double diff; struct pangea_queueitem *ptr;
    for (iter=0; iter<2; iter++)
    {
        while ( (ptr= queue_dequeue(&tp->stateQ[iter],0)) != 0 )
        {
            retval = 0;
            diff = tai_diff(ptr->last,tai_now());
            if ( diff > 10000 )
            {
                printf("its been over 10 seconds %.3f no state.%d yet\n",diff,ptr->waitevent);
            }
            switch ( ptr->waitevent )
            {
                case PANGEA_GOTDECKS:
                    if ( pangea_checkstart(myinfo,N,turni,cardi,destplayer,senderind,tp) > 0 )
                        return(1);
                    break;
                case PANGEA_GOTFINAL:
                    printf("sentencoded.%x\n",tp->hand.sentencoded);
                    break;
            }
            if ( retval != 0 )
            {
                flag++;
                free(ptr);
            }
            else
            {
                ptr->last = tai_now();
                queue_enqueue("stateQ",&tp->stateQ[iter ^ 1],&ptr->DL,0);
            }
        }
    }
    return(flag);
}

void pangea_preflop(PANGEA_HANDARGS)
{
    int32_t i,iter,maxlen; bits256 audit[CARDS777_MAXPLAYERS];
    maxlen = (int32_t)(2 * N * N * CARDS777_MAXCARDS * sizeof(bits256));
    if ( N <= 1 || data == 0 || datalen != (2 * N) * (N * N * sizeof(bits256)) )
    {
        PNACL_message("pangea_preflop invalid datalen.%d vs %ld\n",datalen,(long)(2 * N) * (N * N * sizeof(bits256)));
        return;
    }
    //PNACL_message("preflop player.%d\n",tp->priv.myind);
    memcpy(tp->priv.audits,data,datalen);
    if ( tp->priv.myind != pangea_slotA(tp) && tp->priv.myind != pangea_slotB(tp) )
    {
        //for (i=0; i<tp->G.numcards*N; i++)
        //    PNACL_message("%llx ",(long long)tp->priv.outcards[i].txid);
        PNACL_message("player.%d outcards\n",tp->priv.myind);
        for (cardi=0; cardi<N*2; cardi++)
            for (destplayer=0; destplayer<N; destplayer++)
            {
                pangea_rwaudit(0,audit,tp->priv.audits,cardi,destplayer,N);
                //if ( 1 && (card= cards777_checkcard(&cardpriv,cardi,tp->priv.myind,destplayer,hn->client->H.privkey,hand->cardpubs,tp->G.numcards,audit[0])) >= 0 )
                    //PNACL_message("ERROR: unexpected decode player.%d got card.[%d]\n",tp->priv.myind,card);
                audit[0] = cards777_decode(&audit[tp->priv.myind],tp->priv.xoverz,destplayer,audit[0],tp->priv.outcards,tp->G.numcards,N);
                pangea_rwaudit(1,audit,tp->priv.audits,cardi,destplayer,N);
            }
            //PNACL_message("issue preflop\n");
            pangea_sendcmd(myinfo,tp,"preflop",pangea_prevnode(tp),tp->priv.audits[0].bytes,datalen,N * 2 * N,-1);
    }
    else
    {
        PNACL_message("P%d sendout cards\n",tp->priv.myind);
        for (iter=cardi=0; iter<2; iter++)
            for (i=0; i<N; i++,cardi++)
            {
                destplayer = (tp->hand.button + i) % N;
                pangea_rwaudit(0,audit,tp->priv.audits,cardi,destplayer,N);
                //PNACL_message("audit[0] %llx -> ",(long long)audit[0].txid);
                audit[0] = cards777_decode(&audit[tp->priv.myind],tp->priv.xoverz,destplayer,audit[0],tp->priv.outcards,tp->G.numcards,N);
                pangea_rwaudit(1,audit,tp->priv.audits,cardi,destplayer,N);
                //PNACL_message("[%llx + %llx] ",*(long long *)&audit[0],(long long)&audit[tp->priv.myind]);
                if ( destplayer == tp->priv.myind )
                    pangea_card(myinfo,N,turni,cardi,destplayer,senderind,tp,audit[0].bytes,sizeof(bits256)*N);
                else pangea_sendcmd(myinfo,tp,"card",destplayer,audit[0].bytes,sizeof(bits256)*N,cardi,-1);
            }
    }
}

void pangea_card(PANGEA_HANDARGS)
{
    struct hand_info *hand; int32_t card,selector,validcard = -1;
    bits256 cardpriv,audit[CARDS777_MAXPLAYERS]; char cardAstr[8],cardBstr[8]; struct player_info *destp;
    hand = &tp->hand;
    destp = tp->active[destplayer];
    if ( N <= 1 || data == 0 || datalen != sizeof(bits256)*N || destp == 0 )
    {
        PNACL_message("pangea_card invalid datalen.%d vs %ld\n",datalen,(long)sizeof(bits256)*N);
        return;
    }
    pangea_rwaudit(1,(void *)data,tp->priv.audits,cardi,destplayer,N);
    pangea_rwaudit(0,audit,tp->priv.audits,cardi,destplayer,N);
    PNACL_message("pangea_card.%d destplayer.%d [%llx]\n",cardi,destplayer,(long long)audit[0].txid);
    if ( (card= cards777_checkcard(&cardpriv,cardi,tp->priv.myind,destplayer,myinfo->persistent_priv,hand->cardpubs,tp->G.numcards,audit[0])) >= 0 )
    {
        destplayer = tp->priv.myind;
        //if ( Debuglevel > 2 )
            PNACL_message("player.%d got card.[%d]\n",tp->priv.myind,card);
        selector = (cardi / N);
        tp->priv.holecards[selector] = cardpriv;
        tp->priv.cardis[selector] = cardi;
        destp->hand[5 + selector] = tp->priv.hole[selector] = cardpriv.bytes[1];
        validcard = 1;
        cardAstr[0] = cardBstr[0] = 0;
        if ( tp->priv.hole[0] != 0xff )
            cardstr(cardAstr,tp->priv.hole[0]);
        if ( tp->priv.hole[1] != 0xff )
            cardstr(cardBstr,tp->priv.hole[1]);
        PNACL_message(">>>>>>>>>> dest.%d holecards[%02d] cardi.%d / N %d (%02d %02d) -> (%s %s)\n",destplayer,tp->priv.hole[cardi / N],cardi,N,tp->priv.hole[0],tp->priv.hole[1],cardAstr,cardBstr);
        if ( cards777_validate(cardpriv,hand->final[cardi*N + destplayer],hand->cardpubs,tp->G.numcards,audit,N,tp->priv.mypub) < 0 )
            PNACL_message("player.%d decoded cardi.%d card.[%02d] but it doesnt validate\n",tp->priv.myind,cardi,card);
    } else PNACL_message("ERROR player.%d got no card %llx\n",tp->priv.myind,*(long long *)data);
    if ( cardi < N*2 )
        pangea_sendcmd(myinfo,tp,"facedown",-1,(void *)&cardi,sizeof(cardi),cardi,validcard);
    else pangea_sendcmd(myinfo,tp,"faceup",-1,cardpriv.bytes,sizeof(cardpriv),cardi,0xff);
}

int64_t pangea_snapshot(struct table_info *tp,int64_t *snapshot)
{
    struct player_info *p; int64_t betsize; int32_t i,N = tp->G.numactive;
    memset(snapshot,0,N * sizeof(int64_t));
    for (betsize=i=0; i<N; i++)
    {
        if ( (p= tp->active[i]) != 0 )
        {
            if ( p->bets > betsize )
                betsize = p->bets;
            snapshot[i] = p->bets;
        } else snapshot[i] = 0;
    }
    snapshot[N] = betsize;
    return(betsize);
}

void pangea_startbets(struct supernet_info *myinfo,struct table_info *tp,int32_t cardi)
{
    uint32_t now,i,N = tp->G.numactive; struct player_info *p; int64_t snapshot[CARDS777_MAXPLAYERS+1];
    struct hand_info *hand = &tp->hand;
    if ( PANGEA_PAUSE > 0 )
        sleep(PANGEA_PAUSE);
    if ( hand->betstarted == 0 )
        hand->betstarted = 1;
    else hand->betstarted++;
    hand->numactions = 0;
    hand->cardi = cardi;
    now = (uint32_t)time(NULL);
    for (i=0; i<CARDS777_MAXPLAYERS; i++)
    {
        p = &tp->G.P[i];
        p->action = 0;
        p->turni = 0xff;
        if ( cardi > N*2 )
            p->snapshot = p->bets;
    }
    hand->undergun = ((hand->button + 3) % N);
    if ( cardi < N*2 )
        pangea_checkantes(myinfo,tp);
    hand->betsizesnapshot = hand->betsize = pangea_snapshot(tp,snapshot);
    printf("STARTBETS.%d cardi.%d numactions.%d undergun.%d betsize %.8f N %d\n",hand->betstarted,cardi,hand->numactions,hand->undergun,dstr(hand->betsize),N);
    pangea_sendcmd(myinfo,tp,"turn",-1,(void *)snapshot,sizeof(*snapshot)*(N+1),cardi,hand->undergun);
}

void pangea_facedown(PANGEA_HANDARGS)
{
    int32_t i,validcard,n = 0; uint64_t havemask; struct player_info *p;
    p = tp->active[senderind];
    if ( p == 0 || N <= 1 || data == 0 || datalen != sizeof(int32_t) )
    {
        PNACL_message("pangea_facedown invalid datalen.%d vs %ld\n",datalen,(long)sizeof(bits256));
        return;
    }
    validcard = turni;
    if ( validcard > 0 )
        p->havemask |= (1LL << cardi);
    //if ( Debuglevel > 2 )
        PNACL_message(" | player.%d sees that destplayer.%d got cardi.%d valid.%d | %llx | n.%d\n",tp->priv.myind,senderind,cardi,validcard,(long long)p->havemask,n);
    for (i=0; i<N; i++)
    {
        if ( (p= tp->active[i]) != 0 )
        {
            havemask = p->havemask;
            if ( Debuglevel > 2 )
                PNACL_message("%llx ",(long long)havemask);
            if ( bitweight(havemask) == 2 )
                n++;
        }
    }
    if ( tp->priv.myind == pangea_slotA(tp) && n == N )
        pangea_startbets(myinfo,tp,N*2);
}

void pangea_faceup(PANGEA_HANDARGS)
{
    int32_t validcard,i; struct hand_info *hand; uint16_t tmp; struct player_info *p,*destp;
    hand = &tp->hand;
    destp = tp->active[senderind];
    if ( destp == 0 || N <= 1 || data == 0 || datalen != sizeof(bits256) )
    {
        PNACL_message("pangea_faceup invalid datalen.%d vs %ld\n",datalen,(long)((tp->G.numcards + 1) * sizeof(bits256)));
        return;
    }
    validcard = (turni >= 0);
    if ( Debuglevel > 2 || tp->priv.myind == pangea_slotA(tp) )
    {
        PNACL_message("from.%d -> player.%d COMMUNITY.[%d] cardi.%d valid.%d\n",senderind,tp->priv.myind,data[1],cardi,validcard);
    }
    PNACL_message("got FACEUP cardi.%d validcard.%d [%d]\n",cardi,validcard,data[1]);
    if ( validcard > 0 )
    {
        tmp = (cardi << 8);
        tmp |= (turni & 0xff);
        pangea_summaryadd(myinfo,tp,CARDS777_FACEUP,&tmp,sizeof(tmp),data,sizeof(bits256));
        if ( cardi >= N*2 && cardi < N*2+5 )
        {
            hand->community[cardi - N*2] = data[1];
            for (i=0; i<N; i++)
            {
                if ( (p= tp->active[i]) != 0 )
                    p->hand[cardi - N*2] = data[1];
            }
            memcpy(hand->community256[cardi - N*2].bytes,data,sizeof(bits256));
            PNACL_message("set community[%d] <- %d\n",cardi - N*2,data[1]);
            if ( senderind == tp->priv.myind )
                pangea_rank(myinfo,tp,senderind);
            if ( tp->priv.myind == pangea_slotA(tp) && cardi >= N*2+2 && cardi < N*2+5 )
                pangea_startbets(myinfo,tp,cardi+1);
            //else PNACL_message("dont start bets %d\n",cardi+1);
        }
        else
        {
            PNACL_message("valid.%d cardi.%d vs N.%d\n",validcard,cardi,N);
            if ( cardi < N*2 )
            {
                memcpy(hand->cards[senderind][cardi/N].bytes,data,sizeof(bits256));
                destp->hand[5 + cardi/N] = data[1];
                pangea_rank(myinfo,tp,senderind);
            }
        }
    }
}

void pangea_turn(PANGEA_HANDARGS)
{
    struct player_info *destp; int64_t snapshot[CARDS777_MAXPLAYERS+1]; struct hand_info *hand = &tp->hand;
    destp = tp->active[senderind];
    if ( destp == 0 || N <= 1 )
    {
        PNACL_message("pangea_turn illegal arg\n");
        return;
    }
    //if ( Debuglevel > 2 )
        printf("P%d: got turn.%d from %d | cardi.%d summary[%d] crc.%u\n",tp->priv.myind,turni,senderind,cardi,tp->summarysize,calc_crc32(0,tp->summary,tp->summarysize));
    destp->turni = turni;
    if ( senderind == 0 )
    {
        hand->cardi = cardi;
        hand->betstarted = 1;
        hand->undergun = turni;
        if ( tp->priv.myind != pangea_slotA(tp) )
        {
            pangea_checkantes(myinfo,tp);
            hand->betsizesnapshot = pangea_snapshot(tp,snapshot);
            //printf("player.%d sends confirmturn.%d\n",tp->priv.myind,turni);
            pangea_sendcmd(myinfo,tp,"confirm",-1,(void *)snapshot,sizeof(uint64_t)*(N+1),cardi,turni);
        }
    }
}

void pangea_confirm(PANGEA_HANDARGS)
{
    uint32_t starttime; int32_t i; uint64_t betsize=0,amount=0;
    int64_t snapshot[CARDS777_MAXPLAYERS+1]; struct player_info *p; struct hand_info *hand;
    hand = &tp->hand; p = tp->active[senderind];
    if ( p == 0 || N <= 1 || data == 0 )
    {
        printf("pangea_turn: null data\n");
        return;
    }
    printf("P%d: got confirmturn.%d cardi.%d sender.%d\n",tp->priv.myind,turni,cardi,senderind);
    //if ( datalen == sizeof(betsize) )
    //    memcpy(&betsize,data,sizeof(betsize));
    starttime = hand->starttime;
    if ( senderind == 0 && tp->priv.myind != pangea_slotA(tp) )
    {
        hand->undergun = turni;
        hand->cardi = cardi;
        betsize = pangea_snapshot(tp,snapshot);
        if ( betsize != hand->betsizesnapshot )
            printf("T%d ERROR BETSIZE MISMATCH: %.8f vs %.8f\n",tp->priv.myind,dstr(betsize),dstr(hand->betsizesnapshot));
        hand->betsize = betsize;
    }
    p->turni = turni;
    for (i=0; i<N; i++)
    {
        if ( (p= tp->active[i]) != 0 && p->turni != turni )
            break;
    }
    //printf("sp.%p vs turni.%d cardi.%d hand.cardi %d\n",sp,turni,cardi,hand->cardi);
    if ( tp->priv.myind == pangea_slotA(tp) && i == N )
    {
        betsize = pangea_snapshot(tp,snapshot);
        hand->betsize = hand->betsizesnapshot = betsize;
        //if ( Debuglevel > 2 )
        printf("player.%d sends confirmturn.%d cardi.%d betsize %.0f\n",tp->priv.myind,hand->undergun,hand->cardi,dstr(betsize));
        if ( senderind != 0 )
            pangea_sendcmd(myinfo,tp,"confirm",-1,(void *)snapshot,sizeof(*snapshot)*(N+1),hand->cardi,hand->undergun);
    }
    if ( senderind == 0 && (turni= hand->undergun) == tp->priv.myind && (p= tp->active[senderind]) != 0 )
    {
        if ( hand->betsize != betsize )
            printf("P%d: pangea_turn warning hand.betsize %.8f != betsize %.8f\n",tp->priv.myind,dstr(hand->betsize),dstr(betsize));
        //if ( sp->isbot[tp->priv.myind] != 0 )
        //    pangea_bot(myinfo,tp,turni,cardi,betsize);
        //else
            if ( p->betstatus == CARDS777_FOLD || p->betstatus == CARDS777_ALLIN )
            pangea_sendcmd(myinfo,tp,"action",-1,(void *)&amount,sizeof(amount),cardi,0);
        else if ( tp->priv.autofold != 0 )
            pangea_sendcmd(myinfo,tp,"action",-1,(void *)&amount,sizeof(amount),cardi,0);
        else
        {
            hand->userinput_starttime = (uint32_t)time(NULL);
            hand->cardi = cardi;
            hand->betsize = betsize;
            fprintf(stderr,"Waiting for user input cardi.%d: ",cardi);
        }
        if ( tp->priv.myind == pangea_slotA(tp) )
        {
            char *str = jprint(pangea_tablestatus(myinfo,tp),1);
            printf("%s\n",str);
            free(str);
        }
        //pangea_statusprint(dp,priv,tp->priv.myind);
    }
}

void pangea_finish(struct supernet_info *myinfo,struct table_info *tp)
{
    int64_t tsnap,sidepots[CARDS777_MAXPLAYERS][CARDS777_MAXPLAYERS];//,list[CARDS777_MAXPLAYERS];
    uint64_t pangearake,rake; int64_t balances[CARDS777_MAXPLAYERS],bets[CARDS777_MAXPLAYERS+1];
    uint32_t changes; uint16_t busted,rebuy; int32_t j,n,r,N,norake = 0; struct hand_info *hand;
    N = tp->G.numactive, hand = &tp->hand;
    if ( hand->finished == 0 )
    {
        memset(sidepots,0,sizeof(sidepots));
        pangea_snapshot(tp,bets);
        n = pangea_sidepots(myinfo,tp,1,sidepots,bets);
        if ( hand->community[0] == 0xff )
            norake = 1;
        for (pangearake=rake=j=0; j<n; j++)
            rake += pangea_splitpot(myinfo,tp,&pangearake,sidepots[j],norake == 0 ? tp->G.rakemillis : 0);
        hand->finished = (uint32_t)time(NULL);
        tp->hostrake += rake;
        tp->pangearake += pangearake;
        tp->G.hostrake = rake;
        tp->G.pangearake = pangearake;
        for (j=busted=rebuy=r=0; j<N; j++)
        {
            if ( tp->active[j] != 0 )
            {
                balances[j] = tp->active[j]->balance;
                tsnap = tp->snapshot[tp->active[j]->ind];
                //balances[j] += hand->won[j];
                //sp->balances[pangea_slot(sp,j)] = balances[j];
                if ( tsnap > 0 && balances[j] <= 0 )
                {
                    busted |= (1 << j);
                    //list[r++] = sp->active[j];
                }
                else if ( tsnap <= 0 && balances[j] > 0 )
                    rebuy |= (1 << j);
            }
        }
        changes = (((uint32_t)rebuy<<20) | ((uint32_t)busted<<4) | (tp->G.N&0xf));
        pangea_summaryadd(myinfo,tp,CARDS777_CHANGES,(void *)&changes,sizeof(changes),(void *)balances,sizeof(uint64_t)*tp->G.N);
        pangea_summaryadd(myinfo,tp,CARDS777_RAKES,(void *)&rake,sizeof(rake),(void *)&pangearake,sizeof(pangearake));
        if ( tp->priv.myind == pangea_slotA(tp) )
        {
            char *sumstr,*statstr;
            statstr = jprint(pangea_tablestatus(myinfo,tp),1);
            sumstr = pangea_dispsummary(myinfo,tp,1,tp->summary,tp->summarysize,tp->G.tablehash,tp->numhands-1,tp->G.N);
            printf("%s\n\n%s",statstr,sumstr);
            free(statstr), free(sumstr);
            pangea_sendcmd(myinfo,tp,"summary",-1,tp->summary,tp->summarysize,0,0);
        }
        /*if ( 0 && busted != 0 )
        {
            for (j=0; j<r; j++)
            {
                if ( list[j] != sp->active[0] )
                {
                    pangea_inactivate(dp,sp,list[j]);
                    printf("T%d: INACTIVATE.[%d] %llu\n",sp->myslot,j,(long long)list[j]);
                }
            }
        }*/
    }
}

int32_t pangea_lastman(struct supernet_info *myinfo,struct table_info *tp)
{
    int32_t activej = -1; struct hand_info *hand = &tp->hand;
    if ( hand->betstarted != 0 && pangea_actives(&activej,tp) <= 1 )
    {
        if ( hand->finished != 0 )
        {
            printf("DUPLICATE LASTMAN!\n");
            return(1);
        }
        if ( 0 && tp->priv.myind == activej && tp->priv.automuck == 0 )
        {
            pangea_sendcmd(myinfo,tp,"faceup",-1,tp->priv.holecards[0].bytes,sizeof(tp->priv.holecards[0]),tp->priv.cardis[0],tp->priv.cardis[0] != 0xff);
            pangea_sendcmd(myinfo,tp,"faceup",-1,tp->priv.holecards[1].bytes,sizeof(tp->priv.holecards[1]),tp->priv.cardis[1],tp->priv.cardis[1] != 0xff);
        }
        pangea_finish(myinfo,tp);
        return(1);
    }
    return(0);
}

void pangea_action(PANGEA_HANDARGS)
{
    uint32_t now; struct player_info *p; int64_t x,snapshot[CARDS777_MAXPLAYERS + 1]; int32_t action,i,j;
    bits256 audit[CARDS777_MAXPLAYERS]; struct hand_info *hand; uint8_t tmp; uint64_t amount = 0;
    hand = &tp->hand;
    p = tp->active[senderind];
    memcpy(&amount,data,sizeof(amount));
    if ( N <= 1 || p == 0 || cardi < 2*N )
    {
        printf("pangea_action: illegal cardi.%d\n",cardi);
        return;
    }
    action = cardi;
    if ( senderind != hand->undergun )
    {
        printf("T%d: out of turn action.%d by player.%d (undergun.%d) cardi.%d amount %.8f\n",tp->priv.myind,action,senderind,hand->undergun,cardi,dstr(amount));
        return;
    }
    tmp = senderind;
    pangea_bet(myinfo,tp,tp->active[senderind],amount,CARDS777_CHECK);
    p->action = action;
    hand->undergun = (hand->undergun + 1) % N;
    hand->numactions++;
    //if ( Debuglevel > 2 )//|| tp->priv.myind == 0 )
        printf("player.%d: got action.%d cardi.%d senderind.%d -> undergun.%d numactions.%d\n",tp->priv.myind,action,cardi,senderind,hand->undergun,hand->numactions);
    if ( pangea_lastman(myinfo,tp) > 0 )
        return;
    if ( tp->priv.myind == pangea_slotA(tp) )
    {
        now = (uint32_t)time(NULL);
        for (i=j=0; i<N; i++)
        {
            j = (hand->undergun + i) % N;
            if ( (p= tp->active[j]) != 0 )
            {
                if ( p->betstatus == CARDS777_FOLD || p->betstatus == CARDS777_ALLIN )
                {
                    p->action = p->betstatus;
                    //printf("skip player.%d\n",j);
                    hand->numactions++;
                } else break;
            }
        }
        hand->undergun = j;
        if ( hand->numactions < N )
        {
            //printf("T%d: senderind.%d i.%d j.%d -> undergun.%d numactions.%d\n",tp->priv.myind,senderind,i,j,hand->undergun,hand->numactions);
            //if ( senderind != 0 )
            memset(snapshot,0,sizeof(*snapshot)*(N+1));
            for (x=i=0; i<N; i++)
                if ( (p= tp->active[i]) != 0 )
                {
                    if ( p->snapshot > x )
                        x = p->snapshot;
                    snapshot[i] = p->snapshot;
                }
            snapshot[N] = x;
            pangea_sendcmd(myinfo,tp,"turn",-1,(void *)snapshot,sizeof(*snapshot)*(N+1),hand->cardi,hand->undergun);
        }
        else
        {
            for (i=0; i<5; i++)
            {
                if ( hand->community[i] == 0xff )
                    break;
                printf("%02x ",hand->community[i]);
            }
            printf("COMMUNITY\n");
            if ( i == 0 )
            {
                if ( hand->cardi != N * 2 )
                    printf("cardi mismatch %d != %d\n",hand->cardi,N * 2);
                cardi = hand->cardi;
                printf("decode flop\n");
                for (i=0; i<3; i++,cardi++)
                {
                    memset(audit,0,sizeof(audit));
                    audit[0] = hand->final[cardi*N + destplayer];
                    pangea_sendcmd(myinfo,tp,"decoded",-1,audit[0].bytes,sizeof(bits256)*N,cardi,N-1);
                }
            }
            else if ( i == 3 )
            {
                if ( hand->cardi != N * 2+3 )
                    printf("cardi mismatch %d != %d\n",hand->cardi,N * 2 + 3);
                cardi = hand->cardi;
                printf("decode turn\n");
                memset(audit,0,sizeof(audit));
                audit[0] = hand->final[cardi*N + destplayer];
                pangea_sendcmd(myinfo,tp,"decoded",-1,audit[0].bytes,sizeof(bits256)*N,cardi,N-1);
                //pangea_sendcmd(myinfo,tp,"decoded",-1,hand->final[cardi*N + destplayer].bytes,sizeof(hand->final[cardi*N + destplayer]),cardi,N-1);
            }
            else if ( i == 4 )
            {
                printf("decode river\n");
                if ( hand->cardi != N * 2+4 )
                    printf("cardi mismatch %d != %d\n",hand->cardi,N * 2+4);
                cardi = hand->cardi;
                memset(audit,0,sizeof(audit));
                audit[0] = hand->final[cardi*N + destplayer];
                pangea_sendcmd(myinfo,tp,"decoded",-1,audit[0].bytes,sizeof(bits256)*N,cardi,N-1);
                //pangea_sendcmd(myinfo,tp,"decoded",-1,hand->final[cardi*N + destplayer].bytes,sizeof(hand->final[cardi*N + destplayer]),cardi,N-1);
            }
            else
            {
                cardi = N * 2 + 5;
                if ( hand->cardi != N * 2+5 )
                    printf("cardi mismatch %d != %d\n",hand->cardi,N * 2+5);
                for (i=0; i<N; i++)
                {
                    j = (hand->lastbettor + i) % N;
                    if ( tp->active[j] != 0 && tp->active[j]->betstatus != CARDS777_FOLD )
                        break;
                }
                hand->undergun = j;
                printf("sent showdown request for undergun.%d\n",j);
                pangea_sendcmd(myinfo,tp,"showdown",-1,(void *)&hand->betsize,sizeof(hand->betsize),cardi,hand->undergun);
            }
        }
    }
    if ( Debuglevel > 2 )// || tp->priv.myind == 0 )
    {
        char *str = jprint(pangea_tablestatus(myinfo,tp),1);
        printf("player.%d got pangea_action.%d for player.%d action.%d amount %.8f | numactions.%d\n%s\n",tp->priv.myind,cardi,senderind,action,dstr(amount),hand->numactions,str);
        free(str);
    }
}

void pangea_decoded(PANGEA_HANDARGS)
{
    int32_t card; bits256 cardpriv,audit[CARDS777_MAXPLAYERS]; struct hand_info *hand;
    hand = &tp->hand;
    if ( N <= 1 || data == 0 || datalen != sizeof(bits256)*N )
    {
        PNACL_message("pangea_decoded invalid datalen.%d vs %ld\n",datalen,(long)sizeof(bits256));
        return;
    }
    if ( cardi < N*2 || cardi >= N*2 + 5 )
    {
        PNACL_message("pangea_decoded invalid cardi.%d\n",cardi);
        return;
    }
    destplayer = 0;
    pangea_rwaudit(1,(void *)data,tp->priv.audits,cardi,destplayer,N);
    pangea_rwaudit(0,audit,tp->priv.audits,cardi,destplayer,N);
    if ( turni == tp->priv.myind )
    {
        if ( tp->priv.myind != pangea_slotA(tp) )
        {
            audit[0] = cards777_decode(&audit[tp->priv.myind],tp->priv.xoverz,destplayer,audit[0],tp->priv.outcards,tp->G.numcards,N);
            pangea_rwaudit(1,audit,tp->priv.audits,cardi,destplayer,N);
            pangea_sendcmd(myinfo,tp,"decoded",-1,audit[0].bytes,sizeof(bits256)*N,cardi,pangea_prevnode(tp));
        }
        else
        {
            if ( (card= cards777_checkcard(&cardpriv,cardi,tp->priv.myind,tp->priv.myind,tp->priv.mypriv,hand->cardpubs,tp->G.numcards,audit[0])) >= 0 )
            {
                if ( cards777_validate(cardpriv,hand->final[cardi*N + destplayer],hand->cardpubs,tp->G.numcards,audit,N,tp->priv.mypub) < 0 )
                    PNACL_message("player.%d decoded cardi.%d card.[%d] but it doesnt validate\n",tp->priv.myind,cardi,card);
                pangea_sendcmd(myinfo,tp,"faceup",-1,cardpriv.bytes,sizeof(cardpriv),cardi,cardpriv.txid!=0?0xff:-1);
                //PNACL_message("-> FACEUP.(%s)\n",hex);
            }
        }
    }
}

void pangea_showdown(PANGEA_HANDARGS)
{
    struct player_info *p; int32_t i,myind; struct hand_info *hand; uint64_t amount=0;
    hand = &tp->hand;
    myind = tp->priv.myind;
    if ( (p= tp->active[myind]) == 0 )
    {
        printf("error nullp myind.%d\n",myind);
        return;
    }
    //if ( Debuglevel > 2 )
        printf("P%d: showdown from sender.%d\n",myind,senderind);
    if ( p->betstatus != CARDS777_FOLD && ((tp->priv.automuck == 0 && p->action != CARDS777_SENTCARDS) || (turni == myind && hand->lastbettor == myind)) )
    {
        if ( tp->priv.automuck != 0 && pangea_myrank(myinfo,tp,p) < 0 )
            pangea_sendcmd(myinfo,tp,"action",-1,(void *)&amount,sizeof(amount),cardi,CARDS777_FOLD);
        else
        {
            pangea_sendcmd(myinfo,tp,"faceup",-1,tp->priv.holecards[0].bytes,sizeof(tp->priv.holecards[0]),tp->priv.cardis[0],myind);
            pangea_sendcmd(myinfo,tp,"faceup",-1,tp->priv.holecards[1].bytes,sizeof(tp->priv.holecards[1]),tp->priv.cardis[1],myind);
            p->action = CARDS777_SENTCARDS;
        }
    }
    if ( pangea_lastman(myinfo,tp) > 0 )
        return;
    if ( myind == pangea_slotA(tp) && senderind != 0 )
    {
        for (i=0; i<N; i++)
        {
            hand->undergun = (hand->undergun + 1) % N;
            if ( hand->undergun == hand->lastbettor )
            {
                printf("all players queried with showdown handmask.%x finished.%u\n",hand->handmask,hand->finished);
                return;
            }
            if ( (p= tp->active[hand->undergun]) != 0 && p->betstatus != CARDS777_FOLD )
                break;
        }
        printf("senderind.%d host sends showdown for undergun.%d\n",senderind,hand->undergun);
        pangea_sendcmd(myinfo,tp,"showdown",-1,(void *)&hand->betsize,sizeof(hand->betsize),cardi,hand->undergun);
    }
}

int32_t pangea_anotherhand(struct supernet_info *myinfo,struct table_info *tp,int32_t sleepflag)
{
    int32_t i,n,activej = -1; int64_t balance,onlybalance = 0,total = 0;
    for (i=n=0; i<tp->G.N; i++)
    {
        PNACL_message("(p%d %.8f) ",i,dstr(tp->G.P[i].balance));
        if ( (balance= tp->G.P[i].balance) != 0 )
        {
            total += balance;
            onlybalance = balance;
            if ( activej < 0 )
                activej = i;
            n++;
        }
    }
    PNACL_message("balance %.8f [%.8f]\n",dstr(total),dstr(total + tp->G.hostrake + tp->G.pangearake));
    if ( n == 1 )
    {
        PNACL_message("Only player.%d left with %.8f | get sigs and cashout after numhands.%d\n",activej,dstr(onlybalance),tp->numhands);
        sleep(60);
        return(1);
    }
    else
    {
        if ( sleepflag != 0 )
            sleep(sleepflag);
        //hand->betstarted = 0;
        pangea_newdeck(myinfo,tp);
        if ( sleepflag != 0 )
            sleep(sleepflag);
    }
    return(n);
}
