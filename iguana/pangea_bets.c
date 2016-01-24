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

void pangea_fold(struct supernet_info *myinfo,struct table_info *tp,struct player_info *player)
{
    uint8_t tmp;
    //printf("player.%d folded\n",player); //getchar();
    tp->hand.handmask |= (1 << player->ind);
    player->betstatus = CARDS777_FOLD;
    player->action = CARDS777_FOLD;
    tmp = player->ind;
    pangea_summaryadd(myinfo,tp,CARDS777_FOLD,&tmp,sizeof(tmp),(void *)&player->bets,sizeof(player->bets));
}

int32_t pangea_bet(struct supernet_info *myinfo,struct table_info *tp,struct player_info *player,int64_t bet,int32_t action)
{
    uint64_t sum; uint8_t tmp; struct hand_info *hand = &tp->hand;
    if ( Debuglevel > 2 )
        printf("PANGEA_BET[%d] <- %.8f\n",player->ind,dstr(bet));
    if ( player->betstatus == CARDS777_ALLIN )
        return(CARDS777_ALLIN);
    else if ( player->betstatus == CARDS777_FOLD )
        return(CARDS777_FOLD);
    if ( bet > 0 && bet >= player->balance )
    {
        bet = player->balance;
        player->betstatus = action = CARDS777_ALLIN;
    }
    else
    {
        if ( bet > hand->betsize && bet > hand->lastraise && bet < (hand->lastraise<<1) )
        {
            printf("pangea_bet %.8f not double %.8f, clip to lastraise\n",dstr(bet),dstr(hand->lastraise));
            bet = hand->lastraise;
            action = CARDS777_RAISE;
        }
    }
    sum = player->bets;
    if ( sum+bet < hand->betsize && action != CARDS777_ALLIN )
    {
        pangea_fold(myinfo,tp,player);
        action = CARDS777_FOLD;
        if ( Debuglevel > 2 )
            printf("player.%d betsize %.8f < hand.betsize %.8f FOLD\n",player->ind,dstr(bet),dstr(hand->betsize));
        return(action);
    }
    else if ( bet >= 2*hand->lastraise )
    {
        hand->lastraise = bet;
        hand->numactions = 0;
        if ( action == CARDS777_CHECK )
        {
            action = CARDS777_FULLRAISE; // allows all players to check/bet again
            if ( Debuglevel > 2 )
                printf("FULLRAISE by player.%d\n",player->ind);
        }
    }
    sum += bet;
    if ( sum > hand->betsize )
    {
        hand->numactions = 0;
        hand->betsize = sum, hand->lastbettor = player->ind;
        if ( sum > hand->lastraise && action == CARDS777_ALLIN )
            hand->lastraise = sum;
        else if ( action == CARDS777_CHECK )
            action = CARDS777_BET;
    }
    if ( bet > 0 && action == CARDS777_CHECK )
        action = CARDS777_CALL;
    tmp = player->ind;
    pangea_summaryadd(myinfo,tp,action,&tmp,sizeof(tmp),(void *)&bet,sizeof(bet));
    player->balance -= bet, player->bets += bet;
    if ( Debuglevel > 2 )
        printf("player.%d: player.%d BET %f -> balances %f bets %f\n",tp->myind,player->ind,dstr(bet),dstr(player->balance),dstr(player->bets));
    return(action);
}

void pangea_antes(struct supernet_info *myinfo,struct table_info *tp)
{
    int32_t i,n,N; struct player_info *p; uint64_t threshold; int32_t handid;
    N = tp->numactive;
    for (i=0; i<tp->G.N; i++)
    {
        tp->G.P[i].ind = i;
        if ( (tp->snapshot[i]= tp->G.P[i].balance) <= 0 )
            pangea_fold(myinfo,tp,&tp->G.P[i]);
    }
    handid = tp->numhands - 1;
    pangea_summaryadd(myinfo,tp,CARDS777_SNAPSHOT,(void *)&handid,sizeof(handid),(void *)tp->snapshot,sizeof(uint64_t)*CARDS777_MAXPLAYERS);
    if ( tp->G.ante != 0 )
    {
        for (i=0; i<N; i++)
        {
            if ( (p= tp->active[i]) != 0 )
            {
                if ( p->balance < tp->G.ante )
                    pangea_fold(myinfo,tp,p);
                else pangea_bet(myinfo,tp,p,tp->G.ante,CARDS777_ANTE);
            } else printf("unexpected null player ptr\n");
        }
    }
    for (i=n=0; i<N; i++)
    {
        if ( i == 0 )
            threshold = (tp->G.bigblind >> 1) - 1;
        else if ( i == 1 )
            threshold = tp->G.bigblind - 1;
        else threshold = 0;
        if ( (p= tp->active[i]) != 0 &&  p->balance < threshold )
            pangea_fold(myinfo,tp,p);
        else n++;
    }
    if ( n < 2 )
        printf("pangea_antes not enough players n.%d\n",n);
    else
    {
        pangea_bet(myinfo,tp,tp->active[0],(tp->G.bigblind>>1),CARDS777_SMALLBLIND);
        pangea_bet(myinfo,tp,tp->active[1],tp->G.bigblind,CARDS777_BIGBLIND);
        
    }
}

void pangea_checkantes(struct supernet_info *myinfo,struct table_info *tp)
{
    int64_t bets[CARDS777_MAXPLAYERS+1]; int32_t i,N = tp->numactive; struct hand_info *hand = &tp->hand;
    pangea_snapshot(tp,bets);
    for (i=0; i<N; i++)
    {
        //printf("%.8f ",dstr(dp->balances[i]));
        if ( bets[i] != 0 )
            break;
    }
    if ( i == N && hand->checkprod.txid != 0 )
    {
        for (i=0; i<N; i++)
            if ( bets[i] != 0 )
                break;
        if ( i == N )
        {
            //printf("i.%d vs N.%d call antes\n",i,N);
            pangea_antes(myinfo,tp);
        } else printf("bets i.%d\n",i);
    }
}

uint64_t pangea_winnings(int32_t player,uint64_t *pangearakep,uint64_t *hostrakep,uint64_t total,int32_t numwinners,int32_t rakemillis,uint64_t maxrake)
{
    uint64_t split,pangearake,rake;
    if ( numwinners > 0 )
    {
        split = (total * (1000 - rakemillis)) / (1000 * numwinners);
        pangearake = (total - split*numwinners);
        if ( pangearake > maxrake )
        {
            pangearake = maxrake;
            split = (total - pangearake) / numwinners;
            pangearake = (total - split*numwinners);
        }
    }
    else
    {
        split = 0;
        pangearake = total;
    }
    if ( rakemillis > PANGEA_MINRAKE_MILLIS )
    {
        rake = (pangearake * (rakemillis - PANGEA_MINRAKE_MILLIS)) / rakemillis;
        pangearake -= rake;
    }
    else rake = 0;
    *hostrakep = rake;
    *pangearakep = pangearake;
    printf("\nP%d: rakemillis.%d total %.8f split %.8f rake %.8f pangearake %.8f\n",player,rakemillis,dstr(total),dstr(split),dstr(rake),dstr(pangearake));
    return(split);
}

int32_t pangea_sidepots(struct supernet_info *myinfo,struct table_info *tp,int32_t dispflag,int64_t sidepots[CARDS777_MAXPLAYERS][CARDS777_MAXPLAYERS],int64_t *bets)
{
    int32_t i,j,nonz,N,n = 0; uint64_t bet,minbet = 0;
    memset(sidepots,0,sizeof(uint64_t)*CARDS777_MAXPLAYERS*CARDS777_MAXPLAYERS);
    N = tp->numactive;
    for (j=0; j<N; j++)
        sidepots[0][j] = bets[j];
    nonz = 1;
    while ( nonz > 0 )
    {
        for (minbet=j=0; j<N; j++)
        {
            if ( (bet= sidepots[n][j]) != 0 )
            {
                if ( tp->active[j] != 0 && tp->active[j]->betstatus != CARDS777_FOLD )
                {
                    if ( minbet == 0 || bet < minbet )
                        minbet = bet;
                }
            }
        }
        for (j=nonz=0; j<N; j++)
        {
            if ( sidepots[n][j] > minbet && tp->active[j] != 0 && tp->active[j]->betstatus != CARDS777_FOLD )
                nonz++;
        }
        if ( nonz > 0 )
        {
            for (j=0; j<N; j++)
            {
                if ( sidepots[n][j] > minbet )
                {
                    sidepots[n+1][j] = (sidepots[n][j] - minbet);
                    sidepots[n][j] = minbet;
                }
            }
        }
        if ( ++n >= N )
            break;
    }
    if ( dispflag != 0 )
    {
        for (i=0; i<n; i++)
        {
            for (j=0; j<N; j++)
                printf("%.8f ",dstr(sidepots[i][j]));
            printf("sidepot.%d of %d\n",i,n);
        }
    }
    return(n);
}

int64_t pangea_splitpot(struct supernet_info *myinfo,struct table_info *tp,uint64_t *pangearakep,int64_t sidepot[CARDS777_MAXPLAYERS],int32_t rakemillis)
{
    struct player_info *winners[CARDS777_MAXPLAYERS];
    int32_t j,n,N,numwinners = 0; uint32_t bestrank,rank; uint8_t tmp; struct player_info *p;
    uint64_t total = 0,bet,split,maxrake,rake=0,pangearake=0; char handstr[128],besthandstr[128];
    N = tp->numactive;
    bestrank = 0;
    besthandstr[0] = 0;
    for (j=n=0; j<N; j++)
    {
        if ( (bet= sidepot[j]) != 0 )
        {
            total += bet;
            if ( (p= tp->active[j]) != 0 && p->betstatus != CARDS777_FOLD )
            {
                if ( p->handrank > bestrank )
                {
                    bestrank = p->handrank;
                    set_handstr(besthandstr,p->hand,0);
                    //printf("set besthandstr.(%s)\n",besthandstr);
                }
            }
        }
    }
    for (j=0; j<N; j++)
    {
        if ( (p= tp->active[j]) != 0 && p->betstatus != CARDS777_FOLD && sidepot[j] > 0 )
        {
            if ( p->handrank == bestrank )
                winners[numwinners++] = p;
            rank = set_handstr(handstr,p->hand,0);
            if ( handstr[strlen(handstr)-1] == ' ' )
                handstr[strlen(handstr)-1] = 0;
            //if ( hn->server->H.slot == 0 )
            printf("(p%d %14s)",j,handstr[0]!=' '?handstr:handstr+1);
            //printf("(%2d %2d).%d ",dp->hands[j][5],dp->hands[j][6],(int32_t)dp->balances[j]);
        }
    }
    if ( numwinners == 0 )
        printf("pangea_splitpot error: numwinners.0\n");
    else
    {
        uint64_t maxrakes[CARDS777_MAXPLAYERS+1] = { 0, 0, 1, 2, 2, 3, 3, 3, 3, 3 }; // 2players 1BB, 3-4players, 2BB, 5+players 3BB
        for (j=n=0; j<N; j++)
            if ( (p= tp->active[j]) != 0 && p->bets > 0 )
                n++;
        if ( (maxrake= maxrakes[n] * tp->G.bigblind) > tp->G.maxrake )
        {
            maxrake = tp->G.maxrake;
            //if ( strcmp(dp->coinstr,"BTC") == 0 && maxrake < PANGEA_BTCMAXRAKE )
            //    maxrake = PANGEA_BTCMAXRAKE;
            //else if ( maxrake < PANGEA_MAXRAKE )
                maxrake = PANGEA_MAXRAKE;
        }
        split = pangea_winnings(tp->priv.myind,&pangearake,&rake,total,numwinners,rakemillis,maxrake);
        (*pangearakep) += pangearake;
        for (j=0; j<numwinners; j++)
        {
            tmp = winners[j]->ind;
            pangea_summaryadd(myinfo,tp,CARDS777_WINNINGS,&tmp,sizeof(tmp),(void *)&split,sizeof(split));
            winners[j]->balance += split;
            winners[j]->won += split;
        }
        if ( split*numwinners + rake + pangearake != total )
            printf("pangea_split total error %.8f != split %.8f numwinners %d rake %.8f pangearake %.8f\n",dstr(total),dstr(split),numwinners,dstr(rake),dstr(pangearake));
        //if ( hn->server->H.slot == 0 )
        {
            printf(" total %.8f split %.8f rake %.8f Prake %.8f hand.(%s) N%d winners ",dstr(total),dstr(split),dstr(rake),dstr(pangearake),besthandstr,tp->numhands);
            for (j=0; j<numwinners; j++)
                printf("%d ",winners[j]->ind);
            printf("\n");
        }
    }
    return(rake);
}

/*char *pangea_input(uint64_t my64bits,uint64_t tableid,cJSON *json)
{
    char *actionstr; uint64_t sum,amount=0; int32_t action=0,num,threadid; struct table_info *sp; struct cards777_pubdata *dp; char hex[4096];
    threadid = juint(json,"threadid");
    if ( (sp= pangea_threadtables(&num,threadid,tableid)) == 0 )
        return(clonestr("{\"error\":\"you are not playing on any tables\"}"));
    if ( 0 && num != 1 )
        return(clonestr("{\"error\":\"more than one active table\"}"));
    else if ( (dp= sp->dp) == 0 )
        return(clonestr("{\"error\":\"no pubdata ptr for table\"}"));
    else if ( dp->hand.undergun != pangea_ind(sp,sp->myslot) || dp->hand.betsize == 0 )
    {
        printf("undergun.%d threadid.%d myind.%d\n",dp->hand.undergun,sp->tp->threadid,pangea_ind(sp,sp->myslot));
        return(clonestr("{\"error\":\"not your turn\"}"));
    }
    else if ( (actionstr= jstr(json,"action")) == 0 )
        return(clonestr("{\"error\":\"on action specified\"}"));
    else
    {
        if ( strcmp(actionstr,"check") == 0 || strcmp(actionstr,"call") == 0 || strcmp(actionstr,"bet") == 0 || strcmp(actionstr,"raise") == 0 || strcmp(actionstr,"allin") == 0 || strcmp(actionstr,"fold") == 0 )
        {
            sum = dp->hand.bets[pangea_ind(sp,sp->myslot)];
            if ( strcmp(actionstr,"allin") == 0 )
                amount = sp->balances[sp->myslot], action = CARDS777_ALLIN;
            else if ( strcmp(actionstr,"bet") == 0 )
                amount = j64bits(json,"amount"), action = 1;
            else
            {
                if ( dp->hand.betsize == sum )
                {
                    if ( strcmp(actionstr,"check") == 0 || strcmp(actionstr,"call") == 0 )
                        action = 0;
                    else if ( strcmp(actionstr,"raise") == 0 )
                    {
                        action = 1;
                        if ( (amount= dp->hand.lastraise) < j64bits(json,"amount") )
                            amount = j64bits(json,"amount");
                    }
                    else printf("unsupported userinput command.(%s)\n",actionstr);
                }
                else
                {
                    if ( strcmp(actionstr,"check") == 0 || strcmp(actionstr,"call") == 0 )
                        action = 1, amount = (dp->hand.betsize - sum);
                    else if ( strcmp(actionstr,"raise") == 0 )
                    {
                        action = 2;
                        amount = (dp->hand.betsize - sum);
                        if ( amount < dp->hand.lastraise )
                            amount = dp->hand.lastraise;
                        if ( j64bits(json,"amount") > amount )
                            amount = j64bits(json,"amount");
                    }
                    else if ( strcmp(actionstr,"fold") == 0 )
                        action = 0;
                    else printf("unsupported userinput command.(%s)\n",actionstr);
                }
            }
            if ( amount > sp->balances[sp->myslot] )
                amount = sp->balances[sp->myslot], action = CARDS777_ALLIN;
            pangea_sendcmd(hex,&sp->tp->hn,"action",-1,(void *)&amount,sizeof(amount),dp->hand.cardi,action);
            printf("ACTION.(%s)\n",hex);
            return(clonestr("{\"result\":\"action submitted\"}"));
        }
        else return(clonestr("{\"error\":\"illegal action specified, must be: check, call, bet, raise, fold or allin\"}"));
    }
}*/


