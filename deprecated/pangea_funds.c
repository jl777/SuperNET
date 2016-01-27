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

void pangea_fold(union pangeanet777 *hn,struct cards777_pubdata *dp,int32_t player)
{
    uint8_t tmp;
    //printf("player.%d folded\n",player); //getchar();
    dp->hand.handmask |= (1 << player);
    dp->hand.betstatus[player] = CARDS777_FOLD;
    dp->hand.actions[player] = CARDS777_FOLD;
    tmp = player;
    pangea_summary(hn,dp,CARDS777_FOLD,&tmp,sizeof(tmp),(void *)&dp->hand.bets[player],sizeof(dp->hand.bets[player]));
}

uint64_t pangea_totalbet(struct cards777_pubdata *dp)
{
    int32_t j; uint64_t total;
    for (total=j=0; j<dp->N; j++)
        total += dp->hand.bets[j];
    return(total);
}

int32_t pangea_actives(int32_t *activej,struct cards777_pubdata *dp)
{
    int32_t i,n;
    *activej = -1;
    for (i=n=0; i<dp->N; i++)
    {
        if ( dp->hand.betstatus[i] != CARDS777_FOLD )
        {
            if ( *activej < 0 )
                *activej = i;
            n++;
        }
    }
    return(n);
}

struct pangea_info *pangea_usertables(int32_t *nump,uint64_t my64bits,uint64_t tableid)
{
    int32_t i,j,num = 0; struct pangea_info *sp,*retsp = 0;
    *nump = 0;
    for (i=0; i<sizeof(TABLES)/sizeof(*TABLES); i++)
    {
        if ( (sp= TABLES[i]) != 0 )
        {
            for (j=0; j<sp->numaddrs; j++)
                if ( sp->addrs[j] == my64bits && (tableid == 0 || sp->tableid == tableid) )
                {
                    if ( num++ == 0 )
                    {
                        retsp = sp;
                        break;
                    }
                }
        }
    }
    *nump = num;
    return(retsp);
}

struct pangea_info *pangea_threadtables(int32_t *nump,int32_t threadid,uint64_t tableid)
{
    int32_t i,j,num = 0; struct pangea_info *sp,*retsp = 0;
    *nump = 0;
    for (i=0; i<sizeof(TABLES)/sizeof(*TABLES); i++)
    {
        if ( (sp= TABLES[i]) != 0 )
        {
            for (j=0; j<sp->numaddrs; j++)
                if ( sp->tp != 0 && sp->tp->threadid == threadid && (tableid == 0 || sp->tableid == tableid) )
                {
                    if ( num++ == 0 )
                    {
                        retsp = sp;
                        break;
                    }
                }
        }
    }
    *nump = num;
    return(retsp);
}

int32_t pangea_bet(union pangeanet777 *hn,struct cards777_pubdata *dp,int32_t player,int64_t bet,int32_t action)
{
    uint64_t sum; uint8_t tmp; struct pangea_info *sp = dp->table;
    player %= dp->N;
    if ( Debuglevel > 2 )
        printf("player.%d PANGEA_BET[%d] <- %.8f\n",hn->client->H.slot,player,dstr(bet));
    if ( dp->hand.betstatus[player] == CARDS777_ALLIN )
        return(CARDS777_ALLIN);
    else if ( dp->hand.betstatus[player] == CARDS777_FOLD )
        return(CARDS777_FOLD);
    if ( bet > 0 && bet >= sp->balances[pangea_slot(sp,player)] )
    {
        bet = sp->balances[pangea_slot(sp,player)];
        dp->hand.betstatus[player] = action = CARDS777_ALLIN;
    }
    else
    {
        if ( bet > dp->hand.betsize && bet > dp->hand.lastraise && bet < (dp->hand.lastraise<<1) )
        {
            printf("pangea_bet %.8f not double %.8f, clip to lastraise\n",dstr(bet),dstr(dp->hand.lastraise));
            bet = dp->hand.lastraise;
            action = CARDS777_RAISE;
        }
    }
    sum = dp->hand.bets[player];
    if ( sum+bet < dp->hand.betsize && action != CARDS777_ALLIN )
    {
        pangea_fold(hn,dp,player);
        action = CARDS777_FOLD;
        tmp = player;
        if ( Debuglevel > 2 )
            printf("player.%d betsize %.8f < hand.betsize %.8f FOLD\n",player,dstr(bet),dstr(dp->hand.betsize));
        return(action);
    }
    else if ( bet >= 2*dp->hand.lastraise )
    {
        dp->hand.lastraise = bet;
        dp->hand.numactions = 0;
        if ( action == CARDS777_CHECK )
        {
            action = CARDS777_FULLRAISE; // allows all players to check/bet again
            if ( Debuglevel > 2 )
                printf("FULLRAISE by player.%d\n",player);
        }
    }
    sum += bet;
    if ( sum > dp->hand.betsize )
    {
        dp->hand.numactions = 0;
        dp->hand.betsize = sum, dp->hand.lastbettor = player;
        if ( sum > dp->hand.lastraise && action == CARDS777_ALLIN )
            dp->hand.lastraise = sum;
        else if ( action == CARDS777_CHECK )
            action = CARDS777_BET;
    }
    if ( bet > 0 && action == CARDS777_CHECK )
        action = CARDS777_CALL;
    tmp = player;
    pangea_summary(hn,dp,action,&tmp,sizeof(tmp),(void *)&bet,sizeof(bet));
    sp->balances[pangea_slot(sp,player)] -= bet, dp->hand.bets[pangea_slot(sp,player)] += bet;
    if ( Debuglevel > 2 )
        printf("player.%d: player.%d BET %f -> balances %f bets %f\n",hn->client->H.slot,player,dstr(bet),dstr(sp->balances[pangea_slot(sp,player)]),dstr(dp->hand.bets[player]));
    return(action);
}

void pangea_antes(union pangeanet777 *hn,struct cards777_pubdata *dp)
{
    int32_t i,j,n,actives[CARDS777_MAXPLAYERS]; uint64_t threshold; int32_t handid; struct pangea_info *sp = dp->table;
    for (i=0; i<sp->numaddrs; i++)
        dp->snapshot[i] = sp->balances[i];
    handid = dp->numhands - 1;
    pangea_summary(hn,dp,CARDS777_SNAPSHOT,(void *)&handid,sizeof(handid),(void *)dp->snapshot,sizeof(uint64_t)*CARDS777_MAXPLAYERS);
    for (i=0; i<dp->N; i++)
        if ( sp->balances[pangea_slot(sp,i)] <= 0 )
            pangea_fold(hn,dp,i);
    if ( dp->ante != 0 )
    {
        for (i=0; i<dp->N; i++)
        {
            if ( i != dp->button && i != (dp->button+1) % dp->N )
            {
                if ( sp->balances[pangea_slot(sp,i)] < dp->ante )
                    pangea_fold(hn,dp,i);
                else pangea_bet(hn,dp,i,dp->ante,CARDS777_ANTE);
            }
        }
    }
    memset(actives,0,sizeof(actives));
    for (i=n=0; i<dp->N; i++)
    {
        j = (1 + dp->button + i) % dp->N;
        if ( n == 0 )
            threshold = (dp->bigblind >> 1) - 1;
        else if ( n == 1 )
            threshold = dp->bigblind - 1;
        else threshold = 0;
        if ( sp->balances[pangea_slot(sp,j)] > threshold )
        {
            //printf("active[%d] <- %d\n",n,j);
            actives[n++] = j;
        }
        else pangea_fold(hn,dp,j);
    }
    if ( n < 2 )
    {
        printf("pangea_antes not enough players n.%d\n",n);
    }
    else
    {
        pangea_bet(hn,dp,actives[0],(dp->bigblind>>1),CARDS777_SMALLBLIND);
        dp->button = (actives[0] + dp->N - 1) % dp->N;
        pangea_bet(hn,dp,actives[1],dp->bigblind,CARDS777_BIGBLIND);
        
    }
    /*for (i=0; i<dp->N; i++)
     {
     j = (1 + dp->button + i) % dp->N;
     if ( dp->balances[j] < (dp->bigblind >> 1) )
     pangea_fold(hn,dp,j);
     else
     {
     smallblindi = j;
     pangea_bet(hn,dp,smallblindi,(dp->bigblind>>1),CARDS777_SMALLBLIND);
     break;
     }
     }
     for (i=0; i<dp->N; i++)
     {
     j = (1 + smallblindi + i) % dp->N;
     if ( dp->balances[j] < dp->bigblind )
     pangea_fold(hn,dp,j);
     else
     {
     pangea_bet(hn,dp,j,dp->bigblind,CARDS777_BIGBLIND);
     break;
     }
     }*/
    if ( 0 )
    {
        for (i=0; i<dp->N; i++)
            printf("%.8f ",dstr(dp->hand.bets[i]));
        printf("antes\n");
    }
}

void pangea_checkantes(union pangeanet777 *hn,struct cards777_pubdata *dp)
{
    int32_t i;
    for (i=0; i<dp->N; i++)
    {
        //printf("%.8f ",dstr(dp->balances[i]));
        if ( dp->hand.bets[i] != 0 )
            break;
    }
    if ( i == dp->N && dp->hand.checkprod.txid != 0 )
    {
        for (i=0; i<dp->N; i++)
            if ( dp->hand.bets[i] != 0 )
                break;
        if ( i == dp->N )
        {
            //printf("i.%d vs N.%d call antes\n",i,dp->N);
            pangea_antes(hn,dp);
        } else printf("bets i.%d\n",i);
    }
}

/*int32_t pangea_cashout(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    return(0);
}*/

int32_t _pangea_addfunds(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    char *txidstr,*destaddr; uint32_t vout; int32_t slot; uint64_t amount = 0; struct pangea_info *sp = dp->table;
    slot = pangea_slot(sp,senderind);
    if ( datalen == sizeof(amount) )
        memcpy(&amount,data,sizeof(amount));
    else
    {
        if ( (json= cJSON_Parse((void *)data)) != 0 )
        {
            amount = j64bits(json,"amount");
            txidstr = jstr(json,"txidstr");
            destaddr = jstr(json,"msigaddr");
            vout = juint(json,"vout");
            if ( txidstr != 0 && destaddr != 0 && amount > 0 && strcmp(destaddr,sp->multisigaddr) == 0 )
            {
                // of course need to verify on blockchain
                strcpy(sp->buyintxids[slot],txidstr);
                sp->buyinvouts[slot] = vout;
                sp->buyinamounts[slot] = amount;
            }
            free_json(json);
        }
    }
    if ( sp->balances[slot] == 0 )
        sp->balances[slot] = amount;
    pangea_checkantes(hn,dp);
    printf("slot.%d: addfunds.%d <- %.8f total %.8f\n",hn->client->H.slot,senderind,dstr(amount),dstr(sp->balances[senderind]));
    return(0);
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

int32_t pangea_sidepots(int32_t dispflag,uint64_t sidepots[CARDS777_MAXPLAYERS][CARDS777_MAXPLAYERS],struct cards777_pubdata *dp,int64_t *bets)
{
    int32_t i,j,nonz,n = 0; uint64_t bet,minbet = 0;
    memset(sidepots,0,sizeof(uint64_t)*CARDS777_MAXPLAYERS*CARDS777_MAXPLAYERS);
    for (j=0; j<dp->N; j++)
        sidepots[0][j] = bets[j];
    nonz = 1;
    while ( nonz > 0 )
    {
        for (minbet=j=0; j<dp->N; j++)
        {
            if ( (bet= sidepots[n][j]) != 0 )
            {
                if ( dp->hand.betstatus[j] != CARDS777_FOLD )
                {
                    if ( minbet == 0 || bet < minbet )
                        minbet = bet;
                }
            }
        }
        for (j=nonz=0; j<dp->N; j++)
        {
            if ( sidepots[n][j] > minbet && dp->hand.betstatus[j] != CARDS777_FOLD )
                nonz++;
        }
        if ( nonz > 0 )
        {
            for (j=0; j<dp->N; j++)
            {
                if ( sidepots[n][j] > minbet )
                {
                    sidepots[n+1][j] = (sidepots[n][j] - minbet);
                    sidepots[n][j] = minbet;
                }
            }
        }
        if ( ++n >= dp->N )
            break;
    }
    if ( dispflag != 0 )
    {
        for (i=0; i<n; i++)
        {
            for (j=0; j<dp->N; j++)
                printf("%.8f ",dstr(sidepots[i][j]));
            printf("sidepot.%d of %d\n",i,n);
        }
    }
    return(n);
}

int64_t pangea_splitpot(int64_t *won,uint64_t *pangearakep,uint64_t sidepot[CARDS777_MAXPLAYERS],union pangeanet777 *hn,int32_t rakemillis)
{
    int32_t winners[CARDS777_MAXPLAYERS],j,n,numwinners = 0; uint32_t bestrank,rank; uint8_t tmp; struct pangea_info *sp;
    uint64_t total = 0,bet,split,maxrake,rake=0,pangearake=0; char handstr[128],besthandstr[128]; struct cards777_pubdata *dp;
    dp = hn->client->H.pubdata, sp = dp->table;
    bestrank = 0;
    besthandstr[0] = 0;
    for (j=n=0; j<dp->N; j++)
    {
        if ( (bet= sidepot[j]) != 0 )
        {
            total += bet;
            if ( dp->hand.betstatus[j] != CARDS777_FOLD )
            {
                if ( dp->hand.handranks[j] > bestrank )
                {
                    bestrank = dp->hand.handranks[j];
                    set_handstr(besthandstr,dp->hand.hands[j],0);
                    //printf("set besthandstr.(%s)\n",besthandstr);
                }
            }
        }
    }
    for (j=0; j<dp->N; j++)
    {
        if ( dp->hand.betstatus[j] != CARDS777_FOLD && sidepot[j] > 0 )
        {
            if ( dp->hand.handranks[j] == bestrank )
                winners[numwinners++] = j;
            rank = set_handstr(handstr,dp->hand.hands[j],0);
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
        for (j=n=0; j<dp->N; j++)
            if ( dp->hand.bets[j] > 0 )
                n++;
        if ( (maxrake= maxrakes[n] * dp->bigblind) > dp->maxrake )
        {
            maxrake = dp->maxrake;
            if ( strcmp(dp->coinstr,"BTC") == 0 && maxrake < PANGEA_BTCMAXRAKE )
                maxrake = PANGEA_BTCMAXRAKE;
            else if ( maxrake < PANGEA_MAXRAKE )
                maxrake = PANGEA_MAXRAKE;
        }
        split = pangea_winnings(pangea_ind(dp->table,hn->client->H.slot),&pangearake,&rake,total,numwinners,rakemillis,maxrake);
        (*pangearakep) += pangearake;
        for (j=0; j<numwinners; j++)
        {
            tmp = winners[j];
            pangea_summary(hn,dp,CARDS777_WINNINGS,&tmp,sizeof(tmp),(void *)&split,sizeof(split));
            sp->balances[pangea_slot(sp,winners[j])] += split;
            won[winners[j]] += split;
        }
        if ( split*numwinners + rake + pangearake != total )
            printf("pangea_split total error %.8f != split %.8f numwinners %d rake %.8f pangearake %.8f\n",dstr(total),dstr(split),numwinners,dstr(rake),dstr(pangearake));
        //if ( hn->server->H.slot == 0 )
        {
            printf(" total %.8f split %.8f rake %.8f Prake %.8f hand.(%s) N%d winners ",dstr(total),dstr(split),dstr(rake),dstr(pangearake),besthandstr,dp->numhands);
            for (j=0; j<numwinners; j++)
                printf("%d ",pangea_slot(sp,winners[j]));
            printf("\n");
        }
    }
    return(rake);
}

uint64_t pangea_bot(PANGEA_ARGS,int32_t turni,int32_t cardi,uint64_t betsize)
{
    int32_t r,action=CARDS777_CHECK,n,activej; uint64_t threshold,total,sum,amount = 0; struct pangea_info *sp = dp->table;
    sum = dp->hand.bets[pangea_ind(dp->table,priv->myslot)];
    action = 0;
    n = pangea_actives(&activej,dp);
    if ( (r = (rand() % 100)) < 1 )
        amount = sp->balances[priv->myslot], action = CARDS777_ALLIN;
    else
    {
        if ( betsize == sum )
        {
            if ( r < 100/n )
            {
                amount = dp->hand.lastraise;
                action = 1;
                if ( (rand() % 100) < 10 )
                    amount <<= 1;
            }
        }
        else if ( betsize > sum )
        {
            amount = (betsize - sum);
            total = pangea_totalbet(dp);
            threshold = (300 * amount)/(1 + total);
            n++;
            if ( r/n > threshold )
            {
                action = 1;
                if ( r/n > 3*threshold && amount < dp->hand.lastraise*2 )
                    amount = dp->hand.lastraise * 2, action = 2;
                //else if ( r/n > 10*threshold )
                //    amount = dp->balances[pangea_ind(dp->table,hn->client->H.slot)], action = CARDS777_ALLIN;
            }
            else if ( amount < sum/10 || amount <= SATOSHIDEN )
                action = CARDS777_CALL;
            else
            {
                //printf("amount %.8f, sum %.8f, betsize %.8f\n",dstr(amount),dstr(sum),dstr(betsize));
                action = CARDS777_FOLD, amount = 0;
            }
        }
        else printf("pangea_turn error betsize %.8f vs sum %.8f | slot.%d ind.%d\n",dstr(betsize),dstr(sum),priv->myslot,pangea_ind(dp->table,priv->myslot));
        if ( amount > sp->balances[priv->myslot] )
            amount = sp->balances[priv->myslot], action = CARDS777_ALLIN;
    }
    pangea_sendcmd(PANGEA_CALLARGS,"action",-1,(void *)&amount,sizeof(amount),cardi,action);
    printf("playerbot.%d got pangea_turn.%d for player.%d action.%d bet %.8f\n",priv->myslot,cardi,turni,action,dstr(amount));
    return(amount);
}

cJSON *pangea_handjson(struct cards777_handinfo *hand,uint8_t *holecards,int32_t isbot)
{
    int32_t i,card; char cardAstr[8],cardBstr[8],pairstr[18],cstr[128]; cJSON *array,*json = cJSON_CreateObject();
    array = cJSON_CreateArray();
    cstr[0] = 0;
    for (i=0; i<5; i++)
    {
        if ( (card= hand->community[i]) != 0xff )
        {
            jaddinum(array,card);
            cardstr(&cstr[strlen(cstr)],card);
            strcat(cstr," ");
        }
    }
    jaddstr(json,"community",cstr);
    jadd(json,"cards",array);
    if ( (card= holecards[0]) != 0xff )
    {
        jaddnum(json,"cardA",card);
        cardstr(cardAstr,holecards[0]);
    } else cardAstr[0] = 0;
    if ( (card= holecards[1]) != 0xff )
    {
        jaddnum(json,"cardB",card);
        cardstr(cardBstr,holecards[1]);
    } else cardBstr[0] = 0;
    sprintf(pairstr,"%s %s",cardAstr,cardBstr);
    jaddstr(json,"holecards",pairstr);
    jaddnum(json,"betsize",dstr(hand->betsize));
    jaddnum(json,"lastraise",dstr(hand->lastraise));
    jaddnum(json,"lastbettor",hand->lastbettor);
    jaddnum(json,"numactions",hand->numactions);
    jaddnum(json,"undergun",hand->undergun);
    jaddnum(json,"isbot",isbot);
    jaddnum(json,"cardi",hand->cardi);
    return(json);
}

char *pangea_statusstr(int32_t status)
{
    if ( status == CARDS777_FOLD )
        return("folded");
    else if ( status == CARDS777_ALLIN )
        return("ALLin");
    else return("active");
}

int32_t pangea_countdown(struct cards777_pubdata *dp,int32_t player)
{
    if ( dp->hand.undergun == player && dp->hand.userinput_starttime != 0 )
        return((int32_t)(dp->hand.userinput_starttime + PANGEA_USERTIMEOUT - time(NULL)));
    else return(-1);
}

cJSON *pangea_tablestatus(struct pangea_info *sp)
{
    uint64_t sidepots[CARDS777_MAXPLAYERS][CARDS777_MAXPLAYERS],totals[CARDS777_MAXPLAYERS],sum; char *handhist;
    int32_t i,n,j,countdown,iter; int64_t total; struct cards777_pubdata *dp; cJSON *bets,*item,*array,*json = cJSON_CreateObject();
    jadd64bits(json,"tableid",sp->tableid);
    jadd64bits(json,"myslot",sp->myslot);
    jadd64bits(json,"myind",pangea_ind(sp,sp->myslot));
    dp = sp->dp;
    jaddstr(json,"tablemsig",sp->multisigaddr);
    jaddnum(json,"minbuyin",dp->minbuyin);
    jaddnum(json,"maxbuyin",dp->maxbuyin);
    jaddnum(json,"button",dp->button);
    jaddnum(json,"M",dp->M);
    jaddnum(json,"N",dp->N);
    jaddnum(json,"numcards",dp->numcards);
    jaddnum(json,"numhands",dp->numhands);
    jaddnum(json,"rake",(double)dp->rakemillis/10.);
    jaddnum(json,"maxrake",dstr(dp->maxrake));
    jaddnum(json,"hostrake",dstr(dp->hostrake));
    jaddnum(json,"pangearake",dstr(dp->pangearake));
    jaddnum(json,"bigblind",dstr(dp->bigblind));
    jaddnum(json,"ante",dstr(dp->ante));
    array = cJSON_CreateArray();
    for (i=0; i<dp->N; i++)
        jaddi64bits(array,sp->active[i]);
    jadd(json,"addrs",array);
    array = cJSON_CreateArray();
    for (i=0; i<dp->N; i++)
        jaddinum(array,dp->hand.turnis[i]);
    jadd(json,"turns",array);
    array = cJSON_CreateArray();
    for (i=0; i<sp->numaddrs; i++)
        jaddinum(array,dstr(sp->balances[i]));
    jadd(json,"balances",array);
    array = cJSON_CreateArray();
    for (i=0; i<dp->N; i++)
        jaddinum(array,dstr(dp->hand.snapshot[i]));
    jadd(json,"snapshot",array);
    array = cJSON_CreateArray();
    for (i=0; i<dp->N; i++)
        jaddistr(array,pangea_statusstr(dp->hand.betstatus[i]));
    jadd(json,"status",array);
    bets = cJSON_CreateArray();
    for (total=i=0; i<dp->N; i++)
    {
        total += dp->hand.bets[i];
        jaddinum(bets,dstr(dp->hand.bets[i]));
    }
    jadd(json,"bets",bets);
    jaddnum(json,"totalbets",dstr(total));
    for (iter=0; iter<2; iter++)
        if ( (n= pangea_sidepots(0,sidepots,dp,iter == 0 ? dp->hand.snapshot : dp->hand.bets)) > 0 && n < dp->N )
    {
        array = cJSON_CreateArray();
        for (i=0; i<n; i++)
        {
            item = cJSON_CreateArray();
            for (sum=j=0; j<dp->N; j++)
                jaddinum(item,dstr(sidepots[i][j])), sum += sidepots[i][j];
            totals[i] = sum;
            jaddi(array,item);
        }
        jadd(json,iter == 0 ? "pots" : "RTpots",array);
        item = cJSON_CreateArray();
        for (sum=i=0; i<n; i++)
            jaddinum(item,dstr(totals[i])), sum += totals[i];
        jadd(json,iter == 0 ? "potTotals" : "RTpotTotals",item);
        jaddnum(json,iter == 0 ? "sum" : "RTsum",dstr(sum));
    }
    if ( sp->priv != 0 )
    {
        jadd64bits(json,"automuck",sp->priv->automuck);
        jadd64bits(json,"autofold",sp->priv->autofold);
        jadd(json,"hand",pangea_handjson(&dp->hand,sp->priv->hole,sp->isbot[sp->myslot]));
    }
    if ( (handhist= pangea_dispsummary(sp,0,dp->summary,dp->summarysize,sp->tableid,dp->numhands-1,dp->N)) != 0 )
    {
        if ( (item= cJSON_Parse(handhist)) != 0 )
            jadd(json,"actions",item);
        free(handhist);
    }
    if ( (countdown= pangea_countdown(dp,pangea_ind(sp,sp->myslot))) >= 0 )
        jaddnum(json,"timeleft",countdown);
    if ( dp->hand.finished != 0 )
    {
        item = cJSON_CreateObject();
        jaddnum(item,"hostrake",dstr(dp->hand.hostrake));
        jaddnum(item,"pangearake",dstr(dp->hand.pangearake));
        array = cJSON_CreateArray();
        for (i=0; i<dp->N; i++)
            jaddinum(array,dstr(dp->hand.won[i]));
        jadd(item,"won",array);
        jadd(json,"summary",item);
    }
    return(json);
}

void pangea_playerprint(struct cards777_pubdata *dp,int32_t i,int32_t myind)
{
    int32_t countdown; char str[8]; struct pangea_info *sp = dp->table;
    if ( (countdown= pangea_countdown(dp,i)) >= 0 )
        sprintf(str,"%2d",countdown);
    else str[0] = 0;
    printf("%d: %6s %12.8f %2s  | %12.8f %s\n",i,pangea_statusstr(dp->hand.betstatus[i]),dstr(dp->hand.bets[i]),str,dstr(sp->balances[pangea_slot(sp,i)]),i == myind ? "<<<<<<<<<<<": "");
}

void pangea_statusprint(struct cards777_pubdata *dp,struct cards777_privdata *priv,int32_t myind)
{
    int32_t i; char handstr[64]; uint8_t hand[7];
    for (i=0; i<dp->N; i++)
        pangea_playerprint(dp,i,myind);
    handstr[0] = 0;
    if ( dp->hand.community[0] != dp->hand.community[1] )
    {
        for (i=0; i<5; i++)
            if ( (hand[i]= dp->hand.community[i]) == 0xff )
                break;
        if ( i == 5 )
        {
            if ( (hand[5]= priv->hole[0]) != 0xff && (hand[6]= priv->hole[1]) != 0xff )
                set_handstr(handstr,hand,1);
        }
    }
    printf("%s\n",handstr);
}

/*
 if ( hn->server->H.slot == 0 )
{
    char *pangea_cashout(char *coinstr,int32_t oldtx_format,uint64_t values[],char *txidstrs[],int32_t vouts[],int32_t numinputs,char *destaddrs[],char *destscripts[],uint64_t outputs[],int32_t n,char *scriptPubKey,char *redeemScript,char *wip,uint64_t txfee,char sigs[][256],int32_t numplayers,uint8_t *privkey,int32_t privkeyind,char *othersignedtx);
    uint64_t values[1],txfee; char *othersignedtx,*rawtx,*txidstrs[1],*destaddrs[1],*destscripts[1],sigs[CARDS777_MAXPLAYERS][256]; int32_t vouts[1]; uint64_t outputs[1];
    if ( strcmp(dp->coinstr,"BTC") == 0 )
    {
        txfee = SATOSHIDEN/10000;
        values[0] = SATOSHIDEN / 5000, txidstrs[0] = "94cb2925d802c6c3695f0765767d892e13bd90ca256cc08ed5d85fd737bcc848", vouts[0] = 0;
        outputs[0] = SATOSHIDEN / 5000 - txfee;
    }
    else
    {
        txfee = SATOSHIDEN/1000;
        values[0] = SATOSHIDEN, txidstrs[0] = "af980e0cf15c028d571767935e9e78ff0ad3068ff1a2ae2ca62c723a75ed8a80", vouts[0] = 1;
        outputs[0] = SATOSHIDEN - txfee;
    }
    destaddrs[0] = dp->multisigaddr, destscripts[0] = dp->scriptPubKey;
    memset(sigs,0,sizeof(sigs));
    othersignedtx = 0;
    for (i=0; i<dp->N; i++)
    {
        rawtx = pangea_cashout(dp->coinstr,strcmp(dp->coinstr,"BTC") == 0,values,txidstrs,vouts,1,destaddrs,destscripts,outputs,1,dp->scriptPubKey,dp->redeemScript,priv->wipstr,txfee,sigs,dp->N,THREADS[i]->hn.client->H.privkey.bytes,i,othersignedtx);
        if ( othersignedtx != 0 )
            free(othersignedtx);
        othersignedtx = rawtx;
    }
}
*/
