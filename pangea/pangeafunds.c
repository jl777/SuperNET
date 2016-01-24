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

char *pangea_typestr(uint8_t type)
{
    static char err[64];
    switch ( type )
    {
        case 0xff: return("fold");
        case CARDS777_START: return("start");
        case CARDS777_ANTE: return("ante");
        case CARDS777_SMALLBLIND: return("smallblind");
        case CARDS777_BIGBLIND: return("bigblind");
        case CARDS777_CHECK: return("check");
        case CARDS777_CALL: return("call");
        case CARDS777_BET: return("bet");
        case CARDS777_RAISE: return("raise");
        case CARDS777_FULLRAISE: return("fullraise");
        case CARDS777_SENTCARDS: return("sentcards");
        case CARDS777_ALLIN: return("allin");
        case CARDS777_FACEUP: return("faceup");
        case CARDS777_WINNINGS: return("won");
        case CARDS777_RAKES: return("rakes");
        case CARDS777_CHANGES: return("changes");
        case CARDS777_SNAPSHOT: return("snapshot");
    }
    sprintf(err,"unknown type.%d",type);
    return(err);
}

cJSON *pangea_handitem(int32_t *cardip,cJSON **pitemp,uint8_t type,uint64_t valA,uint64_t *bits64p,bits256 card,int32_t numplayers)
{
    int32_t cardi,n,i,rebuy,busted; char str[128],hexstr[65],cardpubs[(CARDS777_MAXCARDS+1)*64+1]; cJSON *item,*array,*pitem = 0;
    item = cJSON_CreateObject();
    *cardip = -1;
    switch ( type )
    {
        case CARDS777_START:
            jaddnum(item,"handid",valA);
            init_hexbytes_noT(cardpubs,(void *)bits64p,(int32_t)((CARDS777_MAXCARDS+1) * sizeof(bits256)));
            jaddstr(item,"cardpubs",cardpubs);
            break;
        case CARDS777_RAKES:
            jaddnum(item,"hostrake",dstr(valA));
            jaddnum(item,"pangearake",dstr(*bits64p));
            break;
        case CARDS777_SNAPSHOT:
            jaddnum(item,"handid",valA);
            array = cJSON_CreateArray();
            for (i=0; i<CARDS777_MAXPLAYERS; i++)
            {
                if ( i < numplayers )
                    jaddinum(array,dstr(bits64p[i]));
                else jaddinum(array,dstr(0));
            }
            jadd(item,"snapshot",array);
            //printf("add snapshot for numplayers.%d\n",numplayers);
            break;
        case CARDS777_CHANGES:
            n = (int32_t)(valA & 0xf);
            busted = (int32_t)((valA>>4) & 0xffff);
            rebuy = (int32_t)((valA>>20) & 0xffff);
            if ( busted != 0 )
                jaddnum(item,"busted",busted);
            if ( rebuy != 0 )
                jaddnum(item,"rebuy",rebuy);
            array = cJSON_CreateArray();
            for (i=0; i<n; i++)
                jaddinum(array,dstr(bits64p[i]));
            jadd(item,"balances",array);
            break;
        case CARDS777_WINNINGS:
            if ( (int32_t)valA >= 0 && valA < numplayers )
                jaddnum(item,"player",valA);
            jaddnum(item,"won",dstr(*bits64p));
            if ( pitem == 0 )
                pitem = cJSON_CreateObject();
            jaddnum(pitem,"won",dstr(*bits64p));
            break;
        case CARDS777_FACEUP:
            *cardip = cardi = (int32_t)(valA >> 8);
            if ( cardi >= 0 && cardi < 52 )
                jaddnum(item,"cardi",cardi);
            else printf("illegal cardi.%d valA.%llu\n",cardi,(long long)valA);
            valA &= 0xff;
            if ( (int32_t)valA >= 0 && valA < numplayers )
                jaddnum(item,"player",valA);
            else if ( valA == 0xff )
                jaddnum(item,"community",cardi - numplayers*2);
            cardstr(str,card.bytes[1]);
            jaddnum(item,str,card.bytes[1]);
            init_hexbytes_noT(hexstr,card.bytes,sizeof(card));
            jaddstr(item,"privkey",hexstr);
            break;
        default:
            if ( (int32_t)valA >= 0 && valA < numplayers )
                jaddnum(item,"player",valA);
            jaddstr(item,"action",pangea_typestr(type));
            if ( pitem == 0 )
                pitem = cJSON_CreateObject();
            if ( *bits64p != 0 )
            {
                jaddnum(item,"bet",dstr(*bits64p));
                jaddnum(pitem,pangea_typestr(type),dstr(*bits64p));
            }
            else jaddstr(pitem,"action",pangea_typestr(type));
            break;
    }
    *pitemp = pitem;
    return(item);
}

int32_t pangea_parsesummary(uint8_t *typep,uint64_t *valAp,uint64_t *bits64p,bits256 *cardp,uint8_t *summary,int32_t len)
{
    int32_t handid; uint16_t cardi_player; uint32_t changes=0; uint8_t player;
    *bits64p = 0;
    memset(cardp,0,sizeof(*cardp));
    len += hostnet777_copybits(1,&summary[len],(void *)typep,sizeof(*typep));
    if ( *typep == 0 )
    {
        printf("len.%d type.%d [%d]\n",len,*typep,summary[len-1]);
        return(-1);
    }
    if ( *typep == CARDS777_START || *typep == CARDS777_SNAPSHOT )
        len += hostnet777_copybits(1,&summary[len],(void *)&handid,sizeof(handid)), *valAp = handid;
    else if ( *typep == CARDS777_CHANGES )
        len += hostnet777_copybits(1,&summary[len],(void *)&changes,sizeof(changes)), *valAp = changes;
    else if ( *typep == CARDS777_RAKES )
        len += hostnet777_copybits(1,&summary[len],(void *)valAp,sizeof(*valAp));
    else if ( *typep == CARDS777_FACEUP )
        len += hostnet777_copybits(1,&summary[len],(void *)&cardi_player,sizeof(cardi_player)), *valAp = cardi_player;
    else len += hostnet777_copybits(1,&summary[len],(void *)&player,sizeof(player)), *valAp = player;
    if ( *typep == CARDS777_FACEUP )
        len += hostnet777_copybits(1,&summary[len],cardp->bytes,sizeof(*cardp));
    else if ( *typep == CARDS777_START )
        len += hostnet777_copybits(1,&summary[len],(void *)bits64p,sizeof(bits256)*(CARDS777_MAXCARDS+1));
    else if ( *typep == CARDS777_SNAPSHOT )
        len += hostnet777_copybits(1,&summary[len],(void *)bits64p,sizeof(*bits64p) * CARDS777_MAXPLAYERS);
    else if ( *typep == CARDS777_CHANGES )
        len += hostnet777_copybits(1,&summary[len],(void *)bits64p,sizeof(*bits64p) * (changes & 0xf));
    else len += hostnet777_copybits(1,&summary[len],(void *)bits64p,sizeof(*bits64p));
    return(len);
}

void pangea_summary(union hostnet777 *hn,struct cards777_pubdata *dp,uint8_t type,void *arg0,int32_t size0,void *arg1,int32_t size1)
{
    uint64_t valA,bits64[CARDS777_MAXPLAYERS + (CARDS777_MAXCARDS+1)*4]; bits256 card; uint8_t checktype; char *str;
    cJSON *item,*pitem; int32_t len,cardi,startlen = dp->summarysize;
    if ( type == 0 )
    {
        printf("type.0\n"); getchar();
    }
    //printf("summarysize.%d type.%d [%02x %02x]\n",dp->summarysize,type,*(uint8_t *)arg0,*(uint8_t *)arg1);
    dp->summarysize += hostnet777_copybits(0,&dp->summary[dp->summarysize],(void *)&type,sizeof(type));
    //printf("-> %d\n",dp->summary[dp->summarysize-1]);
    dp->summarysize += hostnet777_copybits(0,&dp->summary[dp->summarysize],arg0,size0);
    dp->summarysize += hostnet777_copybits(0,&dp->summary[dp->summarysize],arg1,size1);
    //printf("startlen.%d summarysize.%d\n",startlen,dp->summarysize);
    len = pangea_parsesummary(&checktype,&valA,bits64,&card,dp->summary,startlen);
    if ( len != dp->summarysize || checktype != type || memcmp(&valA,arg0,size0) != 0 )
        printf("pangea_summary parse error [%d] (%d vs %d) || (%d vs %d).%d || cmp.%d size0.%d size1.%d\n",startlen,len,dp->summarysize,checktype,type,dp->summary[startlen],memcmp(&valA,arg0,size0),size0,size1);
    if ( card.txid != 0 && memcmp(card.bytes,arg1,sizeof(card)) != 0 )
        printf("pangea_summary: parse error card mismatch %llx != %llx\n",(long long)card.txid,*(long long *)arg1);
    else if ( card.txid == 0 && memcmp(arg1,bits64,size1) != 0 )
        printf("pangea_summary: parse error bits64 %llx != %llx\n",(long long)bits64[0],*(long long *)arg0);
    if ( 1 && hn->client->H.slot == pangea_slotA(dp->table) )
    {
        if ( (item= pangea_handitem(&cardi,&pitem,type,valA,bits64,card,dp->N)) != 0 )
        {
            str = jprint(item,1);
            printf("ITEM.(%s)\n",str);
            free(str);
        }
        if ( pitem != 0 )
        {
            str = jprint(pitem,1);
            printf("PITEM.(%s)\n",str);
            free(str);
        }
    }
    if ( Debuglevel > 2 )//|| hn->client->H.slot == pangea_slotA(dp->table) )
        printf("pangea_summary.%d %d | summarysize.%d crc.%u\n",type,*(uint8_t *)arg0,dp->summarysize,_crc32(0,dp->summary,dp->summarysize));
}

char *pangea_dispsummary(struct pangea_info *sp,int32_t verbose,uint8_t *summary,int32_t summarysize,uint64_t tableid,int32_t handid,int32_t numplayers)
{
    int32_t i,cardi,n = 0,len = 0; uint8_t type; uint64_t valA,bits64[CARDS777_MAXPLAYERS + (CARDS777_MAXCARDS+1)*4]; bits256 card;
    cJSON *item,*json,*all,*cardis[52],*players[CARDS777_MAXPLAYERS],*pitem,*array = cJSON_CreateArray();
    all = cJSON_CreateArray();
    memset(cardis,0,sizeof(cardis));
    memset(players,0,sizeof(players));
    for (i=0; i<numplayers; i++)
        players[i] = cJSON_CreateArray();
    while ( len < summarysize )
    {
        memset(bits64,0,sizeof(bits64));
        len = pangea_parsesummary(&type,&valA,bits64,&card,summary,len);
        if ( (item= pangea_handitem(&cardi,&pitem,type,valA,bits64,card,numplayers)) != 0 )
        {
            if ( cardi >= 0 && cardi < 52 )
            {
                //printf("cardis[%d] <- %p\n",cardi,item);
                cardis[cardi] = item;
            }
            else jaddi(array,item);
            item = 0;
        }
        if ( pitem != 0 )
        {
            jaddnum(pitem,"n",n), n++;
            if ( (int32_t)valA >= 0 && valA < numplayers )
                jaddi(players[valA],pitem);
            else free_json(pitem), printf("illegal player.%llu\n",(long long)valA);
            pitem = 0;
        }
    }
    for (i=0; i<numplayers; i++)
        jaddi(all,players[i]);
    if ( verbose == 0 )
    {
        for (i=0; i<52; i++)
            if ( cardis[i] != 0 )
                free_json(cardis[i]);
        free_json(array);
        return(jprint(all,1));
    }
    else
    {
        json = cJSON_CreateObject();
        if ( tableid != 0 )
            jadd64bits(json,"tableid",tableid);
        if ( 0 && sp != 0 )
        {
            //array = cJSON_CreateArray();
            //for (i=0; i<sp->numactive; i++)
            //    jaddi64bits(array,sp->active[i]);
            //jadd(json,"active",array);
            for (i=0; i<sp->numactive; i++)
                printf("%llu ",(long long)sp->active[i]);
            printf("sp->numactive[%d]\n",sp->numactive);
        }
        jaddnum(json,"size",summarysize);
        jaddnum(json,"handid",handid);
        //jaddnum(json,"crc",_crc32(0,summary,summarysize));
        jadd(json,"hand",array);
        array = cJSON_CreateArray();
        for (i=0; i<52; i++)
            if ( cardis[i] != 0 )
                jaddi(array,cardis[i]);
        jadd(json,"cards",array);
        //jadd(json,"players",all);
        return(jprint(json,1));
    }
}

void pangea_fold(union hostnet777 *hn,struct cards777_pubdata *dp,int32_t player)
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

int32_t pangea_bet(union hostnet777 *hn,struct cards777_pubdata *dp,int32_t player,int64_t bet,int32_t action)
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

void pangea_antes(union hostnet777 *hn,struct cards777_pubdata *dp)
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

void pangea_checkantes(union hostnet777 *hn,struct cards777_pubdata *dp)
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

/*int32_t pangea_cashout(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    return(0);
}*/

int32_t pangea_addfunds(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
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

int64_t pangea_splitpot(int64_t *won,uint64_t *pangearakep,uint64_t sidepot[CARDS777_MAXPLAYERS],union hostnet777 *hn,int32_t rakemillis)
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

uint64_t pangea_bot(union hostnet777 *hn,struct cards777_pubdata *dp,int32_t turni,int32_t cardi,uint64_t betsize)
{
    int32_t r,action=CARDS777_CHECK,n,activej; char hex[1024]; uint64_t threshold,total,sum,amount = 0; struct pangea_info *sp = dp->table;
    sum = dp->hand.bets[pangea_ind(dp->table,hn->client->H.slot)];
    action = 0;
    n = pangea_actives(&activej,dp);
    if ( (r = (rand() % 100)) < 1 )
        amount = sp->balances[hn->client->H.slot], action = CARDS777_ALLIN;
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
        else printf("pangea_turn error betsize %.8f vs sum %.8f | slot.%d ind.%d\n",dstr(betsize),dstr(sum),hn->client->H.slot,pangea_ind(dp->table,hn->client->H.slot));
        if ( amount > sp->balances[hn->client->H.slot] )
            amount = sp->balances[hn->client->H.slot], action = CARDS777_ALLIN;
    }
    pangea_sendcmd(hex,hn,"action",-1,(void *)&amount,sizeof(amount),cardi,action);
    printf("playerbot.%d got pangea_turn.%d for player.%d action.%d bet %.8f\n",hn->client->H.slot,cardi,turni,action,dstr(amount));
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

int32_t pangea_turn(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    int32_t turni,cardi,i; char hex[2048]; uint64_t betsize = 0; struct pangea_info *sp = dp->table;
    turni = juint(json,"turni");
    cardi = juint(json,"cardi");
    if ( Debuglevel > 2 )
        printf("P%d: got turn.%d from %d | cardi.%d summary[%d] crc.%u\n",hn->server->H.slot,turni,senderind,cardi,dp->summarysize,_crc32(0,dp->summary,dp->summarysize));
    dp->hand.turnis[senderind] = turni;
    if ( senderind == 0 && sp != 0 )
    {
        dp->hand.cardi = cardi;
        dp->hand.betstarted = 1;
        dp->hand.undergun = turni;
        if ( hn->client->H.slot != pangea_slotA(dp->table) )
        {
            pangea_checkantes(hn,dp);
            memcpy(dp->hand.snapshot,dp->hand.bets,dp->N*sizeof(uint64_t));
            for (i=0; i<dp->N; i++)
                if ( dp->hand.bets[i] > betsize )
                    betsize = dp->hand.bets[i];
            dp->hand.snapshot[dp->N] = betsize;
            //printf("player.%d sends confirmturn.%d\n",hn->client->H.slot,turni);
            pangea_sendcmd(hex,hn,"confirm",-1,(void *)dp->hand.snapshot,sizeof(uint64_t)*(dp->N+1),cardi,turni);
        }
    }
    return(0);
}

int32_t pangea_confirmturn(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    uint32_t starttime; int32_t i,turni,cardi; uint64_t betsize=0,amount=0; struct pangea_info *sp=0; char hex[1024];
    if ( data == 0 )
    {
        printf("pangea_turn: null data\n");
        return(-1);
    }
    turni = juint(json,"turni");
    cardi = juint(json,"cardi");
    //printf("got confirmturn.%d cardi.%d sender.%d\n",turni,cardi,senderind);
    //if ( datalen == sizeof(betsize) )
    //    memcpy(&betsize,data,sizeof(betsize));
    starttime = dp->hand.starttime;
    if ( (sp= dp->table) != 0 )
    {
        if ( senderind == 0 && hn->client->H.slot != pangea_slotA(dp->table) )
        {
            dp->hand.undergun = turni;
            dp->hand.cardi = cardi;
            memcpy(dp->hand.snapshot,data,(dp->N+1)*sizeof(uint64_t));
            for (betsize=i=0; i<dp->N; i++)
                if ( dp->hand.bets[i] > betsize )
                    betsize = dp->hand.bets[i];
            if ( betsize != dp->hand.snapshot[dp->N] )
                printf("T%d ERROR BETSIZE MISMATCH: %.8f vs %.8f\n",sp->myslot,dstr(betsize),dstr(dp->hand.snapshot[dp->N]));
            dp->hand.betsize = betsize;
        }
        dp->hand.turnis[senderind] = turni;
        for (i=0; i<dp->N; i++)
        {
            //printf("[i%d %d] ",i,dp->turnis[i]);
            if ( dp->hand.turnis[i] != turni )
                break;
        }
        //printf("sp.%p vs turni.%d cardi.%d hand.cardi %d\n",sp,turni,cardi,dp->hand.cardi);
        if ( hn->client->H.slot == pangea_slotA(dp->table) && i == dp->N )
        {
            for (betsize=i=0; i<dp->N; i++)
                if ( dp->hand.bets[i] > betsize )
                    betsize = dp->hand.bets[i];
            dp->hand.betsize = dp->hand.snapshot[dp->N] = betsize;
            //if ( Debuglevel > 2 )
                printf("player.%d sends confirmturn.%d cardi.%d betsize %.0f\n",hn->client->H.slot,dp->hand.undergun,dp->hand.cardi,dstr(betsize));
            if ( senderind != 0 )
                pangea_sendcmd(hex,hn,"confirm",-1,(void *)dp->hand.snapshot,sizeof(uint64_t)*(dp->N+1),dp->hand.cardi,dp->hand.undergun);
        }
        if ( senderind == 0 && (turni= dp->hand.undergun) == pangea_ind(dp->table,hn->client->H.slot) )
        {
            if ( dp->hand.betsize != betsize )
                printf("P%d: pangea_turn warning hand.betsize %.8f != betsize %.8f\n",hn->client->H.slot,dstr(dp->hand.betsize),dstr(betsize));
            if ( sp->isbot[hn->client->H.slot] != 0 )
                pangea_bot(hn,dp,turni,cardi,betsize);
            else if ( dp->hand.betstatus[pangea_ind(dp->table,hn->client->H.slot)] == CARDS777_FOLD || dp->hand.betstatus[pangea_ind(dp->table,hn->client->H.slot)] == CARDS777_ALLIN )
                pangea_sendcmd(hex,hn,"action",-1,(void *)&amount,sizeof(amount),cardi,0);
            else if ( priv->autofold != 0 )
                pangea_sendcmd(hex,hn,"action",-1,(void *)&amount,sizeof(amount),cardi,0);
            else
            {
                dp->hand.userinput_starttime = (uint32_t)time(NULL);
                dp->hand.cardi = cardi;
                dp->hand.betsize = betsize;
                fprintf(stderr,"Waiting for user input cardi.%d: ",cardi);
            }
            if ( hn->client->H.slot == pangea_slotA(dp->table) )
            {
                char *str = jprint(pangea_tablestatus(sp),1);
                printf("%s\n",str);
                free(str);
            }
            //pangea_statusprint(dp,priv,pangea_ind(dp->table,hn->client->H.slot));
        }
    }
    return(0);
}

void pangea_sendsummary(union hostnet777 *hn,struct cards777_pubdata *dp,struct cards777_privdata *priv)
{
    char *hex;
    if ( (hex= malloc(dp->summarysize*2 + 4096)) != 0 )
    {
        pangea_sendcmd(hex,hn,"summary",-1,dp->summary,dp->summarysize,0,0);
        free(hex);
    }
}

int32_t pangea_gotsummary(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    char *otherhist,*handhist = 0; int32_t matched = 0; struct pangea_info *sp = dp->table;
    if ( Debuglevel > 2 ) // ordering changes crc
        printf("player.%d [%d]: got summary.%d from %d memcmp.%d\n",hn->client->H.slot,dp->summarysize,datalen,senderind,memcmp(data,dp->summary,datalen));
    if ( datalen == dp->summarysize )
    {
        if ( memcmp(dp->summary,data,datalen) == 0 )
        {
            //printf("P%d: matched senderind.%d\n",hn->client->H.slot,senderind);
            matched = 1;
        }
        else
        {
            if ( (handhist= pangea_dispsummary(sp,1,dp->summary,dp->summarysize,sp->tableid,dp->numhands-1,dp->N)) != 0 )
            {
                if ( (otherhist= pangea_dispsummary(sp,1,data,datalen,sp->tableid,dp->numhands-1,dp->N)) != 0 )
                {
                    if ( strcmp(handhist,otherhist) == 0 )
                    {
                        //printf("P%d: matched B senderind.%d\n",hn->client->H.slot,senderind);
                        matched = 1;
                    }
                    else printf("\n[%s] MISMATCHED vs \n[%s]\n",handhist,otherhist);
                    free(otherhist);
                } else printf("error getting otherhist\n");
                free(handhist);
            } else printf("error getting handhist\n");
        }
    }
    if ( matched != 0 )
        dp->summaries |= (1LL << senderind);
    else
    {
        //printf("P%d: MISMATCHED senderind.%d\n",hn->client->H.slot,senderind);
        dp->mismatches |= (1LL << senderind);
    }
    if ( senderind == 0 && hn->client->H.slot != pangea_slotA(dp->table) )
        pangea_sendsummary(hn,dp,priv);
    if ( (dp->mismatches | dp->summaries) == (1LL << dp->N)-1 )
    {
        if ( Debuglevel > 2 )
            printf("P%d: hand summary matches.%llx errors.%llx | size.%d\n",hn->client->H.slot,(long long)dp->summaries,(long long)dp->mismatches,dp->summarysize);
        //if ( handhist == 0 && (handhist= pangea_dispsummary(sp,1,dp->summary,dp->summarysize,sp->tableid,dp->numhands-1,dp->N)) != 0 )
        //    printf("HAND.(%s)\n",handhist), free(handhist);
        if ( hn->server->H.slot == 0 )
        {
            dp->mismatches = dp->summaries = 0;
            pangea_anotherhand(hn,dp,3);
        }
    }
    return(0);
}

void pangea_finish(union hostnet777 *hn,struct cards777_pubdata *dp)
{
    int32_t j,n,r,norake = 0; uint64_t sidepots[CARDS777_MAXPLAYERS][CARDS777_MAXPLAYERS],list[CARDS777_MAXPLAYERS],pangearake,rake; int64_t balances[CARDS777_MAXPLAYERS];
    uint32_t changes; uint16_t busted,rebuy; struct pangea_info *sp = dp->table;
    if ( dp->hand.finished == 0 )
    {
        memset(sidepots,0,sizeof(sidepots));
        n = pangea_sidepots(1,sidepots,dp,dp->hand.bets);
        if ( dp->hand.community[0] == 0xff )
            norake = 1;
        for (pangearake=rake=j=0; j<n; j++)
            rake += pangea_splitpot(dp->hand.won,&pangearake,sidepots[j],hn,norake == 0 ? dp->rakemillis : 0);
        dp->hostrake += rake;
        dp->pangearake += pangearake;
        dp->hand.hostrake = rake;
        dp->hand.pangearake = pangearake;
        dp->hand.finished = (uint32_t)time(NULL);
        for (j=busted=rebuy=r=0; j<dp->N; j++)
        {
            balances[j] = sp->balances[pangea_slot(sp,j)];
            //balances[j] += dp->hand.won[j];
            //sp->balances[pangea_slot(sp,j)] = balances[j];
            if ( dp->snapshot[pangea_slot(sp,j)] > 0 && balances[j] <= 0 )
            {
                busted |= (1 << j);
                list[r++] = sp->active[j];
            }
            else if ( dp->snapshot[pangea_slot(sp,j)] <= 0 && balances[j] > 0 )
                rebuy |= (1 << j);
        }
        changes = (((uint32_t)rebuy<<20) | ((uint32_t)busted<<4) | (dp->N&0xf));
        pangea_summary(hn,dp,CARDS777_CHANGES,(void *)&changes,sizeof(changes),(void *)balances,sizeof(uint64_t)*dp->N);
        pangea_summary(hn,dp,CARDS777_RAKES,(void *)&rake,sizeof(rake),(void *)&pangearake,sizeof(pangearake));
        if ( hn->client->H.slot == pangea_slotA(dp->table) )
        {
            char *sumstr,*statstr;
            statstr = jprint(pangea_tablestatus(dp->table),1);
            sumstr = pangea_dispsummary(dp->table,1,dp->summary,dp->summarysize,0,dp->numhands-1,dp->N);
            printf("%s\n\n%s",statstr,sumstr);
            free(statstr), free(sumstr);
            pangea_sendsummary(hn,dp,hn->client->H.privdata);
        }
        if ( 0 && busted != 0 )
        {
            for (j=0; j<r; j++)
            {
                if ( list[j] != sp->active[0] )
                {
                    pangea_inactivate(dp,sp,list[j]);
                    printf("T%d: INACTIVATE.[%d] %llu\n",sp->myslot,j,(long long)list[j]);
                }
            }
        }
    }
}

int32_t pangea_lastman(union hostnet777 *hn,struct cards777_pubdata *dp,struct cards777_privdata *priv)
{
    int32_t activej = -1; char hex[1024];
    if ( dp->hand.betstarted != 0 && pangea_actives(&activej,dp) <= 1 )
    {
        if ( dp->hand.finished != 0 )
        {
            printf("DUPLICATE LASTMAN!\n");
            return(1);
        }
        if ( 0 && hn->server->H.slot == activej && priv->automuck == 0 )
        {
            pangea_sendcmd(hex,hn,"faceup",-1,priv->holecards[0].bytes,sizeof(priv->holecards[0]),priv->cardis[0],priv->cardis[0] != 0xff);
            pangea_sendcmd(hex,hn,"faceup",-1,priv->holecards[1].bytes,sizeof(priv->holecards[1]),priv->cardis[1],priv->cardis[1] != 0xff);
        }
        pangea_finish(hn,dp);
        return(1);
    }
    return(0);
}

void pangea_startbets(union hostnet777 *hn,struct cards777_pubdata *dp,int32_t cardi)
{
    uint32_t now,i; char hex[1024];
    msleep(3000);
    if ( dp->hand.betstarted == 0 )
    {
        dp->hand.betstarted = 1;
    } else dp->hand.betstarted++;
    dp->hand.numactions = 0;
    dp->hand.cardi = cardi;
    now = (uint32_t)time(NULL);
    memset(dp->hand.actions,0,sizeof(dp->hand.actions));
    memset(dp->hand.turnis,0xff,sizeof(dp->hand.turnis));
    dp->hand.undergun = ((dp->button + 3) % dp->N);
    if ( cardi > dp->N*2 )
    {
        for (i=0; i<dp->N; i++)
            dp->hand.snapshot[i] = dp->hand.bets[i];
    }
    else pangea_checkantes(hn,dp);
    dp->hand.snapshot[dp->N] = dp->hand.betsize;
    printf("STARTBETS.%d cardi.%d numactions.%d undergun.%d betsize %.8f dp->N %d\n",dp->hand.betstarted,cardi,dp->hand.numactions,dp->hand.undergun,dstr(dp->hand.betsize),dp->N);
    pangea_sendcmd(hex,hn,"turn",-1,(void *)dp->hand.snapshot,sizeof(uint64_t)*(dp->N+1),cardi,dp->hand.undergun);
    /*for (i=0; i<dp->N; i++)
    {
        j = (dp->hand.undergun + i) % dp->N;
        if ( dp->hand.betstatus[j] != CARDS777_FOLD && dp->hand.betstatus[j] != CARDS777_ALLIN )
            break;
        dp->hand.numactions++;
    }
    if ( i != dp->N )
    {
        dp->hand.undergun = j;
        pangea_sendcmd(hex,hn,"turn",-1,(void *)dp->hand.snapshot,sizeof(uint64_t)*(dp->N+1),cardi,dp->hand.undergun);
    }
    else if ( pangea_lastman(hn,dp,hn->client->H.privdata) > 0 )
    {
        pangea_sendsummary(hn,dp,hn->client->H.privdata);
        return;
    } else printf("UNEXPECTED condition missing lastman\n");*/
}

int32_t pangea_action(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    uint32_t now; int32_t action,cardi,i,j,destplayer = 0; bits256 audit[CARDS777_MAXPLAYERS]; char hex[1024]; uint8_t tmp; uint64_t amount = 0;
    action = juint(json,"turni");
    cardi = juint(json,"cardi");
    memcpy(&amount,data,sizeof(amount));
    if ( cardi < 2*dp->N )
    {
        char *str = jprint(json,0);
        printf("pangea_action: illegal cardi.%d: (%s)\n",cardi,str);
        free(str);
    }
    if ( senderind != dp->hand.undergun )
    {
        printf("T%d: out of turn action.%d by player.%d (undergun.%d) cardi.%d amount %.8f\n",hn->client->H.slot,action,senderind,dp->hand.undergun,cardi,dstr(amount));
        return(-1);
    }
    tmp = senderind;
    pangea_bet(hn,dp,senderind,amount,CARDS777_CHECK);
    dp->hand.actions[senderind] = action;
    dp->hand.undergun = (dp->hand.undergun + 1) % dp->N;
    dp->hand.numactions++;
    if ( Debuglevel > 2 )//|| hn->client->H.slot == 0 )
        printf("player.%d: got action.%d cardi.%d senderind.%d -> undergun.%d numactions.%d\n",hn->client->H.slot,action,cardi,senderind,dp->hand.undergun,dp->hand.numactions);
    if ( pangea_lastman(hn,dp,priv) > 0 )
        return(0);
    if ( hn->client->H.slot == pangea_slotA(dp->table) )
    {
        now = (uint32_t)time(NULL);
        for (i=j=0; i<dp->N; i++)
        {
            j = (dp->hand.undergun + i) % dp->N;
            if ( dp->hand.betstatus[j] == CARDS777_FOLD || dp->hand.betstatus[j] == CARDS777_ALLIN )
            {
                dp->hand.actions[j] = dp->hand.betstatus[j];
                //printf("skip player.%d\n",j);
                dp->hand.numactions++;
            } else break;
        }
        dp->hand.undergun = j;
        if ( dp->hand.numactions < dp->N )
        {
            //printf("T%d: senderind.%d i.%d j.%d -> undergun.%d numactions.%d\n",hn->client->H.slot,senderind,i,j,dp->hand.undergun,dp->hand.numactions);
            //if ( senderind != 0 )
                pangea_sendcmd(hex,hn,"turn",-1,(void *)dp->hand.snapshot,sizeof(uint64_t)*(dp->N+1),dp->hand.cardi,dp->hand.undergun);
        }
        else
        {
            for (i=0; i<5; i++)
            {
                if ( dp->hand.community[i] == 0xff )
                    break;
                printf("%02x ",dp->hand.community[i]);
            }
            printf("COMMUNITY\n");
            if ( i == 0 )
            {
                if ( dp->hand.cardi != dp->N * 2 )
                    printf("cardi mismatch %d != %d\n",dp->hand.cardi,dp->N * 2);
                cardi = dp->hand.cardi;
                printf("decode flop\n");
                for (i=0; i<3; i++,cardi++)
                {
                    memset(audit,0,sizeof(audit));
                    audit[0] = dp->hand.final[cardi*dp->N + destplayer];
                    pangea_sendcmd(hex,hn,"decoded",-1,audit[0].bytes,sizeof(bits256)*dp->N,cardi,dp->N-1);
                }
            }
            else if ( i == 3 )
            {
                if ( dp->hand.cardi != dp->N * 2+3 )
                    printf("cardi mismatch %d != %d\n",dp->hand.cardi,dp->N * 2 + 3);
                cardi = dp->hand.cardi;
                printf("decode turn\n");
                memset(audit,0,sizeof(audit));
                audit[0] = dp->hand.final[cardi*dp->N + destplayer];
                pangea_sendcmd(hex,hn,"decoded",-1,audit[0].bytes,sizeof(bits256)*dp->N,cardi,dp->N-1);
                //pangea_sendcmd(hex,hn,"decoded",-1,dp->hand.final[cardi*dp->N + destplayer].bytes,sizeof(dp->hand.final[cardi*dp->N + destplayer]),cardi,dp->N-1);
            }
            else if ( i == 4 )
            {
                printf("decode river\n");
                if ( dp->hand.cardi != dp->N * 2+4 )
                    printf("cardi mismatch %d != %d\n",dp->hand.cardi,dp->N * 2+4);
                cardi = dp->hand.cardi;
                memset(audit,0,sizeof(audit));
                audit[0] = dp->hand.final[cardi*dp->N + destplayer];
                pangea_sendcmd(hex,hn,"decoded",-1,audit[0].bytes,sizeof(bits256)*dp->N,cardi,dp->N-1);
                //pangea_sendcmd(hex,hn,"decoded",-1,dp->hand.final[cardi*dp->N + destplayer].bytes,sizeof(dp->hand.final[cardi*dp->N + destplayer]),cardi,dp->N-1);
            }
            else
            {
                cardi = dp->N * 2 + 5;
                if ( dp->hand.cardi != dp->N * 2+5 )
                    printf("cardi mismatch %d != %d\n",dp->hand.cardi,dp->N * 2+5);
                for (i=0; i<dp->N; i++)
                {
                    j = (dp->hand.lastbettor + i) % dp->N;
                    if ( dp->hand.betstatus[j] != CARDS777_FOLD )
                        break;
                }
                dp->hand.undergun = j;
                printf("sent showdown request for undergun.%d\n",j);
                pangea_sendcmd(hex,hn,"showdown",-1,(void *)&dp->hand.betsize,sizeof(dp->hand.betsize),cardi,dp->hand.undergun);
            }
        }
    }
    if ( Debuglevel > 2 )// || hn->client->H.slot == 0 )
    {
        char *str = jprint(pangea_tablestatus(dp->table),1);
        printf("player.%d got pangea_action.%d for player.%d action.%d amount %.8f | numactions.%d\n%s\n",hn->client->H.slot,cardi,senderind,action,dstr(amount),dp->hand.numactions,str);
        free(str);
    }
    return(0);
}

int32_t pangea_myrank(struct cards777_pubdata *dp,int32_t senderind)
{
    int32_t i; uint32_t myrank = dp->hand.handranks[senderind];
    for (i=0; i<dp->N; i++)
        if ( i != senderind && dp->hand.handranks[i] > myrank )
            return(-1);
    return(myrank != 0);
}

int32_t pangea_showdown(union hostnet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    char hex[1024]; int32_t i,turni,cardi; uint64_t amount = 0;
    turni = juint(json,"turni");
    cardi = juint(json,"cardi");
    if ( Debuglevel > 2 )
        printf("P%d: showdown from sender.%d\n",hn->client->H.slot,senderind);
    if ( dp->hand.betstatus[pangea_ind(dp->table,hn->client->H.slot)] != CARDS777_FOLD && ((priv->automuck == 0 && dp->hand.actions[pangea_ind(dp->table,hn->client->H.slot)] != CARDS777_SENTCARDS) || (turni == pangea_ind(dp->table,hn->client->H.slot) && dp->hand.lastbettor == pangea_ind(dp->table,hn->client->H.slot))) )
    {
        if ( priv->automuck != 0 && pangea_myrank(dp,pangea_ind(dp->table,hn->client->H.slot)) < 0 )
            pangea_sendcmd(hex,hn,"action",-1,(void *)&amount,sizeof(amount),cardi,CARDS777_FOLD);
        else
        {
            pangea_sendcmd(hex,hn,"faceup",-1,priv->holecards[0].bytes,sizeof(priv->holecards[0]),priv->cardis[0],pangea_ind(dp->table,hn->client->H.slot));
            pangea_sendcmd(hex,hn,"faceup",-1,priv->holecards[1].bytes,sizeof(priv->holecards[1]),priv->cardis[1],pangea_ind(dp->table,hn->client->H.slot));
            dp->hand.actions[pangea_ind(dp->table,hn->client->H.slot)] = CARDS777_SENTCARDS;
        }
    }
    if ( pangea_lastman(hn,dp,priv) > 0 )
        return(0);
    if ( hn->client->H.slot == pangea_slotA(dp->table) && senderind != 0 )
    {
        for (i=0; i<dp->N; i++)
        {
            dp->hand.undergun = (dp->hand.undergun + 1) % dp->N;
            if ( dp->hand.undergun == dp->hand.lastbettor )
            {
                printf("all players queried with showdown handmask.%x finished.%u\n",dp->hand.handmask,dp->hand.finished);
                return(0);
            }
            if ( dp->hand.betstatus[dp->hand.undergun] != CARDS777_FOLD )
                break;
        }
        printf("senderind.%d host sends showdown for undergun.%d\n",senderind,dp->hand.undergun);
        pangea_sendcmd(hex,hn,"showdown",-1,(void *)&dp->hand.betsize,sizeof(dp->hand.betsize),cardi,dp->hand.undergun);
    }
    return(0);
}

char *pangea_input(uint64_t my64bits,uint64_t tableid,cJSON *json)
{
    char *actionstr; uint64_t sum,amount=0; int32_t action=0,num,threadid; struct pangea_info *sp; struct cards777_pubdata *dp; char hex[4096];
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
