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
    len += SuperNET_copybits(1,&summary[len],(void *)typep,sizeof(*typep));
    if ( *typep == 0 )
    {
        printf("len.%d type.%d [%d]\n",len,*typep,summary[len-1]);
        return(-1);
    }
    if ( *typep == CARDS777_START || *typep == CARDS777_SNAPSHOT )
        len += SuperNET_copybits(1,&summary[len],(void *)&handid,sizeof(handid)), *valAp = handid;
    else if ( *typep == CARDS777_CHANGES )
        len += SuperNET_copybits(1,&summary[len],(void *)&changes,sizeof(changes)), *valAp = changes;
    else if ( *typep == CARDS777_RAKES )
        len += SuperNET_copybits(1,&summary[len],(void *)valAp,sizeof(*valAp));
    else if ( *typep == CARDS777_FACEUP )
        len += SuperNET_copybits(1,&summary[len],(void *)&cardi_player,sizeof(cardi_player)), *valAp = cardi_player;
    else len += SuperNET_copybits(1,&summary[len],(void *)&player,sizeof(player)), *valAp = player;
    if ( *typep == CARDS777_FACEUP )
        len += SuperNET_copybits(1,&summary[len],cardp->bytes,sizeof(*cardp));
    else if ( *typep == CARDS777_START )
        len += SuperNET_copybits(1,&summary[len],(void *)bits64p,sizeof(bits256)*(CARDS777_MAXCARDS+1));
    else if ( *typep == CARDS777_SNAPSHOT )
        len += SuperNET_copybits(1,&summary[len],(void *)bits64p,sizeof(*bits64p) * CARDS777_MAXPLAYERS);
    else if ( *typep == CARDS777_CHANGES )
        len += SuperNET_copybits(1,&summary[len],(void *)bits64p,sizeof(*bits64p) * (changes & 0xf));
    else len += SuperNET_copybits(1,&summary[len],(void *)bits64p,sizeof(*bits64p));
    return(len);
}

char *pangea_dispsummary(struct supernet_info *myinfo,struct table_info *tp,int32_t verbose,uint8_t *summary,int32_t summarysize,bits256 tablehash,int32_t handid,int32_t numplayers)
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
        jaddbits256(json,"tablehash",tablehash);
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

void pangea_summaryadd(struct supernet_info *myinfo,struct table_info *tp,uint8_t type,void *arg0,int32_t size0,void *arg1,int32_t size1)
{
    uint64_t valA,bits64[CARDS777_MAXPLAYERS + (CARDS777_MAXCARDS+1)*4];
    bits256 card; uint8_t checktype; int32_t len,startlen = tp->summarysize;
    if ( type == 0 )
    {
        printf("type.0\n"); getchar();
    }
    //printf("summarysize.%d type.%d [%02x %02x]\n",dp->summarysize,type,*(uint8_t *)arg0,*(uint8_t *)arg1);
    tp->summarysize += SuperNET_copybits(0,&tp->summary[tp->summarysize],(void *)&type,sizeof(type));
    //printf("-> %d\n",tp->summary[tp->summarysize-1]);
    tp->summarysize += SuperNET_copybits(0,&tp->summary[tp->summarysize],arg0,size0);
    tp->summarysize += SuperNET_copybits(0,&tp->summary[tp->summarysize],arg1,size1);
    //printf("startlen.%d summarysize.%d\n",startlen,tp->summarysize);
    len = pangea_parsesummary(&checktype,&valA,bits64,&card,tp->summary,startlen);
    if ( len != tp->summarysize || checktype != type || memcmp(&valA,arg0,size0) != 0 )
        printf("pangea_summary parse error [%d] (%d vs %d) || (%d vs %d).%d || cmp.%d size0.%d size1.%d\n",startlen,len,tp->summarysize,checktype,type,tp->summary[startlen],memcmp(&valA,arg0,size0),size0,size1);
    if ( card.txid != 0 && memcmp(card.bytes,arg1,sizeof(card)) != 0 )
        printf("pangea_summary: parse error card mismatch %llx != %llx\n",(long long)card.txid,*(long long *)arg1);
    else if ( card.txid == 0 && memcmp(arg1,bits64,size1) != 0 )
        printf("pangea_summary: parse error bits64 %llx != %llx\n",(long long)bits64[0],*(long long *)arg0);
    /*if ( 1 && hn->client->H.slot == pangea_slotA(tp->table) )
     {
     if ( (item= pangea_handitem(&cardi,&pitem,type,valA,bits64,card,tp->G.N)) != 0 )
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
     }*/
    if ( Debuglevel > 2 )//|| hn->client->H.slot == pangea_slotA(tp->table) )
        printf("pangea_summary.%d %d | summarysize.%d crc.%u\n",type,*(uint8_t *)arg0,tp->summarysize,calc_crc32(0,tp->summary,tp->summarysize));
}

void pangea_summary(PANGEA_HANDARGS)
{
    char *otherhist,*handhist = 0; int32_t senderind,N,matched = 0; struct hand_info *hand = &tp->hand;
    senderind = pm->myind, N = tp->numactive;
    if ( Debuglevel > 2 ) // ordering changes crc
        printf("player.%d [%d]: got summary.%d from %d memcmp.%d\n",tp->priv.myind,tp->summarysize,datalen,senderind,memcmp(data,tp->summary,datalen));
    if ( datalen == tp->summarysize )
    {
        if ( memcmp(tp->summary,data,datalen) == 0 )
        {
            //printf("P%d: matched senderind.%d\n",priv->myslot,senderind);
            matched = 1;
        }
        else
        {
            if ( (handhist= pangea_dispsummary(myinfo,tp,1,tp->summary,tp->summarysize,tp->G.tablehash,tp->numhands-1,N)) != 0 )
            {
                if ( (otherhist= pangea_dispsummary(myinfo,tp,1,data,datalen,tp->G.tablehash,tp->numhands-1,N)) != 0 )
                {
                    if ( strcmp(handhist,otherhist) == 0 )
                    {
                        //printf("P%d: matched B senderind.%d\n",priv->myslot,senderind);
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
        hand->summaries |= (1LL << senderind);
    else
    {
        //printf("P%d: MISMATCHED senderind.%d\n",priv->myslot,senderind);
        hand->mismatches |= (1LL << senderind);
    }
    if ( senderind == 0 && tp->priv.myind != pangea_slotA(tp) )
        pangea_sendcmd(myinfo,tp,"summary",-1,tp->summary,tp->summarysize,0,0);
    if ( (hand->mismatches | hand->summaries) == (1LL << N)-1 )
    {
        if ( Debuglevel > 2 )
            printf("P%d: hand summary matches.%llx errors.%llx | size.%d\n",tp->priv.myind,(long long)hand->summaries,(long long)hand->mismatches,tp->summarysize);
        //if ( handhist == 0 && (handhist= pangea_dispsummary(sp,1,dp->summary,dp->summarysize,sp->tableid,dp->numhands-1,dp->N)) != 0 )
        //    printf("HAND.(%s)\n",handhist), free(handhist);
        if ( tp->priv.myind == 0 )
        {
            hand->mismatches = hand->summaries = 0;
            pangea_anotherhand(myinfo,tp,PANGEA_PAUSE);
        }
    }
}
