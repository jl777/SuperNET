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
        PNACL_message("pangea_nextnode: no next node from last node slot.%d ind.%d of numaddrs.%d numactive.%d\n",sp->myslot,sp->myind,sp->numaddrs,sp->numactive);
        return(-1);
    }
}

int32_t pangea_prevnode(struct pangea_info *sp)
{
    if ( sp->myind > 0 )
        return(sp->myind - 1);
    else
    {
        PNACL_message("pangea_prevnode: no prev node from node slot %d, ind.%d\n",sp->myslot,sp->myind);
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
        PNACL_message("pangea_neworder: neworder requires host nodeA to be first active node\n");
        return(-1);
    }
    slots[0] = 0;
    for (i=1; i<numactive; i++)
    {
        if ( (slots[i]= pangea_tableaddr(dp,active[i])) < 0 )
        {
            PNACL_message("cant find %llu in addrs[%d]\n",(long long)active[i],sp->numaddrs);
            return(-1);
        }
    }
    for (i=0; i<numactive; i++)
    {
        sp->active[i] = active[i];
        //PNACL_message("%llu ",(long long)sp->active[i]);
    }
    sp->numactive = dp->N = numactive;
    dp->M = (numactive >> 1) + 1;
    sp->myind = pangea_ind(sp,sp->myslot);
    //PNACL_message("T%d neworder.%d -> M.%d N.%d ind.%d\n",sp->myslot,sp->numactive,dp->M,dp->N,sp->myind);
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
        PNACL_message("pangea_inactivate: cant find %llu\n",(long long)nxt64bits);
    PNACL_message("T%d inactivate %llu n.%d\n",sp->myslot,(long long)nxt64bits,n);
    pangea_neworder(dp,sp,active,n);
    return(n);
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

void pangea_sendnewdeck(union pangeanet777 *hn,struct cards777_pubdata *dp)
{
    int32_t hexlen; bits256 destpub;
    hexlen = (int32_t)strlen(dp->newhand)+1;
    memset(destpub.bytes,0,sizeof(destpub));
    pangeanet777_msg(0,destpub,hn,0,dp->newhand,hexlen);
    dp->hand.startdecktime = (uint32_t)time(NULL);
    PNACL_message("pangea_sendnewdeck new deck at %u\n",dp->hand.startdecktime);
}

int32_t pangea_newdeck(union pangeanet777 *src)
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
    sprintf(dp->newhand,"{\"cmd\":\"%s\",\"active\":%s,\"sender\":\"%llu\",\"timestamp\":\"%lu\",\"n\":%u,\"data\":\"","newhand",str,(long long)src->client->H.nxt64bits,(long)time(NULL),len);
    free(str);
    n = (int32_t)strlen(dp->newhand);
    memcpy(data,dp->hand.cardpubs,len);
    init_hexbytes_noT(&dp->newhand[n],data,len);
    strcat(dp->newhand,"\"}");
    pangea_sendnewdeck(src,dp);
    PNACL_message("host sends NEWDECK checkprod.%llx numhands.%d\n",(long long)dp->hand.checkprod.txid,dp->numhands);
    return(0);
}

int32_t pangea_anotherhand(void *hn,struct cards777_pubdata *dp,int32_t sleepflag)
{
    int32_t i,n,activej = -1; uint64_t total = 0; struct pangea_info *sp = dp->table;
    for (i=n=0; i<sp->numaddrs; i++)
    {
        total += sp->balances[i];
        PNACL_message("(p%d %.8f) ",i,dstr(sp->balances[i]));
        if ( sp->balances[i] != 0 )
        {
            if ( activej < 0 )
                activej = i;
            n++;
        }
    }
    PNACL_message("balances %.8f [%.8f]\n",dstr(total),dstr(total + dp->hostrake + dp->pangearake));
    if ( n == 1 )
    {
        PNACL_message("Only player.%d left with %.8f | get sigs and cashout after numhands.%d\n",activej,dstr(sp->balances[pangea_slot(sp,activej)]),dp->numhands);
        sleep(60);
        return(1);
    }
    else
    {
        if ( sleepflag != 0 )
            sleep(sleepflag);
        //dp->hand.betstarted = 0;
        pangea_newdeck(hn);
        if ( sleepflag != 0 )
            sleep(sleepflag);
    }
    return(n);
}

int32_t _pangea_newhand(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    char hex[1024]; int32_t handid,m,i; uint64_t active[CARDS777_MAXPLAYERS]; cJSON *array; struct pangea_info *sp = dp->table;
    if ( data == 0 || datalen != (dp->numcards + 1) * sizeof(bits256) )
    {
        PNACL_message("pangea_newhand invalid datalen.%d vs %ld\n",datalen,(long)((dp->numcards + 1) * sizeof(bits256)));
        return(-1);
    }
    if ( hn->server->H.slot != 0 )
    {
        pangea_clearhand(dp,&dp->hand,priv);
        if ( (array= jarray(&m,json,"active")) != 0 )
        {
            //PNACL_message("T%d (%s)\n",sp->myslot,jprint(array,0));
            for (i=0; i<m; i++)
                active[i] = j64bits(jitem(array,i),0);
            pangea_neworder(dp,dp->table,active,m);
        } else pangea_neworder(dp,dp->table,0,0);
    }
    dp->button = (dp->numhands++ % dp->N);
    memcpy(dp->hand.cardpubs,data,(dp->numcards + 1) * sizeof(bits256));
    PNACL_message("player.%d NEWHAND.%llx received numhands.%d button.%d cardi.%d | dp->N %d\n",hn->client->H.slot,(long long)dp->hand.cardpubs[dp->numcards].txid,dp->numhands,dp->button,dp->hand.cardi,dp->N);
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

void pangea_checkstart(union pangeanet777 *hn,struct cards777_pubdata *dp,struct cards777_privdata *priv)
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
                sleep(PANGEA_PAUSE);
            dp->hand.encodestarted = (uint32_t)time(NULL);
            PNACL_message("SERVERSTATE issues encoded %llx\n",(long long)dp->hand.checkprod.txid);
            pangea_sendcmd(dp->newhand,hn,"encoded",pangea_slotB(dp->table),priv->outcards[0].bytes,sizeof(bits256)*dp->N*dp->numcards,dp->N*dp->numcards,-1);
        }
    }
}

int32_t _pangea_gotdeck(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    int32_t i,slot; uint64_t total = 0; struct pangea_info *sp = dp->table;
    dp->hand.othercardpubs[senderind] = *(uint64_t *)data;
    if ( Debuglevel > 2 )
    {
        for (i=0; i<dp->N; i++)
        {
            slot = pangea_slot(sp,i);
            total += sp->balances[slot];
            PNACL_message("(p%d %.8f) ",i,dstr(sp->balances[slot]));
        }
        PNACL_message("balances %.8f [%.8f] | ",dstr(total),dstr(total + dp->hostrake + dp->pangearake));
        PNACL_message("player.%d pangea_gotdeck from P.%d otherpubs.%llx\n",hn->client->H.slot,senderind,(long long)dp->hand.othercardpubs[senderind]);
    }
    pangea_checkstart(hn,dp,priv);
    return(0);
}

int32_t _pangea_ready(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    int32_t create_MofN(uint8_t addrtype,char *redeemScript,char *scriptPubKey,char *p2shaddr,char *pubkeys[],int32_t M,int32_t N);
    char hex[4096],hexstr[67],*pubkeys[CARDS777_MAXPLAYERS]; struct pangea_info *sp = dp->table;
    uint8_t addrtype; int32_t i,slot,retval = -1; struct iguana_info *coin = 0;
    slot = pangea_slot(sp,senderind);
    dp->readymask |= (1 << slot);
    if ( (coin= iguana_coinfind(dp->coinstr)) != 0 )
        addrtype = coin->chain->pubval;//coin777_addrtype(&p2shtype,dp->coinstr);
    else return(-1);
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
        retval = create_MofN(coin->chain->p2shval,sp->redeemScript,sp->scriptPubKey,sp->multisigaddr,pubkeys,dp->M,dp->N);
        PNACL_message("retval.%d scriptPubKey.(%s) multisigaddr.(%s) redeemScript.(%s)\n",retval,sp->scriptPubKey,sp->multisigaddr,sp->redeemScript);
    }
    PNACL_message("player.%d got ready from senderind.%d slot.%d readymask.%x btcpubkey.(%s) (%s) wip.(%s)\n",hn->client->H.slot,senderind,slot,dp->readymask,hexstr,sp->coinaddrs[slot],sp->wipstr);
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

int32_t _pangea_card(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t cardi,int32_t senderind)
{
    int32_t destplayer,card,selector,validcard = -1; bits256 cardpriv,audit[CARDS777_MAXPLAYERS]; char hex[1024],cardAstr[8],cardBstr[8]; struct pangea_info *sp = dp->table;
    if ( data == 0 || datalen != sizeof(bits256)*dp->N )
    {
        PNACL_message("pangea_card invalid datalen.%d vs %ld\n",datalen,(long)sizeof(bits256)*dp->N);
        return(-1);
    }
    //PNACL_message("pangea_card priv.%llx\n",(long long)hn->client->H.privkey.txid);
    destplayer = juint(json,"dest");
    pangea_rwaudit(1,(void *)data,priv->audits,cardi,destplayer,dp->N);
    pangea_rwaudit(0,audit,priv->audits,cardi,destplayer,dp->N);
    //PNACL_message("card.%d destplayer.%d [%llx]\n",cardi,destplayer,(long long)audit[0].txid);
    if ( (card= cards777_checkcard(&cardpriv,cardi,pangea_ind(dp->table,hn->client->H.slot),destplayer,hn->client->H.privkey,dp->hand.cardpubs,dp->numcards,audit[0])) >= 0 )
    {
        destplayer = pangea_ind(dp->table,hn->client->H.slot);
        if ( Debuglevel > 2 )
            PNACL_message("player.%d got card.[%d]\n",hn->client->H.slot,card);
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
        PNACL_message(">>>>>>>>>> dest.%d priv.%p holecards[%02d] cardi.%d / dp->N %d (%02d %02d) -> (%s %s)\n",destplayer,priv,priv->hole[cardi / dp->N],cardi,dp->N,priv->hole[0],priv->hole[1],cardAstr,cardBstr);
        if ( cards777_validate(cardpriv,dp->hand.final[cardi*dp->N + destplayer],dp->hand.cardpubs,dp->numcards,audit,dp->N,sp->playerpubs[hn->client->H.slot]) < 0 )
            PNACL_message("player.%d decoded cardi.%d card.[%02d] but it doesnt validate\n",hn->client->H.slot,cardi,card);
    } else PNACL_message("ERROR player.%d got no card %llx\n",hn->client->H.slot,*(long long *)data);
    if ( cardi < dp->N*2 )
        pangea_sendcmd(hex,hn,"facedown",-1,(void *)&cardi,sizeof(cardi),cardi,validcard);
    else pangea_sendcmd(hex,hn,"faceup",-1,cardpriv.bytes,sizeof(cardpriv),cardi,0xff);
    return(0);
}

int32_t _pangea_decoded(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    int32_t cardi,destplayer,card,turni; bits256 cardpriv,audit[CARDS777_MAXPLAYERS]; char hex[1024]; struct pangea_info *sp = dp->table;
    if ( data == 0 || datalen != sizeof(bits256)*dp->N )
    {
        PNACL_message("pangea_decoded invalid datalen.%d vs %ld\n",datalen,(long)sizeof(bits256));
        return(-1);
    }
    cardi = juint(json,"cardi");
    turni = juint(json,"turni");
    if ( cardi < dp->N*2 || cardi >= dp->N*2 + 5 )
    {
        PNACL_message("pangea_decoded invalid cardi.%d\n",cardi);
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
            //PNACL_message("player.%d decoded cardi.%d %llx -> %llx\n",hn->client->H.slot,cardi,(long long)priv->incards[cardi*dp->N + destplayer].txid,(long long)decoded.txid);
        }
        else
        {
            if ( (card= cards777_checkcard(&cardpriv,cardi,pangea_ind(dp->table,hn->client->H.slot),pangea_ind(dp->table,hn->client->H.slot),hn->client->H.privkey,dp->hand.cardpubs,dp->numcards,audit[0])) >= 0 )
            {
                if ( cards777_validate(cardpriv,dp->hand.final[cardi*dp->N + destplayer],dp->hand.cardpubs,dp->numcards,audit,dp->N,sp->playerpubs[hn->client->H.slot]) < 0 )
                    PNACL_message("player.%d decoded cardi.%d card.[%d] but it doesnt validate\n",hn->client->H.slot,cardi,card);
                pangea_sendcmd(hex,hn,"faceup",-1,cardpriv.bytes,sizeof(cardpriv),cardi,cardpriv.txid!=0?0xff:-1);
                //PNACL_message("-> FACEUP.(%s)\n",hex);
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
    //PNACL_message("zlen %d to len2 %d\n",len,len2);
    //free(tmp);
   return(len2);
}

int32_t _pangea_preflop(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    char *hex,*zbuf; int32_t i,card,len,iter,cardi,destplayer,maxlen = (int32_t)(2 * CARDS777_MAXPLAYERS * CARDS777_MAXPLAYERS * CARDS777_MAXCARDS * sizeof(bits256));
    bits256 cardpriv,audit[CARDS777_MAXPLAYERS]; struct pangea_info *sp = dp->table;
    if ( data == 0 || datalen != (2 * dp->N) * (dp->N * dp->N * sizeof(bits256)) || (hex= malloc(maxlen)) == 0 )
    {
        PNACL_message("pangea_preflop invalid datalen.%d vs %ld\n",datalen,(long)(2 * dp->N) * (dp->N * dp->N * sizeof(bits256)));
        return(-1);
    }
    //PNACL_message("preflop player.%d\n",hn->client->H.slot);
    //memcpy(priv->incards,data,datalen);
    memcpy(priv->audits,data,datalen);
    if ( hn->client->H.slot != pangea_slotA(dp->table) && hn->client->H.slot != pangea_slotB(dp->table) )
    {
        //for (i=0; i<dp->numcards*dp->N; i++)
        //    PNACL_message("%llx ",(long long)priv->outcards[i].txid);
        //PNACL_message("player.%d outcards\n",hn->client->H.slot);
        for (cardi=0; cardi<dp->N*2; cardi++)
            for (destplayer=0; destplayer<dp->N; destplayer++)
            {
                pangea_rwaudit(0,audit,priv->audits,cardi,destplayer,dp->N);
                if ( 0 && (card= cards777_checkcard(&cardpriv,cardi,pangea_ind(dp->table,hn->client->H.slot),destplayer,hn->client->H.privkey,dp->hand.cardpubs,dp->numcards,audit[0])) >= 0 )
                    PNACL_message("ERROR: unexpected decode player.%d got card.[%d]\n",hn->client->H.slot,card);
                audit[0] = cards777_decode(&audit[sp->myind],priv->xoverz,destplayer,audit[0],priv->outcards,dp->numcards,dp->N);
                pangea_rwaudit(1,audit,priv->audits,cardi,destplayer,dp->N);
            }
        //PNACL_message("issue preflop\n");
        if ( (zbuf= calloc(1,datalen*2+1)) != 0 )
        {
            //init_hexbytes_noT(zbuf,priv->audits[0].bytes,datalen);
            //PNACL_message("STARTZBUF.(%s)\n",zbuf);
            len = pangea_zbuf(zbuf,priv->audits[0].bytes,datalen);
            {
                int32_t len2;
                len2 = pangea_unzbuf((void *)hex,zbuf,len);
                if ( len2 != datalen || memcmp(hex,priv->audits[0].bytes,datalen) != 0 )
                {
                    if ( calc_crc32(0,(void *)hex,datalen) != calc_crc32(0,priv->audits[0].bytes,datalen) )
                    {
                        PNACL_message("zbuf error len2.%d vs datalen.%d crcs %u vs %u\n%s\n",len2,datalen,calc_crc32(0,(void *)hex,datalen),calc_crc32(0,priv->audits[0].bytes,datalen),hex);
                        getchar();
                    }
                }
            }
            //PNACL_message("datalen.%d -> len.%d zbuf %ld\n",datalen,len,(long)strlen(zbuf));
            pangea_sendcmd(hex,hn,"preflop",pangea_prevnode(dp->table),(void *)zbuf,len,dp->N * 2 * dp->N,-1);
            free(zbuf);
        }
    }
    else
    {
        //PNACL_message("sendout cards\n");
        for (iter=cardi=0; iter<2; iter++)
            for (i=0; i<dp->N; i++,cardi++)
            {
                destplayer = (dp->button + i) % dp->N;
                pangea_rwaudit(0,audit,priv->audits,cardi,destplayer,dp->N);
                //PNACL_message("audit[0] %llx -> ",(long long)audit[0].txid);
                audit[0] = cards777_decode(&audit[sp->myind],priv->xoverz,destplayer,audit[0],priv->outcards,dp->numcards,dp->N);
                pangea_rwaudit(1,audit,priv->audits,cardi,destplayer,dp->N);
                //PNACL_message("[%llx + %llx] ",*(long long *)&audit[0],(long long)&audit[pangea_ind(dp->table,hn->client->H.slot)]);
                if ( destplayer == pangea_ind(dp->table,hn->client->H.slot) )
                    _pangea_card(hn,json,dp,priv,audit[0].bytes,sizeof(bits256)*dp->N,cardi,destplayer);
                else pangea_sendcmd(hex,hn,"card",destplayer,audit[0].bytes,sizeof(bits256)*dp->N,cardi,-1);
            }
    }
    free(hex);
    return(0);
}

int32_t _pangea_encoded(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    char *hex; bits256 audit[CARDS777_MAXPLAYERS]; int32_t i,iter,cardi,destplayer; struct pangea_info *sp = dp->table;
    if ( data == 0 || datalen != (dp->numcards * dp->N) * sizeof(bits256) )
    {
        PNACL_message("pangea_encode invalid datalen.%d vs %ld\n",datalen,(long)((dp->numcards * dp->N) * sizeof(bits256)));
        return(-1);
    }
    cards777_encode(priv->outcards,priv->xoverz,priv->allshares,priv->myshares,dp->hand.sharenrs[pangea_ind(dp->table,hn->client->H.slot)],dp->M,(void *)data,dp->numcards,dp->N);
    //int32_t i; for (i=0; i<dp->numcards*dp->N; i++)
    //    PNACL_message("%llx ",(long long)priv->outcards[i].txid);
    PNACL_message("player.%d ind.%d encodes into %p %llx -> %llx next.%d dp->N %d\n",hn->client->H.slot,pangea_ind(sp,hn->client->H.slot),priv->outcards,(long long)*(uint64_t *)data,(long long)priv->outcards[0].txid,pangea_nextnode(sp),dp->N);
    if ( pangea_ind(sp,hn->client->H.slot) > 0 && (hex= malloc(65536)) != 0 )
    {
        if ( pangea_ind(sp,hn->client->H.slot) < sp->numactive-1 )
        {
            //PNACL_message("send encoded\n");
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
            PNACL_message("call preflop %ld\n",(long)((2 * dp->N) * (dp->N * dp->N * sizeof(bits256))));
            _pangea_preflop(hn,json,dp,priv,priv->audits[0].bytes,(2 * dp->N) * (dp->N * dp->N * sizeof(bits256)),pangea_ind(sp,hn->client->H.slot));
        }
        free(hex);
    }
    return(0);
}

int32_t _pangea_final(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    if ( data == 0 || datalen != (dp->numcards * dp->N) * sizeof(bits256) )
    {
        PNACL_message("pangea_final invalid datalen.%d vs %ld\n",datalen,(long)((dp->numcards * dp->N) * sizeof(bits256)));
        return(-1);
    }
    if ( Debuglevel > 2 )
        PNACL_message("player.%d final into %p\n",hn->client->H.slot,priv->outcards);
    memcpy(dp->hand.final,data,sizeof(bits256) * dp->N * dp->numcards);
    return(0);
}

int32_t _pangea_facedown(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t cardi,int32_t senderind)
{
    int32_t i,validcard,n = 0;
    if ( data == 0 || datalen != sizeof(int32_t) )
    {
        PNACL_message("pangea_facedown invalid datalen.%d vs %ld\n",datalen,(long)sizeof(bits256));
        return(-1);
    }
    validcard = juint(json,"turni");
    if ( validcard > 0 )
        dp->hand.havemasks[senderind] |= (1LL << cardi);
    for (i=0; i<dp->N; i++)
    {
        if ( Debuglevel > 2 )
            PNACL_message("%llx ",(long long)dp->hand.havemasks[i]);
        if ( bitweight(dp->hand.havemasks[i]) == 2 )
            n++;
    }
    if ( Debuglevel > 2 )
        PNACL_message(" | player.%d sees that destplayer.%d got cardi.%d valid.%d | %llx | n.%d\n",hn->client->H.slot,senderind,cardi,validcard,(long long)dp->hand.havemasks[senderind],n);
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
        PNACL_message("sender.%d (%s) rank.%x handmask.%x\n",senderind,handstr,dp->hand.handranks[senderind],dp->hand.handmask);
    }
    return(dp->hand.handranks[senderind]);
}

int32_t _pangea_faceup(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    int32_t cardi,validcard,i; char hexstr[65]; uint16_t tmp;
    if ( data == 0 || datalen != sizeof(bits256) )
    {
        PNACL_message("pangea_faceup invalid datalen.%d vs %ld\n",datalen,(long)((dp->numcards + 1) * sizeof(bits256)));
        return(-1);
    }
    init_hexbytes_noT(hexstr,data,sizeof(bits256));
    cardi = juint(json,"cardi");
    validcard = ((int32_t)juint(json,"turni")) >= 0;
    if ( Debuglevel > 2 || hn->client->H.slot == pangea_slotA(dp->table) )
    {
        char *str = jprint(json,0);
        PNACL_message("from.%d -> player.%d COMMUNITY.[%d] (%s) cardi.%d valid.%d (%s)\n",senderind,hn->client->H.slot,data[1],hexstr,cardi,validcard,str);
        free(str);
    }
    //PNACL_message("got FACEUP.(%s)\n",jprint(json,0));
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
            
            //PNACL_message("set community[%d] <- %d\n",cardi - dp->N*2,data[1]);
            if ( senderind == pangea_ind(dp->table,hn->client->H.slot) )
                pangea_rank(dp,senderind);
            //PNACL_message("calc rank\n");
            if ( hn->client->H.slot == pangea_slotA(dp->table) && cardi >= dp->N*2+2 && cardi < dp->N*2+5 )
                pangea_startbets(hn,dp,cardi+1);
            //else PNACL_message("dont start bets %d\n",cardi+1);
        }
        else
        {
            //PNACL_message("valid.%d cardi.%d vs N.%d\n",validcard,cardi,dp->N);
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

int32_t _pangea_turn(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
{
    int32_t turni,cardi,i; char hex[2048]; uint64_t betsize = 0; struct pangea_info *sp = dp->table;
    turni = juint(json,"turni");
    cardi = juint(json,"cardi");
    if ( Debuglevel > 2 )
        printf("P%d: got turn.%d from %d | cardi.%d summary[%d] crc.%u\n",hn->server->H.slot,turni,senderind,cardi,dp->summarysize,calc_crc32(0,dp->summary,dp->summarysize));
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
            pangea_sendcmd(hex,hn,"confirmturn",-1,(void *)dp->hand.snapshot,sizeof(uint64_t)*(dp->N+1),cardi,turni);
        }
    }
    return(0);
}

int32_t _pangea_confirmturn(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
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
                pangea_sendcmd(hex,hn,"confirmturn",-1,(void *)dp->hand.snapshot,sizeof(uint64_t)*(dp->N+1),dp->hand.cardi,dp->hand.undergun);
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

void pangea_sendsummary(union pangeanet777 *hn,struct cards777_pubdata *dp,struct cards777_privdata *priv)
{
    char *hex;
    if ( (hex= malloc(dp->summarysize*2 + 4096)) != 0 )
    {
        pangea_sendcmd(hex,hn,"summary",-1,dp->summary,dp->summarysize,0,0);
        free(hex);
    }
}

int32_t _pangea_gotsummary(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
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

void pangea_finish(union pangeanet777 *hn,struct cards777_pubdata *dp)
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

int32_t pangea_lastman(union pangeanet777 *hn,struct cards777_pubdata *dp,struct cards777_privdata *priv)
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

void pangea_startbets(union pangeanet777 *hn,struct cards777_pubdata *dp,int32_t cardi)
{
    uint32_t now,i; char hex[1024];
    sleep(3);
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

int32_t _pangea_action(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
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

int32_t _pangea_showdown(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
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

char *_pangea_input(uint64_t my64bits,uint64_t tableid,cJSON *json)
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

int32_t _pangea_ping(union pangeanet777 *hn,cJSON *json,struct cards777_pubdata *dp,struct cards777_privdata *priv,uint8_t *data,int32_t datalen,int32_t senderind)
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
    //PNACL_message("player.%d GOTPING.(%s) %llx\n",hn->client->H.slot,jprint(json,0),(long long)dp->othercardpubs[senderind]);
    return(0);
}

void p_angea_chat(uint64_t senderbits,void *buf,int32_t len,int32_t senderind)
{
    PNACL_message(">>>>>>>>>>> CHAT FROM.%d %llu: (%s)\n",senderind,(long long)senderbits,(char *)buf);
}

int32_t pangea_poll(uint64_t *senderbitsp,uint32_t *timestampp,union pangeanet777 *hn)
{
    char *jsonstr,*hexstr,*cmdstr; cJSON *json; struct cards777_privdata *priv; struct cards777_pubdata *dp; struct pangea_info *sp;
    int32_t len,senderind,maxlen; uint8_t *buf;
    *senderbitsp = 0;
    dp = hn->client->H.pubdata, sp = dp->table;
    priv = hn->client->H.privdata;
    if ( hn == 0 || hn->client == 0 || dp == 0 || priv == 0 )
    {
        if ( Debuglevel > 2 )
            PNACL_message("pangea_poll: null hn.%p %p dp.%p priv.%p\n",hn,hn!=0?hn->client:0,dp,priv);
        return(-1);
    }
    maxlen = (int32_t)(sizeof(bits256) * dp->N*dp->N*dp->numcards);
    if ( (buf= malloc(maxlen)) == 0 )
    {
        PNACL_message("pangea_poll: null buf\n");
        return(-1);
    }
    if ( dp != 0 && priv != 0 && (jsonstr= queue_dequeue(&hn->client->H.Q,1)) != 0 )
    {
        //pangea_neworder(dp,dp->table,0,0);
        //PNACL_message("player.%d GOT.(%s)\n",hn->client->H.slot,jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            *senderbitsp = j64bits(json,"sender");
            if ( (senderind= juint(json,"myind")) < 0 || senderind >= dp->N )
            {
                PNACL_message("pangea_poll: illegal senderind.%d cardi.%d turni.%d (%s)\n",senderind,juint(json,"cardi"),juint(json,"turni"),jsonstr);
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
                    PNACL_message("len too big for pangea_poll\n");
                    goto cleanup;
                }
                decode_hex(buf,len,hexstr);
            } else if ( hexstr != 0 )
                PNACL_message("len.%d vs hexlen.%ld (%s)\n",len,(long)(strlen(hexstr)>>1),hexstr);
            if ( cmdstr != 0 )
            {
                if ( strcmp(cmdstr,"newhand") == 0 )
                    _pangea_newhand(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"ping") == 0 )
                    _pangea_ping(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"gotdeck") == 0 )
                    _pangea_gotdeck(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"ready") == 0 )
                    _pangea_ready(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"encoded") == 0 )
                    _pangea_encoded(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"final") == 0 )
                    _pangea_final(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"addfunds") == 0 )
                    _pangea_addfunds(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"preflop") == 0 )
                    _pangea_preflop(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"decoded") == 0 )
                    _pangea_decoded(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"card") == 0 )
                    _pangea_card(hn,json,dp,priv,buf,len,juint(json,"cardi"),senderind);
                else if ( strcmp(cmdstr,"facedown") == 0 )
                    _pangea_facedown(hn,json,dp,priv,buf,len,juint(json,"cardi"),senderind);
                else if ( strcmp(cmdstr,"faceup") == 0 )
                    _pangea_faceup(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"turn") == 0 )
                    _pangea_turn(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"confirmturn") == 0 )
                    _pangea_confirmturn(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"chat") == 0 )
                    _pangea_chat(*senderbitsp,buf,len,senderind);
                else if ( strcmp(cmdstr,"action") == 0 )
                    _pangea_action(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"showdown") == 0 )
                    _pangea_showdown(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"summary") == 0 )
                    _pangea_gotsummary(hn,json,dp,priv,buf,len,senderind);
            }
        cleanup:
            free_json(json);
        }
        free_queueitem(jsonstr);
    }
    free(buf);
    return(hn->client->H.state);
}

void pangea_serverstate(union pangeanet777 *hn,struct cards777_pubdata *dp,struct cards777_privdata *priv)
{
    int32_t i,j,n; struct pangea_info *sp = dp->table;
    if ( dp->hand.finished != 0 && time(NULL) > dp->hand.finished+PANGEA_HANDGAP )
    {
        PNACL_message("HANDGAP\n");
        pangea_anotherhand(hn,dp,3);
    }
    if ( dp->hand.betstarted == 0 && dp->newhand[0] == 0 )
    {
        static uint32_t disptime;
        for (i=n=0; i<dp->N; i++)
        {
            if ( Debuglevel > 2 )
                PNACL_message("%llx ",(long long)dp->hand.havemasks[i]);
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
                    PNACL_message("send newdeck len.%ld\n",(long)strlen(dp->newhand));
                    pangea_newdeck(hn);
                    PNACL_message("sent newdeck %ld\n",(long)strlen(dp->newhand));
                }
            }
            else if ( disptime != time(NULL) && (time(NULL) % 60) == 0 )
            {
                disptime = (uint32_t)time(NULL);
                for (j=0; j<dp->N; j++)
                    PNACL_message("%.8f ",dstr(sp->balances[pangea_slot(sp,i)]));
                PNACL_message("no buyin for %d (%.8f %.8f)\n",i,dstr(dp->minbuyin*dp->bigblind),dstr(dp->maxbuyin*dp->bigblind));
            }
        }
    }
    else pangea_checkstart(hn,dp,priv);
}

int32_t pangea_idle(struct supernet_info *plugin)
{
    int32_t i,n,m,pinggap = 1; uint64_t senderbits; uint32_t timestamp; struct pangea_thread *tp; union pangeanet777 *hn;
    struct cards777_pubdata *dp; char hex[1024];
    while ( 1 )
    {
        for (i=n=m=0; i<_PANGEA_MAXTHREADS; i++)
        {
            if ( (tp= THREADS[i]) != 0 )
            {
                hn = &tp->hn;
            //PNACL_message("pangea idle player.%d\n",hn->client->H.slot);
                if ( hn->client->H.done == 0 )
                {
                    n++;
                    if ( pangeanet777_idle(hn) != 0 )
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
                            PNACL_message("P%d: all players folded or showed cards at %ld | rakemillis %d\n",hn->client->H.slot,(long)time(NULL),dp->rakemillis);
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
            usleep(3000);
    }
    //for (i=0; i<_PANGEA_MAXTHREADS; i++)
    //    if ( THREADS[i] != 0 && Pangea_waiting != 0 )
    //        pangea_userpoll(&THREADS[i]->hn);
    return(0);
}
