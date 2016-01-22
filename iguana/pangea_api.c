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

//struct acct777_sig { bits256 sigbits,pubkey; uint64_t signer64bits; uint32_t timestamp; };

struct pangea_msghdr
{
    struct acct777_sig sig __attribute__((packed));
} __attribute__((packed));

cJSON *pangea_lobbyjson(struct supernet_info *myinfo)
{
    cJSON *retjson = cJSON_CreateObject();
    return(retjson);
}

int32_t pangea_updatemsg(struct supernet_info *myinfo,struct pangea_msghdr *pm,int32_t len)
{
    return(0);
}

int32_t pangea_validate(struct pangea_msghdr *pm,bits256 privkey,bits256 pubkey)
{
    uint64_t signerbits;
    if ( (signerbits= acct777_validate(&pm->sig,privkey,pubkey)) != 0 )
    {
        return(0);
    }
    return(-1);
}

struct pangea_msghdr *pangea_msgcreate(struct supernet_info *myinfo,uint8_t *space,bits256 tablehash,uint8_t *serialized,int32_t datalen)
{
    bits256 otherpubkey; uint32_t timestamp; struct pangea_msghdr *pm = (struct pangea_msghdr *)space;
    memset(pm,0,sizeof(*pm));
    otherpubkey = acct777_msgpubkey(serialized,datalen);
    if ( datalen > 0 )
        memcpy(pm->sig.serialized,serialized,datalen);
    timestamp = (uint32_t)time(NULL);
    acct777_sign(&pm->sig,myinfo->privkey,otherpubkey,timestamp,serialized,datalen);
    if ( pangea_validate(pm,acct777_msgprivkey(serialized,datalen),pm->sig.pubkey) == 0 )
        return(pm);
    else printf("error validating pangea msg\n");
    return(0);
}

void pangea_update(struct supernet_info *myinfo)
{
    struct category_msg *m; bits256 pangeahash;
    pangeahash = calc_categoryhashes(0,"pangea",0);
    while ( (m= category_gethexmsg(myinfo,pangeahash,GENESIS_PUBKEY)) != 0 )
    {
        pangea_updatemsg(myinfo,(struct pangea_msghdr *)m->msg,m->len);
        free(m);
    }
}

void pangea_sendcmd(char *hex,union pangeanet777 *hn,char *cmdstr,int32_t destplayer,uint8_t *data,int32_t datalen,int32_t cardi,int32_t turni)
{
    int32_t n,hexlen,blindflag = 0; uint64_t destbits; bits256 destpub; cJSON *json; char hoststr[1024]; struct pangea_info *sp;
    struct cards777_pubdata *dp = hn->client->H.pubdata;
    hoststr[0] = 0;
    sp = dp->table;
    sprintf(hex,"{\"cmd\":\"%s\",\"turni\":%d,\"myslot\":%d,\"myind\":%d,\"cardi\":%d,\"dest\":%d,\"sender\":\"%llu\",\"timestamp\":\"%lu\",\"n\":%u,%s\"data\":\"",cmdstr,turni,hn->client->H.slot,pangea_ind(dp->table,hn->client->H.slot),cardi,destplayer,(long long)hn->client->H.nxt64bits,(long)time(NULL),datalen,hoststr);
    n = (int32_t)strlen(hex);
    if ( strcmp(cmdstr,"preflop") == 0 )
    {
        memcpy(&hex[n],data,datalen+1);
        hexlen = (int32_t)strlen(hex)+1;
        PNACL_message("P%d HEX.[] hexlen.%d n.%d\n",hn->server->H.slot,hexlen,datalen);
    }
    else if ( data != 0 && datalen != 0 )
        init_hexbytes_noT(&hex[n],data,datalen);
    strcat(hex,"\"}");
    if ( (json= cJSON_Parse(hex)) == 0 )
    {
        PNACL_message("error creating json\n");
        return;
    }
    free_json(json);
    hexlen = (int32_t)strlen(hex)+1;
    //PNACL_message("HEX.[%s] hexlen.%d n.%d\n",hex,hexlen,datalen);
    if ( destplayer < 0 )//|| ((1LL << destplayer) & dp->pmworks) == 0 )
    {
        destbits = 0;
        memset(destpub.bytes,0,sizeof(destpub));
        //PNACL_message("T%d broadcasts %d\n",hn->client->H.slot,hexlen);
    }
    else
    {
        destpub = sp->playerpubs[pangea_slot(sp,destplayer)];
        destbits = acct777_nxt64bits(destpub);
        //PNACL_message("T%d sends %d to dest.%d\n",hn->client->H.slot,hexlen,destplayer);
    }
    pangeanet777_msg(destbits,destpub,hn,blindflag,hex,hexlen);
}

char *_pangea_status(uint64_t my64bits,uint64_t tableid,cJSON *json)
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

/*int32_t pangea_idle(struct supernet_info *plugin)
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
}*/

char *_pangea_history(uint64_t my64bits,uint64_t tableid,cJSON *json)
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

char *_pangea_buyin(uint64_t my64bits,uint64_t tableid,cJSON *json)
{
    struct pangea_info *sp; uint32_t buyin,vout; uint64_t amount = 0; char hex[1024],jsonstr[1024],*txidstr,*destaddr;
    if ( (sp= pangea_find64(tableid,my64bits)) != 0 && sp->dp != 0 && sp->tp != 0 && (amount= j64bits(json,"amount")) != 0 )
    {
        buyin = (uint32_t)(amount / sp->dp->bigblind);
        PNACL_message("buyin.%u amount %.8f -> %.8f\n",buyin,dstr(amount),dstr(buyin * sp->bigblind));
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
            PNACL_message("buyin.%d vs (%d %d)\n",buyin,sp->dp->minbuyin,sp->dp->maxbuyin);
            return(clonestr("{\"error\":\"buyin too small or too big\"}"));
        }
    }
    return(clonestr("{\"error\":\"cant buyin unless you are part of the table\"}"));
}

char *_pangea_mode(uint64_t my64bits,uint64_t tableid,cJSON *json)
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

void _pangea_chat(uint64_t senderbits,void *buf,int32_t len,int32_t senderind)
{
    PNACL_message(">>>>>>>>>>> CHAT FROM.%d %llu: (%s)\n",senderind,(long long)senderbits,(char *)buf);
}

/*
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
                    pangea_newhand(hn,json,dp,priv,buf,len,senderind);
                else if ( strcmp(cmdstr,"ping") == 0 )
                    pangea_ping(hn,json,dp,priv,buf,len,senderind);
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
}*/

char *Pangea_bypass(uint64_t my64bits,uint8_t myprivkey[32],cJSON *json)
{
    char *methodstr,*retstr = 0;
    if ( (methodstr= jstr(json,"method")) != 0 )
    {
        if ( strcmp(methodstr,"turn") == 0 )
            retstr = _pangea_input(my64bits,j64bits(json,"tableid"),json);
        else if ( strcmp(methodstr,"status") == 0 )
            retstr = _pangea_status(my64bits,j64bits(json,"tableid"),json);
        else if ( strcmp(methodstr,"mode") == 0 )
            retstr = _pangea_mode(my64bits,j64bits(json,"tableid"),json);
        //else if ( strcmp(methodstr,"rosetta") == 0 )
        //    retstr = pangea_univ(myprivkey,json);
        else if ( strcmp(methodstr,"buyin") == 0 )
            retstr = _pangea_buyin(my64bits,j64bits(json,"tableid"),json);
        else if ( strcmp(methodstr,"history") == 0 )
            retstr = _pangea_history(my64bits,j64bits(json,"tableid"),json);
    }
    return(retstr);
}

#include "../includes/iguana_apidefs.h"

INT_AND_ARRAY(pangea,newhand,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,ping,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,gotdeck,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,ready,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,encoded,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,final,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,addedfunds,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,preflop,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,decoded,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,card,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,facedown,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,faceup,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,turn,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,confirmturn,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,chat,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,action,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,showdown,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(pangea,handsummary,senderind,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}


HASH_AND_ARRAY(pangea,status,tablehash,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

HASH_AND_ARRAY(pangea,mode,tablehash,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

HASH_AND_ARRAY(pangea,buyin,tablehash,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

HASH_AND_ARRAY(pangea,history,tablehash,params)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

ZERO_ARGS(pangea,lobby)
{
    pangea_update(myinfo);
    return(jprint(pangea_lobbyjson(myinfo),1));
}

INT_AND_ARRAY(pangea,host,minplayers,params)
{
    cJSON *retjson,*argjson; char *str,hexstr[1024],*reqstr;
    bits256 pangeahash,tablehash; struct pangea_msghdr *pm; uint8_t space[sizeof(*pm) + 512];
    pangeahash = calc_categoryhashes(0,"pangea",0);
    OS_randombytes(tablehash.bytes,sizeof(tablehash));
    argjson = cJSON_CreateObject();
    jaddbits256(argjson,"newtable",tablehash);
    jaddnum(argjson,"minplayers",minplayers);
    jaddstr(argjson,"ipaddr",myinfo->ipaddr);
    reqstr = jprint(argjson,1);
    if ( (pm= pangea_msgcreate(myinfo,space,tablehash,(void *)reqstr,(int32_t)strlen(reqstr)+1)) != 0 )
    {
        free(reqstr);
        init_hexbytes_noT(hexstr,(uint8_t *)pm,pm->sig.allocsize);
        str = SuperNET_categorymulticast(myinfo,0,pangeahash,GENESIS_PUBKEY,hexstr,0,1,1);
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","table created");
        jaddstr(retjson,"multicast",str);
        jaddbits256(retjson,"tablehash",tablehash);
        return(jprint(retjson,1));
    }
    else
    {
        free(reqstr);
        return(clonestr("{\"error\":\"couldnt create pangea message\"}"));
    }
}

HASH_AND_ARRAY(pangea,join,tablehash,params)
{
    char hexstr[512],*req = "{\"lobby\":\"join\"}";
    bits256 pangeahash; struct pangea_msghdr *pm; uint8_t space[sizeof(*pm) + 512];
    pangeahash = calc_categoryhashes(0,"pangea",0);
    if ( (pm= pangea_msgcreate(myinfo,space,tablehash,(void *)req,(int32_t)strlen(req))) != 0 )
    {
        init_hexbytes_noT(hexstr,(uint8_t *)pm,pm->sig.allocsize);
        return(SuperNET_categorymulticast(myinfo,0,pangeahash,tablehash,hexstr,0,1,1));
    } else return(clonestr("{\"error\":\"couldnt create pangea message\"}"));

}

#undef IGUANA_ARGS

#include "../includes/iguana_apiundefs.h"
