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


/*
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
*/

#include "pangea777.h"

int32_t pangea_datalen(struct pangea_msghdr *pm)
{
    return((int32_t)(pm->sig.allocsize - sizeof(pm->sig) - sizeof(*pm)));
}

int32_t pangea_validate(struct pangea_msghdr *pm,bits256 privkey,bits256 pubkey)
{
    uint64_t signerbits; //uint8_t buf[sizeof(pm->sig)];
    //acct777_rwsig(0,(void *)&pm->sig,(void *)buf);
    //if ( acct777_sigcheck((void *)buf) == 0 )
    {
        if ( (signerbits= acct777_validate(&pm->sig,privkey,pubkey)) != 0 )
        {
            return(0);
        }
    }
    return(-1);
}

int32_t pangea_rwdata(int32_t rwflag,uint8_t *serialized,int32_t datalen,uint8_t *endianedp)
{
    int32_t i,n,len = 0; uint64_t x; bits256 X,*pubkeys; cJSON *json;
    if ( rwflag == 0 && serialized[datalen-1] == 0 )
        json = cJSON_Parse((char *)serialized);
    else if ( rwflag == 1 && endianedp[datalen-1] == 0 )
        json = cJSON_Parse((char *)endianedp);
    else json = 0;
    if ( json != 0 )
    {
        if ( rwflag != 0 )
            memcpy(serialized,endianedp,datalen);
        else memcpy(endianedp,serialized,datalen);
        free_json(json);
        return(datalen);
    }
    if ( datalen <= sizeof(uint64_t) )
    {
        if ( rwflag != 0 )
            memcpy(&x,endianedp,datalen);
        iguana_rwnum(rwflag,&serialized[0],datalen,&x);
        if ( rwflag == 0 )
            memcpy(endianedp,&x,datalen);
    }
    else if ( datalen >= sizeof(bits256) && (datalen % sizeof(bits256)) == 0 )
    {
        n = (int32_t)(datalen / sizeof(bits256));
        pubkeys = (void *)serialized;
        for (i=0; i<n; i++)
        {
            if ( rwflag != 0 )
                len += iguana_rwbignum(rwflag,&serialized[len],sizeof(bits256),X.bytes);
            else
            {
                len += iguana_rwbignum(0,pubkeys[i].bytes,sizeof(bits256),X.bytes);
                pubkeys[i] = X;
                //char str[65]; printf("i.%d len.%d X.%s\n",i,len,bits256_str(str,pubkeys[i]));
            }
        }
    }
    else
    {
        for (i=0; i<datalen; i++)
            printf("%02x",endianedp[i]);
        printf(" pangea_sendcmd: unexpected datalen.%d mod.%ld\n",datalen,(datalen % sizeof(bits256)));
        return(-1);
    }
    return(datalen);
}

struct pangea_msghdr *pangea_msgcreate(struct supernet_info *myinfo,bits256 tablehash,struct pangea_msghdr *pm,int32_t datalen)
{
    bits256 otherpubkey; uint32_t timestamp; uint8_t buf[sizeof(pm->sig)],*serialized;
    memset(&pm->sig,0,sizeof(pm->sig));
    iguana_rwbignum(1,pm->tablehash.bytes,sizeof(bits256),tablehash.bytes);
    datalen += (int32_t)(sizeof(*pm) - sizeof(pm->sig));
    serialized = (void *)((long)pm + sizeof(pm->sig));
    otherpubkey = acct777_msgpubkey(serialized,datalen);
    timestamp = (uint32_t)time(NULL);
    acct777_sign(&pm->sig,myinfo->privkey,otherpubkey,timestamp,serialized,datalen);
    if ( pangea_validate(pm,acct777_msgprivkey(serialized,datalen),pm->sig.pubkey) == 0 )
    {
        //int32_t i; char str[65],str2[65];
        //for (i=0; i<datalen; i++)
        //    printf("%02x",serialized[i]);
        //printf(">>>>>>>>>>>>>>>> validated [%ld] len.%d (%s + %s)\n",(long)serialized-(long)pm,datalen,bits256_str(str,acct777_msgprivkey(serialized,datalen)),bits256_str(str2,pm->sig.pubkey));
        memset(buf,0,sizeof(buf));
        acct777_rwsig(1,buf,&pm->sig);
        memcpy(&pm->sig,buf,sizeof(buf));
        return(pm);
    } else printf("error validating pangea msg\n");
    return(0);
}

void pangea_playeradd(struct supernet_info *myinfo,struct table_info *tp,struct player_info *p,cJSON *json)
{
    if ( jobj(json,"playerpub") != 0 )
        p->playerpub = jbits256(json,"playerpub");
    else p->playerpub = GENESIS_PUBKEY;
    p->ipbits = calc_ipbits(jstr(json,"playeripaddr"));
    safecopy(p->handle,jstr(json,"handle"), sizeof(p->handle));
    p->balance = 100 * SATOSHIDEN;
    p->nxt64bits = acct777_nxt64bits(p->playerpub);
}

struct table_info *pangea_table(bits256 tablehash)
{
    struct table_info *tp; int32_t allocsize; bits256 pangeahash; char str[65];
    pangeahash = calc_categoryhashes(0,"pangea",0);
    if ( (tp= category_info(pangeahash,tablehash)) == 0 )
    {
        allocsize = (int32_t)(sizeof(tp->G) + sizeof(void *)*2);
        if ( (tp= calloc(1,allocsize)) == 0 )
            printf("error: couldnt create table.(%s)\n",bits256_str(str,tablehash));
    }
    if ( tp != 0 )
    {
        category_subscribe(SuperNET_MYINFO(0),pangeahash,tablehash);
        if ( category_infoset(pangeahash,tablehash,tp) == 0 )
            printf("error: couldnt set table.(%s)\n",bits256_str(str,tablehash)), tp = 0;
        else tp->G.allocsize = allocsize;
    }
    return(tp);
}

char *pangea_jsondatacmd(struct supernet_info *myinfo,bits256 tablehash,struct pangea_msghdr *pm,cJSON *json,char *cmdstr,char *ipaddr)
{
    cJSON *argjson; char *reqstr,hexstr[8192]; uint64_t nxt64bits;
    struct table_info *tp; int32_t i,datalen; bits256 pangeahash;
    pangeahash = calc_categoryhashes(0,"pangea",0);
    category_subscribe(myinfo,pangeahash,GENESIS_PUBKEY);
    category_subscribe(myinfo,pangeahash,tablehash);
    argjson = cJSON_CreateObject();//SuperNET_argjson(json);
    jaddstr(argjson,"cmd",cmdstr);
    if ( myinfo->ipaddr[0] == 0 || strncmp(myinfo->ipaddr,"127.0.0.1",strlen("127.0.0.1")) == 0 )
        return(clonestr("{\"error\":\"need to send your ipaddr for now\"}"));
    jaddstr(argjson,"agent","SuperNET");
    jaddstr(argjson,"method","DHT");
    jaddstr(argjson,"playeripaddr",ipaddr);
    jaddbits256(argjson,"categoryhash",pangeahash);
    jaddbits256(argjson,"subhash",tablehash);
    jaddbits256(argjson,"playerpub",myinfo->myaddr.persistent);
    jaddstr(argjson,"handle",jstr(json,"handle"));
    nxt64bits = acct777_nxt64bits(myinfo->myaddr.persistent);
    if ( (tp= pangea_table(tablehash)) != 0 && tp->G.numactive < tp->G.maxplayers )
    {
        for (i=0; i<tp->G.numactive; i++)
            if ( tp->G.P[i].nxt64bits == nxt64bits )
                break;
        if ( i == tp->G.numactive )
        {
            printf("self join\n");
            struct player_info *p = &tp->G.P[tp->G.numactive++];
            p->playerpub = myinfo->myaddr.persistent;
            p->ipbits = calc_ipbits(myinfo->ipaddr);
            safecopy(p->handle,jstr(json,"handle"),sizeof(p->handle));
            p->balance = 100 * SATOSHIDEN;
            p->nxt64bits = nxt64bits;
            //pangea_playeradd(myinfo,tp,&tp->G.P[tp->G.numactive++],argjson);
        }
    }
    reqstr = jprint(argjson,1);
    datalen = (int32_t)(strlen(reqstr) + 1);
    memcpy(pm->serialized,reqstr,datalen);
    free(reqstr);
    if ( pangea_msgcreate(myinfo,tablehash,pm,datalen) != 0 )
    {
        printf("pangea send.(%s)\n",cmdstr);
        init_hexbytes_noT(hexstr,(uint8_t *)pm,pm->sig.allocsize);
        return(SuperNET_categorymulticast(myinfo,0,pangeahash,tablehash,hexstr,0,2,1));
    }
    else
    {
        printf("cant msgcreate\n");
        return(clonestr("{\"error\":\"couldnt create pangea message\"}"));
    }
}

void pangea_sendcmd(struct supernet_info *myinfo,struct table_info *tp,char *cmdstr,int32_t destplayer,uint8_t *data,int32_t datalen,int32_t cardi,int32_t turni)
{
    struct player_info *p; struct pangea_msghdr *pm; char *str;
    pm = (void *)tp->space;
    memset(pm,0,sizeof(*pm));
    strncpy(pm->cmd,cmdstr,8);
    pm->turni = turni, pm->myind = tp->priv.myind, pm->cardi = cardi, pm->destplayer = destplayer;
    pangea_rwdata(1,pm->serialized,datalen,data);
    if ( pangea_msgcreate(myinfo,tp->G.tablehash,pm,datalen) != 0 )
    {
        if ( destplayer < 0 )
        {
            init_hexbytes_noT(tp->spacestr,(uint8_t *)pm,pm->sig.allocsize);
            if ( (str= SuperNET_categorymulticast(myinfo,0,tp->G.gamehash,tp->G.tablehash,tp->spacestr,0,2,1)) != 0 )
                free(str);
        }
        else if ( (p= tp->active[destplayer]) != 0 )
        {
            // encrypt here!
            int32_t plaintext = 1; // for now
            if ( (str= SuperNET_DHTsend(myinfo,p->ipbits,tp->G.gamehash,tp->G.tablehash,tp->spacestr,0,0,plaintext)) != 0 )
                free(str);
        }
    }
}

int32_t pangea_allocsize(struct table_info *tp,int32_t setptrs)
{
    long allocsize = sizeof(*tp); int32_t N,numcards = tp->G.numcards;
    N = tp->G.numactive;
    allocsize += sizeof(bits256) * (2 * ((N * numcards * N) + (N * numcards)));
    allocsize += sizeof(bits256) * ((numcards + 1) + (N * numcards));
    if ( setptrs != 0 )
    {
        tp->hand.cardpubs = tp->priv.data;
        tp->hand.final = &tp->hand.cardpubs[numcards + 1 + N];
        tp->priv.audits = &tp->hand.final[N * numcards];
        tp->priv.outcards = &tp->priv.audits[N * numcards * N];
        tp->priv.xoverz = &tp->priv.outcards[N * numcards];
        tp->priv.allshares = (void *)&tp->priv.xoverz[N * numcards]; // N*numcards*N
    }
    return((int32_t)allocsize);
}

struct table_info *pangea_tablealloc(struct table_info *tp)
{
    int32_t allocsize = pangea_allocsize(tp,0);
    if ( tp->G.allocsize != allocsize )
    {
        tp = realloc(tp,allocsize);
        pangea_allocsize(tp,1);
    }
    return(tp);
}

void pangea_ping(PANGEA_HANDARGS)
{
    
}

void pangea_ready(PANGEA_HANDARGS)
{
    
}

void pangea_addfunds(PANGEA_HANDARGS)
{
    
}

void pangea_tablejoin(PANGEA_HANDARGS)
{
    char str[65],str2[65],space[4096]; struct tai t; int32_t i,seconds; cJSON *json;
    if ( tp->G.started != 0 )
    {
        OS_conv_unixtime(&t,&seconds,tp->G.finished == 0 ? tp->G.started : tp->G.finished);
        printf("table.(%s) already %s %s\n",bits256_str(str,pm->tablehash),tp->G.finished == 0 ? "started" : "finished",utc_str(str2,t));
    }
    else if ( tp->G.numactive >= tp->G.maxplayers )
    {
        printf("table.(%s) numactive.%d >= max.%d\n",bits256_str(str,pm->tablehash),tp->G.numactive,tp->G.maxplayers);
    }
    else if ( (json= cJSON_Parse((char *)pm->serialized)) != 0 )
    {
        for (i=0; i<tp->G.numactive; i++)
            if ( tp->G.P[i].nxt64bits == pm->sig.signer64bits )
                break;
        if ( i == tp->G.numactive )
        {
            pangea_playeradd(myinfo,tp,&tp->G.P[tp->G.numactive++],json);
            printf("add player.%d %p\n",i,tp);
            if ( tp->G.creatorbits == myinfo->myaddr.nxt64bits )
            {
                pangea_jsondatacmd(myinfo,pm->tablehash,(struct pangea_msghdr *)space,json,"accept",myinfo->ipaddr);
                printf("my table! ");
            }
        } else printf("duplicate player.%llu\n",(long long)pm->sig.signer64bits);
        printf("pending join of %llu table.(%s)\n",(long long)pm->sig.signer64bits,bits256_str(str,pm->tablehash));
        free_json(json);
    } else printf("tablejoin cant parse json\n");
}

void pangea_tableaccept(PANGEA_HANDARGS)
{
    cJSON *json; char ipaddr[64]; struct iguana_peer *addr; uint64_t ipbits = 0;
    struct iguana_info *coin; struct player_info p;
    ipaddr[0] = 0;
    if ( pm->sig.signer64bits == tp->G.creatorbits && tp->G.numactive < tp->G.maxplayers )
    {
        if ( (json= cJSON_Parse((char *)pm->serialized)) != 0 )
        {
            if ( tp->G.creatorbits == myinfo->myaddr.nxt64bits )
            {
                expand_ipbits(ipaddr,p.ipbits);
                printf("connect to new player.(%s)\n",ipaddr);
            }
            else if ( pm->sig.signer64bits == myinfo->myaddr.nxt64bits )
            {
                expand_ipbits(ipaddr,tp->G.hostipbits);
                printf("connect to host.(%s)\n",ipaddr);
            }
            free_json(json);
            if ( ipbits != 0 )
            {
                coin = iguana_coinfind("BTCD");
                if ( (addr= iguana_peerslot(coin,ipbits,1)) == 0 )
                {
                    iguana_peerkill(coin);
                    sleep(3);
                    addr = iguana_peerslot(coin,ipbits,1);
                }
                if ( addr != 0 )
                {
                    if ( addr->usock < 0 )
                    {
                        iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
                        printf("launch start connection to (%s)\n",ipaddr);
                    }
                    else
                    {
                        printf("already connected\n");
                        addr->persistent_peer = 1;
                    }
                } else printf("no open iguana peer slots, cant connect\n");
            }
        }
    }
}

void pangea_tablecreate(PANGEA_HANDARGS)
{
    cJSON *json;
    if ( tp->G.gamehash.txid != 0 )
    {
        char str[65]; printf("table.(%s) already exists\n",bits256_str(str,pm->tablehash));
    }
    else if ( (json= cJSON_Parse((char *)pm->serialized)) != 0 )
    {
        printf("create table\n");
        pangea_gamecreate(&tp->G,pm->sig.timestamp,pm->tablehash,json);
        tp->G.creatorbits = pm->sig.signer64bits;
        free_json(json);
    }
}

void pangea_parse(struct supernet_info *myinfo,struct pangea_msghdr *pm,cJSON *argjson,char *remoteaddr)
{
    bits256 tablehash; char *method; struct table_info *tp;
    tablehash = jbits256(argjson,"subhash");
    tp = pangea_table(tablehash);
    if ( (method= jstr(argjson,"cmd")) != 0 )
    {
        if ( strcmp(method,"lobby") == 0 )
        {
            //categoryhash = jbits256(argjson,"categoryhash");
        }
        else if ( strcmp(method,"host") == 0 )
        {
            if ( tp != 0 )
            {
                pangea_gamecreate(&tp->G,pm->sig.timestamp,pm->tablehash,argjson);
                tp->G.creatorbits = pm->sig.signer64bits;
            }
            char str[65],str2[65]; printf("new game detected (%s) vs (%s)\n",bits256_str(str,tablehash),bits256_str(str2,pm->tablehash));
        }
        else if ( strcmp(method,"join") == 0 )
        {
            printf("JOIN.(%s)\n",jprint(argjson,0));
            pangea_tablejoin(myinfo,pm,tp,pm->serialized,(int32_t)(pm->sig.allocsize - sizeof(*pm)));
        }
        else if ( strcmp(method,"accept") == 0 )
        {
            printf("ACCEPT.(%s)\n",jprint(argjson,0));
            //pangea_tableaccept(myinfo,pm,tp,pm->serialized,(int32_t)(pm->sig.allocsize - sizeof(*pm)));
        }
    }
}

int32_t pangea_hexmsg(struct supernet_info *myinfo,void *data,int32_t len,char *remoteaddr)
{
    static struct { char *cmdstr; void (*func)(PANGEA_HANDARGS); uint64_t cmdbits; } tablecmds[] =
    {
        { "newtable", pangea_tablecreate }, { "join", pangea_tablejoin },
        { "accept", pangea_tableaccept }, { "addfunds", pangea_addfunds },
        { "newhand", pangea_newhand }, { "ping", pangea_ping },
        { "gotdeck", pangea_gotdeck }, { "ready", pangea_ready },
        { "encoded", pangea_encoded }, { "decoded", pangea_decoded },
        { "final", pangea_final }, { "preflop", pangea_preflop },
        { "card", pangea_card }, { "facedown", pangea_facedown }, { "faceup", pangea_faceup },
        { "turn", pangea_turn }, { "confirm", pangea_confirm }, { "action", pangea_action },
        { "showdown", pangea_showdown }, { "summary", pangea_summary },
    };
    struct pangea_msghdr *pm = data; cJSON *argjson; bits256 tablehash;
    uint64_t cmdbits; uint8_t *serialized; uint8_t tmp[sizeof(pm->sig)]; char str[65],str2[65];
    struct table_info *tp; int32_t i,allocsize,datalen,flag = 0;
    if ( tablecmds[0].cmdbits == 0 )
    {
        for (i=0; i<sizeof(tablecmds)/sizeof(*tablecmds); i++)
            tablecmds[i].cmdbits = stringbits(tablecmds[i].cmdstr);
    }
    acct777_rwsig(0,(void *)&pm->sig,(void *)tmp);
    memcpy(&pm->sig,tmp,sizeof(pm->sig));
    datalen = len  - (int32_t)sizeof(pm->sig);
    serialized = (void *)((long)pm + sizeof(pm->sig));
    if ( remoteaddr != 0 && remoteaddr[0] == 0 && strcmp("127.0.0.1",remoteaddr) == 0 && ((uint8_t *)pm)[len-1] == 0 && (argjson= cJSON_Parse((char *)pm)) != 0 )
    {
        printf("pangea_hexmsg RESULT.(%s)\n",jprint(argjson,0));
        pangea_parse(myinfo,pm,argjson,remoteaddr);
        free_json(argjson);
        return(1);
    }
    //printf("pm.%p len.%d serialized.%p datalen.%d crc.%u %s\n",pm,len,serialized,datalen,calc_crc32(0,(void *)pm,len),bits256_str(str,pm->sig.pubkey));
    //return(0);
    if ( pangea_validate(pm,acct777_msgprivkey(serialized,datalen),pm->sig.pubkey) == 0 )
    {
        flag++;
        iguana_rwbignum(0,pm->tablehash.bytes,sizeof(bits256),tablehash.bytes);
        pm->tablehash = tablehash;
        printf("<<<<<<<<<<<<< sigsize.%ld VALIDATED [%ld] len.%d t%u allocsize.%d (%s) [%d]\n",sizeof(pm->sig),(long)serialized-(long)pm,datalen,pm->sig.timestamp,pm->sig.allocsize,(char *)pm->serialized,serialized[datalen-1]);
        if ( serialized[datalen-1] == 0 && (argjson= cJSON_Parse((char *)pm->serialized)) != 0 )
        {
            pangea_parse(myinfo,pm,argjson,remoteaddr);
            free_json(argjson);
        }
        else
        {
            if ( (tp= pangea_table(tablehash)) != 0 && pangea_rwdata(0,pm->serialized,len-(int32_t)((long)pm->serialized-(long)pm),pm->serialized) > 0 )
            {
                cmdbits = stringbits(pm->cmd);
                for (i=0; i<sizeof(tablecmds)/sizeof(*tablecmds); i++)
                {
                    if ( tablecmds[i].cmdbits == cmdbits )
                    {
                        allocsize = pangea_allocsize(tp,0);
                        if ( tp->G.allocsize < allocsize )
                        {
                            tp = pangea_tablealloc(tp);
                            category_infoset(tp->G.gamehash,tp->G.tablehash,tp);
                        }
                        if ( strcmp(tablecmds[i].cmdstr,"newhand") == 0 )
                        {
                            tp->G.numactive = pm->turni;
                            tp->G.numcards = 52;
                            if ( tp->G.minplayers == 0 )
                                tp->G.minplayers = tp->G.maxplayers = tp->G.numactive;
                        }
                        printf("PANGEA.(%s) numactive.%d minplayers.%d\n",tablecmds[i].cmdstr,tp->G.numactive,tp->G.minplayers);
                        (*tablecmds[i].func)(myinfo,pm,tp,pm->serialized,(int32_t)(pm->sig.allocsize - sizeof(*pm)));
                        break;
                    }
                }
            }
        }
    }
    else if ( 0 )
    {
        for (i=0; i<datalen; i++)
            printf("%02x",serialized[i]);
        printf("<<<<<<<<<<<<< sigsize.%ld SIG ERROR [%ld] len.%d (%s + %s)\n",sizeof(pm->sig),(long)serialized-(long)pm,datalen,bits256_str(str,acct777_msgprivkey(serialized,datalen)),bits256_str(str2,pm->sig.pubkey));
    }
    return(flag);
}

void pangea_update(struct supernet_info *myinfo)
{
    struct pangea_msghdr *pm; struct category_msg *m; bits256 pangeahash; char remoteaddr[64];
    pangeahash = calc_categoryhashes(0,"pangea",0);
    while ( (m= category_gethexmsg(myinfo,pangeahash,GENESIS_PUBKEY)) != 0 )
    {
        pm = (struct pangea_msghdr *)m->msg;
        if ( m->remoteipbits != 0 )
            expand_ipbits(remoteaddr,m->remoteipbits);
        if ( pangea_hexmsg(myinfo,pm,m->len,remoteaddr) > 0 )
        {
        }
        free(m);
    }
}
/*
char *_pangea_status(struct supernet_info *myinfo,bits256 tablehash,cJSON *json)
{
    int32_t i,j,threadid = juint(json,"threadid"); struct pangea_info *sp;
    cJSON *item,*array=0,*retjson = 0; uint64_t my64bits = myinfo->myaddr.nxt64bits;
    if ( tablehash.txid != 0 )
    {
        if ( (sp= pangea_find(tablehash.txid,threadid)) != 0 )
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

char *_pangea_history(struct supernet_info *myinfo,bits256 tablehash,cJSON *json)
{
    struct pangea_info *sp;
    if ( (sp= pangea_find64(tablehash.txid,myinfo->myaddr.nxt64bits)) != 0 && sp->dp != 0 )
    {
        if ( jobj(json,"handid") == 0 )
            return(pangea_dispsummary(sp,juint(json,"verbose"),sp->dp->summary,sp->dp->summarysize,tablehash.txid,sp->dp->numhands-1,sp->dp->N));
        else return(pangea_dispsummary(sp,juint(json,"verbose"),sp->dp->summary,sp->dp->summarysize,tablehash.txid,juint(json,"handid"),sp->dp->N));
    }
    return(clonestr("{\"error\":\"cant find tableid\"}"));
}

char *_pangea_buyin(struct supernet_info *myinfo,bits256 tablehash,cJSON *json)
{
    struct pangea_info *sp; uint32_t buyin,vout; uint64_t amount = 0; char hex[1024],jsonstr[1024],*txidstr,*destaddr;
    if ( (sp= pangea_find64(tablehash.txid,myinfo->myaddr.nxt64bits)) != 0 && sp->dp != 0 && sp->tp != 0 && (amount= j64bits(json,"amount")) != 0 )
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
                pangea_sendcmd(PANGEA_ARGS,"addfunds",-1,(void *)jsonstr,(int32_t)strlen(jsonstr)+1,pangea_ind(sp,sp->myslot),-1);
            } else pangea_sendcmd(PANGEA_ARGS,"addfunds",-1,(void *)&amount,sizeof(amount),pangea_ind(sp,sp->myslot),-1);
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


char *_pangea_mode(struct supernet_info *myinfo,bits256 tablehash,cJSON *json)
{
    struct pangea_info *sp;
    if ( jobj(json,"automuck") != 0 )
    {
        if ( tablehash.txid == 0 )
            Showmode = juint(json,"automuck");
        else if ( (sp= pangea_find64(tablehash.txid,myinfo->myaddr.nxt64bits)) != 0 && sp->priv != 0 )
            sp->priv->automuck = juint(json,"automuck");
        else return(clonestr("{\"error\":\"automuck not tableid or sp->priv\"}"));
        return(clonestr("{\"result\":\"set automuck mode\"}"));
    }
    else if ( jobj(json,"autofold") != 0 )
    {
        if ( tablehash.txid == 0 )
            Autofold = juint(json,"autofold");
        else if ( (sp= pangea_find64(tablehash.txid,myinfo->myaddr.nxt64bits)) != 0 && sp->priv != 0 )
            sp->priv->autofold = juint(json,"autofold");
        else return(clonestr("{\"error\":\"autofold not tableid or sp->priv\"}"));
        return(clonestr("{\"result\":\"set autofold mode\"}"));
    }
    return(clonestr("{\"error\":\"unknown pangea mode\"}"));
}*/

#include "../includes/iguana_apidefs.h"

/*HASH_AND_ARRAY(pangea,turn,tablehash,params)
{
    return(_pangea_turn(myinfo,tablehash,json));
}

HASH_AND_ARRAY(pangea,status,tablehash,params)
{
    return(_pangea_status(myinfo,tablehash,json));
}

HASH_AND_ARRAY(pangea,mode,tablehash,params)
{
    return(_pangea_mode(myinfo,tablehash,json));
}

HASH_AND_ARRAY(pangea,buyin,tablehash,params)
{
    return(_pangea_buyin(myinfo,tablehash,json));
}

HASH_AND_ARRAY(pangea,history,tablehash,params)
{
    return(_pangea_history(myinfo,tablehash,json));
}*/

ZERO_ARGS(pangea,lobby)
{
    //cJSON *retjson,*argjson; char *retstr,*result; uint8_t *buf; int32_t flag,len; struct pangea_msghdr *pm;
    bits256 pangeahash = calc_categoryhashes(0,"pangea",0);
    category_subscribe(myinfo,pangeahash,GENESIS_PUBKEY);
    pangea_update(myinfo);
    return(jprint(pangea_lobbyjson(myinfo),1));
}

INT_AND_ARRAY(pangea,host,minplayers,params)
{
    bits256 tablehash; struct table_info *tp; uint8_t space[sizeof(struct pangea_msghdr) + 4096];
    OS_randombytes(tablehash.bytes,sizeof(tablehash));
    tp = pangea_table(tablehash);
    if ( tp != 0 )
    {
        pangea_gamecreate(&tp->G,(uint32_t)time(NULL),tablehash,json);
        tp->G.creatorbits = myinfo->myaddr.nxt64bits;
    }
    return(pangea_jsondatacmd(myinfo,tablehash,(struct pangea_msghdr *)space,json,"host",myinfo->ipaddr));
}

HASH_AND_STRING(pangea,join,tablehash,handle)
{
    uint8_t space[sizeof(struct pangea_msghdr) + 4096];
    return(pangea_jsondatacmd(myinfo,tablehash,(struct pangea_msghdr *)space,json,"join",myinfo->ipaddr));
}

HASH_AND_ARRAY(pangea,start,tablehash,params)
{
    struct table_info *tp; int32_t allocsize;
    if ( (tp= pangea_table(tablehash)) != 0 )
    {
        if ( tp->G.numactive >= tp->G.minplayers && pangea_tableismine(myinfo,tp) >= 0 )
        {
            allocsize = pangea_allocsize(tp,0);
            if ( tp->G.allocsize < allocsize )
            {
                tp = pangea_tablealloc(tp);
                category_infoset(tp->G.gamehash,tp->G.tablehash,tp);
            }
            if ( tp->G.creatorbits == myinfo->myaddr.nxt64bits )
                pangea_newdeck(myinfo,tp);
        }
        return(clonestr("{\"result\":\"started tablehash\"}"));
    }
    return(clonestr("{\"error\":\"cant find tablehash\"}"));
}
#undef IGUANA_ARGS

#include "../includes/iguana_apiundefs.h"
