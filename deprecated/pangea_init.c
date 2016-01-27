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

struct pangea_info *TABLES[100];
struct pangea_thread *THREADS[_PANGEA_MAXTHREADS];

void pangea_buyins(uint32_t *minbuyinp,uint32_t *maxbuyinp)
{
    if ( *minbuyinp == 0 && *maxbuyinp == 0 )
    {
        *minbuyinp = 100;
        *maxbuyinp = 1000;
    }
    else
    {
        PNACL_message("minbuyin.%d maxbuyin.%d -> ",*minbuyinp,*maxbuyinp);
        if ( *minbuyinp < 20 )
            *minbuyinp = 20;
        if ( *maxbuyinp < *minbuyinp )
            *maxbuyinp = (*minbuyinp * 4);
        if ( *maxbuyinp > 1000 )
            *maxbuyinp = 1000;
        if ( *minbuyinp > *maxbuyinp )
            *minbuyinp = *maxbuyinp;
        PNACL_message("(%d %d)\n",*minbuyinp,*maxbuyinp);
    }
}

struct pangea_info *pangea_create(struct pangea_thread *tp,int32_t *createdflagp,char *base,uint32_t timestamp,uint64_t *addrs,int32_t numaddrs,uint64_t bigblind,uint64_t ante,uint64_t *isbot,uint32_t minbuyin,uint32_t maxbuyin,int32_t hostrake)
{
    struct pangea_info *sp = 0; bits256 hash; int32_t i,j,numcards,firstslot = -1; struct cards777_privdata *priv; struct cards777_pubdata *dp; struct iguana_info *coin;
    if ( createdflagp != 0 )
        *createdflagp = 0;
    for (i=0; i<numaddrs; i++)
        PNACL_message("%llu ",(long long)addrs[i]);
    PNACL_message("pangea_create numaddrs.%d\n",numaddrs);
    for (i=0; i<numaddrs; i++)
    {
        if ( addrs[i] == tp->nxt64bits )
            break;
    }
    if ( i == numaddrs )
    {
        PNACL_message("this node not in addrs\n");
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
            PNACL_message("pangea_create: unexpected out of memory pub\n");
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
            PNACL_message("pangea_create: unexpected out of memory priv\n");
            return(0);
        }
        priv->automuck = Showmode;
        priv->autofold = Autofold;
        btc_priv2pub(sp->btcpub,tp->hn.client->H.privkey.bytes);
        init_hexbytes_noT(sp->btcpubkeystr,sp->btcpub,33);
        strcpy(sp->coinstr,base);
        strcpy(dp->coinstr,base);
        if ( (coin= iguana_coinfind(base)) != 0 )
        {
            sp->addrtype = coin->chain->pubval;//coin777_addrtype(&sp->p2shtype,base);
            sp->wiftype = coin->chain->wipval;//coin777_wiftype(base);
        }
        btc_priv2wip(sp->wipstr,tp->hn.client->H.privkey.bytes,sp->wiftype);
        strcpy(sp->btcpubkeys[sp->myslot],sp->btcpubkeystr);
        PNACL_message("T%d: Automuck.%d Autofold.%d rakemillis.%d btcpubkey.(%s) (%s) addrtype.%02x p2sh.%02x wif.%02x\n",tp->hn.client->H.slot,priv->automuck,priv->autofold,dp->rakemillis,sp->btcpubkeystr,dp->coinstr,sp->addrtype,sp->p2shtype,sp->wiftype);
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
                    PNACL_message("tableid %llu already exists!\n",(long long)sp->tableid);
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
        //PNACL_message("(%llx-> %s) ",(long long)playerpubs[i].txid,hexstr);
        jaddistr(array,hexstr);
    }
    //PNACL_message("playerpubs\n");
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

/*
char *pangea_newtable(int32_t threadid,cJSON *json,uint64_t my64bits,bits256 privkey,bits256 pubkey,char *transport,char *ipaddr,uint16_t port,uint32_t minbuyin,uint32_t maxbuyin,int32_t hostrake)
{
    int32_t createdflag,num,i,myind= -1; uint64_t tableid,addrs[CARDS777_MAXPLAYERS],isbot[CARDS777_MAXPLAYERS];
    struct pangea_info *sp; cJSON *array; struct pangea_thread *tp=0; char *base,*str,*hexstr,*endpoint,hex[1024]; uint32_t timestamp;
    struct cards777_pubdata *dp; struct pangeanet777_server *srv=0;
    str = jprint(json,0);
    PNACL_message("T%d NEWTABLE.(%s)\n",threadid,str);
    free(str);
    if ( (tableid= j64bits(json,"tableid")) != 0 && (base= jstr(json,"base")) != 0 && (timestamp= juint(json,"timestamp")) != 0 )
    {
        if ( (array= jarray(&num,json,"addrs")) == 0 || num < 2 || num > CARDS777_MAXPLAYERS )
        {
            PNACL_message("no address or illegal num.%d\n",num);
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
                        if ( (srv= pangeanet777_server(privkey,pubkey,transport,ipaddr,port,num)) == 0 )
                            PNACL_message("cant create pangeanet777 server\n");
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
                                PNACL_message("ILLEGAL pangea_endpoint.(%s)\n",endpoint);
                                return(clonestr("{\"error\":\"contact pangea host and tell them to add myipaddr to their SuperNET.conf\"}"));
                            }
                            if ( (tp->hn.client= pangeanet777_client(privkey,pubkey,endpoint,i)) == 0 )
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
        if ( (array= jarray(&num,json,"isbot")) != 0 )
        {
            for (i=0; i<num; i++)
                isbot[i] = j64bits(jitem(array,i),0);
        }
        else memset(isbot,0,sizeof(isbot));
        PNACL_message("call pangea_create\n");
        if ( (sp= pangea_create(tp,&createdflag,base,timestamp,addrs,num,j64bits(json,"bigblind"),j64bits(json,"ante"),isbot,minbuyin,maxbuyin,hostrake)) == 0 )
        {
            PNACL_message("cant create table.(%s) numaddrs.%d\n",base,num);
            return(clonestr("{\"error\":\"cant create table\"}"));
        }
        PNACL_message("back from pangea_create\n");
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
            PNACL_message("no address or illegal num.%d\n",num);
            return(clonestr("{\"error\":\"no addrs or illegal numplayers\"}"));
        }
        for (i=0; i<num; i++)
        {
            hexstr = jstr(jitem(array,i),0);
            decode_hex(sp->playerpubs[i].bytes,sizeof(bits256),hexstr);
            PNACL_message("set playerpubs.(%s) %llx\n",hexstr,(long long)sp->playerpubs[i].txid);
            if ( sp->playerpubs[i].txid == 0 )
            {
                PNACL_message("player.%d has no NXT pubkey\n",i);
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
}*/

struct pangea_thread *pangea_threadinit(struct supernet_info *plugin,int32_t maxplayers)
{
  /*  struct pangea_thread *tp; struct pangeanet777_server *srv;
    PANGEA_MAXTHREADS = 1;
    THREADS[0] = tp = calloc(1,sizeof(*THREADS[0]));
    if ( tp == 0 )
    {
        PNACL_message("pangea_threadinit: unexpected out of memory\n");
        return(0);
    }
    tp->nxt64bits = plugin->nxt64bits;
    if ( (srv= pangeanet777_server(*(bits256 *)plugin->mypriv,*(bits256 *)plugin->mypub,plugin->transport,plugin->ipaddr,plugin->pangeaport,9)) == 0 )
        PNACL_message("cant create pangeanet777 server\n");
    else
    {
        tp->hn.server = srv;
        memcpy(srv->H.privkey.bytes,plugin->mypriv,sizeof(bits256));
        memcpy(srv->H.pubkey.bytes,plugin->mypub,sizeof(bits256));
    }
    return(tp);*/
    return(0);
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
    sprintf(retbuf,"{\"cmd\":\"newtable\",\"broadcast\":\"allnodes\",\"myind\":%d,\"pangea_endpoint\":\"%s\",\"plugin\":\"relay\",\"destplugin\":\"pangea\",\"method\":\"busdata\",\"submethod\":\"newtable\",\"my64bits\":\"%llu\",\"tableid\":\"%llu\",\"timestamp\":%u,\"M\":%d,\"N\":%d,\"base\":\"%s\",\"bigblind\":\"%llu\",\"minbuyin\":\"%d\",\"maxbuyin\":\"%u\",\"rakemillis\":\"%u\",\"ante\":\"%llu\",\"playerpubs\":%s,\"addrs\":%s,\"isbot\":%s}",sp->myslot,sp->tp->hn.server->ep.endpoint,(long long)sp->tp->nxt64bits,(long long)sp->tableid,sp->timestamp,dp->M,dp->N,sp->coinstr,(long long)sp->bigblind,dp->minbuyin,dp->maxbuyin,dp->rakemillis,(long long)sp->ante,playerpubs,addrstr,isbotstr); //\"pluginrequest\":\"SuperNET\",
    PNACL_message("START.(%s)\n",retbuf);
    //dp->pmworks |= (1 << sp->myind);
    free(addrstr), free(ciphers), free(playerpubs), free(isbotstr);// free(balancestr);
}

int32_t pangea_start(struct supernet_info *plugin,char *retbuf,char *base,uint32_t timestamp,uint64_t bigblind,uint64_t ante,int32_t hostrake,int32_t maxplayers,uint32_t minbuyin,uint32_t maxbuyin,cJSON *json)
{
    char destNXT[64]; struct pangea_thread *tp; struct cards777_pubdata *dp;
    int32_t createdflag,addrtype,haspubkey,i,j,slot,n,myind=-1,r,num=0,threadid=0; uint64_t addrs[512],isbot[512],tmp;
    struct pangea_info *sp; cJSON *bids,*walletitem,*item; struct iguana_info *coin;
    memset(addrs,0,sizeof(addrs));
    PNACL_message("pangea_start rakemillis.%d\n",hostrake);
    //memset(balances,0,sizeof(balances));
    pangea_buyins(&minbuyin,&maxbuyin);
    if ( hostrake < 0 || hostrake > PANGEA_MAX_HOSTRAKE )
    {
        PNACL_message("illegal hostrake.%d\n",hostrake);
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
            PNACL_message("%s\n",retbuf);
            return(-1);
        }
    }
    PNACL_message("mynxt64bits.%llu base.(%s) maxplayers.%d minbuyin.%u maxbuyin.%u\n",(long long)tp->nxt64bits,base,maxplayers,minbuyin,maxbuyin);
    if ( base == 0 || base[0] == 0 || maxplayers < 2 || maxplayers > CARDS777_MAXPLAYERS )
    {
        sprintf(retbuf,"{\"error\":\"bad params\"}");
        PNACL_message("%s\n",retbuf);
        return(-1);
    }
    if ( (coin= iguana_coinfind(base)) != 0 )
        addrtype = coin->chain->pubval;//coin777_addrtype(&p2shtype,base);
    if ( (bids= jarray(&n,json,"bids")) != 0 )
    {
        PNACL_message("numbids.%d\n",n);
        for (i=num=0; i<n; i++)
        {
            item = jitem(bids,i);
            if ( (addrs[num]= j64bits(item,"offerNXT")) != 0 && (walletitem= jobj(item,"wallet")) != 0 )
            {
                if ( j64bits(walletitem,"bigblind") == bigblind && j64bits(walletitem,"ante") == ante && juint(walletitem,"rakemillis") == hostrake )
                {
                    //balances[num] = j64bits(walletitem,"balance");
                    isbot[num] = juint(walletitem,"isbot");
                    PNACL_message("(i.%d %llu) ",i,(long long)addrs[num]);//,dstr(balances[num]));
                    for (j=0; j<num; j++)
                        if ( addrs[j] == addrs[num] )
                            break;
                    if ( j == num )
                    {
                        if ( addrs[num] == tp->nxt64bits )
                            myind = num;
                        PNACL_message("%llu ",(long long)addrs[num]);
                        num++;
                    }
                }
                else PNACL_message("%d: %llu mismatched walletitem bigblind %.8f ante %.8f rake %.1f%%\n",i,(long long)addrs[num],dstr(j64bits(walletitem,"bigblind")),dstr(j64bits(walletitem,"ante")),(double)juint(walletitem,"rakemillis")/10.);
            }
        }
    }
    PNACL_message("(%llu) pangea_start(%s) threadid.%d myind.%d num.%d maxplayers.%d\n",(long long)tp->nxt64bits,base,tp->threadid,myind,num,maxplayers);
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
        PNACL_message("swap out %d of %d\n",r+1,num);
        num--;
        isbot[r + 1] = isbot[num];
        //balances[r + 1] = balances[num];
        addrs[r + 1] = addrs[num];
    }
    PNACL_message("pangea numplayers.%d\n",num);
    if ( (sp= pangea_create(tp,&createdflag,base,timestamp,addrs,num,bigblind,ante,isbot,minbuyin,maxbuyin,hostrake)) == 0 )
    {
        PNACL_message("cant create table.(%s) numaddrs.%d\n",base,num);
        strcpy(retbuf,"{\"error\":\"cant create table, make sure all players have published NXT pubkeys\"}");
        return(-1);
    }
    PNACL_message("back from pangea_create\n");
    dp = sp->dp, dp->table = sp;
    sp->myslot = sp->myind = myind;
    if ( createdflag != 0 && myind == 0 && addrs[myind] == tp->nxt64bits )
    {
        tp->numcards = dp->numcards, tp->N = dp->N, tp->M = dp->M;
        PNACL_message("myind.%d: hostrake.%d\n",myind,dp->rakemillis);
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
                if ( (slot= pangeanet777_register(THREADS[0]->hn.server,sp->playerpubs[j],-1)) != j )
                    PNACL_message("unexpected register slot.%d for j.%d\n",slot,j);
            }
            //PNACL_message("thread[%d] pub.%llx priv.%llx\n",j,(long long)dp->playerpubs[j].txid,(long long)THREADS[j]->hn.client->H.privkey.txid);
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
