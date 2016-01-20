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

struct pangeanet777_id *pangeanet777_find(struct pangeanet777_server *srv,bits256 senderpub)
{
    int32_t i; uint64_t senderbits = acct777_nxt64bits(senderpub);
    if ( srv->num > 0 )
    {
        for (i=0; i<srv->max; i++)
            if ( srv->clients[i].nxt64bits == senderbits )
                return(&srv->clients[i]);
    }
    return(0);
}

void pangeanet777_lastcontact(struct pangeanet777_server *srv,bits256 senderpub)
{
    struct pangeanet777_id *ptr;
    if ( (ptr= pangeanet777_find(srv,senderpub)) != 0 )
        ptr->lastcontact = (uint32_t)time(NULL);
}

void pangeanet777_processmsg(uint64_t *destbitsp,bits256 *senderpubp,queue_t *Q,bits256 mypriv,bits256 mypub,uint8_t *msg,int32_t origlen,int32_t pmflag)
{
    char *jsonstr = 0; bits256 sig; uint32_t timestamp; int32_t len; uint64_t senderbits; uint8_t *ptr=0; cJSON *json; long extra;
    extra = sizeof(*senderpubp) + sizeof(*destbitsp) + sizeof(sig) + sizeof(senderbits) + sizeof(timestamp);
    if ( (len= origlen) > extra )
    {
        //printf("got msglen.%d\n",origlen);
        if ( (ptr= malloc(len*4 + 8192 + sizeof(struct queueitem) - extra)) == 0 )
        {
            printf("hostnet777_processmsg cant alloc queueitem\n");
            return;
        }
        if ( (len= SuperNET_decrypt(senderpubp,&senderbits,&timestamp,mypriv,mypub,&ptr[sizeof(struct queueitem)],len*4,msg,len)) > 1 && len < len*4 )
        {
            jsonstr = (char *)&ptr[sizeof(struct queueitem)];
            if ( (json= cJSON_Parse(jsonstr)) != 0 )
            {
                //printf("now.%lld vs millitime.%lld lag.%lld\n",(long long)now,(long long)millitime,(long long)(millitime - now));
                if ( pmflag != 0 && juint(json,"timestamp") != timestamp && juint(json,"timestamp")+1 != timestamp )
                    printf("msg.(%s) timestamp.%u mismatch | now.%ld\n",jsonstr,timestamp,(long)time(NULL));
                else if ( pmflag != 0 && j64bits(json,"sender") != senderbits )
                    printf("msg.(%ld) sender.%llu mismatch vs json.%llu\n",(long)strlen(jsonstr),(long long)senderbits,(long long)j64bits(json,"sender"));
                else
                {
                    //printf("%llu: QUEUE msg.%d\n",(long long)acct777_nxt64bits(mypub),len);
                    //if ( hostnet777_hashes(recvhashes,64,ptr,len) < 0 )
                    queue_enqueue("host777",Q,(void *)ptr,0);
                    ptr = 0;
                }
                free_json(json);
            } else printf("parse error.(%s)\n",jsonstr);
        } else printf("decrypt error len.%d origlen.%d\n",len,origlen);
    } else printf("origlen.%d\n",origlen);
    if ( ptr != 0 )
        free(ptr);
}

int32_t pangeanet777_idle(union pangeanet777 *hn)
{
    int32_t len,slot,sock,n = 0; bits256 senderpub,mypriv,mypub; uint64_t destbits; uint8_t *msg;
    long extra = sizeof(bits256)+sizeof(uint64_t);
    if ( (slot= hn->client->H.slot) != 0 )
    {
        mypriv = hn->client->H.privkey, mypub = hn->client->H.pubkey;
        if ( (sock= hn->client->subsock) >= 0 && (len= nn_recv(sock,&msg,NN_MSG,0)) > extra )
        {
            SuperNET_copybits(1,msg,(void *)&destbits,sizeof(uint64_t));
            //printf("client got pub len.%d\n",len);
            if ( destbits == 0 || destbits == hn->client->H.nxt64bits )
                pangeanet777_processmsg(&destbits,&senderpub,&hn->client->H.Q,mypriv,mypub,msg,len,0), n++;
            nn_freemsg(msg);
        } else if ( hn->client->H.pollfunc != 0 )
            (*hn->client->H.pollfunc)(hn);
    }
    else
    {
        //printf("server idle %.0f\n",milliseconds());
        mypriv = hn->server->H.privkey, mypub = hn->server->H.pubkey;
        for (slot=1; slot<hn->server->num; slot++)
        {
            //printf("check ind.%d %.0f\n",ind,milliseconds());
            if ( (sock= hn->server->clients[slot].pmsock) >= 0 && (len= nn_recv(sock,&msg,NN_MSG,0)) > extra )
            {
                //printf("server got pm[%d] %d\n",slot,len);
                SuperNET_copybits(1,msg,(void *)&destbits,sizeof(uint64_t));
                if ( destbits == 0 || destbits == hn->server->H.nxt64bits )
                {
                    pangeanet777_processmsg(&destbits,&senderpub,&hn->server->H.Q,mypriv,mypub,msg,len,1);
                    pangeanet777_lastcontact(hn->server,senderpub);
                }
                printf("pangeanet777_idle: do the send here\n");
                //pangeanet777_send(hn->server->pubsock,msg,len);
                nn_freemsg(msg);
            }
        }
        if ( hn->server->H.pollfunc != 0 )
            (*hn->server->H.pollfunc)(hn);
    }
    return(n);
}

int32_t pangeanet777_replace(struct pangeanet777_server *srv,bits256 clientpub,int32_t slot)
{
    char endpoint[128],buf[128]; uint64_t nxt64bits = acct777_nxt64bits(clientpub);
    sprintf(endpoint,"%s://%s:%u",srv->ep.transport,srv->ep.ipaddr,srv->ep.port + slot + 1);
    //sprintf(buf,"%s://127.0.0.1:%u",srv->ep.transport,srv->ep.port + slot + 1);
    strcpy(buf,endpoint);
    if ( srv->clients[slot].pmsock < 0 )
    {
        printf("pangeanet777_replace deal with getting new socket here\n");
        //srv->clients[slot].pmsock = nn_createsocket(buf,1,"NN_PULL",NN_PULL,srv->ep.port + slot + 1,10,10);
    }
    printf("NN_PULL.%d for slot.%d\n",srv->clients[slot].pmsock,slot);
    srv->clients[slot].pubkey = clientpub;
    srv->clients[slot].nxt64bits = nxt64bits;
    srv->clients[slot].lastcontact = (uint32_t)time(NULL);
    return(srv->clients[slot].pmsock);
}

int32_t pangeanet777_register(struct pangeanet777_server *srv,bits256 clientpub,int32_t slot)
{
    int32_t i,n; struct pangeanet777_id *ptr;
    if ( slot < 0 )
    {
        if ( (ptr= pangeanet777_find(srv,clientpub)) != 0 )
        {
            slot = (int32_t)(((long)ptr - (long)srv->clients) / sizeof(*srv->clients));
            //printf("pangea_register: deregister slot.%d\n",slot);
            if ( ptr->pmsock >= 0 )
                nn_shutdown(ptr->pmsock,0);
            memset(ptr,0,sizeof(*ptr));
            ptr->pmsock = -1;
            srv->num--;
            return(-1);
        }
        for (slot=1; slot<srv->max; slot++)
            if ( srv->clients[slot].nxt64bits == 0 )
                break;
    }
    if ( srv->num >= srv->max )
    {
        printf("pangea_register: cant register anymore num.%d vs max.%d\n",srv->num,srv->max);
        return(-1);
    }
    if ( (ptr= pangeanet777_find(srv,clientpub)) != 0 )
    {
        printf("pangea_register: cant register duplicate %llu\n",(long long)acct777_nxt64bits(clientpub));
        return((int32_t)(((long)ptr - (long)srv->clients) / sizeof(*srv->clients)));
    }
    if ( slot != srv->num )
    {
        printf("pangea_register: cant register slot.%d vs num.%d vs max.%d\n",slot,srv->num,srv->max);
        return(-1);
    }
    pangeanet777_replace(srv,clientpub,slot);
    srv->num++;
    for (i=n=0; i<srv->max; i++)
        if ( srv->clients[i].nxt64bits != 0 )
            n++;
    if ( n != srv->num )
    {
        printf("mismatched nonz nxt64bits n.%d vs %d\n",n,srv->num);
        srv->num = n;
    }
    return(slot);
}

struct pangeanet777_client *pangeanet777_client(bits256 privkey,bits256 pubkey,char *srvendpoint,int32_t slot)
{
    char endbuf[128],endbuf2[128]; uint16_t port; struct pangeanet777_client *ptr;
    ptr = calloc(1,sizeof(*ptr));
    ptr->H.slot = slot;
    ptr->H.privkey = privkey, ptr->H.pubkey = ptr->my.pubkey = pubkey;
    ptr->H.nxt64bits = ptr->my.nxt64bits = acct777_nxt64bits(pubkey);
    ptr->my.lastcontact = (uint32_t)time(NULL);
    strcpy(endbuf,srvendpoint);
    endbuf[strlen(endbuf)-4] = 0;
    port = atoi(&srvendpoint[strlen(endbuf)]);
    sprintf(endbuf2,"%s%u",endbuf,port + 1 + slot);
    printf("pangeanet777_client: deal with creating connections here\n");
    //ptr->my.pmsock = nn_createsocket(endbuf2,0,"NN_PUSH",NN_PUSH,0,10,100);
    printf("NN_PUSH %d from (%s) port.%d\n",ptr->my.pmsock,endbuf2,port+1+slot);
    sprintf(endbuf2,"%s%u",endbuf,port);
    //ptr->subsock = nn_createsocket(endbuf2,0,"NN_SUB",NN_SUB,0,10,100);
    printf("SUB %d from (%s) port.%d\n",ptr->subsock,endbuf2,port);
    nn_setsockopt(ptr->subsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
    //sprintf(endbuf2,"%s%u",endbuf,port);
    //ptr->pushsock = nn_createsocket(endbuf2,0,"NN_PUSH",NN_PUSH,0,10,1);
    //printf("PUSH %d to (%s)\n",ptr->pushsock,endbuf2);
    return(ptr);
}

void pangeanet777_freeclient(struct pangeanet777_client *client)
{
    client->H.done = 1;
    if ( client->subsock >= 0 )
        nn_shutdown(client->subsock,0);
    //if ( client->pushsock >= 0 )
    //    nn_shutdown(client->pushsock,0);
    if ( client->my.pmsock >= 0 )
        nn_shutdown(client->my.pmsock,0);
}

void pangeanet777_freeserver(struct pangeanet777_server *srv)
{
    int32_t ind;
    srv->H.done = 1;
    //if ( srv->pullsock >= 0 )
    //    nn_shutdown(srv->pullsock,0);
    if ( srv->pubsock >= 0 )
        nn_shutdown(srv->pubsock,0);
    for (ind=1; ind<srv->max; ind++)
    {
        if ( srv->clients[ind].pmsock >= 0 )
            nn_shutdown(srv->clients[ind].pmsock,0);
    }
}

struct pangeanet777_server *pangeanet777_server(bits256 srvprivkey,bits256 srvpubkey,char *transport,char *ipaddr,uint16_t port,int32_t maxclients)
{
    struct pangeanet777_server *srv; int32_t i; struct pangeanet777_endpoint *ep; char buf[128];
    srv = calloc(1,sizeof(*srv) + maxclients*sizeof(struct pangeanet777_id));
    srv->max = maxclients;
    ep = &srv->ep;
    if ( (ep->port= port) == 0 )
        ep->port = port = 8000 + (rand() % 1000);
    if ( transport == 0 || transport[0] == 0 )
        transport = TEST_TRANSPORT;
    if ( ipaddr == 0 || ipaddr[0] == 0 )
        ipaddr = "127.0.0.1";
    strcpy(ep->transport,transport), strcpy(ep->ipaddr,ipaddr);
    for (i=0; i<maxclients; i++)
        srv->clients[i].pmsock = -1;
    srv->H.privkey = srvprivkey;
    srv->H.pubkey = srv->clients[0].pubkey = srvpubkey;
    srv->H.nxt64bits = srv->clients[0].nxt64bits = acct777_nxt64bits(srvpubkey);
    sprintf(ep->endpoint,"%s://%s:%u",transport,ipaddr,port);
    if ( strcmp(transport,"tcpmux") == 0 )
        strcat(ep->endpoint,"/pangea");
    //sprintf(buf,"%s://127.0.0.1:%u",transport,port);
    strcpy(buf,ep->endpoint);
    printf("pangeanet777_server: create socket here\n");
    //srv->pubsock = nn_createsocket(buf,1,"NN_PUB",NN_PUB,port,10,100);
    printf("PUB.%d to (%s) pangeaport.%d\n",srv->pubsock,ep->endpoint,port);
    srv->num = 1;
    return(srv);
}

void *pangeanet777_idler(union pangeanet777 *ptr)
{
    while ( ptr->client->H.done == 0 )
    {
        if ( pangeanet777_idle(ptr) == 0 )
            usleep(1000);
    }
    //printf("pangea_idler ind.%d done\n",ptr->client->H.slot);
    sleep(1);
    free(ptr);
    return(0);
}

int32_t SuperNET_sendmsg(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,bits256 destpub,bits256 mypriv,bits256 mypub,uint8_t *msg,int32_t len,uint8_t *data,int32_t delaymillis);

#define pangeanet777_broadcast(mypriv,mypub,msg,len) SuperNET_sendmsg(myinfo,coin,addr,zeropoint,mypriv,mypub,msg,len,space,0)
#define pangeanet777_blindcast(msg,len) SuperNET_sendmsg(myinfo,coin,addr,zeropoint,zeropoint,zeropoint,msg,len,space,0)
#define pangeanet777_signedPM(destpub,mypriv,mypub,msg,len) SuperNET_sendmsg(myinfo,coin,addr,destpub,mypriv,mypub,msg,len,space,0)
#define pangeanet777_blindPM(destpub,msg,len) SuperNET_sendmsg(myinfo,coin,addr,destpub,zeropoint,zeropoint,msg,len,space,0)
void pangeanet777_msg(uint64_t destbits,bits256 destpub,union pangeanet777 *src,int32_t blindflag,char *jsonstr,int32_t len)
{
    static bits256 zeropoint;
    struct supernet_info *myinfo = SuperNET_MYINFO(0); uint8_t *space;
    struct iguana_peer *addr = 0; struct iguana_info *coin = iguana_coinfind("BTCD");
    if ( destbits == 0 )
    {
        //printf(">>>>>>>>> blind.%d broadcast from %llu, len.%d\n",blindflag,(long long)src->client->H.nxt64bits,len);
        space = calloc(1,IGUANA_MAXPACKETSIZE);
        if ( blindflag != 0 )
            pangeanet777_blindcast((uint8_t *)jsonstr,len);
        else pangeanet777_broadcast(src->client->H.privkey,src->client->H.pubkey,(uint8_t *)jsonstr,len);
        free(space);
        if ( src->server->H.slot == 0 )
            queue_enqueue("loopback",&src->client->H.Q,queueitem(jsonstr),1);
    }
    else if ( destbits != src->client->H.nxt64bits )
    {
        //printf(">>>>>>>>> blind.%d PM from %llu to %llu\n",blindflag,(long long)src->client->H.nxt64bits,(long long)destbits);
        space = calloc(1,IGUANA_MAXPACKETSIZE);
        if ( blindflag != 0 )
            pangeanet777_blindPM(destpub,(uint8_t *)jsonstr,len);
        else pangeanet777_signedPM(destpub,src->client->H.privkey,src->client->H.pubkey,(uint8_t *)jsonstr,len);
        free(space);
    }
    else queue_enqueue("loopback",&src->client->H.Q,queueitem(jsonstr),1);
}

int32_t pangea_search(struct pangea_info *sp,uint64_t nxt64bits)
{
    int32_t i;
    for (i=0; i<sp->numactive; i++)
        if ( sp->active[i] == nxt64bits )
            return(i);
    for (i=0; i<sp->numactive; i++)
        PNACL_message("%llu ",(long long)sp->active[i]);
    PNACL_message("active[]\n");
    for (i=0; i<sp->numaddrs; i++)
        PNACL_message("%llu ",(long long)sp->addrs[i]);
    PNACL_message("addrs[]\n");
    PNACL_message("pangea_search: slot.%d ind.%d cant find %llu in active[%d]\n",sp->myslot,sp->myind,(long long)nxt64bits,sp->numactive);
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

int32_t pangea_addplayer(struct cards777_pubdata *dp,struct pangea_info *sp,bits256 clientpub)
{
    int32_t i,n,openslot = -1; uint64_t nxt64bits = acct777_nxt64bits(clientpub);
    for (i=n=0; i<sp->numaddrs; i++)
    {
        if ( sp->addrs[i] == nxt64bits )
        {
            PNACL_message("pangea_addplayer: player %llu already in addrs[%d]\n",(long long)nxt64bits,i);
            return(-1);
        }
        if ( sp->balances[i] <= 0 )
            openslot = i;
    }
    if ( openslot < 0 || sp->numactive >= sp->numaddrs-1 )
    {
        PNACL_message("pangea_addplayer: no room to add %llu\n",(long long)nxt64bits);
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
            pangeanet777_replace(sp->tp->hn.server,clientpub,openslot);
            for (i=0; i<sp->numactive; i++)
                isbot[i] = sp->isbot[i];
            pangea_create_newtable(retbuf,sp,dp,isbot);
            pangeanet777_msg(nxt64bits,clientpub,&sp->tp->hn,0,retbuf,(int32_t)strlen(retbuf)+1);
            free(retbuf);
        }
    }
    pangea_neworder(dp,sp,0,0);
    return(n);
}

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
    PNACL_message("PANGEA PURGE %llu\n",(long long)sp->tableid);
    free(sp);
}

