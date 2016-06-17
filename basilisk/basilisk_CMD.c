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

// included from basilisk.c

struct iguana_peer *basilisk_ensurerelay(struct iguana_info *btcd,uint32_t ipbits)
{
    struct iguana_peer *addr;
    if ( (addr= iguana_peerfindipbits(btcd,ipbits,0)) == 0 )
    {
        if ( (addr= iguana_peerslot(btcd,ipbits,0)) != 0 )
        {
            printf("launch peer for relay\n");
            addr->isrelay = 1;
            iguana_launch(btcd,"addrelay",iguana_startconnection,addr,IGUANA_CONNTHREAD);
        } else printf("error getting peerslot\n");
    } else addr->isrelay = 1;
    return(addr);
}

char *basilisk_addrelay_info(struct supernet_info *myinfo,char *btcdaddr,uint32_t ipbits,bits256 pubkey,char *sigstr)
{
    int32_t i; struct basilisk_relay *rp; struct iguana_info *btcd;
    if ( (btcd= iguana_coinfind("BTCD")) == 0 )
        return(clonestr("{\"error\":\"add relay needs BTCD\"}"));
    for (i=0; i<myinfo->numrelays; i++)
    {
        rp = &myinfo->relays[i];
        if ( ipbits == rp->ipbits )
            return(clonestr("{\"error\":\"relay already there\"}"));
    }
    if ( i >= sizeof(myinfo->relays)/sizeof(*myinfo->relays) )
        i = (rand() % (sizeof(myinfo->relays)/sizeof(*myinfo->relays)));
    rp = &myinfo->relays[i];
    printf("verify relay sig\n");
    rp->ipbits = ipbits;
    rp->pubkey = pubkey;
    safecopy(rp->btcdaddr,btcdaddr,sizeof(rp->btcdaddr));
    safecopy(rp->sigstr,sigstr,sizeof(rp->sigstr));
    rp->addr = basilisk_ensurerelay(btcd,rp->ipbits);
    for (i=0; i<myinfo->numrelays; i++)
        myinfo->relaybits[i] = myinfo->relays[i].ipbits;
    revsort32(&myinfo->relaybits[0],myinfo->numrelays,sizeof(myinfo->relaybits[0]));
    return(clonestr("{\"result\":\"relay added\"}"));
}

char *basilisk_respond_relays(struct supernet_info *myinfo,char *CMD,void *_addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    uint32_t *ipbits = (uint32_t *)data; int32_t num,i,j,n = datalen >> 2;
    for (i=num=0; i<n; i++)
    {
        for (j=0; j<myinfo->numrelays; j++)
            if ( ipbits[i] == myinfo->relays[j].ipbits )
                break;
        if ( j == myinfo->numrelays )
        {
            num++;
            printf("ensure unknown relay\n");
            basilisk_ensurerelay(iguana_coinfind("BTCD"),ipbits[i]);
        }
    }
    if ( num == 0 )
        return(clonestr("{\"result\":\"no new relays found\"}"));
    else return(clonestr("{\"result\":\"relay added\"}"));
}

char *basilisk_respond_goodbye(struct supernet_info *myinfo,char *CMD,void *_addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    struct iguana_peer *addr = _addr;
    printf("(%s) sends goodbye\n",remoteaddr);
    addr->dead = (uint32_t)time(NULL);
    addr->rank = 0;
    return(0);
}

void basilisk_request_goodbye(struct supernet_info *myinfo)
{
    cJSON *valsobj = cJSON_CreateObject();
    jaddnum(valsobj,"timeout",-1);
    basilisk_requestservice(myinfo,"BYE",valsobj,GENESIS_PUBKEY,0,0,0);
    free_json(valsobj);
}

char *basilisk_respond_instantdex(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *retstr=0;
    printf("from.(%s) DEX.(%s) datalen.%d\n",remoteaddr,jprint(valsobj,0),datalen);
    instantdex_quotep2p(myinfo,0,addr,data,datalen);
    return(retstr);
}

char *basilisk_respond_dispatch(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *ipaddr,*btcdaddr,*sigstr,*retstr=0;
    printf("from.(%s) ADD.(%s) datalen.%d\n",remoteaddr,jprint(valsobj,0),datalen);
    if ( (ipaddr= jstr(valsobj,"ipaddr")) != 0 && (btcdaddr= jstr(valsobj,"btcdaddr")) != 0 && (sigstr= jstr(valsobj,"sigstr")) != 0 )
        retstr = basilisk_addrelay_info(myinfo,btcdaddr,(uint32_t)calc_ipbits(ipaddr),hash,sigstr);
    else retstr = clonestr("{\"error\":\"need rmd160, address and ipaddr\"}");
    return(retstr);
}

char *basilisk_respond_addrelay(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_forward(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_mailbox(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_VPNcreate(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_VPNjoin(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_VPNlogout(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_VPNbroadcast(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_VPNreceive(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_VPNmessage(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}


