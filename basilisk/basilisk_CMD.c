/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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

/*int32_t basilisk_relayid(struct supernet_info *myinfo,char *ipaddr)
{
    uint32_t i,ipbits = (uint32_t)calc_ipbits(ipaddr);
    for (i=0; i<NUMRELAYS; i++)
        if ( ipbits == RELAYS[i].ipbits )
            return(i);
    return(-1);
}*/

void basilisk_ensurerelay(struct supernet_info *myinfo,struct iguana_info *notaries,uint32_t ipbits)
{
    char ipaddr[64];
    expand_ipbits(ipaddr,ipbits);
//#if ISNOTARYNODE
    //dpow_nanomsginit(myinfo,ipaddr);
//#else
    struct iguana_peer *addr; int32_t i;
    if ( notaries == 0 || ipbits == myinfo->myaddr.myipbits )
        return;
    if ( (addr= iguana_peerfindipbits(notaries,ipbits,0)) == 0 )
    {
        if ( (addr= iguana_peerslot(notaries,ipbits,0)) != 0 && addr->isrelay == 0 )
        {
            printf("launch peer.%s for relay vs (%s)\n",ipaddr,myinfo->ipaddr);
            addr->isrelay = 1;
            myinfo->NOTARY.RELAYID = -1;
            for (i=0; i<myinfo->NOTARY.NUMRELAYS; i++)
                if ( myinfo->NOTARY.RELAYS[i].ipbits == myinfo->myaddr.myipbits )
                {
                    myinfo->NOTARY.RELAYID = i;
                    break;
                }
            iguana_launch(notaries,"addrelay",iguana_startconnection,addr,IGUANA_CONNTHREAD);
        } else printf("error getting peerslot\n");
    } else addr->isrelay = 1;
//#endif
}

static int _increasing_ipbits(const void *a,const void *b)
{
#define uint32_a (*(struct basilisk_relay *)a).ipbits
#define uint32_b (*(struct basilisk_relay *)b).ipbits
	if ( uint32_b > uint32_a )
		return(-1);
	else if ( uint32_b < uint32_a )
		return(1);
	return(0);
#undef uint32_a
#undef uint32_b
}

void basilisk_relay_remap(struct supernet_info *myinfo,struct basilisk_relay *rp)
{
    int32_t i; struct basilisk_relaystatus tmp[BASILISK_MAXRELAYS];
    // need to verify this works
    for (i=0; i<myinfo->NOTARY.NUMRELAYS; i++)
        tmp[i] = rp->reported[i];
    for (i=0; i<myinfo->NOTARY.NUMRELAYS; i++)
        rp->reported[myinfo->NOTARY.RELAYS[i].relayid] = tmp[myinfo->NOTARY.RELAYS[i].oldrelayid];
}

void basilisk_setmyid(struct supernet_info *myinfo)
{
    int32_t i; char ipaddr[64]; struct iguana_info *notaries = iguana_coinfind("RELAY");
    for (i=0; i<myinfo->NOTARY.NUMRELAYS; i++)
    {
        expand_ipbits(ipaddr,myinfo->NOTARY.RELAYS[i].ipbits);
        if ( myinfo->myaddr.myipbits == myinfo->NOTARY.RELAYS[i].ipbits )
            myinfo->NOTARY.RELAYID = i;
        basilisk_ensurerelay(myinfo,notaries,myinfo->NOTARY.RELAYS[i].ipbits);
    }
}

char *basilisk_addrelay_info(struct supernet_info *myinfo,uint8_t *pubkey33,uint32_t ipbits,bits256 pubkey)
{
    int32_t i; struct basilisk_relay *rp;
    for (i=0; i<myinfo->NOTARY.NUMRELAYS; i++)
    {
        rp = &myinfo->NOTARY.RELAYS[i];
        if ( ipbits == rp->ipbits )
        {
            if ( bits256_cmp(GENESIS_PUBKEY,pubkey) != 0 && bits256_nonz(pubkey) != 0 )
                rp->pubkey = pubkey;
            if ( pubkey33 != 0 && pubkey33[0] != 0 )
                memcpy(rp->pubkey33,pubkey33,33);
            basilisk_setmyid(myinfo);
            //printf("updated relay[%d] %x vs mine.%x\n",i,ipbits,myinfo->myaddr.myipbits);
            return(clonestr("{\"error\":\"relay already there\"}"));
        }
    }
    if ( i >= sizeof(myinfo->NOTARY.RELAYS)/sizeof(*myinfo->NOTARY.RELAYS) )
        i = (rand() % (sizeof(myinfo->NOTARY.RELAYS)/sizeof(*myinfo->NOTARY.RELAYS)));
    printf("add relay[%d] <- %x\n",i,ipbits);
    for (i=0; i<myinfo->NOTARY.NUMRELAYS; i++)
        myinfo->NOTARY.RELAYS[i].oldrelayid = i;
    rp = &myinfo->NOTARY.RELAYS[i];
    rp->ipbits = ipbits;
    rp->relayid = myinfo->NOTARY.NUMRELAYS;
    basilisk_ensurerelay(myinfo,iguana_coinfind("RELAY"),rp->ipbits);
    if ( myinfo->NOTARY.NUMRELAYS < sizeof(myinfo->NOTARY.RELAYS)/sizeof(*myinfo->NOTARY.RELAYS) )
        myinfo->NOTARY.NUMRELAYS++;
    qsort(myinfo->NOTARY.RELAYS,myinfo->NOTARY.NUMRELAYS,sizeof(myinfo->NOTARY.RELAYS[0]),_increasing_ipbits);
    for (i=0; i<myinfo->NOTARY.NUMRELAYS; i++)
        myinfo->NOTARY.RELAYS[i].relayid = i;
    basilisk_setmyid(myinfo);
    printf("sorted MYRELAYID.%d\n",myinfo->NOTARY.RELAYID);
    for (i=0; i<myinfo->NOTARY.NUMRELAYS; i++)
        basilisk_relay_remap(myinfo,&myinfo->NOTARY.RELAYS[i]);
    return(clonestr("{\"result\":\"relay added\"}"));
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
    basilisk_requestservice(myinfo,0,"BYE",0,valsobj,GENESIS_PUBKEY,0,0,0);
    free_json(valsobj);
}

char *basilisk_respond_addrelay(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *ipaddr,*retstr=0;
    if ( valsobj == 0 )
        return(clonestr("{\"error\":\"null valsobj\"}"));
    if ( (ipaddr= jstr(valsobj,"ipaddr")) != 0 )
        retstr = basilisk_addrelay_info(myinfo,0,(uint32_t)calc_ipbits(ipaddr),jbits256(valsobj,"pubkey"));
    else retstr = clonestr("{\"error\":\"need rmd160, address and ipaddr\"}");
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

/*char *basilisk_respond_rawtx(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *symbol,*retstr=0; struct basilisk_item Lptr,*ptr; int32_t timeoutmillis; struct iguana_info *coin = 0;
    timeoutmillis = jint(valsobj,"timeout");
    if ( (symbol= jstr(valsobj,"coin")) != 0 || (symbol= jstr(valsobj,"symbol")) != 0 )
        coin = iguana_coinfind(symbol);
    if ( coin != 0 && (ptr= basilisk_bitcoinrawtx(&Lptr,myinfo,coin,remoteaddr,basilisktag,timeoutmillis,valsobj)) != 0 )
    {
        retstr = ptr->retstr;
        ptr->finished = OS_milliseconds() + 10000;
    } else retstr = clonestr("{\"error\":\"no coin specified or error bitcoinrawtx\"}");
    return(retstr);
}*/

char *basilisk_respond_value(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *symbol,*retstr=0; struct basilisk_item Lptr,*ptr; int32_t timeoutmillis; struct iguana_info *coin = 0;
    timeoutmillis = jint(valsobj,"timeout");
    if ( (symbol= jstr(valsobj,"coin")) != 0 || (symbol= jstr(valsobj,"symbol")) != 0 )
        coin = iguana_coinfind(symbol);
    if ( coin != 0 && (ptr= basilisk_bitcoinvalue(&Lptr,myinfo,coin,remoteaddr,basilisktag,timeoutmillis,valsobj)) != 0 )
    {
        retstr = ptr->retstr;
        ptr->finished = OS_milliseconds() + 10000;
    } else retstr = clonestr("{\"error\":\"no coin specified or error bitcoin value\"}");
    return(retstr);
}

char *basilisk_respond_balances(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *symbol,*retstr=0; struct basilisk_item Lptr,*ptr; int32_t timeoutmillis; struct iguana_info *coin = 0;
    timeoutmillis = jint(valsobj,"timeout");
    if ( (symbol= jstr(valsobj,"coin")) != 0 || (symbol= jstr(valsobj,"symbol")) != 0 )
        coin = iguana_coinfind(symbol);
    if ( coin != 0 && (ptr= basilisk_bitcoinbalances(&Lptr,myinfo,coin,remoteaddr,basilisktag,timeoutmillis,valsobj)) != 0 )
    {
        retstr = ptr->retstr;
        ptr->finished = OS_milliseconds() + 10000;
    } else retstr = clonestr("{\"error\":\"no coin specified or error bitcoin balances\"}");
    return(retstr);
}

char *basilisk_respond_getinfo(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *symbol,*retstr=0; struct basilisk_item Lptr,*ptr; int32_t timeoutmillis; struct iguana_info *coin = 0;
    if ( (timeoutmillis= jint(valsobj,"timeout")) <= 0 )
        timeoutmillis = 5000;
    if ( (symbol= jstr(valsobj,"coin")) != 0 || (symbol= jstr(valsobj,"symbol")) != 0 )
        coin = iguana_coinfind(symbol);
    if ( coin != 0 && (ptr= basilisk_getinfo(&Lptr,myinfo,coin,remoteaddr,basilisktag,timeoutmillis,valsobj)) != 0 )
    {
        retstr = ptr->retstr;
        ptr->finished = OS_milliseconds() + 10000;
    } else retstr = clonestr("{\"error\":\"no coin specified or error bitcoin getinfo\"}");
    return(retstr);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

HASH_ARRAY_STRING(basilisk,vote,hash,vals,hexstr)
{
    return(basilisk_standardservice("VOT",myinfo,0,hash,vals,hexstr,0));
}

HASH_ARRAY_STRING(basilisk,addrelay,hash,vals,hexstr)
{
    return(basilisk_standardservice("ADD",myinfo,0,hash,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,relays,hash,vals,hexstr)
{
    return(basilisk_standardservice("RLY",myinfo,0,hash,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,dispatch,hash,vals,hexstr)
{
    return(basilisk_standardservice("RUN",myinfo,0,hash,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,publish,hash,vals,hexstr)
{
    return(basilisk_standardservice("PUB",myinfo,0,hash,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,subscribe,hash,vals,hexstr)
{
    return(basilisk_standardservice("SUB",myinfo,0,hash,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,forward,hash,vals,hexstr)
{
    return(basilisk_standardservice("HOP",myinfo,0,hash,vals,hexstr,0));
}

HASH_ARRAY_STRING(basilisk,mailbox,hash,vals,hexstr)
{
    return(basilisk_standardservice("BOX",myinfo,0,hash,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,VPNcreate,hash,vals,hexstr)
{
    return(basilisk_standardservice("VPN",myinfo,0,hash,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,VPNjoin,hash,vals,hexstr)
{
    return(basilisk_standardservice("ARC",myinfo,0,hash,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,VPNmessage,hash,vals,hexstr)
{
    return(basilisk_standardservice("GAB",myinfo,0,hash,vals,hexstr,0));
}

HASH_ARRAY_STRING(basilisk,VPNbroadcast,hash,vals,hexstr)
{
    return(basilisk_standardservice("SAY",myinfo,0,hash,vals,hexstr,0));
}

HASH_ARRAY_STRING(basilisk,VPNreceive,hash,vals,hexstr)
{
    return(basilisk_standardservice("EAR",myinfo,0,hash,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,VPNlogout,hash,vals,hexstr)
{
    return(basilisk_standardservice("END",myinfo,0,hash,vals,hexstr,0));
}

uint16_t basilisk_portavailable(struct supernet_info *myinfo,uint16_t port)
{
    struct iguana_info *coin,*tmp;
    if ( port < 10000 )
        return(0);
    HASH_ITER(hh,myinfo->allcoins,coin,tmp)
    {
        if ( port == coin->chain->portp2p || port == coin->chain->rpcport )
            return(0);
    }
    return(port);
}

HASH_ARRAY_STRING(basilisk,genesis_opreturn,hash,vals,hexstr)
{
    int32_t len; uint16_t blocktime,port; uint8_t p2shval,wifval; uint8_t serialized[4096],tmp[4]; char hex[8192],*symbol,*name,*destaddr; uint64_t PoSvalue; uint32_t nBits;
    symbol = jstr(vals,"symbol");
    name = jstr(vals,"name");
    destaddr = jstr(vals,"issuer");
    PoSvalue = jdouble(vals,"stake") * SATOSHIDEN;
    if ( (blocktime= juint(vals,"blocktime")) == 0 )
        blocktime = 1;
    p2shval = juint(vals,"p2sh");
    wifval = juint(vals,"wif");
    if ( (port= juint(vals,"port")) == 0 )
        while ( (port= basilisk_portavailable(myinfo,(rand() % 50000) + 10000)) == 0 )
            ;
    if ( jstr(vals,"nBits") != 0 )
    {
        decode_hex((void *)&tmp,sizeof(tmp),jstr(vals,"nBits"));
        ((uint8_t *)&nBits)[0] = tmp[3];
        ((uint8_t *)&nBits)[1] = tmp[2];
        ((uint8_t *)&nBits)[2] = tmp[1];
        ((uint8_t *)&nBits)[3] = tmp[0];
    } else nBits = 0x1e00ffff;
    len = datachain_opreturn_create(serialized,symbol,name,destaddr,PoSvalue,nBits,blocktime,port,p2shval,wifval);
    init_hexbytes_noT(hex,serialized,len);
    return(clonestr(hex));
}

#include "../includes/iguana_apiundefs.h"

