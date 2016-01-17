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

#include "iguana777.h"

int32_t SuperNET_delaymillis(struct supernet_info *myinfo,int32_t maxdelay)
{
    maxdelay += myinfo->maxdelay;
    if ( maxdelay > SUPERNET_MAXDELAY )
        maxdelay = SUPERNET_MAXDELAY;
    return(rand() % maxdelay);
}

void SuperNET_remotepeer(struct supernet_info *myinfo,struct iguana_info *coin,char *symbol,char *ipaddr,int32_t supernetflag)
{
    uint64_t ipbits; struct iguana_peer *addr;
    //printf("got %s remotepeer.(%s) supernet.%d\n",symbol,ipaddr,supernetflag);
    if ( supernetflag != 0 )
    {
        ipbits = calc_ipbits(ipaddr);
        if ( (addr= iguana_peerslot(coin,ipbits)) != 0 )
        {
            printf("launch startconnection to supernet peer.(%s)\n",ipaddr);
            iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
            return;
        }
    }
    iguana_possible_peer(coin,ipaddr);
}

int32_t SuperNET_confirmip(struct supernet_info *myinfo,uint32_t ipbits)
{
    int32_t i,j,total = 0; uint32_t x;
    for (i=0; i<IGUANA_MAXCOINS; i++)
    {
        if ( Coins[i] != 0 )
        {
            for (j=0; j<IGUANA_MAXPEERS; j++)
            {
                if ( (x= Coins[i]->peers.active[j].myipbits) != 0 )
                {
                    if ( x == ipbits )
                        total++;
                    else total--;
                }
            }
        }
    }
    return(total);
}

void SuperNET_myipaddr(struct supernet_info *myinfo,struct iguana_peer *addr,char *myipaddr,char *remoteaddr)
{
    uint32_t myipbits = (uint32_t)calc_ipbits(myipaddr);
    if ( addr->myipbits == 0 )
        addr->myipbits = myipbits;
    else if ( addr->myipbits != myipbits )
    {
        printf("%s: myipaddr conflict %x != %x?\n",addr->ipaddr,addr->myipbits,myipbits);
        addr->myipbits = 0;
    }
    if ( addr->myipbits != 0 && myinfo->myaddr.myipbits == 0 )
        myinfo->myaddr.myipbits = addr->myipbits;
    if ( addr->myipbits == myinfo->myaddr.myipbits )
    {
        myinfo->myaddr.confirmed++;
        if ( myinfo->myaddr.selfipbits == 0 || myinfo->ipaddr[0] == 0 )
        {
            if ( (myinfo->myaddr.totalconfirmed= SuperNET_confirmip(myinfo,addr->myipbits)) > 3 )
                myinfo->myaddr.selfipbits = addr->myipbits;
        }
    }
    else myinfo->myaddr.confirmed--;
    if ( myinfo->myaddr.selfipbits == myinfo->myaddr.myipbits )
    {
        expand_ipbits(myinfo->ipaddr,myinfo->myaddr.selfipbits);
        vcalc_sha256(0,myinfo->myaddr.iphash.bytes,(uint8_t *)&myinfo->myaddr.selfipbits,sizeof(myinfo->myaddr.selfipbits));
    }
}

int32_t SuperNET_json2bits(struct supernet_info *myinfo,uint8_t *serialized,int32_t maxsize,char *destip,bits256 destpub,cJSON *json)
{
    uint32_t ipbits; uint64_t tag; char *hexmsg; int32_t n,len = 0;
    if ( (tag= j64bits(json,"tag")) == 0 )
        OS_randombytes((uint8_t *)&tag,sizeof(tag));
    ipbits = (uint32_t)calc_ipbits(destip);
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&ipbits);
    ipbits = (uint32_t)calc_ipbits(myinfo->ipaddr);
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&ipbits);
    len += iguana_rwbignum(1,&serialized[len],sizeof(myinfo->myaddr.pubkey),myinfo->myaddr.pubkey.bytes);
    len += iguana_rwnum(1,&serialized[len],sizeof(tag),&tag);
    if ( (hexmsg= jstr(json,"message")) != 0 )
    {
        n = (int32_t)strlen(hexmsg);
        if ( (n & 1) == 0 && is_hexstr(hexmsg,n) > 0 )
        {
            n >>= 1;
            decode_hex(&serialized[len],n,hexmsg);
        } else return(-1);
    }
    return(len);
}

cJSON *SuperNET_bits2json(struct supernet_info *myinfo,bits256 prevpub,uint8_t *serialized,int32_t datalen)
{
    char destip[64],myipaddr[64],str[65],*hexmsg; uint64_t tag; int32_t len = 0;
    uint32_t destipbits,myipbits; bits256 senderpub; cJSON *json = cJSON_CreateObject();
    int32_t i; for (i=0; i<datalen; i++)
        printf("%02x ",serialized[i]);
    printf("bits[%d]\n",datalen);
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&destipbits);
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&myipbits);
    len += iguana_rwbignum(0,&serialized[len],sizeof(bits256),senderpub.bytes);
    len += iguana_rwnum(0,&serialized[len],sizeof(tag),&tag);
    printf("-> dest.%x myip.%x senderpub.%llx tag.%llu\n",destipbits,myipbits,(long long)senderpub.txid,(long long)tag);
    expand_ipbits(destip,destipbits), jaddstr(json,"yourip",destip);
    expand_ipbits(myipaddr,myipbits), jaddstr(json,"myip",myipaddr);
    jaddstr(json,"mypub",bits256_str(str,senderpub));
    jadd64bits(json,"tag",tag);
    if ( len < datalen )
    {
        printf("len %d vs %d datalen\n",len,datalen);
        hexmsg = malloc(((datalen - len)<<1) + 1);
        init_hexbytes_noT(hexmsg,&serialized[len],datalen - len);
        printf("hex.(%s)\n",hexmsg);
        jaddstr(json,"message",hexmsg);
        free(hexmsg);
    }
    return(json);
}

int32_t iguana_send_supernet(struct iguana_info *coin,struct iguana_peer *addr,char *jsonstr,int32_t delaymillis)
{
    int32_t datalen,qlen = -1; uint8_t *serialized; cJSON *json;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        serialized = malloc(sizeof(struct iguana_msghdr) + IGUANA_MAXPACKETSIZE);
        datalen = SuperNET_json2bits(SuperNET_MYINFO(0),&serialized[sizeof(struct iguana_msghdr)],IGUANA_MAXPACKETSIZE,addr->ipaddr,addr->pubkey,json);
        printf("SUPERSEND.(%s) -> (%s) delaymillis.%d\n",jsonstr,addr->ipaddr,delaymillis);
        qlen = iguana_queue_send(coin,addr,delaymillis,serialized,"SuperNET",datalen,0,1);
        free(serialized);
    }
    return(qlen);
}

char *SuperNET_DHTsend(struct supernet_info *myinfo,bits256 routehash,char *hexmsg,int32_t maxdelay)
{
    static int lastpurge; static uint64_t Packetcache[1024];
    bits256 packethash; char retbuf[512]; int32_t i,j,datalen,firstz,iter,n = 0; char *jsonstr=0;
    struct iguana_peer *addr; cJSON *json;
    if ( myinfo == 0 )
        return(clonestr("{\"error\":\"no supernet_info\"}"));
    datalen = (int32_t)strlen(hexmsg) + 1;
    json = cJSON_CreateObject();
    jaddstr(json,"message",hexmsg);
    jsonstr = jprint(json,1);
    vcalc_sha256(0,packethash.bytes,(void *)hexmsg,datalen);
    firstz = -1;
    for (i=0; i<sizeof(Packetcache)/sizeof(*Packetcache); i++)
    {
        if ( Packetcache[i] == 0 )
        {
            Packetcache[i] = packethash.txid;
            printf("add.%llx packetcache(%s)\n",(long long)packethash.txid,hexmsg);
            break;
        }
        else if ( Packetcache[i] == packethash.txid )
        {
            printf("SuperNET_DHTsend reject repeated packet.%llx (%s)\n",(long long)packethash.txid,hexmsg);
            return(clonestr("{\"error\":\"duplicate packet rejected\"}"));
        }
    }
    if ( i == sizeof(Packetcache)/sizeof(*Packetcache) )
    {
        printf("purge slot[%d]\n",lastpurge);
        Packetcache[lastpurge++] = packethash.txid;
        if ( lastpurge >= sizeof(Packetcache)/sizeof(*Packetcache) )
            lastpurge = 0;
    }
    for (iter=0; iter<2; iter++)
    {
        for (i=0; i<IGUANA_MAXCOINS; i++)
        {
            if ( Coins[i] != 0 )
            {
                for (j=0; j<IGUANA_MAXPEERS; j++)
                {
                    addr = &Coins[i]->peers.active[j];
                    if ( addr->usock >= 0 )
                    {
                        if ( iter == 0 && memcmp(addr->iphash.bytes,routehash.bytes,sizeof(addr->iphash)) == 0 )
                        {
                            iguana_send_supernet(Coins[i],addr,jsonstr,maxdelay==0?0:rand()%maxdelay);
                            return(clonestr("{\"result\":\"packet sent directly to destip\"}"));
                        }
                        else if ( iter == 1 )
                        {
                            char str[65],str2[65]; printf("%s vs %s -> %d\n",bits256_str(str,packethash),bits256_str(str2,addr->iphash),bits256_cmp(addr->iphash,packethash));
                            if ( bits256_cmp(addr->iphash,packethash) < 0 )
                            {
                                iguana_send_supernet(Coins[i],addr,jsonstr,maxdelay==0?0:rand()%maxdelay);
                                n++;
                            }
                        }
                    }
                }
            }
        }
    }
    if ( jsonstr != 0 )
        free(jsonstr);
    if ( n > 0 )
        sprintf(retbuf,"{\"result\":\"packet forwarded to superDHT\",\"branches\":%d}",n);
    else sprintf(retbuf,"{\"error\":\"no nodes to forward packet to\"}");
    return(clonestr(retbuf));
}

char *SuperNET_DHTencode(struct supernet_info *myinfo,char *destip,bits256 destpub,char *hexmsg,int32_t maxdelay)
{
    uint32_t destipbits; bits256 routehash; char *retstr; cJSON *msgjson = cJSON_CreateObject();
    if ( destip == 0 || destip[0] == 0 || strncmp(destip,"127.0.0.1",strlen("127.0.0.1")) == 0 )
    {
        routehash = destpub;
        jaddbits256(msgjson,"destpub",destpub);
    }
    else
    {
        destipbits = (uint32_t)calc_ipbits(destip);
        vcalc_sha256(0,routehash.bytes,(uint8_t *)&destipbits,sizeof(destipbits));
        jaddstr(msgjson,"destip",destip);
    }
    retstr = SuperNET_DHTsend(myinfo,routehash,hexmsg,maxdelay);
    return(retstr);
}

char *SuperNET_forward(struct supernet_info *myinfo,char *hexmsg,uint32_t destipbits,bits256 destpub,int32_t maxdelay)
{
    bits256 routehash;
    if ( destipbits != 0 )
        vcalc_sha256(0,routehash.bytes,(uint8_t *)&destipbits,sizeof(destipbits));
    else routehash = destpub;
    return(SuperNET_DHTsend(myinfo,routehash,hexmsg,maxdelay));
}

int32_t SuperNET_destination(struct supernet_info *myinfo,uint32_t *destipbitsp,bits256 *destpubp,int32_t *maxdelayp,cJSON *json)
{
    char *destip; int32_t destflag = SUPERNET_FORWARD;
    if ( (destip= jstr(json,"destip")) != 0 )
        *destipbitsp = (uint32_t)calc_ipbits(destip);
    else *destipbitsp = 0;
    *maxdelayp = juint(json,"delay");
    *destpubp = jbits256(json,"destpub");
    if ( *destipbitsp == myinfo->myaddr.selfipbits )
        destflag = SUPERNET_ISMINE;
    else if ( memcmp(destpubp,myinfo->myaddr.pubkey.bytes,sizeof(*destpubp)) == 0 )
        destflag = SUPERNET_ISMINE;
    // check for encrypted packets
    return(destflag);
}

char *SuperNET_JSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr)
{
    int32_t destflag,maxdelay; bits256 destpub; uint32_t destipbits; cJSON *retjson;
    char *forwardstr=0,*retstr=0,*agent=0,*method=0,*message,*jsonstr=0;
    if ( remoteaddr != 0 && strcmp(remoteaddr,"127.0.0.1") == 0 )
        remoteaddr = 0;
    printf("SuperNET_JSON.(%s) remote.(%s)\n",jprint(json,0),remoteaddr!=0?remoteaddr:"");
    destflag = SuperNET_destination(myinfo,&destipbits,&destpub,&maxdelay,json);
    printf("destflag.%d\n",destflag);
    if ( (destflag & SUPERNET_FORWARD) != 0 )
    {
        if ( (message= jstr(json,"message")) == 0 )
        {
            jsonstr = jprint(json,0);
            message = jsonstr;
        }
        forwardstr = SuperNET_forward(myinfo,message,destipbits,destpub,maxdelay);
    }
    if ( (destflag & SUPERNET_ISMINE) && (agent= jstr(json,"agent")) != 0 && (method= jstr(json,"method")) != 0 )
    {
        if ( (retstr= SuperNET_processJSON(myinfo,json,remoteaddr)) != 0 )
        {
            //printf("retstr.(%s)\n",retstr);
            if ( remoteaddr != 0 && (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( jobj(retjson,"result") != 0 || jobj(retjson,"error") != 0 || jobj(retjson,"method") == 0 )
                {
                    //printf("it is a result, dont return\n");
                    free(retstr);
                    retstr = 0;
                }
                free_json(retjson);
            }
        } else printf("null retstr from SuperNET_JSON\n");
    }
    printf("retstr.%p forwardstr.%p jsonstr.%p\n",retstr,forwardstr,jsonstr);
    if ( retstr == 0 )
        retstr = forwardstr, forwardstr = 0;
    if ( forwardstr != 0 )
        free(forwardstr);
    if ( jsonstr != 0 )
        free(jsonstr);
    return(retstr);
}

char *SuperNET_p2p(struct iguana_info *coin,struct iguana_peer *addr,int32_t *delaymillisp,char *ipaddr,uint8_t *data,int32_t datalen)
{
    cJSON *json; bits256 senderpub; char *myipaddr,*method,*retstr = 0; int32_t maxdelay; struct supernet_info *myinfo;
    myinfo = SuperNET_MYINFO(0);
    *delaymillisp = 0;
    if ( (json= SuperNET_bits2json(myinfo,addr->pubkey,data,datalen)) != 0 )
    {
        maxdelay = juint(json,"maxdelay");
        printf("GOT >>>>>>>> SUPERNET P2P.(%s) from.%s\n",jprint(json,0),coin->symbol);
        if ( (myipaddr= jstr(json,"yourip")) != 0 )
            SuperNET_myipaddr(SuperNET_MYINFO(0),addr,myipaddr,ipaddr);
        senderpub = jbits256(json,"mypub");
        if ( bits256_nonz(senderpub) > 0 )
            addr->pubkey = senderpub;
        jaddstr(json,"fromp2p",coin->symbol);
        method = jstr(json,"method");
        if ( method != 0 && strcmp(method,"stop") == 0 )
        {
            addr->dead = (uint32_t)time(NULL);
            free_json(json);
            return(clonestr("{\"result\":\"peer marked as dead\"}"));
        }
        retstr = SuperNET_JSON(myinfo,json,ipaddr);
        *delaymillisp = SuperNET_delaymillis(myinfo,maxdelay);
        free_json(json);
    } else retstr = clonestr("{\"error\":\"p2p cant parse json\"}");
    return(retstr);
}
