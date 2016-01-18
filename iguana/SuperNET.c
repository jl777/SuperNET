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
    if ( maxdelay == 0 )
        return(0);
    return(rand() % maxdelay);
}

void SuperNET_remotepeer(struct supernet_info *myinfo,struct iguana_info *coin,char *symbol,char *ipaddr,int32_t supernetflag)
{
    uint64_t ipbits; struct iguana_peer *addr;
    ipbits = calc_ipbits(ipaddr);
    printf("got %s remotepeer.(%s) supernet.%d\n",symbol,ipaddr,supernetflag);
    if ( supernetflag != 0 && (uint32_t)myinfo->myaddr.selfipbits != (uint32_t)ipbits )
    {
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

int32_t SuperNET_json2bits(struct supernet_info *myinfo,uint8_t *serialized,int32_t *complenp,uint8_t *compressed,int32_t maxsize,char *destip,bits256 destpub,cJSON *json)
{
    uint16_t apinum; uint32_t ipbits; uint64_t tag; bits256 seed,seed2; char *hexmsg; int32_t n,numbits,len = 0;
    *complenp = -1;
    if ( (tag= j64bits(json,"tag")) == 0 )
        OS_randombytes((uint8_t *)&tag,sizeof(tag));
    ipbits = (uint32_t)calc_ipbits(destip);
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&ipbits);
    ipbits = (uint32_t)calc_ipbits(myinfo->ipaddr);
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&ipbits);
    len += iguana_rwbignum(1,&serialized[len],sizeof(myinfo->myaddr.pubkey),myinfo->myaddr.pubkey.bytes);
    len += iguana_rwnum(1,&serialized[len],sizeof(tag),&tag);
    if ( (apinum= SuperNET_API2num(jstr(json,"agent"),jstr(json,"method"))) == 0xffff )
        return(-1);
    len += iguana_rwnum(1,&serialized[len],sizeof(apinum),&apinum);
    if ( (hexmsg= jstr(json,"message")) != 0 )
    {
        n = (int32_t)strlen(hexmsg);
        if ( (n & 1) == 0 && is_hexstr(hexmsg,n) > 0 )
        {
            n >>= 1;
            decode_hex(&serialized[len],n,hexmsg);
            len += n;
        } else return(-1);
    }
    compressed[0] = (len & 0xff);
    compressed[1] = ((len>>8) & 0xff);
    compressed[2] = ((len>>16) & 0xff);
    memset(seed.bytes,0,sizeof(seed));
    numbits = ramcoder_compress(&compressed[3],maxsize-3,serialized,len,seed);
    *complenp = (int32_t)hconv_bitlen(numbits);
    seed = curve25519_shared(GENESIS_PRIVKEY,destpub);//myinfo->privkey,destpub);
    vcalc_sha256(0,seed2.bytes,seed.bytes,sizeof(seed));
    char str[65],str2[65],str3[65],str4[65];
    printf("mypriv.%s destpub.%s seed.%s seed2.%s\n",bits256_str(str,myinfo->privkey),bits256_str(str2,destpub),bits256_str(str3,seed),bits256_str(str4,seed2));
    int32_t seedlen; seedlen = ramcoder_compress(&compressed[3],maxsize-3,serialized,len,seed2);
    printf("strlen.%d len.%d -> complen.%d %s seedlen.%d\n",(int32_t)strlen(jprint(json,0)),len,*complenp,bits256_str(str,seed2),(int32_t)hconv_bitlen(seedlen));
    *complenp = (int32_t)hconv_bitlen(seedlen);
    return(len);
}

cJSON *SuperNET_bits2json(struct supernet_info *myinfo,bits256 prevpub,uint8_t *serialized,uint8_t *space,int32_t datalen,int32_t iscompressed)
{
    char destip[64],method[64],agent[64],myipaddr[64],str[65],*hexmsg; uint64_t tag; int32_t numbits,len = 0;
    uint16_t apinum; uint32_t destipbits,myipbits; bits256 seed,seed2,senderpub; cJSON *json = cJSON_CreateObject();
    int32_t i; for (i=0; i<datalen; i++)
        printf("%02x ",serialized[i]);
    printf("bits[%d]\n",datalen);
    if ( iscompressed != 0 )
    {
        len = serialized[0];
        len = (len << 8) + serialized[1];
        len = (len << 8) + serialized[2];
        seed = curve25519_shared(GENESIS_PRIVKEY,prevpub);
        vcalc_sha256(0,seed2.bytes,seed.bytes,sizeof(seed));
        char str[65]; printf("compressed len.%d seed2.(%s)\n",len,bits256_str(str,seed2));
        numbits = ramcoder_decompress(space,IGUANA_MAXPACKETSIZE,&serialized[3],len<<3,seed2);
        datalen = (int32_t)hconv_bitlen(numbits);
        serialized = space;
    }
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&destipbits);
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&myipbits);
    len += iguana_rwbignum(0,&serialized[len],sizeof(bits256),senderpub.bytes);
    len += iguana_rwnum(0,&serialized[len],sizeof(tag),&tag);
    len += iguana_rwnum(0,&serialized[len],sizeof(apinum),&apinum);
    //printf("-> dest.%x myip.%x senderpub.%llx tag.%llu\n",destipbits,myipbits,(long long)senderpub.txid,(long long)tag);
    if ( SuperNET_num2API(agent,method,apinum) >= 0 )
    {
        jaddstr(json,"agent",agent);
        jaddstr(json,"method",method);
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
    return(0);
}

int32_t iguana_send_supernet(struct iguana_info *coin,struct iguana_peer *addr,char *jsonstr,int32_t delaymillis)
{
    int32_t datalen,complen,qlen = -1; uint8_t *serialized,*compressed; cJSON *json;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        compressed = malloc(sizeof(struct iguana_msghdr) + IGUANA_MAXPACKETSIZE);
        serialized = malloc(sizeof(struct iguana_msghdr) + IGUANA_MAXPACKETSIZE);
        datalen = SuperNET_json2bits(SuperNET_MYINFO(0),&serialized[sizeof(struct iguana_msghdr)],&complen,&compressed[sizeof(struct iguana_msghdr)],IGUANA_MAXPACKETSIZE,addr->ipaddr,addr->pubkey,json);
        printf("SUPERSEND.(%s) -> (%s) delaymillis.%d datalen.%d\n",jsonstr,addr->ipaddr,delaymillis,datalen);
        if ( datalen >= 0 )
        {
            if ( complen >= 0 && complen < (((datalen-3) * 7) >> 3) )
                qlen = iguana_queue_send(coin,addr,delaymillis,compressed,"SuperNETb",complen,0,0);
            else qlen = iguana_queue_send(coin,addr,delaymillis,serialized,"SuperNET",datalen,0,0);
        }
        free(compressed);
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

int32_t SuperNET_destination(struct supernet_info *myinfo,uint32_t *destipbitsp,bits256 *destpubp,int32_t *maxdelayp,cJSON *json,char *remoteaddr)
{
    char *destip; int32_t destflag = 0;
    if ( remoteaddr != 0 && remoteaddr[0] != 0 )
        destflag = SUPERNET_FORWARD;
    else destflag = SUPERNET_ISMINE;
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
    //printf("SuperNET_JSON.(%s) remote.(%s)\n",jprint(json,0),remoteaddr!=0?remoteaddr:"");
    destflag = SuperNET_destination(myinfo,&destipbits,&destpub,&maxdelay,json,remoteaddr);
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
    if ( retstr == 0 )
        retstr = forwardstr, forwardstr = 0;
    if ( forwardstr != 0 )
        free(forwardstr);
    if ( jsonstr != 0 )
        free(jsonstr);
    return(retstr);
}

char *SuperNET_p2p(struct iguana_info *coin,struct iguana_peer *addr,int32_t *delaymillisp,char *ipaddr,uint8_t *data,int32_t datalen,int32_t compressed)
{
    cJSON *json; bits256 senderpub; char *myipaddr,*method,*retstr = 0; int32_t maxdelay; struct supernet_info *myinfo; uint8_t *space = 0;
    myinfo = SuperNET_MYINFO(0);
    *delaymillisp = 0;
    if ( compressed != 0 )
        space = malloc(sizeof(struct iguana_msghdr) + IGUANA_MAXPACKETSIZE);
    if ( (json= SuperNET_bits2json(myinfo,addr->pubkey,data,space,datalen,compressed)) != 0 )
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
            if ( space != 0 )
                free(space);
            return(clonestr("{\"result\":\"peer marked as dead\"}"));
        }
        retstr = SuperNET_JSON(myinfo,json,ipaddr);
        printf("p2pret.(%s)\n",retstr);
        *delaymillisp = SuperNET_delaymillis(myinfo,maxdelay);
        free_json(json);
    }
    if ( space != 0 )
        free(space);
    return(retstr);
}
