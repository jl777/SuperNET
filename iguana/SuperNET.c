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

bits256 SuperNET_sharedseed(struct supernet_info *myinfo,bits256 otherpub)
{
    bits256 seed2;
    if ( myinfo == 0 )
        myinfo = SuperNET_MYINFO(0);
    vcalc_sha256(0,seed2.bytes,curve25519_shared(myinfo->privkey,otherpub).bytes,sizeof(bits256));
    return(seed2);
}

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

void SuperNET_myipaddr(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,char *myipaddr,char *remoteaddr)
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
        myinfo->myaddr.confirmed++;
    else myinfo->myaddr.confirmed--;
    if ( (myinfo->myaddr.totalconfirmed= SuperNET_confirmip(myinfo,addr->myipbits)) >= coin->peers.numranked )
        myinfo->myaddr.selfipbits = addr->myipbits;
    if ( myinfo->myaddr.selfipbits == myinfo->myaddr.myipbits )
    {
        expand_ipbits(myinfo->ipaddr,myinfo->myaddr.selfipbits);
        vcalc_sha256(0,myinfo->myaddr.iphash.bytes,(uint8_t *)&myinfo->myaddr.selfipbits,sizeof(myinfo->myaddr.selfipbits));
    }
    //printf("myipaddr.%s self.%x your.%x\n",myinfo->ipaddr,myinfo->myaddr.selfipbits,myinfo->myaddr.myipbits);
}

uint16_t SuperNET_checkc(struct supernet_info *myinfo,bits256 otherpub,uint64_t tag)
{
    uint8_t buf[40]; bits256 check,seed,seed2;
    seed = curve25519_shared(myinfo->privkey,otherpub);
    vcalc_sha256(0,seed2.bytes,seed.bytes,sizeof(seed));
    memcpy(buf,seed2.bytes,sizeof(seed));
    iguana_rwnum(1,&buf[sizeof(seed)],sizeof(tag),&tag);
    vcalc_sha256(0,check.bytes,buf,sizeof(buf));
    return(check.ushorts[0]);
}

int32_t SuperNET_json2bits(struct supernet_info *myinfo,bits256 seed2,uint8_t *serialized,int32_t *complenp,uint8_t *compressed,int32_t maxsize,char *destip,bits256 destpub,cJSON *json)
{
    uint16_t apinum,checkc; uint32_t ipbits,crc; uint64_t tag; char *hexmsg;
    int32_t n,numbits,len = sizeof(uint32_t);
    *complenp = -1;
    if ( (tag= j64bits(json,"tag")) == 0 )
        OS_randombytes((uint8_t *)&tag,sizeof(tag));
    ipbits = (uint32_t)calc_ipbits(destip);
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&ipbits);
    ipbits = (uint32_t)calc_ipbits(myinfo->ipaddr);
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&ipbits);
    len += iguana_rwbignum(1,&serialized[len],sizeof(myinfo->myaddr.pubkey),myinfo->myaddr.pubkey.bytes);
    len += iguana_rwnum(1,&serialized[len],sizeof(tag),&tag);
    checkc = SuperNET_checkc(myinfo,destpub,tag);
    len += iguana_rwnum(1,&serialized[len],sizeof(checkc),&checkc);
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
    crc = calc_crc32(0,&serialized[sizeof(crc)],len - sizeof(crc));
    iguana_rwnum(1,serialized,sizeof(crc),&crc);
    //char str[65],str2[65],str3[65],str4[65];
    //int32_t i; for (i=0; i<len; i++)
    //    printf("%02x ",serialized[i]);
    //printf("ORIG SERIALIZED.%d\n",len);
    //printf("mypriv.%s destpub.%s seed.%s seed2.%s -> crc.%08x\n",bits256_str(str,myinfo->privkey),bits256_str(str2,destpub),bits256_str(str3,seed),bits256_str(str4,seed2),crc);
    numbits = ramcoder_compress(&compressed[3],maxsize-3,serialized,len,seed2);
    compressed[0] = (numbits & 0xff);
    compressed[1] = ((numbits>>8) & 0xff);
    compressed[2] = ((numbits>>16) & 0xff);
    //printf("strlen.%d len.%d -> %s numbits.%d\n",(int32_t)strlen(jprint(json,0)),len,bits256_str(str,seed2),(int32_t)hconv_bitlen(numbits));
    if ( 0 )
    {
        uint8_t space[9999];
        int32_t testlen = ramcoder_decompress(space,IGUANA_MAXPACKETSIZE,&compressed[3],numbits,seed2);
        printf("len.%d -> testlen.%d cmp.%d\n",len,testlen,memcmp(space,serialized,testlen));
        int32_t i; for (i=0; i<3+hconv_bitlen(numbits); i++)
            printf("%02x ",compressed[i]);
        printf("complen.%d\n",i+3);
    }
    *complenp = (int32_t)hconv_bitlen(numbits) + 3;
    return(len);
}

cJSON *SuperNET_bits2json(struct supernet_info *myinfo,bits256 senderpub,bits256 sharedseed,uint8_t *serialized,uint8_t *space,int32_t datalen,int32_t iscompressed)
{
    char destip[64],method[64],checkstr[5],agent[64],myipaddr[64],str[65],*hexmsg; uint64_t tag;
    uint16_t apinum,checkc; uint32_t destipbits,myipbits; bits256 seed2;
    int32_t numbits,iter,flag=0,len = 0; uint32_t crc,checkcrc; cJSON *json = cJSON_CreateObject();
    int32_t i; for (i=0; i<datalen; i++)
        printf("%02x ",serialized[i]);
    printf("bits[%d] iscompressed.%d\n",datalen,iscompressed);
    if ( iscompressed != 0 )
    {
        numbits = serialized[2];
        numbits = (numbits << 8) + serialized[1];
        numbits = (numbits << 8) + serialized[0];
        if ( hconv_bitlen(numbits)+3 == datalen )
        {
            memset(seed2.bytes,0,sizeof(seed2));
            for (iter=0; iter<2; iter++)
            {
                //char str[65]; printf("compressed len.%d seed2.(%s)\n",numbits,bits256_str(str,seed2));
                datalen = ramcoder_decompress(space,IGUANA_MAXPACKETSIZE,&serialized[3],numbits,seed2);
                serialized = space;
                if ( datalen > sizeof(crc) )
                {
                    crc = calc_crc32(0,&serialized[sizeof(crc)],datalen - sizeof(crc));
                    iguana_rwnum(0,serialized,sizeof(checkcrc),&checkcrc);
                    //int32_t i; for (i=0; i<datalen; i++)
                    //    printf("%02x ",serialized[i]);
                    printf("bits[%d] numbits.%d after decompress crc.(%08x vs %08x) <<<<<<<<<<<<<<< iter.%d\n",datalen,numbits,crc,checkcrc,iter);
                    if ( crc == checkcrc )
                    {
                        flag = 1;
                        break;
                    }
                }
                //seed = (iter == 0) ? curve25519_shared(GENESIS_PRIVKEY,prevpub) : genesis2;
                //vcalc_sha256(0,seed2.bytes,seed.bytes,sizeof(seed));
                seed2 = sharedseed;
            }
        }
        else
        {
            printf("numbits.%d + 3 -> %d != datalen.%d\n",numbits,(int32_t)hconv_bitlen(numbits)+3,datalen);
            return(0);
        }
    }
    if ( flag == 0 )
        return(0);
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&crc);
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&destipbits);
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&myipbits);
    len += iguana_rwbignum(0,&serialized[len],sizeof(bits256),senderpub.bytes);
    len += iguana_rwnum(0,&serialized[len],sizeof(tag),&tag);
    len += iguana_rwnum(0,&serialized[len],sizeof(checkc),&checkc);
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
        init_hexbytes_noT(checkstr,(void *)&checkc,sizeof(checkc));
        jaddstr(json,"check",checkstr);
        if ( len < datalen )
        {
            printf("len %d vs %d datalen\n",len,datalen);
            hexmsg = malloc(((datalen - len)<<1) + 1);
            init_hexbytes_noT(hexmsg,&serialized[len],datalen - len);
            printf("hex.(%s)\n",hexmsg);
            jaddstr(json,"message",hexmsg);
            free(hexmsg);
        }
        //printf("bits2json.(%s)\n",jprint(json,0));
        return(json);
    } else printf("cant decode apinum.%d (%d.%d)\n",apinum,apinum>>5,apinum%0x1f);
    return(0);
}

int32_t iguana_send_supernet(struct iguana_info *coin,struct iguana_peer *addr,char *jsonstr,int32_t delaymillis)
{
    int32_t datalen,complen,qlen = -1; uint8_t *serialized,*compressed; cJSON *json;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        compressed = malloc(sizeof(struct iguana_msghdr) + IGUANA_MAXPACKETSIZE);
        serialized = malloc(sizeof(struct iguana_msghdr) + IGUANA_MAXPACKETSIZE);
        datalen = SuperNET_json2bits(SuperNET_MYINFO(0),addr->sharedseed,&serialized[sizeof(struct iguana_msghdr)],&complen,&compressed[sizeof(struct iguana_msghdr)],IGUANA_MAXPACKETSIZE,addr->ipaddr,addr->pubkey,json);
        printf("SUPERSEND.(%s) -> (%s) delaymillis.%d datalen.%d\n",jsonstr,addr->ipaddr,delaymillis,datalen);
        if ( datalen >= 0 )
        {
            if ( complen >= 0 )
                qlen = iguana_queue_send(coin,addr,delaymillis,compressed,"SuperNETb",complen,0,0);
            else qlen = iguana_queue_send(coin,addr,delaymillis,serialized,"SuperNET",datalen,0,0);
        }
        free(compressed);
        free(serialized);
    } else printf("cant parse.(%s)\n",jsonstr);
    return(qlen);
}

int32_t DHT_dist(bits256 desthash,bits256 hash)
{
    int32_t i,dist = 0;
    for (i=0; i<4; i++)
        dist += bitweight(desthash.ulongs[i] ^ hash.ulongs[i]);
    printf("(dist.%d) ",dist);
    return(dist*0);
}

char *SuperNET_DHTsend(struct supernet_info *myinfo,bits256 routehash,char *hexmsg,int32_t maxdelay,int32_t broadcastflag)
{
    static int lastpurge; static uint64_t Packetcache[1024];
    bits256 packethash; char retbuf[512]; int32_t mydist,i,j,datalen,firstz,iter,n = 0; char *jsonstr=0;
    struct iguana_peer *addr; cJSON *json;
    if ( myinfo == 0 )
        return(clonestr("{\"error\":\"no supernet_info\"}"));
    datalen = (int32_t)strlen(hexmsg) + 1;
    json = cJSON_CreateObject();
    jaddstr(json,"agent","SuperNET");
    jaddstr(json,"method","DHT");
    jaddstr(json,"message",hexmsg);
    jsonstr = jprint(json,1);
    vcalc_sha256(0,packethash.bytes,(void *)hexmsg,datalen);
    firstz = -1;
    for (i=broadcastflag!=0; i<sizeof(Packetcache)/sizeof(*Packetcache); i++)
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
    mydist = DHT_dist(packethash,myinfo->myaddr.iphash);
    for (iter=broadcastflag!=0; iter<2; iter++)
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
                            printf("DHT send\n");
                            iguana_send_supernet(Coins[i],addr,jsonstr,maxdelay==0?0:(rand()%maxdelay));
                            return(clonestr("{\"result\":\"packet sent directly to destip\"}"));
                        }
                        else if ( iter == 1 )
                        {
                            if ( DHT_dist(packethash,addr->iphash) <= mydist )
                            {
                                iguana_send_supernet(Coins[i],addr,jsonstr,maxdelay==0?0:(rand()%maxdelay));
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

char *SuperNET_DHTencode(struct supernet_info *myinfo,char *destip,bits256 destpub,char *hexmsg,int32_t maxdelay,int32_t broadcastflag)
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
    retstr = SuperNET_DHTsend(myinfo,routehash,hexmsg,maxdelay,broadcastflag);
    return(retstr);
}

char *SuperNET_forward(struct supernet_info *myinfo,char *hexmsg,uint32_t destipbits,bits256 destpub,int32_t maxdelay,int32_t broadcastflag)
{
    bits256 routehash;
    if ( destipbits != 0 )
        vcalc_sha256(0,routehash.bytes,(uint8_t *)&destipbits,sizeof(destipbits));
    else routehash = destpub;
    return(SuperNET_DHTsend(myinfo,routehash,hexmsg,maxdelay,broadcastflag));
}

int32_t SuperNET_destination(struct supernet_info *myinfo,uint32_t *destipbitsp,bits256 *destpubp,int32_t *maxdelayp,cJSON *json,char *remoteaddr)
{
    char *destip; int32_t destflag = 0;
    if ( (destip= jstr(json,"destip")) != 0 )
        *destipbitsp = (uint32_t)calc_ipbits(destip);
    else *destipbitsp = 0;
    *maxdelayp = juint(json,"delay");
    *destpubp = jbits256(json,"destpub");
    if ( *destipbitsp != 0 )
    {
        if ( *destipbitsp == myinfo->myaddr.selfipbits )
            destflag |= SUPERNET_ISMINE;
        else destflag |= SUPERNET_FORWARD;
    }
    else if ( bits256_nonz(*destpubp) > 0 )
    {
        if ( memcmp(destpubp,myinfo->myaddr.pubkey.bytes,sizeof(*destpubp)) == 0 )
            destflag |= SUPERNET_ISMINE;
        else destflag |= SUPERNET_FORWARD;
    }
    else if ( remoteaddr == 0 || remoteaddr[0] == 0 )
        destflag |= SUPERNET_ISMINE;
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
    //printf("destflag.%d\n",destflag);
    if ( (destflag & SUPERNET_FORWARD) != 0 )
    {
        if ( (message= jstr(json,"message")) == 0 )
        {
            jsonstr = jprint(json,0);
            message = jsonstr;
        }
        forwardstr = SuperNET_forward(myinfo,message,destipbits,destpub,maxdelay,juint(json,"broadcast"));
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
    cJSON *json; bits256 senderpub; bits256 zero; char *checkstr,*myipaddr,*method,*retstr;
    int32_t maxdelay; struct supernet_info *myinfo; uint16_t checkc,othercheckc; uint8_t *space;
    myinfo = SuperNET_MYINFO(0);
    retstr = 0; space = 0;
    *delaymillisp = 0;
    memset(zero.bytes,0,sizeof(zero));
    if ( compressed != 0 )
        space = malloc(sizeof(struct iguana_msghdr) + IGUANA_MAXPACKETSIZE);
    if ( (json= SuperNET_bits2json(myinfo,addr->pubkey,addr->validpub>2?addr->sharedseed:zero,data,space,datalen,compressed)) != 0 )
    {
        senderpub = jbits256(json,"mypub");
        if ( memcmp(senderpub.bytes,addr->pubkey.bytes,sizeof(senderpub)) != 0 )
            addr->pubkey = senderpub;
        if ( (checkstr= jstr(json,"checkstr")) != 0 )
        {
            decode_hex((uint8_t *)&othercheckc,sizeof(othercheckc),checkstr);
            checkc = SuperNET_checkc(myinfo,senderpub,j64bits(json,"tag"));
            printf("validpub.%d: %x vs %x\n",addr->validpub,checkc,othercheckc);
            if ( checkc == othercheckc )
                addr->validpub++;
            else addr->validpub--;
        }
        maxdelay = juint(json,"maxdelay");
        printf("GOT >>>>>>>> SUPERNET P2P.(%s) from.%s\n",jprint(json,0),coin->symbol);
        if ( (myipaddr= jstr(json,"yourip")) != 0 )
            SuperNET_myipaddr(SuperNET_MYINFO(0),coin,addr,myipaddr,ipaddr);
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
        //printf("p2pret.(%s)\n",retstr);
        *delaymillisp = SuperNET_delaymillis(myinfo,maxdelay);
        free_json(json);
    } else memset(addr->sharedseed.bytes,0,sizeof(addr->sharedseed)), printf("decode error clear %s shared seed\n",addr->ipaddr);
    if ( space != 0 )
        free(space);
    return(retstr);
}
