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
#include "../includes/tweetnacl.h"

bits256 SuperNET_sharedseed(bits256 privkey,bits256 otherpub)
{
    bits256 seed2,seed;
    seed = curve25519_shared(privkey,otherpub);
    vcalc_sha256(0,seed2.bytes,seed.bytes,sizeof(bits256));
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

int32_t SuperNET_copybits(int32_t reverse,uint8_t *dest,uint8_t *src,int32_t len)
{
    int32_t i; uint8_t *tmp;
    if ( reverse != 0 )
    {
        tmp = dest;
        dest = src;
        src = tmp;
    }
    //printf("src.%p dest.%p len.%d\n",src,dest,len);
    //for (i=0; i<len; i++)
    //    dest[i] = 0;
    memset(dest,0,len);
    len <<= 3;
    for (i=0; i<len; i++)
        if ( GETBIT(src,i) != 0 )
            SETBIT(dest,i);
    return(len >> 3);
}

int32_t SuperNET_serialize(int32_t reverse,bits256 *senderpubp,uint64_t *senderbitsp,bits256 *sigp,uint32_t *timestampp,uint64_t *destbitsp,uint8_t *origbuf)
{
    uint8_t *buf = origbuf; long extra = sizeof(bits256) + sizeof(uint64_t) + sizeof(uint64_t);
    buf += SuperNET_copybits(reverse,buf,(void *)destbitsp,sizeof(uint64_t));
    buf += SuperNET_copybits(reverse,buf,senderpubp->bytes,sizeof(bits256));
    buf += SuperNET_copybits(reverse,buf,(void *)senderbitsp,sizeof(uint64_t));
    buf += SuperNET_copybits(reverse,buf,(void *)timestampp,sizeof(uint32_t)), extra += sizeof(uint32_t);
    if ( *senderbitsp != 0 )
        buf += SuperNET_copybits(reverse,buf,sigp->bytes,sizeof(bits256)), extra += sizeof(bits256);
    else memset(sigp,0,sizeof(*sigp));
    if ( ((long)buf - (long)origbuf) != extra )
    {
        printf("SuperNET_serialize: extrasize mismatch %ld vs %ld\n",((long)buf - (long)origbuf),extra);
    }
    return((int32_t)extra);
}

uint8_t *SuperNET_encode(int32_t *cipherlenp,void *str,int32_t len,bits256 destpubkey,bits256 myprivkey,bits256 mypubkey,uint64_t senderbits,bits256 sig,uint32_t timestamp)
{
    uint8_t *buf,*nonce,*origcipher,*cipher,*ptr; uint64_t destbits; int32_t totalsize,hdrlen;
    long extra = crypto_box_NONCEBYTES + crypto_box_ZEROBYTES + sizeof(sig) + sizeof(struct iguana_msghdr);
    destbits = (memcmp(destpubkey.bytes,GENESIS_PUBKEY.bytes,sizeof(destpubkey)) != 0) ? acct777_nxt64bits(destpubkey) : 0;
    totalsize = (int32_t)(len + sizeof(mypubkey) + sizeof(senderbits) + sizeof(destbits) + sizeof(timestamp));
    *cipherlenp = 0;
    if ( (buf= calloc(1,totalsize + extra)) == 0 )
    {
        printf("SuperNET_encode: outof mem for buf[%ld]\n",totalsize+extra);
        return(0);
    }
    if ( (cipher= calloc(1,totalsize + extra)) == 0 )
    {
        printf("SuperNET_encode: outof mem for cipher[%ld]\n",totalsize+extra);
        free(buf);
        return(0);
    }
    origcipher = cipher;
    ptr = &cipher[sizeof(struct iguana_msghdr)];
    hdrlen = SuperNET_serialize(0,&mypubkey,&senderbits,&sig,&timestamp,&destbits,ptr);
    if ( senderbits != 0 )
        totalsize += sizeof(sig);//, printf("totalsize.%d extra.%ld add %ld\n",totalsize-len,extra,(long)(sizeof(sig) + sizeof(timestamp)));
    if ( destbits != 0 && senderbits != 0 )
    {
        totalsize += crypto_box_NONCEBYTES + crypto_box_ZEROBYTES;//, printf("totalsize.%d extra.%ld add %d\n",totalsize-len,extra,crypto_box_NONCEBYTES + crypto_box_ZEROBYTES);
        nonce = &ptr[hdrlen];
        OS_randombytes(nonce,crypto_box_NONCEBYTES);
        cipher = &nonce[crypto_box_NONCEBYTES];
        //printf("len.%d -> %d %d\n",len,len+crypto_box_ZEROBYTES,len + crypto_box_ZEROBYTES + crypto_box_NONCEBYTES);
        memset(cipher,0,len+crypto_box_ZEROBYTES);
        memset(buf,0,crypto_box_ZEROBYTES);
        memcpy(buf+crypto_box_ZEROBYTES,str,len);
        crypto_box(cipher,buf,len+crypto_box_ZEROBYTES,nonce,destpubkey.bytes,myprivkey.bytes);
        hdrlen += crypto_box_NONCEBYTES + crypto_box_ZEROBYTES;
    }
    else memcpy(&cipher[hdrlen],str,len);
    if ( totalsize != len+hdrlen )
        printf("unexpected totalsize.%d != len.%d + hdrlen.%d %d\n",totalsize,len,hdrlen,len+hdrlen);
    free(buf);
    *cipherlenp = totalsize;
    return(origcipher);
}

int32_t SuperNET_decode(uint64_t *senderbitsp,bits256 *sigp,uint32_t *timestampp,uint64_t *destbitsp,uint8_t *str,uint8_t *cipher,int32_t *lenp,uint8_t *myprivkey)
{
    bits256 srcpubkey; uint8_t *nonce; int i,hdrlen,err=0,len = *lenp;
    hdrlen = SuperNET_serialize(1,&srcpubkey,senderbitsp,sigp,timestampp,destbitsp,cipher);
    cipher += hdrlen, len -= hdrlen;
    if ( *destbitsp != 0 && *senderbitsp != 0 )
    {
        nonce = cipher;
        cipher += crypto_box_NONCEBYTES, len -= crypto_box_NONCEBYTES;
        err = crypto_box_open((uint8_t *)str,cipher,len,nonce,srcpubkey.bytes,myprivkey);
        for (i=0; i<len-crypto_box_ZEROBYTES; i++)
            str[i] = str[i+crypto_box_ZEROBYTES];
        *lenp = len - crypto_box_ZEROBYTES;
    } else memcpy(str,cipher,len);
    return(err);
}

int32_t SuperNET_decrypt(bits256 *senderpubp,uint64_t *senderbitsp,uint32_t *timestampp,bits256 mypriv,bits256 mypub,uint8_t *dest,int32_t maxlen,uint8_t *src,int32_t len)
{
    bits256 seed,sig,msgpriv; uint64_t my64bits,destbits,senderbits,sendertmp,desttmp;
    uint8_t *buf; int32_t hdrlen,diff,newlen = -1; HUFF H,*hp = &H; struct acct777_sig checksig;
    *senderbitsp = 0;
    my64bits = acct777_nxt64bits(mypub);
    if ( (buf = calloc(1,maxlen)) == 0 )
    {
        printf("SuperNET_decrypt cant allocate maxlen.%d\n",maxlen);
        return(-1);
    }
    hdrlen = SuperNET_serialize(1,senderpubp,&senderbits,&sig,timestampp,&destbits,src);
    if ( destbits != 0 && my64bits != destbits && destbits != acct777_nxt64bits(GENESIS_PUBKEY) )
    {
        free(buf);
        printf("SuperNET_decrypt received destination packet.%llu when my64bits.%llu len.%d\n",(long long)destbits,(long long)my64bits,len);
        return(-1);
    }
    if ( memcmp(mypub.bytes,senderpubp->bytes,sizeof(mypub)) == 0 )
    {
        if ( destbits != 0 )
            printf("SuperNET: got my own msg?\n");
    }
    //printf("decrypt(%d) destbits.%llu my64.%llu mypriv.%llx mypub.%llx senderpub.%llx shared.%llx\n",len,(long long)destbits,(long long)my64bits,(long long)mypriv.txid,(long long)mypub.txid,(long long)senderpubp->txid,(long long)seed.txid);
    if ( SuperNET_decode(&sendertmp,&sig,timestampp,&desttmp,(void *)buf,src,&len,mypriv.bytes) == 0 )
    {
        if ( (diff= (*timestampp - (uint32_t)time(NULL))) < 0 )
            diff = -diff;
        if ( 1 && diff > SUPERNET_MAXTIMEDIFF )
            printf("diff.%d > %d %u vs %u\n",diff,SUPERNET_MAXTIMEDIFF,*timestampp,(uint32_t)time(NULL));
        else
        {
            if ( 1 )
            {
                memset(seed.bytes,0,sizeof(seed));
                //for (i='0'; i<='9'; i++)
                //    SETBIT(seed.bytes,i);
                //for (i='a'; i<='f'; i++)
                //    SETBIT(seed.bytes,i);
                _init_HUFF(hp,len,buf), hp->endpos = (len << 3);
                newlen = ramcoder_decoder(0,1,dest,maxlen,hp,&seed);
            }
            else memcpy(dest,buf,len), newlen = len;
            //printf("T%d decrypted newlen.%d\n",threadid,newlen);
            if ( senderbits != 0 && senderpubp->txid != 0 )
            {
                *senderbitsp = senderbits;
                if ( destbits == 0 )
                    msgpriv = GENESIS_PRIVKEY;
                else msgpriv = mypriv;
                acct777_sign(&checksig,msgpriv,*senderpubp,*timestampp,dest,newlen);
                if ( memcmp(checksig.sigbits.bytes,&sig,sizeof(checksig.sigbits)) != 0 )
                {
                    printf("sender.%llu sig %llx compare error vs %llx using sig->pub from %llu, broadcast.%d\n",(long long)senderbits,(long long)sig.txid,(long long)checksig.sigbits.txid,(long long)senderbits,destbits == 0);
                    //free(buf);
                    //return(0);
                } //else printf("SIG VERIFIED newlen.%d (%llu -> %llu)\n",newlen,(long long)senderbits,(long long)destbits);
            }
        }
    }
    else printf("%llu: SuperNET_decrypt skip: decode_cipher error len.%d -> newlen.%d\n",(long long)acct777_nxt64bits(mypub),len,newlen);
    free(buf);
    return(newlen);
}

int32_t SuperNET_sendmsg(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,bits256 destpub,bits256 mypriv,bits256 mypub,uint8_t *msg,int32_t len,uint8_t *data,int32_t delaymillis)
{
    int32_t cipherlen,datalen,qlen=-1; bits256 seed; uint8_t *cipher; uint64_t destbits; struct acct777_sig sig; HUFF H,*hp = &H;
    if ( destpub.txid != 0 )
        destbits = acct777_nxt64bits(destpub);
    else
    {
        destbits = 0;
        destpub = GENESIS_PUBKEY;
    }
    //printf("hostnet777_sendmsg dest.%llu destpub.%llx priv.%llx pub.%llx\n",(long long)destbits,(long long)destpub.txid,(long long)mypriv.txid,(long long)mypub.txid);
    memset(&sig,0,sizeof(sig));
    if ( mypub.txid == 0 || mypriv.txid == 0 )
        mypriv = curve25519_keypair(&mypub), sig.timestamp = (uint32_t)time(NULL);
    else acct777_sign(&sig,mypriv,destpub,(uint32_t)time(NULL),msg,len);
    if ( 1 )
    {
        memset(seed.bytes,0,sizeof(seed));
        //seed = addr->sharedseed;
        data = calloc(1,len*2);
        _init_HUFF(hp,len*2,data);
        /*for (i='0'; i<='9'; i++)
            SETBIT(seed.bytes,i);
        for (i='a'; i<='f'; i++)
            SETBIT(seed.bytes,i);*/
        ramcoder_encoder(0,1,msg,len,hp,0,&seed);
        datalen = (int32_t)hconv_bitlen(hp->bitoffset);
    }
    else data = msg, datalen = len;
    if ( (cipher= SuperNET_encode(&cipherlen,data,datalen,destpub,mypriv,mypub,sig.signer64bits,sig.sigbits,sig.timestamp)) != 0 )
    {
        qlen = iguana_queue_send(coin,addr,delaymillis,cipher,"SuperNETb",cipherlen,0,0);
        free(cipher);
    }
    return(qlen);
}

uint16_t SuperNET_checkc(bits256 privkey,bits256 otherpub,uint64_t tag)
{
    uint8_t buf[40]; bits256 check,seed,seed2;
    seed = curve25519_shared(privkey,otherpub);
    vcalc_sha256(0,seed2.bytes,seed.bytes,sizeof(seed));
    memcpy(buf,seed2.bytes,sizeof(seed));
    iguana_rwnum(1,&buf[sizeof(seed)],sizeof(tag),&tag);
    vcalc_sha256(0,check.bytes,buf,sizeof(buf));
    return(check.ushorts[0]);
}

int32_t SuperNET_json2bits(char *myipaddr,bits256 sessionpriv,uint8_t *serialized,int32_t maxsize,char *destip,bits256 destpub,cJSON *json)
{
    uint16_t apinum,checkc=0; uint32_t ipbits,crc; char *agent,*method; uint64_t tag; char *hexmsg;
    int32_t n,len = sizeof(uint32_t);
    if ( (tag= j64bits(json,"tag")) == 0 )
        OS_randombytes((uint8_t *)&tag,sizeof(tag));
    ipbits = (uint32_t)calc_ipbits(destip);
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&ipbits);
    ipbits = (uint32_t)calc_ipbits(myipaddr);
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&ipbits);
    //len += iguana_rwbignum(1,&serialized[len],sizeof(sessionpub),sessionpub.bytes);
    len += iguana_rwnum(1,&serialized[len],sizeof(tag),&tag);
    checkc = SuperNET_checkc(sessionpriv,destpub,tag);
    len += iguana_rwnum(1,&serialized[len],sizeof(checkc),&checkc);
    agent = jstr(json,"agent"), method = jstr(json,"method");
    if ( strcmp(agent,"SuperNET") == 0 && strcmp(method,"json2bits") == 0 )
    {
        agent = jstr(json,"destagent");
        method = jstr(json,"destmethod");
    }
    if ( (apinum= SuperNET_API2num(agent,method)) == 0xffff )
    {
        printf("agent.(%s) method.(%s) is not found\n",agent,method);
        return(-1);
    }
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
    return(len);
}

cJSON *SuperNET_bits2json(bits256 mypriv,bits256 mypub,struct iguana_peer *addr,uint8_t *serialized,uint8_t *space,int32_t datalen,int32_t iscompressed)
{
    char destip[64],method[64],checkstr[5],agent[64],myipaddr[64],str[65],*hexmsg; uint64_t tag;
    uint16_t apinum,checkc; uint32_t destipbits,myipbits,timestamp; bits256 senderpub; uint64_t senderbits;
    int32_t len = 0; uint32_t crc; cJSON *json = cJSON_CreateObject();
    if ( iscompressed != 0 )
    {
        if ( (len= SuperNET_decrypt(&senderpub,&senderbits,&timestamp,mypriv,mypub,space,IGUANA_MAXPACKETSIZE,serialized,datalen)) > 1 && len < IGUANA_MAXPACKETSIZE )
        {
            if ( memcmp(senderpub.bytes,addr->pubkey.bytes,sizeof(senderpub)) != 0 )
            {
                printf("got new pubkey.(%s) for %s\n",bits256_str(str,senderpub),addr->ipaddr);
                addr->pubkey = senderpub;
                addr->sharedseed = SuperNET_sharedseed(mypriv,senderpub);
            }
            serialized = space;
            datalen = len;
            len = 0;
        } else printf("decrypt error len.%d origlen.%d\n",len,datalen);
    }
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&crc);
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&destipbits);
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&myipbits);
    //len += iguana_rwbignum(0,&serialized[len],sizeof(bits256),senderpub.bytes);
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
    int32_t datalen,qlen = -1; uint8_t *serialized,*space; cJSON *json; struct supernet_info *myinfo;
    myinfo = SuperNET_MYINFO(0);
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        serialized = malloc(sizeof(struct iguana_msghdr) + IGUANA_MAXPACKETSIZE);
        space = malloc(sizeof(struct iguana_msghdr) + IGUANA_MAXPACKETSIZE);
        datalen = SuperNET_json2bits(myinfo->ipaddr,myinfo->privkey,&serialized[sizeof(struct iguana_msghdr)],IGUANA_MAXPACKETSIZE,addr->ipaddr,addr->pubkey,json);
        printf("SUPERSEND.(%s) -> (%s) delaymillis.%d datalen.%d\n",jsonstr,addr->ipaddr,delaymillis,datalen);
        qlen = SuperNET_sendmsg(myinfo,coin,addr,addr->pubkey,myinfo->privkey,myinfo->myaddr.pubkey,serialized,datalen,space,delaymillis);
        free(serialized);
        free(space);
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
    cJSON *json; bits256 senderpub; char *checkstr,*myipaddr,*method,*retstr;
    int32_t maxdelay; struct supernet_info *myinfo; uint16_t checkc,othercheckc; uint8_t *space;
    myinfo = SuperNET_MYINFO(0);
    retstr = 0; space = 0;
    *delaymillisp = 0;
    if ( compressed != 0 )
        space = malloc(sizeof(struct iguana_msghdr) + IGUANA_MAXPACKETSIZE);
    if ( (json= SuperNET_bits2json(myinfo->privkey,myinfo->myaddr.pubkey,addr,data,space,datalen,compressed)) != 0 )
    {
        senderpub = jbits256(json,"mypub");
        if ( memcmp(senderpub.bytes,addr->pubkey.bytes,sizeof(senderpub)) != 0 )
            addr->pubkey = senderpub;
        if ( (checkstr= jstr(json,"check")) != 0 )
        {
            decode_hex((uint8_t *)&othercheckc,sizeof(othercheckc),checkstr);
            checkc = SuperNET_checkc(myinfo->privkey,senderpub,j64bits(json,"tag"));
            if ( checkc == othercheckc )
                addr->validpub++;
            else if ( addr->validpub > 0 )
                addr->validpub = 0;
            else addr->validpub--;
            printf("validpub.%d: %x vs %x shared.%llx\n",addr->validpub,checkc,othercheckc,(long long)addr->sharedseed.txid);
        }
        if ( addr->validpub > 3 && bits256_nonz(addr->sharedseed) == 0 )
            addr->sharedseed = SuperNET_sharedseed(myinfo->privkey,senderpub);
        else if ( addr->validpub < -2 )
            memset(addr->sharedseed.bytes,0,sizeof(addr->sharedseed));
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
