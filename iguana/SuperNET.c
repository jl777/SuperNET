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
    if ( strcmp(myinfo->ipaddr,"127.0.0.1") == 0 )
    {
        strcpy(myinfo->ipaddr,myipaddr);
    }
    //printf("myipaddr.%s self.%x your.%x\n",myinfo->ipaddr,myinfo->myaddr.selfipbits,myinfo->myaddr.myipbits);
}

int32_t _SuperNET_cipher(uint8_t nonce[crypto_box_NONCEBYTES],uint8_t *cipher,uint8_t *message,int32_t len,bits256 destpub,bits256 srcpriv,uint8_t *buf)
{
    memset(cipher,0,len+crypto_box_ZEROBYTES);
    memset(buf,0,crypto_box_ZEROBYTES);
    memcpy(buf+crypto_box_ZEROBYTES,message,len);
    crypto_box(cipher,buf,len+crypto_box_ZEROBYTES,nonce,destpub.bytes,srcpriv.bytes);
    return(len + crypto_box_ZEROBYTES);
}

uint8_t *_SuperNET_decipher(uint8_t nonce[crypto_box_NONCEBYTES],uint8_t *cipher,uint8_t *message,int32_t len,bits256 srcpub,bits256 mypriv)
{
    int32_t err;
    if ( (err= crypto_box_open(message,cipher,len,nonce,srcpub.bytes,mypriv.bytes)) == 0 )
    {
        message += crypto_box_ZEROBYTES;
        len -= crypto_box_ZEROBYTES;
        return(message);
    }
    return(0);
}

void *SuperNET_deciphercalc(void **ptrp,int32_t *msglenp,bits256 privkey,bits256 srcpubkey,uint8_t *cipher,int32_t cipherlen,uint8_t *buf,int32_t bufsize)
{
    uint8_t *origptr,*nonce,*message; void *retptr;
    if ( bits256_nonz(privkey) == 0 )
        privkey = GENESIS_PRIVKEY;
    *ptrp = 0;
    if ( cipherlen > bufsize )
    {
        message = calloc(1,cipherlen);
        *ptrp = (void *)message;
    }
    else message = buf;
    origptr = cipher;
    if ( bits256_nonz(srcpubkey) == 0 )
    {
        memcpy(srcpubkey.bytes,cipher,sizeof(srcpubkey));
        //char str[65]; printf("use attached pubkey.(%s)\n",bits256_str(str,srcpubkey));
        cipher += sizeof(srcpubkey);
        cipherlen -= sizeof(srcpubkey);
    }
    nonce = cipher;
    cipher += crypto_box_NONCEBYTES, cipherlen -= crypto_box_NONCEBYTES;
    *msglenp = cipherlen - crypto_box_ZEROBYTES;
    if ( (retptr= _SuperNET_decipher(nonce,cipher,message,cipherlen,srcpubkey,privkey)) == 0 )
    {
        *msglenp = -1;
        free(*ptrp);
    }
    return(retptr);
}

uint8_t *SuperNET_ciphercalc(void **ptrp,int32_t *cipherlenp,bits256 *privkeyp,bits256 *destpubkeyp,uint8_t *data,int32_t datalen,uint8_t *space2,int32_t space2size)
{
    bits256 mypubkey; uint8_t *buf,*nonce,*cipher,*origptr,space[8192]; int32_t onetimeflag=0,allocsize;
    *ptrp = 0;
    allocsize = (datalen + crypto_box_NONCEBYTES + crypto_box_ZEROBYTES);
    if ( bits256_nonz(*destpubkeyp) == 0 || memcmp(destpubkeyp->bytes,GENESIS_PUBKEY.bytes,sizeof(*destpubkeyp)) == 0 )
    {
        *destpubkeyp = GENESIS_PUBKEY;
        onetimeflag = 2; // prevent any possible leakage of privkey by encrypting to known destpub
    }
    if ( bits256_nonz(*privkeyp) == 0 )
        onetimeflag = 1;
    if ( onetimeflag != 0 )
    {
        crypto_box_keypair(mypubkey.bytes,privkeyp->bytes);
        allocsize += sizeof(bits256);
    }
    if ( allocsize > sizeof(space) )
        buf = calloc(1,allocsize);
    else buf = space;
    if ( allocsize+sizeof(struct iguana_msghdr) > space2size )
    {
        cipher = calloc(1,allocsize + sizeof(struct iguana_msghdr));
        *ptrp = (void *)cipher;
    } else cipher = space2;
    cipher = &cipher[sizeof(struct iguana_msghdr)];
    origptr = nonce = cipher;
    if ( onetimeflag != 0 )
    {
        memcpy(cipher,mypubkey.bytes,sizeof(mypubkey));
        nonce = &cipher[sizeof(mypubkey)];
    }
    OS_randombytes(nonce,crypto_box_NONCEBYTES);
    cipher = &nonce[crypto_box_NONCEBYTES];
    _SuperNET_cipher(nonce,cipher,(void *)data,datalen,*destpubkeyp,*privkeyp,buf);
    if ( buf != space )
        free(buf);
    *cipherlenp = allocsize;
    return(origptr);
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

uint16_t SuperNET_checkc(bits256 privkey,bits256 otherpub,void *num,int32_t len)
{
    uint8_t buf[40]; bits256 check,seed,seed2;
    seed = curve25519_shared(privkey,otherpub);
    vcalc_sha256(0,seed2.bytes,seed.bytes,sizeof(seed));
    memcpy(buf,seed2.bytes,sizeof(seed));
    iguana_rwnum(1,&buf[sizeof(seed)],len,num);
    vcalc_sha256(0,check.bytes,buf,sizeof(buf));
    return(check.ushorts[0]);
}

int32_t SuperNET_json2bits(uint8_t *serialized,int32_t maxsize,cJSON *json,bits256 mypub,uint16_t checkc,uint32_t myipbits,uint32_t destipbits,int32_t _othervalid)
{
    uint16_t apinum; bits256 categoryhash,subhash; uint32_t tmp,crc,timestamp;
    char *agent,*method; //uint64_t tag;
    char *hexmsg; uint8_t broadcastflag; int8_t othervalid; int32_t n,len = sizeof(uint32_t);
    if ( _othervalid > 100 )
        othervalid = 100;
    else if ( _othervalid < -100 )
        othervalid = -100;
    else othervalid = _othervalid;
    tmp = juint(json,"broadcast");
    if ( tmp > SUPERNET_MAXHOPS )
        broadcastflag = SUPERNET_MAXHOPS;
    else broadcastflag = tmp;
    categoryhash = jbits256(json,"categoryhash");
    subhash = jbits256(json,"subhash");
    timestamp = juint(json,"timestamp");
    if ( bits256_nonz(categoryhash) > 0 && memcmp(categoryhash.bytes,GENESIS_PUBKEY.bytes,sizeof(categoryhash)) != 0 )
    {
        broadcastflag |= 0x40;
        if ( bits256_nonz(subhash) > 0 && memcmp(subhash.bytes,GENESIS_PUBKEY.bytes,sizeof(subhash)) != 0 )
            broadcastflag |= 0x20;
        else subhash = GENESIS_PUBKEY;
        if ( broadcastflag == 0 )
            broadcastflag = 1;
    }
    else
    {
        categoryhash = subhash = GENESIS_PUBKEY;
        if ( broadcastflag == 0 )
            broadcastflag = 1;
    }
    if ( juint(json,"plaintext") != 0 )
        broadcastflag |= 0x80;
    //if ( (tag= j64bits(json,"tag")) == 0 )
    //    OS_randombytes((uint8_t *)&tag,sizeof(tag));
    agent = jstr(json,"agent"), method = jstr(json,"method");
    if ( agent != 0 && method != 0 && strcmp(agent,"SuperNET") == 0 && strcmp(method,"json2bits") == 0 )
    {
        agent = jstr(json,"destagent");
        method = jstr(json,"destmethod");
    }
    if ( (apinum= SuperNET_API2num(agent,method)) == 0xffff )
    {
        printf("agent.(%s) method.(%s) is not found\n",agent,method);
        return(-1);
    }
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&timestamp);
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&myipbits);
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&destipbits);
    len += iguana_rwnum(1,&serialized[len],sizeof(checkc),&checkc);
    len += iguana_rwnum(1,&serialized[len],sizeof(apinum),&apinum);
    //len += iguana_rwnum(1,&serialized[len],sizeof(tag),&tag);
    len += iguana_rwbignum(1,&serialized[len],sizeof(mypub),mypub.bytes);
    len += iguana_rwnum(1,&serialized[len],sizeof(othervalid),&othervalid);
    len += iguana_rwnum(1,&serialized[len],sizeof(broadcastflag),&broadcastflag);
    if ( (broadcastflag & 0x40) != 0 )
    {
        len += iguana_rwbignum(1,&serialized[len],sizeof(bits256),categoryhash.bytes);
        if ( (broadcastflag & 0x20) != 0 )
            len += iguana_rwbignum(1,&serialized[len],sizeof(bits256),subhash.bytes);
    }
    printf("broadcastflag.%x\n",broadcastflag);
    if ( (hexmsg= jstr(json,"hexmsg")) != 0 )
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
   // char str[65]; printf("crc.%u ip.(%s %s) tag.%llx checkc.%x apinum.%d >>>>>>>>>>>>>>>> mypub.%s\n",crc,destip,myipaddr,(long long)tag,checkc,apinum,bits256_str(str,mypubkey));
    iguana_rwnum(1,serialized,sizeof(crc),&crc);
    //int32_t i; for (i=0; i<len; i++)
    //    printf("%02x ",serialized[i]);
    //printf("SEND[%d]\n",len);
    return(len);
}

cJSON *SuperNET_bits2json(uint8_t *serialized,int32_t datalen)
{
    char destip[64],method[64],checkstr[5],agent[64],myipaddr[64],str[65],*hexmsg; //uint64_t tag;
    uint16_t apinum,checkc; int8_t othervalid; uint32_t destipbits,myipbits,timestamp;
    bits256 categoryhash,subhash,senderpub; cJSON *json = cJSON_CreateObject();
    int32_t len = 0; uint32_t crc; uint8_t broadcastflag,plaintext;
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&crc);
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&timestamp);
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&destipbits);
    len += iguana_rwnum(0,&serialized[len],sizeof(uint32_t),&myipbits);
    len += iguana_rwnum(0,&serialized[len],sizeof(checkc),&checkc);
    len += iguana_rwnum(0,&serialized[len],sizeof(apinum),&apinum);
    //len += iguana_rwnum(0,&serialized[len],sizeof(tag),&tag);
    len += iguana_rwbignum(0,&serialized[len],sizeof(bits256),senderpub.bytes);
    len += iguana_rwnum(0,&serialized[len],sizeof(othervalid),&othervalid);
    len += iguana_rwnum(0,&serialized[len],sizeof(broadcastflag),&broadcastflag);
    categoryhash = subhash = GENESIS_PUBKEY;
    if ( (broadcastflag & 0x40) != 0 )
    {
        len += iguana_rwbignum(0,&serialized[len],sizeof(bits256),categoryhash.bytes);
        if ( (broadcastflag & 0x20) != 0 )
            len += iguana_rwbignum(0,&serialized[len],sizeof(bits256),subhash.bytes);
    }
    //char str2[65]; printf("set cat.(%s) sub.(%s)\n",bits256_str(str,categoryhash),bits256_str(str2,subhash));
    plaintext = (broadcastflag & 0x80) != 0;
    broadcastflag &= 0x3f;
    if ( broadcastflag > SUPERNET_MAXHOPS )
        broadcastflag = SUPERNET_MAXHOPS;
    //printf("<<<<<<<<<<<<<<<< crc.%u ipbits.(%x %x) tag.%llx checkc.%x apinum.%d valid.%d other.%d broadcast.%d plaintext.%d\n",crc,destipbits,myipbits,(long long)tag,checkc,apinum,addr->validpub,othervalid,broadcastflag,plaintext);
    if ( SuperNET_num2API(agent,method,apinum) >= 0 )
    {
        jaddstr(json,"agent",agent);
        jaddstr(json,"method",method);
        if ( timestamp != 0 )
            jaddnum(json,"timestamp",timestamp);
        if ( bits256_nonz(categoryhash) > 0 && memcmp(GENESIS_PUBKEY.bytes,categoryhash.bytes,sizeof(categoryhash)) != 0 )
            jaddbits256(json,"categoryhash",categoryhash);
        if ( bits256_nonz(categoryhash) > 0 && memcmp(GENESIS_PUBKEY.bytes,subhash.bytes,sizeof(subhash)) != 0 )
            jaddbits256(json,"subhash",subhash);
        expand_ipbits(destip,destipbits), jaddstr(json,"yourip",destip);
        expand_ipbits(myipaddr,myipbits), jaddstr(json,"myip",myipaddr);
        jaddstr(json,"mypub",bits256_str(str,senderpub));
        categoryhash = subhash = GENESIS_PUBKEY;
        if ( (broadcastflag & 0x40) != 0 )
        {
            jaddbits256(json,"categoryhash",categoryhash);
            if ( (broadcastflag & 0x20) != 0 )
                jaddbits256(json,"subhash",subhash);
        }
        //jadd64bits(json,"tag",tag);
        init_hexbytes_noT(checkstr,(void *)&checkc,sizeof(checkc));
        jaddstr(json,"check",checkstr);
        jaddnum(json,"ov",othervalid);
        if ( plaintext != 0 )
            jaddnum(json,"plaintext",plaintext!=0);
        if ( broadcastflag != 0 )
            jaddnum(json,"broadcast",broadcastflag%SUPERNET_MAXHOPS);
        if ( len < datalen )
        {
            //printf("len %d vs %d datalen\n",len,datalen);
            hexmsg = malloc(((datalen - len)<<1) + 1);
            init_hexbytes_noT(hexmsg,&serialized[len],datalen - len);
            //printf("hex.(%s)\n",hexmsg);
            jaddstr(json,"hexmsg",hexmsg);
            free(hexmsg);
        }
        //printf("bits2json.(%s)\n",jprint(json,0));
        return(json);
    } else printf("cant decode apinum.%d (%d.%d)\n",apinum,apinum>>5,apinum%0x1f);
    return(0);
}

char *SuperNET_hexconv(char *hexmsg)
{
    cJSON *json; char *myip,*yourip,*retstr = hexmsg; uint32_t myipbits=0,destipbits=0;
    uint8_t *bits; int32_t n,len = (int32_t)strlen(hexmsg) >> 1;
    if ( (bits = calloc(1,len)) != 0 )
    {
        decode_hex(bits,len,hexmsg);
        if ( (json= cJSON_Parse((char *)bits)) != 0 )
        {
            if ( (myip= jstr(json,"myip")) != 0 )
                myipbits = (uint32_t)calc_ipbits(myip);
            if ( (yourip= jstr(json,"yourip")) != 0 )
                destipbits = (uint32_t)calc_ipbits(yourip);
            n = SuperNET_json2bits(bits,len,json,jbits256(json,"mypub"),juint(json,"checkc"),myipbits,destipbits,(int32_t)jdouble(json,"ov"));
            cJSON *json2 = SuperNET_bits2json(bits,n); printf("hexconv.(%s) -> (%s)\n",jprint(json,0),jprint(json2,1));
            if ( (retstr= calloc(1,n*2+1)) != 0 )
                init_hexbytes_noT(retstr,bits,n);
            else retstr = hexmsg;
        } else printf("SuperNET_hexconv cant parse.(%s)\n",hexmsg);
        free(bits);
    }
    return(retstr);
}

void iguana_setkeys(struct supernet_info *myinfo,struct iguana_peer *addr,bits256 *myprivp,bits256 *mypubp,bits256 *destpubp,bits256 *nextprivp,bits256 *nextpubp,bits256 *nextdestpubp)
{
    *nextprivp = myinfo->privkey;
    *nextpubp = myinfo->myaddr.pubkey;
    *nextdestpubp = addr->pubkey;
    if ( 1 || addr->validpub < 3 || addr->othervalid < 3 )
        *myprivp = GENESIS_PRIVKEY, *destpubp = *mypubp = GENESIS_PUBKEY;
    else *myprivp = *nextprivp, *mypubp = *nextpubp, *destpubp = *nextdestpubp;
    //char str[65]; printf("(priv.%llx pub.%llx) -> destpub.%s\n",(long long)myprivp->txid,(long long)mypubp->txid,bits256_str(str,*destpubp));
}

bits256 iguana_actualpubkey(int32_t *offsetp,uint8_t *cipher,int32_t cipherlen,bits256 destpubkey)
{
    int32_t i;
    *offsetp = 0;
    if ( cipherlen < 56+16 )
        return(destpubkey);
    for (i=56; i<56+16; i++)
        if ( cipher[i] != 0 )
            break;
    if ( i == 56+16 )
    {
        *offsetp = sizeof(destpubkey);
        memcpy(destpubkey.bytes,cipher,sizeof(destpubkey));
        //char str[65]; printf("extracted destpubkey.(%s)\n",bits256_str(str,destpubkey));
    }
    return(destpubkey);
}

int32_t iguana_send_supernet(struct iguana_info *coin,struct iguana_peer *addr,char *jsonstr,int32_t delaymillis)
{
    int32_t datalen,cipherlen,qlen = -1; uint8_t *serialized,space2[8192],*cipher; cJSON *json;
    struct supernet_info *myinfo; uint16_t checkc;
    bits256 destpub,privkey,pubkey,nextprivkey,nextpubkey,nextdestpub; void *ptr = 0;
    myinfo = SuperNET_MYINFO(0);
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        iguana_setkeys(myinfo,addr,&privkey,&pubkey,&destpub,&nextprivkey,&nextpubkey,&nextdestpub);
        if ( juint(json,"plaintext") == 0 && juint(json,"broadcast") == 0 && memcmp(destpub.bytes,GENESIS_PUBKEY.bytes,sizeof(pubkey)) == 0 )
        {
            printf("reject broadcasting non-plaintext! (%s)\n",jsonstr); getchar();
            free_json(json);
            return(-1);
        }
        serialized = malloc(sizeof(struct iguana_msghdr) + IGUANA_MAXPACKETSIZE);
        checkc = SuperNET_checkc(nextprivkey,nextdestpub,&nextpubkey.txid,sizeof(nextpubkey.txid));
        if ( (datalen= SuperNET_json2bits(&serialized[sizeof(struct iguana_msghdr)],IGUANA_MAXPACKETSIZE,json,nextpubkey,checkc,(uint32_t)calc_ipbits(myinfo->ipaddr),(uint32_t)calc_ipbits(addr->ipaddr),addr->othervalid)) > 0 )
        {
            printf("SUPERSEND.(%s) -> (%s) (%s) delaymillis.%d datalen.%d\n",jsonstr,jprint(SuperNET_bits2json(&serialized[sizeof(struct iguana_msghdr)],datalen),1),addr->ipaddr,delaymillis,datalen);
            if ( 0 && memcmp(destpub.bytes,GENESIS_PUBKEY.bytes,sizeof(destpub)) == 0 )
                qlen = iguana_queue_send(coin,addr,delaymillis,serialized,"SuperNET",datalen,0,0);
            else
            {
                if ( (cipher= SuperNET_ciphercalc(&ptr,&cipherlen,&privkey,&destpub,&serialized[sizeof(struct iguana_msghdr)],datalen,space2,sizeof(space2))) != 0 )
                {
                    void *msgbits; int32_t msglen,offset; bits256 testpriv; uint8_t space[65536]; void *ptr2;
                    destpub = iguana_actualpubkey(&offset,cipher,cipherlen,destpub);
                    if ( (msgbits= SuperNET_deciphercalc(&ptr2,&msglen,testpriv,destpub,&cipher[offset],cipherlen-offset,space,sizeof(space))) == 0 )
                    {
                        int32_t i; for (i=0; i<cipherlen; i++)
                            printf("%02x",cipher[i]);
                        printf(" cant decrypt cipherlen.%d otherpriv.%llx pub.%llx\n",cipherlen,(long long)testpriv.txid,(long long)pubkey.txid);
                        printf("encrypted mypriv.%llx destpub.%llx\n",(long long)privkey.txid,(long long)destpub.txid);
                    } else printf("decrypted\n");
                    qlen = iguana_queue_send(coin,addr,delaymillis,&cipher[-sizeof(struct iguana_msghdr)],"SuperNETb",cipherlen,0,0);
                    if ( ptr != 0 )
                        free(ptr);
                }
            }
        }
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

struct iguana_peer *iguana_peerfind(struct supernet_info *myinfo,struct iguana_info **coinp,uint32_t destipbits,bits256 category,bits256 subhash)
{
    int32_t i,j; struct iguana_peer *addr;
    *coinp = 0;
    for (i=0; i<IGUANA_MAXCOINS; i++)
    {
        if ( Coins[i] != 0 )
        {
            for (j=0; j<IGUANA_MAXPEERS; j++)
            {
                addr = &Coins[i]->peers.active[j];
                if ( addr->usock >= 0 )
                {
                    if ( destipbits == addr->ipbits || category_peer(myinfo,addr,category,subhash) >= 0 )
                    {
                        *coinp = Coins[i];
                        return(addr);
                    }
                }
            }
        }
    }
    return(0);
}

char *SuperNET_DHTsend(struct supernet_info *myinfo,uint32_t destipbits,bits256 categoryhash,bits256 subhash,char *hexmsg,int32_t maxdelay,int32_t broadcastflag,int32_t plaintext)
{
    int32_t i,j; char *convstr,*jsonstr=0; struct iguana_peer *addr; cJSON *json; struct iguana_info *coin;
    if ( myinfo == 0 )
        return(clonestr("{\"error\":\"no supernet_info\"}"));
    json = cJSON_CreateObject();
    jaddstr(json,"agent","SuperNET");
    jaddstr(json,"method","DHT");
    convstr = SuperNET_hexconv(hexmsg);
    jaddstr(json,"hexmsg",convstr);
    if ( convstr != hexmsg )
        free(convstr);
    if ( broadcastflag > 0 )
        jaddnum(json,"broadcast",broadcastflag-1);
    if ( plaintext != 0 )
        jaddnum(json,"plaintext",plaintext!=0);
    if ( bits256_nonz(categoryhash) > 0 && memcmp(categoryhash.bytes,GENESIS_PUBKEY.bytes,sizeof(bits256)) != 0 )
        jaddbits256(json,"categoryhash",categoryhash);
    if ( bits256_nonz(subhash) > 0 && memcmp(subhash.bytes,GENESIS_PUBKEY.bytes,sizeof(bits256)) != 0 )
        jaddbits256(json,"subhash",subhash);
    if ( SuperNET_hexmsgfind(myinfo,categoryhash,subhash,hexmsg,1) >= 0 )
    {
        char str[65]; printf("duplicate hex.(%s) for %s\n",hexmsg,bits256_str(str,categoryhash));
        return(clonestr("{\"error\":\"duplicate packet rejected\"}"));
    }
    jsonstr = jprint(json,1);
    if ( broadcastflag != 0 || destipbits == 0 )
    {
        for (i=0; i<IGUANA_MAXCOINS; i++)
        {
            if ( Coins[i] != 0 )
            {
                for (j=0; j<IGUANA_MAXPEERS; j++)
                {
                    addr = &Coins[i]->peers.active[j];
                    if ( addr->usock >= 0 && addr->supernet != 0 && (broadcastflag != 0 || category_peer(myinfo,addr,categoryhash,subhash) >= 0) )
                    {
                        char str[65]; printf("BROADCAST[%d] %s SEND.(%ld) to %s\n",j,bits256_str(str,categoryhash),strlen(jsonstr),addr->ipaddr);
                        iguana_send_supernet(Coins[i],addr,jsonstr,maxdelay==0?0:(rand()%maxdelay));
                    }
                }
            }
        }
        return(clonestr("{\"result\":\"packet sent to all peers\"}"));
    }
    if ( (addr= iguana_peerfind(myinfo,&coin,destipbits,categoryhash,subhash)) == 0 )
        return(clonestr("{\"error\":\"no route found\"}"));
    if ( SuperNET_hexmsgfind(myinfo,categoryhash,subhash,hexmsg,1) >= 0 )
    {
        printf("SEND.(%s) to %s\n",jsonstr,addr->ipaddr);
        iguana_send_supernet(coin,addr,jsonstr,maxdelay==0?0:(rand()%maxdelay));
        return(clonestr("{\"result\":\"packet sent directly\"}"));
    }
    return(clonestr("{\"result\":\"no appropriate peers to send to\"}"));
}

char *SuperNET_DHTencode(struct supernet_info *myinfo,char *destip,bits256 categoryhash,bits256 subhash,char *hexmsg,int32_t maxdelay,int32_t broadcastflag,int32_t plaintext)
{
    uint32_t destipbits; char *retstr;
    destipbits = (uint32_t)calc_ipbits(destip);
    if ( (retstr = SuperNET_DHTsend(myinfo,destipbits,categoryhash,subhash,hexmsg,maxdelay,broadcastflag,plaintext)) != 0 )
        free(retstr);
    return(clonestr("{\"result\":\"DHT sent\"}"));
}

char *SuperNET_forward(struct supernet_info *myinfo,char *hexmsg,uint32_t destipbits,bits256 categoryhash,bits256 subhash,int32_t maxdelay,int32_t broadcastflag,int32_t plaintext)
{
    return(SuperNET_DHTsend(myinfo,destipbits,categoryhash,subhash,hexmsg,maxdelay,broadcastflag,plaintext));
}

int32_t SuperNET_destination(struct supernet_info *myinfo,uint32_t *destipbitsp,bits256 *categoryp,bits256 *subhashp,int32_t *maxdelayp,cJSON *json,char *remoteaddr)
{
    char *destip; int32_t destflag = 0;
    if ( (destip= jstr(json,"destip")) != 0 )
        *destipbitsp = (uint32_t)calc_ipbits(destip);
    else *destipbitsp = 0;
    *maxdelayp = juint(json,"delay");
    *categoryp = jbits256(json,"categoryhash");
    *subhashp = jbits256(json,"subhash");
    if ( *destipbitsp != 0 )
    {
        if ( *destipbitsp == myinfo->myaddr.selfipbits )
            destflag |= SUPERNET_ISMINE;
        else destflag |= SUPERNET_FORWARD;
    }
    else if ( bits256_nonz(*categoryp) > 0 )
    {
        if ( category_peer(myinfo,0,*categoryp,*subhashp) > 0 )
            destflag |= SUPERNET_ISMINE;
        destflag |= SUPERNET_FORWARD;
    }
    if ( remoteaddr == 0 || remoteaddr[0] == 0 || strcmp(remoteaddr,"127.0.0.1") == 0 )
        destflag |= SUPERNET_ISMINE;
    return(destflag);
}

char *SuperNET_JSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr)
{
    char hexbuf[8192]; bits256 category,subhash;
    int32_t hexlen,destflag,maxdelay,flag=0; uint32_t destipbits,timestamp; cJSON *retjson;
    char *forwardstr=0,*retstr=0,*agent=0,*method=0,*message,*hexmsg=0,*jsonstr=0; uint64_t tag;
    if ( remoteaddr != 0 && strcmp(remoteaddr,"127.0.0.1") == 0 )
        remoteaddr = 0;
    agent = jstr(json,"agent");
    method = jstr(json,"method");
    if ( remoteaddr == 0 )
    {
        if ( jobj(json,"timestamp") != 0 )
            jdelete(json,"timestamp");
        timestamp = (uint32_t)time(NULL);
        jaddnum(json,"timestamp",timestamp);
    }
    if ( (tag= j64bits(json,"tag")) == 0 )
    {
        OS_randombytes((uint8_t *)&tag,sizeof(tag));
        jadd64bits(json,"tag",tag);
    }
    //printf("SuperNET_JSON.(%s) remote.(%s)\n",jprint(json,0),remoteaddr!=0?remoteaddr:"");
    destflag = SuperNET_destination(myinfo,&destipbits,&category,&subhash,&maxdelay,json,remoteaddr);
    //printf("destflag.%d\n",destflag);
    if ( (hexmsg= jstr(json,"hexmsg")) == 0 && (message= jstr(json,"message")) == 0 )
    {
        jsonstr = jprint(json,0);
        hexlen = (int32_t)strlen(jsonstr);
        if ( hexlen*2+1 > sizeof(hexbuf) )
            hexmsg = malloc(hexlen*2+1), flag = 1;
        else hexmsg = hexbuf;
        init_hexbytes_noT(hexmsg,(uint8_t *)jsonstr,(int32_t)strlen(jsonstr)+1);
    }
    if ( (destflag & SUPERNET_FORWARD) != 0 )
    {
        if ( hexmsg != 0 )
        {
            //printf("check.(%s)\n",hexmsg);
            if ( SuperNET_hexmsgfind(myinfo,category,subhash,hexmsg,0) < 0 )
            {
                SuperNET_hexmsgadd(myinfo,category,subhash,hexmsg,tai_now());
                forwardstr = SuperNET_forward(myinfo,hexmsg,destipbits,category,subhash,maxdelay,juint(json,"broadcast"),juint(json,"plaintext")!=0);
            }
        }
    }
    if ( (destflag & SUPERNET_ISMINE) != 0 && agent != 0 && method != 0 )
    {
        if ( hexmsg != 0 && SuperNET_hexmsgfind(myinfo,category,subhash,hexmsg,0) < 0 )
            SuperNET_hexmsgadd(myinfo,category,subhash,hexmsg,tai_now());
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
    if ( flag != 0 && hexmsg != 0 && hexmsg != hexbuf )
        free(hexmsg);
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
    struct supernet_info *myinfo;char *myipaddr,*method,*retstr,*checkstr; void *ptr=0;
    bits256 senderpub,privkey,pubkey,nextprivkey,nextpubkey,nextdestpub;
    uint16_t checkc,othercheckc; cJSON *json,*retjson; int32_t offset,maxdelay,msglen = datalen;
    uint8_t space[8192],*msgbits = 0;
    myinfo = SuperNET_MYINFO(0);
    retstr = 0;
    *delaymillisp = 0;
    if ( compressed != 0 )
    {
        //int32_t i; for (i=0; i<datalen; i++)
        //    printf("%02x ",data[i]);
        //printf("DECRYPT %d\n",datalen);
        iguana_setkeys(myinfo,addr,&privkey,&pubkey,&senderpub,&nextprivkey,&nextpubkey,&nextdestpub);
        senderpub = iguana_actualpubkey(&offset,data,datalen,senderpub);
        if ( (msgbits= SuperNET_deciphercalc(&ptr,&msglen,privkey,senderpub,data+offset,datalen-offset,space,sizeof(space))) == 0 )
        {
            if ( (msgbits= SuperNET_deciphercalc(&ptr,&msglen,GENESIS_PRIVKEY,GENESIS_PUBKEY,data+offset,datalen-offset,space,sizeof(space))) == 0 )
            {
                if ( (msgbits= SuperNET_deciphercalc(&ptr,&msglen,GENESIS_PRIVKEY,senderpub,data+offset,datalen-offset,space,sizeof(space))) == 0 )
                {
                    int32_t i; for (i=0; i<datalen; i++)
                        printf("%02x ",data[i]);
                    printf("error decrypting %d from %s\n",datalen,addr->ipaddr);
                    addr->validpub = 0;
                    return(0);
                } else { char str[65]; printf("GENESIS recv %s\n",bits256_str(str,senderpub)); }
            } else printf("GENESIS recv GENESIS\n");
        } //else printf("decrypted mypriv.%llx senderpub.%llx\n",(long long)privkey.txid,(long long)senderpub.txid);
        //for (i=0; i<msglen; i++)
        //    printf("%02x ",msgbits[i]);
        //printf("DECRYPTED %d\n",msglen);
    } else msgbits = data;
    if ( (json= SuperNET_bits2json(msgbits,msglen)) != 0 )
    {
        senderpub = jbits256(json,"mypub");
        if ( (checkstr= jstr(json,"check")) != 0 )
        {
            decode_hex((uint8_t *)&othercheckc,sizeof(othercheckc),checkstr);
            checkc = SuperNET_checkc(myinfo->privkey,senderpub,&senderpub.txid,sizeof(senderpub.txid));
            if ( checkc == othercheckc )
                addr->validpub++;
            else if ( addr->validpub > 0 )
                addr->validpub >>= 1;
            else addr->validpub--;
            //printf("validpub.%d: %x vs %x shared.%llx\n",addr->validpub,checkc,othercheckc,(long long)addr->sharedseed.txid);
        }
        maxdelay = juint(json,"maxdelay");
        if ( jstr(json,"method") != 0 && strcmp(jstr(json,"method"),"getpeers") != 0 )
            printf("GOT >>>>>>>> SUPERNET P2P.(%s) from.%s %s valid.%d:%d\n",jprint(json,0),coin->symbol,addr->ipaddr,addr->validpub,addr->othervalid);
        if ( (myipaddr= jstr(json,"yourip")) != 0 )
            SuperNET_myipaddr(SuperNET_MYINFO(0),coin,addr,myipaddr,ipaddr);
        jaddstr(json,"fromp2p",coin->symbol);
        method = jstr(json,"method");
        if ( method != 0 && strcmp(method,"stop") == 0 )
        {
            addr->dead = (uint32_t)time(NULL);
            free_json(json);
            if ( ptr != 0 )
                free(ptr);
            //return(clonestr("{\"result\":\"peer marked as dead\"}"));
            return(0);
        }
        retstr = SuperNET_JSON(myinfo,json,ipaddr);
        //printf("p2pret.(%s)\n",retstr);
        *delaymillisp = SuperNET_delaymillis(myinfo,maxdelay);
        senderpub = jbits256(json,"mypub");
        addr->othervalid = (int32_t)jdouble(json,"ov");
        addr->pubkey = senderpub;
        free_json(json);
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( jstr(retjson,"error") != 0 || (jstr(retjson,"result") != 0 && jstr(retjson,"method") == 0) )
            {
                //printf("filter.(%s) no need to send back\n",retstr);
                free(retstr);
                retstr = 0;
            }
            free_json(retjson);
        }
    }
    if ( ptr != 0 )
        free(ptr);
    return(retstr);
}

cJSON *SuperNET_peerarray(struct iguana_info *coin,int32_t max,int32_t supernetflag)
{
    int32_t i,r,j,n = 0; struct iguana_peer *addr; cJSON *array = cJSON_CreateArray();
    r = rand();
    for (j=0; j<IGUANA_MAXPEERS; j++)
    {
        i = (r + j) % IGUANA_MAXPEERS;
        addr = &coin->peers.active[i];
        if ( addr->usock >= 0 && supernetflag == (addr->supernet != 0) )
        {
            jaddistr(array,addr->ipaddr);
            if ( ++n >= max )
                break;
        }
    }
    if ( n == 0 )
    {
        free_json(array);
        return(0);
    }
    return(array);
}

int32_t SuperNET_coinpeers(struct iguana_info *coin,cJSON *SNjson,cJSON *rawjson,int32_t max)
{
    cJSON *array,*item;
    if ( (array= SuperNET_peerarray(coin,max,1)) != 0 )
    {
        max -= cJSON_GetArraySize(array);
        item = cJSON_CreateObject();
        jaddstr(item,"coin",coin->symbol);
        jadd(item,"peers",array);
        jaddi(SNjson,item);
    }
    if ( max > 0 && (array= SuperNET_peerarray(coin,max,0)) != 0 )
    {
        max -= cJSON_GetArraySize(array);
        item = cJSON_CreateObject();
        jaddstr(item,"coin",coin->symbol);
        jadd(item,"peers",array);
        jaddi(rawjson,item);
    }
    return(max);
}

void SuperNET_parsepeers(struct supernet_info *myinfo,cJSON *array,int32_t n,int32_t supernetflag)
{
    int32_t i,j,m; cJSON *coinarray,*item; char *symbol,*ipaddr; struct iguana_info *ptr;
    if ( array != 0 && n > 0 )
    {
        for (i=0; i<n; i++)
        {
            if ( (item= jitem(array,i)) != 0 && (symbol= jstr(item,"coin")) != 0 )
            {
                ptr = iguana_coinfind(symbol);
                if ( (coinarray= jarray(&m,item,"peers")) != 0 )
                {
                    for (j=0; j<m; j++)
                    {
                        if ( (ipaddr= jstr(jitem(coinarray,j),0)) != 0 )
                            SuperNET_remotepeer(myinfo,ptr,symbol,ipaddr,supernetflag);
                        else printf("no ipaddr[%d] of %d\n",j,m);
                    }
                }
                printf("parsed.%d %s.peers supernet.%d\n",m,symbol,supernetflag);
            }
        }
    }
}

#include "../includes/iguana_apidefs.h"

HASH_ARG(SuperNET,priv2pub,privkey)
{
    cJSON *retjson = cJSON_CreateObject(); bits256 pubkey;
    crypto_box_priv2pub(pubkey.bytes,privkey.bytes);
    jaddbits256(retjson,"result",pubkey);
    return(jprint(retjson,1));
}

ZERO_ARGS(SuperNET,keypair)
{
    cJSON *retjson = cJSON_CreateObject(); bits256 pubkey,privkey;
    crypto_box_keypair(pubkey.bytes,privkey.bytes);
    jaddstr(retjson,"result","generated keypair");
    jaddbits256(retjson,"privkey",privkey);
    jaddbits256(retjson,"pubkey",pubkey);
    return(jprint(retjson,1));
}

TWOHASHES_AND_STRING(SuperNET,decipher,privkey,srcpubkey,cipherstr)
{
    int32_t cipherlen,msglen; char *retstr; cJSON *retjson; void *ptr = 0; uint8_t *cipher,*message,space[8192];
    cipherlen = (int32_t)strlen(cipherstr) >> 1;
    if ( cipherlen < crypto_box_NONCEBYTES )
        return(clonestr("{\"error\":\"cipher is too short\"}"));
    cipher = calloc(1,cipherlen);
    decode_hex(cipher,cipherlen,cipherstr);
    if ( (message= SuperNET_deciphercalc(&ptr,&msglen,privkey,srcpubkey,cipher,cipherlen,space,sizeof(space))) != 0 )
    {
        message[msglen] = 0;
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","deciphered message");
        jaddstr(retjson,"message",(char *)message);
        retstr = jprint(retjson,1);
        if ( ptr != 0 )
            free(ptr);
    } else retstr = clonestr("{\"error\":\"couldnt decipher message\"}");
    return(retstr);
}

TWOHASHES_AND_STRING(SuperNET,cipher,privkey,destpubkey,message)
{
    cJSON *retjson; char *retstr,*hexstr,space[8129]; uint8_t space2[8129];
    uint8_t *cipher; int32_t cipherlen,onetimeflag; bits256 origprivkey; void *ptr = 0;
    if ( (cipher= SuperNET_ciphercalc(&ptr,&cipherlen,&privkey,&destpubkey,(uint8_t *)message,(int32_t)strlen(message)+1,space2,sizeof(space2))) != 0 )
    {
        if ( cipherlen > sizeof(space)/2 )
            hexstr = calloc(1,(cipherlen<<1)+1);
        else hexstr = (void *)space;
        init_hexbytes_noT(hexstr,cipher,cipherlen);
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result",hexstr);
        onetimeflag = memcmp(origprivkey.bytes,privkey.bytes,sizeof(privkey));
        if ( onetimeflag != 0 )
        {
            jaddbits256(retjson,"onetime_privkey",privkey);
            jaddbits256(retjson,"onetime_pubkey",destpubkey);
            if ( onetimeflag == 2 )
                jaddstr(retjson,"warning","onetime keypair was used to broadcast");
        }
        retstr = jprint(retjson,1);
        if ( hexstr != (void *)space )
            free(hexstr);
        if ( ptr != 0 )
            free(ptr);
        return(retstr);
    }
    printf("error encrypting message.(%s)\n",message);
    return(clonestr("{\"error\":\"cant encrypt message\"}"));
}

bits256 SuperNET_pindecipher(IGUANA_ARGS,char *pin,char *privcipher)
{
    cJSON *testjson; char *mstr,*cstr; bits256 privkey,pinpriv,pinpub;
    conv_NXTpassword(pinpriv.bytes,pinpub.bytes,(uint8_t *)pin,(int32_t)strlen(pin));
    if ( (cstr= SuperNET_decipher(IGUANA_CALLARGS,pinpriv,pinpub,privcipher)) != 0 )
    {
        if ( (testjson= cJSON_Parse(cstr)) != 0 )
        {
            if ( (mstr= jstr(testjson,"message")) != 0 && strlen(mstr) == sizeof(bits256)*2 )
            {
                decode_hex(privkey.bytes,sizeof(privkey),mstr);
            } else printf("error cant find message privcipher\n");
            free_json(testjson);
        } else printf("Error decipher.(%s)\n",cstr);
        free(cstr);
    } else printf("null return from deciphering privcipher\n");
    return(privkey);
}

THREE_STRINGS(SuperNET,rosetta,passphrase,pin,showprivkey)
{
    uint8_t rmd160[20],pub[33],flag = 0; uint64_t nxt64bits; bits256 check,privkey,pubkey,pinpriv,pinpub;
    char str2[41],wifbuf[64],addr[64],str[128],privcipher[512],*privcipherstr,*cstr; cJSON *retjson;
    nxt64bits = conv_NXTpassword(privkey.bytes,pubkey.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
    if ( showprivkey != 0 && strcmp(showprivkey,"yes") == 0 )
        flag = 1;
    privcipher[0] = 0;
    conv_NXTpassword(pinpriv.bytes,pinpub.bytes,(uint8_t *)pin,(int32_t)strlen(pin));
    if ( (cstr= SuperNET_cipher(IGUANA_CALLARGS,pinpriv,pinpub,bits256_str(str,privkey))) != 0 )
    {
        if ( (retjson= cJSON_Parse(cstr)) != 0 )
        {
            if ( (privcipherstr= jstr(retjson,"result")) != 0 )
                strcpy(privcipher,privcipherstr);
            free_json(retjson);
        } else printf("error parsing cipher retstr.(%s)\n",cstr);
        free(cstr);
    } else printf("error SuperNET_cipher null return\n");
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"privcipher",privcipher);
    jaddbits256(retjson,"pubkey",pubkey);
    RS_encode(str,nxt64bits);
    jaddstr(retjson,"RS",str);
    jadd64bits(retjson,"NXT",nxt64bits);
    btc_priv2pub(pub,privkey.bytes);
    init_hexbytes_noT(str,pub,33);
    jaddstr(retjson,"btcpubkey",str);
    calc_OP_HASH160(str2,rmd160,str);
    jaddstr(retjson,"rmd160",str2);
    if ( btc_coinaddr(addr,0,str) == 0 )
    {
        jaddstr(retjson,"BTC",addr);
        btc_priv2wip(wifbuf,privkey.bytes,0x80);
        if ( flag != 0 )
            jaddstr(retjson,"BTCwif",wifbuf);
    }
    if ( btc_coinaddr(addr,60,str) == 0 )
    {
        jaddstr(retjson,"BTCD",addr);
        btc_priv2wip(wifbuf,privkey.bytes,0xbc);
        if ( flag != 0 )
            jaddstr(retjson,"BTCDwif",wifbuf);
    }
    if ( flag != 0 )
        jaddbits256(retjson,"privkey",privkey);
    check = SuperNET_pindecipher(IGUANA_CALLARGS,pin,privcipher);
    if ( memcmp(check.bytes,privkey.bytes,sizeof(check)) != 0 )
    {
        jaddbits256(retjson,"deciphered",check);
        jaddstr(retjson,"error","cant recreate privkey from (pin + privcipher)");
    }
    else if ( flag != 0 )
        jaddbits256(retjson,"deciphered",check);
    if ( jobj(retjson,"error") == 0 )
        jaddstr(retjson,"result","use pin and privcipher to access wallet");
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,broadcastcipher,message)
{
    bits256 zero;
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_cipher(IGUANA_CALLARGS,zero,zero,message));
}

STRING_ARG(SuperNET,broadcastdecipher,message)
{
    bits256 zero;
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_decipher(IGUANA_CALLARGS,zero,zero,message));
}

HASH_AND_STRING(SuperNET,multicastcipher,pubkey,message)
{
    bits256 zero;
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_cipher(IGUANA_CALLARGS,zero,pubkey,message));
}

HASH_AND_STRING(SuperNET,multicastdecipher,privkey,cipherstr)
{
    bits256 zero;
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_decipher(IGUANA_CALLARGS,privkey,zero,cipherstr));
}

ZERO_ARGS(SuperNET,stop)
{
    if ( remoteaddr == 0 || strncmp(remoteaddr,"127.0.0.1",strlen("127.0.0.1")) == 0 )
    {
        iguana_exit();
        return(clonestr("{\"result\":\"exit started\"}"));
    } else return(clonestr("{\"error\":\"cant do a remote stop of this node\"}"));
}

TWO_ARRAYS(SuperNET,mypeers,supernet,rawpeers)
{
    SuperNET_parsepeers(myinfo,supernet,cJSON_GetArraySize(supernet),1);
    SuperNET_parsepeers(myinfo,rawpeers,cJSON_GetArraySize(rawpeers),0);
    return(clonestr("{\"result\":\"peers parsed\"}"));
}

STRING_ARG(SuperNET,getpeers,activecoin)
{
    int32_t i,max = 64;
    cJSON *SNjson,*rawjson,*retjson = cJSON_CreateObject();
    SNjson = cJSON_CreateArray();
    rawjson = cJSON_CreateArray();
    if ( coin != 0 )
        max = SuperNET_coinpeers(coin,SNjson,rawjson,max);
    else
    {
        for (i=0; i<IGUANA_MAXCOINS&&max>0; i++)
            if ( Coins[i] != 0 )
                max = SuperNET_coinpeers(Coins[i],SNjson,rawjson,max);
    }
    if ( max != 64 )
    {
        jaddstr(retjson,"agent","SuperNET");
        jaddstr(retjson,"method","mypeers");
        jadd(retjson,"supernet",SNjson);
        jadd(retjson,"rawpeers",rawjson);
    }
    else
    {
        jaddstr(retjson,"error","no peers");
        free_json(SNjson);
        free_json(rawjson);
    }
    return(jprint(retjson,1));
}

TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(SuperNET,DHT,hexmsg,destip,categoryhash,subhash,maxdelay,broadcast)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"cant remote DHT\"}"));
    else if ( hexmsg == 0 || is_hexstr(hexmsg,(int32_t)strlen(hexmsg)) <= 0 )
        return(clonestr("{\"error\":\"hexmsg missing or not in hex\"}"));
    return(SuperNET_DHTencode(myinfo,destip,categoryhash,subhash,hexmsg,maxdelay,broadcast,juint(json,"plaintext")!=0));
}

HASH_AND_STRING(SuperNET,saveconf,wallethash,confjsonstr)
{
    return(clonestr("{\"result\":\"saveconf here\"}"));
}

HASH_ARRAY_STRING(SuperNET,layer,mypriv,otherpubs,str)
{
    return(clonestr("{\"result\":\"layer encrypt here\"}"));
}

bits256 calc_categoryhashes(bits256 *subhashp,char *category,char *subcategory)
{
    bits256 categoryhash;
    if ( category == 0 || category[0] == 0 || strcmp(category,"broadcast") == 0 )
        categoryhash = GENESIS_PUBKEY;
    else vcalc_sha256(0,categoryhash.bytes,(uint8_t *)category,(int32_t)strlen(category));
    if ( subcategory == 0 || subcategory[0] == 0 || strcmp(subcategory,"broadcast") == 0 )
        *subhashp = GENESIS_PUBKEY;
    else vcalc_sha256(0,subhashp->bytes,(uint8_t *)subcategory,(int32_t)strlen(subcategory));
    return(categoryhash);
}

TWO_STRINGS(SuperNET,subscribe,category,subcategory)
{
    bits256 categoryhash,subhash;
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    if ( category_sub(myinfo,categoryhash,subhash) != 0 )
        return(clonestr("{\"result\":\"subscribed\"}"));
    else return(clonestr("{\"error\":\"couldnt subscribe\"}"));
}

TWO_STRINGS(SuperNET,gethexmsg,category,subcategory)
{
    bits256 categoryhash,subhash; struct category_msg *m; char *hexstr; cJSON *retjson;
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    if ( (m= category_gethexmsg(myinfo,categoryhash,subhash)) != 0 )
    {
        hexstr = calloc(1,m->len*2+1);
        init_hexbytes_noT(hexstr,m->msg,m->len);
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result",hexstr);
        free(hexstr);
        return(jprint(retjson,1));
    } else return(clonestr("{\"result\":\"no message\"}"));
}

THREE_STRINGS(SuperNET,posthexmsg,category,subcategory,hexmsg)
{
    bits256 categoryhash,subhash;
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    category_posthexmsg(myinfo,categoryhash,subhash,hexmsg,tai_now());
    return(clonestr("{\"result\":\"posted message\"}"));
}

THREE_STRINGS(SuperNET,announce,category,subcategory,message)
{
    bits256 categoryhash,subhash;
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    return(SuperNET_categorymulticast(myinfo,0,categoryhash,subhash,message,juint(json,"maxdelay"),juint(json,"broadcast"),juint(json,"plaintext")));
}

THREE_STRINGS(SuperNET,survey,category,subcategory,message)
{
    bits256 categoryhash,subhash;
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    return(SuperNET_categorymulticast(myinfo,1,categoryhash,subhash,message,juint(json,"maxdelay"),juint(json,"broadcast"),juint(json,"plaintext")));
}
#include "../includes/iguana_apiundefs.h"
