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
#include "../crypto777/OS_portable.h"
#include "../includes/libgfshare.h"
#include "../includes/utlist.h"
#include "../includes/uthash.h"
#include "../includes/curve25519.h"
#include "../includes/cJSON.h"


cJSON *SuperNET_argjson(cJSON *json)
{
    cJSON *argjson = jduplicate(json);
    jdelete(argjson,"agent");
    jdelete(argjson,"method");
    jdelete(argjson,"categoryhash");
    jdelete(argjson,"subhash");
    jdelete(argjson,"mypub");
    jdelete(argjson,"hexmsg");
    jdelete(argjson,"plaintext");
    jdelete(argjson,"broadcast");
    jdelete(argjson,"ov");
    jdelete(argjson,"check");
    jdelete(argjson,"yourip");
    jdelete(argjson,"myip");
    jdelete(argjson,"myipaddr");
    return(argjson);
}

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
        if ( (addr= iguana_peerslot(coin,ipbits,0)) != 0 )
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

void SuperNET_checkipaddr(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,char *myipaddr,char *remoteaddr)
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
    if ( myinfo->ipaddr[0] == 0 || strcmp(myinfo->ipaddr,"127.0.0.1") == 0 )
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
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&destipbits);
    len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&myipbits);
    //printf("myipbits.%x destipbits.%x\n",myipbits,destipbits);
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
    //printf("broadcastflag.%x\n",broadcastflag);
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
    uint8_t *bits; int32_t n,len = (int32_t)strlen(hexmsg);
    //if ( hexmsg == 0 || is_hexstr(hexmsg,len) == 0 )
    return(hexmsg);
    len >>= 1;
    if ( (bits= calloc(1,len)) != 0 )
    {
        decode_hex(bits,len,hexmsg);
        if ( (json= cJSON_Parse((char *)bits)) != 0 )
        {
            printf("parsed hexmsg.(%s)\n",(char *)bits);
            if ( (myip= jstr(json,"myip")) != 0 )
                myipbits = (uint32_t)calc_ipbits(myip);
            if ( (yourip= jstr(json,"yourip")) != 0 )
                destipbits = (uint32_t)calc_ipbits(yourip);
            n = SuperNET_json2bits(bits,len,json,jbits256(json,"mypub"),juint(json,"checkc"),myipbits,destipbits,(int32_t)jdouble(json,"ov"));
            cJSON *json2 = SuperNET_bits2json(bits,n); printf("hexconv.(%s) -> (%s)\n",jprint(json,0),jprint(json2,1));
            if ( (retstr= calloc(1,n*2+1)) != 0 )
                init_hexbytes_noT(retstr,bits,n);
            else retstr = hexmsg;
            free_json(json);
        } //else printf("SuperNET_hexconv cant parse.(%s)\n",hexmsg);
        free(bits);
    }
    return(retstr);
}

void iguana_setkeys(struct supernet_info *myinfo,struct iguana_peer *addr,bits256 *myprivp,bits256 *mypubp,bits256 *destpubp,bits256 *nextprivp,bits256 *nextpubp,bits256 *nextdestpubp)
{
    *nextprivp = myinfo->privkey;
    *nextpubp = myinfo->myaddr.pubkey;
    *nextdestpubp = addr->pubkey;
    if ( 0 || addr->validpub < 3 || addr->othervalid < 3 )
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
    int32_t datalen,cipherlen,qlen = -1; uint8_t *serialized,space2[32768],*cipher; cJSON *json;
    struct supernet_info *myinfo; uint16_t checkc;
    bits256 destpub,privkey,pubkey,nextprivkey,nextpubkey,nextdestpub; void *ptr = 0;
    myinfo = SuperNET_MYINFO(0);
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        iguana_setkeys(myinfo,addr,&privkey,&pubkey,&destpub,&nextprivkey,&nextpubkey,&nextdestpub);
        if ( juint(json,"plaintext") == 0 && juint(json,"broadcast") == 0 && memcmp(destpub.bytes,GENESIS_PUBKEY.bytes,sizeof(pubkey)) == 0 )
        {
            //printf("reject broadcasting non-plaintext! (%s)\n",jsonstr); //getchar();
            free_json(json);
            return(-1);
        }
        serialized = malloc(sizeof(struct iguana_msghdr) + IGUANA_MAXPACKETSIZE);
        checkc = SuperNET_checkc(nextprivkey,nextdestpub,&nextpubkey.txid,sizeof(nextpubkey.txid));
        if ( (datalen= SuperNET_json2bits(&serialized[sizeof(struct iguana_msghdr)],IGUANA_MAXPACKETSIZE,json,nextpubkey,checkc,(uint32_t)calc_ipbits(myinfo->ipaddr),(uint32_t)calc_ipbits(addr->ipaddr),addr->othervalid)) > 0 )
        {
            if ( 1 && jstr(json,"method") != 0 && strcmp("getpeers",jstr(json,"method")) != 0 )
                printf("SUPERSEND -> (%s) (%s) delaymillis.%d datalen.%d\n",jprint(SuperNET_bits2json(&serialized[sizeof(struct iguana_msghdr)],datalen),1),addr->ipaddr,delaymillis,datalen);
            if ( 0 && memcmp(destpub.bytes,GENESIS_PUBKEY.bytes,sizeof(destpub)) == 0 )
                qlen = iguana_queue_send(coin,addr,delaymillis,serialized,"SuperNET",datalen,0,0);
            else
            {
                if ( (cipher= SuperNET_ciphercalc(&ptr,&cipherlen,&privkey,&destpub,&serialized[sizeof(struct iguana_msghdr)],datalen,space2,sizeof(space2))) != 0 )
                {
                    void *msgbits; int32_t msglen,offset; bits256 testpriv; uint8_t space[65536]; void *ptr2;
                    destpub = iguana_actualpubkey(&offset,cipher,cipherlen,destpub);
                    if ( 0 && (msgbits= SuperNET_deciphercalc(&ptr2,&msglen,testpriv,destpub,&cipher[offset],cipherlen-offset,space,sizeof(space))) == 0 )
                    {
                        int32_t i; for (i=0; i<cipherlen; i++)
                            printf("%02x",cipher[i]);
                        printf(" cant decrypt cipherlen.%d otherpriv.%llx pub.%llx\n",cipherlen,(long long)testpriv.txid,(long long)pubkey.txid);
                        printf("encrypted mypriv.%llx destpub.%llx\n",(long long)privkey.txid,(long long)destpub.txid);
                    } //else printf("decrypted\n");
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

struct iguana_peer *iguana_peerfind(struct supernet_info *myinfo,struct iguana_info **coinp,uint64_t destipbits,bits256 category,bits256 subhash)
{
    int32_t i,j; struct iguana_peer *addr; uint16_t port;
    *coinp = 0;
    port = (uint16_t)(destipbits >> 32);
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
                        if ( port == 0 || addr->A.port == port )
                        {
                            *coinp = Coins[i];
                            return(addr);
                        }
                    }
                }
            }
        }
    }
    return(0);
}

char *SuperNET_DHTsend(struct supernet_info *myinfo,uint64_t destipbits,bits256 categoryhash,bits256 subhash,char *hexmsg,int32_t maxdelay,int32_t broadcastflag,int32_t plaintext)
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
    else
    {
        printf("DHT send\n");
        SuperNET_hexmsgadd(myinfo,categoryhash,subhash,hexmsg,tai_now(),0);
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
                        if ( strcmp("0.0.0.0",addr->ipaddr) != 0 && strcmp("127.0.0.1",addr->ipaddr) != 0 )
                        {
                            char str[65]; printf("BROADCAST[%d] crc.%x %s SEND.(%d) to %s\n",j,calc_crc32(0,jsonstr,(int32_t)strlen(jsonstr)),bits256_str(str,categoryhash),(int32_t)strlen(jsonstr),addr->ipaddr);
                            iguana_send_supernet(Coins[i],addr,jsonstr,maxdelay==0?0:(rand()%maxdelay));
                        }
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
        if ( juint(json,"broadcast") > 0 )
            destflag |= SUPERNET_FORWARD;
    }
    if ( remoteaddr == 0 || remoteaddr[0] == 0 || strcmp(remoteaddr,"127.0.0.1") == 0 )
        destflag |= SUPERNET_ISMINE;
    return(destflag);
}

char *SuperNET_JSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr,uint16_t port)
{
    char hexbuf[8192]; bits256 category,subhash;
    int32_t autologin = 0,hexlen,destflag,maxdelay,flag=0,newflag=0; uint32_t destipbits,timestamp; //cJSON *retjson;
    char *str,*forwardstr=0,*retstr=0,*agent=0,*method=0,*message,*hexmsg=0,*jsonstr=0; uint64_t tag;
    //printf("SuperNET_JSON.(%s)\n",jprint(json,0));
    if ( remoteaddr != 0 && strcmp(remoteaddr,"127.0.0.1") == 0 )
        remoteaddr = 0;
    if ( (agent = jstr(json,"agent")) == 0 )
        agent = "bitcoinrpc";
    method = jstr(json,"method");
    if ( agent != 0 )
    {
        if ( strcmp(agent,"pangea") == 0 && jobj(json,"categoryhash") == 0 )
        {
            jaddbits256(json,"categoryhash",calc_categoryhashes(0,"pangea",0));
            if ( jobj(json,"subhash") == 0 )
                jaddbits256(json,"subhash",GENESIS_PUBKEY);
        }
        else if ( strcmp(agent,"InstantDEX") == 0 )
        {
            if ( jobj(json,"passphrase") != 0 )
            {
                if ( (str= SuperNET_login(myinfo,0,json,remoteaddr,jstr(json,"handle"),0,0,jstr(json,"passphrase"))) != 0 )
                    free(str);
                autologin = 1;
            }
            else if ( jobj(json,"password") != 0 )
            {
                if ( (str= SuperNET_login(myinfo,0,json,remoteaddr,jstr(json,"handle"),jstr(json,"password"),jstr(json,"permanentfile"),0)) != 0 )
                    free(str);
                autologin = 1;
            }
        }
    }
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
    if ( method != 0 && (hexmsg= jstr(json,"hexmsg")) == 0 && strcmp(agent,"bitcoinrpc") != 0 && (message= jstr(json,"message")) == 0 )
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
            if ( SuperNET_hexmsgfind(myinfo,category,subhash,hexmsg,0) < 0 )
            {
                //printf("FORWARD.(%s)\n",hexmsg);
                newflag = 1;
                SuperNET_hexmsgadd(myinfo,category,subhash,hexmsg,tai_now(),remoteaddr);
                forwardstr = SuperNET_forward(myinfo,hexmsg,destipbits,category,subhash,maxdelay,juint(json,"broadcast"),juint(json,"plaintext")!=0);
            }
        }
    }
    if ( (destflag & SUPERNET_ISMINE) != 0 && agent != 0 && method != 0 )
    {
        if ( strcmp(agent,"bitcoinrpc") != 0 && newflag == 0 && hexmsg != 0 && SuperNET_hexmsgfind(myinfo,category,subhash,hexmsg,0) < 0 )
        {
            //printf("SuperNET_JSON hexmsgadd\n");
            SuperNET_hexmsgadd(myinfo,category,subhash,hexmsg,tai_now(),remoteaddr);
        }
        if ( (retstr= SuperNET_processJSON(myinfo,json,remoteaddr,port)) == 0 )
            printf("null retstr from SuperNET_JSON\n");
    }
    if ( flag != 0 && hexmsg != 0 && hexmsg != hexbuf )
        free(hexmsg);
    if ( retstr == 0 )
        retstr = forwardstr, forwardstr = 0;
    if ( forwardstr != 0 )
        free(forwardstr);
    if ( jsonstr != 0 )
        free(jsonstr);
    if ( autologin != 0 )
        SuperNET_logout(myinfo,0,json,remoteaddr);
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
        } else printf("decrypted mypriv.%llx senderpub.%llx\n",(long long)privkey.txid,(long long)senderpub.txid);
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
            printf("validpub.%d: %x vs %x shared.%llx priv.%llx senderpub.%llx\n",addr->validpub,checkc,othercheckc,(long long)addr->sharedseed.txid,(long long)myinfo->privkey.txid,(long long)senderpub.txid);
        }
        maxdelay = juint(json,"maxdelay");
        //if ( 1 && jstr(json,"method") != 0 && strcmp(jstr(json,"method"),"getpeers") != 0 )
            printf("GOT >>>>>>>> SUPERNET P2P.(%s) from.%s %s valid.%d:%d\n",jprint(json,0),coin->symbol,addr->ipaddr,addr->validpub,addr->othervalid);
        if ( (myipaddr= jstr(json,"yourip")) != 0 )
            SuperNET_checkipaddr(SuperNET_MYINFO(0),coin,addr,myipaddr,ipaddr);
        jaddstr(json,"fromp2p",coin->symbol);
        method = jstr(json,"method");
        if ( method != 0 && strcmp(method,"stop") == 0 )
        {
            addr->dead = (uint32_t)time(NULL);
            addr->rank = 0;
            free_json(json);
            if ( ptr != 0 )
                free(ptr);
            //return(clonestr("{\"result\":\"peer marked as dead\"}"));
            return(0);
        }
        retstr = SuperNET_JSON(myinfo,json,ipaddr,addr->A.port);
        printf("(%s) -> p2pret.(%s)\n",jprint(json,0),retstr);
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
    } else printf("error decoding bits2json\n");
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

cJSON *SuperNET_rosettajson(bits256 privkey,int32_t showprivs)
{
    uint8_t rmd160[20],pub[33]; uint64_t nxt64bits; bits256 pubkey;
    char str2[41],wifbuf[64],addr[64],str[128]; cJSON *retjson;
    pubkey = acct777_pubkey(privkey);
    nxt64bits = acct777_nxt64bits(pubkey);
    retjson = cJSON_CreateObject();
    jaddbits256(retjson,"pubkey",pubkey);
    RS_encode(str,nxt64bits);
    jaddstr(retjson,"RS",str);
    jadd64bits(retjson,"NXT",nxt64bits);
    bitcoin_pubkey33(0,pub,privkey);
    init_hexbytes_noT(str,pub,33);
    jaddstr(retjson,"btcpubkey",str);
    calc_OP_HASH160(str2,rmd160,str);
    jaddstr(retjson,"rmd160",str2);
    if ( bitcoin_address(addr,0,pub,33) != 0 )
    {
        jaddstr(retjson,"BTC",addr);
        if ( showprivs != 0 )
        {
            bitcoin_priv2wif(wifbuf,privkey,128);
            jaddstr(retjson,"BTCwif",wifbuf);
        }
    }
    if ( bitcoin_address(addr,60,pub,33) != 0 )
    {
        jaddstr(retjson,"BTCD",addr);
        if ( showprivs != 0 )
        {
            bitcoin_priv2wif(wifbuf,privkey,188);
            jaddstr(retjson,"BTCDwif",wifbuf);
        }
    }
    if ( showprivs != 0 )
        jaddbits256(retjson,"privkey",privkey);
    return(retjson);
}

#include "../includes/iguana_apidefs.h"

STRING_ARG(SuperNET,addr2rmd160,address)
{
    uint8_t addrtype,rmd160[20]; char rmdstr[41]; cJSON *retjson;
    bitcoin_addr2rmd160(&addrtype,rmd160,address);
    init_hexbytes_noT(rmdstr,rmd160,sizeof(rmd160));
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",rmdstr);
    jaddnum(retjson,"addrtype",addrtype);
    jaddstr(retjson,"address",address);
    return(jprint(retjson,1));
}

HASH_AND_INT(SuperNET,priv2pub,privkey,addrtype)
{
    cJSON *retjson; bits256 pub; uint8_t pubkey[33]; char coinaddr[64],pubkeystr[67];
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    crypto_box_priv2pub(pub.bytes,privkey.bytes);
    jaddbits256(retjson,"curve25519",pub);
    pub = bitcoin_pubkey33(myinfo->ctx,pubkey,privkey);
    init_hexbytes_noT(pubkeystr,pubkey,33);
    jaddstr(retjson,"secp256k1",pubkeystr);
    bitcoin_address(coinaddr,addrtype,pubkey,33);
    jaddstr(retjson,"result",coinaddr);
    return(jprint(retjson,1));
}

ZERO_ARGS(SuperNET,keypair)
{
    cJSON *retjson; bits256 pubkey,privkey;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    crypto_box_keypair(pubkey.bytes,privkey.bytes);
    jaddstr(retjson,"result","generated keypair");
    jaddbits256(retjson,"privkey",privkey);
    jaddbits256(retjson,"pubkey",pubkey);
    return(jprint(retjson,1));
}

TWOHASHES_AND_STRING(SuperNET,decipher,privkey,srcpubkey,cipherstr)
{
    int32_t cipherlen=0,msglen; char *retstr; cJSON *retjson; void *ptr = 0; uint8_t *cipher,*message,space[8192];
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( cipherstr != 0 )
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
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
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
            //jaddbits256(retjson,"onetime_privkey",privkey);
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
    privkey = GENESIS_PRIVKEY;
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
    uint8_t flag = 0; uint64_t nxt64bits; bits256 check,privkey,pubkey,pinpriv,pinpub;
    char str[128],privcipher[512],*privcipherstr,*cstr; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
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
    retjson = SuperNET_rosettajson(privkey,flag);
    jaddstr(retjson,"privcipher",privcipher);
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
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_cipher(IGUANA_CALLARGS,zero,zero,message));
}

STRING_ARG(SuperNET,broadcastdecipher,message)
{
    bits256 zero;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_decipher(IGUANA_CALLARGS,zero,zero,message));
}

HASH_AND_STRING(SuperNET,multicastcipher,pubkey,message)
{
    bits256 zero;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_cipher(IGUANA_CALLARGS,zero,pubkey,message));
}

HASH_AND_STRING(SuperNET,multicastdecipher,privkey,cipherstr)
{
    bits256 zero;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
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
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(clonestr("{\"result\":\"saveconf here\"}"));
}

HASH_ARRAY_STRING(SuperNET,layer,mypriv,otherpubs,str)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(clonestr("{\"result\":\"layer encrypt here\"}"));
}

TWO_STRINGS(SuperNET,categoryhashes,category,subcategory)
{
    bits256 categoryhash,subhash; cJSON *retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    jaddstr(retjson,"result","category hashes calculated");
    jaddbits256(retjson,"categoryhash",categoryhash);
    jaddbits256(retjson,"subhash",subhash);
    return(jprint(retjson,1));
}

TWO_STRINGS(SuperNET,subscribe,category,subcategory)
{
    bits256 categoryhash,subhash;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    if ( category_subscribe(myinfo,categoryhash,subhash) != 0 )
        return(clonestr("{\"result\":\"subscribed\"}"));
    else return(clonestr("{\"error\":\"couldnt subscribe\"}"));
}

TWO_STRINGS(SuperNET,gethexmsg,category,subcategory)
{
    bits256 categoryhash,subhash; struct category_msg *m; char *hexstr; cJSON *retjson; struct category_info *cat;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    if ( (m= category_gethexmsg(myinfo,&cat,categoryhash,subhash)) != 0 )
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
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    category_posthexmsg(myinfo,categoryhash,subhash,hexmsg,tai_now(),remoteaddr);
    return(clonestr("{\"result\":\"posted message\"}"));
}

THREE_STRINGS(SuperNET,announce,category,subcategory,message)
{
    bits256 categoryhash,subhash;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    return(SuperNET_categorymulticast(myinfo,0,categoryhash,subhash,message,juint(json,"maxdelay"),juint(json,"broadcast"),juint(json,"plaintext"),json,remoteaddr));
}

THREE_STRINGS(SuperNET,survey,category,subcategory,message)
{
    bits256 categoryhash,subhash;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    return(SuperNET_categorymulticast(myinfo,1,categoryhash,subhash,message,juint(json,"maxdelay"),juint(json,"broadcast"),juint(json,"plaintext"),json,remoteaddr));
}

STRING_ARG(SuperNET,wif2priv,wif)
{
    bits256 privkey; char str[65]; uint8_t privkeytype; cJSON *retjson = cJSON_CreateObject();
    if ( bitcoin_wif2priv(&privkeytype,&privkey,wif) == sizeof(privkey) )
    {
        jaddstr(retjson,"result","success");
        jaddstr(retjson,"privkey",bits256_str(str,privkey));
        jaddnum(retjson,"type",privkeytype);
    } else jaddstr(retjson,"error","couldnt convert wif");
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,priv2wif,priv)
{
    bits256 privkey; char wifstr[65]; uint8_t wiftype; cJSON *retjson = cJSON_CreateObject();
    if ( is_hexstr(priv,0) == sizeof(bits256)*2 )
    {
        wiftype = coin != 0 ? coin->chain->wiftype : 0x80;
        decode_hex(privkey.bytes,sizeof(privkey),priv);
        if ( bitcoin_priv2wif(wifstr,privkey,wiftype) > 0 )
        {
            jaddstr(retjson,"result","success");
            jaddstr(retjson,"privkey",priv);
            jaddnum(retjson,"type",wiftype);
            jaddstr(retjson,"wif",wifstr);
        } else jaddstr(retjson,"error","couldnt convert privkey");
    } else jaddstr(retjson,"error","non 32 byte hex privkey");
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,myipaddr,ipaddr)
{
    cJSON *retjson = cJSON_CreateObject();
    if ( myinfo->ipaddr[0] == 0 )
    {
        if ( is_ipaddr(ipaddr) != 0 )
            strcpy(myinfo->ipaddr,ipaddr);
    }
    jaddstr(retjson,"result",myinfo->ipaddr);
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,setmyipaddr,ipaddr)
{
    cJSON *retjson = cJSON_CreateObject();
    if ( is_ipaddr(ipaddr) != 0 )
    {
        strcpy(myinfo->ipaddr,ipaddr);
        jaddstr(retjson,"result",myinfo->ipaddr);
    } else jaddstr(retjson,"error","illegal ipaddr");
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,utime2utc,utime)
{
    uint32_t utc = 0; cJSON *retjson = cJSON_CreateObject();
    utc = OS_conv_utime(utime);
    char str[65]; printf("utime.%s -> %u -> %s\n",utime,utc,utc_str(str,utc));
    jaddnum(retjson,"result",utc);
    return(jprint(retjson,1));
}

INT_ARG(SuperNET,utc2utime,utc)
{
    char str[65]; cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",utc_str(str,utc));
    return(jprint(retjson,1));
}

ZERO_ARGS(SuperNET,logout)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    memset(myinfo->persistent_priv.bytes,0,sizeof(myinfo->persistent_priv));
    memset(myinfo->myaddr.persistent.bytes,0,sizeof(myinfo->myaddr.persistent));
    memset(myinfo->handle,0,sizeof(myinfo->handle));
    memset(myinfo->myaddr.NXTADDR,0,sizeof(myinfo->myaddr.NXTADDR));
    myinfo->myaddr.nxt64bits = 0;
    myinfo->expiration = 0;
    return(clonestr("{\"result\":\"logged out\"}"));
}

ZERO_ARGS(SuperNET,activehandle)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = SuperNET_rosettajson(myinfo->persistent_priv,0);
    jaddstr(retjson,"result","success");
    jaddstr(retjson,"handle",myinfo->handle);
    jaddbits256(retjson,"persistent",myinfo->myaddr.persistent);
    if ( myinfo->expiration != 0 )
    {
        jaddstr(retjson,"status","unlocked");
        jaddnum(retjson,"duration",myinfo->expiration - time(NULL));
    } else jaddstr(retjson,"status","locked");
    SuperNET_MYINFOadd(myinfo);
    return(jprint(retjson,1));
}

struct supernet_info *SuperNET_accountfind(cJSON *json)
{
    int32_t num; char *decryptstr; struct supernet_info M,*myinfo; struct iguana_info *coin = 0;
    char *password,*permanentfile,*passphrase,*remoteaddr,*perspriv;
    myinfo = 0;
    if ( (password= jstr(json,"password")) == 0 )
        password = "";
    if ( (permanentfile= jstr(json,"permanentfile")) == 0 )
        permanentfile = "";
    if ( (passphrase= jstr(json,"passphrase")) == 0 )
        passphrase = "";
    remoteaddr = jstr(json,"remoteaddr");
    if ( (passphrase == 0 || passphrase[0] == 0) && (decryptstr= SuperNET_decryptjson(IGUANA_CALLARGS,password,permanentfile)) != 0 )
    {
        if ( (json= cJSON_Parse(decryptstr)) != 0 )
        {
            memset(&M,0,sizeof(M));
            if ( (perspriv= jstr(json,"persistent_priv")) != 0 && strlen(perspriv) == sizeof(bits256)*2 )
            {
                M.persistent_priv = bits256_conv(perspriv);
                SuperNET_setkeys(&M,0,0,0);
                if ( (myinfo = SuperNET_MYINFOfind(&num,M.myaddr.persistent)) != 0 )
                {
                    //printf("found account.(%s) %s %llu\n",myinfo!=0?myinfo->handle:"",M.myaddr.NXTADDR,(long long)M.myaddr.nxt64bits);
                    return(myinfo);
                }
            }
            else if ( (passphrase= jstr(json,"result")) != 0 || (passphrase= jstr(json,"passphrase")) != 0 )
            {
                SuperNET_setkeys(&M,passphrase,(int32_t)strlen(passphrase),1);
                if ( (myinfo= SuperNET_MYINFOfind(&num,M.myaddr.persistent)) != 0 )
                {
                    //printf("found account.(%s) %s %llu\n",myinfo!=0?myinfo->handle:"",M.myaddr.NXTADDR,(long long)M.myaddr.nxt64bits);
                    return(myinfo);
                }
            } else printf("no passphrase in (%s)\n",jprint(json,0));
            free_json(json);
        } else printf("cant parse.(%s)\n",decryptstr);
        free(decryptstr);
    }
    return(SuperNET_MYINFO(0));
}

FOUR_STRINGS(SuperNET,login,handle,password,permanentfile,passphrase)
{
    char *str,*decryptstr = 0; cJSON *argjson,*item,*walletitem;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( handle != 0 && handle[0] != 0 )
        safecopy(myinfo->handle,handle,sizeof(myinfo->handle));
    else memset(myinfo->handle,0,sizeof(myinfo->handle));
    if ( password == 0 || password[0] == 0 )
        password = passphrase;
    /*if ( password != 0 && password[0] != 0 )
     safecopy(myinfo->secret,password,sizeof(myinfo->secret));
     else if ( passphrase != 0 && passphrase[0] != 0 )
     safecopy(myinfo->secret,passphrase,sizeof(myinfo->secret));*/
    if ( permanentfile != 0 )
        safecopy(myinfo->permanentfile,permanentfile,sizeof(myinfo->permanentfile));
    if ( (decryptstr= SuperNET_decryptjson(IGUANA_CALLARGS,password,myinfo->permanentfile)) != 0 )
    {
        if ( (argjson= cJSON_Parse(decryptstr)) != 0 )
        {
            if ( jobj(argjson,"error") == 0 )
            {
                //printf("decrypted.(%s) exp.%u pass.(%s)\n",decryptstr,myinfo->expiration,password);
                if ( myinfo->decryptstr != 0 )
                    free(myinfo->decryptstr);
                myinfo->decryptstr = decryptstr;
                if ( (passphrase= jstr(argjson,"passphrase")) != 0 )
                {
                    SuperNET_setkeys(myinfo,passphrase,(int32_t)strlen(passphrase),1);
                    free_json(argjson);
                    myinfo->expiration = (uint32_t)(time(NULL) + 3600);
                    return(SuperNET_activehandle(IGUANA_CALLARGS));
                }
                else
                {
                    free_json(argjson);
                    return(clonestr("{\"error\":\"cant find passphrase in decrypted json\"}"));
                }
            } else free_json(argjson);
        }
        else
        {
            free(decryptstr);
            return(clonestr("{\"error\":\"cant parse decrypted json\"}"));
        }
    }
    if ( passphrase != 0 && passphrase[0] != 0 )
    {
        SuperNET_setkeys(myinfo,passphrase,(int32_t)strlen(passphrase),1);
        if ( myinfo->decryptstr != 0 && (argjson= cJSON_Parse(myinfo->decryptstr)) != 0 )
        {
            if ( jobj(argjson,"passphrase") != 0 )
                jdelete(argjson,"passphrase");
            if ( jobj(argjson,"error") != 0 )
                jdelete(argjson,"error");
        }
        else
        {
            char rmd160str[41],str[65]; uint8_t rmd160[20],pubkey33[33];
            item = cJSON_CreateObject();
            bitcoin_pubkey33(myinfo->ctx,pubkey33,myinfo->persistent_priv);
            calc_rmd160_sha256(rmd160,pubkey33,33);
            init_hexbytes_noT(rmd160str,rmd160,20);
            jaddstr(item,rmd160str,bits256_str(str,myinfo->persistent_priv));
            walletitem = cJSON_CreateObject();
            jadd(walletitem,"default",item);
            argjson = cJSON_CreateObject();
            jadd(argjson,"wallet",walletitem);
            myinfo->dirty = (uint32_t)time(NULL);
        }
        jaddstr(argjson,"passphrase",passphrase);
        if ( (str= SuperNET_encryptjson(myinfo,coin,argjson,remoteaddr,password,myinfo->permanentfile,"")) != 0 )
            free(str);
        myinfo->expiration = (uint32_t)(time(NULL) + 3600);
        return(SuperNET_activehandle(IGUANA_CALLARGS));
    } else return(clonestr("{\"error\":\"need passphrase\"}"));
    printf("logged into (%s) %s %s\n",myinfo->myaddr.NXTADDR,myinfo->myaddr.BTC,myinfo->myaddr.BTCD);
    return(SuperNET_activehandle(IGUANA_CALLARGS));
}

#include "../includes/iguana_apiundefs.h"
