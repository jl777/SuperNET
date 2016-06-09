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

#ifdef oldway
int32_t SuperNET_hexmsgfind(struct supernet_info *myinfo,bits256 category,bits256 subhash,char *hexmsg,int32_t addflag)
{
    static int lastpurge; static uint64_t Packetcache[1024];
    bits256 packethash; int32_t i,datalen;
    datalen = (int32_t)strlen(hexmsg) + 1;
    vcalc_sha256(0,packethash.bytes,(void *)hexmsg,datalen);
    if ( bits256_nonz(category) == 0 )
        category = GENESIS_PUBKEY;
    if ( bits256_nonz(subhash) == 0 )
        subhash = GENESIS_PUBKEY;
    packethash = curve25519(category,packethash);
    //printf("addflag.%d packethash.%llx dest.%llx\n",addflag,(long long)packethash.txid,(long long)category.txid);
    for (i=0; i<sizeof(Packetcache)/sizeof(*Packetcache); i++)
    {
        if ( Packetcache[i] == 0 )
        {
            if ( addflag != 0 )
            {
                Packetcache[i] = packethash.txid;
                //printf("add.%llx packetcache(%s) -> slot[%d]\n",(long long)packethash.txid,hexmsg,i);
            }
            break;
        }
        else if ( Packetcache[i] == packethash.txid )
        {
            //printf("SuperNET_DHTsend reject duplicate packet.%llx\n",(long long)packethash.txid);
            return(i);
        }
    }
    if ( i == sizeof(Packetcache)/sizeof(*Packetcache) )
    {
        if ( addflag != 0 )
        {
            printf("purge slot[%d]\n",lastpurge);
            Packetcache[lastpurge++] = packethash.txid;
            if ( lastpurge >= sizeof(Packetcache)/sizeof(*Packetcache) )
                lastpurge = 0;
        }
    }
    return(-1);
}

void SuperNET_hexmsgadd(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash,char *hexmsg,struct tai now,char *remoteaddr)
{
    char str[512],str2[65];
    str[0] = 0;
    if ( memcmp(categoryhash.bytes,GENESIS_PUBKEY.bytes,sizeof(categoryhash)) == 0 )
        strcpy(str,"BROADCAST.");
    else bits256_str(str+strlen(str),categoryhash);
    if ( memcmp(subhash.bytes,GENESIS_PUBKEY.bytes,sizeof(subhash)) != 0 )
    {
        bits256_str(str2,subhash);
        strcat(str,str2);
    }
    category_posthexmsg(myinfo,categoryhash,subhash,hexmsg,now,remoteaddr);
    //printf("HEXMSG.(%s).%llx -> %s\n",hexmsg,(long long)subhash.txid,str);
}

void SuperNET_hexmsgprocess(struct supernet_info *myinfo,cJSON *retjson,cJSON *json,char *hexmsg,char *remoteaddr)
{
    int32_t len,flag=0; char *str; uint8_t _buf[8192],*buf = _buf; bits256 categoryhash,subhash; struct private_chain *cat;
    if ( hexmsg != 0 )
    {
        len = (int32_t)strlen(hexmsg);
        if ( is_hexstr(hexmsg,len) > 0 )
        {
            len >>= 1;
            if ( len > sizeof(_buf) )
                buf = malloc(len);
            decode_hex(buf,len,hexmsg);
            //printf("hex.(%s) -> (%s)\n",hexmsg,buf);
            categoryhash = jbits256(json,"categoryhash");
            subhash = jbits256(json,"categoryhash");
            if ( bits256_nonz(subhash) == 0 )
                subhash = GENESIS_PUBKEY;
            if ( (cat= category_find(categoryhash,subhash)) != 0 )
            {
                if ( cat->processfunc != 0 )
                {
                    if ( (str= (*cat->processfunc)(myinfo,cat,buf,len,remoteaddr)) != 0 )
                    {
                        if ( retjson != 0 )
                            jaddstr(retjson,"processfunc",str);
                        else free(str);
                    }
                    flag = 1;
                    //printf("PROCESSFUNC\n");
                }
            }
            if ( flag == 0 )
            {
                printf("no processfunc, posthexmsg\n");
                category_posthexmsg(myinfo,categoryhash,jbits256(json,"subhash"),hexmsg,tai_now(),remoteaddr);
            }
            //char str[65]; printf("HEXPROCESS.(%s) -> %s\n",hexmsg,bits256_str(str,categoryhash));
            if ( buf != _buf )
                free(buf);
        }
    }
}

int32_t category_default_blockhash(struct category_chain *catchain,void *blockhashp,void *data,int32_t datalen)
{
    bits256 hash;
    vcalc_sha256(0,hash.bytes,data,datalen);
    vcalc_sha256(0,blockhashp,hash.bytes,sizeof(hash));
    return(sizeof(*blockhashp));
}

bits256 category_default_stake(struct category_chain *catchain,void *addr,int32_t addrlen)
{
    bits256 stake;
    memset(stake.bytes,0,sizeof(stake));
    stake.txid = ((uint64_t)1 << 63);
    return(stake);
}

bits256 catgory_default_hit(struct category_chain *catchain,int32_t height,void *prevgenerator,void *addr,void *blockhashp)
{
    bits256 hash; bits256 rawhit,hit;
    memset(rawhit.bytes,0,sizeof(rawhit));
    memset(hit.bytes,0,sizeof(hit));
    vcalc_sha256cat(hash.bytes,prevgenerator,catchain->addrlen,addr,catchain->addrlen);
    hit = (*catchain->stake_func)(catchain,addr,catchain->addrlen);
    rawhit.txid = hash.txid % ((uint64_t)1 << 42);
    if ( rawhit.txid != 0 )
        hit.txid /= rawhit.txid;
    return(hit);
}

#define category_default_heaviest() (*catchain->default_func)(catchain,'H',0,0,0,0,zero)
#define category_default_latest() (*catchain->default_func)(catchain,'L',0,0,0,0,zero)
#define category_default_setheaviest(height,blockhashp,heaviest) (*catchain->default_func)(catchain,'S',height,0,0,blockhashp,zero)
#define category_default_weight(height) (*catchain->default_func)(catchain,'W',height,0,0,0,zero)
#define category_default_blockfind(height) (*catchain->default_func)(catchain,'B',height,0,0,0,zero)

bits256 category_default_func(struct category_chain *catchain,int32_t func,int32_t height,void *prevgenerator,void *addr,void *blockhashp,bits256 heaviest)
{
    static const bits256 zero;
    if ( catchain->hashlen != sizeof(bits256) || catchain->addrlen != sizeof(bits256) )
    {
        printf("unsupported hashlen.%d or addrlen.%d\n",catchain->hashlen,catchain->addrlen);
        return(zero);
    }
    if ( height > catchain->maxblocknum + (func == 'S') )
    {
        printf("error func.%c setting heaviest. skipped %d -> %d?\n",func,catchain->maxblocknum,height);
        return(catchain->category_hwm);
    }
    if ( func == 'H' )
        return(catchain->category_hwm);
    else if ( func == 'L' )
    {
        if ( catchain->maxblocknum < 0 )
            return(catchain->genesishash);
        else return(catchain->blocks[catchain->maxblocknum]);
    }
    else if ( func == 'S' )
    {
        catchain->category_hwm = heaviest;
        if ( height > catchain->maxblocknum )
        {
            catchain->weights = realloc(catchain->weights,(catchain->maxblocknum+1) * sizeof(*catchain->weights));
            catchain->blocks = realloc(catchain->blocks,(catchain->maxblocknum+1) * sizeof(*catchain->blocks));
        }
        catchain->maxblocknum = height;
        catchain->weights[height] = heaviest;
        if ( blockhashp != 0 )
            memcpy(&catchain->blocks[height],blockhashp,sizeof(catchain->blocks[height]));
    }
    else if ( func == 'B' )
    {
        if ( height <= catchain->maxblocknum )
            return(catchain->blocks[height]);
        else
        {
            printf("error: illegal height.%d vs max.%d\n",height,catchain->maxblocknum);
            return(zero);
        }
    }
    else if ( func == 'W' )
    {
        if ( height >= 0 && height < catchain->maxblocknum )
            return(catchain->weights[height]);
        else printf("error getting weight for height.%d vs maxblocknum.%d\n",height,catchain->maxblocknum);
    }
    return(catchain->category_hwm);
}

int32_t category_default_ishwm(struct category_chain *catchain,int32_t prevheight,void *prevblockhashp,void *blockhashp,void *prevgenerator,void *addr)
{
    bits256 checkhash,prevwt,oldhit,hit,heaviest; static const bits256 zero;
    checkhash = category_default_blockfind(prevheight);
    if ( memcmp(checkhash.bytes,prevblockhashp,catchain->hashlen) == 0 )
    {
        heaviest = category_default_heaviest();
        prevwt = category_default_weight(prevheight);
        oldhit = category_default_weight(prevheight+1);
        hit = (*catchain->hit_func)(catchain,prevheight+1,prevgenerator,addr,blockhashp);
        if ( hit.txid > oldhit.txid && prevwt.txid+hit.txid > heaviest.txid )
        {
            heaviest.txid = (prevwt.txid + hit.txid);
            category_default_setheaviest(prevheight+1,blockhashp,heaviest);
            return(prevheight+1);
        }
        
    } else return(-2);
    return(-1);
}

int32_t category_default_payment(struct category_chain *catchain,void *src,void *dest,uint64_t amount)
{
    //uint32_t srcind=0,destind=0;
    // catchain->balances[destind] += amount;
    // catchain->balances[srcind] -= amount;
    return(0);
}

struct category_chain *category_chain_functions(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash,int32_t hashlen,int32_t addrlen,void *hash_func,void *stake_func,void *hit_func,void *default_func,void *ishwm_func,void *payment_func)
{
    struct private_chain *cat; struct category_chain *catchain = calloc(1,sizeof(*catchain));
    if ( (cat= category_find(categoryhash,subhash)) != 0 )
    {
        catchain->maxblocknum = -1;
        catchain->myinfo = myinfo, catchain->subinfo = cat->info;
        if ( bits256_cmp(subhash,GENESIS_PUBKEY) == 0 )
            catchain->categoryinfo = cat->info, catchain->genesishash = categoryhash;
        else catchain->categoryinfo = category_find(categoryhash,GENESIS_PUBKEY), catchain->genesishash = subhash;
        if ( catchain->myinfo == 0 || catchain->categoryinfo || catchain->subinfo )
        {
            printf("error with catchain pointers\n");
            return(0);
        }
        if ( (catchain->addrlen= addrlen) <= 0 || (catchain->hashlen= hashlen) <= 0 )
        {
            printf("error with catchain lens.%d %d\n",addrlen,hashlen);
            return(0);
        }
        if ( (catchain->blockhash_func= hash_func) == 0 || (catchain->stake_func= stake_func) == 0 || (catchain->hit_func= hit_func) == 0 || (catchain->default_func= default_func) == 0 || (catchain->ishwm_func= ishwm_func) == 0 || (catchain->payment_func= payment_func) == 0 )
        {
            if ( addrlen == sizeof(bits256) && hashlen == sizeof(bits256) )
            {
                catchain->blockhash_func = category_default_blockhash;
                catchain->stake_func = category_default_stake;
                catchain->hit_func = catgory_default_hit;
                catchain->default_func = category_default_func;
                catchain->ishwm_func = category_default_ishwm;
                catchain->payment_func = category_default_payment;
            }
            else
            {
                printf("no category chain functions and addrlen.%d hashlen.%d not 32\n",addrlen,hashlen);
                return(0);
            }
        }
        //cat->catchain = catchain;
        return(catchain);
    }
    return(0);
}

struct crypto777_msghdr *crypto777_msgcreate(struct supernet_info *myinfo,struct crypto777_msghdr *msg,int32_t datalen)
{
    bits256 otherpubkey; uint64_t signerbits; uint32_t timestamp; uint8_t buf[sizeof(msg->sig)],*data;
    memset(&msg->sig,0,sizeof(msg->sig));
    datalen += (int32_t)(sizeof(*msg) - sizeof(msg->sig));
    data = (void *)((long)msg + sizeof(msg->sig));
    otherpubkey = acct777_msgpubkey(data,datalen);
    timestamp = (uint32_t)time(NULL);
    acct777_sign(&msg->sig,myinfo->privkey,otherpubkey,timestamp,data,datalen);
    if ( (signerbits= acct777_validate(&msg->sig,acct777_msgprivkey(data,datalen),msg->sig.pubkey)) != 0 )
    {
        //int32_t i;
        //char str[65],str2[65];
        //for (i=0; i<datalen; i++)
        //    printf("%02x",data[i]);
        //printf(">>>>>>>>>>>>>>>> validated [%ld] len.%d (%s + %s)\n",(long)data-(long)msg,datalen,bits256_str(str,acct777_msgprivkey(data,datalen)),bits256_str(str2,msg->sig.pubkey));
        memset(buf,0,sizeof(buf));
        acct777_rwsig(1,buf,&msg->sig);
        memcpy(&msg->sig,buf,sizeof(buf));
        return(msg);
    } else printf("error validating crypto777_msgcreate msg\n");
    return(0);
}

void crypto777_catchain(struct supernet_info *myinfo,struct private_chain *cat,bits256 *prevhashp,bits256 *btchashp)
{
    *btchashp = myinfo->BTCmarkerhash;
    //*prevhashp = cat->catchain->hwmhash;
}

char *crypto777_sendmsg(struct supernet_info *myinfo,bits256 category,bits256 subhash,uint8_t *data,int32_t datalen,int32_t hops,char cmdstr[8])
{
    char *hexstr,*retstr; int32_t i; struct crypto777_msghdr *msg; bits256 prevhash,btchash; struct private_chain *cat;
    msg = calloc(1,datalen + sizeof(*msg));
    for (i=0; i<sizeof(msg->cmd); i++)
        if ( (msg->cmd[i]= cmdstr[i]) == 0 )
            break;
    cat = private_chain(category,subhash);
    crypto777_catchain(myinfo,cat,&prevhash,&btchash);
    iguana_rwbignum(1,msg->prevhash.bytes,sizeof(bits256),prevhash.bytes);
    iguana_rwbignum(1,msg->btchash.bytes,sizeof(bits256),btchash.bytes);
    memcpy(msg->serialized,data,datalen);
    if ( crypto777_msgcreate(myinfo,msg,datalen) != 0 )
    {
        printf(">>>>>>>>>>>> crypto777_send.(%s) datalen.%d allocsize.%d crc.%x\n",cmdstr,datalen,msg->sig.allocsize,calc_crc32(0,(void *)((long)msg + 8),datalen-8));
        hexstr = malloc(msg->sig.allocsize*2 + 1);
        init_hexbytes_noT(hexstr,(uint8_t *)msg,msg->sig.allocsize);
        retstr = SuperNET_categorymulticast(myinfo,0,category,subhash,hexstr,0,hops,1,0,0);
        free(hexstr), free(msg);
        return(retstr);
    }
    else
    {
        free(msg);
        printf("cant crypto777 msgcreate datalen.%d\n",datalen);
        return(clonestr("{\"error\":\"couldnt create crypto777 message\"}"));
    }
}

char *crypto777_hexmsg(struct supernet_info *myinfo,void *ptr,int32_t len,char *remoteaddr)
{
    struct crypto777_msghdr *msg = ptr; int32_t slen,datalen,newlen,flag = 0; bits256 prevhash,btchash;
    uint8_t *serdata; uint64_t signerbits; uint8_t tmp[sizeof(msg->sig)]; cJSON *argjson = 0;
    datalen = len  - (int32_t)sizeof(msg->sig);
    serdata = (void *)((long)msg + sizeof(msg->sig));
    acct777_rwsig(0,(void *)&msg->sig,(void *)tmp);
    memcpy(&msg->sig,tmp,sizeof(msg->sig));
    /*if ( remoteaddr != 0 && remoteaddr[0] == 0 && strcmp("127.0.0.1",remoteaddr) == 0 && ((uint8_t *)msg)[len-1] == 0 && (argjson= cJSON_Parse((char *)msg)) != 0 )
    {
        printf("string crypto777_hexmsg RESULT.(%s)\n",jprint(argjson,0));
        free_json(argjson);
        return(clonestr("{\"error\":\"string base packets deprecated\"}"));
    }
    else*/ if ( (signerbits= acct777_validate(&msg->sig,acct777_msgprivkey(serdata,datalen),msg->sig.pubkey)) != 0 )
    {
        flag++;
        iguana_rwbignum(0,msg->prevhash.bytes,sizeof(bits256),prevhash.bytes);
        iguana_rwbignum(0,msg->btchash.bytes,sizeof(bits256),btchash.bytes);
        printf("crypto777_hexmsg <<<<<<<<<<<<< sigsize.%d VALIDATED [%ld] len.%d t%u allocsize.%d (%s) [%d]\n",(int32_t)sizeof(msg->sig),(long)serdata-(long)msg,datalen,msg->sig.timestamp,msg->sig.allocsize,(char *)msg->serialized,serdata[datalen-1]);
        newlen = (int32_t)(msg->sig.allocsize - ((long)msg->serialized - (long)msg));
        serdata = msg->serialized;
        if ( (argjson= cJSON_Parse((char *)serdata)) != 0 )
        {
            slen = (int32_t)strlen((char *)serdata) + 1;
            serdata = &serdata[slen];
            newlen -= slen;
            free_json(argjson);
        }
    }
    return(clonestr("{\"result\":\"test packet\"}"));
}
#endif

/*
 Consensus rules: 
 0. Valid burn protocol or new issuance with small fee to crypto777 account -> OP_RETURN on BTCD with txid of payment/burn
 Ti boundary - Balances reconciled and signed by issuer or super majority vote. Only amounts marked as frozen eligible for atomic swaps.
 tx via p2p, signed payment to dest acct, based on balance. no outputs to double spend
 payment valid during Ti and Ti+1
 atomic cross chain: both sides freeze trade amount, wait for this to be confirmed in BTC OP_RETURN, then a joint swap tx is signed by both and submitted to both chains
 
 valid tx must be accepted and sig added with Ti slippage. It is valid if signed, and balance is available.
 
 When Ti boundary changes, all online nodes reconcile the submitted tx to make sure all are confirmed and balances updated. Special tx like freezing, atomics, etc.
 
Top PoS account publishes balance changes and majority stake approves. Next trade period starts at Ti+2
 
 Split into odd/even offset periods to allow nonstop tx
 
 1. all nodes must ntp and all tx must be timestamped within 50 seconds in the past and cant be more than 10 seconds from the future.
 2. tx spends cannot exceed available balance/2 as of prior Ti.
 2. all tx must refer to the latest BTC.Ti and BTCD.Ti and BTC.RTblock. any tx received that has older BTC.Ti is rejected.
 3.
*/
