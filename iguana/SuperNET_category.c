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

bits256 calc_categoryhashes(bits256 *subhashp,char *category,char *subcategory)
{
    bits256 categoryhash;
    if ( category == 0 || category[0] == 0 || strcmp(category,"broadcast") == 0 )
        categoryhash = GENESIS_PUBKEY;
    else vcalc_sha256(0,categoryhash.bytes,(uint8_t *)category,(int32_t)strlen(category));
    if ( subhashp != 0 )
    {
        if ( subcategory == 0 || subcategory[0] == 0 || strcmp(subcategory,"broadcast") == 0 )
            *subhashp = GENESIS_PUBKEY;
        else vcalc_sha256(0,subhashp->bytes,(uint8_t *)subcategory,(int32_t)strlen(subcategory));
    }
    return(categoryhash);
}

struct category_info *category_find(bits256 categoryhash,bits256 subhash)
{
    struct category_info *cat=0,*sub = 0;
    HASH_FIND(hh,Categories,categoryhash.bytes,sizeof(categoryhash),cat);
    if ( cat != 0 )
    {
        if ( bits256_nonz(subhash) > 0 && memcmp(GENESIS_PUBKEY.bytes,subhash.bytes,sizeof(subhash)) != 0 )
        {
            HASH_FIND(hh,cat->sub,subhash.bytes,sizeof(subhash),sub);
            if ( sub != 0 )
                return(sub);
        }
        return(cat);
    } //else printf("category_find.(%s) not found\n",bits256_str(str,categoryhash));//, getchar();
    return(0);
}

queue_t *category_Q(bits256 categoryhash,bits256 subhash)
{
    struct category_info *cat;
    if ( (cat= category_find(categoryhash,subhash)) != 0 )
        return(&cat->Q);
    else return(0);
}

void *category_info(bits256 categoryhash,bits256 subhash)
{
    struct category_info *cat;
    if ( (cat= category_find(categoryhash,subhash)) != 0 )
        return(cat->info);
    else return(0);
}

void *category_infoset(bits256 categoryhash,bits256 subhash,void *info)
{
    struct category_info *cat;
    if ( (cat= category_find(categoryhash,subhash)) != 0 )
    {
        cat->info = info;
        return(info);
    }
    return(0);
}

struct category_info *category_processfunc(bits256 categoryhash,bits256 subhash,char *(*process_func)(struct supernet_info *myinfo,void *data,int32_t datalen,char *remoteaddr))
{
    struct category_info *cat;
    if ( (cat= category_find(categoryhash,subhash)) != 0 )
    {
        cat->processfunc = process_func;
        return(cat);
    }
    return(0);
}

int32_t category_default_blockhash(struct category_chain *cchain,void *blockhashp,void *data,int32_t datalen)
{
    bits256 hash;
    vcalc_sha256(0,hash.bytes,data,datalen);
    vcalc_sha256(0,blockhashp,hash.bytes,sizeof(hash));
    return(sizeof(*blockhashp));
}

bits256 category_default_stake(struct category_chain *cchain,void *addr,int32_t addrlen)
{
    bits256 stake;
    memset(stake.bytes,0,sizeof(stake));
    stake.txid = ((uint64_t)1 << 63);
    return(stake);
}

bits256 catgory_default_hit(struct category_chain *cchain,int32_t height,void *prevgenerator,void *addr,void *blockhashp)
{
    bits256 hash; bits256 rawhit,hit;
    memset(rawhit.bytes,0,sizeof(rawhit));
    memset(hit.bytes,0,sizeof(hit));
    vcalc_sha256cat(hash.bytes,prevgenerator,cchain->addrlen,addr,cchain->addrlen);
    hit = (*cchain->stake_func)(cchain,addr,cchain->addrlen);
    rawhit.txid = hash.txid % ((uint64_t)1 << 42);
    if ( rawhit.txid != 0 )
        hit.txid /= rawhit.txid;
    return(hit);
}

#define category_default_heaviest() (*cchain->default_func)(cchain,'H',0,0,0,0,zero)
#define category_default_latest() (*cchain->default_func)(cchain,'L',0,0,0,0,zero)
#define category_default_setheaviest(height,blockhashp,heaviest) (*cchain->default_func)(cchain,'S',height,0,0,blockhashp,zero)
#define category_default_weight(height) (*cchain->default_func)(cchain,'W',height,0,0,0,zero)
#define category_default_blockfind(height) (*cchain->default_func)(cchain,'B',height,0,0,0,zero)

bits256 category_default_func(struct category_chain *cchain,int32_t func,int32_t height,void *prevgenerator,void *addr,void *blockhashp,bits256 heaviest)
{
    static bits256 zero;
    if ( cchain->hashlen != sizeof(bits256) || cchain->addrlen != sizeof(bits256) )
    {
        printf("unsupported hashlen.%d or addrlen.%d\n",cchain->hashlen,cchain->addrlen);
        return(zero);
    }
    if ( height > cchain->maxblocknum + (func == 'S') )
    {
        printf("error func.%c setting heaviest. skipped %d -> %d?\n",func,cchain->maxblocknum,height);
        return(cchain->category_hwm);
    }
    if ( func == 'H' )
        return(cchain->category_hwm);
    else if ( func == 'L' )
    {
        if ( cchain->maxblocknum < 0 )
            return(cchain->cchainhash);
        else return(cchain->blocks[cchain->maxblocknum]);
    }
    else if ( func == 'S' )
    {
        cchain->category_hwm = heaviest;
        if ( height > cchain->maxblocknum )
        {
            cchain->weights = realloc(cchain->weights,(cchain->maxblocknum+1) * sizeof(*cchain->weights));
            cchain->blocks = realloc(cchain->blocks,(cchain->maxblocknum+1) * sizeof(*cchain->blocks));
        }
        cchain->maxblocknum = height;
        cchain->weights[height] = heaviest;
        if ( blockhashp != 0 )
            memcpy(&cchain->blocks[height],blockhashp,sizeof(cchain->blocks[height]));
    }
    else if ( func == 'B' )
    {
        if ( height <= cchain->maxblocknum )
            return(cchain->blocks[height]);
        else
        {
            printf("error: illegal height.%d vs max.%d\n",height,cchain->maxblocknum);
            return(zero);
        }
    }
    else if ( func == 'W' )
    {
        if ( height >= 0 && height < cchain->maxblocknum )
            return(cchain->weights[height]);
        else printf("error getting weight for height.%d vs maxblocknum.%d\n",height,cchain->maxblocknum);
    }
    return(cchain->category_hwm);
}

int32_t category_default_ishwm(struct category_chain *cchain,int32_t prevheight,void *prevblockhashp,void *blockhashp,void *prevgenerator,void *addr)
{
    bits256 checkhash,prevwt,oldhit,hit,heaviest; static bits256 zero;
    checkhash = category_default_blockfind(prevheight);
    if ( memcmp(checkhash.bytes,prevblockhashp,cchain->hashlen) == 0 )
    {
        heaviest = category_default_heaviest();
        prevwt = category_default_weight(prevheight);
        oldhit = category_default_weight(prevheight+1);
        hit = (*cchain->hit_func)(cchain,prevheight+1,prevgenerator,addr,blockhashp);
        if ( hit.txid > oldhit.txid && prevwt.txid+hit.txid > heaviest.txid )
        {
            heaviest.txid = (prevwt.txid + hit.txid);
            category_default_setheaviest(prevheight+1,blockhashp,heaviest);
            return(prevheight+1);
        }
        
    } else return(-2);
    return(-1);
}

struct category_chain *category_chain_functions(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash,int32_t hashlen,int32_t addrlen,void *hash_func,void *stake_func,void *hit_func,void *default_func)
{
    struct category_info *cat; struct category_chain *cchain = calloc(1,sizeof(*cchain));
    if ( (cat= category_find(categoryhash,subhash)) != 0 )
    {
        cchain->maxblocknum = -1;
        cchain->myinfo = myinfo, cchain->subinfo = cat->info;
        if ( bits256_cmp(subhash,GENESIS_PUBKEY) == 0 )
            cchain->categoryinfo = cat->info, cchain->cchainhash = categoryhash;
        else cchain->categoryinfo = category_find(categoryhash,GENESIS_PUBKEY), cchain->cchainhash = subhash;
        if ( cchain->myinfo == 0 || cchain->categoryinfo || cchain->subinfo )
        {
            printf("error with cchain pointers\n");
            return(0);
        }
        if ( (cchain->addrlen= addrlen) <= 0 || (cchain->hashlen= hashlen) <= 0 )
        {
            printf("error with cchain lens.%d %d\n",addrlen,hashlen);
            return(0);
        }
        if ( (cchain->blockhash_func= hash_func) == 0 || (cchain->stake_func= stake_func) == 0 || (cchain->hit_func= hit_func) == 0 || (cchain->default_func= default_func) == 0 )
        {
            if ( addrlen == sizeof(bits256) && hashlen == sizeof(bits256) )
            {
                cchain->blockhash_func = category_default_blockhash;
                cchain->stake_func = category_default_stake;
                cchain->hit_func = catgory_default_hit;
                cchain->default_func = category_default_func;
            }
            else
            {
                printf("no category chain functions and addrlen.%d hashlen.%d not 32\n",addrlen,hashlen);
                return(0);
            }
        }
        cat->cchain = cchain;
        return(cchain);
    }
    return(0);
}

struct category_msg *category_gethexmsg(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash)
{
    queue_t *Q;
    //char str[65]; printf("getmsg.(%s) %llx\n",bits256_str(str,categoryhash),(long long)subhash.txid);
    if ( (Q= category_Q(categoryhash,subhash)) != 0 )
        return(queue_dequeue(Q,0));
    else return(0);
}

void category_posthexmsg(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash,char *hexmsg,struct tai now,char *remoteaddr)
{
    int32_t len; struct category_msg *m; queue_t *Q = 0;
    if ( (Q= category_Q(categoryhash,subhash)) != 0 )
    {
        len = (int32_t)strlen(hexmsg) >> 1;
        m = calloc(1,sizeof(*m) + len);
        m->t = now, m->len = len;
        if ( remoteaddr != 0 && remoteaddr[0] != 0 )
            m->remoteipbits = calc_ipbits(remoteaddr);
        decode_hex(m->msg,m->len,hexmsg);
        queue_enqueue("categoryQ",Q,&m->DL,0);
        //char str[65]; printf("POST HEXMSG.(%s) -> %s.%llx len.%d\n",hexmsg,bits256_str(str,categoryhash),(long long)subhash.txid,m->len);
        return;
    }
   // char str[65]; printf("no subscription for category.(%s) %llx\n",bits256_str(str,categoryhash),(long long)subhash.txid);
}

void *category_subscribe(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash)
{
    struct category_info *cat,*sub; bits256 hash;
    HASH_FIND(hh,Categories,categoryhash.bytes,sizeof(categoryhash),cat);
    if ( cat == 0 )
    {
        cat = mycalloc('c',1,sizeof(*cat));
        cat->hash = hash = categoryhash;
        char str[65]; printf("ADD cat.(%s)\n",bits256_str(str,categoryhash));
        HASH_ADD(hh,Categories,hash,sizeof(hash),cat);
    }
    if ( bits256_nonz(subhash) > 0 && memcmp(GENESIS_PUBKEY.bytes,subhash.bytes,sizeof(subhash)) != 0 && cat != 0 )
    {
        HASH_FIND(hh,cat->sub,subhash.bytes,sizeof(subhash),sub);
        if ( sub == 0 )
        {
            sub = mycalloc('c',1,sizeof(*sub));
            sub->hash = hash = subhash;
            char str[65],str2[65]; printf("subadd.(%s) -> (%s)\n",bits256_str(str,hash),bits256_str(str2,categoryhash));
            HASH_ADD(hh,cat->sub,hash,sizeof(hash),sub);
        }
    }
    return(cat);
}

int32_t category_peer(struct supernet_info *myinfo,struct iguana_peer *addr,bits256 category,bits256 subhash)
{
    return(1);
}

int32_t category_plaintext(struct supernet_info *myinfo,bits256 category,bits256 subhash,int32_t plaintext)
{
    return(plaintext);
}

int32_t category_maxdelay(struct supernet_info *myinfo,bits256 category,bits256 subhash,int32_t maxdelay)
{
    return(maxdelay);
}

int32_t category_broadcastflag(struct supernet_info *myinfo,bits256 category,bits256 subhash,int32_t broadcastflag)
{
    if ( broadcastflag < 1 )
        broadcastflag = 1;
    else if ( broadcastflag > SUPERNET_MAXHOPS )
        broadcastflag = SUPERNET_MAXHOPS;
    return(broadcastflag);
}

char *SuperNET_categorymulticast(struct supernet_info *myinfo,int32_t surveyflag,bits256 categoryhash,bits256 subhash,char *message,int32_t maxdelay,int32_t broadcastflag,int32_t plaintext,cJSON *argjson,char *remoteaddr)
{
    char *hexmsg,*retstr; int32_t len; cJSON *retjson = cJSON_CreateObject();
    len = (int32_t)strlen(message);
    //char str[65]; printf("multicast.(%s)\n",bits256_str(str,categoryhash));
    if ( is_hexstr(message,len) == 0 )
    {
        hexmsg = malloc(((len+1) << 1) + 1);
        init_hexbytes_noT(hexmsg,(uint8_t *)message,len+1);
    } else hexmsg = message;
    plaintext = category_plaintext(myinfo,categoryhash,subhash,plaintext);
    broadcastflag = category_broadcastflag(myinfo,categoryhash,subhash,broadcastflag);
    maxdelay = category_maxdelay(myinfo,categoryhash,subhash,maxdelay);
    retstr = SuperNET_DHTsend(myinfo,0,categoryhash,subhash,hexmsg,maxdelay,broadcastflag,plaintext);
    //if ( 0 && argjson != 0 )
    //    SuperNET_hexmsgprocess(myinfo,retjson,argjson,hexmsg,remoteaddr);
    if ( hexmsg != message)
        free(hexmsg);
    if ( retjson != 0 )
    {
        if ( retstr != 0 )
            jaddstr(retjson,"result",retstr);
        retstr = jprint(retjson,1);
    }
    return(retstr);
}

void category_init(struct supernet_info *myinfo)
{
    bits256 pangeahash;
    category_subscribe(myinfo,GENESIS_PUBKEY,GENESIS_PUBKEY);
    pangeahash = calc_categoryhashes(0,"pangea",0);
    category_subscribe(myinfo,pangeahash,GENESIS_PUBKEY);
    category_processfunc(pangeahash,GENESIS_PUBKEY,pangea_hexmsg);
    category_chain_functions(myinfo,pangeahash,GENESIS_PUBKEY,sizeof(bits256),sizeof(bits256),0,0,0,0);
    exchanges777_init(myinfo,0,0);
}
