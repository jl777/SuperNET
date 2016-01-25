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

struct category_info *category_funcset(bits256 categoryhash,int32_t (*process_func)(struct supernet_info *myinfo,void *data,int32_t datalen,char *remoteaddr))
{
    struct category_info *cat;
    if ( (cat= category_find(categoryhash,GENESIS_PUBKEY)) != 0 )
    {
        cat->process_func = process_func;
        return(cat);
    }
    return(0);
}

struct category_msg *category_gethexmsg(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash)
{
    queue_t *Q;
    char str[65]; printf("getmsg.(%s) %llx\n",bits256_str(str,categoryhash),(long long)subhash.txid);
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

char *SuperNET_categorymulticast(struct supernet_info *myinfo,int32_t surveyflag,bits256 categoryhash,bits256 subhash,char *message,int32_t maxdelay,int32_t broadcastflag,int32_t plaintext)
{
    char *hexmsg,*retstr; int32_t len;
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
    if ( hexmsg != message)
        free(hexmsg);
    return(retstr);
}
