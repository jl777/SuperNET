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

queue_t *category_Q(struct category_info **catptrp,bits256 categoryhash,bits256 subhash)
{
    struct category_info *cat;
    *catptrp = 0;
    if ( (cat= category_find(categoryhash,subhash)) != 0 )
    {
        *catptrp = cat;
        return(&cat->Q);
    }
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

struct category_info *category_processfunc(bits256 categoryhash,bits256 subhash,char *(*process_func)(struct supernet_info *myinfo,struct category_info *cat,void *data,int32_t datalen,char *remoteaddr))
{
    struct category_info *cat;
    if ( (cat= category_find(categoryhash,subhash)) != 0 )
    {
        cat->processfunc = process_func;
        return(cat);
    }
    return(0);
}

struct category_msg *category_gethexmsg(struct supernet_info *myinfo,struct category_info **catptrp,bits256 categoryhash,bits256 subhash)
{
    queue_t *Q;
    //char str[65]; printf("getmsg.(%s) %llx\n",bits256_str(str,categoryhash),(long long)subhash.txid);
    if ( (Q= category_Q(catptrp,categoryhash,subhash)) != 0 )
        return(queue_dequeue(Q,0));
    else return(0);
}

void category_posthexmsg(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash,char *hexmsg,struct tai now,char *remoteaddr)
{
    int32_t len; struct category_msg *m; queue_t *Q = 0; struct category_info *cat;
    if ( (Q= category_Q(&cat,categoryhash,subhash)) != 0 )
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

char *bitcoin_hexmsg(struct supernet_info *myinfo,struct category_info *cat,void *ptr,int32_t len,char *remoteaddr)
{
    char *method="",*agent="",*retstr = 0; int32_t i,j; cJSON *json,*valsobj; struct iguana_info *coin=0; struct iguana_peer *addr;
    if ( (json= cJSON_Parse(ptr)) != 0 )
    {
        printf("bitcoinprocess.(%s)\n",jprint(json,0));
        agent = jstr(json,"agent");
        method = jstr(json,"method");
        valsobj = jobj(json,"vals");
        if ( strcmp(agent,"iguana") == 0 )
        {
            if ( valsobj != 0 && jobj(valsobj,"coin") != 0 )
                coin = iguana_coinfind(jstr(valsobj,"coin"));
            else if ( jstr(json,"activecoin") != 0 )
                coin = iguana_coinfind(jstr(json,"activecoin"));
            if ( coin != 0 )
            {
                if ( coin->RELAYNODE != 0 || coin->VALIDATENODE != 0 )
                {
                    if ( valsobj != 0 && strcmp(method,"rawtx") == 0 )
                    {
                        retstr = iguana_rawtx(myinfo,coin,json,remoteaddr,jstr(json,"changeaddr"),jobj(json,"addresses"),valsobj,jstr(json,"spendscriptstr"));
                    }
                    else if ( strcmp(method,"balances") == 0 )
                    {
                        retstr = iguana_balances(myinfo,coin,json,remoteaddr,juint(json,"lastheight"),jobj(json,"addresses"),jstr(json,"activecoin"));
                    }
                    if ( retstr == 0 )
                        return(0);
                    printf("RELAY will return.(%s)\n",retstr);
                    for (j=0; j<IGUANA_MAXCOINS; j++)
                    {
                        if ( (coin= Coins[j]) == 0 )
                            continue;
                        for (i=0; i<IGUANA_MAXPEERS; i++)
                        {
                            if ( (addr= &coin->peers.active[i]) != 0 && addr->usock >= 0 )
                            {
                                if ( addr->supernet != 0 && strcmp(addr->ipaddr,remoteaddr) == 0 )
                                {
                                    //printf("send back rawtx_result addr->supernet.%u to (%s)\n",addr->supernet,addr->ipaddr);
                                    iguana_send_supernet(addr,retstr,0);
                                    free_json(json);
                                    return(retstr);
                                }
                            }
                            if ( 0 && addr->ipbits != 0 )
                                printf("i.%d (%s) vs (%s) %s\n",i,addr->ipaddr,remoteaddr,coin->symbol);
                        }
                    }
                }
                else
                {
                    if ( strcmp(method,"rawtx_result") == 0 )
                    {
                        return(iguana_rawtx_result(myinfo,coin,json,remoteaddr,juint(json,"rawtxtag"),jobj(json,"vins"),jstr(json,"rawtx")));
                    }
                }
            }
        }
    }
    printf("unhandled bitcoin_hexmsg.(%d) from %s (%s/%s)\n",len,remoteaddr,agent,method);
    free_json(json);
    return(retstr);
}

void category_init(struct supernet_info *myinfo)
{
    bits256 pangeahash,instantdexhash,bitcoinhash;
    category_subscribe(myinfo,GENESIS_PUBKEY,GENESIS_PUBKEY);
    pangeahash = calc_categoryhashes(0,"pangea",0);
    myinfo->pangea_category = pangeahash;
    category_subscribe(myinfo,pangeahash,GENESIS_PUBKEY);
    category_processfunc(pangeahash,GENESIS_PUBKEY,pangea_hexmsg);
    category_chain_functions(myinfo,pangeahash,GENESIS_PUBKEY,sizeof(bits256),sizeof(bits256),0,0,0,0,0,0);
    instantdexhash = calc_categoryhashes(0,"InstantDEX",0);
    myinfo->instantdex_category = instantdexhash;
    category_subscribe(myinfo,instantdexhash,GENESIS_PUBKEY);
    category_processfunc(instantdexhash,GENESIS_PUBKEY,InstantDEX_hexmsg);
    category_processfunc(instantdexhash,myinfo->myaddr.persistent,InstantDEX_hexmsg);
    
    bitcoinhash = calc_categoryhashes(0,"bitcoin",0);
    myinfo->bitcoin_category = bitcoinhash;
    category_subscribe(myinfo,bitcoinhash,GENESIS_PUBKEY);
    category_processfunc(bitcoinhash,GENESIS_PUBKEY,bitcoin_hexmsg);
    category_processfunc(bitcoinhash,myinfo->myaddr.persistent,bitcoin_hexmsg);
}
