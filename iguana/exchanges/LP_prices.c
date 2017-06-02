
/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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
//
//  LP_prices.c
//  marketmaker
//

double LP_kmdbtc;

struct LP_cacheinfo
{
    UT_hash_handle hh;
    struct LP_quoteinfo Q;
    uint8_t key[sizeof(bits256)+sizeof(uint64_t)*2+sizeof(int32_t)];
    double price;
    uint32_t timestamp;
} *LP_cacheinfos;

int32_t LP_cachekey(uint8_t *key,char *base,char *rel,bits256 txid,int32_t vout)
{
    uint64_t basebits,relbits; int32_t offset = 0;
    basebits = stringbits(base);
    relbits = stringbits(rel);
    memcpy(&key[offset],&basebits,sizeof(basebits)), offset += sizeof(basebits);
    memcpy(&key[offset],&relbits,sizeof(relbits)), offset += sizeof(relbits);
    memcpy(&key[offset],&txid,sizeof(txid)), offset += sizeof(txid);
    memcpy(&key[offset],&vout,sizeof(vout)), offset += sizeof(vout);
    return(offset);
}

struct LP_cacheinfo *LP_cachefind(char *base,char *rel,bits256 txid,int32_t vout)
{
    struct LP_cacheinfo *ptr=0; uint8_t key[sizeof(bits256)+sizeof(uint64_t)*2+sizeof(vout)];
    if ( LP_cachekey(key,base,rel,txid,vout) == sizeof(key) )
    {
        portable_mutex_lock(&LP_cachemutex);
        HASH_FIND(hh,LP_cacheinfos,key,sizeof(key),ptr);
        portable_mutex_unlock(&LP_cachemutex);
    } else printf("LP_cachefind keysize mismatch?\n");
    if ( 0 && ptr != 0 && ptr->timestamp != 0 && ptr->timestamp < time(NULL)-LP_CACHEDURATION )
    {
        printf("expire price %.8f\n",ptr->price);
        ptr->price = 0.;
        ptr->timestamp = 0;
        memset(&ptr->Q,0,sizeof(ptr->Q));
    }
    return(ptr);
}

double LP_pricecache(struct LP_quoteinfo *qp,char *base,char *rel,bits256 txid,int32_t vout)
{
    struct LP_cacheinfo *ptr;
    if ( (ptr= LP_cachefind(base,rel,txid,vout)) != 0 )
    {
        if ( qp != 0 )
            (*qp) = ptr->Q;
        if ( ptr->price == 0. && ptr->Q.satoshis != 0 )
        {
            printf("null ptr->price? ");
            ptr->price = (double)ptr->Q.destsatoshis / ptr->Q.satoshis;
        }
        //printf("found %s/%s %.8f\n",base,rel,ptr->price);
        return(ptr->price);
    }
    //char str[65]; printf("cachemiss %s/%s %s/v%d\n",base,rel,bits256_str(str,txid),vout);
    return(0.);
}

struct LP_cacheinfo *LP_cacheadd(char *base,char *rel,bits256 txid,int32_t vout,double price,struct LP_quoteinfo *qp)
{
    char str[65]; struct LP_cacheinfo *ptr=0;
    if ( (ptr= LP_cachefind(base,rel,txid,vout)) == 0 )
    {
        ptr = calloc(1,sizeof(*ptr));
        if ( LP_cachekey(ptr->key,base,rel,txid,vout) == sizeof(ptr->key) )
        {
            portable_mutex_lock(&LP_cachemutex);
            HASH_ADD(hh,LP_cacheinfos,key,sizeof(ptr->key),ptr);
            portable_mutex_unlock(&LP_cachemutex);
        } else printf("LP_cacheadd keysize mismatch?\n");
    }
    if ( price != ptr->price )
    {
        printf("updated %s/v%d %s/%s %llu price %.8f\n",bits256_str(str,txid),vout,base,rel,(long long)qp->satoshis,price);
    }
    ptr->price = price;
    ptr->Q = *qp;
    ptr->timestamp = (uint32_t)time(NULL);
    return(ptr);
}

static int _cmp_orderbook(const void *a,const void *b)
{
#define ptr_a ((struct LP_cacheinfo *)a)->price
#define ptr_b ((struct LP_cacheinfo *)b)->price
    if ( ptr_b > ptr_a )
        return(1);
    else if ( ptr_b < ptr_a )
        return(-1);
    else
    {
#undef ptr_a
#undef ptr_b
#define ptr_a ((struct LP_cacheinfo *)a)->Q.satoshis
#define ptr_b ((struct LP_cacheinfo *)b)->Q.satoshis
        if ( ptr_b > ptr_a )
            return(1);
        else if ( ptr_b < ptr_a )
            return(-1);
    }
    return(0);
#undef ptr_a
#undef ptr_b
}

static int _cmp_orderbookrev(const void *a,const void *b)
{
    return(-_cmp_orderbook(a,b));
}

cJSON *LP_orderbookjson(struct LP_cacheinfo *ptr,int32_t polarity)
{
    double price,volume; cJSON *item = cJSON_CreateObject();
    if ( (price= ptr->price) != 0. && (volume= dstr(ptr->Q.satoshis)) != 0. )
    {
        jaddnum(item,"price",polarity > 0 ? price : 1. / price);
        jaddnum(item,"volume",polarity > 0 ? volume : volume / price);
        jaddbits256(item,"txid",ptr->Q.txid);
        jaddnum(item,"vout",ptr->Q.vout);
    }
    return(item);
}

char *LP_orderbook(char *base,char *rel)
{
    uint32_t now,i; struct LP_cacheinfo *ptr,*tmp,**bids = 0,**asks = 0; cJSON *retjson,*array; int32_t numbids=0,numasks=0;
    now = (uint32_t)time(NULL);
    HASH_ITER(hh,LP_cacheinfos,ptr,tmp)
    {
        if ( ptr->timestamp < now-60 || ptr->price == 0. )
            continue;
        if ( strcmp(ptr->Q.srccoin,base) == 0 && strcmp(ptr->Q.destcoin,rel) == 0 )
        {
            asks = realloc(asks,sizeof(*asks) * (numasks+1));
            asks[numasks++] = ptr;
        }
        else if ( strcmp(ptr->Q.srccoin,rel) == 0 && strcmp(ptr->Q.destcoin,base) == 0 )
        {
            bids = realloc(bids,sizeof(*bids) * (numbids+1));
            bids[numbids++] = ptr;
        }
    }
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    if ( numbids > 1 )
        qsort(bids,numbids,sizeof(*bids),_cmp_orderbook);
    for (i=0; i<numbids; i++)
        jaddi(array,LP_orderbookjson(bids[i],1));
    jadd(retjson,"bids",array);
    array = cJSON_CreateArray();
    if ( numasks > 1 )
        qsort(asks,numasks,sizeof(*asks),_cmp_orderbookrev);
    for (i=0; i<numasks; i++)
        jaddi(array,LP_orderbookjson(asks[i],-1));
    jadd(retjson,"asks",array);
    jaddstr(retjson,"base",base);
    jaddstr(retjson,"rel",rel);
    jaddnum(retjson,"timestamp",now);
    return(jprint(retjson,1));
}

// very, very simple for now

void LP_priceupdate(char *base,char *rel,double price,double avebid,double aveask,double highbid,double lowask,double PAXPRICES[32])
{
    if ( avebid > SMALLVAL && aveask > SMALLVAL && strcmp(base,"KMD") == 0 && strcmp(rel,"BTC") == 0 )
        LP_kmdbtc = (avebid + aveask) * 0.5;
}

double LP_price(char *base,char *rel)
{
    if ( LP_kmdbtc != 0. )
    {
        if ( strcmp(base,"KMD") == 0 && strcmp(rel,"BTC") == 0 )
            return(LP_kmdbtc);
        else if ( strcmp(rel,"KMD") == 0 && strcmp(base,"BTC") == 0 )
            return(1. / LP_kmdbtc);
    }
    return(0.);
}

char *LP_pricestr(char *base,char *rel)
{
    double price = 0.; cJSON *retjson;
    if ( base != 0 && base[0] != 0 && rel != 0 && rel[0] != 0 )
        price = LP_price(base,rel);
    if ( price != 0. )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","success");
        jaddstr(retjson,"base",base);
        jaddstr(retjson,"rel",rel);
        jaddnum(retjson,"price",price);
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"cant find baserel pair\"}"));
}







