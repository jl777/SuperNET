
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

#define LP_MAXPRICEINFOS 64
struct LP_priceinfo
{
    char symbol[16];
    uint64_t coinbits;
    int32_t ind,pad;
    double diagval;
    double relvals[LP_MAXPRICEINFOS];
    double myprices[LP_MAXPRICEINFOS];
} LP_priceinfos[LP_MAXPRICEINFOS];
int32_t LP_numpriceinfos;

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

struct LP_priceinfo *LP_priceinfofind(char *symbol)
{
    int32_t i; struct LP_priceinfo *pp; uint64_t coinbits;
    if ( LP_numpriceinfos > 0 )
    {
        coinbits = stringbits(symbol);
        pp = LP_priceinfos;
        for (i=0; i<LP_numpriceinfos; i++,pp++)
            if ( pp->coinbits == coinbits )
                return(pp);
    }
    return(0);
}

struct LP_priceinfo *LP_priceinfoptr(int32_t *indp,char *base,char *rel)
{
    struct LP_priceinfo *basepp,*relpp;
    if ( (basepp= LP_priceinfofind(base)) != 0 && (relpp= LP_priceinfofind(rel)) != 0 )
    {
        *indp = relpp->ind;
        return(basepp);
    }
    else
    {
        *indp = -1;
        return(0);
    }
}

void LP_priceinfoupdate(char *base,char *rel,double price)
{
    struct LP_priceinfo *basepp,*relpp;
    if ( (basepp= LP_priceinfofind(base)) != 0 && (relpp= LP_priceinfofind(rel)) != 0 )
    {
        dxblend(&basepp->relvals[relpp->ind],price,0.9);
        dxblend(&relpp->relvals[basepp->ind],1. / price,0.9);
    }
}

double LP_myprice(double *bidp,double *askp,char *base,char *rel)
{
    struct LP_priceinfo *basepp,*relpp;
    if ( (basepp= LP_priceinfofind(base)) != 0 && (relpp= LP_priceinfofind(rel)) != 0 )
    {
        *askp = basepp->myprices[relpp->ind];
        *bidp = relpp->myprices[basepp->ind];
        return((*askp + *bidp) * 0.5);
    } else return(0.);
}

int32_t LP_mypriceset(char *base,char *rel,double price)
{
    struct LP_priceinfo *basepp,*relpp;
    if ( price != 0. && (basepp= LP_priceinfofind(base)) != 0 && (relpp= LP_priceinfofind(rel)) != 0 )
    {
        basepp->myprices[relpp->ind] = price;        // ask
        relpp->myprices[basepp->ind] = 1. / price;   // bid
        return(0);
    } else return(-1);
}

double LP_price(char *base,char *rel)
{
    struct LP_priceinfo *basepp; int32_t relind; double price = 0.;
    if ( (basepp= LP_priceinfoptr(&relind,base,rel)) != 0 )
    {
        if ( (price= basepp->myprices[relind]) == 0. )
            price = basepp->relvals[relind];
    }
    return(price);
}

cJSON *LP_priceinfomatrix(int32_t usemyprices)
{
    int32_t i,j,n,m; double total,sum,val; struct LP_priceinfo *pp; uint32_t now; struct LP_cacheinfo *ptr,*tmp; cJSON *vectorjson = cJSON_CreateObject();
    now = (uint32_t)time(NULL);
    HASH_ITER(hh,LP_cacheinfos,ptr,tmp)
    {
        if ( ptr->timestamp < now-60 || ptr->price == 0. )
            continue;
        LP_priceinfoupdate(ptr->Q.srccoin,ptr->Q.destcoin,ptr->price);
    }
    pp = LP_priceinfos;
    total = m = 0;
    for (i=0; i<LP_numpriceinfos; i++,pp++)
    {
        pp->diagval = sum = n = 0;
        for (j=0; j<LP_numpriceinfos; j++)
        {
            if ( usemyprices == 0 || (val= pp->myprices[j]) == 0. )
                val = pp->relvals[j];
            if ( val != 0. )
            {
                sum += val;
                n++;
            }
        }
        if ( n > 0 )
        {
            pp->diagval = sum / n;
            total += pp->diagval, m++;
        }
    }
    if ( m > 0 )
    {
        pp = LP_priceinfos;
        for (i=0; i<LP_numpriceinfos; i++,pp++)
        {
            pp->diagval /= total;
            jaddnum(vectorjson,pp->symbol,pp->diagval);
        }
    }
    return(vectorjson);
}

struct LP_priceinfo *LP_priceinfoadd(char *symbol)
{
    struct LP_priceinfo *pp; cJSON *retjson;
    if ( LP_numpriceinfos >= sizeof(LP_priceinfos)/sizeof(*LP_priceinfos) )
    {
        printf("cant add any more priceinfos\n");
        return(0);
    }
    pp = &LP_priceinfos[LP_numpriceinfos];
    memset(pp,0,sizeof(*pp));
    safecopy(pp->symbol,symbol,sizeof(pp->symbol));
    pp->coinbits = stringbits(symbol);
    pp->ind = LP_numpriceinfos++;
    /*pp->relvals = calloc(LP_numpriceinfos+1,sizeof(*pp->relvals));
    //pp->myprices = calloc(LP_numpriceinfos+1,sizeof(*pp->myprices));
    vecsize = sizeof(*LP_priceinfos[i].relvals) * (LP_numpriceinfos + 1);
    for (i=0; i<LP_numpriceinfos; i++)
    {
        printf("realloc i.%d of %d relvals.%p\n",i,LP_numpriceinfos,LP_priceinfos[i].relvals);
        LP_priceinfos[i].relvals = realloc(LP_priceinfos[i].relvals,vecsize);
        memset(LP_priceinfos[i].relvals,0,vecsize);
        LP_priceinfos[i].myprices[LP_numpriceinfos] = 0.;
    }*/
    LP_numpriceinfos++;
    if ( (retjson= LP_priceinfomatrix(0)) != 0 )
        free_json(retjson);
    return(pp);
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
    ptr->Q = *qp;
    ptr->timestamp = (uint32_t)time(NULL);
    if ( price != ptr->price )
    {
        ptr->price = price;
        LP_priceinfoupdate(base,rel,price);
        printf("updated %s/v%d %s/%s %llu price %.8f\n",bits256_str(str,txid),vout,base,rel,(long long)qp->satoshis,price);
    } else ptr->price = price;
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
    double price; cJSON *item = cJSON_CreateObject();
    if ( ptr->Q.satoshis != 0 && ptr->Q.destsatoshis != 0 )
    {
        price = (double)ptr->Q.destsatoshis / ptr->Q.satoshis;
        jaddnum(item,"price",polarity > 0 ? price : 1. / price);
        jaddnum(item,"volume",polarity > 0 ? dstr(ptr->Q.satoshis) : dstr(ptr->Q.destsatoshis));
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
        jaddi(array,LP_orderbookjson(bids[i],-1));
    jadd(retjson,"bids",array);
    array = cJSON_CreateArray();
    if ( numasks > 1 )
        qsort(asks,numasks,sizeof(*asks),_cmp_orderbookrev);
    for (i=0; i<numasks; i++)
        jaddi(array,LP_orderbookjson(asks[i],1));
    jadd(retjson,"asks",array);
    jaddstr(retjson,"base",base);
    jaddstr(retjson,"rel",rel);
    jaddnum(retjson,"timestamp",now);
    return(jprint(retjson,1));
}

void LP_priceupdate(char *base,char *rel,double price,double avebid,double aveask,double highbid,double lowask,double PAXPRICES[32])
{
    LP_priceinfoupdate(base,rel,price);
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
        jadd(retjson,"theoretical",LP_priceinfomatrix(0));
        jadd(retjson,"quotes",LP_priceinfomatrix(1));
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"cant find baserel pair\"}"));
}







