
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

struct LP_orderbookentry { bits256 pubkey; double price; uint64_t minsatoshis,maxsatoshis,depth; uint32_t timestamp; int32_t numutxos; char coinaddr[64]; };

struct LP_priceinfo
{
    char symbol[16];
    uint64_t coinbits;
    int32_t ind,pad;
    double diagval,high[2],low[2],last[2],bid[2],ask[2]; //volume,btcvolume,prevday; // mostly bittrex info
    double relvals[LP_MAXPRICEINFOS];
    double myprices[LP_MAXPRICEINFOS];
    double minprices[LP_MAXPRICEINFOS]; // autoprice
    double fixedprices[LP_MAXPRICEINFOS]; // fixedprices
    double margins[LP_MAXPRICEINFOS];
    double offsets[LP_MAXPRICEINFOS];
    double factors[LP_MAXPRICEINFOS];
    //double maxprices[LP_MAXPRICEINFOS]; // autofill of base/rel
    //double relvols[LP_MAXPRICEINFOS];
    //FILE *fps[LP_MAXPRICEINFOS];
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

struct LP_priceinfo *LP_priceinfo(int32_t ind)
{
    if ( ind < 0 || ind >= LP_MAXPRICEINFOS )
        return(0);
    else return(&LP_priceinfos[ind]);
}

char *LP_priceinfostr(int32_t ind)
{
    if ( ind < 0 || ind >= LP_MAXPRICEINFOS )
        return("UNKNOWN");
    else return(LP_priceinfos[ind].symbol);
}

int32_t LP_pricevalid(double price)
{
    if ( price > SMALLVAL && isnan(price) == 0 && price < SATOSHIDEN )
        return(1);
    else return(0);
}

struct LP_priceinfo *LP_priceinfofind(char *symbol)
{
    int32_t i; struct LP_priceinfo *pp; uint64_t coinbits;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
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

int32_t LP_priceinfoind(char *symbol)
{
    struct LP_priceinfo *pp;
    if ( (pp= LP_priceinfofind(symbol)) != 0 )
        return(pp->ind);
    else return(-1);
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
    if ( base == 0 || rel == 0 )
        return(0);
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

struct LP_pubkeyinfo *LP_pubkey_rmd160find(uint8_t rmd160[20])
{
    struct LP_pubkeyinfo *pubp=0,*tmp;
    portable_mutex_lock(&LP_pubkeymutex);
    HASH_ITER(hh,LP_pubkeyinfos,pubp,tmp)
    {
        if ( memcmp(rmd160,pubp->rmd160,sizeof(pubp->rmd160)) == 0 )
            break;
        pubp = 0;
    }
    portable_mutex_unlock(&LP_pubkeymutex);
    return(pubp);
}

struct LP_address *_LP_addressfind(struct iguana_info *coin,char *coinaddr)
{
    uint8_t rmd160[20],addrtype; struct LP_address *ap; struct LP_pubkeyinfo *pubp;
    HASH_FIND(hh,coin->addresses,coinaddr,strlen(coinaddr),ap);
    if ( ap != 0 && bits256_nonz(ap->pubkey) == 0 )
    {
        bitcoin_addr2rmd160(coin->taddr,&addrtype,rmd160,coinaddr);
        if ( (pubp= LP_pubkey_rmd160find(rmd160)) != 0 )
        {
            ap->pubkey = pubp->pubkey;
            memcpy(ap->pubsecp,pubp->pubsecp,sizeof(ap->pubsecp));
        }
    }
    return(ap);
}

struct LP_address *_LP_addressadd(struct iguana_info *coin,char *coinaddr)
{
    uint8_t rmd160[20],addrtype; struct LP_address *ap; struct LP_pubkeyinfo *pubp;
    ap = calloc(1,sizeof(*ap));
    safecopy(ap->coinaddr,coinaddr,sizeof(ap->coinaddr));
    bitcoin_addr2rmd160(coin->taddr,&addrtype,rmd160,coinaddr);
    if ( (pubp= LP_pubkey_rmd160find(rmd160)) != 0 )
    {
        ap->pubkey = pubp->pubkey;
        memcpy(ap->pubsecp,pubp->pubsecp,sizeof(ap->pubsecp));
    }
    //printf("LP_ADDRESS %s ADD.(%s)\n",coin->symbol,coinaddr);
    HASH_ADD_KEYPTR(hh,coin->addresses,ap->coinaddr,strlen(ap->coinaddr),ap);
    return(ap);
}

struct LP_pubkeyinfo *LP_pubkeyfind(bits256 pubkey)
{
    struct LP_pubkeyinfo *pubp=0;
    portable_mutex_lock(&LP_pubkeymutex);
    HASH_FIND(hh,LP_pubkeyinfos,&pubkey,sizeof(pubkey),pubp);
    portable_mutex_unlock(&LP_pubkeymutex);
    return(pubp);
}

struct LP_pubkeyinfo *LP_pubkeyadd(bits256 pubkey)
{
    char str[65]; struct LP_pubkeyinfo *pubp=0;
    portable_mutex_lock(&LP_pubkeymutex);
    HASH_FIND(hh,LP_pubkeyinfos,&pubkey,sizeof(pubkey),pubp);
    if ( pubp == 0 )
    {
        pubp = calloc(1,sizeof(*pubp));
        pubp->pubkey = pubkey;
        if ( bits256_cmp(G.LP_mypub25519,pubkey) == 0 )
        {
            memcpy(pubp->rmd160,G.LP_myrmd160,sizeof(pubp->rmd160));
            memcpy(pubp->pubsecp,G.LP_pubsecp,sizeof(pubp->pubsecp));
        }
        HASH_ADD_KEYPTR(hh,LP_pubkeyinfos,&pubp->pubkey,sizeof(pubp->pubkey),pubp);
        HASH_FIND(hh,LP_pubkeyinfos,&pubkey,sizeof(pubkey),pubp);
        if ( pubp == 0 )
            printf("pubkeyadd find %s error after add\n",bits256_str(str,pubp->pubkey));
    }
    portable_mutex_unlock(&LP_pubkeymutex);
    return(pubp);
}

int32_t LP_pubkey_istrusted(bits256 pubkey)
{
    struct LP_pubkeyinfo *pubp;
    if ( (pubp= LP_pubkeyadd(pubkey)) != 0 )
        return(pubp->istrusted != 0);
    return(0);
}

char *LP_pubkey_trustset(bits256 pubkey,uint32_t trustval)
{
    struct LP_pubkeyinfo *pubp;
    if ( (pubp= LP_pubkeyadd(pubkey)) != 0 )
    {
        pubp->istrusted = trustval;
        return(clonestr("{\"result\":\"success\"}"));
    }
    return(clonestr("{\"error\":\"pubkey not found\"}"));
}

char *LP_pubkey_trusted()
{
    struct LP_pubkeyinfo *pubp,*tmp; cJSON *array = cJSON_CreateArray();
    HASH_ITER(hh,LP_pubkeyinfos,pubp,tmp)
    {
        if ( pubp->istrusted != 0 )
            jaddibits256(array,pubp->pubkey);
    }
    return(jprint(array,1));
}

uint64_t LP_unspents_metric(struct iguana_info *coin,char *coinaddr)
{
    cJSON *array,*item; int32_t i,n; uint64_t metric=0,total;
    LP_listunspent_both(coin->symbol,coinaddr,0);
    if ( (array= LP_address_utxos(coin,coinaddr,1)) != 0 )
    {
        total = 0;
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                total += j64bits(item,"value");
            }
        }
        metric = _LP_unspents_metric(total,n);
    }
    return(metric);
}

cJSON *LP_pubkeyjson(struct LP_pubkeyinfo *pubp)
{
    int32_t baseid,relid; char *base,hexstr[67],hexstr2[67],sigstr[256]; double price; cJSON *item,*array,*obj;
    obj = cJSON_CreateObject();
    array = cJSON_CreateArray();
    for (baseid=0; baseid<LP_numpriceinfos; baseid++)
    {
        base = LP_priceinfos[baseid].symbol;
        for (relid=0; relid<LP_numpriceinfos; relid++)
        {
            price = pubp->matrix[baseid][relid];
            if ( LP_pricevalid(price) > 0 )
            {
                item = cJSON_CreateArray();
                jaddistr(item,base);
                jaddistr(item,LP_priceinfos[relid].symbol);
                jaddinum(item,price);
                jaddi(array,item);
            }
        }
    }
    jaddbits256(obj,"pubkey",pubp->pubkey);
    init_hexbytes_noT(hexstr,pubp->rmd160,sizeof(pubp->rmd160));
    jaddstr(obj,"rmd160",hexstr);
    init_hexbytes_noT(hexstr2,pubp->pubsecp,sizeof(pubp->pubsecp));
    jaddstr(obj,"pubsecp",hexstr2);
    init_hexbytes_noT(sigstr,pubp->sig,pubp->siglen);
    jaddstr(obj,"sig",sigstr);
    jaddnum(obj,"timestamp",pubp->timestamp);
    jadd(obj,"asks",array);
    if ( pubp->istrusted != 0 )
        jaddnum(obj,"istrusted",pubp->istrusted);
    return(obj);
}

char *LP_prices()
{
    struct LP_pubkeyinfo *pubp,*tmp; cJSON *array = cJSON_CreateArray();
    HASH_ITER(hh,LP_pubkeyinfos,pubp,tmp)
    {
        jaddi(array,LP_pubkeyjson(pubp));
    }
    return(jprint(array,1));
}

void LP_prices_parse(struct LP_peerinfo *peer,cJSON *obj)
{
    struct LP_pubkeyinfo *pubp; struct LP_priceinfo *basepp,*relpp; uint32_t timestamp; bits256 pubkey; cJSON *asks,*item; uint8_t rmd160[20]; int32_t i,n,relid,mismatch; char *base,*rel,*hexstr; double askprice; uint32_t now;
    now = (uint32_t)time(NULL);
    pubkey = jbits256(obj,"pubkey");
    if ( bits256_nonz(pubkey) != 0 && (pubp= LP_pubkeyadd(pubkey)) != 0 )
    {
        if ( (hexstr= jstr(obj,"rmd160")) != 0 && strlen(hexstr) == 2*sizeof(rmd160) )
            decode_hex(rmd160,sizeof(rmd160),hexstr);
        if ( memcmp(pubp->rmd160,rmd160,sizeof(rmd160)) != 0 )
            mismatch = 1;
        else mismatch = 0;
        if ( bits256_cmp(pubkey,G.LP_mypub25519) == 0 && mismatch == 0 )
            peer->needping = 0;
        LP_pubkey_sigcheck(pubp,obj);
        timestamp = juint(obj,"timestamp");
        if ( timestamp > now )
            timestamp = now;
        if ( timestamp >= pubp->timestamp && (asks= jarray(&n,obj,"asks")) != 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(asks,i);
                base = jstri(item,0);
                rel = jstri(item,1);
                askprice = jdoublei(item,2);
                if ( LP_pricevalid(askprice) > 0 )
                {
                    if ( (basepp= LP_priceinfoptr(&relid,base,rel)) != 0 )
                    {
                        //char str[65]; printf("gotprice %s %s/%s (%d/%d) %.8f\n",bits256_str(str,pubkey),base,rel,basepp->ind,relid,askprice);
                        pubp->matrix[basepp->ind][relid] = askprice;
                        //pubp->timestamps[basepp->ind][relid] = timestamp;
                        if ( (relpp= LP_priceinfofind(rel)) != 0 )
                        {
                            dxblend(&basepp->relvals[relpp->ind],askprice,0.9);
                            dxblend(&relpp->relvals[basepp->ind],1. / askprice,0.9);
                        }
                    }
                }
            }
        }
    }
}

void LP_peer_pricesquery(struct LP_peerinfo *peer)
{
    char *retstr; cJSON *array; int32_t i,n;
    if ( strcmp(peer->ipaddr,LP_myipaddr) == 0 )
        return;
    peer->needping = (uint32_t)time(NULL);
    if ( (retstr= issue_LP_getprices(peer->ipaddr,peer->port)) != 0 )
    {
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( is_cJSON_Array(array) && (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                    LP_prices_parse(peer,jitem(array,i));
            }
            free_json(array);
        }
        free(retstr);
    }
    if ( peer->needping != 0 )
    {
        //printf("%s needs ping\n",peer->ipaddr);
    }
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
            ptr->price = (double)ptr->Q.destsatoshis / ptr->Q.satoshis;
            if ( LP_pricevalid(ptr->price) <= 0 )
                ptr->price = 0.;
            printf("LP_pricecache: set %s/%s ptr->price %.8f\n",base,rel,ptr->price);
        }
        printf(">>>>>>>>>> found %s/%s %.8f\n",base,rel,ptr->price);
        return(ptr->price);
    }
    //char str[65]; printf("cachemiss %s/%s %s/v%d\n",base,rel,bits256_str(str,txid),vout);
    return(0.);
}

void LP_priceinfoupdate(char *base,char *rel,double price)
{
    struct LP_priceinfo *basepp,*relpp;
    if ( LP_pricevalid(price) > 0 )
    {
        if ( (basepp= LP_priceinfofind(base)) != 0 && (relpp= LP_priceinfofind(rel)) != 0 )
        {
            //dxblend(&basepp->relvals[relpp->ind],price,0.9);
            //dxblend(&relpp->relvals[basepp->ind],1. / price,0.9);
            basepp->relvals[relpp->ind] = price;
            relpp->relvals[basepp->ind] = 1. / price;
        }
    }
}

double LP_myprice(double *bidp,double *askp,char *base,char *rel)
{
    struct LP_priceinfo *basepp,*relpp; double val;
    *bidp = *askp = 0.;
    if ( (basepp= LP_priceinfofind(base)) != 0 && (relpp= LP_priceinfofind(rel)) != 0 )
    {
        *askp = basepp->myprices[relpp->ind];
        if ( LP_pricevalid(*askp) > 0 )
        {
            val = relpp->myprices[basepp->ind];
            if ( LP_pricevalid(val) > 0 )
            {
                *bidp = 1. / val;
                return((*askp + *bidp) * 0.5);
            }
            else
            {
                *bidp = 0.;
                return(*askp);
            }
        }
        else
        {
            val = relpp->myprices[basepp->ind];
            if ( LP_pricevalid(val) > 0 )
            {
                *bidp = 1. / val;
                *askp = 0.;
                return(*bidp);
            }
        }
    }
    return(0.);
}

char *LP_myprices()
{
    int32_t baseid,relid; double bid,ask; char *base,*rel; cJSON *item,*array;
    array = cJSON_CreateArray();
    for (baseid=0; baseid<LP_numpriceinfos; baseid++)
    {
        base = LP_priceinfos[baseid].symbol;
        for (relid=0; relid<LP_numpriceinfos; relid++)
        {
            rel = LP_priceinfos[relid].symbol;
            if ( LP_myprice(&bid,&ask,base,rel) > SMALLVAL )
            {
                item = cJSON_CreateObject();
                jaddstr(item,"base",base);
                jaddstr(item,"rel",rel);
                jaddnum(item,"bid",bid);
                jaddnum(item,"ask",ask);
                jaddi(array,item);
            }
        }
    }
    return(jprint(array,1));
}

int32_t LP_mypriceset(int32_t *changedp,char *base,char *rel,double price)
{
    struct LP_priceinfo *basepp,*relpp; struct LP_pubkeyinfo *pubp;
    *changedp = 0;
    if ( base != 0 && rel != 0 && (basepp= LP_priceinfofind(base)) != 0 && (relpp= LP_priceinfofind(rel)) != 0 )
    {
        
        if ( fabs(basepp->myprices[relpp->ind] - price)/price > 0.001 )
            *changedp = 1;
        basepp->myprices[relpp->ind] = price;          // ask
        //printf("LP_mypriceset base.%s rel.%s <- price %.8f\n",base,rel,price);
        //relpp->myprices[basepp->ind] = (1. / price);   // bid
        if ( (pubp= LP_pubkeyadd(G.LP_mypub25519)) != 0 )
        {
            pubp->timestamp = (uint32_t)time(NULL);
            pubp->matrix[basepp->ind][relpp->ind] = price;
            //pubp->timestamps[basepp->ind][relpp->ind] = pubp->timestamp;
            //pubp->matrix[relpp->ind][basepp->ind] = (1. / price);
        }
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
        if ( ptr->timestamp < now-3600*2 || ptr->price == 0. )
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
            if ( val > SMALLVAL )
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
            if ( pp->diagval > SMALLVAL )
            {
                pp->diagval /= total;
                jaddnum(vectorjson,pp->symbol,pp->diagval);
            }
        }
    }
    return(vectorjson);
}

struct LP_priceinfo *LP_priceinfoadd(char *symbol)
{
    struct LP_priceinfo *pp; cJSON *retjson;
    if ( symbol == 0 )
        return(0);
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
    LP_numpriceinfos++;
    if ( (retjson= LP_priceinfomatrix(0)) != 0 )
        free_json(retjson);
    return(pp);
}

struct LP_cacheinfo *LP_cacheadd(char *base,char *rel,bits256 txid,int32_t vout,double price,struct LP_quoteinfo *qp)
{
    char str[65]; struct LP_cacheinfo *ptr=0;
    if ( base == 0 || rel == 0 )
        return(0);
    if ( LP_pricevalid(price) > 0 )
    {
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
    }
    return(ptr);
}

static int _cmp_orderbook(const void *a,const void *b)
{
    int32_t retval = 0;
#define ptr_a (*(struct LP_orderbookentry **)a)->price
#define ptr_b (*(struct LP_orderbookentry **)b)->price
    if ( ptr_b > ptr_a )
        retval = -1;
    else if ( ptr_b < ptr_a )
        retval = 1;
    else
    {
#undef ptr_a
#undef ptr_b
#define ptr_a ((struct LP_orderbookentry *)a)->maxsatoshis
#define ptr_b ((struct LP_orderbookentry *)b)->maxsatoshis
        if ( ptr_b > ptr_a )
            return(-1);
        else if ( ptr_b < ptr_a )
            return(1);
    }
    // printf("%.8f vs %.8f -> %d\n",ptr_a,ptr_b,retval);
    return(retval);
#undef ptr_a
#undef ptr_b
}

static int _revcmp_orderbook(const void *a,const void *b)
{
    int32_t retval = 0;
#define ptr_a (*(struct LP_orderbookentry **)a)->price
#define ptr_b (*(struct LP_orderbookentry **)b)->price
    if ( ptr_b > ptr_a )
        retval = 1;
    else if ( ptr_b < ptr_a )
        retval = -1;
    else
    {
#undef ptr_a
#undef ptr_b
#define ptr_a ((struct LP_orderbookentry *)a)->maxsatoshis
#define ptr_b ((struct LP_orderbookentry *)b)->maxsatoshis
        if ( ptr_b > ptr_a )
            return(-1);
        else if ( ptr_b < ptr_a )
            return(1);
    }
    // printf("%.8f vs %.8f -> %d\n",ptr_a,ptr_b,retval);
    return(retval);
#undef ptr_a
#undef ptr_b
}

cJSON *LP_orderbookjson(char *symbol,struct LP_orderbookentry *op)
{
    cJSON *item = cJSON_CreateObject();
    if ( LP_pricevalid(op->price) > 0 )
    {
        jaddstr(item,"coin",symbol);
        jaddstr(item,"address",op->coinaddr);
        jaddnum(item,"price",op->price);
        jaddnum(item,"numutxos",op->numutxos);
        jaddnum(item,"minvolume",dstr(op->minsatoshis)*0.8);
        jaddnum(item,"maxvolume",dstr(op->maxsatoshis)*0.8);
        jaddnum(item,"depth",dstr(op->depth)*0.8);
        jaddbits256(item,"pubkey",op->pubkey);
        jaddnum(item,"age",time(NULL)-op->timestamp);
    }
    return(item);
}

struct LP_orderbookentry *LP_orderbookentry(char *address,char *base,char *rel,double price,int32_t numutxos,uint64_t minsatoshis,uint64_t maxsatoshis,bits256 pubkey,uint32_t timestamp,uint64_t balance)
{
    struct LP_orderbookentry *op;
    if ( (op= calloc(1,sizeof(*op))) != 0 )
    {
        safecopy(op->coinaddr,address,sizeof(op->coinaddr));
        op->price = price;
        op->numutxos = numutxos;
        op->minsatoshis = minsatoshis;
        op->maxsatoshis = maxsatoshis;
        op->pubkey = pubkey;
        op->timestamp = timestamp;
        op->depth = balance;
    }
    return(op);
}

void LP_pubkeys_query()
{
    uint8_t zeroes[20]; bits256 zero; cJSON *reqjson; struct LP_pubkeyinfo *pubp=0,*tmp;
    memset(zero.bytes,0,sizeof(zero));
    memset(zeroes,0,sizeof(zeroes));
    HASH_ITER(hh,LP_pubkeyinfos,pubp,tmp)
    {
        if ( memcmp(zeroes,pubp->rmd160,sizeof(pubp->rmd160)) == 0 && time(NULL) > pubp->lasttime+60 )
        {
            pubp->lasttime = (uint32_t)time(NULL);
            reqjson = cJSON_CreateObject();
            jaddstr(reqjson,"method","wantnotify");
            jaddbits256(reqjson,"pub",pubp->pubkey);
            //printf("LP_pubkeys_query %s\n",jprint(reqjson,0));
            LP_reserved_msg(0,"","",zero,jprint(reqjson,1));
        }
    }
}

int32_t LP_orderbook_utxoentries(uint32_t now,int32_t polarity,char *base,char *rel,struct LP_orderbookentry *(**arrayp),int32_t num,int32_t cachednum,int32_t duration)
{
    char coinaddr[64]; uint8_t zeroes[20]; struct LP_pubkeyinfo *pubp=0,*tmp; struct LP_priceinfo *basepp; struct LP_orderbookentry *op; struct LP_address *ap; struct iguana_info *basecoin; uint32_t oldest; double price; int32_t baseid,relid,n; uint64_t minsatoshis,maxsatoshis,balance;
    if ( (basepp= LP_priceinfoptr(&relid,base,rel)) != 0 )
        baseid = basepp->ind;
    else return(num);
    if ( (basecoin= LP_coinfind(base)) == 0 )
        return(-1);
    now = (uint32_t)time(NULL);
    oldest = now - duration;
    memset(zeroes,0,sizeof(zeroes));
    HASH_ITER(hh,LP_pubkeyinfos,pubp,tmp)
    {
        if ( memcmp(zeroes,pubp->rmd160,sizeof(pubp->rmd160)) == 0 )
        {
            //printf("skip pubp since no rmd160\n");
            continue;
        }
        if ( pubp->timestamp < oldest )
            continue;
        bitcoin_address(coinaddr,basecoin->taddr,basecoin->pubtype,pubp->rmd160,sizeof(pubp->rmd160));
        minsatoshis = maxsatoshis = n = 0;
        ap = 0;
        if ( (price= pubp->matrix[baseid][relid]) > SMALLVAL )//&& pubp->timestamps[baseid][relid] >= oldest )
        {
            balance = 0;
            if ( (ap= LP_addressfind(basecoin,coinaddr)) != 0 )
            {
                n = LP_address_minmax(&balance,&minsatoshis,&maxsatoshis,ap);
                if ( polarity > 0 )
                {
                    balance *= price;
                    minsatoshis *= price;
                    maxsatoshis *= price;
                }
                //printf("%s/%s %s n.%d ap->n.%d %.8f\n",base,rel,coinaddr,n,ap->n,dstr(ap->total));
            }
            if ( (op= LP_orderbookentry(coinaddr,base,rel,polarity > 0 ? price : 1./price,n,minsatoshis,maxsatoshis,pubp->pubkey,pubp->timestamp,balance)) != 0 )
            {
                *arrayp = realloc(*arrayp,sizeof(*(*arrayp)) * (num+1));
                (*arrayp)[num++] = op;
            }
        }
        //printf("pubp.(%s) %.8f %p\n",coinaddr,price,ap);
    }
    return(num);
}

char *LP_orderbook(char *base,char *rel,int32_t duration)
{
    uint32_t now,i; uint64_t depth; struct LP_priceinfo *basepp=0,*relpp=0; struct LP_orderbookentry **bids = 0,**asks = 0; cJSON *retjson,*array; struct iguana_info *basecoin,*relcoin; int32_t n,numbids=0,numasks=0,cachenumbids,cachenumasks,baseid,relid,suppress_prefetch=0;
    basecoin = LP_coinfind(base);
    relcoin = LP_coinfind(rel);
    if ( basecoin == 0 || relcoin == 0 )
        return(clonestr("{\"error\":\"base or rel not added\"}"));
    if ( (basepp= LP_priceinfofind(base)) == 0 || (relpp= LP_priceinfofind(rel)) == 0 )
        return(clonestr("{\"error\":\"base or rel not added\"}"));
    if ( duration <= 0 )
    {
        if ( duration < 0 )
            suppress_prefetch = 1;
        duration = LP_ORDERBOOK_DURATION;
    }
    LP_pubkeys_query();
    baseid = basepp->ind;
    relid = relpp->ind;
    now = (uint32_t)time(NULL);
    basecoin->obooktime = now;
    relcoin->obooktime = now;
    cachenumbids = numbids, cachenumasks = numasks;
    //printf("start cache.(%d %d) numbids.%d numasks.%d\n",cachenumbids,cachenumasks,numbids,numasks);
    numasks = LP_orderbook_utxoentries(now,1,base,rel,&asks,numasks,cachenumasks,duration);
    numbids = LP_orderbook_utxoentries(now,-1,rel,base,&bids,numbids,cachenumbids,duration);
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    if ( numbids > 1 )
    {
        qsort(bids,numbids,sizeof(*bids),_revcmp_orderbook);
        depth = 0;
        for (i=0; i<numbids; i++)
        {
            depth += bids[i]->depth;
            bids[i]->depth = depth;
        }
    }
    if ( numasks > 1 )
    {
        qsort(asks,numasks,sizeof(*asks),_cmp_orderbook);
        depth = 0;
        for (i=0; i<numasks; i++)
        {
            depth += asks[i]->depth;
            asks[i]->depth = depth;
        }
    }
    for (i=n=0; i<numbids; i++)
    {
        jaddi(array,LP_orderbookjson(rel,bids[i]));
        if ( suppress_prefetch == 0 && n < 7 && bids[i]->numutxos == 0 )
        {
            //printf("bid ping %s %s\n",rel,bids[i]->coinaddr);
            LP_address(relcoin,bids[i]->coinaddr);
            if ( relcoin->electrum == 0 )
                LP_listunspent_issue(rel,bids[i]->coinaddr,0);
            LP_listunspent_query(rel,bids[i]->coinaddr);
            n++;
        }
        free(bids[i]);
        bids[i] = 0;
    }
    if ( n > 0 && relcoin->lastmonitor > 3600 )
        relcoin->lastmonitor -= 3600;
    jadd(retjson,"bids",array);
    jaddnum(retjson,"numbids",numbids);
    array = cJSON_CreateArray();
    for (i=n=0; i<numasks; i++)
    {
        jaddi(array,LP_orderbookjson(base,asks[i]));
        if ( suppress_prefetch == 0 && n < 7 && asks[i]->numutxos == 0 )
        {
            //printf("ask ping %s %s\n",base,asks[i]->coinaddr);
            LP_address(basecoin,asks[i]->coinaddr);
            if ( basecoin->electrum == 0 )
                LP_listunspent_issue(base,asks[i]->coinaddr,0);
            LP_listunspent_query(base,asks[i]->coinaddr);
            n++;
        }
        free(asks[i]);
        asks[i] = 0;
    }
    if ( n > 0 && basecoin->lastmonitor > 3600 )
        basecoin->lastmonitor -= 3600;
    jadd(retjson,"asks",array);
    jaddnum(retjson,"numasks",numasks);
    jaddstr(retjson,"base",base);
    jaddstr(retjson,"rel",rel);
    jaddnum(retjson,"timestamp",now);
    if ( bids != 0 )
        free(bids);
    if ( asks != 0 )
        free(asks);
    return(jprint(retjson,1));
}

uint64_t LP_KMDvalue(struct iguana_info *coin,uint64_t balance)
{
    cJSON *bids,*asks,*orderbook,*item; double bid=0,ask=0,price = 0.; int32_t numasks,numbids; char *retstr; uint64_t KMDvalue=0;
    if ( balance != 0 )
    {
        if ( strcmp(coin->symbol,"KMD") == 0 )
            KMDvalue = balance;
        else if ( (retstr= LP_orderbook(coin->symbol,"KMD",-1)) != 0 )
        {
            if ( (orderbook= cJSON_Parse(retstr)) != 0 )
            {
                if ( (asks= jarray(&numasks,orderbook,"asks")) != 0 && numasks > 0 )
                {
                    item = jitem(asks,0);
                    price = ask = jdouble(item,"price");
                    //printf("%s/%s ask %.8f\n",coin->symbol,"KMD",ask);
                }
                if ( (bids= jarray(&numbids,orderbook,"bids")) != 0 && numbids > 0 )
                {
                    item = jitem(asks,0);
                    bid = jdouble(item,"price");
                    if ( price == 0. )
                        price = bid;
                    else price = (bid + ask) * 0.5;
                    //printf("%s/%s bid %.8f ask %.8f price %.8f\n",coin->symbol,"KMD",bid,ask,price);
                }
                KMDvalue = price * balance;
                free_json(orderbook);
            }
            free(retstr);
        }
    }
    return(KMDvalue);
}

void LP_priceupdate(char *base,char *rel,double price,double avebid,double aveask,double highbid,double lowask,double PAXPRICES[32])
{
    LP_priceinfoupdate(base,rel,price);
}

void LP_pricefname(char *fname,char *base,char *rel)
{
    sprintf(fname,"%s/PRICES/%s_%s",GLOBAL_DBDIR,base,rel);
    OS_compatible_path(fname);
}

void LP_priceitemadd(cJSON *retarray,uint32_t timestamp,double avebid,double aveask,double highbid,double lowask)
{
    cJSON *item = cJSON_CreateArray();
    jaddinum(item,timestamp);
    jaddinum(item,avebid);
    jaddinum(item,aveask);
    jaddinum(item,highbid);
    jaddinum(item,lowask);
    jaddi(retarray,item);
}

cJSON *LP_pricearray(char *base,char *rel,uint32_t firsttime,uint32_t lasttime,int32_t timescale)
{
    cJSON *retarray; char askfname[1024],bidfname[1024]; uint64_t bidprice64,askprice64; uint32_t bidnow,asknow,bidi,aski,lastbidi,lastaski; int32_t numbids,numasks; double bidemit,askemit,bidsum,asksum,bid,ask,highbid,lowbid,highask,lowask,bidemit2,askemit2; FILE *askfp=0,*bidfp=0;
    if ( timescale <= 0 )
        timescale = 60;
    if ( lasttime == 0 )
        lasttime = (uint32_t)-1;
    LP_pricefname(askfname,base,rel);
    LP_pricefname(bidfname,rel,base);
    retarray = cJSON_CreateArray();
    lastbidi = lastaski = 0;
    numbids = numasks = 0;
    bidsum = asksum = askemit = bidemit = highbid = lowbid = highask = lowask = 0.;
    if ( (bidfp= fopen(bidfname,"rb")) != 0 && (askfp= fopen(askfname,"rb")) != 0 )
    {
        while ( bidfp != 0 || askfp != 0 )
        {
            bidi = aski = 0;
            bidemit = askemit = bidemit2 = askemit2 = 0.;
            if ( bidfp != 0 && fread(&bidnow,1,sizeof(bidnow),bidfp) == sizeof(bidnow) && fread(&bidprice64,1,sizeof(bidprice64),bidfp) == sizeof(bidprice64) )
            {
                //printf("bidnow.%u %.8f\n",bidnow,dstr(bidprice64));
                if ( bidnow != 0 && bidprice64 != 0 && bidnow >= firsttime && bidnow <= lasttime )
                {
                    bidi = bidnow / timescale;
                    if ( bidi != lastbidi )
                    {
                        if ( bidsum != 0. && numbids != 0 )
                        {
                            bidemit = bidsum / numbids;
                            bidemit2 = highbid;
                        }
                        bidsum = highbid = lowbid = 0.;
                        numbids = 0;
                    }
                    if ( (bid= 1. / dstr(bidprice64)) != 0. )
                    {
                        if ( bid > highbid )
                            highbid = bid;
                        if ( lowbid == 0. || bid < lowbid )
                            lowbid = bid;
                        bidsum += bid;
                        numbids++;
                        //printf("bidi.%u num.%d %.8f [%.8f %.8f]\n",bidi,numbids,bid,lowbid,highbid);
                    }
                }
            } else fclose(bidfp), bidfp = 0;
            if ( askfp != 0 && fread(&asknow,1,sizeof(asknow),askfp) == sizeof(asknow) && fread(&askprice64,1,sizeof(askprice64),askfp) == sizeof(askprice64) )
            {
                //printf("asknow.%u %.8f\n",asknow,dstr(askprice64));
                if ( asknow != 0 && askprice64 != 0 && asknow >= firsttime && asknow <= lasttime )
                {
                    aski = asknow / timescale;
                    if ( aski != lastaski )
                    {
                        if ( asksum != 0. && numasks != 0 )
                        {
                            askemit = asksum / numasks;
                            askemit2 = lowask;
                        }
                        asksum = highask = lowask = 0.;
                        numasks = 0;
                    }
                    if ( (ask= dstr(askprice64)) != 0. )
                    {
                        if ( ask > highask )
                            highask = ask;
                        if ( lowask == 0. || ask < lowask )
                            lowask = ask;
                        asksum += ask;
                        numasks++;
                        //printf("aski.%u num.%d %.8f [%.8f %.8f]\n",aski,numasks,ask,lowask,highask);
                    }
                }
            } else fclose(askfp), askfp = 0;
            if ( bidemit != 0. || askemit != 0. )
            {
                if ( bidemit != 0. && askemit != 0. && lastbidi == lastaski )
                {
                    LP_priceitemadd(retarray,lastbidi * timescale,bidemit,askemit,bidemit2,askemit2);
                    highbid = lowbid = highask = lowask = 0.;
                }
                else
                {
                    if ( bidemit != 0. )
                    {
                        printf("bidonly %.8f %.8f\n",bidemit,highbid);
                        LP_priceitemadd(retarray,lastbidi * timescale,bidemit,0.,bidemit2,0.);
                        highbid = lowbid = 0.;
                    }
                    if ( askemit != 0. )
                    {
                        printf("askonly %.8f %.8f\n",askemit,lowask);
                        LP_priceitemadd(retarray,lastaski * timescale,0.,askemit,0.,askemit2);
                        highask = lowask = 0.;
                    }
                }
            }
            if ( bidi != 0 )
                lastbidi = bidi;
            if ( aski != 0 )
                lastaski = aski;
        }
    } else printf("couldnt open either %s %p or %s %p\n",bidfname,bidfp,askfname,askfp);
    if ( bidfp != 0 )
        fclose(bidfp);
    if ( askfp != 0 )
        fclose(askfp);
    return(retarray);
}

void LP_pricefeedupdate(bits256 pubkey,char *base,char *rel,double price)
{
    struct LP_priceinfo *basepp,*relpp; uint32_t now; uint64_t price64; struct LP_pubkeyinfo *pubp; char str[65],fname[512]; FILE *fp;
    //printf("check PRICEFEED UPDATE.(%s/%s) %.8f %s\n",base,rel,price,bits256_str(str,pubkey));
    if ( LP_pricevalid(price) > 0 && (basepp= LP_priceinfofind(base)) != 0 && (relpp= LP_priceinfofind(rel)) != 0 )
    {
        //if ( (fp= basepp->fps[relpp->ind]) == 0 )
        {
            LP_pricefname(fname,base,rel);
            fp = OS_appendfile(fname); //basepp->fps[relpp->ind] =
        }
        if ( fp != 0 )
        {
            now = (uint32_t)time(NULL);
            price64 = price * SATOSHIDEN;
            fwrite(&now,1,sizeof(now),fp);
            fwrite(&price64,1,sizeof(price64),fp);
            fclose(fp);
        }
        //if ( (fp= relpp->fps[basepp->ind]) == 0 )
        {
            sprintf(fname,"%s/PRICES/%s_%s",GLOBAL_DBDIR,rel,base);
            fp = OS_appendfile(fname); //relpp->fps[basepp->ind] =
        }
        if ( fp != 0 )
        {
            now = (uint32_t)time(NULL);
            price64 = (1. / price) * SATOSHIDEN;
            fwrite(&now,1,sizeof(now),fp);
            fwrite(&price64,1,sizeof(price64),fp);
            fclose(fp);
        }
        if ( (pubp= LP_pubkeyadd(pubkey)) != 0 )
        {
            if ( (rand() % 1000) == 0 )
                printf("PRICEFEED UPDATE.(%-6s/%6s) %12.8f %s %12.8f\n",base,rel,price,bits256_str(str,pubkey),1./price);
            pubp->timestamp = (uint32_t)time(NULL);
            if ( fabs(pubp->matrix[basepp->ind][relpp->ind] - price) > SMALLVAL )
            {
                pubp->matrix[basepp->ind][relpp->ind] = price;
                //pubp->timestamps[basepp->ind][relpp->ind] = pubp->timestamp;
                dxblend(&basepp->relvals[relpp->ind],price,0.9);
                dxblend(&relpp->relvals[basepp->ind],1. / price,0.9);
            }
        } else printf("error finding pubkey entry %s, ok if rare\n",bits256_str(str,pubkey));
    }
    //else if ( (rand() % 100) == 0 )
    //    printf("error finding %s/%s %.8f\n",base,rel,price);
}

