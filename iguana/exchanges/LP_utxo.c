
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
//  LP_utxo.c
//  marketmaker
//

uint64_t LP_value_extract(cJSON *obj,int32_t addinterest)
{
    double val = 0.; uint64_t value = 0; int32_t electrumflag;
    electrumflag = (jobj(obj,"tx_hash") != 0);
    if ( electrumflag == 0 )
    {
        if ( (val= jdouble(obj,"amount")) < SMALLVAL )
            val = jdouble(obj,"value");
        value = (val + 0.0000000049) * SATOSHIDEN;
    } else value = j64bits(obj,"value");
    if ( value != 0 )
    {
        if ( addinterest != 0 && jobj(obj,"interest") != 0 )
            value += (jdouble(obj,"interest") * SATOSHIDEN);
    }
    return(value);
}

int32_t LP_destaddr(char *destaddr,cJSON *item)
{
    int32_t m,retval = -1; cJSON *addresses,*skey; char *addr;
    if ( (skey= jobj(item,"scriptPubKey")) != 0 && (addresses= jarray(&m,skey,"addresses")) != 0 )
    {
        item = jitem(addresses,0);
        if ( (addr= jstr(item,0)) != 0 )
        {
            safecopy(destaddr,addr,64);
            retval = 0;
        }
        //printf("item.(%s) -> dest.(%s)\n",jprint(item,0),destaddr);
    }
    return(retval);
}

int32_t LP_txdestaddr(char *destaddr,bits256 txid,int32_t vout,cJSON *txobj)
{
    int32_t n,retval = -1; cJSON *vouts;
    if ( (vouts= jarray(&n,txobj,"vout")) != 0 && vout < n )
        retval = LP_destaddr(destaddr,jitem(vouts,vout));
    return(retval);
}

struct LP_address *_LP_address(struct iguana_info *coin,char *coinaddr)
{
    struct LP_address *ap = 0;
    if ( (ap= _LP_addressfind(coin,coinaddr)) == 0 )
        ap = _LP_addressadd(coin,coinaddr);
    return(ap);
}

struct LP_address *LP_addressfind(struct iguana_info *coin,char *coinaddr)
{
    struct LP_address *ap = 0;
    if ( coin != 0 )
    {
        portable_mutex_lock(&coin->addrmutex);
        ap = _LP_addressfind(coin,coinaddr);
        portable_mutex_unlock(&coin->addrmutex);
    }
    return(ap);
}

struct LP_address *LP_address(struct iguana_info *coin,char *coinaddr)
{
    struct LP_address *ap = 0;
    if ( coin != 0 )
    {
        portable_mutex_lock(&coin->addrmutex);
        ap = _LP_address(coin,coinaddr);
        portable_mutex_unlock(&coin->addrmutex);
    }
    return(ap);
}

int32_t LP_address_minmax(uint64_t *balancep,uint64_t *minp,uint64_t *maxp,struct LP_address *ap)
{
    struct LP_address_utxo *up,*tmp; int32_t n = 0;
    *minp = *maxp = *balancep = 0;
    DL_FOREACH_SAFE(ap->utxos,up,tmp)
    {
        if ( up->spendheight <= 0 )
        {
            if ( up->U.value > *maxp )
                *maxp = up->U.value;
            if ( *minp == 0 || up->U.value < *minp )
                *minp = up->U.value;
            *balancep += up->U.value;
            n++;
        }
    }
    if ( 0 && n > 0 )
        printf("n.%d %s min %.8f max %.8f\n",n,ap->coinaddr,dstr(*minp),dstr(*maxp));
    return(n);
}

struct LP_utxoinfo *LP_allocated(bits256 txid,int32_t vout)
{
    struct LP_utxoinfo *utxo;
    if ( (utxo= _LP_utxofind(0,txid,vout)) != 0 && LP_isavailable(utxo) == 0 )
    {
        char str[65]; printf("%s/v%d not available\n",bits256_str(str,txid),vout);
        return(utxo);
    }
    if ( (utxo= _LP_utxo2find(0,txid,vout)) != 0 && LP_isavailable(utxo) == 0 )
    {
        char str[65]; printf("%s/v%d not available2\n",bits256_str(str,txid),vout);
        return(utxo);
    }
    if ( (utxo= _LP_utxofind(1,txid,vout)) != 0 && LP_isavailable(utxo) == 0 )
    {
        char str[65]; printf("%s/v%d not available\n",bits256_str(str,txid),vout);
        return(utxo);
    }
    if ( (utxo= _LP_utxo2find(1,txid,vout)) != 0 && LP_isavailable(utxo) == 0 )
    {
        char str[65]; printf("%s/v%d not available2\n",bits256_str(str,txid),vout);
        return(utxo);
    }
    return(0);
}

int32_t LP_address_utxo_ptrs(struct iguana_info *coin,int32_t iambob,struct LP_address_utxo **utxos,int32_t max,struct LP_address *ap,char *coinaddr)
{
    struct LP_address_utxo *up,*tmp; struct LP_transaction *tx; cJSON *txout; int32_t n = 0; char str[65];
    //printf("LP_address_utxo_ptrs for (%s).(%s)\n",ap->coinaddr,coinaddr);
    if ( strcmp(ap->coinaddr,coinaddr) != 0 )
        printf("UNEXPECTED coinaddr mismatch (%s) != (%s)\n",ap->coinaddr,coinaddr);
    portable_mutex_lock(&LP_utxomutex);
    DL_FOREACH_SAFE(ap->utxos,up,tmp)
    {
        //char str[65]; printf("LP_address_utxo_ptrs %s n.%d %.8f %s v%d spendheight.%d allocated.%p\n",ap->coinaddr,n,dstr(up->U.value),bits256_str(str,up->U.txid),up->U.vout,up->spendheight,LP_allocated(up->U.txid,up->U.vout));
        if ( up->spendheight <= 0 && LP_RTmetrics_avoidtxid(up->U.txid) < 0 )
        {
            if ( coin->electrum == 0 )
            {
                if ( (txout= LP_gettxout(coin->symbol,coinaddr,up->U.txid,up->U.vout)) != 0 )
                {
                    if ( LP_value_extract(txout,0) == 0 )
                    {
                        printf("LP_address_utxo_ptrs skip zero value %s/v%d\n",bits256_str(str,up->U.txid),up->U.vout);
                        free_json(txout);
                        up->spendheight = 1;
                        if ( (tx= LP_transactionfind(coin,up->U.txid)) != 0 && up->U.vout < tx->numvouts )
                            tx->outpoints[up->U.vout].spendheight = 1;
                        continue;
                    }
                    free_json(txout);
                }
                else
                {
                    //printf("LP_address_utxo_ptrs skips %s %s payment %s/v%d is spent\n",coin->symbol,coinaddr,bits256_str(str,up->U.txid),up->U.vout);
                    up->spendheight = 1;
                    if ( (tx= LP_transactionfind(coin,up->U.txid)) != 0 && up->U.vout < tx->numvouts )
                        tx->outpoints[up->U.vout].spendheight = 1;
                    continue;
                }
            }
            else
            {
                if ( up->SPV <= 0 || up->U.height == 0 )
                {
                    printf("LP_address_utxo_ptrs skips %s/v%u due to SPV.%d ht.%d\n",bits256_str(str,up->U.txid),up->U.vout,up->SPV,up->U.height);
                    if ( (tx= LP_transactionfind(coin,up->U.txid)) != 0 && up->U.vout < tx->numvouts )
                        tx->outpoints[up->U.vout].spendheight = 1;
                    continue;
                }
            }
            if ( LP_allocated(up->U.txid,up->U.vout) == 0 )
            {
                utxos[n++] = up;
                if ( n >= max )
                    break;
            }
        }
        else
        {
            if ( (tx= LP_transactionfind(coin,up->U.txid)) != 0 && up->U.vout < tx->numvouts )
                tx->outpoints[up->U.vout].spendheight = 1;
        }
    }
    portable_mutex_unlock(&LP_utxomutex);
    //printf("return n.%d\n",n);
    return(n);
}

struct LP_address_utxo *LP_address_utxofind(struct iguana_info *coin,char *coinaddr,bits256 txid,int32_t vout)
{
    struct LP_address *ap; struct LP_address_utxo *up,*tmp;
    //printf("LP_address_utxofind %s add addr.%s\n",coin->symbol,coinaddr);
    if ( (ap= _LP_address(coin,coinaddr)) != 0 )
    {
        DL_FOREACH_SAFE(ap->utxos,up,tmp)
        {
            if ( vout == up->U.vout && bits256_cmp(up->U.txid,txid) == 0 )
                return(up);
        }
    }
    return(0);
}

void LP_mark_spent(char *symbol,bits256 txid,int32_t vout)
{
    struct iguana_info *coin; struct LP_transaction *tx; struct LP_address_utxo *up;
    if ( (coin= LP_coinfind(symbol)) != 0 )
    {
        if ( (tx= LP_transactionfind(coin,txid)) != 0 )
        {
            if ( vout < tx->numvouts )
            {
                tx->outpoints[vout].spendheight = 1;
                if ( (up= LP_address_utxofind(coin,tx->outpoints[vout].coinaddr,txid,vout)) != 0 )
                    up->spendheight = 1;
            }
        }
    }
}

int32_t LP_address_utxoadd(char *debug,struct iguana_info *coin,char *coinaddr,bits256 txid,int32_t vout,uint64_t value,int32_t height,int32_t spendheight)
{
    struct LP_address *ap; cJSON *txobj; struct LP_address_utxo *up,*tmp; int32_t flag,retval = 0; char str[65];
    if ( coin == 0 )
        return(0);
    if ( spendheight > 0 ) // dont autocreate entries for spends we dont care about
        ap = LP_addressfind(coin,coinaddr);
    else ap = LP_address(coin,coinaddr);
    //printf("%s add addr.%s ht.%d ap.%p\n",coin->symbol,coinaddr,height,ap);
    if ( ap != 0 )
    {
        flag = 0;
        DL_FOREACH_SAFE(ap->utxos,up,tmp)
        {
            if ( vout == up->U.vout && bits256_cmp(up->U.txid,txid) == 0 )
            {
                flag = 1;
                if ( height > 0 && up->U.height != height )
                    up->U.height = height, flag |= 2;
                if ( spendheight > 0 && up->spendheight != spendheight )
                    up->spendheight = spendheight, flag |= 4;
                if ( value != 0 && up->U.value == 0 && up->U.value != value )
                    up->U.value = value, flag |= 8;
//printf("found >>>>>>>>>> %s %s %s/v%d ht.%d %.8f\n",coin->symbol,coinaddr,bits256_str(str,txid),vout,height,dstr(value));
                break;
            }
        }
        if ( flag == 0 && value != 0 )
        {
            if ( coin->electrum == 0 )
            {
                if ( (txobj= LP_gettxout(coin->symbol,coinaddr,txid,vout)) == 0 )
                {
                    //printf("prevent utxoadd since gettxout %s %s %s/v%d missing\n",coin->symbol,coinaddr,bits256_str(str,txid),vout);
                    return(0);
                } else free_json(txobj);
            }
            up = calloc(1,sizeof(*up));
            up->U.txid = txid;
            up->U.vout = vout;
            up->U.height = height;
            up->U.value = value;
            up->spendheight = spendheight;
            portable_mutex_lock(&coin->addrmutex);
            DL_APPEND(ap->utxos,up);
            portable_mutex_unlock(&coin->addrmutex);                
            retval = 1;
            if ( value == 0 )
                printf("%s ADD UTXO >> %s %s %s/v%d ht.%d %.8f\n",debug,coin->symbol,coinaddr,bits256_str(str,txid),vout,height,dstr(value));
        }
    } // else printf("cant get ap %s %s\n",coin->symbol,coinaddr);
    //printf("done %s add addr.%s ht.%d\n",coin->symbol,coinaddr,height);
    return(retval);
}

cJSON *LP_address_item(struct iguana_info *coin,struct LP_address_utxo *up,int32_t electrumret)
{
    cJSON *item = cJSON_CreateObject();
    if ( electrumret == 0 )
    {
        jaddbits256(item,"txid",up->U.txid);
        jaddnum(item,"vout",up->U.vout);
        if ( up->U.height > 0 )
            jaddnum(item,"confirmations",LP_getheight(coin) - up->U.height + 1);
        jaddnum(item,"amount",dstr(up->U.value));
        jaddstr(item,"scriptPubKey","");
    }
    else
    {
        jaddbits256(item,"tx_hash",up->U.txid);
        jaddnum(item,"tx_pos",up->U.vout);
        jaddnum(item,"height",up->U.height);
        jadd64bits(item,"value",up->U.value);
        if ( up->U.value == 0 )
            printf("ERROR LP_address_item illegal.(%s)\n",jprint(item,0));
    }
    return(item);
}

uint64_t _LP_unspents_metric(uint64_t total,int32_t n) { return((total<<16) | (n & 0xffff)); }

bits256 iguana_merkle(bits256 *tree,int32_t txn_count)
{
    int32_t i,n=0,prev; uint8_t serialized[sizeof(bits256) * 2];
    if ( txn_count == 1 )
        return(tree[0]);
    prev = 0;
    while ( txn_count > 1 )
    {
        if ( (txn_count & 1) != 0 )
            tree[prev + txn_count] = tree[prev + txn_count-1], txn_count++;
        n += txn_count;
        for (i=0; i<txn_count; i+=2)
        {
            iguana_rwbignum(1,serialized,sizeof(*tree),tree[prev + i].bytes);
            iguana_rwbignum(1,&serialized[sizeof(*tree)],sizeof(*tree),tree[prev + i + 1].bytes);
            tree[n + (i >> 1)] = bits256_doublesha256(0,serialized,sizeof(serialized));
        }
        prev = n;
        txn_count >>= 1;
    }
    return(tree[n]);
}

bits256 validate_merkle(int32_t pos,bits256 txid,cJSON *proofarray,int32_t proofsize)
{
    int32_t i; uint8_t serialized[sizeof(bits256) * 2]; bits256 hash,proof;
    hash = txid;
    for (i=0; i<proofsize; i++)
    {
        proof = jbits256i(proofarray,i);
        if ( (pos & 1) == 0 )
        {
            iguana_rwbignum(1,&serialized[0],sizeof(hash),hash.bytes);
            iguana_rwbignum(1,&serialized[sizeof(hash)],sizeof(proof),proof.bytes);
        }
        else
        {
            iguana_rwbignum(1,&serialized[0],sizeof(proof),proof.bytes);
            iguana_rwbignum(1,&serialized[sizeof(hash)],sizeof(hash),hash.bytes);
        }
        hash = bits256_doublesha256(0,serialized,sizeof(serialized));
        pos >>= 1;
    }
    return(hash);
}

bits256 LP_merkleroot(struct iguana_info *coin,struct electrum_info *ep,int32_t height)
{
    cJSON *hdrobj; bits256 merkleroot;
    memset(merkleroot.bytes,0,sizeof(merkleroot));
    if ( coin->cachedmerkleheight == height )
        return(coin->cachedmerkle);
    if ( (hdrobj= electrum_getheader(coin->symbol,ep,&hdrobj,height)) != 0 )
    {
        if ( jobj(hdrobj,"merkle_root") != 0 )
        {
            merkleroot = jbits256(hdrobj,"merkle_root");
            if ( bits256_nonz(merkleroot) != 0 )
            {
                coin->cachedmerkle = merkleroot;
                coin->cachedmerkleheight = height;
            }
        }
        free_json(hdrobj);
    } else printf("couldnt get header for ht.%d\n",height);
    return(merkleroot);
}

int32_t LP_merkleproof(struct iguana_info *coin,struct electrum_info *ep,bits256 txid,int32_t height)
{
    cJSON *merkobj,*merkles; bits256 roothash,merkleroot; int32_t m,SPV = 0;
    if ( (merkobj= electrum_getmerkle(coin->symbol,ep,&merkobj,txid,height)) != 0 )
    {
        char str[65],str2[65],str3[65];
        SPV = -1;
        memset(roothash.bytes,0,sizeof(roothash));
        if ( (merkles= jarray(&m,merkobj,"merkle")) != 0 )
        {
            roothash = validate_merkle(jint(merkobj,"pos"),txid,merkles,m);
            merkleroot = LP_merkleroot(coin,ep,height);
            if ( bits256_nonz(merkleroot) != 0 )
            {
                if ( bits256_cmp(merkleroot,roothash) == 0 )
                {
                    SPV = height;
                    //printf("validated MERK %s ht.%d -> %s root.(%s)\n",bits256_str(str,up->U.txid),up->U.height,jprint(merkobj,0),bits256_str(str2,roothash));
                }
                else printf("ERROR MERK %s ht.%d -> %s root.(%s) vs %s\n",bits256_str(str,txid),height,jprint(merkobj,0),bits256_str(str2,roothash),bits256_str(str3,merkleroot));
            } else SPV = 0;
        }
        if ( SPV < 0 )
        {
            printf("MERKLE DIDNT VERIFY.%s %s ht.%d (%s)\n",coin->symbol,bits256_str(str,txid),height,jprint(merkobj,0));
            if ( jobj(merkobj,"error") != 0 )
                SPV = 0; // try again later
        }
        free_json(merkobj);
    }
    return(SPV);
}

cJSON *LP_address_utxos(struct iguana_info *coin,char *coinaddr,int32_t electrumret)
{
    cJSON *array,*item; int32_t n; uint64_t total; struct LP_address *ap=0,*atmp; struct LP_address_utxo *up,*tmp; cJSON *txobj; 
    array = cJSON_CreateArray();
    if ( coinaddr != 0 && coinaddr[0] != 0 )
    {
        //portable_mutex_lock(&coin->addrmutex);
        if ( (ap= _LP_addressfind(coin,coinaddr)) != 0 )
        {
            total = n = 0;
            DL_FOREACH_SAFE(ap->utxos,up,tmp)
            {
                if ( up->spendheight <= 0 && up->U.height > 0 )
                {
                    if ( coin->electrum == 0 )
                    {
                        if ( (txobj= LP_gettxout(coin->symbol,coinaddr,up->U.txid,up->U.vout)) == 0 )
                            up->spendheight = 1;
                        else free_json(txobj);
                    }
                    if ( up->spendheight <= 0 && up->U.value != 0 )
                    {
                        if ( coin->electrum == 0 || up->SPV > 0 )
                        {
                            jaddi(array,LP_address_item(coin,up,electrumret));
                            n++;
                            total += up->U.value;
                        }
                    }
                    //printf("new array %s\n",jprint(array,0));
                }
            }
            ap->total = total;
            ap->n = n;
        }
        //portable_mutex_unlock(&coin->addrmutex);
    }
    else
    {
        HASH_ITER(hh,coin->addresses,ap,atmp)
        {
            if ( ap->total > 0 && ap->n > 0 )
            {
                item = cJSON_CreateObject();
                jadd64bits(item,ap->coinaddr,_LP_unspents_metric(ap->total,ap->n));
                jaddi(array,item);
            }
        }
    }
    //printf("%s %s utxos.(%s) ap.%p\n",coin->symbol,coinaddr,jprint(array,0),ap);
    return(array);
}

cJSON *LP_address_balance(struct iguana_info *coin,char *coinaddr,int32_t electrumret)
{
    cJSON *array,*retjson; int32_t i,n; uint64_t balance = 0;
    if ( (array= LP_address_utxos(coin,coinaddr,1)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
                balance += j64bits(jitem(array,i),"value");
        }
    }
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jaddstr(retjson,"coin",coin->symbol);
    jaddstr(retjson,"address",coinaddr);
    jaddnum(retjson,"balance",dstr(balance));
    return(retjson);
}

int32_t LP_unspents_array(struct iguana_info *coin,char *coinaddr,cJSON *array)
{
    int32_t i,n,v,ht,errs,height,count=0; uint64_t value,val; cJSON *item,*txobj; bits256 txid;
    if ( (n= cJSON_GetArraySize(array)) <= 0 )
        return(0);
    //printf("%s %s LP_unspents.(%s)\n",coin->symbol,coinaddr,jprint(array,0));
    for (i=0; i<n; i++)
    {
        errs = 0;
        item = jitem(array,i);
        txid = jbits256(item,"tx_hash");
        v = jint(item,"tx_pos");
        height = jint(item,"height");
        val = j64bits(item,"value");
        if ( coin->electrum == 0 && (txobj= LP_gettxout(coin->symbol,coinaddr,txid,v)) != 0 )
        {
            value = LP_value_extract(txobj,0);
            if ( value != 0 && value != val )
            {
                char str[65]; printf("REJECT %s %s/v%d value.%llu vs %llu (%s)\n",coin->symbol,bits256_str(str,txid),v,(long long)value,(long long)val,jprint(txobj,0));
                errs++;
            }
            ht = LP_txheight(coin,txid);
            //if ( coin->height != 0 )
            //    ht = LP_getheight(coin) - jint(txobj,"confirmations") + 1;
            //else ht = 0;
            /*if  ( ht != 0 && ht < height-2 )
             {
             printf("REJECT %s %s/v%d ht.%d vs %d confs.%d (%s)\n",symbol,bits256_str(str,txid),v,ht,height,jint(txobj,"confirmations"),jprint(item,0));
             errs++;
             }*/
            free_json(txobj);
        }
        if ( errs == 0 )
        {
            //printf("from LP_unspents_array\n");
            LP_address_utxoadd("LP_unspents_array",coin,coinaddr,txid,v,val,height,-1);
            count++;
        }
    }
    return(count);
}

void LP_utxosetkey(uint8_t *key,bits256 txid,int32_t vout)
{
    memcpy(key,txid.bytes,sizeof(txid));
    memcpy(&key[sizeof(txid)],&vout,sizeof(vout));
}

struct LP_utxoinfo *_LP_utxofind(int32_t iambob,bits256 txid,int32_t vout)
{
    struct LP_utxoinfo *utxo=0; uint8_t key[sizeof(txid) + sizeof(vout)];
    /*if ( iambob != 0 )
    {
        static uint32_t counter;
        if ( counter++ < 3 )
            printf("_LP_utxofind deprecated iambob\n");
        return(0);
    }*/
    LP_utxosetkey(key,txid,vout);
    HASH_FIND(hh,G.LP_utxoinfos[iambob],key,sizeof(key),utxo);
    return(utxo);
}

struct LP_utxoinfo *_LP_utxo2find(int32_t iambob,bits256 txid2,int32_t vout2)
{
    struct LP_utxoinfo *utxo=0; uint8_t key2[sizeof(txid2) + sizeof(vout2)];
    /*if ( iambob != 0 )
    {
        printf("_LP_utxo2find deprecated iambob\n");
        return(0);
    }*/
    LP_utxosetkey(key2,txid2,vout2);
    HASH_FIND(hh2,G.LP_utxoinfos2[iambob],key2,sizeof(key2),utxo);
    return(utxo);
}

struct LP_utxoinfo *LP_utxofind(int32_t iambob,bits256 txid,int32_t vout)
{
    struct LP_utxoinfo *utxo=0;
    /*if ( iambob != 0 )
    {
        printf("LP_utxofind deprecated iambob\n");
        return(0);
    }*/
    portable_mutex_lock(&LP_utxomutex);
    utxo = _LP_utxofind(iambob,txid,vout);
    portable_mutex_unlock(&LP_utxomutex);
    return(utxo);
}

struct LP_utxoinfo *LP_utxo2find(int32_t iambob,bits256 txid2,int32_t vout2)
{
    struct LP_utxoinfo *utxo=0;
    /*if ( iambob != 0 )
    {
        printf("LP_utxo2find deprecated iambob\n");
        return(0);
    }*/
    portable_mutex_lock(&LP_utxomutex);
    utxo = _LP_utxo2find(iambob,txid2,vout2);
    portable_mutex_unlock(&LP_utxomutex);
    return(utxo);
}

struct LP_transaction *LP_transactionfind(struct iguana_info *coin,bits256 txid)
{
    struct LP_transaction *tx;
    portable_mutex_lock(&coin->txmutex);
    HASH_FIND(hh,coin->transactions,txid.bytes,sizeof(txid),tx);
    portable_mutex_unlock(&coin->txmutex);
    return(tx);
}

struct LP_transaction *LP_transactionadd(struct iguana_info *coin,bits256 txid,int32_t height,int32_t numvouts,int32_t numvins)
{
    struct LP_transaction *tx; int32_t i;
    if ( (tx= LP_transactionfind(coin,txid)) == 0 )
    {
        //char str[65]; printf("%s ht.%d u.%u NEW TXID.(%s) vouts.[%d]\n",coin->symbol,height,timestamp,bits256_str(str,txid),numvouts);
        //if ( bits256_nonz(txid) == 0 && tx->height == 0 )
        //    getchar();
        tx = calloc(1,sizeof(*tx) + (sizeof(*tx->outpoints) * numvouts));
        for (i=0; i<numvouts; i++)
            tx->outpoints[i].spendvini = -1;
        tx->height = height;
        tx->numvouts = numvouts;
        tx->numvins = numvins;
        //tx->timestamp = timestamp;
        tx->txid = txid;
        portable_mutex_lock(&coin->txmutex);
        HASH_ADD_KEYPTR(hh,coin->transactions,tx->txid.bytes,sizeof(tx->txid),tx);
        portable_mutex_unlock(&coin->txmutex);
    } // else printf("warning adding already existing txid %s\n",bits256_str(str,tx->txid));
    return(tx);
}

cJSON *LP_transactioninit(struct iguana_info *coin,bits256 txid,int32_t iter,cJSON *txobj)
{
    struct LP_transaction *tx; int32_t i,height,numvouts,numvins,spentvout; cJSON *vins,*vouts,*vout,*vin; bits256 spenttxid; char str[65];
    if ( coin->inactive != 0 )
        return(0);
    if ( txobj != 0 || (txobj= LP_gettx(coin->symbol,txid)) != 0 )
    {
        if ( coin->electrum == 0 )
            height = LP_txheight(coin,txid);
        else height = -1;
        vins = jarray(&numvins,txobj,"vin");
        vouts = jarray(&numvouts,txobj,"vout");
        // maybe filter so only addresses we care about are using RAM
        if ( iter == 0 && vouts != 0 && (tx= LP_transactionadd(coin,txid,height,numvouts,numvins)) != 0 )
        {
            //printf("create txid %s numvouts.%d numvins.%d\n",bits256_str(str,txid),numvouts,numvins);
            for (i=0; i<numvouts; i++)
            {
                vout = jitem(vouts,i);
                tx->outpoints[i].value = LP_value_extract(vout,0);
                tx->outpoints[i].interest = SATOSHIDEN * jdouble(vout,"interest");
                LP_destaddr(tx->outpoints[i].coinaddr,vout);
                //printf("from transaction init %s %s %s/v%d <- %.8f\n",coin->symbol,tx->outpoints[i].coinaddr,bits256_str(str,txid),i,dstr(tx->outpoints[i].value));
                LP_address_utxoadd("LP_transactioninit iter0",coin,tx->outpoints[i].coinaddr,txid,i,tx->outpoints[i].value,height,-1);
            }
            //printf("numvouts.%d\n",numvouts);
        }
        if ( iter == 1 && vins != 0 )
        {
            for (i=0; i<numvins; i++)
            {
                vin = jitem(vins,i);
                spenttxid = jbits256(vin,"txid");
                spentvout = jint(vin,"vout");
                if ( i == 0 && bits256_nonz(spenttxid) == 0 )
                    continue;
                if ( (tx= LP_transactionfind(coin,spenttxid)) != 0 )
                {
                    if ( spentvout < tx->numvouts )
                    {
                        if ( tx->outpoints[spentvout].spendheight <= 0 )
                        {
                            tx->outpoints[spentvout].spendtxid = txid;
                            tx->outpoints[spentvout].spendvini = i;
                            tx->outpoints[spentvout].spendheight = height > 0 ? height : 1;
                            LP_address_utxoadd("LP_transactioninit iter1",coin,tx->outpoints[spentvout].coinaddr,spenttxid,spentvout,tx->outpoints[spentvout].value,-1,height>0?height:1);
                            if ( 0 && strcmp(coin->symbol,"REVS") == 0 )
                                printf("spend %s %s/v%d at ht.%d\n",coin->symbol,bits256_str(str,tx->txid),spentvout,height);
                        }
                    } else printf("LP_transactioninit: %s spentvout.%d < numvouts.%d spendheight.%d\n",bits256_str(str,spenttxid),spentvout,tx->numvouts,tx->outpoints[spentvout].spendheight);
                } //else printf("LP_transactioninit: couldnt find (%s) ht.%d %s\n",bits256_str(str,spenttxid),height,jprint(vin,0));
                if ( bits256_cmp(spenttxid,txid) == 0 )
                    printf("spending same tx's %p vout ht.%d %s.[%d] s%d\n",tx,height,bits256_str(str,txid),tx!=0?tx->numvouts:0,spentvout);
            }
        }
        return(txobj);
    } //else printf("LP_transactioninit error for %s %s\n",coin->symbol,bits256_str(str,txid));
    return(0);
}

int32_t LP_txheight(struct iguana_info *coin,bits256 txid)
{
    bits256 blockhash; struct LP_transaction *tx; cJSON *blockobj,*txobj; int32_t height = 0;
    if ( coin == 0 )
        return(-1);
    if ( coin->electrum == 0 )
    {
        if ( (txobj= LP_gettx(coin->symbol,txid)) != 0 )
        {
            //*timestampp = juint(txobj,"locktime");
            //*blocktimep = juint(txobj,"blocktime");
            blockhash = jbits256(txobj,"blockhash");
            if ( bits256_nonz(blockhash) != 0 && (blockobj= LP_getblock(coin->symbol,blockhash)) != 0 )
            {
                height = jint(blockobj,"height");
                //char str[65];
                //if ( strcmp(coin->symbol,"CHIPS") != 0 && strcmp(coin->symbol,"BTC") != 0 )
                //    printf("%s %s LP_txheight.%d\n",coin->symbol,bits256_str(str,txid),height);
                free_json(blockobj);
            } // else printf("%s LP_txheight error (%s)\n",coin->symbol,jprint(txobj,0)); likely just unconfirmed
            free_json(txobj);
        }
    }
    else
    {
        if ( (tx= LP_transactionfind(coin,txid)) != 0 )
            height = tx->height;
    }
    return(height);
}

int32_t LP_numconfirms(char *symbol,char *coinaddr,bits256 txid,int32_t vout,int32_t mempool)
{
    struct iguana_info *coin; int32_t ht,numconfirms = 100;
    cJSON *txobj;
    if ( (coin= LP_coinfind(symbol)) == 0 || coin->inactive != 0 )
        return(-1);
    if ( coin->electrum == 0 )
    {
        numconfirms = -1;
        if ( (txobj= LP_gettxout(symbol,coinaddr,txid,vout)) != 0 )
        {
            numconfirms = jint(txobj,"confirmations");
            free_json(txobj);
        }
        else if ( mempool != 0 && LP_mempoolscan(symbol,txid) >= 0 )
            numconfirms = 0;
    }
    else
    {
        LP_listunspent_issue(symbol,coinaddr,1);
        if ( (ht= LP_txheight(coin,txid)) > 0 && ht <= coin->height )
            numconfirms = (LP_getheight(coin) - ht + 1);
        else if ( mempool != 0 )
        {
            if ( LP_waitmempool(symbol,coinaddr,txid,vout,30) >= 0 )
                numconfirms = 0;
        }
    }
    return(numconfirms);
}

uint64_t LP_txinterestvalue(uint64_t *interestp,char *destaddr,struct iguana_info *coin,bits256 txid,int32_t vout)
{
    uint64_t interest,value = 0; cJSON *txobj;
    *interestp = 0;
    destaddr[0] = 0;
    if ( (txobj= LP_gettxout(coin->symbol,destaddr,txid,vout)) != 0 )
    {
        if ( (value= LP_value_extract(txobj,0)) == 0 )
        {
            char str[65]; printf("%s LP_txvalue.%s strange utxo.(%s) vout.%d\n",coin->symbol,bits256_str(str,txid),jprint(txobj,0),vout);
        }
        else if ( strcmp(coin->symbol,"KMD") == 0 )
        {
            if ( coin->electrum == 0 )
            {
                if ((interest= jdouble(txobj,"interest")) != 0. )
                {
                    //printf("add interest of %.8f to %.8f\n",interest,dstr(value));
                    *interestp = SATOSHIDEN * interest;
                }
            } else *interestp = LP_komodo_interest(txid,value);
        }
        LP_destaddr(destaddr,txobj);
        //char str[65]; printf("dest.(%s) %.8f <- %s.(%s) txobj.(%s)\n",destaddr,dstr(value),coin->symbol,bits256_str(str,txid),jprint(txobj,0));
        free_json(txobj);
    } //else { char str[65]; printf("null gettxout return %s/v%d\n",bits256_str(str,txid),vout); }
    return(value);
}

int64_t basilisk_txvalue(char *symbol,bits256 txid,int32_t vout)
{
    char destaddr[64]; uint64_t value,interest = 0; struct iguana_info *coin;
    if ( (coin= LP_coinfind(symbol)) == 0 || coin->inactive != 0 )
        return(0);
    //char str[65]; printf("%s txvalue.(%s)\n",symbol,bits256_str(str,txid));
    value = LP_txinterestvalue(&interest,destaddr,coin,txid,vout);
    return(value + interest);
}

uint64_t LP_txvalue(char *coinaddr,char *symbol,bits256 txid,int32_t vout)
{
    struct LP_transaction *tx; cJSON *txobj=0; struct iguana_info *coin;
    if ( bits256_nonz(txid) == 0 )
        return(0);
    if ( (coin= LP_coinfind(symbol)) == 0 || coin->inactive != 0 )
        return(0);
    if ( coinaddr != 0 )
        coinaddr[0] = 0;
    if ( (tx= LP_transactionfind(coin,txid)) == 0 )
    {
        txobj = LP_transactioninit(coin,txid,0,0);
        txobj = LP_transactioninit(coin,txid,1,txobj);
        if ( txobj != 0 )
            free_json(txobj);
        tx = LP_transactionfind(coin,txid);
    }
    if ( tx != 0 )
    {
        if ( vout < tx->numvouts )
        {
            /*if ( bits256_nonz(tx->outpoints[vout].spendtxid) != 0 )
            {
                //printf("LP_txvalue %s/v%d is spent at %s\n",bits256_str(str,txid),vout,bits256_str(str2,tx->outpoints[vout].spendtxid));
                return(0);
            }
            else
            {
                if ( coinaddr != 0 )
                {
                    //if ( tx->outpoints[vout].coinaddr[0] == 0 )
                    //    tx->outpoints[vout].value = LP_txinterestvalue(&tx->outpoints[vout].interest,tx->outpoints[vout].coinaddr,coin,txid,vout);
                    strcpy(coinaddr,tx->outpoints[vout].coinaddr);
                    //printf("(%s) return value %.8f + interest %.8f\n",coinaddr,dstr(tx->outpoints[vout].value),dstr(tx->outpoints[vout].interest));
                }
                return(tx->outpoints[vout].value + 0*tx->outpoints[vout].interest);
            }*/
            return(tx->outpoints[vout].value);
        } else printf("LP_txvalue vout.%d >= tx->numvouts.%d\n",vout,tx->numvouts);
    }
    else if ( coin->electrum == 0 )
    {
        uint64_t value; char _coinaddr[64];
        if ( (txobj= LP_gettxout(coin->symbol,coinaddr,txid,vout)) != 0 )
        {
            value = LP_value_extract(txobj,0);//SATOSHIDEN * (jdouble(txobj,"value") + jdouble(txobj,"interest"));
            if ( coinaddr == 0 )
                coinaddr = _coinaddr;
            LP_destaddr(coinaddr,txobj);
            //printf("pruned node? LP_txvalue couldnt find %s tx %s, but gettxout %.8f\n",coin->symbol,bits256_str(str,txid),dstr(value));
            if ( value != 0 )
            {
                free_json(txobj);
                return(value);
            }
        }
        //printf("pruned node? LP_txvalue couldnt find %s tx %s/v%d (%s)\n",coin->symbol,bits256_str(str,txid),vout,txobj!=0?jprint(txobj,0):"");
        if ( txobj != 0 )
            free_json(txobj);
    }
    return(0);
}

int32_t LP_iseligible(uint64_t *valp,uint64_t *val2p,int32_t iambob,char *symbol,bits256 txid,int32_t vout,uint64_t satoshis,bits256 txid2,int32_t vout2)
{
    uint64_t val,val2=0,txfee,threshold=0; int32_t bypass = 0; char destaddr[64],destaddr2[64]; struct LP_transaction *tx; struct LP_address_utxo *up; struct iguana_info *coin = LP_coinfind(symbol);
    if ( bits256_nonz(txid) == 0 || bits256_nonz(txid2) == 0 )
    {
        printf("null txid not eligible\n");
        return(-1);
    }
    destaddr[0] = destaddr2[0] = 0;
    if ( coin != 0 && IAMLP != 0 && coin->inactive != 0 )
        bypass = 1;
    if ( bypass != 0 )
        val = satoshis;
    else val = LP_txvalue(destaddr,symbol,txid,vout);
    txfee = LP_txfeecalc(LP_coinfind(symbol),0,0);
    if ( val >= satoshis && val > (1+LP_MINSIZE_TXFEEMULT)*txfee )
    {
        threshold = (iambob != 0) ? LP_DEPOSITSATOSHIS(satoshis) : (LP_DEXFEE(satoshis) + txfee);
        if ( bypass != 0 )
            val2 = threshold;
        else val2 = LP_txvalue(destaddr2,symbol,txid2,vout2);
        if ( val2 >= threshold )
        {
            if ( bypass == 0 && strcmp(destaddr,destaddr2) != 0 )
                printf("mismatched %s destaddr (%s) vs (%s)\n",symbol,destaddr,destaddr2);
            else if ( bypass == 0 && ((iambob == 0 && val2 > val) || (iambob != 0 && val2 <= satoshis)) )
                printf("iambob.%d ineligible due to offsides: val %.8f and val2 %.8f vs %.8f diff %lld\n",iambob,dstr(val),dstr(val2),dstr(satoshis),(long long)(val2 - val));
            else
            {
                *valp = val;
                *val2p = val2;
                if ( destaddr[0] == 0 )
                    strcpy(destaddr,destaddr2);
                if ( coin != 0 )
                {
                    if ( (tx= LP_transactionfind(coin,txid)) != 0 && vout < tx->numvouts && tx->outpoints[vout].spendheight > 0 )
                        return(0);
                    if ( (tx= LP_transactionfind(coin,txid2)) != 0 && vout2 < tx->numvouts && tx->outpoints[vout2].spendheight > 0 )
                        return(0);
                    if ( (up= LP_address_utxofind(coin,destaddr,txid,vout)) != 0 && up->spendheight > 0 )
                        return(0);
                    if ( (up= LP_address_utxofind(coin,destaddr,txid2,vout2)) != 0 && up->spendheight > 0 )
                        return(0);
                }
                return(1);
            }
        } // else printf("no val2\n");
    }
    /*char str2[65];
    if ( val != 0 && val2 != 0 )
        printf("spent.%d %s txid or value %.8f < %.8f or val2 %.8f < %.8f, %s/v%d %s/v%d or < 10x txfee %.8f\n",iambob,symbol,dstr(val),dstr(satoshis),dstr(val2),dstr(threshold),bits256_str(str,txid),vout,bits256_str(str2,txid2),vout2,dstr(txfee));
    if ( val == 0 )
        LP_address_utxoadd(coin,destaddr,txid,vout,satoshis,-1,1);
    if ( val2 == 0 )
        LP_address_utxoadd(coin,destaddr,txid2,vout2,threshold,-1,1);
    for (iter=0; iter<2; iter++)
     {
     if ( (utxo= LP_utxofind(iter,txid,vout)) != 0 )
     {
     //printf("iambob.%d case 00\n",iter);
     if ( utxo->T.spentflag == 0 )
     utxo->T.spentflag = (uint32_t)time(NULL);
     }
     if ( (utxo= LP_utxo2find(iter,txid,vout)) != 0 )
     {
     //printf("iambob.%d case 01\n",iter);
     if ( utxo->T.spentflag == 0 )
     utxo->T.spentflag = (uint32_t)time(NULL);
     }
     if ( (utxo= LP_utxofind(iter,txid2,vout2)) != 0 )
     {
     //printf("iambob.%d case 10\n",iter);
     if ( utxo->T.spentflag == 0 )
     utxo->T.spentflag = (uint32_t)time(NULL);
     }
     if ( (utxo= LP_utxo2find(iter,txid2,vout2)) != 0 )
     {
     //printf("iambob.%d case 11\n",iter);
     if ( utxo->T.spentflag == 0 )
     utxo->T.spentflag = (uint32_t)time(NULL);
     }
     }*/
    *valp = val;
    *val2p = val2;
    return(0);
}

int32_t LP_inventory_prevent(int32_t iambob,char *symbol,bits256 txid,int32_t vout)
{
    struct LP_utxoinfo *utxo; struct LP_transaction *tx; struct iguana_info *coin;
    if ( (utxo= LP_utxofind(iambob,txid,vout)) != 0 || (utxo= LP_utxo2find(iambob,txid,vout)) != 0 )
    {
        if ( (coin= LP_coinfind(symbol)) != 0 && (tx= LP_transactionfind(coin,txid)) != 0 )
        {
            if ( tx->outpoints[vout].spendheight > 0 )
                utxo->T.spentflag = tx->outpoints[vout].spendheight;
            else utxo->T.spentflag = 0;
        }
        if ( utxo->T.spentflag != 0 )
        {
            //char str[65]; printf("prevent adding iambob.%d %s/v%d to inventory\n",iambob,bits256_str(str,txid),vout);
            return(1);
        }
    }
    return(0);
}

cJSON *LP_dustcombine_item(struct LP_address_utxo *up)
{
    cJSON *item = cJSON_CreateObject();
    jaddbits256(item,"txid",up->U.txid);
    jaddnum(item,"vout",up->U.vout);
    return(item);
}

uint64_t LP_dustcombine(cJSON *items[2],int32_t dustcombine,struct iguana_info *coin)
{
    struct LP_address *ap=0; struct LP_address_utxo *up,*tmp,*min0,*min1; cJSON *txobj;
    if ( coin == 0 || coin->electrum != 0 || dustcombine <= 0 || dustcombine > 2 )
        return(0);
    min1 = min0 = 0;
    printf("LP_dustcombine\n");
    if ( (ap= _LP_addressfind(coin,coin->smartaddr)) != 0 )
    {
        DL_FOREACH_SAFE(ap->utxos,up,tmp)
        {
            if ( up->spendheight <= 0 && up->U.height > 0 && up->U.value != 0 )
            {
                if ( (txobj= LP_gettxout(coin->symbol,coin->smartaddr,up->U.txid,up->U.vout)) == 0 )
                    up->spendheight = 1;
                else
                {
                    free_json(txobj);
                    if ( LP_inventory_prevent(0,coin->symbol,up->U.txid,up->U.vout) == 0 && LP_inventory_prevent(1,coin->symbol,up->U.txid,up->U.vout) == 0 )
                    {
                        if ( min1 == 0 || up->U.value < min1->U.value )
                        {
                            if ( min0 == 0 || up->U.value < min0->U.value )
                            {
                                min1 = min0;
                                min0 = up;
                            } else min1 = up;
                        }
                    }
                }
            }
        }
    }
    if ( min0 != 0 )
    {
        items[0] = LP_dustcombine_item(min0);
        if ( dustcombine == 2 && min1 != 0 )
        {
            items[1] = LP_dustcombine_item(min1);
            return(min0->U.value + min1->U.value);
        } else return(min0->U.value);
    }
    return(0);
}

int32_t LP_undospends(struct iguana_info *coin,int32_t lastheight)
{
    int32_t i,ht,num = 0; struct LP_transaction *tx,*tmp;
    HASH_ITER(hh,coin->transactions,tx,tmp)
    {
        for (i=0; i<tx->numvouts; i++)
        {
            if ( bits256_nonz(tx->outpoints[i].spendtxid) == 0 )
                continue;
            if ( (ht= tx->outpoints[i].spendheight) == 0 )
            {
                tx->outpoints[i].spendheight = LP_txheight(coin,tx->outpoints[i].spendtxid);
            }
            if ( (ht= tx->outpoints[i].spendheight) != 0 && ht > lastheight )
            {
                char str[65]; printf("clear spend %s/v%d at ht.%d > lastheight.%d\n",bits256_str(str,tx->txid),i,ht,lastheight);
                tx->outpoints[i].spendheight = 0;
                tx->outpoints[i].spendvini = -1;
                memset(tx->outpoints[i].spendtxid.bytes,0,sizeof(bits256));
            }
        }
    }
    return(num);
}

void LP_unspents_cache(char *symbol,char *addr,char *arraystr,int32_t updatedflag)
{
    char fname[1024]; FILE *fp=0;
    sprintf(fname,"%s/UNSPENTS/%s_%s",GLOBAL_DBDIR,symbol,addr), OS_portable_path(fname);
    if ( updatedflag == 0 && (fp= fopen(fname,"rb")) == 0 )
        updatedflag = 1;
    else if ( fp != 0 )
        fclose(fp);
    if ( updatedflag != 0 && (fp= fopen(fname,"wb")) != 0 )
    {
        fwrite(arraystr,1,strlen(arraystr),fp);
        fclose(fp);
    }
}

void LP_unspents_load(char *symbol,char *addr)
{
    char fname[1024],*arraystr; long fsize; struct iguana_info *coin; cJSON *retjson;
    if ( (coin= LP_coinfind(symbol)) != 0 )
    {
        sprintf(fname,"%s/UNSPENTS/%s_%s",GLOBAL_DBDIR,symbol,addr), OS_portable_path(fname);
        if ( (arraystr= OS_filestr(&fsize,fname)) != 0 )
        {
            if ( (retjson= cJSON_Parse(arraystr)) != 0 )
            {
                printf("PROCESS UNSPENTS %s\n",arraystr);
                electrum_process_array(coin,coin->electrum,coin->smartaddr,retjson,1);
                free_json(retjson);
            }
            free(arraystr);
        }
    }
}



