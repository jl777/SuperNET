
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
//  LP_scan.c
//  marketmaker
//


struct LP_transaction *LP_transactionfind(struct iguana_info *coin,bits256 txid)
{
    struct LP_transaction *tx;
    portable_mutex_lock(&coin->txmutex);
    HASH_FIND(hh,coin->transactions,txid.bytes,sizeof(txid),tx);
    portable_mutex_unlock(&coin->txmutex);
    return(tx);
}

struct LP_transaction *LP_transactionadd(struct iguana_info *coin,bits256 txid,int32_t height,int32_t numvouts,int32_t numvins,uint32_t timestamp)
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
        tx->timestamp = timestamp;
        tx->txid = txid;
        portable_mutex_lock(&coin->txmutex);
        HASH_ADD_KEYPTR(hh,coin->transactions,tx->txid.bytes,sizeof(tx->txid),tx);
        portable_mutex_unlock(&coin->txmutex);
    } // else printf("warning adding already existing txid %s\n",bits256_str(str,tx->txid));
    return(tx);
}

int32_t LP_txheight(uint32_t *timestampp,uint32_t *blocktimep,struct iguana_info *coin,bits256 txid)
{
    bits256 blockhash; cJSON *blockobj,*txobj; int32_t height = 0;
    if ( (txobj= LP_gettx(coin->symbol,txid)) != 0 )
    {
        *timestampp = juint(txobj,"locktime");
        *blocktimep = juint(txobj,"blocktime");
        blockhash = jbits256(txobj,"blockhash");
        if ( bits256_nonz(blockhash) != 0 && (blockobj= LP_getblock(coin->symbol,blockhash)) != 0 )
        {
            height = jint(blockobj,"height");
            //printf("%s LP_txheight.%d\n",coin->symbol,height);
            free_json(blockobj);
        } //else printf("%s LP_txheight error (%s)\n",coin->symbol,jprint(txobj,0));
        free_json(txobj);
    }
    return(height);
}

int32_t LP_undospends(struct iguana_info *coin,int32_t lastheight)
{
    int32_t i,ht,num = 0; uint32_t timestamp,blocktime; struct LP_transaction *tx,*tmp;
    HASH_ITER(hh,coin->transactions,tx,tmp)
    {
        for (i=0; i<tx->numvouts; i++)
        {
            if ( bits256_nonz(tx->outpoints[i].spendtxid) == 0 )
                continue;
            if ( (ht= tx->outpoints[i].spendheight) == 0 )
            {
                tx->outpoints[i].spendheight = LP_txheight(&timestamp,&blocktime,coin,tx->outpoints[i].spendtxid);
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

uint64_t LP_txinterestvalue(uint64_t *interestp,char *destaddr,struct iguana_info *coin,bits256 txid,int32_t vout)
{
    uint64_t interest,value = 0; cJSON *txobj,*sobj,*array; int32_t n=0;
    *interestp = 0;
    destaddr[0] = 0;
    if ( (txobj= LP_gettxout(coin->symbol,txid,vout)) != 0 )
    {
        if ( (value= jdouble(txobj,"amount")*SATOSHIDEN) == 0 && (value= jdouble(txobj,"value")*SATOSHIDEN) == 0 )
        {
            char str[65]; printf("%s LP_txvalue.%s strange utxo.(%s) vout.%d\n",coin->symbol,bits256_str(str,txid),jprint(txobj,0),vout);
        }
        else if ( strcmp(coin->symbol,"KMD") == 0 )
        {
            if ( (interest= jdouble(txobj,"interest")) != 0. )
            {
                //printf("add interest of %.8f to %.8f\n",interest,dstr(value));
                *interestp = SATOSHIDEN * interest;
            }
        }
        if ( (sobj= jobj(txobj,"scriptPubKey")) != 0 && (array= jarray(&n,sobj,"addresses")) != 0 )
        {
            strcpy(destaddr,jstri(array,0));
            if ( n > 1 )
                printf("LP_txinterestvalue warning: violation of 1 output assumption n.%d\n",n);
        } else printf("LP_txinterestvalue no addresses found?\n");
        //char str[65]; printf("%s %.8f <- %s.(%s) txobj.(%s)\n",destaddr,dstr(value),coin->symbol,bits256_str(str,txid),jprint(txobj,0));
        free_json(txobj);
    } else { char str[65]; printf("null gettxout return %s/v%d\n",bits256_str(str,txid),vout); }
    return(value);
}

int32_t LP_transactioninit(struct iguana_info *coin,bits256 txid)
{
    struct LP_transaction *tx; int32_t i,height,numvouts,numvins,spentvout; uint32_t timestamp,blocktime; cJSON *txobj,*vins,*vouts,*vout,*vin; bits256 spenttxid; char str[65];
    if ( (txobj= LP_gettx(coin->symbol,txid)) != 0 )
    {
        height = LP_txheight(&timestamp,&blocktime,coin,txid);
        if ( timestamp == 0 && height > 0 )
            timestamp = blocktime;
        vins = jarray(&numvins,txobj,"vin");
        vouts = jarray(&numvouts,txobj,"vout");
        if ( vouts != 0 && (tx= LP_transactionadd(coin,txid,height,numvouts,numvins,timestamp)) != 0 )
        {
            for (i=0; i<numvouts; i++)
            {
                vout = jitem(vouts,i);
                if ( (tx->outpoints[i].value= SATOSHIDEN * jdouble(vout,"value")) == 0 )
                    tx->outpoints[i].value = SATOSHIDEN * jdouble(vout,"amount");
                tx->outpoints[i].interest = SATOSHIDEN * jdouble(vout,"interest");
            }
        }
        if ( vins != 0 )
        {
            for (i=0; i<numvins; i++)
            {
                vin = jitem(vins,i);
                spenttxid = jbits256(vin,"txid");
                spentvout = jint(vin,"vout");
                if ( (tx= LP_transactionfind(coin,spenttxid)) != 0 )
                {
                    if ( spentvout < tx->numvouts )
                    {
                        tx->outpoints[spentvout].spendtxid = txid;
                        tx->outpoints[spentvout].spendvini = i;
                        tx->outpoints[spentvout].spendheight = height;
                        //printf("spend %s %s/v%d at ht.%d\n",coin->symbol,bits256_str(str,tx->txid),spentvout,height);
                    } else printf("LP_transactioninint: %s spentvout.%d < numvouts.%d\n",bits256_str(str,spenttxid),spentvout,tx->numvouts);
                }
            }
        }
        free_json(txobj);
        return(0);
    } else printf("LP_transactioninit error for %s %s\n",coin->symbol,bits256_str(str,txid));
    return(-1);
}

int32_t LP_blockinit(struct iguana_info *coin,int32_t height)
{
    int32_t i,numtx,checkht=-1; cJSON *blockobj,*txs; bits256 txid; struct LP_transaction *tx;
    if ( (blockobj= LP_blockjson(&checkht,coin->symbol,0,height)) != 0 )
    {
        if ( (txs= jarray(&numtx,blockobj,"tx")) != 0 )
        {
            for (i=0; i<numtx; i++)
            {
                txid = jbits256i(txs,i);
                if ( (tx= LP_transactionfind(coin,txid)) != 0 )
                {
                    if ( tx->height == 0 )
                        tx->height = height;
                    else if ( tx->height != height )
                    {
                        printf("LP_blockinit: tx->height %d != %d\n",tx->height,height);
                        tx->height = height;
                    }
                } else LP_transactioninit(coin,txid);
            }
        }
        free_json(blockobj);
    }
    if ( checkht == height )
        return(0);
    else return(-1);
}

cJSON *LP_snapshot(struct iguana_info *coin,int32_t height)
{
    struct LP_transaction *tx,*tmp; int32_t i,ht; uint64_t balance=0; cJSON *retjson,*array;
    for (ht=1; ht<height; ht++)
        if ( LP_blockinit(coin,ht) < 0 )
        {
            printf("error loading block.%d of %d\n",ht,height);
            return(0);
        }
    portable_mutex_lock(&coin->txmutex);
    HASH_ITER(hh,coin->transactions,tx,tmp)
    {
        if ( tx->height < height )
        {
            for (i=0; i<tx->numvouts; i++)
            {
                if ( (ht=tx->outpoints[i].spendheight) > 0 && ht < height )
                    continue;
                balance += tx->outpoints[i].value;
            }
        }
    }
    portable_mutex_unlock(&coin->txmutex);
    printf("%s balance %.8f at height.%d\n",coin->symbol,dstr(balance),height);
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    jadd(retjson,"balances",array);
    jaddnum(retjson,"total",dstr(balance));
    return(retjson);
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
    struct LP_transaction *tx; char _coinaddr[64]; uint64_t interest = 0,value = 0; struct iguana_info *coin;
    if ( (coin= LP_coinfind(symbol)) == 0 || coin->inactive != 0 )
        return(0);
    if ( coinaddr != 0 )
        coinaddr[0] = 0;
    if ( (tx= LP_transactionfind(coin,txid)) != 0 )
    {
        if ( vout < tx->numvouts )
        {
            if ( bits256_nonz(tx->outpoints[vout].spendtxid) != 0 )
            {
                //char str[65]; printf("%s/v%d is spent\n",bits256_str(str,txid),vout);
                return(0);
            }
            else
            {
                if ( coinaddr != 0 )
                    value = LP_txinterestvalue(&tx->outpoints[vout].interest,coinaddr,coin,txid,vout);
                //printf("return value %.8f + interest %.8f\n",dstr(tx->outpoints[vout].value),dstr(tx->outpoints[vout].interest));
                return(tx->outpoints[vout].value + tx->outpoints[vout].interest);
            }
        } else printf("vout.%d >= tx->numvouts.%d\n",vout,tx->numvouts);
    }
    if ( tx == 0 )
        LP_transactioninit(coin,txid);
    if ( coinaddr == 0 )
        coinaddr = _coinaddr;
    value = LP_txinterestvalue(&interest,coinaddr,coin,txid,vout);
    //printf("coinaddr.(%s) value %.8f interest %.8f\n",coinaddr,dstr(value),dstr(interest));
    return(value + interest);
}

int32_t LP_spendsearch(bits256 *spendtxidp,int32_t *indp,char *symbol,bits256 searchtxid,int32_t searchvout)
{
    struct LP_transaction *tx; struct iguana_info *coin;
    *indp = -1;
    if ( (coin= LP_coinfind(symbol)) == 0 || coin->inactive != 0 )
        return(-1);
    memset(spendtxidp,0,sizeof(*spendtxidp));
    if ( (tx= LP_transactionfind(coin,searchtxid)) != 0 )
    {
        if ( searchvout < tx->numvouts && tx->outpoints[searchvout].spendvini >= 0 )
        {
            *spendtxidp = tx->outpoints[searchvout].spendtxid;
            *indp = tx->outpoints[searchvout].spendvini;
            return(tx->outpoints[searchvout].spendheight);
        }
    }
    return(-1);
}

int32_t LP_mempoolscan(char *symbol,bits256 searchtxid)
{
    int32_t i,n; cJSON *array; bits256 txid; struct iguana_info *coin; struct LP_transaction *tx;
    if ( (coin= LP_coinfind(symbol)) == 0 || coin->inactive != 0 )
        return(-1);
    if ( (array= LP_getmempool(symbol)) != 0 )
    {
        if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                txid = jbits256i(array,i);
                if ( (tx= LP_transactionfind(coin,txid)) == 0 )
                    LP_transactioninit(coin,txid);
                if ( bits256_cmp(txid,searchtxid) == 0 )
                {
                    char str[65]; printf("found %s tx.(%s) in mempool slot.%d\n",symbol,bits256_str(str,txid),i);
                    return(i);
                }
            }
        }
        free_json(array);
    }
    return(-1);
}

int32_t LP_numconfirms(struct basilisk_swap *swap,struct basilisk_rawtx *rawtx,int32_t mempool)
{
    struct iguana_info *coin; int32_t numconfirms = 100;
//#ifndef BASILISK_DISABLEWAITTX
    cJSON *txobj;
    if ( (coin= LP_coinfind(rawtx->coin->symbol)) == 0 || coin->inactive != 0 )
        return(-1);
    numconfirms = -1;
    if ( (txobj= LP_gettx(rawtx->coin->symbol,rawtx->I.signedtxid)) != 0 )
    {
        numconfirms = jint(txobj,"confirmations");
        free_json(txobj);
    }
    else if ( mempool != 0 && LP_mempoolscan(rawtx->coin->symbol,rawtx->I.signedtxid) >= 0 )
        numconfirms = 0;
//#endif
    return(numconfirms);
}

int32_t LP_waitmempool(char *symbol,bits256 txid,int32_t duration)
{
    uint32_t expiration = (uint32_t)time(NULL) + duration;
    while ( time(NULL) < expiration )
    {
        if ( LP_mempoolscan(symbol,txid) >= 0 )
            return(0);
        usleep(500000);
    }
    return(-1);
}

int32_t LP_mempool_vinscan(bits256 *spendtxidp,int32_t *spendvinp,char *symbol,bits256 searchtxid,int32_t searchvout,bits256 searchtxid2,int32_t searchvout2)
{
    struct iguana_info *coin; int32_t selector; cJSON *array;
    if ( symbol == 0 || symbol[0] == 0 || bits256_nonz(searchtxid) == 0 || bits256_nonz(searchtxid2) == 0 )
        return(-1);
    if ( (coin= LP_coinfind(symbol)) == 0 || coin->inactive != 0 )
        return(-1);
    if ( time(NULL) > coin->lastmempool+LP_MEMPOOL_TIMEINCR )
    {
        if ( (array= LP_getmempool(symbol)) != 0 )
        {
            free_json(array);
            coin->lastmempool = (uint32_t)time(NULL);
        }
    }
    if ( (selector= LP_spendsearch(spendtxidp,spendvinp,symbol,searchtxid,searchvout)) >= 0 )
        return(selector);
    else if ( (selector= LP_spendsearch(spendtxidp,spendvinp,symbol,searchtxid2,searchvout2)) >= 0 )
        return(selector);
    return(-1);
}


