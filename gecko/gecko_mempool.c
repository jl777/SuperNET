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

// included from gecko.c
// struct gecko_memtx { bits256 txid; char *rawtx; int64_t txfee; int32_t pending; uint32_t ipbits; };

struct gecko_mempool *gecko_mempoolfind(struct supernet_info *myinfo,struct iguana_info *virt,int32_t *numotherp,uint32_t ipbits)
{
    int32_t j,firstz,numother; bits256 *othertxids; struct gecko_mempool *otherpool = 0;
    othertxids = 0;
    numother = firstz = 0;
    for (j=0; j<myinfo->numrelays; j++)
    {
        if ( (otherpool= virt->mempools[j]) != 0 )
        {
            if ( otherpool->ipbits == ipbits )
            {
                othertxids = otherpool->txids;
                numother = otherpool->numtx;
                break;
            }
        } else firstz = j;
    }
    if ( otherpool == 0 )
    {
        virt->mempools[firstz] = otherpool = calloc(1,sizeof(struct gecko_mempool));
        otherpool->ipbits = (uint32_t)ipbits;
    }
    return(otherpool);
}

void gecko_mempool_sync(struct supernet_info *myinfo,struct iguana_info *virt,bits256 *reftxids,int32_t numtx)
{
    int32_t i,j,k,n,num,numother; struct iguana_peer *addr; bits256 txid,*txids; struct gecko_mempool *pool,*otherpool; struct iguana_info *coin;
    if ( (pool= virt->mempool) == 0 || myinfo->numrelays <= 0 )
        return;
    n = sqrt(myinfo->numrelays) + 2;
    if ( n > myinfo->numrelays )
        myinfo->numrelays = n;
    i = (myinfo->myaddr.myipbits % n);
    txids = calloc(pool->numtx,sizeof(bits256));
    if ( virt->peers == 0 )
        coin = iguana_coinfind("BTCD");
    else coin = virt;
    for (; i<myinfo->numrelays; i+=n)
    {
        printf("mempool_sync.%d\n",i);
        if ( (addr= iguana_peerfindipbits(coin,myinfo->relays[i].ipbits,1)) != 0 )
        {
            if ( (otherpool= gecko_mempoolfind(myinfo,virt,&numother,myinfo->relays[i].ipbits)) != 0 )
            {
                for (j=num=0; j<pool->numtx; j++)
                {
                    txid = reftxids[j];
                    if ( numother > 0 )
                    {
                        for (k=0; k<numother; k++)
                            if ( bits256_cmp(txid,otherpool->txids[k]) == 0 )
                                break;
                        if ( k != numother )
                            continue;
                    }
                    txids[num++] = txid;
                }
                if ( num > 0 )
                    basilisk_hashes_send(myinfo,virt,addr,"MEM",txids,num);
            }
        }
    }
    free(txids);
}

uint8_t *gecko_txdata(struct gecko_memtx *memtx)
{
    return((void *)((long)memtx->data256 + memtx->numoutputs * sizeof(int64_t) + memtx->numinputs * sizeof(bits256)));
}

int64_t *gecko_valueptr(struct gecko_memtx *memtx,int32_t vout)
{
    return((void *)((long)memtx->data256 + vout * sizeof(int64_t) + memtx->numinputs * sizeof(bits256)));
}

int32_t gecko_memtxcmp(struct gecko_memtx *memtxA,struct gecko_memtx *memtxB)
{
    int32_t i,numdiff; int64_t valA,valB,diff;
    if ( memtxA->numinputs == memtxB->numinputs && memtxA->numoutputs == memtxB->numoutputs )
    {
        for (i=0; i<memtxA->numinputs; i++)
        {
            if ( bits256_cmp(memtxA->data256[i],memtxB->data256[i]) != 0 )
                return(-1 - 2*i);
        }
        for (i=numdiff=0; i<memtxA->numoutputs; i++)
        {
            memcpy(&valA,gecko_valueptr(memtxA,i),sizeof(valA));
            memcpy(&valB,gecko_valueptr(memtxB,i),sizeof(valB));
            if ( (diff= valA - valB) < 0 )
                diff = -diff;
            if ( diff > 100000 )
                return(-1);
            if ( valA != valB )
                numdiff++;
        }
        if ( numdiff > 1 )
            return(-memtxA->numinputs*2 - 2);
        
        return(0);
    }
    return(-1);
}

struct gecko_memtx *gecko_unspentfind(struct gecko_memtx ***ptrpp,struct iguana_info *virt,bits256 txid)
{
    struct gecko_mempool *pool; int32_t i; struct gecko_memtx *memtx;
    if ( (pool= virt->mempool) != 0 )
    {
        for (i=0; i<pool->numtx; i++)
            if ( (memtx= pool->txs[i]) != 0 && bits256_cmp(memtx->txid,txid) == 0 )
            {
                if ( ptrpp != 0 )
                    *ptrpp = &pool->txs[i];
                return(memtx);
            }
    }
    return(0);
}

struct gecko_memtx *gecko_mempool_txadd(struct supernet_info *myinfo,struct iguana_info *virt,char *rawtx,uint32_t senderbits,int32_t suppress_pubkeys)
{
    struct gecko_memtx *spentmemtx,**ptrp,*memtx = 0; uint8_t *extraspace; char *str; struct iguana_msgtx msgtx; int32_t i,len,extralen = 65536; cJSON *retjson; int64_t value;
    extraspace = calloc(1,extralen);
    if ( (str= iguana_validaterawtx(myinfo,virt,&msgtx,extraspace,extralen,rawtx,1,suppress_pubkeys)) != 0 )
    {
        if ( (retjson= cJSON_Parse(str)) != 0 )
        {
            if ( jobj(retjson,"error") == 0 )
            {
                len = (int32_t)strlen(rawtx) >> 1;
                memtx = calloc(1,sizeof(*memtx) + len + msgtx.numoutputs * sizeof(int64_t) + msgtx.numinputs * sizeof(bits256));
                memtx->numinputs = msgtx.numinputs;
                memtx->numoutputs = msgtx.numoutputs;
                memtx->inputsum = msgtx.inputsum;
                memtx->outputsum = msgtx.outputsum;
                memtx->txfee = msgtx.txfee;
                memtx->txid = msgtx.txid;
                memtx->ipbits = senderbits;
                memtx->datalen = len;
                memtx->feeperkb = dstr(memtx->txfee) / (memtx->datalen / 1024.);
                for (i=0; i<msgtx.numoutputs; i++)
                    memcpy(gecko_valueptr(memtx,i),&msgtx.vouts[i].value,sizeof(msgtx.vouts[i].value));
                decode_hex(gecko_txdata(memtx),len,rawtx);
                for (i=0; i<msgtx.numinputs; i++)
                    memtx->data256[i] = msgtx.vins[i].prev_hash;
                for (i=0; i<msgtx.numinputs; i++)
                {
                    if ( (spentmemtx= gecko_unspentfind(&ptrp,virt->mempool,msgtx.vins[i].prev_hash)) != 0 )
                    {
                        memcpy(&value,gecko_valueptr(spentmemtx,msgtx.vins[i].prev_vout),sizeof(value));
                        if ( value < 0 )
                        {
                            if ( gecko_memtxcmp(spentmemtx,memtx) != 0 || memtx->txfee <= spentmemtx->txfee )
                            {
                                printf("already spent mempool error\n"); // check for replacment!
                                free(memtx);
                            }
                            else
                            {
                                printf("replace identical vins/vouts with higher txfee\n");
                                free(spentmemtx);
                                *ptrp = memtx;
                            }
                            memtx = 0;
                            free_json(retjson);
                            free(extraspace);
                            free(str);
                            return(0);
                        }
                    }
                }
                for (i=0; i<msgtx.numinputs; i++)
                {
                    if ( (spentmemtx= gecko_unspentfind(0,virt->mempool,msgtx.vins[i].prev_hash)) != 0 )
                    {
                        memcpy(&value,gecko_valueptr(spentmemtx,msgtx.vins[i].prev_vout),sizeof(value));
                        value = -value;
                        memcpy(gecko_valueptr(spentmemtx,msgtx.vins[i].prev_vout),&value,sizeof(value));
                    }
                }
            } else printf("gecko_mempool_txadd had error.(%s)\n",str);
            free_json(retjson);
        } else printf("gecko_mempool_txadd couldnt parse.(%s)\n",str);
        free(str);
    }
    free(extraspace);
    return(memtx);
}

struct gecko_mempool *gecko_mempool_alloc(int32_t otherflag)
{
    struct gecko_mempool *pool;
    pool = calloc(1,sizeof(*pool));
    if ( otherflag == 0 )
        pool->txs = calloc(0xffff,sizeof(*pool->txs));
    return(pool);
}

int32_t basilisk_respond_geckogettx(struct supernet_info *myinfo,struct iguana_info *virt,uint8_t *serialized,int32_t maxsize,cJSON *valsobj,bits256 hash2)
{
    int32_t datalen = 0;
    char str[65]; printf("got request for GTX.%s\n",bits256_str(str,hash2));
    // find txid and set serialized
    return(datalen);
}

char *gecko_txarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *serialized,int32_t datalen,bits256 txid)
{
    struct gecko_mempool *pool; int64_t txfee,vinstotal,voutstotal; uint64_t hdrsi_unspentind,value; int32_t i,numvins,numvouts,txlen,spentheight,minconf,maxconf,unspentind,hdrsi; struct iguana_msgtx msg; char *rawtx; struct gecko_memtx *memtx; struct iguana_info *btcd;
    memset(&msg,0,sizeof(msg));
    iguana_memreset(&virt->TXMEM);
    txlen = iguana_rwtx(virt->chain->zcash,0,&virt->TXMEM,serialized,&msg,datalen,&txid,virt->chain->isPoS,strcmp("VPN",virt->symbol) == 0);
    vinstotal = voutstotal = 0;
    maxconf = virt->longestchain;
    minconf = virt->chain->minconfirms;
    if ( (numvins= msg.tx_in) > 0 )
    {
        for (i=0; i<numvins; i++)
        {
            if ( (unspentind= iguana_unspentindfind(myinfo,virt,0,0,0,&value,&spentheight,msg.vins[i].prev_hash,msg.vins[i].prev_vout,virt->bundlescount-1,1)) != 0 )
            {
                hdrsi = spentheight / virt->chain->bundlesize;
                hdrsi_unspentind = ((uint64_t)hdrsi << 32) | unspentind;
                if ( iguana_unspentavail(myinfo,virt,hdrsi_unspentind,minconf,maxconf) != value )
                {
                    printf("vin.%d already spent\n",i);
                    return(clonestr("{\"error\":\"gecko tx has double spend\"}"));
                }
                vinstotal += value;
            }
        }
    }
    if ( (numvouts= msg.tx_out) > 0 )
        for (i=0; i<numvouts; i++)
            voutstotal += msg.vouts[i].value;
    if ( (txfee= (vinstotal - voutstotal)) < 0 )
        return(clonestr("{\"error\":\"gecko tx has more spends than inputs\"}"));
    if ( txlen <= 0 )
        return(clonestr("{\"error\":\"couldnt decode gecko tx\"}"));
    if ( (pool= virt->mempool) == 0 )
        pool = virt->mempool = gecko_mempool_alloc(0);
    rawtx = calloc(1,datalen*2 + 1);
    init_hexbytes_noT(rawtx,serialized,datalen);
    if ( (memtx= gecko_mempool_txadd(myinfo,virt,rawtx,(uint32_t)calc_ipbits(remoteaddr),0)) != 0 )
    {
        for (i=0; i<pool->numtx; i++)
        {
            if ( memtx->feeperkb >= pool->txs[i]->feeperkb )
                break;
        }
        pool->txs[pool->numtx++] = pool->txs[i];
        pool->txs[i] = memtx;
        char str[65]; printf("add tx.%s to mempool i.%d numtx.%d\n",bits256_str(str,memtx->txid),i,pool->numtx);
        for (i=0; i<pool->numtx; i++)
            pool->txids[i] = pool->txs[i]->txid;
        if ( (btcd= iguana_coinfind("BTCD")) != 0 && btcd->RELAYNODE != 0 && myinfo->IAMRELAY != 0 )
            gecko_mempool_sync(myinfo,virt,pool->txids,pool->numtx);
    }
    else
    {
        free(rawtx);
        return(clonestr("{\"error\":\"geckotx invalid\"}"));
    }
    free(rawtx);
    return(clonestr("{\"result\":\"gecko tx queued\"}"));
}

char *basilisk_respond_geckotx(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 txid,int32_t from_basilisk)
{
    bits256 checktxid; char *symbol; struct iguana_info *virt;
    if ( data != 0 && datalen != 0 && (symbol= jstr(valsobj,"symbol")) != 0 && (virt= iguana_coinfind(symbol)) != 0 )
    {
        checktxid = bits256_doublesha256(0,data,datalen);
        if ( bits256_cmp(txid,checktxid) == 0 )
            return(gecko_txarrived(myinfo,virt,addr,data,datalen,txid));
        else return(clonestr("{\"error\":\"geckotx mismatched txid\"}"));
    }
    return(clonestr("{\"error\":\"no geckotx chain or missing tx data\"}"));
}

struct gecko_memtx **gecko_mempool_txptrs(struct supernet_info *myinfo,struct iguana_info *virt,int64_t *rewardp,int32_t *txn_countp,void **ptrp,void *space,int32_t max,int32_t height)
{
    int32_t i,n; struct gecko_memtx **txptrs; struct gecko_mempool *pool; int64_t txfees = 0,reward = virt->chain->initialreward;
    if ( virt->chain->halvingduration != 0 && (n= (height / virt->chain->halvingduration)) != 0 )
    {
        for (i=0; i<n; i++)
            reward >>= 1;
    }
    *ptrp = 0;
    *txn_countp = 0;
    if ( (pool= virt->mempool) == 0 )
        pool = virt->mempool = gecko_mempool_alloc(0);
    if ( pool->numtx*sizeof(char *) <= max )
        txptrs = space;
    else
    {
        txptrs = calloc(pool->numtx,sizeof(char *));
        *ptrp = (void *)txptrs;
    }
    for (i=n=0; i<pool->numtx; i++)
    {
        if ( pool->txs[i]->pending == 0 )
        {
            txfees += pool->txs[i]->txfee;
            txptrs[n++] = pool->txs[i];
            pool->txs[i]->pending = height;
        }
    }
    *rewardp = (reward + txfees);
    if ( n > 0 )
        printf("reward %.8f n.%d numtx.%d\n",dstr(*rewardp),n,pool->numtx);
    if ( (*txn_countp= n) != 0 )
        return(txptrs);
    else return(0);
}

char *gecko_mempoolarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 hash2)
{
    int32_t i,j,numother,len = 0; struct gecko_mempool *otherpool; bits256 txid;
    if ( (otherpool= gecko_mempoolfind(myinfo,virt,&numother,(uint32_t)calc_ipbits(remoteaddr))) != 0 )
    {
        if ( numother > 0 )
        {
            for (i=0; i<numother; i++)
            {
                len += iguana_rwbignum(0,&data[len],sizeof(txid),txid.bytes);
                for (j=0; j<otherpool->numtx; j++)
                    if ( bits256_cmp(txid,otherpool->txids[j]) == 0 )
                        break;
                if ( j == otherpool->numtx )
                {
                    otherpool->txids[otherpool->numtx++] = txid;
                    printf("if first time, submit request for txid\n");
                }
            }
        }
    }
    return(clonestr("{\"result\":\"gecko mempool queued\"}"));
}

char *basilisk_respond_mempool(struct supernet_info *myinfo,char *CMD,void *_addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *symbol; struct iguana_info *virt;
    printf("got getmempool request\n");
    if ( (symbol= jstr(valsobj,"symbol")) != 0 && (virt= iguana_coinfind(symbol)) != 0 )
        return(gecko_mempoolarrived(myinfo,virt,_addr,data,datalen,hash));
    else return(clonestr("{\"error\":\"couldt find gecko chain\"}"));
}
