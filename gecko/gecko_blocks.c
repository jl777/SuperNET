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

char *gecko_headersarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 hash2)
{
    return(clonestr("{\"result\":\"gecko headers queued\"}"));
}

char *gecko_txarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *serialized,int32_t datalen,bits256 txid)
{
    struct gecko_mempool *pool; int64_t txfee,vinstotal,voutstotal; uint64_t hdrsi_unspentind,value; int32_t i,numvins,numvouts,txlen,spentheight,minconf,maxconf,unspentind,hdrsi; struct gecko_mempooltx *mtx; struct iguana_msgtx msg;
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
            if ( (unspentind= iguana_unspentindfind(virt,0,0,0,&value,&spentheight,msg.vins[i].prev_hash,msg.vins[i].prev_vout,virt->bundlescount-1)) != 0 )
            {
                hdrsi = spentheight / virt->chain->bundlesize;
                hdrsi_unspentind = ((uint64_t)hdrsi << 32) | unspentind;
                if ( iguana_unspentavail(virt,hdrsi_unspentind,minconf,maxconf) != value )
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
        pool = virt->mempool = calloc(1,sizeof(*pool));
    mtx = &pool->txs[pool->numtx];
    memset(mtx,0,sizeof(*mtx));
    mtx->txid = txid;
    mtx->txfee = txfee;
    mtx->ipbits = (uint32_t)calc_ipbits(remoteaddr);
    mtx->rawtx = calloc(1,datalen*2 + 1);
    init_hexbytes_noT(mtx->rawtx,serialized,datalen);
    return(clonestr("{\"result\":\"gecko tx queued\"}"));
}

struct iguana_bundle *gecko_ensurebundle(struct iguana_info *virt,struct iguana_block *block,int32_t origheight,int32_t depth)
{
    int32_t hdrsi,bundlei,checkbundlei,height = origheight; bits256 zero; struct iguana_bundle *bp = 0;
    memset(zero.bytes,0,sizeof(zero));
    bundlei = (height % virt->chain->bundlesize);
    hdrsi = (height / virt->chain->bundlesize);
    if ( bundlei == 0 )
    {
        if ( hdrsi+1 > virt->bundlescount )
            virt->bundlescount = hdrsi + 1;
        return(iguana_bundlecreate(virt,&checkbundlei,origheight,block->RO.hash2,zero,0));
    }
   /*for (iter=0; iter<2; iter++)
    {
        prev = block;
        height = block->height;
        for (i=0; i<depth; i++,height--)
        {
            if ( prev == 0 || height < 0 )
                return(0);
            bundlei = (height % virt->chain->bundlesize);
            hdrsi = (height / virt->chain->bundlesize);
            if ( iter == 1 )
            {
                if ( (bp= virt->bundles[hdrsi]) != 0 )
                {
                    iguana_hash2set(virt,"ensure",bp,bundlei,prev->RO.hash2);
                    bp->blocks[bundlei] = prev;
                    bp->hashes[bundlei] = prev->RO.hash2;
                }
                else
                {
                    printf("cant find bundle for ht.%d\n",height);
                    return(0);
                }
            }
            else if ( bundlei == 0 && virt->bundles[hdrsi] == 0 )
                iguana_bundlecreate(virt,&checkbundlei,height,prev->RO.hash2,zero,0);
            prev = iguana_blockfind("geckoensure",virt,prev->RO.prev_block);
        }
        if ( iter == 0 )
        {
            char str[65];
            bundlei = (origheight % virt->chain->bundlesize);
            hdrsi = (origheight / virt->chain->bundlesize);
            if ( (bp= virt->bundles[hdrsi]) != 0 )
                iguana_hash2set(virt,"ensure",bp,bundlei,block->RO.hash2);
            if ( iguana_bundlefind(virt,&bp,&bundlei,block->RO.hash2) == 0 )
                printf("cant find ht.%d %s\n",block->height,bits256_str(str,block->RO.hash2));
        }
    }*/
    hdrsi = (block->height / virt->chain->bundlesize);
    if ( (bp= virt->bundles[hdrsi]) == 0 )
        printf("error ensuring bundle ht.%d\n",origheight);
    else
    {
        bp->blocks[bundlei] = block;
        bp->hashes[bundlei] = block->RO.hash2;
        //char str[65]; printf("[%d:%d] <- %s %p\n",hdrsi,bundlei,bits256_str(str,block->RO.hash2),block);
        iguana_hash2set(virt,"ensure",bp,bundlei,block->RO.hash2);
    }
    return(bp);
}

int32_t gecko_hwmset(struct iguana_info *virt,struct iguana_txblock *txdata,struct iguana_msgtx *txarray,uint8_t *data,int32_t datalen,int32_t depth)
{
    struct iguana_peer *addr; int32_t hdrsi; struct iguana_bundle *bp,*prevbp; struct iguana_block *block;
    if ( (block= iguana_blockhashset("gecko_hwmset",virt,txdata->zblock.height,txdata->zblock.RO.hash2,1)) != 0 )
    {
        iguana_blockcopy(virt->chain->zcash,virt->chain->auxpow,virt,block,(struct iguana_block *)&txdata->zblock);
    } else return(-1);
    addr = &virt->internaladdr;
    if ( gecko_ensurebundle(virt,block,block->height,depth) == 0 )
        return(-1);
    if ( iguana_ramchain_data(virt,addr,txdata,txarray,block->RO.txn_count,data,datalen) >= 0 )
    {
        block->fpipbits = (uint32_t)addr->ipbits;
        block->RO.recvlen = datalen;
        block->txvalid = 1;
        iguana_blockzcopy(virt->chain->zcash,(void *)&virt->blocks.hwmchain,block);
        hdrsi = block->height / virt->chain->bundlesize;
        if ( (bp= virt->bundles[hdrsi]) != 0 )
        {
            bp->numsaved++;
            if ( (block->height % virt->chain->bundlesize) == 13 && hdrsi > 0 && (prevbp= virt->bundles[hdrsi - 1]) != 0 && prevbp->emitfinish == 0 && prevbp->numsaved >= prevbp->n )
            {
                iguana_bundlefinalize(virt,prevbp,&virt->MEM,virt->MEMB);
                prevbp->emitfinish = (uint32_t)(time(NULL) - 3600);
                iguana_bundlepurgefiles(virt,prevbp);
                iguana_savehdrs(virt);
                iguana_bundlevalidate(virt,prevbp,1);
            }
        }
        //printf("created block.%d [%d:%d] %d\n",block->height,bp!=0?bp->hdrsi:-1,block->height%virt->chain->bundlesize,bp->numsaved);
        return(block->height);
    }
    return(-1);
}

char *gecko_blockarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 hash2)
{
    struct iguana_txblock txdata; int32_t valid,adjacent,n,i,j,len = -1; struct iguana_block *block,*prev;
    memset(&txdata,0,sizeof(txdata));
    iguana_memreset(&virt->TXMEM);
    if ( (n= iguana_gentxarray(virt,&virt->TXMEM,&txdata,&len,data,datalen)) == datalen )
    {
        if ( bits256_cmp(hash2,txdata.zblock.RO.hash2) != 0 )
        {
            printf("gecko_blockarrived: mismatched hash2\n");
            return(clonestr("{\"error\":\"gecko block hash2 mismatch\"}"));
        }
        txdata.zblock.RO.allocsize = iguana_ROallocsize(virt);
        if ( iguana_blockvalidate(virt,&valid,(struct iguana_block *)&txdata.zblock,1) < 0 )
        {
            char str[65]; printf("got block that doesnt validate? %s\n",bits256_str(str,txdata.zblock.RO.hash2));
            return(clonestr("{\"error\":\"gecko block didnt validate\"}"));
        }
        if ( (block= iguana_blockfind("geckoblock",virt,hash2)) == 0 )
        {
            if ( (block= iguana_blockhashset("geckoblock",virt,-1,hash2,1)) == 0 )
                return(clonestr("{\"error\":\"gecko block couldnt be created\"}"));
        }
        iguana_blockcopy(virt->chain->zcash,virt->chain->auxpow,virt,block,(struct iguana_block *)&txdata.zblock);
        prev = block;
        adjacent = -1;
        for (i=0; i<virt->chain->bundlesize; i++)
        {
            if ( (prev= iguana_blockfind("geckoprev",virt,prev->RO.prev_block)) == 0 )
                return(clonestr("{\"error\":\"gecko block is orphan\"}"));
            if ( i == 0 )
                adjacent = prev->height;
            //printf("i.%d prevht.%d adjacent.%d hwm.%d\n",i,prev->height,adjacent,virt->blocks.hwmchain.height);
            if ( prev->height >= 0 )
            {
                txdata.zblock.height = block->height = adjacent + 1;
                if ( block->height > virt->blocks.hwmchain.height ) // longest chain wins
                {
                    //printf("new HWM %d adjacent.%d prev.%d i.%d\n",block->height,adjacent,prev->height,i);
                    txdata.zblock.mainchain = block->mainchain = 1;
                    prev = block;
                    // probably should clear mainchain bits in old path
                    for (j=0; j<=i; j++)
                    {
                        if ( (prev= iguana_blockfind("geckoprev",virt,prev->RO.prev_block)) == 0 )
                            return(clonestr("{\"error\":\"gecko block mainchain link error\"}"));
                        prev->mainchain = 1;
                    }
                    if ( gecko_hwmset(virt,&txdata,virt->TXMEM.ptr,data,datalen,i+1) >= 0 )
                        return(clonestr("{\"result\":\"gecko block created\"}"));
                    else return(clonestr("{\"error\":\"gecko error creating hwmblock\"}"));
                } else return(clonestr("{\"results\":\"gecko block wasnt hwmblock\"}"));
            }
        }
        return(clonestr("{\"error\":\"gecko orphan block\"}"));
    }
    return(clonestr("{\"error\":\"gecko block didnt decode\"}"));
}

