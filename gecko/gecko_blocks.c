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

char *gecko_txarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 txid)
{
    return(clonestr("{\"result\":\"gecko headers queued\"}"));
}

struct iguana_bundle *gecko_ensurebundle(struct iguana_info *virt,struct iguana_block *block,int32_t origheight,int32_t depth)
{
    int32_t hdrsi,bundlei,i,iter,checkbundlei,height = origheight; bits256 zero; struct iguana_block *prev; struct iguana_bundle *bp = 0;
    memset(zero.bytes,0,sizeof(zero));
    for (iter=0; iter<2; iter++)
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
    }
    hdrsi = (block->height / virt->chain->bundlesize);
    return(virt->bundles[hdrsi]);
}

char *gecko_blockarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 hash2)
{
    struct iguana_txblock txdata; int32_t valid,adjacent,n,i,hdrsi,j,len = -1; struct iguana_peer *addr; struct iguana_block *block,*prev; struct iguana_bundle *bp;
    memset(&txdata,0,sizeof(txdata));
    if ( virt->TXMEM.ptr == 0 )
        iguana_meminit(&virt->TXMEM,virt->name,0,IGUANA_MAXPACKETSIZE * 2,0);
    iguana_memreset(&virt->TXMEM);
    addr = &virt->internaladdr;
    if ( (n= iguana_gentxarray(virt,&virt->TXMEM,&txdata,&len,data,datalen)) == datalen )
    {
        if ( bits256_cmp(hash2,txdata.zblock.RO.hash2) != 0 )
        {
            printf("gecko_blockarrived: mismatched hash2\n");
            return(clonestr("{\"error\":\"gecko block hash2 mismatch\"}"));
        }
        txdata.zblock.RO.allocsize = sizeof(struct iguana_block);
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
                block->height = adjacent + 1;
                if ( block->height > virt->blocks.hwmchain.height ) // longest chain wins
                {
                    //printf("new HWM %d adjacent.%d prev.%d i.%d\n",block->height,adjacent,prev->height,i);
                    block->mainchain = 1;
                    prev = block;
                    // probably should clear mainchain bits in old path
                    for (j=0; j<=i; j++)
                    {
                        if ( (prev= iguana_blockfind("geckoprev",virt,prev->RO.prev_block)) == 0 )
                            return(clonestr("{\"error\":\"gecko block mainchain link error\"}"));
                        prev->mainchain = 1;
                    }
                    iguana_blockzcopy(virt->chain->zcash,(void *)&virt->blocks.hwmchain,block);
                    if ( gecko_ensurebundle(virt,block,block->height,i+1) == 0 )
                        return(clonestr("{\"error\":\"gecko bundle couldnt be created\"}"));
                    if ( iguana_ramchain_data(virt,addr,&txdata,virt->TXMEM.ptr,txdata.zblock.RO.txn_count,data,datalen) >= 0 )
                    {
                        block->fpipbits = (uint32_t)addr->ipbits;
                        block->RO.recvlen = datalen;
                        block->txvalid = 1;
                        hdrsi = block->height / virt->chain->bundlesize;
                        if ( (bp= virt->bundles[hdrsi]) != 0 )
                        {
                            bp->numsaved++;
                            if ( (block->height % virt->chain->bundlesize) == 13 && hdrsi > 0 && (bp= virt->bundles[hdrsi - 1]) != 0 && bp->emitfinish == 0 && bp->numsaved >= bp->n )
                                iguana_bundlefinalize(virt,bp,&virt->MEM,virt->MEMB);
                        }
                        //printf("created block.%d [%d:%d] %d\n",block->height,bp!=0?bp->hdrsi:-1,block->height%virt->chain->bundlesize,bp->numsaved);
                        return(clonestr("{\"result\":\"gecko block created\"}"));
                    } else return(clonestr("{\"error\":\"gecko error creating ramchain0\"}"));
                }
            }
        }
    }
    return(clonestr("{\"error\":\"gecko block didnt decode\"}"));
}

