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

void gecko_txidpurge(struct iguana_info *virt,bits256 txid)
{
    struct gecko_mempool *pool; int32_t i,n; struct gecko_memtx *memtx;
    if ( (pool= virt->mempool) != 0 && pool->txs != 0 && (n= pool->numtx) )
    {
        for (i=0; i<n; i++)
        {
            if ( (memtx= pool->txs[i]) != 0 && bits256_cmp(txid,memtx->txid) == 0 )
            {
                free(pool->txs[i]);
                pool->txs[i] = pool->txs[--pool->numtx];
            }
        }
    }
    if ( virt->RELAYNODE != 0 )
    {
        for (i=0; i<BASILISK_MAXRELAYS; i++)
        {
            if ( (pool= virt->mempools[i]) != 0 && (n= pool->numtx) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( bits256_cmp(txid,pool->txids[i]) == 0 )
                    {
                        pool->txids[i] = pool->txids[--pool->numtx];
                        memset(pool->txids[pool->numtx].bytes,0,sizeof(pool->txids[pool->numtx]));
                    }
                }
            }
        }
    }
}

struct iguana_bundle *gecko_bundleset(struct iguana_info *virt,struct iguana_block *block)
{
    int32_t hdrsi,bundlei; struct iguana_bundle *bp;
    hdrsi = (block->height / virt->chain->bundlesize);
    bundlei = (block->height % virt->chain->bundlesize);
    if ( (bp= virt->bundles[hdrsi]) == 0 )
        printf("error ensuring bundle ht.%d\n",block->height);
    else
    {
        bp->blocks[bundlei] = block;
        bp->hashes[bundlei] = block->RO.hash2;
        //char str[65]; printf("[%d:%d] <- %s %p\n",hdrsi,bundlei,bits256_str(str,block->RO.hash2),block);
        iguana_hash2set(virt,"ensure",bp,bundlei,block->RO.hash2);
    }
    return(bp);
}

struct iguana_bundle *gecko_ensurebundle(struct iguana_info *virt,struct iguana_block *block,int32_t origheight,int32_t depth)
{
    int32_t hdrsi,bundlei,checkbundlei,height = origheight; bits256 zero;
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
    return(gecko_bundleset(virt,block));
}

int32_t gecko_hwmset(struct supernet_info *myinfo,struct iguana_info *virt,struct iguana_txblock *txdata,struct iguana_msgtx *txarray,uint8_t *data,int32_t datalen,int32_t depth,int32_t verifyonly)
{
    struct iguana_peer *addr; int32_t i,hdrsi; struct iguana_bundle *bp,*prevbp; struct iguana_block *block;
    if ( (block= iguana_blockhashset("gecko_hwmset",virt,txdata->zblock.height,txdata->zblock.RO.hash2,1)) != 0 )
    {
        iguana_blockcopy(virt->chain->zcash,virt->chain->auxpow,virt,block,(struct iguana_block *)&txdata->zblock);
    } else return(-1);
    addr = &virt->internaladdr;
    if ( gecko_ensurebundle(virt,block,block->height,depth) == 0 )
    {
        printf("no bundle for %s.%d\n",virt->symbol,block->height);
        return(-1);
    }
    if ( iguana_ramchain_data(virt,addr,txdata,txarray,block->RO.txn_count,data,datalen) >= 0 )
    {
        block->fpipbits = (uint32_t)addr->ipbits;
        block->RO.recvlen = datalen;
        block->txvalid = 1;
        if ( verifyonly == 0 )
        {
            iguana_blockzcopy(virt->chain->zcash,(void *)&virt->blocks.hwmchain,block);
            hdrsi = block->height / virt->chain->bundlesize;
            block->hdrsi = hdrsi;
            block->height =
            block->bundlei = (block->height % virt->chain->bundlesize);
            if ( (bp= virt->bundles[hdrsi]) != 0 )
            {
                bp->numsaved++;
                virt->current = bp;
                iguana_RTspendvectors(virt,bp);
                iguana_RTramchainalloc("RTbundle",virt,bp);
                iguana_update_balances(virt);
                iguana_realtime_update(myinfo,virt);
                if ( (block->height % virt->chain->bundlesize) == 13 && hdrsi > 0 && (prevbp= virt->bundles[hdrsi - 1]) != 0 && prevbp->emitfinish == 0 && prevbp->numsaved >= prevbp->n )
                {
                    iguana_bundlefinalize(myinfo,virt,prevbp,&virt->MEM,virt->MEMB);
                    prevbp->emitfinish = (uint32_t)(time(NULL) - 3600);
                    iguana_bundlepurgefiles(virt,prevbp);
                    iguana_savehdrs(virt);
                    iguana_bundlevalidate(virt,prevbp,1);
                    for (i=0; i<block->RO.txn_count; i++)
                        gecko_txidpurge(virt,txarray[i].txid);
                }
            }
            //printf("created block.%d [%d:%d] %d\n",block->height,bp!=0?bp->hdrsi:-1,block->height%virt->chain->bundlesize,bp->numsaved);
        }
        return(block->height);
    } else printf("Error updating virt ramchain\n");
    return(-1);
}

char *gecko_blockarrived(struct supernet_info *myinfo,struct iguana_info *virt,char *remoteaddr,uint8_t *data,int32_t datalen,bits256 hash2,int32_t verifyonly)
{
    struct iguana_txblock txdata; int32_t height,valid,adjacent,gap,n,i,j,len = -1; struct iguana_block *block,*prev; struct iguana_txid tx; char str[65]; bits256 txid; struct iguana_msgtx *txs;
    memset(&txdata,0,sizeof(txdata));
    iguana_memreset(&virt->TXMEM);
    if ( (n= iguana_gentxarray(virt,&virt->TXMEM,&txdata,&len,data,datalen)) == datalen )
    {
        if ( bits256_cmp(hash2,txdata.zblock.RO.hash2) != 0 )
        {
            printf("gecko_blockarrived: mismatched hash2\n");
            return(clonestr("{\"error\":\"gecko block hash2 mismatch\"}"));
        }
        txs = virt->TXMEM.ptr;
        for (i=0; i<txdata.zblock.RO.txn_count; i++)
        {
            txid = txs[i].txid;
            if ( iguana_txidfind(virt,&height,&tx,txid,virt->bundlescount-1) != 0 && height >= 0 )
            {
                printf("gecko_blockarrived: duplicate.[%d] txid.%s\n",i,bits256_str(str,txid));
                return(clonestr("{\"error\":\"gecko block duplicate txid\"}"));
            } else printf("%s is new txid ht.%d i.%d\n",bits256_str(str,txid),virt->blocks.hwmchain.height,i);
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
            char str2[65];
            printf("scan back.%d: prev.%s hwm.%s ht.%d\n",i,bits256_str(str,prev->RO.prev_block),bits256_str(str2,virt->blocks.hwmchain.RO.hash2),virt->blocks.hwmchain.height);
            if ( (prev= iguana_blockfind("geckoprev",virt,prev->RO.prev_block)) == 0 )
                return(clonestr("{\"error\":\"gecko block is orphan\"}"));
            if ( i == 0 )
            {
                adjacent = prev->height;
                block->height = (prev->height + 1);
            }
            printf("i.%d prevht.%d adjacent.%d hwm.%d\n",i,prev->height,adjacent,virt->blocks.hwmchain.height);
            if ( prev->height >= 0 && prev->mainchain != 0 )
            {
                if ( (adjacent + 1) > virt->blocks.hwmchain.height ) // longest chain wins
                {
                    //printf("new HWM %d adjacent.%d prev.%d i.%d\n",block->height,adjacent,prev->height,i);
                    if ( (gap= (block->height - virt->blocks.hwmchain.height)) > 1 )
                    {
                        prev = iguana_blockfind("geckoclear",virt,virt->blocks.hwmchain.RO.prev_block);
                        for (j=0; j<gap && prev!=0; j++)
                        {
                            printf("%d of %d: protected.%d unlink %s ht.%d from mainchain, newhwm ht.%d\n",j,gap,prev->protected,bits256_str(str,prev->RO.hash2),prev->height,block->height);
                            if ( prev->protected != 0 )
                            {
                                printf("REJECT block: cant overwrite protected block\n");
                                return(clonestr("{\"error\":\"gecko block cant override protected block\"}"));
                            }
                            prev->mainchain = 0;
                            prev = iguana_blockfind("geckoclrprev",virt,prev->RO.prev_block);
                        }
                    }
                    prev = block;
                    for (j=0; j<=i+1; j++)
                    {
                        if ( prev->protected == 0 || prev->height == (adjacent + 1 - j) )
                        {
                            if ( prev->mainchain != 1 )
                                prev->mainchain = 1;
                            if ( prev->height != (adjacent + 1 - j) )
                                prev->height = (adjacent + 1 - j);
                            gecko_bundleset(virt,prev);
                            if ( prev->height == 0 )
                                break;
                        }
                        else
                        {
                            printf("REJECT block: cant change height of protected block: ht.%d vs %d\n",adjacent + 1 - j, prev->height);
                            return(clonestr("{\"error\":\"gecko block cant override protected block's height\"}"));
                        }
                        if ( (prev= iguana_blockfind("geckoprev",virt,prev->RO.prev_block)) == 0 )
                            return(clonestr("{\"error\":\"gecko block mainchain link error\"}"));
                    }
                    txdata.zblock.height = block->height;
                    txdata.zblock.mainchain = block->mainchain = 1;
                    if ( gecko_hwmset(myinfo,virt,&txdata,virt->TXMEM.ptr,data,datalen,i+1,verifyonly) >= 0 )
                    {
                        block->txvalid = block->valid = 1;
                        if ( block->height > virt->longestchain )
                            virt->longestchain = block->height;
                        virt->backstoptime = (uint32_t)time(NULL);
                        return(clonestr("{\"result\":\"gecko block created\"}"));
                    }
                    else return(clonestr("{\"error\":\"gecko error creating hwmblock\"}"));
                } else return(clonestr("{\"result\":\"gecko block wasnt hwmblock\"}"));
            }
        }
        return(clonestr("{\"error\":\"gecko orphan block\"}"));
    } else printf("blockarrived error generating txlist\n");
    return(clonestr("{\"error\":\"gecko block didnt decode\"}"));
}

char *basilisk_respond_geckoblock(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash2,int32_t from_basilisk)
{
    char *symbol; struct iguana_info *virt; bits256 checkhash2; int32_t hdrsize; uint32_t prevtimestamp,nBits; struct iguana_msgblock msg; struct iguana_block *block;
    printf("got geckoblock len.%d from (%s) %s\n",datalen,remoteaddr!=0?remoteaddr:"",jprint(valsobj,0));
    if ( (symbol= jstr(valsobj,"symbol")) != 0 && (virt= iguana_coinfind(symbol)) != 0 )
    {
        if ( (block= iguana_blockfind("geckoblock",virt,hash2)) != 0 )
        {
            char str[65];
            if ( block->height == virt->blocks.hwmchain.height )
                return(clonestr("{\"result\":\"duplicate chaintip received\"}"));
            printf("REJECT: duplicate block %s\n",bits256_str(str,hash2));
            return(clonestr("{\"error\":\"duplicate block rejected\"}"));
        }
        hdrsize = (virt->chain->zcash != 0) ? sizeof(struct iguana_msgblockhdr_zcash) : sizeof(struct iguana_msgblockhdr);
        nBits = gecko_nBits(virt,&prevtimestamp,(struct iguana_block *)&virt->blocks.hwmchain,GECKO_DIFFITERS);
        if ( gecko_blocknonce_verify(virt,data,hdrsize,nBits,virt->blocks.hwmchain.RO.timestamp,prevtimestamp) > 0 )
        {
            iguana_rwblock(symbol,virt->chain->zcash,virt->chain->auxpow,virt->chain->hashalgo,0,&checkhash2,data,&msg,datalen);
            if ( bits256_cmp(hash2,checkhash2) == 0 )
                return(gecko_blockarrived(myinfo,virt,addr,data,datalen,hash2,0));
            else return(clonestr("{\"error\":\"block error with checkhash2\"}"));
        } else return(clonestr("{\"error\":\"block nonce didnt verify\"}"));
    }
    return(0);
}

int32_t basilisk_blocksubmit(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_info *virt,char *blockstr,bits256 hash2,int32_t height)
{
    int32_t i,datalen,num,numerrs,numresults=0; uint8_t *data,space[16384],*allocptr; cJSON *valsobj=0,*retjson,*retarray,*item; char *str,*str2,*othercoin; bits256 othertip;
    printf("blocksubmit.(%s)\n",blockstr);
    if ( (data= get_dataptr(sizeof(struct iguana_msghdr) + BASILISK_HDROFFSET,&allocptr,&datalen,space,sizeof(space),blockstr)) != 0 )
    {
        if ( (str= gecko_blockarrived(myinfo,virt,"127.0.0.1",data,datalen,hash2,0)) != 0 )
        {
            if ( (retjson= cJSON_Parse(str)) != 0 )
            {
                if ( jobj(retjson,"error") == 0 )
                {
                    valsobj = cJSON_CreateObject();
                    jaddnum(valsobj,"minresults",myinfo->numrelays - 1);
                    jaddnum(valsobj,"timeout",3000);
                    jaddnum(valsobj,"fanout",-1);
                    jaddnum(valsobj,"height",height);
                    jaddstr(valsobj,"symbol",virt->symbol);
                    if ( (str2= basilisk_standardservice("BLK",myinfo,hash2,valsobj,blockstr,0)) != 0 )
                    {
                        if ( 0 && (retarray= cJSON_Parse(str2)) != 0 )
                        {
                            numerrs = numresults = 0;
                            if ( (num= cJSON_GetArraySize(retarray)) > 0 )
                            {
                                for (i=0; i<num; i++)
                                {
                                    item = jitem(retarray,i);
                                    if ( jobj(item,"error") != 0 )
                                        numerrs++;
                                    else if ( jstr(item,"result") != 0 )
                                    {
                                        if ( (othercoin= jstr(item,"symbol")) != 0 && strcmp(othercoin,virt->symbol) == 0 && juint(item,"hwm") == height )
                                        {
                                            othertip = jbits256(item,"chaintip");
                                            if ( bits256_cmp(hash2,othertip) == 0 )
                                                numresults++;
                                            else numerrs++;
                                        } else numerrs++;
                                    }
                                }
                            }
                            printf("%s got responses.%d good.%d errs.%d (%s)\n","BLK",num,numresults,numerrs,str2);
                            free_json(retarray);
                        }
                        free(str2);
                    }
                    free_json(valsobj);
                }
                free_json(retjson);
            }
            free(str);
/*#ifndef __APPLE__
            if ( numresults >= (myinfo->numrelays >> 1) )
#endif
            {
                if ( (str= gecko_blockarrived(myinfo,virt,"127.0.0.1",data,datalen,hash2,0)) != 0 )
                    free(str);
            }*/
        }
    } else printf("basilisk_blocksumbit dataptr error\n");
    if ( allocptr != 0 )
        free(allocptr);
    return(numresults);
}

int32_t basilisk_respond_geckogetblock(struct supernet_info *myinfo,struct iguana_info *virt,uint8_t *serialized,int32_t maxsize,cJSON *valsobj,bits256 hash2)
{
    int32_t datalen = 0; char str[65];
    printf("GOT request for block.(%s)\n",bits256_str(str,hash2));
    // find block and set serialized
    return(datalen);
}
