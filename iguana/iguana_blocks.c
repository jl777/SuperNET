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

#define iguana_blockfind(str,coin,hash2) iguana_blockhashset(str,coin,-1,hash2,0)

void _iguana_blocklink(struct iguana_info *coin,struct iguana_block *prev,struct iguana_block *block)
{
    char str[65],str2[65]; struct iguana_block *next;
    if ( memcmp(block->RO.prev_block.bytes,prev->RO.hash2.bytes,sizeof(bits256)) != 0 )
    {
        printf("illegal blocklink mismatched hashes\n");
        exit(-1);
        return;
    }
    block->hh.prev = prev;
    if ( (next= prev->hh.next) != 0 )
    {
        if ( next != block )
        {
            if ( memcmp(next->RO.prev_block.bytes,prev->RO.hash2.bytes,sizeof(bits256)) != 0 )
            {
                printf("illegal blocklink next mismatched hashes\n");
                return;
            }
            if ( memcmp(next->RO.hash2.bytes,block->RO.hash2.bytes,sizeof(bits256)) != 0 )
                printf("blocklink collision: %s vs %s\n",bits256_str(str,block->RO.hash2),bits256_str(str2,next->RO.hash2));
            else printf("blocklink corruption: identical hashes with diff ptrs %s %p %p\n",bits256_str(str,block->RO.hash2),block,next);
        }
        prev->hh.next = block; // could make a linked list of all at same height for multibranch
    } else prev->hh.next = block;
    printf("link.(%s) -> (%s)\n",bits256_str(str,prev->RO.hash2),bits256_str(str,block->RO.hash2));
}

struct iguana_block *iguana_blockhashset(char *debugstr,struct iguana_info *coin,int32_t height,bits256 hash2,int32_t createflag)
{
    static int depth;
    struct iguana_block *block,*prev;
    if ( height > 0 && height > coin->blocks.maxbits )
    {
        printf("%s: illegal height.%d when max.%d, or nonz depth.%d\n",debugstr,height,coin->blocks.maxbits,depth);
        //getchar();
        return(0);
    }
    while ( depth != 0 )
    {
        printf(">>>>>>>>>> OK only if rare %s blockhashset.%d depth.%d\n",debugstr,height,depth);
        fprintf(stderr,">>>>>>>>>> OK only if rare %s blockhashset.%d depth.%d\n",debugstr,height,depth);
        //printf("%d\n",1/(1 - depth/depth));
    }
    depth++;
    HASH_FIND(hh,coin->blocks.hash,&hash2,sizeof(hash2),block);
    if ( block != 0 )
    {
        depth--;
        while ( depth != 0 )
        {
            printf(">>>>>>>>>> OK only if rare%s match blockhashset.%d depth.%d\n",debugstr,height,depth);
            fprintf(stderr,">>>>>>>>>> OK only if rare%s match blockhashset.%d depth.%d\n",debugstr,height,depth);
            printf("%d\n",1/(1 - depth/depth));
        }
        return(block);
    }
    if ( createflag > 0 )
    {
        portable_mutex_lock(&coin->blocks_mutex);
        block = calloc(1,sizeof(*block));
        block->RO.hash2 = hash2;
        block->hh.itemind = height, block->height = -1;
        HASH_ADD(hh,coin->blocks.hash,RO.hash2,sizeof(hash2),block);
        block->hh.next = block->hh.prev = 0;
        if ( bits256_nonz(block->RO.prev_block) > 0 )
        {
            HASH_FIND(hh,coin->blocks.hash,&block->RO.prev_block,sizeof(block->RO.prev_block),prev);
            if ( prev != 0 )
                _iguana_blocklink(coin,prev,block);
        }
        //char str[65]; printf("added.(%s) height.%d (%p %p)\n",bits256_str(str,hash2),height,block->hh.prev,block->hh.next);
        if ( 0 )
        {
            struct iguana_block *tmp;
            HASH_FIND(hh,coin->blocks.hash,&hash2,sizeof(hash2),tmp);
            char str[65];
            bits256_str(str,hash2);
            if ( tmp != block )
                printf("%s height.%d search error %p != %p\n",str,height,block,tmp);
        }
        portable_mutex_unlock(&coin->blocks_mutex);
    }
    depth--;
    while ( depth != 0 )
    {
        printf(">>>>>>>>>> OK only if rare%s create blockhashset.%d depth.%d\n",debugstr,height,depth);
        fprintf(stderr,">>>>>>>>>> OK only if rare%s create blockhashset.%d depth.%d\n",debugstr,height,depth);
        //printf("%d\n",1/(1 - depth/depth));
    }
    return(block);
}

bits256 *iguana_blockhashptr(struct iguana_info *coin,int32_t height)
{
    int32_t hdrsi,bundlei,bundlesize; struct iguana_bundle *bp; //bits256 *hashptr;
    if ( height >= 0 && (bundlesize= coin->chain->bundlesize) != 0 )
    {
        hdrsi = (height / bundlesize);
        bundlei = height - (hdrsi * bundlesize);
        if ( hdrsi >= 0 && hdrsi < bundlesize && bundlei >= 0 && bundlei < bundlesize && (bp= coin->bundles[hdrsi]) != 0 )
        {
            return(&bp->hashes[bundlei]);
        }
        /*for (i=0; i<coin->bundlescount; i++)
        {
            if ( (bp= coin->bundles[i]) != 0 )
            {
                if ( height >= bp->bundleheight && height < bp->bundleheight+bp->n )
                {
                    hashptr = &bp->hashes[height - bp->bundleheight];
                    //printf("i.%d hashptr.%p height.%d vs (%d %d)\n",i,hashptr,height,bp->bundleheight,bp->bundleheight+bp->n);
                    return(hashptr);
                }
            }
        }*/
    }
    return(0);
}

bits256 iguana_blockhash(struct iguana_info *coin,int32_t height)
{
    bits256 *hash2p; static const bits256 zero;
    if ( (hash2p= iguana_blockhashptr(coin,height)) != 0 )
        return(*hash2p);
    return(zero);
}

struct iguana_block *iguana_blockptr(char *debugstr,struct iguana_info *coin,int32_t height)
{
     static const bits256 zero; bits256 hash2 = iguana_blockhash(coin,height);
    if ( memcmp(zero.bytes,hash2.bytes,sizeof(zero)) != 0 )
        return(iguana_blockfind(debugstr,coin,hash2));
    return(0);
}

int32_t iguana_blockvalidate(struct iguana_info *coin,int32_t *validp,struct iguana_block *block,int32_t dispflag)
{
    bits256 hash2; uint8_t serialized[sizeof(struct iguana_msgblock) + 4096];
    *validp = 0;
    iguana_serialize_block(&hash2,serialized,block);
    *validp = (memcmp(hash2.bytes,block->RO.hash2.bytes,sizeof(hash2)) == 0);
    block->valid = *validp;
    char str[65]; char str2[65];
    if ( *validp == 0 )
    {
        if ( dispflag != 0 )
        {
            printf("iguana_blockvalidate: miscompare (%s) vs (%s)\n",bits256_str(str,hash2),bits256_str(str2,block->RO.hash2));
            //getchar();
        }
        return(-1);
    }
    return(0);
}

/*void iguana_mergeprevdep(struct iguana_prevdep *destlp,struct iguana_prevdep *srclp)
{
    if ( srclp->numpkinds > destlp->numpkinds )
        destlp->numpkinds = srclp->numpkinds;
    if ( srclp->numtxids > destlp->numtxids )
        destlp->numtxids = srclp->numtxids;
    if ( srclp->numunspents > destlp->numunspents )
        destlp->numunspents = srclp->numunspents;
    if ( srclp->numspends > destlp->numspends )
        destlp->numspends = srclp->numspends;
    if ( srclp->PoW > destlp->PoW )
        destlp->PoW = srclp->PoW;
}

void iguana_blockmerge(struct iguana_block *dest,struct iguana_prevdep *destlp,struct iguana_block *block,struct iguana_prevdep *srclp)
{
    if ( block->numvins > dest->numvins )
        dest->numvins = block->numvins;
    if ( block->numvouts > dest->numvouts )
        dest->numvouts = block->numvouts;
    if ( block->txn_count > dest->txn_count )
        dest->txn_count = block->txn_count;
    if ( dest->height == 0 )
        dest->height = block->height;
    iguana_mergeprevdep(destlp,srclp);
}*/

void iguana_blockconv(struct iguana_block *dest,struct iguana_msgblock *msg,bits256 hash2,int32_t height) //uint32_t numtxids,uint32_t numunspents,uint32_t numspends,double PoW)
{
    memset(dest,0,sizeof(*dest));
    dest->RO.version = msg->H.version;
    dest->RO.prev_block = msg->H.prev_block;
    dest->RO.merkle_root = msg->H.merkle_root;
    dest->RO.timestamp = msg->H.timestamp;
    dest->RO.bits = msg->H.bits;
    dest->RO.nonce = msg->H.nonce;
    dest->RO.txn_count = msg->txn_count;
    dest->height = height;
    dest->RO.hash2 = hash2;
}

void iguana_blockcopy(struct iguana_info *coin,struct iguana_block *block,struct iguana_block *origblock)
{
    block->RO.hash2 = origblock->RO.hash2;
    block->RO.merkle_root = origblock->RO.merkle_root;
    if ( bits256_nonz(block->RO.prev_block) == 0 )
        block->RO.prev_block = origblock->RO.prev_block;
    if ( block->mainchain == 0 )
        block->mainchain = origblock->mainchain;
    if ( block->fpos < 0 )
        block->fpos = origblock->fpos;
    if ( block->fpipbits == 0 )
        block->fpipbits = origblock->fpipbits;
    if ( block->RO.timestamp == 0 )
        block->RO.timestamp = origblock->RO.timestamp;
    if ( block->RO.nonce == 0 )
        block->RO.nonce = origblock->RO.nonce;
    if ( block->RO.bits == 0 )
        block->RO.bits = origblock->RO.bits;
    if ( block->RO.txn_count == 0 )
        block->RO.txn_count = origblock->RO.txn_count;
    if ( block->RO.version == 0 )
        block->RO.version = origblock->RO.version;
    if ( block->mainchain == 0 )
        block->mainchain = origblock->mainchain;
    if ( block->valid == 0 )
        block->valid = origblock->valid;
    if ( block->RO.recvlen == 0 )
        block->RO.recvlen = origblock->RO.recvlen;
}

double PoW_from_compact(uint32_t nBits,uint8_t unitval) // NOT consensus safe, but most of the time will be correct
{
	uint32_t nbytes,nbits,i,n; double PoW; uint64_t mult;
    nbytes = (nBits >> 24) & 0xFF;
    nbits = (8 * (nbytes - 3));
    PoW = (nBits & 0xFFFFFF);
    if ( nbytes > unitval )
    {
        printf("illegal nBits.%x\n",nBits);
        return(0.);
    }
    if ( (n= ((8* (unitval-3)) - nbits)) != 0 ) // 0x1d00ffff is genesis nBits so we map that to 1.
    {
        //printf("nbits.%d -> n.%d\n",nbits,n);
        if ( n < 64 )
            PoW /= (1LL << n);
        else // very rare case efficiency not issue
        {
            for (i=0; i<n; i++)
                PoW /= 2.;
        }
    }
    mult = 1;
    while ( nbytes++ < 30 )
        mult <<= 8;
    PoW = (PoW * mult) / (nBits & 0xffffff);
    //printf("nBits.%x -> %.15f diff %.15f | n.%d unitval.%d nbytes.%d\n",nBits,PoW,1./PoW,n,unitval,nbytes);
    return(PoW);
}

int32_t iguana_blockunmain(struct iguana_info *coin,struct iguana_block *block)
{
    struct iguana_block *next; int32_t n = 0;
    while ( block != 0 )
    {
        //printf("n.%d %p (%p %p) mainchain.%d delink %d\n",n,block,block->hh.prev,block->hh.next,block->mainchain,block->height);
        block->mainchain = 0;
        next = block->hh.next;
        block = next;
        n++;
    }
    if ( n > 1000 )
        printf("delinked.%d\n",n);
    return(n);
}

int32_t iguana_walkchain(struct iguana_info *coin)
{
    char str[65]; int32_t height,hdrsi,bundlei,n = 0; struct iguana_block *block;
    height = coin->blocks.hwmchain.height;
    while ( (block= iguana_blockfind("main",coin,iguana_blockhash(coin,height))) != 0 )
    {
        hdrsi = (height / coin->chain->bundlesize);
        bundlei = (height % coin->chain->bundlesize);
        if ( bits256_cmp(iguana_blockhash(coin,height),block->RO.hash2) != 0 )
        {
            printf("blockhash error at %d %s\n",height,bits256_str(str,block->RO.hash2));
            break;
        }
        n++;
        height--;
    }
    printf("n.%d vs hwm.%d %s\n",n,coin->blocks.hwmchain.height,bits256_str(str,coin->blocks.hwmchain.RO.hash2));
    return(n);
}

struct iguana_block *_iguana_chainlink(struct iguana_info *coin,struct iguana_block *newblock)
{
    int32_t valid,bundlei,height=-1; struct iguana_block *hwmchain,*block = 0,*prev=0,*next;
    bits256 *hash2p=0; double prevPoW = 0.; struct iguana_bundle *bp;
    if ( newblock == 0 )
        return(0);
    hwmchain = &coin->blocks.hwmchain;
    if ( 0 && hwmchain->height > 0 && ((bp= coin->current) == 0 || hwmchain->height/coin->chain->bundlesize > bp->hdrsi+0*bp->isRT) )
        return(0);
    if ( (block= iguana_blockfind("chainlink",coin,newblock->RO.hash2)) != 0 )
    {
        if ( memcmp(coin->chain->genesis_hashdata,block->RO.hash2.bytes,sizeof(bits256)) == 0 )
            block->PoW = PoW_from_compact(block->RO.bits,coin->chain->unitval), height = 0;
        else if ( (prev= iguana_blockfind("chainprev",coin,block->RO.prev_block)) != 0 )
        {
            if ( memcmp(prev->RO.hash2.bytes,coin->blocks.hwmchain.RO.hash2.bytes,sizeof(bits256)) == 0 )
                prev->mainchain = 1;
            if ( prev->valid != 0 && prev->mainchain != 0 && prev->height >= 0 )
            {
                prevPoW = prev->PoW;
                block->PoW = PoW_from_compact(block->RO.bits,coin->chain->unitval) + prevPoW;
                if ( (next= prev->hh.next) != 0 )
                {
                    if ( next->mainchain != 0 && block->PoW < next->PoW )
                        return(0);
                    hwmchain = next;
                }
                height = prev->height + 1;
            }
            else
            {
                //char str[65]; printf("(%s) notready v.%d m.%d h.%d\n",bits256_str(str,prev->RO.hash2),prev->valid,prev->mainchain,prev->height);
                return(0);
            }
        }
        else
        {
            char str[65];
            if ( 0 && bits256_nonz(block->RO.prev_block) != 0 )
                printf("chainlink error: cant find prev.(%s)\n",bits256_str(str,block->RO.prev_block));
            iguana_blockunmark(coin,block,0,-1,0);
            //memset(&block->RO.prev_block.bytes,0,sizeof(block->RO.prev_block));
            //getchar();
            return(0);
        }
        //char str[65]; printf("extend? %s.h%d: %.15f vs %.15f ht.%d vs %d\n",bits256_str(str,block->RO.hash2),height,block->PoW,coin->blocks.hwmchain.PoW,height,coin->blocks.hwmchain.height);
        if ( iguana_blockvalidate(coin,&valid,newblock,0) < 0 || valid == 0 )
            return(0);
        block->height = height;
        block->valid = 1;
        if ( block->PoW >= hwmchain->PoW )
        {
            block->hh.prev = prev;
            if ( prev != 0 )
            {
                //if ( prev->hh.next != block )
                //    iguana_blockunmain(coin,prev->hh.next);
                prev->hh.next = block;
            }
            if ( coin->isRT != 0 || block->height == hwmchain->height )
            {
                coin->blocks.maxblocks = (block->height + 1);
                coin->blocks.hwmchain = *block;
                //printf("[%s] <- ht.%d\n",bits256_str(str,block->hash2),coin->blocks.hwmheight);
                char str[65],str2[65]; bits256 zero;
                memset(&zero,0,sizeof(zero));
                bits256_str(str,newblock->RO.hash2);
                if ( hash2p != 0 )
                    bits256_str(str2,*hash2p);
                else str2[0] = 0;
                if ( block->height+1 > coin->longestchain )
                    coin->longestchain = block->height+1;
                if ( 0 && (block->height % 1000) == 0 )
                    printf("EXTENDMAIN %s %d <- (%s) n.%u max.%u PoW %f numtx.%d valid.%d\n",str,block->height,str2,hwmchain->height+1,coin->blocks.maxblocks,block->PoW,block->RO.txn_count,block->valid);
                struct iguana_bundle *bp; int32_t hdrsi;
                if ( (block->height % coin->chain->bundlesize) == 0 )
                {
                    if ( (hdrsi= block->height/coin->chain->bundlesize) < coin->bundlescount )
                    {
                        if ( (bp= coin->bundles[hdrsi]) != 0 && bits256_cmp(block->RO.hash2,bp->hashes[0]) != 0 )
                        {
                            printf(">>>>>>>>>>>>>> interloper bundle.[%d] ht.%d %s != %s\n",hdrsi,block->height,bits256_str(str,bp->hashes[0]),bits256_str(str2,block->RO.hash2));
                            coin->bundles[hdrsi] = 0;
                        }
                    }
                    bp = iguana_bundlecreate(coin,&bundlei,block->height,block->RO.hash2,zero,0);
                    if ( bp != 0 && bp->hdrsi == coin->bundlescount-1 )
                    {
                        //printf("created last bundle ht.%d\n",bp->bundleheight);
                        iguana_blockreq(coin,block->height,1);
                    }
                }
                else
                {
                    if ( (bp= coin->bundles[block->height / coin->chain->bundlesize]) != 0 )
                    {
                        if ( memcmp(bp->hashes[block->height % coin->chain->bundlesize].bytes,block->RO.hash2.bytes,sizeof(bits256)) != 0 || block != bp->blocks[block->height % coin->chain->bundlesize] )
                        {
                            if ( bits256_nonz(bp->hashes[block->height % coin->chain->bundlesize]) > 0 )
                            {
                                printf("ERROR: need to fix up bundle for height.%d\n",block->height);
                                //getchar();
                            }
                            iguana_bundlehash2add(coin,0,bp,block->height % coin->chain->bundlesize,block->RO.hash2);
                        }
                        if ( coin->started != 0 && (block->height % coin->chain->bundlesize) == coin->minconfirms )//&& (block->height > coin->longestchain-coin->chain->bundlesize*2 || ((block->height / coin->chain->bundlesize) % 10) == 9) )
                        {
                            //printf("savehdrs.[%d] ht.%d\n",bp->hdrsi,block->height);
                            iguana_savehdrs(coin);
                            //printf("done savehdrs.%d\n",bp->hdrsi);
                        }
                    }
                }
                if ( 0 && block->fpipbits == 0 ) //strcmp("BTC",coin->symbol) == 0 &&
                {
                    iguana_blockreq(coin,block->height+1,0);
                    //iguana_blockQ("mainchain",coin,bp,block->height % coin->chain->bundlesize,block->RO.hash2,0);
                }
                block->mainchain = 1;
                iguana_walkchain(coin);
                return(block);
            }
        }
    } else printf("chainlink error from block.%p\n",block);
    return(0);
}

void iguana_blocksetheights(struct iguana_info *coin,struct iguana_block *block)
{
    int32_t height;
    if ( (height= block->height) < 0 )
        return;
    while ( block != 0 && block->height != height )
    {
        block->height = height;
        iguana_bundlehash2add(coin,0,coin->bundles[height/coin->chain->bundlesize],height % coin->chain->bundlesize,block->RO.hash2);
        block = block->hh.next, height++;
    }
}

int32_t iguana_chainextend(struct iguana_info *coin,struct iguana_block *newblock)
{
    struct iguana_block *block,*prev; int32_t valid,oldhwm; char str[65];
    if ( iguana_blockvalidate(coin,&valid,newblock,0) < 0 || valid == 0 )
    {
        printf("chainextend: newblock.%s didnt validate\n",bits256_str(str,newblock->RO.hash2));
        return(-1);
    }
    else
    {
        block = iguana_blockhashset("chainextend",coin,-1,newblock->RO.hash2,1);
        if ( block != newblock )
            iguana_blockcopy(coin,block,newblock);
        block->valid = 1;
        if ( block->hh.prev == 0 && (prev= iguana_blockfind("extendprev",coin,block->RO.prev_block)) != 0 )
        {
            if ( prev->hh.next == 0 && block->hh.prev == 0 )
                prev->hh.next = block, block->hh.prev = prev;
            //printf("extend newblock.%s prevm.%d\n",bits256_str(str,block->prev_block),prev->mainchain);
            if ( prev->mainchain == 0 )
            {
                if ( (block= iguana_blockfind("extendmain",coin,coin->blocks.hwmchain.RO.hash2)) != 0 && block->mainchain == 0 )
                {
                    //printf("c hwmchain is not mainchain anymore?\n");
                    prev->mainchain = 1;
                } else return(0);
            }
        }
        if ( memcmp(block->RO.prev_block.bytes,coin->blocks.hwmchain.RO.hash2.bytes,sizeof(bits256)) != 0 )
            return(0);
    }
    if ( block != 0 )
    {
        oldhwm = coin->blocks.hwmchain.height;
        //printf("link.%s\n",bits256_str(str,block->hash2));
        while ( block != 0 && memcmp(block->RO.hash2.bytes,coin->blocks.hwmchain.RO.hash2.bytes,sizeof(bits256)) != 0 && _iguana_chainlink(coin,block) == block && coin->blocks.hwmchain.height != oldhwm )
        {
            oldhwm = coin->blocks.hwmchain.height;
            block = block->hh.next;
            if ( block != 0 )
            {
                if ( bits256_nonz(block->RO.prev_block) == 0 )
                    break;
                //printf("next link.%s\n",bits256_str(str,block->hash2));
            }
        }
    }
    if ( (block= iguana_blockfind("extendcheck",coin,coin->blocks.hwmchain.RO.hash2)) != 0 && block->mainchain == 0 )
    {
        printf("hwmchain is not mainchain anymore?\n");
        block->mainchain = 1;
    }
    return(coin->blocks.hwmchain.height);
}
