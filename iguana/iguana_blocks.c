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

void iguana_blockconv(uint8_t zcash,uint8_t auxpow,struct iguana_block *dest,struct iguana_msgblock *msg,bits256 hash2,int32_t height) //uint32_t numtxids,uint32_t numunspents,uint32_t numspends,double PoW)
{
    int32_t i;
    memset(dest,0,sizeof(*dest));
    dest->RO.version = msg->H.version;
    dest->RO.prev_block = msg->H.prev_block;
    dest->RO.merkle_root = msg->H.merkle_root;
    dest->RO.timestamp = msg->H.timestamp;
    dest->RO.bits = msg->H.bits;
    dest->RO.txn_count = msg->txn_count;
    dest->height = height;
    dest->RO.hash2 = hash2;
    if ( zcash == 0 )
        dest->RO.nonce = msg->H.nonce;
    else
    {
        dest->RO.allocsize = (int32_t)(sizeof(*dest) + sizeof(*dest->zRO));
        dest->zRO[0].bignonce = msg->zH.bignonce;
        for (i=0; i<ZCASH_SOLUTION_ELEMENTS; i++)
            dest->zRO[0].solution[i] = msg->zH.solution[i];
    }
}

void iguana_blockunconv(uint8_t zcash,uint8_t auxpow,struct iguana_msgblock *msg,struct iguana_block *src,int32_t cleartxn_count)
{
    int32_t i;
    memset(msg,0,sizeof(*msg));
    msg->H.version = src->RO.version;
    msg->H.prev_block = src->RO.prev_block;
    msg->H.merkle_root = src->RO.merkle_root;
    msg->H.timestamp = src->RO.timestamp;
    msg->H.bits = src->RO.bits;
    if ( zcash == 0 )
        msg->H.nonce = src->RO.nonce;
    else
    {
        msg->zH.bignonce = src->zRO[0].bignonce;
        msg->zH.numelements = ZCASH_SOLUTION_ELEMENTS;
        for (i=0; i<ZCASH_SOLUTION_ELEMENTS; i++)
            msg->zH.solution[i] = src->zRO[0].solution[i];
    }
    if ( cleartxn_count == 0 )
        msg->txn_count = src->RO.txn_count;
}

void iguana_blockcopy(uint8_t zcash,uint8_t auxpow,struct iguana_info *coin,struct iguana_block *block,struct iguana_block *origblock)
{
    int32_t i;
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
    if ( zcash == 0 )
    {
        if ( block->RO.nonce == 0 )
            block->RO.nonce = origblock->RO.nonce;
    }
    else
    {
        if ( block->RO.allocsize != origblock->RO.allocsize || block->RO.allocsize != sizeof(*block) + sizeof(*block->zRO) )
            printf("missing space for zcash block.%d origblock.%d\n",block->RO.allocsize,origblock->RO.allocsize);
        else
        {
            block->zRO[0].bignonce = origblock->zRO[0].bignonce;
            for (i=0; i<ZCASH_SOLUTION_ELEMENTS; i++)
                block->zRO[0].solution[i] = origblock->zRO[0].solution[i];
        }
    }
}

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

struct iguana_block *iguana_prevblock(struct iguana_info *coin,struct iguana_block *block,int32_t PoSflag)
{
    int32_t hdrsi,bundlei,height; struct iguana_bundle *bp;
    if ( (height= block->height - 1) < 0 )
        return(0);
    hdrsi = (height / coin->chain->bundlesize);
    bundlei = (height % coin->chain->bundlesize);
    if ( hdrsi < coin->bundlescount && (bp= coin->bundles[hdrsi]) != 0 )
        return(bp->blocks[bundlei]);
    else return(0);
}

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
    struct iguana_block *block,*prev;
    /*if ( height > 0 && height > coin->blocks.maxbits )
    {
        printf("%s: illegal height.%d when max.%d, or nonz depth.%d\n",debugstr,height,coin->blocks.maxbits,coin->blockdepth);
        //getchar();
        return(0);
    }*/
    while ( coin->blockdepth > 0 )
    {
        sleep(1);
        if ( coin->blockdepth > 0 )
            printf("A %s >>>>>>>>>> OK only if rare %s blockhashset.%d depth.%d\n",coin->symbol,debugstr,height,coin->blockdepth);
        //fprintf(stderr,">>>>>>>>>> OK only if rare %s blockhashset.%d depth.%d\n",debugstr,height,depth);
        //printf("%d\n",1/(1 - depth/depth));
    }
    coin->blockdepth++;
    HASH_FIND(hh,coin->blocks.hash,&hash2,sizeof(hash2),block);
    if ( block != 0 )
    {
        if ( coin->blockdepth > 0 )
            coin->blockdepth--;
        while ( coin->blockdepth > 0 )
        {
            sleep(1);
            if ( coin->blockdepth > 0 )
                printf("B %s >>>>>>>>>> OK only if rare %s match blockhashset.%d depth.%d\n",coin->symbol,debugstr,height,coin->blockdepth);
            //fprintf(stderr,">>>>>>>>>> OK only if rare%s match blockhashset.%d depth.%d\n",debugstr,height,depth);
            //printf("%d\n",1/(1 - depth/depth));
        }
        return(block);
    }
    if ( createflag > 0 )
    {
        portable_mutex_lock(&coin->blocks_mutex);
        block = calloc(1,sizeof(*block) + coin->chain->zcash*sizeof(*block->zRO));
        block->RO.hash2 = hash2;
        block->RO.allocsize = coin->chain->zcash != 0 ? sizeof(*block) : sizeof(struct iguana_zblock);
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
    if ( coin->blockdepth > 0 )
        coin->blockdepth--;
    while ( coin->blockdepth > 0 )
    {
        sleep(1);
        if ( coin->blockdepth > 0 )
            printf("C %s >>>>>>>>>> OK only if rare %s create blockhashset.%d depth.%d\n",coin->symbol,debugstr,height,coin->blockdepth);
        //fprintf(stderr,">>>>>>>>>> OK only if rare%s create blockhashset.%d depth.%d\n",debugstr,height,depth);
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
        if ( hdrsi >= 0 && hdrsi < coin->bundlescount && bundlei >= 0 && bundlei < bundlesize )
        {
            if ( (bp= coin->bundles[hdrsi]) != 0 )
                return(&bp->hashes[bundlei]);
            else return(0);
        }
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
    iguana_serialize_block(coin->chain,&hash2,serialized,block);
    *validp = (memcmp(hash2.bytes,block->RO.hash2.bytes,sizeof(hash2)) == 0);
    block->valid = *validp;
    if ( block->RO.allocsize == 0 )
        block->RO.allocsize = coin->chain->zcash != 0 ? sizeof(*block) : sizeof(struct iguana_zblock);
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

double PoW_from_compact(uint32_t nBits,uint8_t unitval) // NOT consensus safe, but most of the time will be correct
{
	uint32_t nbytes,nbits,i,n; double PoW; uint64_t mult;
    nbytes = (nBits >> 24) & 0xFF;
    nbits = (8 * (nbytes - 3));
    PoW = (nBits & 0xFFFFFF);
    if ( 1 && nbytes > unitval )
    {
        printf("illegal nBits.%x unitval.%02x\n",nBits,unitval);
        return(0.);
    }
    if ( (n= ((8 * (unitval-3)) - nbits)) != 0 ) // 0x1d00ffff is genesis nBits so we map that to 1.
    {
        //printf("nbits.%d -> n.%d\n",nbits,n);
        if ( n < 64 )
            PoW /= (1LL << n);
        else // rare case efficiency not issue
        {
            for (i=0; i<n; i++)
                PoW /= 2.;
        }
    }
    mult = 1;
    while ( nbytes++ < unitval )
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

int32_t iguana_walkchain(struct iguana_info *coin,int32_t skipflag)
{
    char str[65]; int32_t height,hdrsi,bundlei,n = 0; struct iguana_bundle *bp; struct iguana_block *block;
    height = coin->blocks.hwmchain.height;
    while ( 1 ) //(block= iguana_blockfind("main",coin,iguana_blockhash(coin,height))) != 0 )
    {
        hdrsi = (height / coin->chain->bundlesize);
        bundlei = (height % coin->chain->bundlesize);
        if ( (bp= coin->bundles[hdrsi]) == 0 || (block= bp->blocks[bundlei]) == 0 )
        {
            printf("walk error [%d:%d] %p vs %p\n",hdrsi,bundlei,block,bp->blocks[bundlei]);
            break;
        }
        else if ( block->height >= 0 && block->height != height )
            printf("walkchain height mismatch %d vs %d\n",block->height,height);
        if ( bits256_nonz(iguana_blockhash(coin,height)) != 0 && bits256_cmp(iguana_blockhash(coin,height),block->RO.hash2) != 0 )
        {
            printf("walk error blockhash error at %d %s\n",height,bits256_str(str,iguana_blockhash(coin,height)));
            break;
        }
        else if ( bits256_cmp(bp->hashes[bundlei],block->RO.hash2) != 0 )
        {
            printf("walk error [%d:%d] %s vs %s\n",hdrsi,bundlei,bits256_str(str,bp->hashes[bundlei]),bits256_str(str,block->RO.hash2));
            break;
        }
        else if ( block->hdrsi != hdrsi || block->bundlei != bundlei )
        {
            printf("walk error [%d:%d] vs [%d:%d]\n",hdrsi,bundlei,block->hdrsi,block->bundlei);
            break;
        }
        if ( height == 0 )
            break;
        else if ( skipflag != 0 && (height % coin->chain->bundlesize) == 0 )
        {
            n += coin->chain->bundlesize;
            height -= coin->chain->bundlesize;
        }
        else
        {
            n++;
            height--;
        }
    }
    //printf("walk skip.%d n.%d hwm.%d %s\n",skipflag,n,coin->blocks.hwmchain.height,bits256_str(str,coin->blocks.hwmchain.RO.hash2));
    return(n);
}

struct iguana_block *iguana_fastlink(struct iguana_info *coin,int32_t hwmheight)
{
    int32_t hdrsi,bundlei,height; struct iguana_block *block = 0,*prev=0; double prevPoW = 0.; struct iguana_bundle *bp;
    for (height=0; height<=hwmheight; height++)
    {
        hdrsi = (height / coin->chain->bundlesize);
        bundlei = (height % coin->chain->bundlesize);
/*#ifndef __PNACL__
        if ( (height % 10000) == 0 )
            fprintf(stderr,".");
#endif*/
        if ( (bp= coin->bundles[hdrsi]) == 0 )
        {
            printf("iguana_fastlink null bundle.[%d]\n",hdrsi);
            break;
        }
        block = iguana_blockhashset("fastlink",coin,height,bp->hashes[bundlei],1);
        if ( bp->blocks[bundlei] != 0 && block != bp->blocks[bundlei] )
        {
            printf("iguana_fastlink null block.[%d:%d]\n",hdrsi,bundlei);
            break;
        }
        if ( prev != 0 && bits256_nonz(block->RO.prev_block) == 0 )
        {
            block->RO.prev_block = prev->RO.hash2;
            printf("PATCH.[%d:%d] prev is null\n",bp->hdrsi,bundlei);
            break;
        }
        bp->blocks[bundlei] = block;
        coin->blocks.maxblocks = (block->height + 1);
        if ( coin->blocks.maxblocks > coin->longestchain )
            coin->longestchain = coin->blocks.maxblocks;
        memcpy(&coin->blocks.hwmchain,block,block->RO.allocsize);
        block->valid = block->mainchain = 1;
        block->hdrsi = hdrsi, block->bundlei = bundlei;
        block->height = height;
        block->PoW = PoW_from_compact(block->RO.bits,coin->chain->unitval) + prevPoW;
        block->hh.prev = prev;
        if ( prev != 0 )
            prev->hh.next = block;
        iguana_hash2set(coin,"fastlink",bp,bundlei,block->RO.hash2);
        //iguana_bundlehash2add(coin,0,bp,bundlei,block->RO.hash2);
        prev = block;
        prevPoW = block->PoW;
    }
    return(block);
}

int32_t process_iguanablock(void *pblock,void *chainparams);

void *CHAINPARMS;
void iguana_setchain(void *chainparms)
{
    extern int32_t MAIN_initflag;
    MAIN_initflag = 1;
    OS_init();
    CHAINPARMS = chainparms;
    printf("iguana_setchain chainparms.%p\n",chainparms);
    iguana_launch(0,"iguana_main",iguana_main,0,0);
    printf("RETURN iguana_setchain chainparms.%p\n",chainparms);
}

struct iguana_block *_iguana_chainlink(struct iguana_info *coin,struct iguana_block *newblock)
{
    int32_t valid,bundlei,height=-1; struct iguana_block *hwmchain,*block = 0,*prev=0,*next;
    bits256 *hash2p=0; double prevPoW = 0.; struct iguana_bundle *bp;
    if ( newblock == 0 )
        return(0);
    if ( newblock->RO.allocsize == 0 )
        newblock->RO.allocsize = coin->chain->zcash != 0 ? sizeof(*newblock) : sizeof(struct iguana_zblock);
    hwmchain = (struct iguana_block *)&coin->blocks.hwmchain;
    if ( 0 && hwmchain->height > 0 && ((bp= coin->current) == 0 || hwmchain->height/coin->chain->bundlesize > bp->hdrsi+0*bp->isRT) )
        return(0);
    if ( (block= iguana_blockfind("chainlink",coin,newblock->RO.hash2)) != 0 )
    {
        if ( block->RO.allocsize == 0 )
            block->RO.allocsize = coin->chain->zcash != 0 ? sizeof(*newblock) : sizeof(struct iguana_zblock);
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
                    //printf("block->PoW %f next %f\n",block->PoW,next->PoW);
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
                memcpy(&coin->blocks.hwmchain,block,block->RO.allocsize);
                //printf("[%s] <- ht.%d %f\n",bits256_str(str,block->RO.hash2),coin->blocks.hwmchain.height,coin->blocks.hwmchain.PoW);
                char str[65],str2[65]; bits256 zero;
                memset(&zero,0,sizeof(zero));
                bits256_str(str,newblock->RO.hash2);
                if ( hash2p != 0 )
                    bits256_str(str2,*hash2p);
                else str2[0] = 0;
                if ( coin->blocks.maxblocks > coin->longestchain )
                    coin->longestchain = coin->blocks.maxblocks;
                if ( 1 && (block->height % coin->chain->bundlesize) == 0 )
                {
                    printf("EXTENDMAIN %s %d <- (%s) n.%u max.%u PoW %f numtx.%d valid.%d\n",str,block->height,str2,hwmchain->height+1,coin->blocks.maxblocks,block->PoW,block->RO.txn_count,block->valid);
                    //iguana_walkchain(coin);
                }
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
                            if ( bits256_nonz(bp->hashes[block->height % coin->chain->bundlesize]) != 0 )
                            {
                                if ( bp->blocks[block->height % coin->chain->bundlesize] == 0 && block != 0 )
                                    bp->blocks[block->height % coin->chain->bundlesize] = block;
                                else
                                {
                                    char str[65],str2[65];
                                    printf("ERROR: need to fix up bundle for height.%d (%p %p) (%s %s)\n",block->height,block,bp->blocks[block->height % coin->chain->bundlesize],bits256_str(str,block->RO.hash2),bits256_str(str2,bp->hashes[block->height % coin->chain->bundlesize]));
                                    if ( bp == coin->current && coin->RTheight > 0 )
                                        coin->RTdatabad = 1;
                                    //iguana_bundleremove(coin,bp->hdrsi,0);
                                    //exit(-1);
                                    //getchar();
                                }
                            }
                            iguana_blockunmark(coin,block,bp,block->height % coin->chain->bundlesize,0);
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
                block->mainchain = 1;
                if ( coin->blocks.pending > 0 )
                    coin->blocks.pending--;
                /*if ( block->serdata != 0 )
                {
                    printf(" call process_iguanablock2.%p ht.%d nbits.%08x\n",block->serdata,block->height,*(uint32_t *)&block->serdata[72]);
                    process_iguanablock(block->serdata,CHAINPARMS);
                }*/
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
            iguana_blockcopy(coin->chain->zcash,coin->chain->auxpow,coin,block,newblock);
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
