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

// peer context, ie massively multithreaded -> bundlesQ

struct iguana_bundlereq *iguana_bundlereq(struct iguana_info *coin,struct iguana_peer *addr,int32_t type,int32_t datalen)
{
    struct iguana_bundlereq *req; int32_t allocsize;
    allocsize = (uint32_t)sizeof(*req) + datalen;
    req = mycalloc(type,1,allocsize);
    req->allocsize = allocsize;
    req->datalen = datalen;
    req->addr = addr;
    req->coin = coin;
    req->type = type;
    return(req);
}

int32_t iguana_sendblockreqPT(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t iamthreadsafe)
{
    static bits256 lastreq,lastreq2;
    int32_t len; uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(uint32_t)*32 + sizeof(bits256)];
    char hexstr[65]; init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
    if ( memcmp(lastreq.bytes,hash2.bytes,sizeof(hash2)) == 0 || memcmp(lastreq2.bytes,hash2.bytes,sizeof(hash2)) == 0 )
    {
        //printf("duplicate req\n");
        return(0);
    }
    lastreq2 = lastreq;
    lastreq = hash2;
    if ( addr->msgcounts.verack == 0 )
    {
        printf("iguana_sendblockreq %s hasn't verack'ed yet\n",addr->ipaddr);
        return(-1);
    }
    if ( (len= iguana_getdata(coin,serialized,MSG_BLOCK,hexstr)) > 0 )
    {
        iguana_send(coin,addr,serialized,len);
        coin->numreqsent++;
        addr->pendblocks++;
        addr->pendtime = (uint32_t)time(NULL);
        //printf("REQ.%s bundlei.%d hdrsi.%d\n",bits256_str(hexstr,hash2),bundlei,bp!=0?bp->hdrsi:-1);
    } else printf("MSG_BLOCK null datalen.%d\n",len);
    return(len);
}

int32_t iguana_sendtxidreq(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2)
{
    uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(uint32_t)*32 + sizeof(bits256)];
    int32_t len,i,r,j; char hexstr[65]; init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
    if ( (len= iguana_getdata(coin,serialized,MSG_TX,hexstr)) > 0 )
    {
        if ( addr == 0 )
        {
            r = rand();
            for (i=0; i<coin->MAXPEERS; i++)
            {
                j = (i + r) % coin->MAXPEERS;
                addr = &coin->peers.active[j];
                if ( coin->peers.active[j].usock >= 0 && coin->peers.active[j].dead == 0 )
                {
                    iguana_send(coin,addr,serialized,len);
                    break;
                }
            }
        } else iguana_send(coin,addr,serialized,len);
    } else printf("MSG_TX null datalen.%d\n",len);
    printf("send MSG_TX.%d\n",len);
    return(len);
}

int32_t iguana_txidreq(struct iguana_info *coin,char **retstrp,bits256 txid)
{
    int32_t i;
    while ( coin->numreqtxids >= sizeof(coin->reqtxids)/sizeof(*coin->reqtxids) )
    {
        printf("txidreq full, wait\n");
        sleep(1);
    }
    char str[65]; printf("txidreq.%s\n",bits256_str(str,txid));
    coin->reqtxids[coin->numreqtxids++] = txid;
    for (i=0; i<coin->MAXPEERS; i++)
        if ( coin->peers.active[i].usock >= 0 )
            iguana_sendtxidreq(coin,coin->peers.ranked[i],txid);
    return(0);
}

void iguana_gotunconfirmedM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgtx *tx,uint8_t *data,int32_t datalen)
{
    struct iguana_bundlereq *req;
    char str[65]; printf("%s unconfirmed.%s\n",addr->ipaddr,bits256_str(str,tx->txid));
    req = iguana_bundlereq(coin,addr,'U',datalen);
    req->datalen = datalen;
    req->txid = tx->txid;
    memcpy(req->serialized,data,datalen);
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotblockM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *origtxdata,struct iguana_msgtx *txarray,struct iguana_msghdr *H,uint8_t *data,int32_t recvlen)
{
    struct iguana_bundlereq *req; struct iguana_txblock *txdata = 0; int32_t i,j,bundlei,copyflag; char fname[1024];
    struct iguana_bundle *bp;
    if ( 0 )
    {
        for (i=0; i<txdata->space[0]; i++)
            if ( txdata->space[i] != 0 )
                break;
        if ( i != txdata->space[0] )
        {
            for (i=0; i<txdata->space[0]; i++)
                printf("%02x ",txdata->space[i]);
            printf("extra\n");
        }
    }
    if ( coin->numreqtxids > 0 )
    {
        for (i=0; i<origtxdata->block.RO.txn_count; i++)
        {
            for (j=0; j<coin->numreqtxids; j++)
            {
                if ( memcmp(coin->reqtxids[j].bytes,txarray[i].txid.bytes,sizeof(bits256)) == 0 )
                {
                    char str[65]; printf("i.%d j.%d found txid.%s\n",i,j,bits256_str(str,coin->reqtxids[j]));
                }
            }
        }
    }
    copyflag = 0 * (strcmp(coin->symbol,"BTC") != 0);
    req = iguana_bundlereq(coin,addr,'B',copyflag * recvlen);
    req->recvlen = recvlen;
    req->H = *H;
    bp = 0, bundlei = -2;
    if ( copyflag != 0 && recvlen != 0 && ((bp= iguana_bundlefind(coin,&bp,&bundlei,origtxdata->block.RO.hash2)) == 0 || (bp->blocks[bundlei] != 0 && bp->blocks[bundlei]->fpipbits == 0)) )
    {
        //printf("copy %p serialized[%d]\n",req,req->recvlen);
        memcpy(req->serialized,data,recvlen), req->copyflag = 1;
    }
    if ( bits256_cmp(origtxdata->block.RO.hash2,coin->APIblockhash) == 0 )
    {
        printf("MATCHED APIblockhash\n");
        coin->APIblockstr = calloc(1,recvlen*2+1);
        init_hexbytes_noT(coin->APIblockstr,data,recvlen);
    }
    txdata = origtxdata;
    if ( addr != 0 )
    {
        if ( addr->pendblocks > 0 )
            addr->pendblocks--;
        addr->lastblockrecv = (uint32_t)time(NULL);
        addr->recvblocks += 1.;
        addr->recvtotal += recvlen;
        if ( iguana_ramchain_data(coin,addr,origtxdata,txarray,origtxdata->block.RO.txn_count,data,recvlen) >= 0 )
        {
            txdata->block.fpipbits = (uint32_t)addr->ipbits;
            req->datalen = txdata->datalen;
            req->ipbits = txdata->block.fpipbits;
            if ( 0 )
            {
                struct iguana_txblock *checktxdata; struct OS_memspace checkmem; int32_t checkbundlei;
                memset(&checkmem,0,sizeof(checkmem));
                iguana_meminit(&checkmem,"checkmem",0,txdata->datalen + 4096,0);
                if ( (checktxdata= iguana_peertxdata(coin,&checkbundlei,fname,&checkmem,(uint32_t)addr->ipbits,txdata->block.RO.hash2)) != 0 )
                {
                    printf("check datalen.%d bundlei.%d T.%d U.%d S.%d P.%d X.%d\n",checktxdata->datalen,checkbundlei,checktxdata->numtxids,checktxdata->numunspents,checktxdata->numspends,checktxdata->numpkinds,checktxdata->numexternaltxids);
                }
                iguana_mempurge(&checkmem);
            }
        }
    }
    //printf("recvlen.%d\n",req->recvlen);
    req->block = txdata->block;
    req->block.RO.txn_count = req->numtx = txdata->block.RO.txn_count;
    coin->recvcount++;
    coin->recvtime = (uint32_t)time(NULL);
    req->addr = addr;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gottxidsM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *txids,int32_t n)
{
    struct iguana_bundlereq *req;
    //printf("got %d txids from %s\n",n,addr->ipaddr);
    req = iguana_bundlereq(coin,addr,'T',0);
    req->hashes = txids, req->n = n;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotheadersM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n)
{
    struct iguana_bundlereq *req;
    if ( addr != 0 )
    {
        addr->recvhdrs++;
        if ( addr->pendhdrs > 0 )
            addr->pendhdrs--;
        //printf("%s blocks[%d] ht.%d gotheaders pend.%d %.0f\n",addr->ipaddr,n,blocks[0].height,addr->pendhdrs,milliseconds());
    }
    req = iguana_bundlereq(coin,addr,'H',0);
    req->blocks = blocks, req->n = n;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotblockhashesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *blockhashes,int32_t n)
{
    struct iguana_bundlereq *req;
    if ( addr != 0 )
    {
        addr->recvhdrs++;
        if ( addr->pendhdrs > 0 )
            addr->pendhdrs--;
    }
    req = iguana_bundlereq(coin,addr,'S',0);
    req->hashes = blockhashes, req->n = n;
    //printf("bundlesQ blockhashes.%p[%d]\n",blockhashes,n);
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_patch(struct iguana_info *coin,struct iguana_block *block)
{
    int32_t i,j,origheight,height; struct iguana_block *prev,*next; struct iguana_bundle *bp;
    prev = iguana_blockhashset(coin,-1,block->RO.prev_block,1);
    block->hh.prev = prev;
    if ( prev != 0 )
    {
        if ( prev->mainchain != 0 )
        {
            prev->hh.next = block;
            if ( memcmp(block->RO.prev_block.bytes,coin->blocks.hwmchain.RO.hash2.bytes,sizeof(bits256)) == 0 )
                _iguana_chainlink(coin,block);
            if ( (next= block->hh.next) != 0 && bits256_nonz(next->RO.hash2) > 0 )
                next->height = block->height + 1;
        }
        else if ( 0 && block->height < 0 )
        {
            for (i=0; i<1; i++)
            {
                if ( (prev= prev->hh.prev) == 0 )
                    break;
                if ( prev->mainchain != 0 && prev->height >= 0 )
                {
                    j = i;
                    origheight = (prev->height + i + 2);
                    prev = block->hh.prev;
                    height = (origheight - 1);
                    while ( i > 0 && prev != 0 )
                    {
                        if ( prev->mainchain != 0 && prev->height != height )
                        {
                            printf("mainchain height mismatch j.%d at i.%d %d != %d\n",j,i,prev->height,height);
                            break;
                        }
                        prev = prev->hh.prev;
                        height--;
                    }
                    if ( i == 0 )
                    {
                        //printf("SET HEIGHT.%d j.%d\n",origheight,j);
                        if ( (bp= coin->bundles[origheight / coin->chain->bundlesize]) != 0 )
                        {
                            iguana_bundlehash2add(coin,0,bp,origheight % coin->chain->bundlesize,block->RO.hash2);
                            block->height = origheight;
                            block->mainchain = 1;
                            prev = block->hh.prev;
                            prev->hh.next = block;
                        }
                    } //else printf("break at i.%d for j.%d origheight.%d\n",i,j,origheight);
                    break;
                }
            }
        }
    }
}

uint32_t iguana_allhashcmp(struct iguana_info *coin,struct iguana_bundle *bp,bits256 *blockhashes,int32_t num)
{
    bits256 allhash; int32_t err,i,n; struct iguana_block *block,*prev;
    if ( bits256_nonz(bp->allhash) > 0 && num >= coin->chain->bundlesize )
    {
        vcalc_sha256(0,allhash.bytes,blockhashes[0].bytes,coin->chain->bundlesize * sizeof(*blockhashes));
        if ( memcmp(allhash.bytes,bp->allhash.bytes,sizeof(allhash)) == 0 && bp->queued == 0 )
        {
            if ( bp->bundleheight > 0 )
                prev = iguana_blockfind(coin,iguana_blockhash(coin,bp->bundleheight-1));
            else prev = 0;
            for (i=n=0; i<coin->chain->bundlesize&&i<bp->n; i++)
            {
                if ( (err= iguana_bundlehash2add(coin,&block,bp,i,blockhashes[i])) < 0 )
                    return(err);
                if ( block != 0 && block == bp->blocks[i] )
                {
                    block->height = bp->bundleheight + i;
                    block->mainchain = 1;
                    if ( prev != 0 )
                    {
                        //block->RO.prev_block = prev->RO.hash2;
                        prev->hh.next = block;
                        block->hh.prev = prev;
                    }
                }
                prev = block;
            }
            //printf("ALLHASHES FOUND! %d requested.%d\n",bp->bundleheight,n);
            iguana_bundleQ(coin,bp,bp->n*5 + (rand() % 500));
            return(bp->queued);
        }
    }
    return(0);
}

void iguana_bundlespeculate(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t offset)
{
    if ( bp == 0 )
        return;
    if ( bp->numhashes < bp->n && bundlei == 0 && bp->speculative == 0 && bp->bundleheight < coin->longestchain-coin->chain->bundlesize )
    {
        char str[65]; bits256_str(str,bp->hashes[0]);
        fprintf(stderr,"Afound block -> %d %d hdr.%s\n",bp->bundleheight,coin->longestchain-coin->chain->bundlesize,str);
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(str),1);
    }
    else if ( bp->speculative != 0 && bundlei < bp->numspec && memcmp(hash2.bytes,bp->speculative[bundlei].bytes,sizeof(hash2)) == 0 )
    {
        bundlei += offset;
        if ( bundlei < bp->n && bundlei < bp->numspec )
        {
            //char str[65]; printf("speculative req[%d] %s\n",bundlei,bits256_str(str,bp->speculative[bundlei]));
            //iguana_blockQ(coin,0,-1,bp->speculative[bundlei],0);
        }
    } //else printf("speculative.%p %d vs %d cmp.%d\n",bp->speculative,bundlei,bp->numspec,bp->speculative!=0?memcmp(hash2.bytes,bp->speculative[bundlei].bytes,sizeof(hash2)):-1);
}

int32_t iguana_bundleiters(struct iguana_info *coin,struct iguana_bundle *bp,int32_t timelimit)
{
    int32_t i,n,better,issued,valid,pend,max,counter = 0; uint32_t now; struct iguana_block *block; double endmillis,width;
    coin->numbundlesQ--;
    if ( bp->numhashes < bp->n && bp->bundleheight < coin->longestchain-coin->chain->bundlesize )
    {
        //printf("ITERATE bundle.%d vs %d: h.%d n.%d r.%d s.%d finished.%d speculative.%p\n",bp->bundleheight,coin->longestchain-coin->chain->bundlesize,bp->numhashes,bp->n,bp->numrecv,bp->numsaved,bp->emitfinish,bp->speculative);
        if ( bp->speculative == 0 )
        {
            char str[64];
            queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(bits256_str(str,bp->hashes[0])),1);
        }
        else
        {
            for (i=1; i<bp->n; i++)
                if ( bits256_nonz(bp->hashes[i]) == 0 && bits256_nonz(bp->speculative[i]) > 0 )
                {
                    iguana_blockQ(coin,0,-1,bp->speculative[i],0);
                    break;
                }
        }
        usleep(10000);
        iguana_bundleQ(coin,bp,bp->n*5);
        return(0);
    }
    if ( bp->rank == 0 || bp->rank > coin->peers.numranked )
    {
        iguana_bundleQ(coin,bp,((bp->rank != 0) ? bp->rank : 64) * 1000);
        return(0);
    }
    pend = queue_size(&coin->priorityQ) + queue_size(&coin->blocksQ);
    for (i=0; i<IGUANA_MAXPEERS; i++)
        pend += coin->peers.active[i].pendblocks;
    if ( pend >= coin->MAXPENDING*coin->peers.numranked )
    {
        for (i=better=0; i<coin->bundlescount; i++)
            if ( coin->bundles[i] != 0 && coin->bundles[i]->numsaved > bp->numsaved )
                better++;
        if ( better > 2*coin->peers.numranked )
        {
            usleep(1000);
            //printf("SKIP pend.%d vs %d: better.%d ITERATE bundle.%d n.%d r.%d s.%d finished.%d timelimit.%d\n",pend,coin->MAXPENDING*coin->peers.numranked,better,bp->bundleheight,bp->n,bp->numrecv,bp->numsaved,bp->emitfinish,timelimit);
            iguana_bundleQ(coin,bp,counter == 0 ? bp->n*5 : bp->n*2);
            return(0);
        }
    }
    max = 1 + ((coin->MAXPENDING*coin->MAXPEERS - pend) >> 1);
    endmillis = OS_milliseconds() + timelimit*10;
    while ( bp->emitfinish == 0 && OS_milliseconds() < endmillis )
    {
        now = (uint32_t)time(NULL);
        for (i=n=issued=counter=0; i<bp->n; i++)
        {
            if ( OS_milliseconds() > endmillis )
                break;
            if ( (block= bp->blocks[i]) != 0 )
            {
                if ( block->fpipbits == 0 && (block->queued == 0 || bp->issued[i] == 0 || now > bp->issued[i]+7) )
                {
                    //if ( bp->bundleheight == 20000 )
                    //   printf("(%d:%d) ",bp->hdrsi,i);
                    block->numrequests++;
                    iguana_blockQ(coin,bp,i,block->RO.hash2,bp->numsaved > bp->n*.9);
                    bp->issued[i] = now;
                    counter++;
                    if ( --max <= 0 )
                        break;
                }
                else if ( block->fpipbits != 0 && bits256_nonz(block->RO.prev_block) != 0 )
                    n++, issued++;
                else if ( bp->issued[i] != 0 )
                    issued++;
            } //else printf("iguana_bundleiters[%d] unexpected null block[%d]\n",bp->bundleheight,i);
            bp->numsaved = n;
        }
        if ( max <= 0 )
            break;
        usleep(1000);
    }
    width = 1000 + sqrt(sqrt(bp->n * (1+bp->numsaved+issued)) * (10+coin->bundlescount-bp->hdrsi));
    if ( 0 && counter > 0 && bp->rank <= coin->peers.numranked )
        printf("ITERATE.%d bundle.%d h.%d n.%d r.%d s.%d F.%d I.%d T.%d %f %u next %f\n",bp->rank,bp->bundleheight/coin->chain->bundlesize,bp->numhashes,bp->n,bp->numrecv,bp->numsaved,bp->emitfinish,issued,timelimit,endmillis-OS_milliseconds(),(uint32_t)time(NULL),width);
    if ( bp->emitfinish == 0 )
    {
        if ( bp->numsaved >= bp->n )
        {
            for (i=0; i<bp->n; i++)
            {
                if ( (block= bp->blocks[i]) != 0 )
                {
                    //printf("(%x:%x) ",(uint32_t)block->RO.hash2.ulongs[3],(uint32_t)bp->hashes[i].ulongs[3]);
                    if ( iguana_blockvalidate(coin,&valid,block,1) != 0 || (bp->bundleheight+i > 0 && bits256_nonz(block->RO.prev_block) == 0) )
                    {
                        char str[65]; printf(">>>>>>> null prevblock error at ht.%d patch.(%s) and reissue\n",bp->bundleheight+i,bits256_str(str,block->RO.prev_block));
                        block->queued = 0;
                        block->fpipbits = 0;
                        bp->issued[i] = 0;
                        iguana_blockQ(coin,bp,i,block->RO.hash2,0);
                        iguana_bundleQ(coin,bp,counter == 0 ? bp->n*5 : bp->n*2);
                        return(0);
                    }
                } else printf("error getting block (%d:%d) %p vs %p\n",bp->hdrsi,i,block,iguana_blockfind(coin,bp->hashes[i]));
            }
            // merkle
            printf(">>>>>>>>>>>>>>>>>>>>>>> EMIT bundle.%d\n",bp->bundleheight);
            bp->emitfinish = 1;
            sleep(1);
            iguana_emitQ(coin,bp);
            return(1);
        }
        iguana_bundleQ(coin,bp,width);
    }
    return(0);
}

// main context, ie single threaded
struct iguana_bundle *iguana_bundleset(struct iguana_info *coin,struct iguana_block **blockp,int32_t *bundleip,struct iguana_block *origblock)
{
    struct iguana_block *block,*prevblock; bits256 zero,hash2,prevhash2; struct iguana_bundle *prevbp,*bp = 0; int32_t prevbundlei,bundlei = -2;
    *bundleip = -2; *blockp = 0;
    if ( origblock == 0 )
        return(0);
    memset(zero.bytes,0,sizeof(zero));
    hash2 = origblock->RO.hash2;
    if ( (block= iguana_blockhashset(coin,-1,hash2,1)) != 0 )
    {
        fprintf(stderr,"bundleset block.%p vs origblock.%p\n",block,origblock);
        if ( block != origblock )
            iguana_blockcopy(coin,block,origblock);
        *blockp = block;
        prevhash2 = origblock->RO.prev_block;
        fprintf(stderr,"set prevhash2\n");
        if ( 0 && bits256_nonz(prevhash2) > 0 )
            iguana_patch(coin,block);
        fprintf(stderr,"iguana_bundlefind \n");
        if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,hash2)) != 0 && bundlei < coin->chain->bundlesize )
        {
            fprintf(stderr,"bundle found %d:%d\n",bp->hdrsi,bundlei);
            block->bundlei = bundlei;
            block->hdrsi = bp->hdrsi;
            bp->blocks[bundlei] = block;
            iguana_bundlehash2add(coin,0,bp,bundlei,hash2);
            if ( bundlei > 0 )
                iguana_bundlehash2add(coin,0,bp,bundlei-1,prevhash2);
            else if ( bp->hdrsi > 0 && (bp= coin->bundles[bp->hdrsi-1]) != 0 )
                iguana_bundlehash2add(coin,0,bp,coin->chain->bundlesize-1,prevhash2);
            iguana_bundlespeculate(coin,bp,bundlei,hash2,1);
        }
        prevbp = 0, prevbundlei = -2;
        iguana_bundlefind(coin,&prevbp,&prevbundlei,prevhash2);
        if ( block->blockhashes != 0 )
            fprintf(stderr,"has blockhashes bp.%p[%d] prevbp.%p[%d]\n",bp,bundlei,prevbp,prevbundlei);
        if ( prevbp != 0 && prevbundlei >= 0 && (prevblock= iguana_blockfind(coin,prevhash2)) != 0 )
        {
            fprintf(stderr,"prev case\n");
            if ( prevbundlei < coin->chain->bundlesize )
            {
                if ( prevbp->hdrsi+1 == coin->bundlescount && prevbundlei == coin->chain->bundlesize-1 )
                    iguana_bundlecreate(coin,&prevbundlei,prevbp->bundleheight + coin->chain->bundlesize,hash2,zero,0);
                if ( prevbundlei < coin->chain->bundlesize-1 )
                    iguana_bundlehash2add(coin,0,prevbp,prevbundlei+1,hash2);
                iguana_bundlespeculate(coin,prevbp,prevbundlei,prevhash2,2);
            }
        }
    } else printf("iguana_bundleset: error adding blockhash\n");
    bp = 0, *bundleip = -2;
    return(iguana_bundlefind(coin,&bp,bundleip,hash2));
}

struct iguana_bundlereq *iguana_recvblockhdrs(struct iguana_info *coin,struct iguana_bundlereq *req,struct iguana_block *blocks,int32_t n,int32_t *newhwmp)
{
    int32_t i,bundlei,match; struct iguana_block *block; struct iguana_bundle *bp,*firstbp = 0;
    if ( blocks == 0 )
    {
        printf("iguana_recvblockhdrs null blocks?\n");
        return(req);
    }
    if ( blocks != 0 && n > 0 )
    {
        for (i=match=0; i<n; i++)
        {
            fprintf(stderr,"i.%d of %d bundleset\n",i,n);
            bp = 0, bundlei = -1;
            if ( (bp= iguana_bundleset(coin,&block,&bundlei,&blocks[i])) != 0 )
            {
                if ( i == 0 )
                    firstbp = bp;
                if ( bundlei == i+1 && bp == firstbp )
                    match++;
                else fprintf(stderr,"recvhdr: ht.%d[%d] vs i.%d\n",bp->bundleheight,bundlei,i);
            }
        }
        if ( firstbp != 0 && match == coin->chain->bundlesize-1 && n == firstbp->n )
        {
            if ( firstbp->queued == 0 )
            {
                fprintf(stderr,"firstbp blockQ %d\n",firstbp->bundleheight);
                iguana_bundleQ(coin,firstbp,1000 + 10*(rand() % (int32_t)(1+sqrt(firstbp->bundleheight))));
            }
        } else fprintf(stderr,"match.%d vs n.%d bp->n.%d ht.%d\n",match,n,firstbp->n,firstbp->bundleheight);
    }
    return(req);
}

struct iguana_bundlereq *iguana_recvblockhashes(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *blockhashes,int32_t num)
{
    int32_t bundlei,i; struct iguana_bundle *bp;// struct iguana_block *block;
    bp = 0, bundlei = -2;
    iguana_bundlefind(coin,&bp,&bundlei,blockhashes[1]);
   // char str[65]; printf("blockhashes[%d] %d of %d %s bp.%d[%d]\n",num,bp==0?-1:bp->hdrsi,coin->bundlescount,bits256_str(str,blockhashes[1]),bp==0?-1:bp->bundleheight,bundlei);
    if ( bp != 0 )
    {
        bp->hdrtime = (uint32_t)time(NULL);
        blockhashes[0] = bp->hashes[0];
        if ( num >= coin->chain->bundlesize )
        {
            iguana_blockQ(coin,0,-1,blockhashes[coin->chain->bundlesize],1);
            //printf("call allhashes\n");
            if ( iguana_allhashcmp(coin,bp,blockhashes,num) > 0 )
                return(req);
            //printf("done allhashes\n");
        }
        if ( (bp->speculative == 0 || num > bp->numspec) && bp->emitfinish == 0 )
        {
            printf("FOUND speculative BLOCKHASHES[%d] ht.%d\n",num,bp->bundleheight);
            if ( bp->speculative != 0 )
                myfree(bp->speculative,sizeof(*bp->speculative) * bp->numspec);
            bp->speculative = blockhashes;
            bp->numspec = num;
            req->hashes = 0;
            iguana_blockQ(coin,0,-1,blockhashes[2],1);
        }
    }
    else if ( num >= coin->chain->bundlesize )
    {
        for (i=0; i<coin->bundlescount; i++)
        {
            if ( (bp= coin->bundles[i]) != 0 && bp->emitfinish == 0 && bits256_nonz(bp->hashes[0]) > 0 )
            {
                blockhashes[0] = bp->hashes[0];
                if ( iguana_allhashcmp(coin,bp,blockhashes,coin->chain->bundlesize) > 0 )
                {
                    bp->hdrtime = (uint32_t)time(NULL);
                    iguana_blockQ(coin,bp,1,blockhashes[1],0);
                    iguana_blockQ(coin,bp,0,blockhashes[0],0);
                    iguana_blockQ(coin,bp,coin->chain->bundlesize-1,blockhashes[coin->chain->bundlesize-1],0);
                    //printf("matched bundle.%d\n",bp->bundleheight);
                    return(req);
                }
            }
        }
        //printf("issue block1\n");
        struct iguana_block *block;
        if ( num == coin->chain->bundlesize+1 && (block= iguana_blockhashset(coin,-1,blockhashes[1],1)) != 0 )
            block->blockhashes = blockhashes, req->hashes = 0;
        iguana_blockQ(coin,0,-1,blockhashes[1],1);
    }
    else iguana_blockQ(coin,0,-1,blockhashes[1],0); // should be RT block
    return(req);
}

struct iguana_bundlereq *iguana_recvblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundlereq *req,struct iguana_block *origblock,int32_t numtx,int32_t datalen,int32_t recvlen,int32_t *newhwmp)
{
    struct iguana_bundle *bp=0; int32_t bundlei = -2; struct iguana_block *block;
    bp = iguana_bundleset(coin,&block,&bundlei,origblock);
    //static int total; char str[65]; fprintf(stderr,"RECV %s [%d:%d] block.%08x | %d\n",bits256_str(str,origblock->RO.hash2),bp!=0?bp->hdrsi:-1,bundlei,block->fpipbits,total++);
    if ( block != 0 )
    {
        if ( bp != 0 && bundlei > 0 && bits256_nonz(block->RO.prev_block) > 0 )
            iguana_blockQ(coin,bp,bundlei-1,block->RO.prev_block,0);
        block->RO.recvlen = recvlen;
        if ( req->copyflag != 0 && block->queued == 0 && bp != 0 )
        {
            //char str[65]; fprintf(stderr,"req.%p %s copyflag.%d %d data %d %d\n",req,bits256_str(str,block->RO.hash2),req->copyflag,block->height,req->recvlen,recvlen);
            coin->numcached++;
            block->queued = 1;
            //iguana_parsebuf(coin,addr,&req->H,req->serialized,req->recvlen);
            queue_enqueue("cacheQ",&coin->cacheQ,&req->DL,0);
            return(0);
        }
        /*while ( block != 0 && memcmp(block->RO.prev_block.bytes,coin->blocks.hwmchain.RO.hash2.bytes,sizeof(bits256)) == 0 )
        {
            if ( _iguana_chainlink(coin,block) != 0 )
            {
                printf("chainlink.%d -> next.%p\n",block->height,block->hh.next);
                block = block->hh.next;
            } else break;
        }*/
        //printf("datalen.%d ipbits.%x\n",datalen,req->ipbits);
    } else printf("cant create origblock.%p block.%p bp.%p bundlei.%d\n",origblock,block,bp,bundlei);
    return(req);
}

struct iguana_bundlereq *iguana_recvtxids(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *txids,int32_t n)
{
    return(req);
}

struct iguana_bundlereq *iguana_recvunconfirmed(struct iguana_info *coin,struct iguana_bundlereq *req,uint8_t *data,int32_t datalen)
{
    int32_t i;
    for (i=0; i<coin->numreqtxids; i++)
    {
        if ( memcmp(req->txid.bytes,coin->reqtxids[i].bytes,sizeof(req->txid)) == 0 )
        {
            char str[65]; printf("got reqtxid.%s datalen.%d | numreqs.%d\n",bits256_str(str,req->txid),req->datalen,coin->numreqtxids);
            coin->reqtxids[i] = coin->reqtxids[--coin->numreqtxids];
        }
    }
    return(req);
}

int32_t iguana_processbundlesQ(struct iguana_info *coin,int32_t *newhwmp) // single threaded
{
    int32_t flag = 0; struct iguana_bundlereq *req;
    *newhwmp = 0;
    while ( flag < IGUANA_BUNDLELOOP && (req= queue_dequeue(&coin->bundlesQ,0)) != 0 )
    {
        flag++;
        //fprintf(stderr,"%s bundlesQ.%p type.%c n.%d\n",req->addr != 0 ? req->addr->ipaddr : "0",req,req->type,req->n);
        //if ( req->type == 'H' )
        //    continue;
        if ( req->type == 'B' ) // one block with all txdata
            req = iguana_recvblock(coin,req->addr,req,&req->block,req->numtx,req->datalen,req->recvlen,newhwmp);
        else if ( req->type == 'H' ) // blockhdrs (doesnt have txn_count!)
        {
            if ( (req= iguana_recvblockhdrs(coin,req,req->blocks,req->n,newhwmp)) != 0 )
            {
                if ( req->blocks != 0 )
                    myfree(req->blocks,sizeof(*req->blocks) * req->n), req->blocks = 0;
            }
        }
        else if ( req->type == 'S' ) // blockhashes
        {
            if ( (req= iguana_recvblockhashes(coin,req,req->hashes,req->n)) != 0 && req->hashes != 0 )
                myfree(req->hashes,sizeof(*req->hashes) * req->n), req->hashes = 0;
        }
        else if ( req->type == 'U' ) // unconfirmed tx
            req = iguana_recvunconfirmed(coin,req,req->serialized,req->datalen);
        else if ( req->type == 'T' ) // txids from inv
        {
            if ( (req= iguana_recvtxids(coin,req,req->hashes,req->n)) != 0 )
                myfree(req->hashes,(req->n+1) * sizeof(*req->hashes)), req->hashes = 0;
        }
        else printf("iguana_updatebundles unknown type.%c\n",req->type);
        //fprintf(stderr,"finished bundlesQ\n");
        if ( req != 0 )
            myfree(req,req->allocsize), req = 0;
    }
    return(flag);
}

int32_t iguana_needhdrs(struct iguana_info *coin)
{
    if ( coin->longestchain == 0 || coin->blocks.hashblocks < coin->longestchain-coin->chain->bundlesize )
        return(1);
    else return(0);
}

int32_t iguana_reqhdrs(struct iguana_info *coin)
{
    int32_t i,lag,n = 0; struct iguana_bundle *bp; char hashstr[65];
    if ( iguana_needhdrs(coin) > 0 && queue_size(&coin->hdrsQ) == 0 )
    {
        ///if ( coin->zcount++ > 1 )
        {
            for (i=0; i<coin->bundlescount; i++)
            {
                if ( (bp= coin->bundles[i]) != 0 && bp->emitfinish < coin->startutc )
                {
                    if ( i == coin->bundlescount-1 )
                        lag = 30;
                    else lag = 30 + (rand() % 30);
                    //if ( i < coin->bundlescount-1 && (bp->numhashes >= (rand() % bp->n) || time(NULL) < bp->hdrtime+lag) )
                    //    continue;
                    if ( bp->numhashes < bp->n && bp->bundleheight+bp->numhashes < coin->longestchain && time(NULL) > bp->issuetime+lag )
                    {
                        printf("LAG.%ld hdrsi.%d numhashes.%d:%d needhdrs.%d qsize.%d zcount.%d\n",time(NULL)-bp->hdrtime,i,bp->numhashes,bp->n,iguana_needhdrs(coin),queue_size(&coin->hdrsQ),coin->zcount);
                        if ( bp->issuetime == 0 )
                            coin->numpendings++;
                        char str[65];
                        bits256_str(str,bp->hashes[0]);
                        //printf("(%s %d).%d ",str,bp->bundleheight,i);
                        //printf("%d ",bp->bundleheight);
                        init_hexbytes_noT(hashstr,bp->hashes[0].bytes,sizeof(bits256));
                        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
                        iguana_blockQ(coin,bp,0,bp->hashes[0],0);
                        n++;
                        bp->hdrtime = bp->issuetime = (uint32_t)time(NULL);
                    }
                }
            }
            if ( n > 0 )
                printf("REQ HDRS pending.%d\n",n);
            coin->zcount = 0;
        }
    } else coin->zcount = 0;
    return(n);
}

struct iguana_blockreq { struct queueitem DL; bits256 hash2,*blockhashes; struct iguana_bundle *bp; int32_t n,height,bundlei; };

int32_t iguana_blockQ(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t priority)
{
    queue_t *Q; char *str; int32_t height = -1; struct iguana_blockreq *req; struct iguana_block *block = 0;
    if ( bits256_nonz(hash2) == 0 )
    {
        printf("cant queue zerohash bundlei.%d\n",bundlei);
        return(-1);
    }
    block = iguana_blockfind(coin,hash2);
    if ( priority != 0 || block == 0 || (block->queued == 0 && block->fpipbits == 0) )
    {
        if ( block != 0 && bits256_cmp(coin->APIblockhash,hash2) != 0 )
        {
            if ( block->fpipbits != 0 || block->queued != 0 || block->issued > time(NULL)-10 )
                return(0);
        }
        if ( priority != 0 )
            str = "priorityQ", Q = &coin->priorityQ;
        else str = "blocksQ", Q = &coin->blocksQ;
        if ( Q != 0 )
        {
            if ( bp != 0 && bundlei >= 0 && bundlei < bp->n )
            {
                if ( bp->issued[bundlei] == 0 || time(NULL) > bp->issued[bundlei]+3 )
                {
                    bp->issued[bundlei] = (uint32_t)time(NULL);
                    if ( bp->bundleheight >= 0 )
                        height = (bp->bundleheight + bundlei);
                }
                else
                {
                    return(1);
                }
            }
            req = mycalloc('y',1,sizeof(*req));
            req->hash2 = hash2;
            req->bp = bp;
            req->height = height;
            req->bundlei = bundlei;
            char str2[65];
            if ( 0 && (bundlei % 250) == 0 )
                printf("%s %d %s %d numranked.%d qsize.%d\n",str,req->height,bits256_str(str2,hash2),coin->blocks.recvblocks,coin->peers.numranked,queue_size(Q));
            if ( block != 0 )
            {
                block->numrequests++;
                block->issued = (uint32_t)time(NULL);
            }
            queue_enqueue(str,Q,&req->DL,0);
            return(1);
        } else printf("null Q\n");
    } //else printf("queueblock skip priority.%d bundlei.%d\n",bundlei,priority);
    return(0);
}

int32_t iguana_pollQsPT(struct iguana_info *coin,struct iguana_peer *addr)
{
    uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(uint32_t)*32 + sizeof(bits256)];
    char *hashstr=0; bits256 hash2; uint32_t now; struct iguana_block *block; struct iguana_blockreq *req=0;
    struct iguana_bundle *bp; struct iguana_peer *ptr; int32_t hdrsi,bundlei,gap,priority,i,m,z,pend,limit,height=-1,datalen,flag = 0;
    if ( addr->msgcounts.verack == 0 )
        return(0);
    now = (uint32_t)time(NULL);
    if ( iguana_needhdrs(coin) != 0 && addr->pendhdrs < IGUANA_MAXPENDHDRS )
    {
        //printf("%s check hdrsQ\n",addr->ipaddr);
        if ( (hashstr= queue_dequeue(&coin->hdrsQ,1)) != 0 )
        {
            if ( (datalen= iguana_gethdrs(coin,serialized,coin->chain->gethdrsmsg,hashstr)) > 0 )
            {
                decode_hex(hash2.bytes,sizeof(hash2),hashstr);
                if ( bits256_nonz(hash2) > 0 )
                {
                    bp = 0, bundlei = -2;
                    bp = iguana_bundlefind(coin,&bp,&bundlei,hash2);
                    z = m = 0;
                    if ( bp != 0 && bp->queued == 0 )
                    {
                        if ( bp->bundleheight+coin->chain->bundlesize < coin->longestchain )
                        {
                            m = (coin->longestchain - bp->bundleheight);
                            if ( bp->numhashes < m )
                                z = 1;
                        }
                        else if ( bp->numhashes < 3 )
                            z = 1;
                    }
                    //if ( bp == 0 || z != 0 )
                    {
                        //printf("%s request HDR.(%s) numhashes.%d\n",addr!=0?addr->ipaddr:"local",hashstr,bp->numhashes);
                        iguana_send(coin,addr,serialized,datalen);
                        addr->pendhdrs++;
                        flag++;
                    } //else printf("skip hdrreq.%s m.%d z.%d\n",hashstr,m,z);
                }
                free_queueitem(hashstr);
                return(flag);
            } else printf("datalen.%d from gethdrs\n",datalen);
            free_queueitem(hashstr);
            hashstr = 0;
        }
    }
    if ( (limit= addr->recvblocks) > coin->MAXPENDING )
        limit = coin->MAXPENDING;
    if ( limit < 1 )
        limit = 1;
    //if ( addr->pendblocks >= limit )
    //    printf("%s %d overlimit.%d\n",addr->ipaddr,addr->pendblocks,limit);
    req = queue_dequeue(&coin->priorityQ,0);
    if ( addr->rank != 1 && req == 0 && addr->pendblocks < limit )
    {
        priority = 0;
        for (i=m=pend=0; i<coin->peers.numranked; i++)
        {
            if ( (ptr= coin->peers.ranked[i]) != 0 && ptr->msgcounts.verack > 0 )
                pend += ptr->pendblocks, m++;
        }
        if ( pend < coin->MAXPENDING*m )
            req = queue_dequeue(&coin->blocksQ,0);
    } else priority = 1;
    if ( req != 0 )
    {
        hash2 = req->hash2;
        height = req->height;
        block = 0;
        if ( priority == 0 && (bp= req->bp) != 0 && req->bundlei >= 0 && req->bundlei < bp->n && req->bundlei < coin->chain->bundlesize && (block= bp->blocks[req->bundlei]) != 0 && (block->fpipbits != 0 || block->queued != 0) )
        {
            if ( 1 && priority != 0 )
                printf("SKIP %p[%d] %d\n",bp,bp!=0?bp->bundleheight:-1,req->bundlei);
        }
        else
        {
            //char str[65];
            //if ( 0 && priority != 0 )
            //    printf(" issue.%s\n",bits256_str(str,hash2));
            if ( block != 0 )
                block->numrequests++;
            iguana_sendblockreqPT(coin,addr,req->bp,req->bundlei,hash2,0);
        }
        flag++;
        myfree(req,sizeof(*req));
    }
    else if ( 0 && addr->rank > 1 )
    {
        gap = addr->rank * coin->peers.numranked;
        for (i=0; i<coin->peers.numranked; i++,gap++)
        {
            hdrsi = (coin->blocks.hwmchain.height + gap) / coin->chain->bundlesize;
            if ( (bp= coin->bundles[hdrsi]) != 0 )
            {
                bundlei = (coin->blocks.hwmchain.height + gap) % coin->chain->bundlesize;
                if ( (block= bp->blocks[bundlei]) != 0 && block->fpipbits == 0 && block->queued == 0 )
                {
                    //printf("near hwm gap.%d peer.%s ranked.%d [%d:%d] pending.%d\n",gap,addr->ipaddr,bp->rank,bp->hdrsi,i,addr->pendblocks);
                    block->numrequests++;
                    iguana_sendblockreqPT(coin,addr,bp,bundlei,block->RO.hash2,1);
                    break;
                }
            }
        }
    }
    if ( 0 && (bp= addr->bp) != 0 && bp->rank != 0 && addr->pendblocks < limit )
    {
        for (i=0; i<bp->n; i++)
            if ( (block= bp->blocks[i]) != 0 && block->numrequests == bp->minrequests && block->fpipbits == 0 && block->queued == 0 )
            {
                //printf("peer.%s ranked.%d [%d:%d] pending.%d\n",addr->ipaddr,bp->rank,bp->hdrsi,i,addr->pendblocks);
                block->numrequests++;
                iguana_sendblockreqPT(coin,addr,bp,i,block->RO.hash2,1);
                break;
            }
    }
    return(flag);
}

int32_t iguana_reqblocks(struct iguana_info *coin)
{
    int32_t hdrsi,lflag,bundlei,flag = 0; bits256 hash2; struct iguana_block *next,*block; struct iguana_bundle *bp;
    return(0);
    hdrsi = (coin->blocks.hwmchain.height+1) / coin->chain->bundlesize;
    if ( (bp= coin->bundles[hdrsi]) != 0 )
    {
        bundlei = (coin->blocks.hwmchain.height+1) % coin->chain->bundlesize;
        if ( (next= bp->blocks[bundlei]) != 0 || (next= iguana_blockfind(coin,bp->hashes[bundlei])) != 0 )
        {
            if ( bits256_nonz(next->RO.prev_block) > 0 )
                _iguana_chainlink(coin,next);
            else if ( next->queued == 0 && next->fpipbits == 0 )
            {
                //printf("HWM next %d\n",coin->blocks.hwmchain.height+1);
                iguana_blockQ(coin,bp,bundlei,next->RO.hash2,1);
            }
        }
        else
        {
            if ( bits256_nonz(bp->hashes[bundlei]) > 0 )
            {
                //printf("next %d\n",coin->blocks.hwmchain.height+1);
                iguana_blockQ(coin,bp,bundlei,bp->hashes[bundlei],0);
            }
            else if ( bp->speculative != 0 && bits256_nonz(bp->speculative[bundlei]) > 0 )
            {
                //printf("speculative next %d\n",coin->blocks.hwmchain.height+1);
                iguana_blockQ(coin,0,-1,bp->speculative[bundlei],0);
            }
        }
    }
    else if ( (bp= coin->bundles[--hdrsi]) != 0 )
    {
        char str[65];
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(bits256_str(str,bp->hashes[0])),1);
    }
    lflag = 1;
    while ( lflag != 0 )
    {
        lflag = 0;
        hdrsi = (coin->blocks.hwmchain.height+1) / coin->chain->bundlesize;
        bundlei = (coin->blocks.hwmchain.height+1) % coin->chain->bundlesize;
        if ( (next= iguana_blockfind(coin,iguana_blockhash(coin,coin->blocks.hwmchain.height+1))) == 0 )
        {
            if ( (block= iguana_blockfind(coin,coin->blocks.hwmchain.RO.hash2)) != 0 )
                next = block->hh.next, block->mainchain = 1;
        }
        if ( next == 0 && hdrsi < coin->bundlescount && (bp= coin->bundles[hdrsi]) != 0 && (next= bp->blocks[bundlei]) != 0 )
        {
            if ( bits256_nonz(next->RO.prev_block) == 0 )
                next = 0;
        }
        if ( next != 0 )
        {
            //printf("have next %d\n",coin->blocks.hwmchain.height);
            if ( memcmp(next->RO.prev_block.bytes,coin->blocks.hwmchain.RO.hash2.bytes,sizeof(bits256)) == 0 )
            {
                if ( _iguana_chainlink(coin,next) != 0 )
                    lflag++, flag++;
                //else printf("chainlink error for %d\n",coin->blocks.hwmchain.height+1);
            }
            if ( queue_size(&coin->blocksQ) < _IGUANA_MAXPENDING )
            {
                double threshold,lag = OS_milliseconds() - coin->backstopmillis;
                threshold = (10 + coin->longestchain - coin->blocksrecv);
                if ( threshold < 1 )
                    threshold = 1.;
                if ( (bp= coin->bundles[(coin->blocks.hwmchain.height+1)/coin->chain->bundlesize]) != 0 )
                    threshold = (bp->avetime + coin->avetime) * .5;
                else threshold = coin->avetime;
                threshold *= 100. * sqrt(threshold) * .000777;
                if ( strcmp(coin->symbol,"BTC") != 0 )
                    threshold = 1000;
                else threshold = 10000;
                if ( coin->blocks.hwmchain.height < coin->longestchain && (coin->backstop != coin->blocks.hwmchain.height+1 || lag > threshold) )
                {
                    coin->backstop = coin->blocks.hwmchain.height+1;
                    hash2 = iguana_blockhash(coin,coin->backstop);
                    if ( bits256_nonz(hash2) > 0 )
                    {
                        bp = coin->bundles[(coin->blocks.hwmchain.height+1)/coin->chain->bundlesize];
                        bundlei = (coin->blocks.hwmchain.height+1) % coin->chain->bundlesize;
                        if ( bp != 0 )
                        {
                            coin->backstopmillis = OS_milliseconds();
                            iguana_blockQ(coin,bp,bundlei,hash2,0);
                            flag++;
                            char str[65];
                            if ( 0 && (rand() % 10) == 0 )
                                printf("%s MAINCHAIN.%d threshold %.3f %.3f lag %.3f\n",bits256_str(str,hash2),coin->blocks.hwmchain.height+1,threshold,coin->backstopmillis,lag);
                        }
                    }
                }
            }
        }
    }
    return(flag);
}

int32_t iguana_processrecv(struct iguana_info *coin) // single threaded
{
    int32_t newhwm = 0,flag = 0;
    //fprintf(stderr,"process bundlesQ\n");
    flag += iguana_processbundlesQ(coin,&newhwm);
    //fprintf(stderr,"iguana_reqhdrs\n");
    flag += iguana_reqhdrs(coin);
    //fprintf(stderr,"iguana_reqblocks\n");
    flag += iguana_reqblocks(coin);
    return(flag);
}
