/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
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

/*struct iguana_block *iguana_blockrequest(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,uint32_t now,int32_t iamthreadsafe)
{
    struct iguana_block *block = 0;
    if( bp != 0 && bundlei >= 0 && bundlei < bp->n )
        block = bp->blocks[bundlei];
    if ( block == 0 && iamthreadsafe != 0 )
        block = iguana_blockfind(coin,hash2);
    if ( block != 0 )
    {
        //block->issued = now;
            block->numrequests++;
    }
    return(block);
}*/

int32_t iguana_sendblockreq(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t iamthreadsafe)
{
    int32_t len; uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(uint32_t)*32 + sizeof(bits256)];
    char hexstr[65]; init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
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
        //iguana_blockrequest(coin,bp,bundlei,hash2,addr->pendtime,iamthreadsafe);
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
    copyflag = 1 * (strcmp(coin->symbol,"BTC") != 0);
    req = iguana_bundlereq(coin,addr,'B',copyflag * recvlen);
    req->recvlen = recvlen;
    req->H = *H;
    bp = 0, bundlei = -2;
    if ( copyflag != 0 && recvlen != 0 && ((bp= iguana_bundlefind(coin,&bp,&bundlei,origtxdata->block.RO.hash2)) == 0 || (bp->blocks[bundlei] != 0 && bp->blocks[bundlei]->fpipbits == 0)) )
    {
        //printf("copy %p serialized[%d]\n",req->serialized,req->recvlen);
        memcpy(req->serialized,data,recvlen), req->copyflag = 1;
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
            txdata->block.fpipbits = addr->ipbits;
            req->datalen = txdata->datalen;
            req->ipbits = txdata->block.fpipbits;
            if ( 0 )
            {
                struct iguana_txblock *checktxdata; struct OS_memspace checkmem; int32_t checkbundlei;
                memset(&checkmem,0,sizeof(checkmem));
                iguana_meminit(&checkmem,"checkmem",0,txdata->datalen + 4096,0);
                if ( (checktxdata= iguana_peertxdata(coin,&checkbundlei,fname,&checkmem,addr->ipbits,txdata->block.RO.hash2)) != 0 )
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
            {
                _iguana_chainlink(coin,block);
                //printf("link block %d\n",block->height);
            }
            if ( (next= block->hh.next) != 0 && bits256_nonz(next->RO.hash2) > 0 )
            {
                next->height = block->height + 1;
                //printf("autoreq %d\n",next->height);
                if ( 0 && strcmp(coin->symbol,"BTC") != 0 )
                    iguana_blockQ(coin,coin->bundles[(block->height+1)/coin->chain->bundlesize],(block->height+1)%coin->chain->bundlesize,next->RO.hash2,0);
            }
        }
        else if ( block->height < 0 )
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

int32_t iguana_allhashcmp(struct iguana_info *coin,struct iguana_bundle *bp,bits256 *blockhashes,int32_t num)
{
    bits256 allhash; int32_t err,i,n; struct iguana_block *block;
    if ( bits256_nonz(bp->allhash) > 0 && num >= coin->chain->bundlesize )
    {
        for (i=0; i<bp->n; i++)
            if ( bits256_nonz(blockhashes[i]) == 0 )
                blockhashes[i] = bp->hashes[i];
        vcalc_sha256(0,allhash.bytes,blockhashes[0].bytes,coin->chain->bundlesize * sizeof(*blockhashes));
        if ( memcmp(allhash.bytes,bp->allhash.bytes,sizeof(allhash)) == 0 )
        {
            for (i=n=0; i<coin->chain->bundlesize&&i<bp->n; i++)
            {
                if ( (err= iguana_bundlehash2add(coin,0,bp,i,blockhashes[i])) < 0 )
                    return(err);
                if ( 1 && bp->emitfinish == 0 && (block= bp->blocks[i]) != 0 && (block->queued == 0 && block->fpipbits == 0) && block->numrequests == 0 )
                    iguana_blockQ(coin,bp,i,block->RO.hash2,0), n++;
            }
            printf("ALLHASHES FOUND! %d requested.%d\n",bp->bundleheight,n);
            return(i);
        }
    }
    return(-1);
}

// main context, ie single threaded
struct iguana_bundle *iguana_bundleset(struct iguana_info *coin,struct iguana_block **blockp,int32_t *bundleip,struct iguana_block *origblock)
{
    struct iguana_block *block; bits256 zero; struct iguana_bundle *bp = 0;
    int32_t bundlei = -2;
    *bundleip = -2; *blockp = 0;
    if ( origblock == 0 )
        return(0);
    memset(zero.bytes,0,sizeof(zero));
    if ( (block= iguana_blockhashset(coin,-1,origblock->RO.hash2,1)) != 0 )
    {
        if ( block != origblock )
            iguana_blockcopy(coin,block,origblock);
        *blockp = block;
        if ( bits256_nonz(block->RO.prev_block) > 0 )
            iguana_patch(coin,block);
        if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,block->RO.hash2)) != 0 )
        {
            if ( bundlei < coin->chain->bundlesize )
            {
                block->bundlei = bundlei;
                block->hdrsi = bp->hdrsi;
                iguana_bundlehash2add(coin,0,bp,bundlei,block->RO.hash2);
                if ( bundlei > 0 )
                {
                    //char str[65],str2[65]; printf("call hash2add %d:[%d -1] %s  prev.%s\n",bp->hdrsi,bundlei,bits256_str(str2,block->RO.hash2),bits256_str(str,block->RO.prev_block));
                    iguana_bundlehash2add(coin,0,bp,bundlei-1,block->RO.prev_block);
                }
                else if ( bp->hdrsi > 0 && (bp= coin->bundles[bp->hdrsi-1]) != 0 )
                    iguana_bundlehash2add(coin,0,bp,coin->chain->bundlesize-1,block->RO.prev_block);
            }
        }
        if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,block->RO.prev_block)) != 0 )
        {
            //printf("found prev.%d\n",bp->bundleheight+bundlei);
            if ( bundlei < coin->chain->bundlesize )
            {
                if ( bundlei == coin->chain->bundlesize-1 )
                {
                    //if ( coin->bundlescount < bp->hdrsi+1 )
                    {
                        //char str[65]; printf("autoextend CREATE.%d new bundle.%s\n",bp->bundleheight + coin->chain->bundlesize,bits256_str(str,block->RO.hash2));
                        iguana_bundlecreate(coin,&bundlei,bp->bundleheight + coin->chain->bundlesize,block->RO.hash2,zero,1);
                    }
                }
                else if ( bundlei < coin->chain->bundlesize-1 )
                {
                    iguana_bundlehash2add(coin,0,bp,bundlei+1,block->RO.hash2);
                    if ( bundlei == 0 )
                    {
                        char str[65]; bits256_str(str,block->RO.prev_block);
                        //printf("found block -> hdr.%s\n",str);
                        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(str),1);
                    }
                }
            }
        }
        //char str[65]; printf("iguana_recvblock (%s) %d %d[%d] %p\n",bits256_str(str,block->hash2),block->havebundle,block->hdrsi,bundlei,bp);
    } else printf("iguana_bundleset: error adding blockhash\n");
    return(iguana_bundlefind(coin,&bp,bundleip,origblock->RO.hash2));
}

struct iguana_bundlereq *iguana_recvblockhdrs(struct iguana_info *coin,struct iguana_bundlereq *req,struct iguana_block *blocks,int32_t n,int32_t *newhwmp)
{
    int32_t i,bundlei; struct iguana_block *block; struct iguana_bundle *bp;
    if ( blocks == 0 )
    {
        printf("iguana_recvblockhdrs null blocks?\n");
        return(req);
    }
    if ( blocks != 0 && n > 0 )
    {
        for (i=0; i<n; i++)
        {
            //fprintf(stderr,"i.%d of %d bundleset\n",i,n);
            if ( (bp= iguana_bundleset(coin,&block,&bundlei,&blocks[i])) != 0 && bp->hdrsi < IGUANA_MAXACTIVEBUNDLES )
            {
                iguana_blockQ(coin,bp,bundlei,blocks[i].RO.hash2,0);
                if ( i == 0 )
                    printf("GOT HDRS[%d] Q.(%d %d) ht.%d hashes.%d recv.%d\n",n,queue_size(&coin->priorityQ),queue_size(&coin->blocksQ),bp->bundleheight,bp->numhashes,bp->numrecv);
            }
        }
    }
    return(req);
}

struct iguana_bundlereq *iguana_recvblockhashes(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *blockhashes,int32_t num)
{
    int32_t bundlei,i,n = 0; struct iguana_block *block; struct iguana_bundle *bp;// char str[65];
    bp = 0, bundlei = -2, iguana_bundlefind(coin,&bp,&bundlei,blockhashes[1]);
    if ( bp != 0 )
    {
        blockhashes[0] = bp->hashes[0];
        if ( num >= coin->chain->bundlesize )
        {
            bp->hdrtime = (uint32_t)time(NULL);
            if ( iguana_allhashcmp(coin,bp,blockhashes,num) == 0 )
                return(req);
        }
        for (i=0; i<num; i++)
        {
            if ( bits256_nonz(blockhashes[i]) > 0 && (block= iguana_blockhashset(coin,-1,blockhashes[i],1)) != 0 )
            {
                if ( block->hdrsi == bp->hdrsi && block->bundlei == i )
                    n++;
            }
        }
        printf("got [%d] num.%d matched hashes\n",n,num);
    }
    else
    {
        char str[65]; printf("blockhashes[%d] %s\n",num,bits256_str(str,blockhashes[1]));
        iguana_blockQ(coin,0,-1,blockhashes[1],1);
        for (i=coin->chain->bundlesize; i<num; i++)
        {
            if ( i >= coin->chain->bundlesize && (i % coin->chain->bundlesize) < 2 && bits256_nonz(blockhashes[i]) > 0 )
                iguana_blockQ(coin,0,-1,blockhashes[i],0);
        }
    }
    /*if ( (block= iguana_blockhashset(coin,-1,blockhashes[1],1)) != 0 && num > 2 )
    {
        if ( block->rawdata != 0 )
        {
            if ( block->copyflag != 0 )
                myfree(block->rawdata,block->RO.recvlen), block->copyflag = 0;
            else myfree(block->rawdata,block->numhashes * sizeof(bits256));
        }
        //char str[65]; printf("got %d unmatched hashes %d:%d %s\n",num,bp==0?-1:bp->bundleheight,bundlei,bits256_str(str,blockhashes[1]));
        block->rawdata = blockhashes, block->numhashes = num, block->havehashes = 1;
        req->hashes = 0;
    }
    if ( 0 && num >= coin->chain->bundlesize+1 )
    {
        char str[65]; bits256_str(str,blockhashes[coin->chain->bundlesize]);
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(str),1);
    }*/
    return(req);
}

struct iguana_bundlereq *iguana_recvblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundlereq *req,struct iguana_block *origblock,int32_t numtx,int32_t datalen,int32_t recvlen,int32_t *newhwmp)
{
    
    struct iguana_bundle *prevbp=0,*bp=0; int32_t prevbundlei=-2,bundlei = -2; struct iguana_block *prevblock,*block;
    bp = iguana_bundleset(coin,&block,&bundlei,origblock);
    //usleep(1000);
    //static int total; char str[65]; printf("RECV %s [%d:%d] block.%08x | %d\n",bits256_str(str,origblock->RO.hash2),bp!=0?bp->hdrsi:-1,bundlei,block->fpipbits,total++);
    iguana_bundlefind(coin,&prevbp,&prevbundlei,origblock->RO.prev_block);
    if ( prevbp != 0 && prevbundlei >= 0 && (prevblock= iguana_blockfind(coin,origblock->RO.prev_block)) != 0 )
    {
        static bits256 zero;
        prevbp->blocks[prevbundlei] = prevblock;
        if ( prevbundlei < coin->chain->bundlesize )
        {
            if ( prevbundlei == coin->chain->bundlesize-1 )
            {
                //if ( coin->bundlescount < bp->hdrsi+1 )
                {
                    //char str[65]; printf("autoextend CREATE.%d new bundle.%s\n",bp->bundleheight + coin->chain->bundlesize,bits256_str(str,block->RO.hash2));
                    iguana_bundlecreate(coin,&prevbundlei,prevbp->bundleheight + coin->chain->bundlesize,block->RO.hash2,zero,1);
                }
            }
            else
            {
                iguana_bundlehash2add(coin,0,prevbp,prevbundlei+1,block->RO.hash2);
             }
        }
        if ( prevbp->numhashes < prevbp->n && prevbundlei == 0 )
        {
            char str[65]; bits256_str(str,prevbp->hashes[0]);
            //printf("Afound block -> %d hdr.%s\n",prevbp->bundleheight,str);
            queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(str),1);
        }
        //char str[65]; printf("PREV %s prevbp.%p[%d] h.%d\n",bits256_str(str,origblock->RO.prev_block),prevbp,prevbundlei,prevbp->numhashes);
    }
    if ( block != 0 )
    {
        if ( bp != 0 && bundlei >= 0 )
            bp->blocks[bundlei] = block;
        block->RO.recvlen = recvlen;
        if ( req->copyflag != 0 && block->queued == 0 )//block->rawdata == 0 )
        {
            //char str[65]; printf("%s copyflag.%d %d data %d %d\n",bits256_str(str,block->RO.hash2),req->copyflag,block->height,req->recvlen,recvlen);
            //block->rawdata = mycalloc('n',1,block->RO.recvlen);
            //memcpy(block->rawdata,req->serialized,block->RO.recvlen);
            //block->copyflag = 1;
            coin->numcached++;
            block->queued = 1;
            queue_enqueue("cacheQ",&coin->cacheQ,&req->DL,0);
            return(0);
        }
        //printf("datalen.%d ipbits.%x\n",datalen,req->ipbits);
    } else printf("cant create block.%llx block.%p bp.%p bundlei.%d\n",(long long)origblock->RO.hash2.txid,block,bp,bundlei);
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
        //printf("%s bundlesQ.%p type.%c n.%d\n",req->addr != 0 ? req->addr->ipaddr : "0",req,req->type,req->n);
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
        flag++;
        //printf("done %s bundlesQ.%p type.%c n.%d\n",req->addr != 0 ? req->addr->ipaddr : "0",req,req->type,req->n);
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
                        lag = 5;
                    else lag = 3 + (rand() % 13);
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
                        /*if ( strcmp(coin->symbol,"BTC") != 0 && bits256_nonz(bp->hashes[1]) > 0 )
                        {
                            if ( (block= iguana_blockfind(coin,bp->hashes[1])) != 0 )
                            {
                                if ( block->havehashes != 0 && block->rawdata != 0 )
                                    iguana_allhashcmp(coin,bp,block->rawdata,block->numhashes);
                                //iguana_blockQ(coin,bp,1,bp->hashes[1],1);
                            }
                        }*/
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
    queue_t *Q; char *str; struct iguana_blockreq *req; struct iguana_block *block = 0;
    if ( bits256_nonz(hash2) == 0 )
    {
        printf("cant queue zerohash bundlei.%d\n",bundlei);
        return(-1);
    }
    if ( (bp != 0 && (block= iguana_blockfind(coin,bp->hashes[bundlei])) == 0) || priority != 0 || bp == 0 )
    {
        if ( block != 0 )
        {
            if ( block->fpipbits != 0 || block->queued != 0 )
                return(0);
            block->numrequests++;
            /*if ( block->rawdata != 0 && block->RO.recvlen != 0 )
            {
                printf("free cached copy recvlen.%d need to process it here\n",block->RO.recvlen);
                myfree(block->rawdata,block->RO.recvlen);
                block->rawdata = 0;
                block->RO.recvlen = 0;
            }*/
        }
        if ( priority != 0 )
            str = "priorityQ", Q = &coin->priorityQ;
        else str = "blocksQ", Q = &coin->blocksQ;
        if ( Q != 0 )
        {
            req = mycalloc('r',1,sizeof(*req));
            req->hash2 = hash2;
            req->bp = bp;
            req->bundlei = bundlei;
            if ( bp != 0 && bundlei >= 0 && bundlei < bp->n )
            {
                bp->issued[bundlei] = (uint32_t)time(NULL);
                if ( bp->bundleheight >= 0 )
                    req->height = (bp->bundleheight + bundlei);
            }
            char str[65];
            bits256_str(str,hash2);
            if ( 0 && (bundlei % 250) == 0 )
                printf("%s %d %s blockQ.%d numranked.%d qsize.%d\n",str,req->height,str,coin->blocks.recvblocks,coin->peers.numranked,queue_size(Q));
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
    int32_t i,r,diff,j,k,n,m; double metric,bestmetric = -1.; struct iguana_bundle *bp,*bestbp = 0;
    int32_t limit,refbundlei,height=-1,incr,bundlei,datalen,flag = 0; double val;
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
                    if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,hash2)) == 0 || bp->numhashes < bp->n )
                    {
                        printf("%s request hdr.(%s)\n",addr!=0?addr->ipaddr:"local",hashstr);
                        iguana_send(coin,addr,serialized,datalen);
                        addr->pendhdrs++;
                        flag++;
                    }
                }
                free_queueitem(hashstr);
                return(flag);
            } else printf("datalen.%d from gethdrs\n",datalen);
            free_queueitem(hashstr);
            hashstr = 0;
        }
    }
    if ( addr->msgcounts.verack == 0 )
        return(0);
    if ( (limit= addr->recvblocks) > coin->MAXPENDING )
        limit = coin->MAXPENDING;
    if ( limit < 1 )
        limit = 1;
    //if ( addr->pendblocks >= limit )
    //    printf("%s %d overlimit.%d\n",addr->ipaddr,addr->pendblocks,limit);
    req = queue_dequeue(&coin->priorityQ,0);
    if ( 0 && addr->msgcounts.verack > 0 && coin->bundlescount > 0 && req == 0 && addr->pendblocks < limit )//&& now > addr->lastpoll )
    {
        if ( 1 )//strcmp("BTC",coin->symbol) != 0 )
        {
            int32_t bundlei;
            incr = coin->peers.numranked == 0 ? coin->MAXPEERS : coin->peers.numranked;
            if ( (rand() % 100) < 50 )
                height = addr->rank * _IGUANA_MAXPENDING;
            else if ( (rand() % 100) < 50 )
                height = addr->addrind + (addr->rank * (coin->longestchain - coin->blocks.hwmchain.height) / (coin->peers.numranked+1));
            else if ( (rand() % 100) < 50 )
            {
                height = (addr->lastheight + 1);
                if ( height >= coin->longestchain-coin->chain->bundlesize )
                    height = addr->rank*incr*_IGUANA_MAXPENDING;
            }
            else
            {
                height = coin->longestchain - (rand() % incr) * 1000;
                if ( height < 0 )
                    height = coin->blocks.hwmchain.height;
            }
            for (; height<coin->bundlescount*coin->chain->bundlesize; height+=incr)
            {
                if ( height > coin->longestchain )
                    height = addr->rank*incr*_IGUANA_MAXPENDING;
                if  ( height > addr->lastheight )
                    addr->lastheight = height;
                if ( (bp= coin->bundles[height/coin->chain->bundlesize]) != 0 && bp->emitfinish == 0 )
                {
                    bundlei = (height % coin->chain->bundlesize);
                    if ( bundlei < bp->n && bits256_nonz(bp->hashes[bundlei]) > 0 && (block= bp->blocks[bundlei]) != 0 && block->numrequests <= bp->minrequests && block->fpipbits == 0 && (bp->issued[bundlei] == 0 || now > bp->issued[bundlei]+13) )
                    {
                        block->numrequests++;
                        bp->issued[bundlei] = (uint32_t)time(NULL);;
                        //if ( 0 && (rand() % 100) == 0 )
                            printf("%s Send auto blockreq.%d [%d] minreq.%d\n",addr->ipaddr,bp->bundleheight+bundlei,block->numrequests,bp->minrequests);
                        iguana_sendblockreq(coin,addr,bp,bundlei,bp->hashes[bundlei],0);
                        return(1);
                    }
                }
                //if ( (rand() % 100) < 50 )
                 //   break;
            }
        }
        else
        {
            //printf("%s lastpoll.%u %u\n",addr->ipaddr,addr->lastpoll,now);
            addr->lastpoll = now;
            for (i=n=0; i<coin->bundlescount; i++)
                if ( coin->bundles[i] != 0 && coin->bundles[i]->emitfinish == 0 )
                    n++;
            if ( n >= coin->bundlescount-(coin->bundlescount>>3) || (addr->ipbits % 10) < 5 )
                refbundlei = (addr->ipbits % coin->bundlescount);
            else
            {
                if ( n*2 < coin->bundlescount )
                {
                    for (i=refbundlei=0; i<IGUANA_MAXPEERS; i++)
                    {
                        if ( addr->usock == coin->peers.active[i].usock )
                            break;
                        if ( coin->peers.active[i].usock >= 0 )
                            refbundlei++;
                    }
                    //printf("half done\n");
                } else refbundlei = ((addr->addrind*100) % coin->bundlescount);
            }
            for (i=0; i<coin->bundlescount; i++)
            {
                if ( (diff= (i - refbundlei)) < 0 )
                    diff = -diff;
                if ( (bp= coin->bundles[i]) != 0 && bp->emitfinish == 0 )
                {
                    metric = (1 + diff * ((addr->addrind&1) == 0 ? 1 : 1) * (1. + bp->metric));// / (i*((addr->addrind&1) != 0 ? 1 : i) + 1);
                    //printf("%f ",bp->metric);
                    if ( bestmetric < 0. || metric < bestmetric )
                        bestmetric = metric, bestbp = bp;
                }
            }
            if ( bestbp != 0 && bp->emitfinish == 0 )
            {
                for (k=0; k<coin->bundlescount; k++)
                {
                    i = (bestbp->hdrsi + k) % coin->bundlescount;
                    if ( (bp= coin->bundles[i]) == 0 || bp->emitfinish != 0 )
                        continue;
                    //printf("%.15f ref.%d addrind.%d bestbp.%d\n",bestmetric,refbundlei,addr->addrind,bp->hdrsi);
                    m = coin->chain->bundlesize;
                    if ( bp->n < m )
                        m = bp->n;
                    j = (addr->addrind*3 + 0) % m;
                    val = (bp->threshold / 1000.);
                    for (r=0; r<m; r++,j++)
                    {
                        if ( j >= m )
                            j = 0;
                        if ( (block= bp->blocks[j]) != 0 && block->fpipbits == 0 && block->queued == 0 && block->numrequests <= bp->minrequests )
                        {
                            block->numrequests++;
                            //block->issued = (uint32_t)time(NULL);;
                            //printf("%s Send auto blockreq.%d\n",addr->ipaddr,bp->bundleheight+j);
                            iguana_sendblockreq(coin,addr,bp,j,hash2,0);
                            return(1);
                        }
                    }
                }
            }
        }
    }
    int32_t priority;
    if ( addr->rank != 1 && req == 0 )
    {
        priority = 0;
        req = queue_dequeue(&coin->blocksQ,0);
    } else priority = 1;
    if ( req != 0 )
    {
        hash2 = req->hash2;
        height = req->height;
        block = 0;
        if ( priority == 0 && (bp= req->bp) != 0 && req->bundlei >= 0 && req->bundlei < bp->n && req->bundlei < coin->chain->bundlesize && (block= bp->blocks[req->bundlei]) != 0 && (block->fpipbits != 0 || block->queued != 0) )
        {
            //if ( 0 && priority != 0 )
                printf("SKIP %p[%d] %d\n",bp,bp!=0?bp->bundleheight:-1,req->bundlei);
        }
        else
        {
            //char str[65];
            //if ( 0 && priority != 0 )
            //    printf(" issue.%s\n",bits256_str(str,hash2));
            if ( block != 0 )
                block->numrequests++;
            iguana_sendblockreq(coin,addr,req->bp,req->bundlei,hash2,0);
        }
        flag++;
        myfree(req,sizeof(*req));
    }
    return(flag);
}

int32_t iguana_processrecv(struct iguana_info *coin) // single threaded
{
    int32_t newhwm = 0,h,lflag,bundlei,flag = 0; bits256 hash2; struct iguana_block *next,*block; struct iguana_bundle *bp;
    //printf("process bundlesQ\n");
    flag += iguana_processbundlesQ(coin,&newhwm);
    flag += iguana_reqhdrs(coin);
    lflag = 1;
    while ( lflag != 0 )
    {
        lflag = 0;
        h = coin->blocks.hwmchain.height / coin->chain->bundlesize;
        if ( (next= iguana_blockfind(coin,iguana_blockhash(coin,coin->blocks.hwmchain.height+1))) == 0 )
        {
            if ( (block= iguana_blockfind(coin,coin->blocks.hwmchain.RO.hash2)) != 0 )
                next = block->hh.next, block->mainchain = 1;
        }
        if ( next != 0 )
        {
            //printf("have next\n");
            if ( memcmp(next->RO.prev_block.bytes,coin->blocks.hwmchain.RO.hash2.bytes,sizeof(bits256)) == 0 )
            {
                if ( _iguana_chainlink(coin,next) != 0 )
                    lflag++;
                //else printf("chainlink error for %d\n",coin->blocks.hwmchain.height+1);
            }
            if ( 1 )
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
                    threshold = 400;
                else threshold = 1000;
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
                            iguana_blockQ(coin,bp,bundlei,iguana_blockhash(coin,coin->backstop),1);
                            if ( (rand() % 100) == 0 )
                                printf("MAINCHAIN.%d threshold %.3f %.3f lag %.3f\n",coin->blocks.hwmchain.height+1,threshold,coin->backstopmillis,lag);
                        }
                    }
                }
                else if ( 0 && bits256_nonz(next->RO.prev_block) > 0 )
                    printf("next prev cmp error nonz.%d\n",bits256_nonz(next->RO.prev_block));
            }
        }
        if ( h != coin->blocks.hwmchain.height / coin->chain->bundlesize )
            iguana_savehdrs(coin);
    }
    return(flag);
}
