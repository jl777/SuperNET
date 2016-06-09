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

static int32_t numDuplicates,numAfteremit;
static int64_t sizeDuplicates,sizeAfteremit;

struct iguana_bundlereq *iguana_bundlereq(struct iguana_info *coin,struct iguana_peer *addr,int32_t type,uint8_t *data,int32_t datalen)
{
    struct iguana_bundlereq *req; int32_t allocsize;
    if ( data == 0 )
        datalen = 0;
    allocsize = (uint32_t)sizeof(*req) + datalen;
    req = mycalloc(type,1,allocsize);
    req->allocsize = allocsize;
    req->datalen = datalen;
    req->addr = addr;
    req->coin = coin;
    req->type = type;
    if ( data != 0 && datalen > 0 )
        memcpy(req->serializeddata,data,datalen);
    return(req);
}

int32_t iguana_speculativesearch(struct iguana_info *coin,struct iguana_block **blockptrp,bits256 hash2)
{
    int32_t i,j; struct iguana_bundle *bp;
    if ( blockptrp != 0 )
        *blockptrp = 0;
    for (i=0; i<coin->bundlescount; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && bp->speculative != 0 )
        {
            for (j=0; j<bp->n&&j<bp->numspec; j++)
                if ( bits256_cmp(hash2,bp->speculative[j]) == 0 )
                {
                    if ( blockptrp != 0 )
                        *blockptrp = bp->blocks[j];
                    if ( bp->speculativecache[j] != 0 )
                        return(1);
                    else return(-1);
                }
        }
    }
    return(0);
}

int32_t iguana_sendblockreqPT(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t iamthreadsafe)
{
    static bits256 lastreq,lastreq2;
    int32_t len,j; struct iguana_bundle *checkbp; uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(uint32_t)*32 + sizeof(bits256)]; struct iguana_block *block=0;
    char hexstr[65]; init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
    if ( addr == 0 || memcmp(lastreq.bytes,hash2.bytes,sizeof(hash2)) == 0 || memcmp(lastreq2.bytes,hash2.bytes,sizeof(hash2)) == 0 )
    {
        //printf("duplicate req %s or null addr.%p\n",bits256_str(hexstr,hash2),addr);
       // if ( (rand() % 10 ) != 0 )
            return(0);
    }
    if ( addr->usock < 0 )
        return(0);
    checkbp = 0, j = -2;
    if ( (checkbp= iguana_bundlefind(coin,&checkbp,&j,hash2)) != 0 && j >= 0 && j < checkbp->n )
    {
        if ( checkbp->emitfinish != 0 || ((block= checkbp->blocks[j]) != 0 && block->txvalid != 0) )
        {
            //printf("found valid [%d:%d] in blockreqPT\n",checkbp->hdrsi,j);
            return(0);
        }
    }
    if ( 1 && coin->enableCACHE != 0 && iguana_speculativesearch(coin,&block,hash2) != 0 )
    {
        if ( block != 0 && block->hdrsi != 0 && block->bundlei != 0 )
        {
            //printf("found valid [%d:%d] in blockreqPT txvalid.%d\n",block!=0?block->hdrsi:-1,block!=0?block->bundlei:-1,block->txvalid);
            if ( block->txvalid != 0 )
                return(0);
        }
    }
    if ( addr->msgcounts.verack == 0 )
    {
        //printf("iguana_sendblockreq (%s) addrind.%d hasn't verack'ed yet\n",addr->ipaddr,addr->addrind);
        //iguana_send_version(coin,addr,coin->myservices);
        return(-1);
    }
    lastreq2 = lastreq;
    lastreq = hash2;
    if ( (len= iguana_getdata(coin,serialized,MSG_BLOCK,&hash2,1)) > 0 )
    {
        iguana_send(coin,addr,serialized,len);
        coin->numreqsent++;
        addr->pendblocks++;
        addr->pendtime = (uint32_t)time(NULL);
        if ( bp != 0 && bundlei >= 0 && bundlei < bp->n )
            bp->issued[bundlei] = addr->pendtime;
        if ( block != 0 )
            block->issued = addr->pendtime;
        if ( 0 && coin->current == bp )
            printf("REQ.%s bundlei.%d hdrsi.%d\n",bits256_str(hexstr,hash2),bundlei,bp!=0?bp->hdrsi:-1);
    } else printf("MSG_BLOCK null datalen.%d\n",len);
    return(len);
}

int32_t iguana_sendtxidreq(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2)
{
    uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(uint32_t)*32 + sizeof(bits256)];
    int32_t len,i,r,j; //char hexstr[65]; init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
    if ( (len= iguana_getdata(coin,serialized,MSG_TX,&hash2,1)) > 0 )
    {
        if ( addr == 0 )
        {
            r = rand();
            for (i=0; i<coin->MAXPEERS; i++)
            {
                j = (i + r) % coin->MAXPEERS;
                addr = &coin->peers->active[j];
                if ( coin->peers->active[j].usock >= 0 && coin->peers->active[j].dead == 0 )
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
        if ( coin->peers->active[i].usock >= 0 )
            iguana_sendtxidreq(coin,coin->peers->ranked[i],txid);
    return(0);
}

void iguana_gotunconfirmedM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgtx *tx,uint8_t *data,int32_t datalen)
{
    struct iguana_bundlereq *req;
    char str[65]; printf("%s unconfirmed.%s\n",addr->ipaddr,bits256_str(str,tx->txid));
    req = iguana_bundlereq(coin,addr,'U',data,datalen);
    req->datalen = datalen;
    req->txid = tx->txid;
    memcpy(req->serializeddata,data,datalen);
    queue_enqueue("recvQ",&coin->recvQ,&req->DL,0);
}

#ifdef later
struct iguana_txblock *iguana_peertxdata(struct iguana_info *coin,int32_t *bundleip,char *fname,struct OS_memspace *mem,uint32_t ipbits,bits256 hash2)
{
    int32_t bundlei,datalen,checki,hdrsi,fpos; char str[65],str2[65]; FILE *fp;
    bits256 checkhash2; struct iguana_txblock *txdata = 0; static const bits256 zero;
    if ( (bundlei= iguana_peerfname(coin,&hdrsi,GLOBAL_TMPDIR,fname,ipbits,hash2,zero,1)) >= 0 )
    //if ( (bundlei= iguana_peerfname(coin,&hdrsi,fname,ipbits,hash2)) >= 0 )
    {
        if ( (fp= fopen(fname,"rb")) != 0 )
        {
            fseek(fp,bundlei * sizeof(bundlei),SEEK_SET);
            fread(&fpos,1,sizeof(fpos),fp);
            fseek(fp,fpos,SEEK_SET);
            fread(&checki,1,sizeof(checki),fp);
            if ( ftell(fp)-sizeof(checki) == fpos && bundlei == checki )
            {
                fread(&checkhash2,1,sizeof(checkhash2),fp);
                if ( memcmp(hash2.bytes,checkhash2.bytes,sizeof(hash2)) == 0 )
                {
                    fread(&datalen,1,sizeof(datalen),fp);
                    if ( datalen < (mem->totalsize - mem->used - 4) )
                    {
                        if ( (txdata= iguana_memalloc(mem,datalen,0)) != 0 )
                        {
                            fread(txdata,1,datalen,fp);
                            if ( txdata->datalen != datalen || txdata->block.bundlei != bundlei )
                            {
                                printf("%s peertxdata txdata->datalen.%d != %d bundlei.%d vs %d\n",bits256_str(str,txdata->block.RO.hash2),txdata->datalen,datalen,txdata->block.bundlei,bundlei);
                                //getchar();
                                txdata = 0;
                                iguana_memreset(mem);
                            } //else printf("SUCCESS txdata.%s bundlei.%d fpos.%d T.%d U.%d S.%d P.%d\n",bits256_str(str,txdata->block.hash2),bundlei,fpos,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds);
                        } else printf("peertxdata error allocating txdata\n");
                    } else printf("mismatch peertxdata datalen %d vs %ld totalsize %ld\n",datalen,mem->totalsize - mem->used - 4,(long)mem->totalsize);
                } else printf("peertxdata hash mismatch %s != %s\n",bits256_str(str,hash2),bits256_str(str2,checkhash2));
            } else printf("peertxdata bundlei.%d != checki.%d, fpos.%d ftell.%ld\n",bundlei,checki,fpos,ftell(fp));
            fclose(fp);
        } else printf("cant find file.(%s)\n",fname);
    } //else printf("bundlei.%d\n",bundlei);
    *bundleip = bundlei;
    return(txdata);
}
#endif

int32_t iguana_speculativefind(struct iguana_info *coin,struct iguana_bundle *bp,struct iguana_block *block,uint8_t *data,int32_t recvlen)
{
    int32_t i,j,numcached,cachelen=0; uint8_t *tmp; char str[65];
    if ( coin->enableCACHE == 0 || recvlen < 0 )
        return(-1);
    if ( recvlen < 0 || recvlen > IGUANA_MAXPACKETSIZE )
    {
        printf("iguana_speculativefind: illegal recvlen.%d\n",recvlen);
        return(-1);
    }
    for (i=0; i<bp->n; i++)
    {
        if ( bits256_cmp(bp->speculative[i],block->RO.hash2) == 0 )
        {
            if ( (tmp= bp->speculativecache[i]) != 0 )
            {
                memcpy(&cachelen,tmp,sizeof(cachelen));
                if ( cachelen < 0 || cachelen > IGUANA_MAXPACKETSIZE )
                {
                    printf("illegal cachelen.%d %s [%d:%d] %p\n",cachelen,coin->symbol,bp->hdrsi,i,tmp);
                    bp->speculativecache[i] = 0;
                    continue;
                }
                if ( memcmp(&recvlen,tmp,sizeof(recvlen)) != 0 || memcmp(&tmp[sizeof(recvlen)],data,recvlen) != 0 )
                {
                    //printf("cachedata ERROR [%d:%d] already has recvlen.%d vs %d for %s\n",bp->hdrsi,i,recvlen,cachelen,bits256_str(str,block->RO.hash2));
                }
                return(0);
            }
            bp->speculativecache[i] = calloc(1,recvlen + sizeof(recvlen));
            memcpy(bp->speculativecache[i],&recvlen,sizeof(recvlen));
            memcpy(&bp->speculativecache[i][sizeof(recvlen)],data,recvlen);
            for (j=numcached=0; j<bp->n; j++)
                if ( bp->speculativecache[j] != 0 )
                    numcached++;
            if ( 0 && bp == coin->current )
                printf("cache %s [%d:%d] h.%d s.%d c.%d -> %d\n",bits256_str(str,block->RO.hash2),bp->hdrsi,i,bp->numhashes,bp->numsaved,bp->numcached,numcached);
            return(i);
        }
    }
    return(-1);
}

int8_t iguana_blockstatus(struct iguana_info *coin,struct iguana_block *block)
{
    int32_t status = 0;
    if ( block->RO.recvlen != 0 )
        status |= 1;
    if ( block->fpipbits != 0 )
        status |= 2;
    if ( block->fpos >= 0 )
        status |= 4;
    if ( bits256_nonz(block->RO.prev_block) != 0 )
        status |= 8;
    if ( block->queued != 0 )
        status |= 0xc0; // force negative, 0x80 can be +128
    return(status);
}

void iguana_bundletime(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,struct iguana_block *block,int32_t duplicateflag)
{
    uint32_t starttime; int32_t duration;
    if ( bp != 0 && bundlei >= 0 && bundlei < bp->n && block != 0 )
    {
        starttime = block->issued;
        if ( starttime == 0 || bp->issued[bundlei] > block->issued )
            starttime = bp->issued[bundlei];
        bp->issued[bundlei] = 1;
        if ( starttime != 0 )
        {
            duration = (uint32_t)time(NULL) - starttime;
            if ( duplicateflag != 0 )
            {
                bp->duplicatedurations += duration;
                bp->duplicatescount++;
            }
            else
            {
                bp->totaldurations += duration;
                bp->durationscount++;
            }
            if ( (block= bp->blocks[bundlei]) != 0 && block->lag == 0 )
                block->lag = duration;
        }
    }
}

void iguana_gotblockM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *origtxdata,struct iguana_msgtx *txarray,struct iguana_msghdr *H,uint8_t *data,int32_t recvlen)
{
    struct iguana_bundlereq *req; struct iguana_txblock *txdata = 0; int32_t valid,speculative=0,i,j,bundlei,copyflag; struct iguana_block *block; struct iguana_bundle *bp; uint32_t now; char str[65];
    if ( recvlen < 0 || recvlen > IGUANA_MAXPACKETSIZE )
    {
        printf("iguana_getblockM: illegal recvlen.%d\n",recvlen);
        return;
    }
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
        for (i=0; i<origtxdata->zblock.RO.txn_count; i++)
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
    origtxdata->zblock.RO.allocsize = sizeof(origtxdata->zblock);
    if ( iguana_blockvalidate(coin,&valid,(struct iguana_block *)&origtxdata->zblock,1) < 0 )
    {
        printf("got block that doesnt validate? %s\n",bits256_str(str,origtxdata->zblock.RO.hash2));
        return;
    }
    else if ( 0 && coin->enableCACHE != 0 )
        printf("cache.%d validated.(%s)\n",coin->enableCACHE,bits256_str(str,origtxdata->zblock.RO.hash2));
    origtxdata->zblock.txvalid = 1;
    if ( coin->virtualchain == 0 && addr != 0 && addr != &coin->internaladdr )
    {
        static uint64_t received[IGUANA_MAXPEERS],count[IGUANA_MAXPEERS],lastcount,lastreceived,last;
        received[addr->addrind] += recvlen;
        count[addr->addrind]++;
        now = (uint32_t)time(NULL);
        if ( ((rand() % 1000) == 0 && now > last+10) || now > last+600 )
        {
            int64_t sum2 = 0,sum = 0,diffr,diff; double bw = 0.;
            for (i=0; i<sizeof(received)/sizeof(*received); i++)
                sum += received[i], sum2 += count[i];
            diffr = (sum - lastreceived), diff = (sum2 - lastcount);
            //printf("diffr %d diff %d, last %d/%d\n",(int32_t)diffr,(int32_t)diff,(int32_t)lastreceived,(int32_t)lastcount);
            lastreceived = sum, lastcount = sum2;
            if ( diff != 0 )
            {
                bw = ((double)diffr / (now - last + 1));
                if ( bw > coin->maxbandwidth )
                    coin->maxbandwidth = bw;
            }
            dxblend(&coin->bandwidth,bw,.9);
            char str[65],str2[65],str3[65],str4[65]; printf("%s BLOCKS.%llu RECV %s ave %.1f | dup.%d %s after.%d %s %s/sec %.2f%% %s\n",coin->symbol,(long long)sum2,mbstr(str,sum),(double)sum/(sum2!=0?sum2:1),numDuplicates,mbstr(str2,sizeDuplicates),numAfteremit,mbstr(str3,sizeAfteremit),mbstr(str4,bw),coin->maxbandwidth!=0.?100.*coin->bandwidth/coin->maxbandwidth:0.,coin->maxbandwidth>4*coin->bandwidth?"SLOW":"");
            last = now;
        }
        if ( coin->bandwidth < 0.25*coin->maxbandwidth )
        {
            //printf(">>SLOW.%d<< ",addr->addrind);
            //iguana_blast(coin,addr);
        }
    }
    copyflag = (coin->enableCACHE != 0) && (strcmp(coin->symbol,"BTC") != 0);
    bp = 0, bundlei = -2;
    bp = iguana_bundlefind(coin,&bp,&bundlei,origtxdata->zblock.RO.hash2);
    if ( bp != 0 && bundlei >= 0 && bundlei < bp->n )
    {
        block = bp->blocks[bundlei];
        if ( bp->emitfinish != 0 )
        {
            numAfteremit++;
            sizeAfteremit += recvlen;
            if ( block != 0 )
                iguana_bundletime(coin,bp,bundlei,block,1);
            //printf("got [%d:%d] with emitfinish.%u\n",bp->hdrsi,bundlei,bp->emitfinish);
            return;
        }
        bp->dirty++;
        if ( bundlei >= 0 && block != 0 )
        {
            if ( block->fpipbits != 0 && block->txvalid != 0 )
            {
                numDuplicates++;
                sizeDuplicates += recvlen;
                iguana_bundletime(coin,bp,bundlei,block,1);
                //printf("duplicate [%d:%d] %s\n",bp->hdrsi,bundlei,bits256_str(str,block->RO.hash2));
                if ( bits256_cmp(origtxdata->zblock.RO.hash2,block->RO.hash2) == 0 )
                    return;
                else printf("mismatched tx received? mainchain.%d\n",block->mainchain);
                if ( block->mainchain != 0 )
                    return;
            }
            else
            {
                iguana_bundletime(coin,bp,bundlei,block,0);
                if ( 0 && bp == coin->current )
                    printf("recv [%d:%d] %s\n",bp->hdrsi,bundlei,bits256_str(str,block->RO.hash2));
            }
            iguana_blockzcopyRO(coin->chain->zcash,&block->RO,0,&origtxdata->zblock.RO,0);
            block->txvalid = 1;
        }
    }
    else
    {
        if ( (bp= coin->current) != 0 )
        {
            for (i=0; i<coin->bundlescount; i++)
            {
                if ( (bp= coin->bundles[i]) != 0 && bp->emitfinish == 0 && bp->speculative != 0 && bp->numhashes < bp->n )
                {
                    if ( (j= iguana_speculativefind(coin,bp,(struct iguana_block *)&origtxdata->zblock,data,recvlen)) >= 0 )
                    {
                        copyflag = 0;
                        speculative = 1;
                        if ( bp->blocks[j] != 0 )
                            iguana_bundletime(coin,bp,j,bp->blocks[j],0);
                        break;
                    }
                }
            }
        }
    }
    block = 0;
    if ( copyflag != 0 && recvlen != 0 && (bp == 0 || bundlei < 0 || ((block= bp->blocks[bundlei]) != 0 && block->fpipbits == 0 && block->req == 0)) )
    {
        struct iguana_msghdr checkH;
        req = iguana_bundlereq(coin,addr,'B',data,copyflag * recvlen);
        req->copyflag = 1;
        req->H = *H;
        if ( 0 && iguana_sethdr(&checkH,coin->chain->netmagic,H->command,req->serializeddata,recvlen) > 0 && memcmp(&checkH,H,sizeof(checkH)) != 0 )
        {
            int z;
            for (z=0; z<sizeof(checkH); z++)
                printf("%02x",((uint8_t *)&checkH)[z]);
            printf(" req->H datalen.%d crc.%08x error\n",recvlen,calc_crc32(0,data,recvlen));
        }
    }
    else
    {
        copyflag = 0;
        req = iguana_bundlereq(coin,addr,'B',0,0);
    }
    req->recvlen = recvlen;
    if ( bits256_cmp(origtxdata->zblock.RO.hash2,coin->APIblockhash) == 0 )
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
        if ( speculative == 0 && iguana_ramchain_data(coin,addr,origtxdata,txarray,origtxdata->zblock.RO.txn_count,data,recvlen) >= 0 )
        {
            txdata->zblock.fpipbits = (uint32_t)addr->ipbits;
            txdata->zblock.RO.recvlen = recvlen;
            txdata->zblock.fpos = 0;
            req->datalen = txdata->datalen;
            req->ipbits = txdata->zblock.fpipbits;
            /*if ( 0 )
            {
                struct iguana_txblock *checktxdata; struct OS_memspace checkmem; int32_t checkbundlei;
                memset(&checkmem,0,sizeof(checkmem));
                iguana_meminit(&checkmem,"checkmem",0,txdata->datalen + 4096,0);
                if ( (checktxdata= iguana_peertxdata(coin,&checkbundlei,fname,&checkmem,(uint32_t)addr->ipbits,txdata->block.RO.hash2)) != 0 )
                {
                    printf("check datalen.%d bundlei.%d T.%d U.%d S.%d P.%d X.%d\n",checktxdata->datalen,checkbundlei,checktxdata->numtxids,checktxdata->numunspents,checktxdata->numspends,checktxdata->numpkinds,checktxdata->numexternaltxids);
                }
                iguana_mempurge(&checkmem);
            }*/
        } //else printf("cant save block\n");
    }
    req->zblock = txdata->zblock;
    if ( coin->virtualchain != 0 )
        printf("%s recvlen.%d ipbits.%x prev.(%s)\n",coin->symbol,req->zblock.RO.recvlen,req->zblock.fpipbits,bits256_str(str,txdata->zblock.RO.prev_block));
    req->zblock.RO.txn_count = req->numtx = txdata->zblock.RO.txn_count;
    coin->recvcount++;
    coin->recvtime = (uint32_t)time(NULL);
    req->addr = addr;
    netBLOCKS++;
    queue_enqueue("recvQ",&coin->recvQ,&req->DL,0);
}

void iguana_gottxidsM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *txids,int32_t n)
{
    struct iguana_bundlereq *req;
    //printf("got %d txids from %s\n",n,addr->ipaddr);
    req = iguana_bundlereq(coin,addr,'T',0,0);
    req->hashes = txids, req->n = n;
    queue_enqueue("recvQ",&coin->recvQ,&req->DL,0);
}

void iguana_gotheadersM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_zblock *zblocks,int32_t n)
{
    struct iguana_bundlereq *req; int32_t i,num;
    if ( addr != 0 )
    {
        static uint32_t hdrsreceived[IGUANA_MAXPEERS];
        hdrsreceived[addr->addrind] += n;
        char str[65];
        if ( (rand() % 1000) == 0 )
        {
            uint32_t i,sum = 0;
            for (i=0; i<sizeof(hdrsreceived)/sizeof(*hdrsreceived); i++)
                sum += hdrsreceived[i];
            printf("TOTAL HDRS RECEIVED %u -> %s\n",sum,mbstr(str,sum*80));
        }
        addr->recvhdrs++;
        if ( addr->pendhdrs > 0 )
            addr->pendhdrs--;
        //printf("%s blocks[%d] ht.%d gotheaders pend.%d %.0f\n",addr->ipaddr,n,blocks[0].height,addr->pendhdrs,milliseconds());
        if ( bits256_cmp(zblocks[1].RO.hash2,coin->RThash1) == 0 )
        {
            num = (n < coin->chain->bundlesize ? n : coin->chain->bundlesize);
            for (i=0; i<num; i++)
                addr->RThashes[i] = zblocks[i].RO.hash2;
            addr->numRThashes = num;
        }
    }
    req = iguana_bundlereq(coin,addr,'H',0,0);
    req->blocks = zblocks, req->n = n;
    HDRnet++;
    queue_enqueue("recvQ",&coin->recvQ,&req->DL,0);
}

void iguana_gotblockhashesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *blockhashes,int32_t n)
{
    struct iguana_bundlereq *req; int32_t num;
    if ( addr != 0 )
    {
        addr->recvhdrs++;
        if ( addr->pendhdrs > 0 )
            addr->pendhdrs--;
        if ( bits256_cmp(blockhashes[1],coin->RThash1) == 0 )
        {
            num = (n < coin->chain->bundlesize ? n : coin->chain->bundlesize);
            memcpy(addr->RThashes,blockhashes,num * sizeof(*addr->RThashes));
            addr->numRThashes = num;
        }
    }
    req = iguana_bundlereq(coin,addr,'S',0,0);
    req->hashes = blockhashes, req->n = n;
    char str[65];
    if ( 0 && n > 2 && addr != 0 )
        printf("addr.%d %s [%d]\n",addr->rank,bits256_str(str,blockhashes[1]),n);
    queue_enqueue("recvQ",&coin->recvQ,&req->DL,0);
    if ( strcmp("BTC",coin->symbol) != 0 && n > coin->chain->bundlesize )
        iguana_sendblockreqPT(coin,addr,0,-1,blockhashes[1],0);
}

uint32_t iguana_allhashcmp(struct iguana_info *coin,struct iguana_bundle *bp,bits256 *blockhashes,int32_t num)
{
    bits256 allhash; int32_t err,i,n; struct iguana_block *block,*prev;
    if ( bits256_nonz(bp->allhash) > 0 && num >= coin->chain->bundlesize && bp->emitfinish == 0 )
    {
        vcalc_sha256(0,allhash.bytes,blockhashes[0].bytes,coin->chain->bundlesize * sizeof(*blockhashes));
        if ( memcmp(allhash.bytes,bp->allhash.bytes,sizeof(allhash)) == 0 )
        {
            if ( bp->bundleheight > 0 )
                prev = iguana_blockfind("allhashcmp",coin,iguana_blockhash(coin,bp->bundleheight-1));
            else prev = 0;
            for (i=n=0; i<coin->chain->bundlesize&&i<bp->n; i++)
            {
                if ( (err= iguana_bundlehash2add(coin,&block,bp,i,blockhashes[i])) < 0 )
                {
                    printf("error adding blockhash allhashes hdrsi.%d i.%d\n",bp->hdrsi,i);
                    return(err);
                }
                if ( block != 0 && block == bp->blocks[i] )
                {
                    if ( i > 0 )
                        block->RO.prev_block = blockhashes[i-1];
                    block->height = bp->bundleheight + i;
                    //printf("allhashcmp ht.%d for %d\n",block->height,i);
                    block->mainchain = 1;
                    if ( prev != 0 )
                    {
                        block->RO.prev_block = prev->RO.hash2;
                        prev->hh.next = block;
                        block->hh.prev = prev;
                    }
                    //if ( bp->hdrsi < coin->MAXBUNDLES )
                    //    iguana_blockQ(coin,bp,i,blockhashes[i],0);
                } else printf("no allhashes block.%p or mismatch.%p\n",block,bp->blocks[i]);
                prev = block;
            }
            coin->allhashes++;
            n = 0;
            if ( bp->hdrsi < coin->MAXBUNDLES || (coin->current != 0 && coin->lastpending != 0 && bp->hdrsi >= coin->current->hdrsi && bp->hdrsi <= coin->lastpending->hdrsi) )
                n = iguana_bundleissuemissing(coin,bp,1,3.);
            if ( 0 && n > 0 )
                printf("ALLHASHES FOUND! %d allhashes.%d issued %d\n",bp->bundleheight,coin->allhashes,n);
            if ( bp->queued == 0 )
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
    if ( strcmp("BTC",coin->symbol) != 0 && bp->numhashes < bp->n && bundlei == 0 && bp->speculative == 0 && bp->bundleheight < coin->longestchain-coin->chain->bundlesize )
    {
        char str[65]; bits256_str(str,bp->hashes[0]);
        //fprintf(stderr,"Afound block -> %d %d hdr.%s\n",bp->bundleheight,coin->longestchain-coin->chain->bundlesize,str);
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(str),1);
    }
    /*else if ( bp->speculative != 0 && bundlei < bp->numspec && memcmp(hash2.bytes,bp->speculative[bundlei].bytes,sizeof(hash2)) == 0 )
    {
        bundlei += offset;
        if ( bundlei < bp->n && bundlei < bp->numspec && time(NULL) > bp->issued[bundlei]+30 )
        {
            char str[65]; printf("speculative req[%d] %s\n",bundlei,bits256_str(str,bp->speculative[bundlei]));
            iguana_blockQ("speculate",coin,0,-1,bp->speculative[bundlei],0);
            bp->issued[bundlei] = (uint32_t)time(NULL);
        }
    } */ //else printf("speculative.%p %d vs %d cmp.%d\n",bp->speculative,bundlei,bp->numspec,bp->speculative!=0?memcmp(hash2.bytes,bp->speculative[bundlei].bytes,sizeof(hash2)):-1);*/
}

int32_t iguana_bundlehashadd(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,struct iguana_block *block)
{
    static const bits256 zero;
    struct iguana_ramchain blockR; int32_t hdrsi,firstflag=0,checki,retval=-1; long size = 0; FILE *fp; char fname[1024];
    block->bundlei = bundlei;
    block->hdrsi = bp->hdrsi;
    if ( bits256_nonz(bp->hashes[bundlei]) != 0 && bits256_cmp(bp->hashes[bundlei],block->RO.hash2) != 0 )
    {
        char str[65],str2[65]; printf("mismatched.[%d:%d] %s <-? %s%s\n",bp->hdrsi,bundlei,bits256_str(str,bp->hashes[bundlei]),bits256_str(str2,block->RO.hash2),block->mainchain?".main":"");
        if ( block == bp->blocks[bundlei] )
        {
            if ( block->mainchain == 0 )
            {
                printf("mainchain blockptr.%p vs %p\n",block,bp->blocks[bundlei]);
                return(-1);
            }
        }
        else if ( bp->blocks[bundlei] != 0 )
        {
            printf("mismatched blockptr.%p vs %p\n",block,bp->blocks[bundlei]);
            return(-1);
        }
    }
    //if ( bp->blocks[bundlei] == 0 )
        firstflag = 1;
    bp->blocks[bundlei] = block;
    iguana_bundlehash2add(coin,0,bp,bundlei,block->RO.hash2);
    if ( firstflag != 0 && bp->emitfinish == 0 )
    {
        //block->fpos = -1;
        if ( 0 && iguana_ramchainfile(coin,0,&blockR,bp,bundlei,block) == 0 )
        {
            size = sizeof(blockR);
            iguana_ramchain_free(coin,&blockR,1);
        }
        else if ( bp->hdrsi > 0 && bp->hdrsi == coin->longestchain/bp->n )
        {
            checki = iguana_peerfname(coin,&hdrsi,GLOBAL_TMPDIR,fname,0,block->RO.hash2,zero,1,0);
            if ( (fp= fopen(fname,"rb")) != 0 )
            {
                fseek(fp,0,SEEK_END);
                size = (uint32_t)ftell(fp);
                fclose(fp);
            }
        }
        if ( size != 0 )
        {
            retval = 0;
            //printf("initialize with fp.[%d:%d] len.%ld\n",bp->hdrsi,bundlei,size);
            block->RO.recvlen = (int32_t)size;
            block->fpipbits = 1;
            block->txvalid = 1;
            block->fpos = 0;
            block->issued = (uint32_t)time(NULL);
        }
    }
    return(retval);
}

// main context, ie single threaded
struct iguana_bundle *iguana_bundleset(struct iguana_info *coin,struct iguana_block **blockp,int32_t *bundleip,struct iguana_block *origblock)
{
    struct iguana_block *block,*prevblock; bits256 zero,hash2,prevhash2; struct iguana_bundle *prevbp,*bp = 0; int32_t prevbundlei,bundlei = -2; // struct iguana_ramchain blockR;
    *bundleip = -2; *blockp = 0;
    if ( origblock == 0 )
        return(0);
    memset(zero.bytes,0,sizeof(zero));
    hash2 = origblock->RO.hash2;
    if ( (block= iguana_blockhashset("bundleset",coin,-1,hash2,1)) != 0 )
    {
        prevhash2 = origblock->RO.prev_block;
        if ( block != origblock )
        {
            iguana_blockcopy(coin->chain->zcash,coin->chain->auxpow,coin,block,origblock);
            //fprintf(stderr,"bundleset block.%p vs origblock.%p prev.%d bits.%x fpos.%ld\n",block,origblock,bits256_nonz(prevhash2),block->fpipbits,block->fpos);
        }
        *blockp = block;
        //if ( 0 && bits256_nonz(prevhash2) > 0 )
        //    iguana_patch(coin,block);
        bp = 0, bundlei = -2;
        if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,hash2)) != 0 && bundlei < coin->chain->bundlesize )
        {
            if ( iguana_bundlehashadd(coin,bp,bundlei,block) < 0 )
            {
                if ( bp->emitfinish == 0 && block->issued == 0 && strcmp("BTC",coin->symbol) != 0 )//|| coin->PREFETCHLAG < 0) )
                    iguana_blockQ("bundleset",coin,bp,bundlei,block->RO.hash2,1);//coin->current == 0 || bp->hdrsi <= coin->current->hdrsi+coin->MAXBUNDLES);
            }
            //fprintf(stderr,"bundle found %d:%d\n",bp->hdrsi,bundlei);
             //printf("bundlehashadd set.%d\n",bundlei);
            if ( bundlei > 0 )
            {
                //printf("bundlehashadd prev %d\n",bundlei);
                if ( bits256_nonz(prevhash2) != 0 )
                    iguana_bundlehash2add(coin,0,bp,bundlei-1,prevhash2);
            }
            else if ( bp->hdrsi > 0 && (bp= coin->bundles[bp->hdrsi-1]) != 0 )
                iguana_bundlehash2add(coin,0,bp,coin->chain->bundlesize-1,prevhash2);
            if ( 1 && strcmp("BTC",coin->symbol) != 0 )
                iguana_bundlespeculate(coin,bp,bundlei,hash2,1);
        }
        prevbp = 0, prevbundlei = -2;
        iguana_bundlefind(coin,&prevbp,&prevbundlei,prevhash2);
        //if ( 0 && block->blockhashes != 0 )
        //    fprintf(stderr,"has blockhashes bp.%p[%d] prevbp.%p[%d]\n",bp,bundlei,prevbp,prevbundlei);
        if ( prevbp != 0 && prevbundlei >= 0 && (prevblock= iguana_blockfind("bundleset2",coin,prevhash2)) != 0 )
        {
            if ( prevbundlei < coin->chain->bundlesize )
            {
                if ( prevbp->hdrsi+1 == coin->bundlescount && prevbundlei == coin->chain->bundlesize-1 )
                {
                    printf("AUTOCREATE.%d\n",prevbp->bundleheight + coin->chain->bundlesize);
                    if ( (bp= iguana_bundlecreate(coin,bundleip,prevbp->bundleheight + coin->chain->bundlesize,hash2,zero,0)) != 0 )
                    {
                        if ( bp->queued == 0 )
                            iguana_bundleQ(coin,bp,1000);
                    }
                }
                if ( prevbundlei < coin->chain->bundlesize-1 )
                {
                    //printf("bundlehash2add next %d\n",prevbundlei);
                    iguana_bundlehash2add(coin,0,prevbp,prevbundlei+1,hash2);
                }
                if ( 1 && strcmp("BTC",coin->symbol) != 0 )
                    iguana_bundlespeculate(coin,prevbp,prevbundlei,prevhash2,2);
            }
        }
    } else printf("iguana_bundleset: error adding blockhash\n");
    bp = 0, *bundleip = -2;
    return(iguana_bundlefind(coin,&bp,bundleip,hash2));
}

void iguana_checklongestchain(struct iguana_info *coin,struct iguana_bundle *bp,int32_t num)
{
    int32_t i; struct iguana_peer *addr;
    if ( num > 3 && num < bp->n )
    {
        if ( coin->longestchain > bp->bundleheight+num+10*coin->chain->minconfirms )
        {
            printf("strange.%d suspicious longestchain.%d vs [%d:%d] %d bp->n %d\n",coin->longestchain_strange,coin->longestchain,bp->hdrsi,num,bp->bundleheight+num,bp->n);
            if ( coin->longestchain_strange++ > 10 )
            {
                coin->badlongestchain = coin->longestchain;
                coin->longestchain = bp->bundleheight+num;
                coin->longestchain_strange = 0;
                for (i=0; i<coin->peers->numranked; i++)
                    if ( (addr= coin->peers->ranked[i]) != 0 && addr->height >= coin->badlongestchain )
                    {
                        printf("blacklist addr.(%s) height %d\n",addr->ipaddr,addr->height);
                        addr->dead = 1;
                        addr->rank = 0;
                    }
            }
        }
        else if ( coin->longestchain_strange > 0 )
        {
            printf("not strange.%d suspicious longestchain.%d vs [%d:%d] %d bp->n %d\n",coin->longestchain_strange,coin->longestchain,bp->hdrsi,num,bp->bundleheight+num,bp->n);
            coin->longestchain_strange--;
        }
    }
}

struct iguana_bundlereq *iguana_recvblockhdrs(struct iguana_info *coin,struct iguana_bundlereq *req,struct iguana_zblock *zblocks,int32_t n,int32_t *newhwmp)
{
    int32_t i,bundlei,match; struct iguana_block *block; bits256 prevhash2; uint8_t serialized[sizeof(struct iguana_msgblock) + sizeof(struct iguana_msgblockhdr_zcash)]; struct iguana_peer *addr; struct iguana_bundle *bp,*firstbp = 0;
    if ( zblocks == 0 )
    {
        printf("iguana_recvblockhdrs null blocks?\n");
        return(req);
    }
    if ( zblocks != 0 && n > 0 )
    {
        memset(prevhash2.bytes,0,sizeof(prevhash2));
        for (i=match=0; i<n; i++)
        {
            //fprintf(stderr,"i.%d of %d bundleset\n",i,n);
            if ( bits256_cmp(zblocks[i].RO.prev_block,coin->blocks.hwmchain.RO.hash2) == 0 )
            {
                bp = 0, bundlei = -2;
                if ( (bp= iguana_bundleset(coin,&block,&bundlei,(struct iguana_block *)&zblocks[i])) != 0 )
                {
                    if ( block->height >= 0 && block->height+1 > coin->longestchain )
                        coin->longestchain = block->height+1;
                    _iguana_chainlink(coin,block);
                }
                //char str[65]; printf("HWM in hdr's prev[%d] bp.%p bundlei.%d block.%p %s\n",i,bp,bundlei,block,bp!=0?bits256_str(str,bp->hashes[bundlei]):"()");
            }
            if ( i > 0 && bits256_cmp(prevhash2,zblocks[i].RO.prev_block) == 0 )
            {
                bp = 0, bundlei = -2;
                if ( (bp= iguana_bundleset(coin,&block,&bundlei,(struct iguana_block *)&zblocks[i])) != 0 )
                {
                    bp->dirty++;
                    if ( 0 && bp->issued[bundlei] == 0 && bp->hdrsi < coin->MAXBUNDLES )
                        iguana_blockQ("recvhdr",coin,bp,bundlei,block->RO.hash2,1);
                    //printf("{%d:%d} ",bp->hdrsi,bundlei);
                    if ( i == 0 )
                    {
                        firstbp = bp;
                        iguana_checklongestchain(coin,bp,n);
                    }
                    if ( bundlei == i+1 && bp == firstbp )
                        match++;
                    else
                    {
                        if ( 0 && bp != coin->current && i != n-1 )
                            fprintf(stderr,"recvhdr: ht.%d[%d] vs i.%d\n",bp->bundleheight,bundlei,i);
                    }
                }
            }
            prevhash2 = zblocks[i].RO.hash2;
            //printf("%d bp.%p [%d] bundlei.%d %s prev.%s\n",i,bp,bp!=0?bp->hdrsi:-1,bundlei,bits256_str(str,zblocks[i].RO.hash2),bits256_str(str2,zblocks[i].RO.prev_block));
            //else if ( bp != firstbp )
            //    printf("blockhash[%d] cant be found n.%d\n",i,n);
        }
        char str[65];
        if ( 0 && bp == coin->current )
            printf("i.%d n.%d match.%d blockhdrs.%s hdrsi.%d\n",i,n,match,bits256_str(str,zblocks[0].RO.hash2),firstbp!=0?firstbp->hdrsi:-1);
        if ( firstbp != 0 && match == coin->chain->bundlesize-1 && n == firstbp->n )
        {
            if ( firstbp->queued == 0 )
            {
                //fprintf(stderr,"firstbp blockQ %d\n",firstbp->bundleheight);
                iguana_bundleQ(coin,firstbp,1000);
            }
        }
        if ( i == n && i == match && firstbp == coin->current && (addr= req->addr) != 0 )
        {
            addr->RThashes[i] = firstbp->hashes[0];
            for (i=1; i<n; i++)
            {
                iguana_serialize_block(coin->chain,&addr->RThashes[i],serialized,(struct iguana_block *)&zblocks[i]);
            }
            //memcpy(addr->RThashes,blockhashes,bp->numspec * sizeof(*addr->RThashes));
            addr->numRThashes = n;
        }
    }
    return(req);
}

void iguana_autoextend(struct iguana_info *coin,struct iguana_bundle *bp)
{
    char hashstr[65]; struct iguana_bundle *newbp; int32_t bundlei; static const bits256 zero;
    if ( bp->hdrsi == coin->bundlescount-1 && bits256_nonz(bp->nextbundlehash2) != 0 )
    {
        init_hexbytes_noT(hashstr,bp->nextbundlehash2.bytes,sizeof(bits256));
        newbp = 0, bundlei = -2;
        if ( iguana_bundlefind(coin,&newbp,&bundlei,bp->nextbundlehash2) != 0 )
        {
            if ( newbp->bundleheight != bp->bundleheight+bp->n )
            {
                printf("found spurious extra hash for [%d:%d]\n",bp->hdrsi,bp->n);
                memset(&bp->nextbundlehash2,0,sizeof(bp->nextbundlehash2));
                return;
            }
        }
        newbp = iguana_bundlecreate(coin,&bundlei,bp->bundleheight+coin->chain->bundlesize,bp->nextbundlehash2,zero,1);
        if ( newbp != 0 )
        {
            if ( newbp->speculative == 0 )
                queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
            //char str[65],str2[65]; printf("EXTEND last bundle %s/%s ht.%d\n",bits256_str(str,newbp->hashes[0]),bits256_str(str2,bp->nextbundlehash2),newbp->bundleheight);
            if ( newbp->queued == 0 )
                iguana_bundleQ(coin,newbp,1000);
        }
    }
}

struct iguana_bundlereq *iguana_recvblockhashes(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *blockhashes,int32_t num)
{
    int32_t bundlei,i,starti; struct iguana_block *prevblock; struct iguana_bundle *bp; bits256 allhash,zero; struct iguana_peer *addr; struct iguana_block *block; char str[65],str2[65]; // uint8_t serialized[512];
    memset(zero.bytes,0,sizeof(zero));
    bp = 0, bundlei = -2;
    iguana_bundlefind(coin,&bp,&bundlei,blockhashes[1]);
    if ( strcmp("BTCD",coin->symbol) == 0 )//0 && num >= coin->chain->bundlesize )
        printf("blockhashes[%d] %d of %d %s bp.%d[%d]\n",num,bp==0?-1:bp->hdrsi,coin->bundlescount,bits256_str(str,blockhashes[1]),bp==0?-1:bp->bundleheight,bundlei);
    if ( num < 2 )
        return(req);
    else
    {
        for (i=1; i<num; i++)
            if ( (prevblock= iguana_blockfind("prev",coin,blockhashes[i])) != 0 && prevblock->height+1 > coin->longestchain )
            {
                coin->longestchain = prevblock->height+1;
                if ( bp->speculative != 0 && i < bp->n )
                    bp->speculative[i] = blockhashes[i];
            }
    }
    if ( bp != 0 )
    {
        bp->dirty++;
        bp->hdrtime = (uint32_t)time(NULL);
        blockhashes[0] = bp->hashes[0];
        //iguana_blockQ("recvhash0",coin,bp,0,blockhashes[0],1);
        if ( num >= coin->chain->bundlesize )
        {
            if ( bits256_nonz(bp->nextbundlehash2) == 0 && num > coin->chain->bundlesize )
            {
                bp->nextbundlehash2 = blockhashes[coin->chain->bundlesize];
                iguana_blockQ("recvhash1",coin,0,-1,bp->nextbundlehash2,1);
            }
            //printf("call allhashes\n");
            if ( 0 && bp->hdrsi == coin->bundlescount-1 )
                iguana_autoextend(coin,bp);
            if ( iguana_allhashcmp(coin,bp,blockhashes,num) > 0 )
                return(req);
            //printf("done allhashes\n");
        }
        else if ( bp->hdrsi == coin->bundlescount-1 )
        {
            iguana_checklongestchain(coin,bp,num);
            if ( bp->speculative != 0 && bp->numspec < num )
            {
                for (i=bp->numspec; i<num; i++)
                {
                    if ( bits256_nonz(bp->speculative[i]) == 0 )
                        bp->speculative[i] = blockhashes[i];
                }
            }
        }
        if ( strcmp("BTC",coin->symbol) != 0 && (bp->speculative == 0 || num > bp->numspec) && bp->emitfinish == 0 )
        {
            //printf("FOUND speculative.%s BLOCKHASHES[%d] ht.%d\n",bits256_str(str,blockhashes[1]),num,bp->bundleheight);
            if ( bp->speculative == 0 )
            {
                bp->speculative = mycalloc('s',bp->n+1,sizeof(*bp->speculative));
                for (i=0; i<bp->n; i++)
                    if ( GETBIT(bp->haveblock,i) == 0 )
                        bp->issued[i] = 0;
                iguana_bundleissuemissing(coin,bp,3,1.);
            }
            for (i=1; i<num&&i<=bp->n; i++)
            {
                bp->speculative[i] = blockhashes[i];
                //if ( bp->blocks[i] == 0 || bp->blocks[i]->issued == 0 )
                //    iguana_blockQ("speculate",coin,bp,-i,blockhashes[i],0);
                if ( bp->blocks[i] == 0 )
                    bp->blocks[i] = iguana_blockhashset("recvhashes3",coin,bp->bundleheight+i,blockhashes[i],1);
                //printf("speculate new issue [%d:%d]\n",bp->hdrsi,i);
            }
            bp->speculative[0] = bp->hashes[0];
            bp->numspec = (num <= bp->n+1) ? num : bp->n+1;
            if ( bp == coin->current && (addr= req->addr) != 0 )
            {
                memcpy(addr->RThashes,blockhashes,bp->numspec * sizeof(*addr->RThashes));
                addr->numRThashes = bp->numspec;
            }
            //iguana_blockQ(coin,0,-1,blockhashes[2],1);
        }
    }
    else if ( num >= coin->chain->bundlesize )
    {
        starti = coin->current != 0 ? coin->current->hdrsi : 0;
        for (i=coin->bundlescount-1; i>=starti; i--)
        {
            if ( (bp= coin->bundles[i]) != 0 )//&& bp->emitfinish > 1 )
            {
                blockhashes[0] = bp->hashes[0];
                vcalc_sha256(0,allhash.bytes,blockhashes[0].bytes,coin->chain->bundlesize * sizeof(*blockhashes));
                if ( 0 && i == starti )
                    printf("vcalc.(%s) [%d].(%s)\n",bits256_str(str,allhash),bp->hdrsi,bits256_str(str2,bp->hashes[0]));
                if ( bits256_cmp(allhash,bp->allhash) == 0 )
                {
                    if ( 0 && bp->speculative == 0 )
                        printf("matched allhashes.[%d]\n",bp->hdrsi);
                    if ( bp->queued != 0 )
                        bp->queued = 0;
                    if ( iguana_allhashcmp(coin,bp,blockhashes,coin->chain->bundlesize) > 0 )
                    {
                        bp->hdrtime = (uint32_t)time(NULL);
                        //iguana_blockQ("recvhash2",coin,bp,1,blockhashes[1],1);
                        //iguana_blockQ("recvhash3",coin,bp,0,blockhashes[0],1);
                        //iguana_blockQ("recvhash4",coin,bp,coin->chain->bundlesize-1,blockhashes[coin->chain->bundlesize-1],0);
                        //printf("matched bundle.%d\n",bp->bundleheight);
                        return(req);
                    } else printf("unexpected mismatch??\n");
                }
            }
        }
        //printf("%s.[%d] no match to allhashes\n",bits256_str(str,blockhashes[1]),num);
        struct iguana_block *block;
        if ( (block= iguana_blockhashset("recvhashes",coin,-1,blockhashes[1],1)) != 0 )
        {
            //block->blockhashes = blockhashes, req->hashes = 0;
            //printf("set block->blockhashes[%d]\n",num);
        }
        /*if ( (addr= coin->peers->ranked[0]) != 0 )
        {
            if ( (len= iguana_getdata(coin,serialized,MSG_BLOCK,&blockhashes[1],1)) > 0 )
            {
                iguana_send(coin,addr,serialized,len);
                //char str[65]; printf("REQ.%s\n",bits256_str(str,blockhashes[1]));
            }
        }*/
        iguana_blockQ("hdr1",coin,0,-1,blockhashes[1],1);
    }
    else
    {
        if ( (block= iguana_blockfind("recvhashes2",coin,blockhashes[1])) == 0 )
        {
            iguana_blockhashset("recvhashes3",coin,-1,blockhashes[1],1);
            if ( (block= iguana_blockfind("recvhashes4",coin,blockhashes[1])) != 0 )
                iguana_blockQ("recvhash6",coin,0,-6,blockhashes[1],1); // should be RT block
        }
        if ( block != 0 )
            block->newtx = 1;
        iguana_blockQ("RTblock",coin,0,-7,blockhashes[1],1); // should be RT block
    }
    if ( strcmp("BTC",coin->symbol) != 0 )
    {
        iguana_blockQ("recvhash7",coin,0,-7,blockhashes[1],1);
        iguana_blockQ("recvhash7",coin,0,-7,blockhashes[num-1],1);
    }
    return(req);
}

struct iguana_bundlereq *iguana_recvblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundlereq *req,struct iguana_zblock *origblock,int32_t numtx,int32_t datalen,int32_t recvlen,int32_t *newhwmp)
{
    struct iguana_bundle *bp=0,*prev; int32_t n,bundlei = -2; struct iguana_block *block,*next,*prevblock; char str[65]; bits256 hash2;
    //printf("received.%s\n",bits256_str(str,origblock->RO.hash2));
    if ( bits256_nonz(origblock->RO.prev_block) != 0 )
    {
        if ( (prevblock= iguana_blockfind("prev",coin,origblock->RO.prev_block)) != 0 && prevblock->height+1 > coin->longestchain )
            coin->longestchain = prevblock->height+1;
        else iguana_blockQ("prev",coin,0,-1,origblock->RO.prev_block,1);
    }
    if ( (bp= iguana_bundleset(coin,&block,&bundlei,(struct iguana_block *)origblock)) != 0 && bp == coin->current && block != 0 && bp->speculative != 0 && bundlei >= 0 )
    {
        if ( bp->speculative != 0 && bp->numspec <= bundlei )
        {
            bp->speculative[bundlei] = block->RO.hash2;
            bp->numspec = bundlei+1;
        }
        while ( bundlei < bp->n && block != 0 && bp->bundleheight+bundlei == coin->blocks.hwmchain.height+1 && _iguana_chainlink(coin,block) != 0 )
        {
            //printf("MAIN.%d ",bp->bundleheight+bundlei);
            bundlei++;
            block = iguana_bundleblock(coin,&hash2,bp,bundlei);
        }
        //printf("autoadd [%d:%d]\n",bp->hdrsi,bundlei);
    } // else printf("couldnt find.(%s)\n",bits256_str(str,block->RO.hash2));
    if ( bp != 0 )
    {
        bp->dirty++;
        if ( block != 0 && block->mainchain != 0 && bundlei == 0 && bp->hdrsi > 0 )
        {
            if ( (prev= coin->bundles[bp->hdrsi - 1]) != 0 )
            {
                //printf("found adjacent [%d:%d] speculative.%p\n",prev->hdrsi,bp->n-1,prev->speculative);
            }
        }
    }
    else if ( req->copyflag != 0 )
    {
        if ( bp == 0 && (block == 0 || block->queued == 0))
        {
            //fprintf(stderr,"req.%p copyflag.%d data %d %d\n",req,req->copyflag,req->recvlen,recvlen);
            coin->numcached++;
            if ( block != 0 )
                block->queued = 1;
            queue_enqueue("cacheQ",&coin->cacheQ,&req->DL,0);
            return(0);
        }
        else if ( block != 0 && block->req == 0 )
        {
            block->req = req;
            req = 0;
        } //else printf("already have cache entry.(%s)\n",bits256_str(str,origblock->RO.hash2));
    }
    if ( block != 0 )//&& bp != 0 && bp->hdrsi == coin->bundlescount-1 )
    {
        int32_t i,numsaved = 0; struct iguana_block *tmpblock; static int32_t numrecv;
        numrecv++;
        if ( bp != 0 )
        {
            for (i=numsaved=0; i<bp->n; i++)
                if ( (tmpblock= bp->blocks[i]) != 0 && tmpblock->fpipbits != 0 && tmpblock->fpos >= 0 && ((bp->hdrsi == 0 && i == 0) || bits256_nonz(tmpblock->RO.prev_block) != 0) )
                    numsaved++;
        }
        //fprintf(stderr,"%s [%d:%d] block.%x | s.%d r.%d copy.%d mainchain.%d\n",bits256_str(str,origblock->RO.hash2),bp!=0?bp->hdrsi:-1,bundlei,block!=0?block->fpipbits:0,numsaved,numrecv,req->copyflag,block->mainchain);
        if ( _iguana_chainlink(coin,block) == 0 )
        {
            next = block;
            for (i=n=0; i<coin->chain->bundlesize && n == 0; i++)
            {
                if ( (block= iguana_blockfind("recvblock",coin,block->RO.prev_block)) == 0 )
                    break;
                if ( block->mainchain != 0 || _iguana_chainlink(coin,block) != 0 )
                {
                    _iguana_chainlink(coin,next);
                    n++;
                    break;
                }
                next = block;
            }
        } // else printf("RECV MAINCHAIN.%d\n",coin->blocks.hwmchain.height);
    }
    if ( 0 && bundlei == 1 && bp != 0 && bp->numhashes < bp->n && strcmp("BTC",coin->symbol) != 0 && bp->speculative == 0 && bp == coin->current )
    {
        printf("reissue hdrs request for [%d]\n",bp->hdrsi);
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(bits256_str(str,bp->hashes[0])),1);
    }
    if ( (block= iguana_blockhashset("recvblock",coin,-1,origblock->RO.hash2,1)) != 0 )
    {
        if ( block != (struct iguana_block *)origblock )
            iguana_blockcopy(coin->chain->zcash,coin->chain->auxpow,coin,block,(struct iguana_block *)origblock);
        if ( block->lag != 0 && block->issued != 0 )
            block->lag = (uint32_t)time(NULL) - block->issued;
        //printf("datalen.%d ipbits.%x\n",datalen,req->ipbits);
    } else printf("cant create origblock.%p block.%p bp.%p bundlei.%d\n",origblock,block,bp,bundlei);
    return(req);
}

struct iguana_bundlereq *iguana_recvtxids(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *txids,int32_t n)
{
    int32_t i;
    if ( n > 0 )
    {
        for (i=0; i<n; i++)
            iguana_txidreport(coin,txids[i],req->addr);
    }
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

int32_t iguana_blockreq(struct iguana_info *coin,int32_t height,int32_t priority)
{
    int32_t hdrsi,bundlei; struct iguana_bundle *bp;
    hdrsi = height / coin->chain->bundlesize;
    bundlei = height % coin->chain->bundlesize;
    if ( (bp= coin->bundles[hdrsi]) != 0 && bits256_nonz(bp->hashes[bundlei]) != 0 )
    {
        iguana_blockQ("blockreq",coin,bp,bundlei,bp->hashes[bundlei],priority);
        return(height);
    }
    return(-1);
}

int32_t iguana_reqblocks(struct iguana_info *coin)
{
    int32_t hdrsi,lflag,bundlei,iters=0,flag = 0; bits256 hash2; struct iguana_block *next,*block; struct iguana_bundle *bp;
    if ( time(NULL) < coin->lastreqtime+2 )
        return(0);
    coin->lastreqtime = (uint32_t)time(NULL);
    //printf("reqblocks %u\n",coin->lastreqtime);
    hdrsi = (coin->blocks.hwmchain.height+1) / coin->chain->bundlesize;
    if ( (bp= coin->bundles[hdrsi]) != 0 )
    {
        for (bundlei=0; bundlei<coin->chain->bundlesize; bundlei++)
            if ( (block= bp->blocks[bundlei]) != 0 && bits256_cmp(block->RO.hash2,bp->hashes[bundlei]) != 0 && bits256_nonz(bp->hashes[bundlei]) != 0 )
            {
                char str[65]; printf("%s [%d] bundlei.%d ht.%d vs expected %d\n",bits256_str(str,bp->hashes[bundlei]),hdrsi,bundlei,block->height,bp->bundleheight+bundlei);
                bp->blocks[bundlei] = iguana_blockfind("fixit",coin,bp->hashes[bundlei]);
            }
        bundlei = (coin->blocks.hwmchain.height+1) % coin->chain->bundlesize;
        if ( (next= bp->blocks[bundlei]) != 0 || (next= iguana_blockfind("reqblocks",coin,bp->hashes[bundlei])) != 0 )
        {
            if ( bits256_nonz(next->RO.prev_block) > 0 )
                _iguana_chainlink(coin,next);
            else if ( next->queued == 0 && next->fpipbits == 0 && (rand() % 100) == 0 )
            {
                //printf("HWM next %d\n",coin->blocks.hwmchain.height+1);
                iguana_blockQ("reqblocks",coin,bp,bundlei,next->RO.hash2,1);
            }
        }
    }
    lflag = 1;
    while ( coin->active != 0 && iters < coin->longestchain/3+1 )
    {
        iters++;
        lflag = 0;
        hdrsi = (coin->blocks.hwmchain.height+1) / coin->chain->bundlesize;
        bundlei = (coin->blocks.hwmchain.height+1) % coin->chain->bundlesize;
        if ( 1 )
        {
            int32_t hdrsi0,bundlei0;
            if ( (next= iguana_bundleblock(coin,&hash2,coin->bundles[hdrsi],bundlei)) == 0 )
            {
                hdrsi0 = (coin->blocks.hwmchain.height) / coin->chain->bundlesize;
                bundlei0 = (coin->blocks.hwmchain.height) % coin->chain->bundlesize;
                if ( coin->bundles[hdrsi0] != 0 && (block= iguana_bundleblock(coin,&hash2,coin->bundles[hdrsi0],bundlei0)) != 0 )
                    next = block->hh.next; //, next/block->mainchain = 1;
            }
        }
        else
        {
            if ( (next= iguana_blockfind("reqloop",coin,iguana_blockhash(coin,coin->blocks.hwmchain.height+1))) == 0 )
            {
            }
        }
        if ( next == 0 && hdrsi < coin->bundlescount && (bp= coin->bundles[hdrsi]) != 0 && (next= bp->blocks[bundlei]) != 0 )
        {
            if ( bits256_nonz(next->RO.prev_block) == 0 )
            {
                printf(" next has null prev [%d:%d]\n",bp->hdrsi,bundlei);
                iguana_blockQ("reqblocks0",coin,bp,bundlei,next->RO.hash2,1);
                next = 0;
            }
        }
        if ( next != 0 )//&& time(NULL) > coin->nextchecked+10 )
        {
            //printf("have next %d\n",coin->blocks.hwmchain.height);
            if ( memcmp(next->RO.prev_block.bytes,coin->blocks.hwmchain.RO.hash2.bytes,sizeof(bits256)) == 0 )
            {
                coin->nextchecked = (uint32_t)time(NULL);
                if ( _iguana_chainlink(coin,next) != 0 )
                    lflag++, flag++;
                //else printf("chainlink error for %d\n",coin->blocks.hwmchain.height+1);
            }
        }
        if ( 1 )//queue_size(&coin->blocksQ) < _IGUANA_MAXPENDING )
        {
            double threshold,lag = OS_milliseconds() - coin->backstopmillis;
            bp = coin->bundles[(coin->blocks.hwmchain.height+1)/coin->chain->bundlesize];
            if ( bp != 0 && bp->durationscount != 0 )
                threshold = (double)bp->totaldurations / bp->durationscount;
            else
            {
                if ( coin->blocks.hwmchain.height >= coin->longestchain-1 )
                    threshold = 10000;
                else threshold = 5000;
                if ( strcmp(coin->symbol,"BTC") == 0 )
                    threshold *= 3;
            }
            if ( threshold < 1500 )
                threshold = 1500;
            if ( coin->blocks.hwmchain.height < coin->longestchain && ((strcmp(coin->symbol,"BTC") != 0 && coin->backstop != coin->blocks.hwmchain.height+1) || lag > threshold) )
            {
                coin->backstop = coin->blocks.hwmchain.height+1;
                hash2 = iguana_blockhash(coin,coin->backstop);
                bundlei = (coin->blocks.hwmchain.height+1) % coin->chain->bundlesize;
                if ( bp != 0 && bits256_nonz(hash2) == 0 )
                {
                    hash2 = bp->hashes[bundlei];
                    if ( bits256_nonz(hash2) == 0 && bp->speculative != 0 )
                    {
                        hash2 = bp->speculative[bundlei];
                        if ( bits256_nonz(hash2) > 0 )
                        {
                            if ( (block= iguana_blockfind("reqblocks",coin,hash2)) != 0 && bits256_cmp(block->RO.prev_block,coin->blocks.hwmchain.RO.hash2) == 0 )
                            {
                                //printf("speculative is next at %d\n",coin->backstop);
                                if ( _iguana_chainlink(coin,block) != 0 )
                                    lflag++, flag++;//, printf("NEWHWM.%d\n",coin->backstop);
                            }
                        }
                    }
                }
                if ( bits256_nonz(hash2) > 0 ) //strcmp("BTC",coin->symbol) == 0 &&
                {
                    coin->backstopmillis = OS_milliseconds();
                    iguana_blockQ("mainchain",coin,0,-1,hash2,1);//lag > threshold);
                    flag++;
                    char str[65];
                    if ( 1 && (rand() % 100000) == 0 )//|| bp->bundleheight > coin->longestchain-coin->chain->bundlesize )
                        printf("%s %s MAIN.%d t %.3f lag %.3f\n",coin->symbol,bits256_str(str,hash2),coin->blocks.hwmchain.height+1,threshold,lag);
                }
                if ( 0 && bp != 0 && bundlei < bp->n-1 && (bits256_nonz(bp->hashes[bundlei+1]) != 0 || (bp->speculative != 0 && bits256_nonz(bp->speculative[bundlei+1]) != 0)) )
                {
                    int32_t j;
                    //memset(bp->hashes[bundlei].bytes,0,sizeof(bp->hashes[bundlei]));
                    //bp->blocks[bundlei] = 0;
                    for (j=0; j<1&&bundlei+j+1<bp->n; j++)
                    {
                        if ( time(NULL) > bp->issued[bundlei+1+j]+10 )
                        {
                            bp->issued[bundlei+1+j] = (uint32_t)time(NULL);
                            printf("MAINCHAIN skip issue %d\n",bp->bundleheight+bundlei+1+j);
                            if ( bits256_nonz(bp->hashes[bundlei+1+j]) != 0 )
                                iguana_blockQ("mainskip",coin,bp,bundlei+1+j,bp->hashes[bundlei+1+j],1);
                            else if ( bp->speculative != 0 && bundlei+1+j < bp->numspec )
                                iguana_blockQ("mainskip",coin,bp,bundlei+1+j,bp->speculative[bundlei+1+j],1);
                        }
                    }
                }
            }
        }
    }
    return(flag);
}

int32_t iguana_processrecvQ(struct iguana_info *coin,int32_t *newhwmp) // single threaded
{
    int32_t flag = 0; struct iguana_bundlereq *req;
    *newhwmp = 0;
    while ( flag < IGUANA_MAXITERATIONS && coin->active != 0 && (req= queue_dequeue(&coin->recvQ,0)) != 0 )
    {
        flag++;
        //fprintf(stderr,"flag.%d %s recvQ.%p type.%c n.%d\n",flag,req->addr != 0 ? req->addr->ipaddr : "0",req,req->type,req->n);
        if ( req->type == 'B' ) // one block with all txdata
        {
            netBLOCKS--;
            req = iguana_recvblock(coin,req->addr,req,&req->zblock,req->numtx,req->datalen,req->recvlen,newhwmp);
        }
        else if ( req->type == 'H' ) // blockhdrs (doesnt have txn_count!)
        {
            HDRnet--;
            if ( (req= iguana_recvblockhdrs(coin,req,req->blocks,req->n,newhwmp)) != 0 )
            {
                if ( req->blocks != 0 )
                    myfree(req->blocks,sizeof(struct iguana_zblock) * req->n), req->blocks = 0;
            }
        }
        else if ( req->type == 'S' ) // blockhashes
        {
            if ( (req= iguana_recvblockhashes(coin,req,req->hashes,req->n)) != 0 && req->hashes != 0 )
                myfree(req->hashes,sizeof(*req->hashes) * req->n), req->hashes = 0;
        }
        else if ( req->type == 'U' ) // unconfirmed tx
            req = iguana_recvunconfirmed(coin,req,req->serializeddata,req->datalen);
        else if ( req->type == 'T' ) // txids from inv
        {
            if ( (req= iguana_recvtxids(coin,req,req->hashes,req->n)) != 0 )
                myfree(req->hashes,(req->n+1) * sizeof(*req->hashes)), req->hashes = 0;
        }
        /*else if ( req->type == 'Q' ) // quotes from inv
        {
            if ( (req= instantdex_recvquotes(coin,req,req->hashes,req->n)) != 0 )
                myfree(req->hashes,(req->n+1) * sizeof(*req->hashes)), req->hashes = 0;
        }*/
        else printf("iguana_updatebundles unknown type.%c\n",req->type);//, getchar();
        //fprintf(stderr,"finished coin->recvQ\n");
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
    if ( queue_size(&coin->hdrsQ) == 0 )
    {
        if ( coin->active != 0 )
        {
            for (i=0; i<coin->bundlescount; i++)
            {
                if ( (bp= coin->bundles[i]) != 0 && (bp == coin->current || bp->hdrsi == coin->longestchain/coin->chain->bundlesize || i == coin->bundlescount-1 || (bp->numhashes < bp->n && bp->speculative == 0)) )
                {
                    if ( bp == coin->current )
                        lag = 7;
                    else lag = 13;
                    if ( time(NULL) > bp->issuetime+lag )
                    {
                        if ( 0 && bp == coin->current )
                            printf("LAG.%ld hdrsi.%d numhashes.%d:%d needhdrs.%d qsize.%d zcount.%d\n",time(NULL)-bp->hdrtime,i,bp->numhashes,bp->n,iguana_needhdrs(coin),queue_size(&coin->hdrsQ),coin->zcount);
                        if ( bp->issuetime == 0 )
                            coin->numpendings++;
                        init_hexbytes_noT(hashstr,bp->hashes[0].bytes,sizeof(bits256));
                        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
                        //printf("hdrsi.%d reqHDR.(%s) numhashes.%d\n",bp->hdrsi,hashstr,bp->numhashes);
                        if ( 1 )
                        {
                            iguana_blockQ("reqhdrs0",coin,bp,0,bp->hashes[0],1);
                            if ( bits256_nonz(bp->hashes[1]) > 0 )
                                iguana_blockQ("reqhdrs1",coin,bp,1,bp->hashes[1],1);
                        }
                        n++;
                        bp->hdrtime = bp->issuetime = (uint32_t)time(NULL);
                    }
                }
            }
            if ( 0 && n > 0 )
                printf("REQ HDRS pending.%d\n",n);
            coin->zcount = 0;
        }
    } //else coin->zcount = 0;
    return(n);
}

int32_t iguana_blockQ(char *argstr,struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t priority)
{
    queue_t *Q; char *str; uint32_t now; int32_t n,height = -1; struct iguana_blockreq *req,*ptr; struct iguana_block *block = 0;
    if ( bits256_nonz(hash2) == 0 )
    {
        printf("%s.cant queue zerohash bundlei.%d\n",argstr,bundlei);
        //getchar();
        return(-1);
    }
    if ( 1 && coin->enableCACHE != 0 && iguana_speculativesearch(coin,&block,hash2) != 0 && block != 0 && block->txvalid != 0 )
    {
        //printf("found valid [%d:%d] in blockQ\n",block!=0?block->hdrsi:-1,block!=0?block->bundlei:-1);
        return(0);
    }
  //lag = (priority == 0) ? IGUANA_DEFAULTLAG*3 : IGUANA_DEFAULTLAG;
    now = (uint32_t)time(NULL);
    block = iguana_blockfind("blockQ",coin,hash2);
    if ( priority != 0 || block == 0 )//|| iguana_blockstatus(coin,block) == 0 )
    {
        if ( bp != 0 )
        {
            if (  bits256_cmp(coin->APIblockhash,hash2) != 0 && bp->emitfinish != 0 )
                return(0);
            //if ( now < bp->issued[bundlei]+lag )
            //    return(0);
            if ( bundlei >= 0 && bundlei < bp->n )
            {
                if ( block == 0 )
                    block = bp->blocks[bundlei];
                height = bp->bundleheight + bundlei;
            }
            else
            {
                if ( priority == 0 && -bundlei >= 0 && -bundlei < bp->n && bp->speculative != 0 )
                {
                    if ( bp->speculativecache[-bundlei] != 0 )
                        return(0);
                }
                bp = 0;
                bundlei = -1;
            }
        }
        if ( block != 0 )
        {
            if ( bits256_cmp(coin->APIblockhash,hash2) != 0 && (block->fpipbits != 0 || block->req != 0 || block->queued != 0) )
            {
                if ( block->fpipbits == 0 && block->queued == 0 && block->req != 0 )
                {
                    block->queued = 1;
                    queue_enqueue("cacheQ",&coin->cacheQ,&block->req->DL,0);
                    block->req = 0;
                    //char str2[65]; printf("already have.(%s)\n",bits256_str(str2,block->RO.hash2));
                }
                return(0);
            }
            if ( block->queued != 0 || block->txvalid != 0 )//|| now < block->issued+lag )
                return(0);
            height = block->height;
        }
        if ( bp != 0 && bp->emitfinish != 0 )
            return(0);
        if ( priority != 0 )
            str = "priorityQ", Q = &coin->priorityQ;
        else str = "blocksQ", Q = &coin->blocksQ;
        if ( Q != 0 )
        {
            req = mycalloc('y',1,sizeof(*req));
            req->hash2 = hash2;
            if ( (req->bp= bp) != 0 && bundlei >= 0 )
            {
                height = bp->bundleheight + bundlei;
                bp->issued[bundlei] = 1;
            }
            req->height = height;
            req->bundlei = bundlei;
            char str2[65];
            //printf("%s %s %s [%d:%d] %d %s %d numranked.%d qsize.%d\n",coin->symbol,argstr,str,bp!=0?bp->hdrsi:-1,bundlei,req->height,bits256_str(str2,hash2),coin->blocks.recvblocks,coin->peers->numranked,queue_size(Q));
            if ( (n= queue_size(Q)) > 100000 )
            {
                if ( 1 && n > 200000 )
                    printf("%s %s %s [%d:%d] %d %s %d numranked.%d qsize.%d\n",coin->symbol,argstr,str,bp!=0?bp->hdrsi:-1,bundlei,req->height,bits256_str(str2,hash2),coin->blocks.recvblocks,coin->peers->numranked,queue_size(Q));
                while ( (ptr= queue_dequeue(Q,0)) != 0 )
                    myfree(ptr,sizeof(*ptr));
                coin->backlog = n*10 + 1000000;
            } else coin->backlog >>= 1;
            if ( block != 0 )
            {
                //block->numrequests++;
                block->issued = now;
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
    struct iguana_block *block; struct iguana_blockreq *req=0; char *hashstr=0; bits256 hash2;
    int32_t bundlei,priority,i,m,z,pend,limit,height=-1,datalen,flag = 0;
    uint32_t now; struct iguana_bundle *bp; struct iguana_peer *ptr;
    if ( addr->msgcounts.verack == 0 )
        return(0);
    //if ( netBLOCKS > IGUANA_NUMHELPERS*1000 )
    //    usleep(netBLOCKS);
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
                    if ( bp != 0 )
                    {
                        if ( bp->bundleheight+coin->chain->bundlesize < coin->longestchain )
                        {
                            m = (coin->longestchain - bp->bundleheight);
                            if ( bp->numhashes < m )
                                z = 1;
                        }
                        else if ( bp->numhashes < bp->n )
                            z = 1;
                    }
                    if ( bp == 0 || bp->speculative == 0 || bp == coin->current || bp->hdrsi == coin->bundlescount-1 || bp->numhashes < bp->n )
                    {
                        if ( 0 && bp == coin->current )
                            printf("%s request HDR.(%s) numhashes.%d [%d]\n",addr!=0?addr->ipaddr:"local",hashstr,bp!=0?bp->numhashes:0,bp!=0?bp->hdrsi:-1);
                        iguana_send(coin,addr,serialized,datalen);
                        addr->pendhdrs++;
                        flag++;
                    } //else printf("skip hdrreq.%s m.%d z.%d bp.%p longest.%d queued.%d\n",hashstr,m,z,bp,bp->coin->longestchain,bp->queued);
                }
                //free_queueitem(hashstr);
                //return(flag);
            } else printf("datalen.%d from gethdrs\n",datalen);
            free_queueitem(hashstr);
            hashstr = 0;
        }
    }
    //if ( netBLOCKS > coin->MAXPEERS*coin->MAXPENDING )
    //    usleep(netBLOCKS);
    if ( (limit= addr->recvblocks) > coin->MAXPENDINGREQUESTS )
        limit = coin->MAXPENDINGREQUESTS;
    if ( limit < 1 )
        limit = 1;
    if ( addr->pendblocks >= limit )
    {
        //printf("%s %d overlimit.%d\n",addr->ipaddr,addr->pendblocks,limit);
        return(0);
    }
    priority = 1;
    req = queue_dequeue(&coin->priorityQ,0);
    if ( flag == 0 && req == 0 && addr->pendblocks < limit )
    {
        priority = 0;
        for (i=m=pend=0; i<coin->peers->numranked; i++)
        {
            if ( (ptr= coin->peers->ranked[i]) != 0 && ptr->msgcounts.verack > 0 )
                pend += ptr->pendblocks, m++;
        }
        if ( pend < coin->MAXPENDINGREQUESTS*m )
            req = queue_dequeue(&coin->blocksQ,0);
    }
    if ( req != 0 )
    {
        hash2 = req->hash2;
        height = req->height;
        if ( (bp= req->bp) != 0 && req->bundlei >= 0 && req->bundlei < bp->n )
        {
            if ( bp->emitfinish != 0 )
            {
                //printf("skip emitting bundle [%d:%d]\n",bp->hdrsi,req->bundlei);
                return(0);
            }
            block = bp->blocks[req->bundlei];
        } else block = 0;
        if ( priority == 0 && bp != 0 && req->bundlei >= 0 && req->bundlei < bp->n && req->bundlei < coin->chain->bundlesize && block != 0 && (block->fpipbits != 0 || block->queued != 0) )
        {
            if ( 1 && priority != 0 )
                printf("SKIP %p[%d] %d\n",bp,bp!=0?bp->bundleheight:-1,req->bundlei);
        }
        else
        {
            //if ( block != 0 )
            //    block->numrequests++;
            iguana_sendblockreqPT(coin,addr,bp,req->bundlei,hash2,0);
        }
        flag++;
        myfree(req,sizeof(*req));
    }
    return(flag);
}

int32_t iguana_processrecv(struct supernet_info *myinfo,struct iguana_info *coin) // single threaded
{
    int32_t i,newhwm = 0,hwmheight,flag = 0; char str[2000];
    hwmheight = coin->blocks.hwmchain.height;
    coin->RTramchain_busy = 1;
    if ( coin->balanceflush != 0 )
    {
        if ( iguana_balanceflush(coin,coin->balanceflush) > 0 )
         printf("balanceswritten.%d flushed coin->balanceflush %d vs %d coin->longestchain/coin->chain->bundlesize\n",coin->balanceswritten,coin->balanceflush,coin->longestchain/coin->chain->bundlesize);
        coin->balanceflush = 0;
    }
    //printf("recvQ\n");
    flag += iguana_processrecvQ(coin,&newhwm);
    //printf("reqhdrs\n");
    flag += iguana_reqhdrs(coin);
    if ( coin->spendvectorsaved > 1 )
    {
        if ( time(NULL) > coin->laststats+5 )
        {
            //printf("reqblocks\n");
            flag += iguana_reqblocks(coin);
            //printf("bundlestats\n");
            iguana_bundlestats(coin,str,IGUANA_DEFAULTLAG);
            coin->laststats = (uint32_t)time(NULL);
        }
    }
    else
    {
        flag += iguana_reqblocks(coin);
        iguana_bundlestats(coin,str,IGUANA_DEFAULTLAG);
    }
    if ( time(NULL) > coin->spendvectorsaved )
    {
        for (i=0; i<coin->chain->bundlesize; i++)
        {
            if ( coin->RTdatabad != 0 || iguana_realtime_update(coin) <= 0 )
                break;
        }
    }
    coin->RTramchain_busy = 0;//(coin->RTgenesis == 0);
    flag += iguana_process_msgrequestQ(myinfo,coin);
    //if ( strcmp("BTCD",coin->symbol) == 0 )
    //    instantdex_update(SuperNET_MYINFO(0));

    if ( hwmheight != coin->blocks.hwmchain.height )
        flag = 1;
    return(flag);
}
