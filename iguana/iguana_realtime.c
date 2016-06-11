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

void iguana_RTramchainfree(struct iguana_info *coin,struct iguana_bundle *bp)
{
    int32_t hdrsi;
    if ( coin->utxotable != 0 )
    {
        printf("free RTramchain\n");
        iguana_utxoupdate(coin,-1,0,0,0,0,-1); // free hashtables
        coin->RTheight = coin->balanceswritten * coin->chain->bundlesize;
        coin->RTgenesis = 0;
        iguana_ramchain_free(coin,&coin->RTramchain,1);
        if ( bp != 0 )
            bp->ramchain = coin->RTramchain;
        iguana_mempurge(&coin->RTmem);
        iguana_mempurge(&coin->RThashmem);
        coin->RTdatabad = 0;
        for (hdrsi=coin->bundlescount-1; hdrsi>0; hdrsi--)
            if ( (bp= coin->bundles[hdrsi]) == 0 && bp != coin->current )
            {
                iguana_volatilespurge(coin,&bp->ramchain);
                if ( iguana_volatilesmap(coin,&bp->ramchain) != 0 )
                    printf("error mapping bundle.[%d]\n",hdrsi);
            }
        printf("done RTramchain\n");
    }
}

void *iguana_ramchainfile(struct iguana_info *coin,struct iguana_ramchain *dest,struct iguana_ramchain *R,struct iguana_bundle *bp,int32_t bundlei,struct iguana_block *block)
{
    char fname[1024]; long filesize; int32_t err; void *ptr=0;
    if ( block == bp->blocks[bundlei] && (ptr= iguana_bundlefile(coin,fname,&filesize,bp,bundlei)) != 0 )
    {
        if ( iguana_mapchaininit(fname,coin,R,bp,bundlei,block,ptr,filesize) >= 0 )
        {
            if ( dest != 0 && dest->H.data != 0 )
                err = iguana_ramchain_iterate(coin,dest,R,bp,bundlei);
            else err = 0;
            if ( err != 0 || dest->H.data == 0 || bits256_cmp(R->H.data->firsthash2,block->RO.hash2) != 0 )
            {
                char str[65];
                printf("ERROR [%d:%d] %s vs ",bp->hdrsi,bundlei,bits256_str(str,block->RO.hash2));
                printf("mapped.%s\n",bits256_str(str,R->H.data->firsthash2));
            } else return(ptr);
        }
        iguana_blockunmark(coin,block,bp,bundlei,1);
        iguana_ramchain_free(coin,R,1);
    } //else printf("ramchainfile ptr.%p block.%p\n",ptr,block);
    return(0);
}

void iguana_RTramchainalloc(char *fname,struct iguana_info *coin,struct iguana_bundle *bp)
{
    uint32_t i,changed = 0; struct iguana_ramchaindata *rdata; struct iguana_ramchain *dest = &coin->RTramchain; struct iguana_blockRO *B; struct iguana_bundle *tmpbp;
    if ( (rdata= dest->H.data) != 0 )
    {
        i = 0;
        if ( coin->RTheight != bp->bundleheight + rdata->numblocks )
            changed++;
        else
        {
            B = RAMCHAIN_PTR(rdata,Boffset);
            //B = (void *)(long)((long)rdata + rdata->Boffset);
            for (i=0; i<rdata->numblocks; i++)
                if ( bits256_cmp(B[i].hash2,bp->hashes[i]) != 0 )
                {
                    char str[65],str2[65]; printf("mismatched hash2 at %d %s vs %s\n",bp->bundleheight+i,bits256_str(str,B[i].hash2),bits256_str(str2,bp->hashes[i]));
                    changed++;
                    break;
                }
        }
        if ( changed != 0 )
        {
            printf("RTramchain changed %d bundlei.%d | coin->RTheight %d != %d bp->bundleheight +  %d coin->RTramchain.H.data->numblocks\n",coin->RTheight,i,coin->RTheight,bp->bundleheight,rdata->numblocks);
            //coin->RTheight = coin->balanceswritten * coin->chain->bundlesize;
            iguana_RTramchainfree(coin,bp);
        }
    }
    if ( coin->RTramchain.H.data == 0 )
    {
        printf("ALLOC RTramchain\n");
        iguana_ramchainopen(fname,coin,dest,&coin->RTmem,&coin->RThashmem,bp->bundleheight,bp->hashes[0]);
        dest->H.txidind = dest->H.unspentind = dest->H.spendind = dest->pkind = dest->H.data->firsti;
        dest->externalind = dest->H.stacksize = 0;
        dest->H.scriptoffset = 1;
        if ( 1 )
        {
            for (i=0; i<bp->hdrsi; i++)
                if ( (tmpbp= coin->bundles[i]) != 0 )
                {
                    //iguana_volatilespurge(coin,&tmpbp->ramchain);
                    iguana_volatilesmap(coin,&tmpbp->ramchain);
                }
            sleep(1);
        }
    }
}

void iguana_rdataset(struct iguana_ramchain *dest,struct iguana_ramchaindata *rdest,struct iguana_ramchain *src)
{
    *dest = *src;
    dest->H.data = rdest;
    *rdest = *src->H.data;
    rdest->numpkinds = src->pkind;
    rdest->numexternaltxids = src->externalind;
    rdest->numtxids = src->H.txidind;
    rdest->numunspents = src->H.unspentind;
    rdest->numspends = src->H.spendind;
    //printf("RT set numtxids.%u numspends.%u\n",rdest->numtxids,rdest->numspends);
}

void iguana_rdatarestore(struct iguana_ramchain *dest,struct iguana_ramchaindata *rdest,struct iguana_ramchain *src)
{
    *src = *dest;
    *src->H.data = *rdest;
    src->pkind = rdest->numpkinds;
    src->externalind = rdest->numexternaltxids;
    src->H.txidind = rdest->numtxids;
    src->H.unspentind = rdest->numunspents;
    src->H.spendind = rdest->numspends;
    printf("RT restore numtxids.%u numspends.%u\n",rdest->numtxids,rdest->numspends);
}

void iguana_RThdrs(struct iguana_info *coin,struct iguana_bundle *bp,int32_t numaddrs)
{
    int32_t datalen,i; uint8_t serialized[512]; char str[65]; struct iguana_peer *addr;
    if ( coin->peers == 0 )
        return;
    for (i=0; i<numaddrs && i<coin->peers->numranked; i++)
    {
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(bits256_str(str,bp->hashes[0])),1);
        if ( (addr= coin->peers->ranked[i]) != 0 && addr->usock >= 0 && addr->dead == 0 && (datalen= iguana_gethdrs(coin,serialized,coin->chain->gethdrsmsg,bits256_str(str,bp->hashes[0]))) > 0 )
        {
            iguana_send(coin,addr,serialized,datalen);
            addr->pendhdrs++;
        }
    }
}

void iguana_RTspendvectors(struct iguana_info *coin,struct iguana_bundle *bp)
{
    int32_t iterate,lasti,num,hdrsi,orignumemit; struct iguana_ramchain R; struct iguana_ramchaindata RDATA;
    if ( bp->hdrsi <= 0 )
        return;
    bp->ramchain = coin->RTramchain;
    iguana_rdataset(&R,&RDATA,&coin->RTramchain);
    if ( (lasti= (coin->RTheight - ((coin->RTheight/bp->n)*bp->n))) >= bp->n-1 )
        lasti = bp->n - 1;
    orignumemit = bp->numtmpspends;
#ifdef __APPLE__
    iterate = 0*(coin->bundlescount-1);
#else
    iterate = 0;
#endif
    if ( iguana_spendvectors(coin,bp,&coin->RTramchain,coin->RTstarti,lasti,0,iterate) < 0 )
    {
        printf("RTutxo error -> RTramchainfree\n");
        coin->RTdatabad = 1;
        return;
    }
    else
    {
        //printf("RTspendvectors calculated to %d [%d]\n",coin->RTheight,bp->hdrsi);
        bp->converted = 1;
        for (hdrsi=num=0; hdrsi<bp->hdrsi; hdrsi++)
        {
#ifdef __APPLE__
            if ( coin->bundles[hdrsi]->lastprefetch == 0 )
            {
                iguana_ramchain_prefetch(coin,&coin->bundles[hdrsi]->ramchain,2);
                coin->bundles[hdrsi]->lastprefetch = (uint32_t)time(NULL);
            }
#endif
            num += iguana_convert(coin,IGUANA_NUMHELPERS,coin->bundles[hdrsi],1,orignumemit);
        }
        //printf("RTspendvectors converted.%d to %d\n",num,coin->RTheight);
        bp->converted = (uint32_t)time(NULL);
        if ( iguana_balancegen(coin,1,bp,coin->RTstarti,coin->RTheight > 0 ? coin->RTheight-1 : bp->n-1,orignumemit) < 0 )
        {
            printf("balancegen error\n");
            coin->RTdatabad = 1;
        }
        else if ( coin->RTgenesis == 0 && coin->firstRTgenesis == 0 )
            coin->firstRTgenesis++, printf(">>>>>> IGUANA %s READY FOR REALTIME RPC <<<<<<\n",coin->symbol);
        //printf("iguana_balancegen [%d] (%d to %d)\n",bp->hdrsi,coin->RTstarti,(coin->RTheight-1)%bp->n);
        coin->RTstarti = (coin->RTheight % bp->n);
    }
}

int32_t iguana_realtime_update(struct iguana_info *coin)
{
    double startmillis0; static double totalmillis0; static int32_t num0;
    struct iguana_bundle *bp; struct iguana_ramchaindata *rdata; int32_t offset,bundlei,i,n,flag=0; bits256 hash2,*ptr; struct iguana_peer *addr;
    struct iguana_block *block=0; struct iguana_blockRO *B; struct iguana_ramchain *dest=0,blockR;
    if ( coin->peers == 0 )
        return(0);
    offset = (strcmp("BTC",coin->symbol) != 0);
    if ( coin->current != 0 && (coin->blocks.hwmchain.height % coin->chain->bundlesize) == coin->chain->bundlesize-1 && coin->blocks.hwmchain.height/coin->chain->bundlesize == coin->longestchain/coin->chain->bundlesize )
    {
        block = coin->current->blocks[coin->current->n - 1];
        if ( _iguana_chainlink(coin,block) <= 0 )
        {
            //printf("RT edge case couldnt link\n");
        }
        else printf("RT edge case.%d\n",block->height);
    }
    if ( coin->spendvectorsaved <= 1 )
    {
        //printf("spendvectorsaved not yet\n");
        return(0);
    }
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && (i > 0 && bp->utxofinish == 0) && bp != coin->current )
        {
            if ( iguana_spendvectors(coin,bp,&bp->ramchain,0,bp->n,0,0) < 0 )
            {
                printf("error generating spendvectors.[%d], skipping\n",i);
                return(0);
            } // else printf("generated UTXO.[%d]\n",i);
            coin->spendvectorsaved = 1;
        }
    }
    bp = coin->current;
    if ( bp == 0 || iguana_validated(coin) < bp->hdrsi )
    {
        //printf("bp.%p validated.%d vs hdrsi.%d\n",bp,iguana_validated(coin),bp->hdrsi);
        return(0);
    }
    if ( 1 && coin->RTheight > 0 && coin->spendvectorsaved != 1 && coin->bundlescount-1 != coin->balanceswritten )
    {
        printf("RT mismatch %d != %d\n",coin->bundlescount-1,coin->balanceswritten);
        coin->spendvectorsaved = 0;
        iguana_RTramchainfree(coin,coin->current);
        return(0);
    }
    if ( coin->RTdatabad == 0 && bp->hdrsi == coin->longestchain/coin->chain->bundlesize && bp->hdrsi >= coin->balanceswritten && coin->RTheight >= bp->bundleheight && coin->RTheight < bp->bundleheight+bp->n && ((coin->RTheight < coin->blocks.hwmchain.height-offset && time(NULL) > bp->lastRT) || time(NULL) > bp->lastRT+10) )
    {
        if ( (block= bp->blocks[0]) == 0 || block->txvalid == 0 || block->mainchain == 0 )
        {
            if ( block != 0 )
            {
                if ( _iguana_chainlink(coin,block) <= 0 )
                {
                    iguana_blockunmark(coin,block,bp,0,0);
                    bp->issued[0] = 0;
                    hash2 = bp->hashes[0];
                    //char str[65]; printf("RT[0] [%d:%d] %s %p\n",bp->hdrsi,0,bits256_str(str,hash2),block);
                    addr = coin->peers->ranked[rand() % 8];
                    if ( addr != 0 && addr->usock >= 0 && addr->dead == 0 )
                        iguana_sendblockreqPT(coin,addr,bp,0,hash2,0);
                }
            }
        }
        //char str[65]; printf("check longest.%d RTheight.%d hwm.%d %s %p\n",coin->longestchain,coin->RTheight,coin->blocks.hwmchain.height,bits256_str(str,bp->hashes[0]),block);
        if ( bits256_cmp(coin->RThash1,bp->hashes[1]) != 0 )
            coin->RThash1 = bp->hashes[1];
        bp->lastRT = (uint32_t)time(NULL);
        if ( coin->RTheight <= coin->longestchain-offset && coin->peers->numranked > 0 && time(NULL) > coin->RThdrstime+60 )
        {
            iguana_RThdrs(coin,bp,coin->peers->numranked);
            coin->RThdrstime = bp->lastRT;
            for (i=0; i<coin->peers->numranked; i++)
            {
                if ( (addr= coin->peers->ranked[i]) != 0 && addr->usock >= 0 && addr->dead == 0 )
                {
                    //printf("%d ",addr->numRThashes);
                }
            }
            //printf("RTheaders %s\n",coin->symbol);
        }
        bp->lastRT = (uint32_t)time(NULL);
        iguana_RTramchainalloc("RTbundle",coin,bp);
        bp->isRT = 1;
        while ( (rdata= coin->RTramchain.H.data) != 0 && coin->RTheight <= coin->blocks.hwmchain.height-offset )
        {
            if ( coin->RTdatabad != 0 )
                break;
            dest = &coin->RTramchain;
            B = RAMCHAIN_PTR(rdata,Boffset);
            //B = (void *)(long)((long)rdata + rdata->Boffset);
            bundlei = (coin->RTheight % coin->chain->bundlesize);
            if ( (block= iguana_bundleblock(coin,&hash2,bp,bundlei)) != 0 )
                iguana_bundlehashadd(coin,bp,bundlei,block);
            //printf("RT.%d vs hwm.%d starti.%d bp->n %d block.%p/%p ramchain.%p databad.%d prevnonz.%d\n",coin->RTheight,coin->blocks.hwmchain.height,coin->RTstarti,bp->n,block,bp->blocks[bundlei],dest->H.data,coin->RTdatabad,bits256_nonz(block->RO.prev_block));
            if ( coin->RTdatabad == 0 && block != 0 && bits256_nonz(block->RO.prev_block) != 0 )
            {
                iguana_blocksetcounters(coin,block,dest);
                startmillis0 = OS_milliseconds();
                if ( coin->RTdatabad == 0 && iguana_ramchainfile(coin,dest,&blockR,bp,bundlei,block) == 0 )
                {
                    for (i=0; i<bp->n; i++)
                        if ( GETBIT(bp->haveblock,i) == 0 )
                            bp->issued[i] = 0;
                    if (  (n= iguana_bundleissuemissing(coin,bp,3,1.)) > 0 )
                        printf("RT issued %d priority requests [%d] to unstick stuckiters.%d\n",n,bp->hdrsi,coin->stuckiters);
                    for (i=bundlei; i<bp->n; i++)
                    {
                        block = iguana_bundleblock(coin,&hash2,bp,i);
                        if ( bits256_nonz(hash2) != 0 && (block == 0 || block->txvalid == 0) )
                        {
                            uint8_t serialized[512]; int32_t len; struct iguana_peer *addr;
                            //char str[65]; printf("RT error [%d:%d] %s %p\n",bp->hdrsi,i,bits256_str(str,hash2),block);
                            addr = coin->peers->ranked[rand() % 8];
                            if ( addr != 0 && addr->usock >= 0 && addr->dead == 0 && (len= iguana_getdata(coin,serialized,MSG_BLOCK,&hash2,1)) > 0 )
                                iguana_send(coin,addr,serialized,len);
                            coin->RTgenesis = 0;
                        }
                        if ( bits256_nonz(hash2) != 0 )
                            iguana_blockQ("RTerr",coin,bp,i,hash2,1);
                        break;
                    }
                    return(-1);
                } else iguana_ramchain_free(coin,&blockR,1);
                B[bundlei] = block->RO;
                totalmillis0 += (OS_milliseconds() - startmillis0);
                num0++;
                flag++;
                //coin->blocks.RO[bp->bundleheight+bundlei] = block->RO;
                coin->RTheight++;
                //printf(">>>> RT.%d hwm.%d L.%d T.%d U.%d S.%d P.%d X.%d -> size.%ld\n",coin->RTheight,coin->blocks.hwmchain.height,coin->longestchain,dest->H.txidind,dest->H.unspentind,dest->H.spendind,dest->pkind,dest->externalind,(long)dest->H.data->allocsize);
                if ( coin->RTramchain.H.data != 0 )
                    coin->RTramchain.H.data->numblocks = bundlei + 1;
                else break;
            } else break;
        }
    }
    n = 0;
    if ( coin->RTdatabad == 0 && dest != 0 && flag != 0 && coin->RTheight >= coin->longestchain-offset )
    {
        //printf("ramchainiterate.[%d] ave %.2f micros, total %.2f seconds starti.%d num.%d\n",num0,(totalmillis0*1000.)/num0,totalmillis0/1000.,coin->RTstarti,coin->RTheight%bp->n);
        if ( (n= iguana_walkchain(coin,1)) == coin->RTheight-1+offset )
        {
            //printf("RTgenesis verified\n");
            if ( (coin->RTheight % coin->chain->bundlesize) > 3 )
            {
                iguana_RTspendvectors(coin,bp);
                coin->RTgenesis = (uint32_t)time(NULL);
            }
        }
        else
        {
            printf("walkchain error n.%d != %d\n",n,coin->RTheight-1+offset);
            coin->RTdatabad = 1;
        }
    }
    if ( dest != 0 && flag != 0 )
        printf("<<<< flag.%d RT.%d:%d hwm.%d L.%d T.%d U.%d S.%d P.%d X.%d -> size.%ld\n",flag,coin->RTheight,n,coin->blocks.hwmchain.height,coin->longestchain,dest->H.txidind,dest->H.unspentind,dest->H.spendind,dest->pkind,dest->externalind,dest->H.data!=0?(long)dest->H.data->allocsize:-1);
    if ( coin->RTdatabad != 0 )
    {
        iguana_RTramchainfree(coin,bp);
        coin->RTdatabad = 0;
        //memset(bp->hashes,0,sizeof(bp->hashes));
        memset(bp->blocks,0,sizeof(bp->blocks));
        if ( 0 && bp->speculative != 0 )
        {
            ptr = bp->speculative;
            bp->speculative = 0;
            memset(ptr,0,sizeof(*bp->speculative)*bp->n);
            myfree(ptr,(bp->n+1)*sizeof(*bp->speculative));
        }
        iguana_RTramchainalloc("RTbundle",coin,bp);
    }
    return(flag);
}
