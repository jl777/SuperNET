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
//#define ENABLE_RAMCHAIN

void iguana_RTramchainfree(struct iguana_info *coin,struct iguana_bundle *bp)
{
    //return;
#ifdef ENABLE_RAMCHAIN
    int32_t hdrsi;
    //portable_mutex_lock(&coin->RTmutex);
    if ( coin->utxotable != 0 )
    {
        printf("free RTramchain\n");
        iguana_utxoupdate(coin,-1,0,0,0,0,-1,0); // free hashtables
        coin->lastRTheight = coin->RTheight = 0;//(coin->bundlescount-1) * coin->chain->bundlesize;
        coin->RTgenesis = 0;
        iguana_utxoaddrs_purge(coin);
        iguana_ramchain_free(coin,&coin->RTramchain,1);
        if ( bp != 0 )
            bp->ramchain = coin->RTramchain;
        iguana_mempurge(&coin->RTmem);
        iguana_mempurge(&coin->RThashmem);
        for (hdrsi=coin->bundlescount-1; hdrsi>0; hdrsi--)
            if ( (bp= coin->bundles[hdrsi]) == 0 && bp != coin->current )
            {
                iguana_volatilespurge(coin,&bp->ramchain);
                if ( iguana_volatilesmap(coin,&bp->ramchain) != 0 )
                    printf("error mapping bundle.[%d]\n",hdrsi);
            }
        coin->RTdatabad = 0;
        printf("done RTramchain\n");
    }
    //portable_mutex_unlock(&coin->RTmutex);
#endif
}

void *iguana_ramchainfile(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_ramchain *dest,struct iguana_ramchain *R,struct iguana_bundle *bp,int32_t bundlei,struct iguana_block *block)
{
    //return(0);
#ifdef ENABLE_RAMCHAIN
    char fname[1024]; long filesize; int32_t err; void *ptr=0;
    if ( block == bp->blocks[bundlei] && (ptr= iguana_bundlefile(coin,fname,&filesize,bp,bundlei)) != 0 )
    {
        if ( iguana_mapchaininit(fname,coin,R,bp,bundlei,block,ptr,filesize) >= 0 )
        {
            if ( dest != 0 && dest->H.data != 0 )
                err = iguana_ramchain_iterate(myinfo,coin,dest,R,bp,bundlei);
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
#endif
    return(0);
}

void iguana_RTramchainalloc(char *fname,struct iguana_info *coin,struct iguana_bundle *bp)
{
    //return;
#ifdef ENABLE_RAMCHAIN
    uint32_t i,changed = 0; struct iguana_ramchaindata *rdata; struct iguana_ramchain *dest = &coin->RTramchain; struct iguana_blockRO *B; struct iguana_bundle *tmpbp;
    //portable_mutex_lock(&coin->RTmutex);
    if ( (rdata= dest->H.data) != 0 )
    {
        i = 0;
        if ( coin->RTheight != coin->lastRTheight )
            changed++;
        else
        {
            B = RAMCHAIN_PTR(rdata,Boffset);
            for (i=0; i<rdata->numblocks; i++)
                if ( bits256_cmp(B[i].hash2,bp->hashes[i]) != 0 )
                {
                    char str[65],str2[65]; printf("mismatched hash2 at %d %s vs %s\n",bp->bundleheight+i,bits256_str(str,B[i].hash2),bits256_str(str2,bp->hashes[i]));
                    changed++;
                    iguana_blockunmark(coin,bp->blocks[i],bp,i,1);
                    break;
                }
        }
        if ( changed != 0 )
        {
            printf("RTramchain changed %d bundlei.%d | coin->RTheight %d != %d bp->bundleheight +  %d coin->RTramchain.H.data->numblocks\n",coin->RTheight,i,coin->RTheight,bp->bundleheight,rdata->numblocks);
            iguana_RTramchainfree(coin,bp);
        }
    }
    if ( coin->RTramchain.H.data == 0 )
    {
        iguana_ramchainopen(fname,coin,dest,&coin->RTmem,&coin->RThashmem,bp->bundleheight,bp->hashes[0]);
        printf("ALLOC RTramchain.(%s) RTrdata %p rdata.%p\n",fname,coin->RTramchain.H.data,bp->ramchain.H.data);
        dest->H.txidind = dest->H.unspentind = dest->H.spendind = dest->pkind = dest->H.data->firsti;
        dest->externalind = dest->H.stacksize = 0;
        dest->H.scriptoffset = 1;
        if ( 1 )
        {
            for (i=0; i<bp->hdrsi; i++)
                if ( (tmpbp= coin->bundles[i]) != 0 )
                {
                    iguana_volatilespurge(coin,&tmpbp->ramchain);
                    iguana_volatilesmap(coin,&tmpbp->ramchain);
                }
            sleep(1);
        }
    }
    //portable_mutex_unlock(&coin->RTmutex);
#endif
}

void iguana_rdataset(struct iguana_ramchain *dest,struct iguana_ramchaindata *rdest,struct iguana_ramchain *src)
{
    //return;
#ifdef ENABLE_RAMCHAIN
    *dest = *src;
    dest->H.data = rdest;
    *rdest = *src->H.data;
    rdest->numpkinds = src->pkind;
    rdest->numexternaltxids = src->externalind;
    rdest->numtxids = src->H.txidind;
    rdest->numunspents = src->H.unspentind;
    rdest->numspends = src->H.spendind;
    //printf("RT set numtxids.%u numspends.%u\n",rdest->numtxids,rdest->numspends);
#endif
}

void iguana_rdatarestore(struct iguana_ramchain *dest,struct iguana_ramchaindata *rdest,struct iguana_ramchain *src)
{
    //return;
#ifdef ENABLE_RAMCHAIN
    *src = *dest;
    *src->H.data = *rdest;
    src->pkind = rdest->numpkinds;
    src->externalind = rdest->numexternaltxids;
    src->H.txidind = rdest->numtxids;
    src->H.unspentind = rdest->numunspents;
    src->H.spendind = rdest->numspends;
    printf("RT restore numtxids.%u numspends.%u\n",rdest->numtxids,rdest->numspends);
#endif
}

void iguana_RThdrs(struct iguana_info *coin,struct iguana_bundle *bp,int32_t numaddrs)
{
    //return;
#ifdef ENABLE_RAMCHAIN
    int32_t datalen,i; uint8_t serialized[512]; char str[65]; struct iguana_peer *addr;
    if ( coin->peers == 0 )
        return;
    datalen = iguana_gethdrs(coin,serialized,coin->chain->gethdrsmsg,bits256_str(str,bp->hashes[0]));
    for (i=0; i<numaddrs && i<coin->peers->numranked; i++)
    {
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(bits256_str(str,bp->hashes[0])),1);
        if ( coin->chain->hasheaders == 0 )
            queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(bits256_str(str,coin->blocks.hwmchain.RO.hash2)),1);
        if ( (addr= coin->peers->ranked[i]) != 0 && addr->usock >= 0 && addr->dead == 0 && datalen > 0 )
        {
            iguana_send(coin,addr,serialized,datalen);
            //addr->pendhdrs++;
        }
    }
#endif
}

void iguana_RTspendvectors(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp)
{
    //return;
#ifdef ENABLE_RAMCHAIN
    int32_t iterate,lasti,num,hdrsi,orignumemit; struct iguana_ramchain R; struct iguana_ramchaindata RDATA;
    if ( bp->hdrsi <= 0 )
        return;
    printf("RTspendvectors [%d]\n",bp->hdrsi);
    bp->ramchain = coin->RTramchain;
    iguana_rdataset(&R,&RDATA,&coin->RTramchain);
    if ( (lasti= (coin->RTheight - ((coin->RTheight/bp->n)*bp->n))) >= bp->n-1 )
        lasti = bp->n - 1;
    orignumemit = bp->numtmpspends;
    iterate = 0;
    if ( iguana_spendvectors(myinfo,coin,bp,&coin->RTramchain,coin->RTstarti%coin->chain->bundlesize,lasti,0,iterate) < 0 )
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
        //iguana_rdatarestore(&R,&RDATA,&bp->ramchain);
        bp->converted = (uint32_t)time(NULL);
        if ( iguana_balancegen(coin,1,bp,coin->RTstarti,coin->RTheight > 0 ? coin->RTheight-1 : bp->bundleheight+bp->n-1,orignumemit) < 0 )
        {
            printf("balancegen error\n");
            coin->RTdatabad = 1;
        }
        else if ( coin->RTgenesis == 0 && coin->firstRTgenesis == 0 )
            coin->firstRTgenesis++, printf(">>>>>> IGUANA %s READY FOR REALTIME RPC <<<<<<\n",coin->symbol);
        //printf("iguana_balancegen [%d] (%d to %d)\n",bp->hdrsi,coin->RTstarti,(coin->RTheight-1)%bp->n);
        coin->RTstarti = coin->RTheight;
    }
#endif
}

int32_t iguana_realtime_update(struct supernet_info *myinfo,struct iguana_info *coin)
{
    int32_t flag = 0;
    //return(0);
#ifdef ENABLE_RAMCHAIN
    double startmillis0; static double totalmillis0; static int32_t num0;
    struct iguana_bundle *bp; struct iguana_ramchaindata *rdata; int32_t offset,bundlei,i,n; bits256 hash2,*ptr; struct iguana_peer *addr;
    struct iguana_block *block=0; struct iguana_blockRO *B; struct iguana_ramchain *dest=0,blockR;
    if ( coin->peers == 0 && coin->virtualchain == 0 )
        return(0);
    offset = 0;//(strcmp("BTC",coin->symbol) != 0);
    if ( coin->RTheight >= (coin->current->hdrsi+1)*coin->chain->bundlesize )
    {
        printf("inversion RT %d >= %d\n",coin->RTheight,(coin->current->hdrsi+1)*coin->chain->bundlesize);
        coin->lastRTheight = coin->RTheight = coin->current->hdrsi*coin->chain->bundlesize;
        iguana_utxoaddrs_purge(coin);
    }
    if ( coin->current != 0 && (coin->blocks.hwmchain.height % coin->chain->bundlesize) == coin->chain->bundlesize-1 && coin->blocks.hwmchain.height/coin->chain->bundlesize == coin->longestchain/coin->chain->bundlesize )
    {
        block = coin->current->blocks[coin->current->n - 1];
        if ( _iguana_chainlink(coin,block) <= 0 )
        {
            printf("RT edge case couldnt link\n");
        }
        else
        {
            printf("RT edge case.%d\n",block->height);
            if ( (bp= coin->bundles[coin->RTheight / coin->chain->bundlesize]) != 0 )
                iguana_spendvectors(myinfo,coin,bp,&bp->ramchain,0,bp->n,0,0);
            iguana_update_balances(coin);
        }
    }
    if ( coin->spendvectorsaved <= 1 )
    {
        //printf("%s spendvectorsaved not yet\n",coin->symbol);
        usleep(100000);
        return(0);
    }
    //portable_mutex_lock(&coin->RTmutex);
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && (i > 0 && bp->utxofinish == 0) && bp != coin->current )
        {
            if ( iguana_spendvectors(myinfo,coin,bp,&bp->ramchain,0,bp->n,0,0) < 0 )
            {
                //portable_mutex_unlock(&coin->RTmutex);
                printf("error generating spendvectors.[%d], skipping\n",i);
                return(0);
            } // else printf("generated UTXO.[%d]\n",i);
            coin->spendvectorsaved = 1;
        }
    }
    //portable_mutex_unlock(&coin->RTmutex);
    bp = coin->current;
    if ( bp == 0 )//|| iguana_validated(coin) < bp->hdrsi )
    {
        //printf("bp.%p validated.%d vs hdrsi.%d\n",bp,iguana_validated(coin),bp->hdrsi);
        return(0);
    }
    if ( 0 && coin->RTheight > 0 && coin->spendvectorsaved != 1 && coin->bundlescount-1 != coin->balanceswritten )
    {
        printf("RT mismatch %d != %d\n",coin->bundlescount-1,coin->balanceswritten);
        iguana_RTramchainfree(coin,coin->current);
        coin->spendvectorsaved = 0;
        coin->lastRTheight = coin->RTheight = 0;
        iguana_utxoaddrs_purge(coin);
        /*while ( coin->spendvectorsaved <= 1 )
         {
         fprintf(stderr,"wait for spendvectorsaved\n");
         sleep(3);
         }*/
        return(0);
    }
    if ( coin->RTdatabad == 0 && bp->hdrsi >= (coin->longestchain/coin->chain->bundlesize)-1 && bp->hdrsi >= coin->balanceswritten-2 && ((coin->RTheight < coin->blocks.hwmchain.height-offset && time(NULL) > bp->lastRT) || time(NULL) > bp->lastRT+1) ) //coin->RTheight >= bp->bundleheight && coin->RTheight < bp->bundleheight+bp->n &&
    {
        if ( coin->RTheight < bp->hdrsi*coin->chain->bundlesize )
        {
            coin->lastRTheight = coin->RTheight = bp->hdrsi*coin->chain->bundlesize;
            iguana_utxoaddrs_purge(coin);
        }
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
                    if ( coin->peers != 0 )
                    {
                        addr = coin->peers->ranked[rand() % 8];
                        if ( addr != 0 && addr->usock >= 0 && addr->dead == 0 )
                            iguana_sendblockreqPT(coin,addr,bp,0,hash2,0);
                    }
                }
            }
        }
        //char str[65]; printf("check longest.%d RTheight.%d hwm.%d %s %p\n",coin->longestchain,coin->RTheight,coin->blocks.hwmchain.height,bits256_str(str,bp->hashes[0]),block);
        if ( bits256_cmp(coin->RThash1,bp->hashes[1]) != 0 )
            coin->RThash1 = bp->hashes[1];
        //bp->lastRT = (uint32_t)time(NULL);
        if ( coin->peers != 0 && coin->RTheight <= coin->longestchain-offset && coin->peers->numranked > 0 && time(NULL) > coin->RThdrstime+16 )
        {
            iguana_RThdrs(coin,bp,coin->peers->numranked);
            coin->RThdrstime = (uint32_t)time(NULL);
        }
        bp->lastRT = (uint32_t)time(NULL);
        iguana_RTramchainalloc("RTbundle",coin,bp);
        bp->isRT = 1;
        //printf("%s rdata.%p RTheight.%d hwm.%d RTdatabad.%d\n",coin->symbol,coin->RTramchain.H.data,coin->RTheight,coin->blocks.hwmchain.height,coin->RTdatabad);
        while ( (rdata= coin->RTramchain.H.data) != 0 && coin->RTheight <= coin->blocks.hwmchain.height-offset && coin->RTdatabad == 0 )
        {
            dest = &coin->RTramchain;
            B = RAMCHAIN_PTR(rdata,Boffset);
            bundlei = (coin->RTheight % coin->chain->bundlesize);
            if ( (block= iguana_bundleblock(coin,&hash2,bp,bundlei)) != 0 )
            {
                iguana_bundlehashadd(coin,bp,bundlei,block);
                //printf("RT.%d vs hwm.%d starti.%d bp->n %d block.%p/%p ramchain.%p databad.%d prevnonz.%d\n",coin->RTheight,coin->blocks.hwmchain.height,coin->RTstarti,bp->n,block,bp->blocks[bundlei],dest->H.data,coin->RTdatabad,bits256_nonz(block->RO.prev_block));
            }
            else
            {
                //printf("cant find bundleblock [%d:%d]\n",bp->hdrsi,bundlei);
                iguana_blockQ("RTmissing",coin,bp,bundlei,hash2,1);
                break;
            }
            if ( coin->RTdatabad == 0 && block != 0 && (block->height == 0 || bits256_nonz(block->RO.prev_block) != 0) )
            {
                //printf("bundlei.%d blockht.%d RTheight.%d\n",bundlei,block->height,coin->RTheight);
                iguana_blocksetcounters(coin,block,dest);
                startmillis0 = OS_milliseconds();
                if ( iguana_ramchainfile(myinfo,coin,dest,&blockR,bp,bundlei,block) == 0 )
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
                            if ( coin->peers != 0 )
                            {
                                addr = coin->peers->ranked[rand() % 8];
                                if ( addr != 0 && addr->usock >= 0 && addr->dead == 0 && (len= iguana_getdata(coin,serialized,MSG_BLOCK,&hash2,1)) > 0 )
                                    iguana_send(coin,addr,serialized,len);
                            }
                            coin->RTgenesis = 0;
                        }
                        if ( bits256_nonz(hash2) != 0 )
                            iguana_blockQ("RTerr",coin,bp,i,hash2,1);
                        //break;
                    }
                    return(-1);
                } else iguana_ramchain_free(coin,&blockR,1);
                B[bundlei] = block->RO;
                totalmillis0 += (OS_milliseconds() - startmillis0);
                num0++;
                flag++;
                //coin->blocks.RO[bp->bundleheight+bundlei] = block->RO;
                coin->RTheight++;
                coin->lastRTheight = coin->RTheight;
                //printf(">>>> RT.%d hwm.%d L.%d T.%d U.%d S.%d P.%d X.%d -> size.%ld\n",coin->RTheight,coin->blocks.hwmchain.height,coin->longestchain,dest->H.txidind,dest->H.unspentind,dest->H.spendind,dest->pkind,dest->externalind,(long)dest->H.data->allocsize);
                if ( coin->RTramchain.H.data != 0 )
                    coin->RTramchain.H.data->numblocks = bundlei + 1;
                else break;
            } else break;
        }
    }
    else
    {
        if ( coin->virtualchain == 0 )
        {
            //printf("%s skip RT.(%d %d %d %d %d %d %d %u)\n",coin->symbol,coin->RTdatabad,bp->hdrsi,coin->longestchain/coin->chain->bundlesize,coin->balanceswritten,coin->RTheight,bp->bundleheight,coin->blocks.hwmchain.height,bp->lastRT);
            //sleep(1);
        }
    }
    n = 0;
    if ( coin->RTdatabad == 0 && dest != 0 && flag != 0 && coin->RTheight >= coin->blocks.hwmchain.height-offset )
    {
        printf("ramchainiterate.[%d] ave %.2f micros, total %.2f seconds starti.%d num.%d\n",num0,(totalmillis0*1000.)/num0,totalmillis0/1000.,coin->RTstarti,coin->RTheight%bp->n);
        if ( (n= iguana_walkchain(coin,1)) == coin->RTheight-1+offset )
        {
            //printf("RTgenesis verified\n");
            if ( (coin->RTheight % coin->chain->bundlesize) > 3 )
            {
                //portable_mutex_lock(&coin->RTmutex);
                iguana_RTspendvectors(myinfo,coin,bp);
                //portable_mutex_unlock(&coin->RTmutex);
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
        printf("<<<< flag.%d RT.%d:%d hwm.%d L.%d T.%d U.%d S.%d P.%d X.%d -> size.%ld balance %.8f + %.8f - %.8f = supply %.8f\n",flag,coin->RTheight,n,coin->blocks.hwmchain.height,coin->longestchain,dest->H.txidind,dest->H.unspentind,dest->H.spendind,dest->pkind,dest->externalind,dest->H.data!=0?(long)dest->H.data->allocsize:-1,dstr(coin->histbalance),dstr(coin->RTcredits),dstr(coin->RTdebits),dstr(coin->histbalance + coin->RTcredits - coin->RTdebits));
    if ( coin->RTdatabad != 0 )
    {
        bits256 lastbundle;
        //portable_mutex_lock(&coin->RTmutex);
        printf("START DATABAD fixing\n");
        iguana_RTramchainfree(coin,bp);
        if ( coin->RTdatabad < 0 )
        {
            memset(lastbundle.bytes,0,sizeof(lastbundle));
            iguana_initfinal(myinfo,coin,lastbundle);
        }
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
        printf("DONE DATABAD fixing\n");
        //portable_mutex_unlock(&coin->RTmutex);
    }
#endif
    return(flag);
}

void iguana_RTunspent(struct iguana_info *coin,struct iguana_block *block,int64_t polarity,char *coinaddr,uint8_t *rmd160,bits256 txid,int32_t vout,int64_t value)
{
    int32_t i;
    // fill in array element and update counters
    if ( 0 && strcmp("BTC",coin->symbol) != 0 )
    {
        for (i=0; i<20; i++)
            printf("%02x",rmd160[i]);
        printf(" %s vout.%d %.8f %lld\n",coinaddr,vout,dstr(value),(long long)polarity);
    }
}

void iguana_RTspend(struct iguana_info *coin,struct iguana_block *block,int64_t polarity,bits256 txid,int32_t vini,bits256 prev_hash,int32_t prev_vout)
{
    char str[65],str2[65];
    // fill in array element and update counters
    if ( 0 && strcmp("BTC",coin->symbol) != 0 )
        printf("%s vini.%d spend.(%s/v%d) %lld\n",bits256_str(str,txid),vini,bits256_str(str2,prev_hash),prev_vout,(long long)polarity);
}

void iguana_RTtxid(struct iguana_info *coin,struct iguana_block *block,int64_t polarity,int32_t txi,int32_t txn_count,bits256 txid,int32_t numvouts,int32_t numvins,uint32_t locktime,uint32_t version,uint32_t timestamp,void *unspents,void *spends)
{
    char str[65];
    // add to hashtable block <-> txids[]
    if ( 0 && strcmp("BTC",coin->symbol) != 0 )
        printf("%s txid.(%s) vouts.%d vins.%d version.%d lock.%u t.%u %lld\n",coin->symbol,bits256_str(str,txid),numvouts,numvins,version,locktime,timestamp,(long long)polarity);
}

void iguana_RTreset(struct iguana_info *coin)
{
    iguana_utxoaddrs_purge(coin);
    iguana_utxoupdate(coin,-1,0,0,0,0,-1,0); // free hashtables
    printf("%s RTreset\n",coin->symbol);
}

void iguana_RTunmap(uint8_t *ptr,uint32_t len)
{
    OS_releasemap(&ptr[-2*sizeof(len)],len+2*sizeof(len));
}

void *iguana_RTrawdata(struct iguana_info *coin,bits256 hash2,uint8_t *data,int32_t *recvlenp,int32_t *numtxp)
{
    FILE *fp; char fname[1024],str[65]; long filesize; uint8_t *ptr; uint32_t i,nonz,checknumtx,checklen;
    sprintf(fname,"%s/%s/RT/%s.raw",GLOBAL_TMPDIR,coin->symbol,bits256_str(str,hash2));
    OS_compatible_path(fname);
    if ( *recvlenp > 0 )
    {
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            if ( fwrite(recvlenp,1,sizeof(*recvlenp),fp) != sizeof(*recvlenp) || fwrite(numtxp,1,sizeof(*numtxp),fp) != sizeof(*numtxp) || fwrite(data,1,*recvlenp,fp) != *recvlenp )
                printf("error writing %s len.%d numtx.%d\n",bits256_str(str,hash2),*recvlenp,*numtxp);
            fclose(fp);
            //printf("numtx.%d len.%d %s\n",*numtxp,*recvlenp,fname);
        } else printf("couldnt create %s\n",fname);
    }
    else if ( *recvlenp == 0 )
    {
        if ( (ptr= OS_mapfile(fname,&filesize,0)) != 0 )
        {
            memcpy(&checklen,ptr,sizeof(checklen));
            memcpy(&checknumtx,&ptr[sizeof(checklen)],sizeof(checknumtx));
            *numtxp = checknumtx;
            if ( checklen == (int32_t)(filesize - sizeof(checklen) - sizeof(checknumtx)) )//&& checknumtx == *numtxp )
            {
                for (i=nonz=0; i<checklen; i++)
                    if ( ptr[2*sizeof(checklen) + i] != 0 )
                        nonz++;
                *recvlenp = (int32_t)(filesize - sizeof(checklen) - sizeof(checknumtx));
                return(&ptr[sizeof(*recvlenp) + sizeof(checknumtx)]);
            } else printf("checklen.%d vs %d, checknumtx %d vs %d\n",checklen,(int32_t)(filesize - sizeof(checklen) - sizeof(checknumtx)),checknumtx,*numtxp);
        }
    }
    else if ( *recvlenp == -1 )
        OS_removefile(fname,0);
    return(0);
}

void iguana_RTpurge(struct iguana_info *coin,int32_t lastheight)
{
    int32_t hdrsi,bundlei,height,numtx=0,recvlen=-1; struct iguana_bundle *bp;
    printf("start RTpurge from %d\n",lastheight - coin->chain->bundlesize*10);
    for (height=lastheight-coin->chain->bundlesize*10; height<lastheight; height++)
    {
        if ( height < 0 )
            height = 0;
        hdrsi = (height / coin->chain->bundlesize);
        bundlei = (height % coin->chain->bundlesize);
        if ( (bp= coin->bundles[hdrsi]) != 0 && bits256_nonz(bp->hashes[bundlei]) != 0 )
            iguana_RTrawdata(coin,bp->hashes[bundlei],0,&recvlen,&numtx); // delete file
    }
    printf("end RTpurge.%d\n",lastheight);
}

void iguana_RTiterate(struct iguana_info *coin,int32_t offset,struct iguana_block *block,int64_t polarity)
{
    struct iguana_txblock txdata; uint8_t *serialized; int32_t n,numtx,len; uint32_t recvlen = 0;
    if ( (numtx= coin->RTnumtx[offset]) == 0 || (serialized= coin->RTrawdata[offset]) == 0 || (recvlen= coin->RTrecvlens[offset]) == 0 )
    {
        printf("cant load from tmpdir ht.%d polarity.%lld numtx.%d %p recvlen.%d\n",block->height,(long long)polarity,coin->RTnumtx[offset],coin->RTrawdata[offset],coin->RTrecvlens[offset]);
        return;
    }
    printf("%s RTiterate.%lld offset.%d numtx.%d len.%d\n",coin->symbol,(long long)polarity,offset,coin->RTnumtx[offset],coin->RTrecvlens[offset]);
    memset(&txdata,0,sizeof(txdata));
    if ( coin->RTrawmem.ptr == 0 )
        iguana_meminit(&coin->RTrawmem,"RTrawmem",0,IGUANA_MAXPACKETSIZE * 2,0);
    if ( coin->RTmem.ptr == 0 )
        iguana_meminit(&coin->RTmem,"RTmem",0,IGUANA_MAXPACKETSIZE * 2,0);
    if ( coin->RThashmem.ptr == 0 )
        iguana_meminit(&coin->RThashmem,"RThashmem",0,IGUANA_MAXPACKETSIZE * 2,0);
    iguana_memreset(&coin->RTrawmem), iguana_memreset(&coin->RTmem), iguana_memreset(&coin->RThashmem);
    if ( (n= iguana_gentxarray(coin,&coin->RTrawmem,&txdata,&len,serialized,recvlen)) > 0 )
    {
        iguana_RTramchaindata(coin,&coin->RTmem,&coin->RThashmem,polarity,block,coin->RTrawmem.ptr,numtx);
    } else printf("gentxarray n.%d RO.txn_count.%d recvlen.%d\n",n,numtx,recvlen);
}

struct iguana_block *iguana_RTblock(struct iguana_info *coin,int32_t height)
{
    int32_t offset;
    offset = height - coin->firstRTheight;
    //printf("%s iguana_RTblock.%d offset.%d\n",coin->symbol,height,offset);
    if ( offset < sizeof(coin->RTblocks)/sizeof(*coin->RTblocks) )
        return(coin->RTblocks[offset]);
    else printf("RTblock offset.%d too big\n",offset);
    return(0);
}

void iguana_RTblockadd(struct iguana_info *coin,struct iguana_block *block)
{
    int32_t offset;
    if ( block != 0 )
    {
        offset = block->height - coin->firstRTheight;
        if ( coin->RTrawdata[offset] == 0 )
            coin->RTrawdata[offset] = iguana_RTrawdata(coin,block->RO.hash2,0,&coin->RTrecvlens[offset],&coin->RTnumtx[offset]);
        //printf("%s RTblockadd.%d offset.%d numtx.%d len.%d\n",coin->symbol,block->height,offset,coin->RTnumtx[offset],coin->RTrecvlens[offset]);
        coin->RTblocks[offset] = block;
        iguana_RTiterate(coin,offset,block,1);
    }
}

void iguana_RTblocksub(struct iguana_info *coin,struct iguana_block *block)
{
    int32_t offset;
    if ( block != 0 )
    {
        offset = block->height - coin->firstRTheight;
        //printf("%s RTblocksub.%d offset.%d\n",coin->symbol,block->height,offset);
        iguana_RTiterate(coin,offset,block,-1);
        if ( coin->RTrawdata[offset] != 0 && coin->RTrecvlens[offset] != 0 )
            iguana_RTunmap(coin->RTrawdata[offset],coin->RTrecvlens[offset]);
        coin->RTrawdata[offset] = 0;
        coin->RTrecvlens[offset] = 0;
        coin->RTblocks[offset] = 0;
    }
}

void iguana_RTnewblock(struct iguana_info *coin,struct iguana_block *block)
{
    int32_t i,n,height,hdrsi,bundlei; struct iguana_block *addblock,*subblock; struct iguana_bundle *bp;
    if ( coin->RTheight > 0 )
    {
        if ( block->height > coin->lastRTheight )
        {
            if ( coin->lastRTheight == 0 )
            {
                coin->firstRTheight = coin->RTheight;
                iguana_RTreset(coin);
                iguana_RTpurge(coin,coin->firstRTheight);
            }
            n = (block->height - coin->RTheight) + 1;
            for (i=0; i<n; i++,coin->RTheight++)
            {
                height = (coin->RTheight + i);
                hdrsi = (height / coin->chain->bundlesize);
                bundlei = (height % coin->chain->bundlesize);
                if ( (bp= coin->bundles[hdrsi]) != 0 && (addblock= bp->blocks[bundlei]) != 0 && addblock->height == coin->RTheight+i )
                {
                    iguana_RTblockadd(coin,addblock);
                    coin->lastRTheight = addblock->height;
                }
                else
                {
                    printf("missing RTaddblock at i.%d RTheight.%d vs %p %d\n",i,coin->RTheight,addblock,addblock!=0?addblock->height:-1);
                    break;
                }
            }
            printf(">= RTnewblock RTheight %d prev %d\n",coin->RTheight,coin->lastRTheight);
        }
        else if ( block->height == coin->lastRTheight )
        {
            if ( (subblock= iguana_RTblock(coin,block->height)) != 0 && subblock != block )
            {
                iguana_RTblocksub(coin,block);
                iguana_RTblockadd(coin,block);
                printf("== RTnewblock RTheight %d prev %d\n",coin->RTheight,coin->lastRTheight);
            }
        }
        else
        {
            if ( block->height < coin->firstRTheight )
            {
                if ( coin->lastRTheight > 0 )
                    printf("ht.%d reorg past firstRTheight.%d\n",block->height,coin->firstRTheight);
                coin->lastRTheight = 0;
                iguana_RTreset(coin);
            }
            else
            {
                while ( coin->lastRTheight >= block->height )
                    iguana_RTblocksub(coin,iguana_RTblock(coin,coin->lastRTheight--));
                iguana_RTblockadd(coin,block);
                coin->lastRTheight = block->height;
            }
        }
    }
}
