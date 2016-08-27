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

// verify undo cases for hhutxo, and all 4 permutations of setting

#include "iguana777.h"
//#define ENABLE_RAMCHAIN

#ifdef oldway
void iguana_RTramchainfree(struct iguana_info *coin,struct iguana_bundle *bp)
{
    //return;
#ifdef ENABLE_RAMCHAIN
    int32_t hdrsi;
    //portable_mutex_lock(&coin->RTmutex);
    if ( coin->utxotable != 0 )
    {
        printf("free RTramchain\n");
        //iguana_utxoupdate(coin,-1,0,0,0,0,-1,0); // free hashtables
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
#endif

//#define FAST_UTHASH
#ifdef FAST_UTHASH
#undef uthash_malloc
#undef uthash_free
#define uthash_malloc(size) ((coin->RTHASHMEM.ptr == 0) ? mycalloc('u',1,size) : iguana_memalloc(&coin->RTHASHMEM,size,1))
#define uthash_free(mem,size) ((coin->RTHASHMEM.ptr == 0) ? myfree(mem,size) : 0)
#endif

void iguana_RTtxid_free(struct iguana_RTtxid *RTptr)
{
    int32_t i;
    for (i=0; i<RTptr->numvouts; i++)
        if ( RTptr->unspents[i] != 0 )
            free(RTptr->unspents[i]);
    for (i=0; i<RTptr->numvins; i++)
        if ( RTptr->spends[i] != 0 )
            free(RTptr->spends[i]);
    free(RTptr);
}

void iguana_RTdataset_free(struct iguana_info *coin)
{
    struct iguana_RTtxid *RTptr,*tmp; struct iguana_RTaddr *RTaddr,*tmp2;
    HASH_ITER(hh,coin->RTdataset,RTptr,tmp)
    {
        HASH_DELETE(hh,coin->RTdataset,RTptr);
        iguana_RTtxid_free(RTptr);
    }
    HASH_ITER(hh,coin->RTaddrs,RTaddr,tmp2)
    {
        HASH_DELETE(hh,coin->RTaddrs,RTaddr);
        free(RTaddr);
    }
    iguana_hhutxo_purge(coin);
    iguana_memreset(&coin->RTHASHMEM);
}

void iguana_RTreset(struct iguana_info *coin)
{
    iguana_utxoaddrs_purge(coin);
    //iguana_utxoupdate(coin,-1,0,0,0,0,-1,0); // free hashtables
    coin->lastRTheight = 0;
    iguana_RTdataset_free(coin);
#ifdef FAST_UTHASH
    if ( coin->RTHASHMEM.ptr == 0 )
        iguana_meminit(&coin->RTHASHMEM,"RTHASHMEM",0,1024*1024*1024,0);
    iguana_memreset(&coin->RTHASHMEM);
#endif
    printf("%s RTreset %d\n",coin->symbol,coin->RTheight);
    coin->RTheight = coin->firstRTheight;
}

struct iguana_RTaddr *iguana_RTaddrfind(struct iguana_info *coin,uint8_t *rmd160,char *coinaddr)
{
    struct iguana_RTaddr *RTaddr; int32_t len; char _coinaddr[64];
    if ( coinaddr == 0 )
    {
        coinaddr = _coinaddr;
        bitcoin_address(coinaddr,coin->chain->pubtype,rmd160,20);
    }
    len = (int32_t)strlen(coinaddr);
    HASH_FIND(hh,coin->RTaddrs,coinaddr,len,RTaddr);
    return(RTaddr);
}

int64_t iguana_RTbalance(struct iguana_info *coin,char *coinaddr)
{
    struct iguana_RTaddr *RTaddr; uint8_t addrtype,rmd160[20]; int32_t len;
    len = (int32_t)strlen(coinaddr);
    HASH_FIND(hh,coin->RTaddrs,coinaddr,len,RTaddr);
    if ( RTaddr != 0 )
        return(RTaddr->credits - RTaddr->debits + RTaddr->histbalance);
    else
    {
        bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
        return(iguana_utxoaddrtablefind(coin,-1,-1,rmd160));
    }
}

void iguana_RTcoinaddr(struct iguana_info *coin,struct iguana_RTtxid *RTptr,struct iguana_block *block,int64_t polarity,char *coinaddr,uint8_t *rmd160,int32_t spendflag,int64_t value,struct iguana_RTunspent *unspent)
{
    struct iguana_RTaddr *RTaddr; int32_t len = (int32_t)strlen(coinaddr);
    HASH_FIND(hh,coin->RTaddrs,coinaddr,len,RTaddr);
    if ( RTaddr == 0 )
    {
        RTaddr = calloc(1,sizeof(*RTaddr));
        strncpy(RTaddr->coinaddr,coinaddr,len);
        RTaddr->histbalance = iguana_utxoaddrtablefind(coin,-1,-1,rmd160);
        HASH_ADD_KEYPTR(hh,coin->RTaddrs,RTaddr->coinaddr,len,RTaddr);
    }
    if ( spendflag != 0 )
    {
        RTaddr->debits += polarity * value;
        coin->RTdebits += polarity * value;
    }
    else
    {
        RTaddr->credits += polarity * value;
        coin->RTcredits += polarity * value;
        if ( polarity > 0 )
        {
            //printf("unspent[%d] <- %p\n",RTaddr->numunspents,unspent);
            RTaddr->numunspents++;
            unspent->prevunspent = RTaddr->lastunspent;
            RTaddr->lastunspent = unspent;
        }
        else if ( polarity < 0 )
        {
            if ( RTaddr->lastunspent == unspent )
            {
                RTaddr->lastunspent = unspent->prevunspent;
                free(unspent);
            } else printf("lastunspent.%p != %p\n",RTaddr->lastunspent,unspent);
            //RTaddr->unspents[i] = RTaddr->unspents[--RTaddr->numunspents];
        }
    }
    if ( 0 && strcmp("BTC",coin->symbol) != 0 && strcmp("LTC",coin->symbol) != 0 && strcmp("DOGE",coin->symbol) != 0 )
        printf("%lld %s %.8f h %.8f, cr %.8f deb %.8f [%.8f] numunspents.%d %p\n",(long long)polarity,coinaddr,dstr(value),dstr(RTaddr->histbalance),dstr(RTaddr->credits),dstr(RTaddr->debits),dstr(RTaddr->credits)-dstr(RTaddr->debits)+dstr(RTaddr->histbalance),RTaddr->numunspents,unspent);
}

struct iguana_RTunspent *iguana_RTunspent_create(uint8_t *rmd160,int64_t value,uint8_t *script,int32_t scriptlen,struct iguana_RTtxid *parent,int32_t vout)
{
    struct iguana_RTunspent *unspent;
    unspent = calloc(1,sizeof(*unspent) + scriptlen);
    unspent->value = value;
    if ( (unspent->parent= parent) != 0 )
        unspent->height = parent->height;
    else unspent->height = -1;
    unspent->vout = vout;
    unspent->scriptlen = scriptlen;
    memcpy(unspent->rmd160,rmd160,sizeof(unspent->rmd160));
    memcpy(unspent->script,script,scriptlen);
    return(unspent);
}

void iguana_RTunspent(struct iguana_info *coin,struct iguana_RTtxid *RTptr,struct iguana_block *block,int64_t polarity,char *coinaddr,uint8_t *rmd160,int32_t type,uint8_t *script,int32_t scriptlen,bits256 txid,int32_t vout,int64_t value)
{
    int32_t i; struct iguana_RTunspent *unspent; char str[65];
    //printf("iguana_RTunspent.%lld %s vout.%d %.8f\n",(long long)polarity,coinaddr,vout,dstr(value));
    //fprintf(stderr,"+");
    if ( RTptr != 0 )
    {
        if ( bits256_cmp(RTptr->txid,txid) == 0 )
        {
            if ( (unspent= RTptr->unspents[vout]) == 0 )
            {
                if ( polarity > 0 )
                {
                    unspent = iguana_RTunspent_create(rmd160,value,script,scriptlen>0?scriptlen:0,RTptr,vout);
                    RTptr->unspents[vout] = unspent;
                } else printf("iguana_RTunspent missing vout.%d ptr\n",vout);
            }
            else
            {
                if ( memcmp(rmd160,unspent->rmd160,sizeof(unspent->rmd160)) != 0 || value != unspent->value || scriptlen != unspent->scriptlen || memcmp(unspent->script,script,scriptlen) != 0 )
                {
                    printf("iguana_RTunspent.%d of %d mismatch %s\n",vout,RTptr->numvouts,bits256_str(str,RTptr->txid));
                    return;
                }
            }
            if ( (unspent->spend == 0 && polarity < 0) || (unspent->spend != 0 && polarity > 0) )
                printf("unspent spend.%p opposite when polarity.%lld\n",unspent->spend,(long long)polarity);
            iguana_RTcoinaddr(coin,RTptr,block,polarity,coinaddr,unspent->rmd160,0,value,unspent);
            if ( polarity < 0 )
                RTptr->unspents[vout] = 0;
        } else printf("iguana_RTunspent txid mismatch %llx != %llx\n",(long long)RTptr->txid.txid,(long long)txid.txid);
    }
    else
    {
        for (i=0; i<20; i++)
            printf("%02x",rmd160[i]);
        printf(" %s vout.%d %.8f %lld\n",coinaddr,vout,dstr(value),(long long)polarity);
    }
    //fprintf(stderr,",");
}

void iguana_RTspend(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_RTtxid *RTptr,struct iguana_block *block,int64_t polarity,uint8_t *script,int32_t scriptlen,bits256 txid,int32_t vini,bits256 prev_hash,int32_t prev_vout)
{
    struct iguana_RTspend *spend; struct iguana_RTtxid *spentRTptr; struct iguana_RTunspent *unspent=0; char str[65],str2[65],coinaddr[64]; uint8_t addrtype,rmd160[20],spendscript[IGUANA_MAXSCRIPTSIZE]; uint32_t unspentind; int32_t spendlen,height; uint64_t value; struct iguana_outpoint spentpt;
    //printf("RTspend %s vini.%d spend.(%s/v%d) %lld\n",bits256_str(str,txid),vini,bits256_str(str2,prev_hash),prev_vout,(long long)polarity);
    if ( vini == 0 && bits256_nonz(prev_hash) == 0 && prev_vout < 0 )
        return;
    //fprintf(stderr,"-");
    if ( RTptr != 0 )
    {
        if ( bits256_cmp(RTptr->txid,txid) == 0 )
        {
            if ( (spend= RTptr->spends[vini]) == 0 )
            {
                if ( polarity > 0 )
                {
                    spend = calloc(1,sizeof(*spend) + scriptlen);
                    spend->prev_hash = prev_hash;
                    spend->prev_vout = prev_vout;
                    spend->scriptlen = scriptlen;
                    memcpy(spend->vinscript,script,scriptlen);
                    RTptr->spends[vini] = spend;
                } else printf("iguana_RTspend missing vini.%d ptr\n",vini);
            }
            else
            {
                if ( bits256_cmp(prev_hash,spend->prev_hash) != 0 || prev_vout != spend->prev_vout || scriptlen != spend->scriptlen || memcmp(spend->vinscript,script,scriptlen) != 0 )
                {
                    printf("RTspend.%d of %d mismatch %s\n",vini,RTptr->numvins,bits256_str(str,RTptr->txid));
                    return;
                }
            }
            if ( bits256_nonz(prev_hash) != 0 && prev_vout >= 0 )
            {
                HASH_FIND(hh,coin->RTdataset,prev_hash.bytes,sizeof(prev_hash),spentRTptr);
                if ( spentRTptr != 0 )
                {
                    if ( (unspent= spentRTptr->unspents[prev_vout]) == 0 )
                    {
                        printf("iguana_RTspend null unspent.(%s).%d\n",bits256_str(str,prev_hash),prev_vout);
                    }
                }
                else
                {
                    if ( (unspentind= iguana_unspentindfind(myinfo,coin,coinaddr,spendscript,&spendlen,&value,&height,prev_hash,prev_vout,coin->bundlescount,0)) == 0 )
                        printf("iguana_RTspend cant find spentRTptr.(%s) search history\n",bits256_str(str,prev_hash));
                    else
                    {
                        int32_t spentheight,lockedflag,RTspentflag;
                        bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
                        //printf("found unspentind (%s %.8f).%d spendlen.%d\n",coinaddr,dstr(value),addrtype,spendlen);
                        unspent = iguana_RTunspent_create(rmd160,value,spendscript,spendlen>0?spendlen:0,0,prev_vout);
                        memset(&spentpt,0,sizeof(spentpt));
                        spentpt.unspentind = unspentind;
                        spentpt.hdrsi = height / coin->chain->bundlesize;
                        iguana_RTutxofunc(coin,&spentheight,&lockedflag,spentpt,&RTspentflag,0,RTptr->height);
                    }
                }
                if ( unspent != 0 )
                {
                    bitcoin_address(coinaddr,coin->chain->pubtype,unspent->rmd160,sizeof(unspent->rmd160));
                    iguana_RTcoinaddr(coin,RTptr,block,polarity,coinaddr,unspent->rmd160,1,unspent->value,unspent);
                    if ( polarity < 0 )
                        unspent->spend = 0;
                    else unspent->spend = spend;
                }
            }
        } else printf("iguana_RTspend txid mismatch %llx != %llx\n",(long long)RTptr->txid.txid,(long long)txid.txid);
    } else printf("null rtptr? %s vini.%d spend.(%s/v%d) %lld\n",bits256_str(str,txid),vini,bits256_str(str2,prev_hash),prev_vout,(long long)polarity);
    //fprintf(stderr,",");
}

struct iguana_RTtxid *iguana_RTtxid_create(struct iguana_info *coin,struct iguana_block *block,int64_t polarity,int32_t txi,int32_t txn_count,bits256 txid,int32_t numvouts,int32_t numvins,uint32_t locktime,uint32_t version,uint32_t timestamp)
{
    struct iguana_RTtxid *RTptr; char str[65];
    if ( block == 0 || block->height < coin->firstRTheight || block->height >= coin->firstRTheight+sizeof(coin->RTblocks)/sizeof(*coin->RTblocks) )
    {
        printf("iguana_RTtxid_create: illegal block height.%d\n",block!=0?block->height:-1);
        return(0);
    }
    //fprintf(stderr,"t");
    HASH_FIND(hh,coin->RTdataset,txid.bytes,sizeof(txid),RTptr);
    if ( RTptr == 0 )
    {
        RTptr = calloc(1,sizeof(*RTptr) + sizeof(void *)*numvins + sizeof(void *)*numvouts);
        RTptr->txi = txi, RTptr->txn_count = txn_count;
        RTptr->coin = coin;
        RTptr->block = block;
        RTptr->height = block->height;
        RTptr->txid = txid;
        RTptr->txn_count = txn_count;
        RTptr->numvouts = numvouts;
        RTptr->numvins = numvins;
        RTptr->locktime = locktime;
        RTptr->version = version;
        RTptr->timestamp = timestamp;
        RTptr->unspents = (void *)&RTptr->spends[numvins];
        HASH_ADD_KEYPTR(hh,coin->RTdataset,RTptr->txid.bytes,sizeof(RTptr->txid),RTptr);
        if ( 0 && strcmp("BTC",coin->symbol) != 0 )
            printf("%s txid.(%s) vouts.%d vins.%d version.%d lock.%u t.%u %lld\n",coin->symbol,bits256_str(str,txid),numvouts,numvins,version,locktime,timestamp,(long long)polarity);
    }
    else if ( RTptr->txn_count != txn_count || RTptr->numvouts != numvouts || RTptr->numvins != numvins )
    {
        printf("%s inconsistent counts.(%d %d %d) vs (%d %d %d)\n",bits256_str(str,txid),RTptr->txn_count,RTptr->numvouts,RTptr->numvins,txn_count,numvouts,numvins);
        return(0);
    }
    //fprintf(stderr," %d ",txi);
    //if ( txi == txn_count-1 )
    //    fprintf(stderr," ht.%d\n",block->height);
    return(RTptr);
}

int64_t _RTgettxout(struct iguana_info *coin,int32_t *height,int32_t *scriptlen,uint8_t *script,uint8_t *rmd160,char *coinaddr,bits256 txid,int32_t vout,int32_t mempool)
{
    int64_t value = 0; struct iguana_RTtxid *RTptr; struct iguana_RTunspent *unspent = 0;
    HASH_FIND(hh,coin->RTdataset,txid.bytes,sizeof(txid),RTptr);
    if ( RTptr != 0 && (RTptr->height <= coin->blocks.hwmchain.height || mempool != 0) )
    {
        if ( vout >= 0 && vout < RTptr->txn_count && (unspent= RTptr->unspents[vout]) != 0 )
        {
            *height = RTptr->height;
            if ( (*scriptlen= unspent->scriptlen) > 0 )
                memcpy(script,unspent->script,*scriptlen);
            memcpy(rmd160,unspent->rmd160,sizeof(unspent->rmd160));
            bitcoin_address(coinaddr,coin->chain->pubtype,rmd160,sizeof(unspent->rmd160));
            value = unspent->value;
        } else printf("vout.%d error %p\n",vout,unspent);
    }
    return(value);
}

int32_t iguana_RTunspentindfind(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,uint8_t *spendscript,int32_t *spendlenp,uint64_t *valuep,int32_t *heightp,bits256 txid,int32_t vout,int32_t lasthdrsi,int32_t mempool)
{
    char _coinaddr[64]; uint8_t rmd160[20]; int64_t value;
    if ( coinaddr == 0 )
        coinaddr = _coinaddr;
    if ( (value= _RTgettxout(coin,heightp,spendlenp,spendscript,rmd160,coinaddr,txid,vout,mempool)) > 0 )
    {
        if ( valuep != 0 )
            *valuep = value;
        return(0);
    }
    else return(iguana_unspentindfind(myinfo,coin,coinaddr,spendscript,spendlenp,valuep,heightp,txid,vout,lasthdrsi,mempool));
}

int32_t _iguana_RTunspentfind(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,int32_t *voutp,uint8_t *spendscript,struct iguana_outpoint outpt,int64_t value)
{
    int32_t spendlen = 0; struct iguana_RTunspent *unspent; struct iguana_RTtxid *parent;
    if ( outpt.isptr != 0 && (unspent= outpt.ptr) != 0 && (parent= unspent->parent) != 0 )
    {
        if ( value != unspent->value )
            printf("_iguana_RTunspentfind: mismatched value %.8f != %.8f\n",dstr(value),dstr(unspent->value));
        if ( (spendlen= unspent->scriptlen) > 0 )
            memcpy(spendscript,unspent->script,spendlen);
        *txidp = parent->txid;
        *voutp = unspent->vout;
    }
    return(spendlen);
}

void iguana_RTunmap(uint8_t *ptr,uint32_t len)
{
    OS_releasemap(&ptr[-2*sizeof(len)],len+2*sizeof(len));
}

void *iguana_RTrawdata(struct iguana_info *coin,bits256 hash2,uint8_t *data,int32_t *recvlenp,int32_t *numtxp,int32_t checkonly)
{
    FILE *fp; char fname[1024],str[65]; long filesize; int32_t len; uint8_t *ptr; uint32_t i,nonz,checknumtx,checklen;
    sprintf(fname,"%s/%s/RT/%s.raw",GLOBAL_TMPDIR,coin->symbol,bits256_str(str,hash2));
    OS_compatible_path(fname);
    if ( *recvlenp == -1 )
        OS_removefile(fname,0);
    else
    {
        if ( (checkonly != 0 || *recvlenp > 0) && (fp= fopen(fname,"rb")) != 0 )
        {
            fseek(fp,0,SEEK_END);
            filesize = ftell(fp);
            rewind(fp);
            if ( fread(&len,1,sizeof(len),fp) == sizeof(len) && len == filesize-sizeof(int32_t)*2 )
            {
                fclose(fp);
                //printf("already have %s\n",bits256_str(str,hash2));
                *recvlenp = 0;
                if ( checkonly != 0 )
                    return((void *)"already have rawdata");
                return(0);
            }
            //printf("len.%d filesize.%ld\n",len,filesize);
            fclose(fp);
            OS_removefile(fname,0);
        }
        else if ( checkonly == 0 )
        {
            if ( *recvlenp > 0 )
            {
                if ( coin->RTheight == 0 && coin->blocks.hwmchain.height < coin->longestchain-coin->chain->bundlesize && iguana_utxofinished(coin) < coin->bundlescount-3 )
                {
                    //printf("skip %s\n",bits256_str(str,hash2));
                    return(0);
                }
                if ( (fp= fopen(fname,"wb")) != 0 )
                {
                    if ( fwrite(recvlenp,1,sizeof(*recvlenp),fp) != sizeof(*recvlenp) || fwrite(numtxp,1,sizeof(*numtxp),fp) != sizeof(*numtxp) || fwrite(data,1,*recvlenp,fp) != *recvlenp )
                        printf("error writing %s len.%d numtx.%d\n",bits256_str(str,hash2),*recvlenp,*numtxp);
                    fclose(fp);
                    //printf("numtx.%d len.%d %s hwm.%d L.%d\n",*numtxp,*recvlenp,fname,coin->blocks.hwmchain.height,coin->longestchain);
                } else printf("couldnt create %s\n",fname);
            }
            else if ( (ptr= OS_mapfile(fname,&filesize,0)) != 0 )
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
    }
    return(0);
}

void iguana_RTpurge(struct iguana_info *coin,int32_t lastheight)
{
    int32_t hdrsi,bundlei,height,numtx=0,recvlen=-1,width=50000; struct iguana_bundle *bp;
    printf("start RTpurge from %d\n",lastheight - width);
    for (height=lastheight-width; height<lastheight; height++)
    {
        if ( height < 0 )
            height = 0;
        hdrsi = (height / coin->chain->bundlesize);
        bundlei = (height % coin->chain->bundlesize);
        if ( (bp= coin->bundles[hdrsi]) != 0 && bits256_nonz(bp->hashes[bundlei]) != 0 )
            iguana_RTrawdata(coin,bp->hashes[bundlei],0,&recvlen,&numtx,0); // delete file
    }
    printf("end %s RTpurge.%d\n",coin->symbol,lastheight);
}

int32_t iguana_RTiterate(struct supernet_info *myinfo,struct iguana_info *coin,int32_t offset,struct iguana_block *block,int64_t polarity)
{
    struct iguana_txblock txdata; uint8_t *serialized; struct iguana_bundle *bp; int32_t hdrsi,bundlei,height,i,n,errs=0,numtx,num,len; int32_t recvlen = 0;
    if ( (numtx= coin->RTnumtx[offset]) == 0 || (serialized= coin->RTrawdata[offset]) == 0 || (recvlen= coin->RTrecvlens[offset]) == 0 )
    {
        char str[65];
        //printf("errs.%d cant load %s ht.%d polarity.%lld numtx.%d %p recvlen.%d\n",errs,bits256_str(str,block->RO.hash2),block->height,(long long)polarity,coin->RTnumtx[offset],coin->RTrawdata[offset],coin->RTrecvlens[offset]);
        coin->RTrecvlens[offset] = 0;
        coin->RTrawdata[offset] = iguana_RTrawdata(coin,block->RO.hash2,0,&coin->RTrecvlens[offset],&coin->RTnumtx[offset],0);
        if ( (numtx= coin->RTnumtx[offset]) == 0 || (serialized= coin->RTrawdata[offset]) == 0 || (recvlen= coin->RTrecvlens[offset]) == 0 )
        {
            printf("%s errs.%d cant load %s ht.%d polarity.%lld numtx.%d %p recvlen.%d\n",coin->symbol,errs,bits256_str(str,block->RO.hash2),block->height,(long long)polarity,coin->RTnumtx[offset],coin->RTrawdata[offset],coin->RTrecvlens[offset]);
            struct iguana_peer *addr;
            iguana_blockQ("RTiterate",coin,0,-1,block->RO.hash2,1);
            if ( coin->peers != 0 && coin->peers->numranked > 0 )
            {
                for (i=0; i<coin->peers->numranked&&i<8; i++)
                    if ( (addr= coin->peers->ranked[i]) != 0 )
                        iguana_sendblockreqPT(coin,addr,0,-1,block->RO.hash2,1);
            }
            num = 0;
            for (height=block->height+1; height<=coin->blocks.hwmchain.height; height++)
            {
                hdrsi = (height / coin->chain->bundlesize);
                bundlei = (height % coin->chain->bundlesize);
                if ( (bp= coin->bundles[hdrsi]) != 0 && (block= bp->blocks[bundlei]) != 0 )
                {
                    recvlen = 0;
                    if ( iguana_RTrawdata(coin,block->RO.hash2,0,&recvlen,&numtx,0) == 0 )
                    {
                        num++;
                        iguana_blockQ("RTiterate",coin,0,-1,block->RO.hash2,1);
                        if ( coin->peers != 0 && (n= coin->peers->numranked) > 0 )
                        {
                            if ( (addr= coin->peers->ranked[rand() % n]) != 0 )
                                iguana_sendblockreqPT(coin,addr,0,-1,block->RO.hash2,1);
                        }
                    }
                }
            }
            printf("issue missing %d to ht.%d\n",num,height);
            return(-1);
        }
    }
    printf("%s RTiterate.%lld offset.%d numtx.%d len.%d\n",coin->symbol,(long long)polarity,offset,coin->RTnumtx[offset],coin->RTrecvlens[offset]);
    if ( coin->RTrawmem.ptr == 0 )
        iguana_meminit(&coin->RTrawmem,"RTrawmem",0,IGUANA_MAXPACKETSIZE * 2,0);
    if ( coin->RTmem.ptr == 0 )
        iguana_meminit(&coin->RTmem,"RTmem",0,IGUANA_MAXPACKETSIZE * 2,0);
    if ( coin->RThashmem.ptr == 0 )
        iguana_meminit(&coin->RThashmem,"RThashmem",0,IGUANA_MAXPACKETSIZE * 2,0);
    iguana_memreset(&coin->RTrawmem), iguana_memreset(&coin->RTmem), iguana_memreset(&coin->RThashmem);
    memset(&txdata,0,sizeof(txdata));
    //extern int32_t debugtest;
    //debugtest = 1;
    //fprintf(stderr,"T");
    if ( (n= iguana_gentxarray(coin,&coin->RTrawmem,&txdata,&len,serialized,recvlen)) > 0 )
    {
        //fprintf(stderr,"R");
        iguana_RTramchaindata(myinfo,coin,&coin->RTmem,&coin->RThashmem,polarity,block,coin->RTrawmem.ptr,numtx);
        return(0);
    } else printf("gentxarray n.%d RO.txn_count.%d recvlen.%d\n",n,numtx,recvlen);
    //debugtest = 0;
    iguana_RTreset(coin);
    return(-1);
}

struct iguana_block *iguana_RTblock(struct iguana_info *coin,int32_t height)
{
    int32_t offset; struct iguana_block *block;
    offset = height - coin->firstRTheight;
    //printf("%s iguana_RTblock.%d offset.%d\n",coin->symbol,height,offset);
    if ( offset < sizeof(coin->RTblocks)/sizeof(*coin->RTblocks) )
    {
        if ( (block= coin->RTblocks[offset]) != 0 )
        {
            if ( block->height != coin->firstRTheight+offset )
            {
                printf("block height mismatch patch %d != %d\n",block->height,coin->firstRTheight+offset);
                block->height = coin->firstRTheight+offset;
            }
            return(block);
        }
    }
    else printf("RTblock offset.%d too big\n",offset);
    return(0);
}

int32_t iguana_RTblockadd(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_block *block)
{
    int32_t offset;
    if ( block != 0 )
    {
        offset = block->height - coin->firstRTheight;
        if ( coin->RTrawdata[offset] == 0 )
            coin->RTrawdata[offset] = iguana_RTrawdata(coin,block->RO.hash2,0,&coin->RTrecvlens[offset],&coin->RTnumtx[offset],0);
        //printf("%s RTblockadd.%d offset.%d numtx.%d len.%d\n",coin->symbol,block->height,offset,coin->RTnumtx[offset],coin->RTrecvlens[offset]);
        block->RO.txn_count = coin->RTnumtx[offset];
        coin->RTblocks[offset] = block;
        if ( iguana_RTiterate(myinfo,coin,offset,block,1) < 0 )
            return(-1);
    }
    return(0);
}

int32_t iguana_RTblocksub(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_block *block)
{
    int32_t offset;
    if ( block != 0 )
    {
        offset = block->height - coin->firstRTheight;
        block->RO.txn_count = coin->RTnumtx[offset];
        printf("%s RTblocksub.%d offset.%d\n",coin->symbol,block->height,offset);
        if ( iguana_RTiterate(myinfo,coin,offset,block,-1) < 0 )
            return(-1);
        if ( coin->RTrawdata[offset] != 0 && coin->RTrecvlens[offset] != 0 )
            iguana_RTunmap(coin->RTrawdata[offset],coin->RTrecvlens[offset]);
        coin->RTrawdata[offset] = 0;
        coin->RTrecvlens[offset] = 0;
        coin->RTnumtx[offset] = 0;
        coin->RTblocks[offset] = 0;
    }
    return(0);
}

void iguana_RTnewblock(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_block *block)
{
    int32_t i,n,height,hdrsi,bundlei; struct iguana_block *addblock,*subblock; struct iguana_bundle *bp;
    if ( block->height < coin->firstRTheight || block->height >= coin->firstRTheight+sizeof(coin->RTblocks)/sizeof(*coin->RTblocks) )
    {
        if ( coin->firstRTheight > 0 )
            printf("iguana_RTnewblock illegal blockheight.%d\n",block->height);
        return;
    }
    if ( block != 0 && coin->RTheight > 0 && coin->RTheight <= coin->blocks.hwmchain.height )
    {
        portable_mutex_lock(&coin->RTmutex);
        if ( block->height > coin->lastRTheight )
        {
            n = (block->height - coin->RTheight) + 1;
            for (i=0; i<n; i++)
            {
                height = (coin->RTheight + i);
                hdrsi = (height / coin->chain->bundlesize);
                bundlei = (height % coin->chain->bundlesize);
                if ( (bp= coin->bundles[hdrsi]) != 0 && (addblock= bp->blocks[bundlei]) != 0 && addblock->height == coin->RTheight+i )
                {
                    if ( iguana_RTblockadd(myinfo,coin,addblock) < 0 )
                        break;
                    coin->lastRTheight = addblock->height;
                }
                else
                {
                    printf("missing RTaddblock at i.%d RTheight.%d vs %p %d\n",i,coin->RTheight,addblock,addblock!=0?addblock->height:-1);
                    break;
                }
            }
            coin->RTheight += i;
            //printf("%s >= RTnewblock RTheight %d prev %d\n",coin->symbol,coin->RTheight,coin->lastRTheight);
        }
        else if ( block->height == coin->lastRTheight )
        {
            if ( (subblock= iguana_RTblock(coin,block->height)) != 0 && subblock != block )
            {
                if ( iguana_RTblocksub(myinfo,coin,subblock) < 0 || iguana_RTblockadd(myinfo,coin,block) < 0 )
                {
                    portable_mutex_unlock(&coin->RTmutex);
                    return;
                }
                printf("%s == RTnewblock RTheight %d prev %d\n",coin->symbol,coin->RTheight,coin->lastRTheight);
            }
        }
        else
        {
            if ( block->height < coin->firstRTheight )
            {
                if ( coin->lastRTheight > 0 )
                    printf("%s ht.%d reorg past firstRTheight.%d\n",coin->symbol,block->height,coin->firstRTheight);
                iguana_RTreset(coin);
            }
            else
            {
                while ( coin->lastRTheight >= block->height )
                {
                    if ( iguana_RTblocksub(myinfo,coin,iguana_RTblock(coin,coin->lastRTheight--)) < 0 )
                    {
                        coin->RTheight = coin->lastRTheight+1;
                        portable_mutex_unlock(&coin->RTmutex);
                        return;
                    }
                }
                coin->RTheight = coin->lastRTheight+1;
                if ( iguana_RTblockadd(myinfo,coin,block) < 0 )
                {
                    portable_mutex_unlock(&coin->RTmutex);
                    return;
                }
                coin->lastRTheight = block->height;
                coin->RTheight = coin->lastRTheight+1;
            }
        }
        portable_mutex_unlock(&coin->RTmutex);
        //block = iguana_blockfind("next",coin,iguana_blockhash(coin,block->height+1));
    }
}

// infinite loops at bundle boundary?
// >= RTnewblock RTheight 1254001 prev 1254000
// B errs.0 cant load 15102564820405cd16506d2731567453c437af07cdd5954bc21b32304e39b1d4 ht.1254001 polarity.1 numtx.0 (nil) recvlen.0
