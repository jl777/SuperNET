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

static uint16_t iguana_primes[] = { 65353, 65357, 65371, 65381, 65393, 65407, 65413, 65419, 65423, 65437, 65447, 65449, 65479, 65497, 65519, 65521 };


struct iguana_bloominds iguana_calcbloom(bits256 hash2)
{
    int32_t i,j,k; struct iguana_bloominds bit;
    k = (int32_t)(sizeof(bit)/sizeof(uint16_t)) - 1;
    j = 15;
    for (i=0; i<sizeof(bit)/sizeof(uint16_t); i++,j--,k--)
        bit.inds[i] = (hash2.ushorts[j] % iguana_primes[k]);//, printf("%d ",bit.inds[i]);
    //printf("bit.inds\n");
    return(bit);
}

struct iguana_bloominds iguana_bloomset(struct iguana_info *coin,struct iguana_bloom16 *bloom,int32_t incr,struct iguana_bloominds bit)
{
    int32_t i,alreadyset;
    for (alreadyset=i=0; i<sizeof(bit)/sizeof(uint16_t); i++,bloom+=incr)
    {
        if ( GETBIT(bloom->hash2bits,bit.inds[i]) == 0 )
            SETBIT(bloom->hash2bits,bit.inds[i]);
        else alreadyset++;
    }
    if ( alreadyset == i )
        printf("iguana_bloomset: collision\n");
    return(bit);
}

int32_t iguana_bloomfind(struct iguana_info *coin,struct iguana_bloom16 *bloom,int32_t incr,struct iguana_bloominds bit)
{
    int32_t i;
    coin->bloomsearches++;
    for (i=0; i<sizeof(bit)/sizeof(uint16_t); i++,bloom+=incr)
        if ( GETBIT(bloom->hash2bits,bit.inds[i]) == 0 )
            return(-1);
    coin->bloomhits++;
    return(0);
}

int32_t iguana_bundlescan(struct iguana_info *coin,struct iguana_bundle *bp,bits256 hash2)
{
    int32_t bundlei;
    for (bundlei=0; bundlei<bp->n; bundlei++)
    {
        if ( memcmp(hash2.bytes,bp->hashes[bundlei].bytes,sizeof(hash2)) == 0 )
        {
            //char str[65]; printf("hdrsi.%d scan.%s found %d of %d\n",bp->hdrsi,bits256_str(str,hash2),bundlei,bp->n);
            return(bundlei);
        }
    }
    return(-2);
}

struct iguana_bundle *iguana_bundlefind(struct iguana_info *coin,struct iguana_bundle **bpp,int32_t *bundleip,bits256 hash2)
{
    int32_t i; struct iguana_bloominds bit; struct iguana_bundle *bp = *bpp;
    bit = iguana_calcbloom(hash2);
    if ( bp == 0 )
    {
        for (i=coin->bundlescount-1; i>=0; i--)
        //for (i=0; i<coin->bundlescount; i++)
        {
            if ( (bp= coin->bundles[i]) != 0 )
            {
                if ( iguana_bloomfind(coin,&bp->bloom,0,bit) == 0 )
                {
                    *bpp = bp;
                    if ( (*bundleip= iguana_bundlescan(coin,bp,hash2)) < 0 )
                    {
                        //printf("bloom miss\n");
                        coin->bloomfalse++;
                    } else return(bp);
                } //else printf("no bloom\n");
            }
        }
        *bundleip = -2;
        *bpp = 0;
        return(0);
    }
    else if ( iguana_bloomfind(coin,&bp->bloom,0,bit) == 0 )
    {
        if ( (*bundleip= iguana_bundlescan(coin,bp,hash2)) >= 0 )
        {
            *bpp = bp;
            return(bp);
        } else printf("scan miss\n");
    }
    *bpp = 0;
    *bundleip = -2;
    return(0);
}

bits256 *iguana_bundleihash2p(struct iguana_info *coin,int32_t *isinsidep,struct iguana_bundle *bp,int32_t bundlei)
{
    *isinsidep = 0;
    if ( bundlei >= 0 && bundlei < coin->chain->bundlesize )
    {
        *isinsidep = 1;
        return(&bp->hashes[bundlei]);
    }
    else if ( bundlei == -1 )
        return(&bp->prevbundlehash2);
    else if ( bundlei == coin->chain->bundlesize)
        return(&bp->nextbundlehash2);
    else return(0);
}

int32_t iguana_hash2set(struct iguana_info *coin,char *debugstr,struct iguana_bundle *bp,int32_t bundlei,bits256 newhash2)
{
    int32_t isinside,checki,retval = -1; bits256 *orighash2p = 0; struct iguana_bundle *checkbp; char str[65]; struct iguana_bloominds bit;
    if ( bp == 0 )
        return(-1);
    if ( bp->n <= bundlei )
    {
        printf("hash2set.%s [%d] of %d <- %s\n",debugstr,bundlei,bp->n,bits256_str(str,newhash2));
        bp->n = coin->chain->bundlesize;
    }
    if ( bits256_nonz(newhash2) == 0 || (orighash2p= iguana_bundleihash2p(coin,&isinside,bp,bundlei)) == 0 )
    {
        printf("iguana_hash2set warning: bundlei.%d newhash2.%s orighash2p.%p\n",bundlei,bits256_str(str,newhash2),orighash2p);
        //*orighash2p = newhash2;
      //getchar();
        return(-1);
    }
    if ( bits256_nonz(*orighash2p) > 0 && memcmp(newhash2.bytes,orighash2p,sizeof(bits256)) != 0 )
    {
        char str2[65],str3[65];
        bits256_str(str2,*orighash2p), bits256_str(str3,newhash2);
        printf("WARNING iguana_hash2set overwrite [%s] %s with %s [%d:%d]\n",debugstr,str2,str3,bp->hdrsi,bundlei);
        *orighash2p = newhash2;
       // getchar();
       // return(-1);
    }
    if ( isinside != 0 )
    {
        bit = iguana_calcbloom(newhash2);
        if ( iguana_bloomfind(coin,&bp->bloom,0,bit) < 0 )
        {
           // printf("bloomset (%s) -> [%d:%d]\n",bits256_str(str,newhash2),bp->hdrsi,bundlei);
            iguana_bloomset(coin,&bp->bloom,0,bit);
            if ( 0 )
            {
                int32_t i;
                if ( iguana_bloomfind(coin,&bp->bloom,0,bit) < 0 )
                {
                    for (i=0; i<8; i++)
                        printf("%d ",bit.inds[i]);
                    printf("cant bloomfind just bloomset\n");
                }
                else
                {
                    *orighash2p = newhash2;
                    checkbp = bp, checki = -2;
                    if ( iguana_bundlefind(coin,&checkbp,&checki,newhash2) == 0 || checki != bundlei )
                    {
                        printf("cant iguana_bundlefind just added.(%s) bundlei.%d %p vs checki.%d %p\n",bits256_str(str,newhash2),bundlei,bp,checki,checkbp);
                    }
                    else if ( (coin->bloomsearches % 100000) == 0 )
                        printf("BLOOM SUCCESS %.2f%% FP.%d/%d collisions.%d\n",100.*(double)coin->bloomhits/coin->bloomsearches,(int32_t)coin->bloomfalse,(int32_t)coin->bloomsearches,(int32_t)coin->collisions);
                }
            }
        } //else printf("bloom found\n");
        retval = 0;
    } else retval = (bundlei >= 0 && bundlei < coin->chain->bundlesize) ? 0 : 1;
    //printf("set [%d] <- %s\n",bundlei,bits256_str(str,newhash2));
    if ( bits256_cmp(*orighash2p,newhash2) != 0 )
    {
        if ( bits256_nonz(*orighash2p) != 0 && bp->bundleheight+bundlei <= coin->blocks.hwmchain.height )
        {
            printf("changing [%d:%d] -> %d < hwmheight %d\n",bp->hdrsi,bundlei,bp->bundleheight+bundlei,coin->blocks.hwmchain.height);
            if ( bp->bundleheight+bundlei > 0 )
            {
                printf("REORG %d blocks\n",coin->blocks.hwmchain.height - (bp->bundleheight+bundlei));
            }
        }
        *orighash2p = newhash2;
    }
    return(retval);
}

int32_t iguana_bundlehash2add(struct iguana_info *coin,struct iguana_block **blockp,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2)
{
    struct iguana_block *block =0; struct iguana_bundle *otherbp; //
    int32_t otherbundlei,setval,bundlesize,err = 0;
    if ( blockp != 0 )
        *blockp = 0;
    if ( bp == 0 || bits256_nonz(hash2) == 0 )
        return(-1111);
    if ( bits256_nonz(hash2) > 0 && (block= iguana_blockhashset(coin,-1,hash2,1)) != 0 )
    {
        /*if ( (block->hdrsi != bp->hdrsi || block->bundlei != bundlei) && (block->hdrsi != 0 || block->bundlei != 0) )
        {
            return(-2);
        }*/
        bundlesize = coin->chain->bundlesize;
        if ( bp->n > bundlesize )
        {
            printf("bp->n.%d is too big\n",bp->n);
            return(0);
        }
        if ( bundlei >= bp->n && bundlei < coin->chain->bundlesize )
            bp->n = bundlesize;//(bundlei < bundlesize-1) ? bundlesize : (bundlei + 1);
        if ( (setval= iguana_hash2set(coin,"blockadd",bp,bundlei,hash2)) == 0 )
        {
            if ( (block->hdrsi != bp->hdrsi || block->bundlei != bundlei) && (block->hdrsi != 0 || block->bundlei != 0) )
            {
                printf("blockadd warning: %d[%d] <- %d[%d]\n",block->hdrsi,block->bundlei,bp->hdrsi,bundlei);
                err |= 2;
                exit(-1);
            }
            else
            {
//char str[65]; printf(">>>>>>>>>>>>>> bundlehash2.(%s) ht.(%d %d)\n",bits256_str(str,hash2),bp->bundleheight,bundlei);
                block->hdrsi = bp->hdrsi;
                block->bundlei = bundlei;
                bp->hashes[bundlei] = block->RO.hash2;
                if ( bp->speculative != 0 && bundlei < bp->numspec )
                    bp->speculative[bundlei] = bp->hashes[bundlei];
                bp->blocks[bundlei] = block;
                otherbp = 0;
                if ( (otherbp= iguana_bundlefind(coin,&otherbp,&otherbundlei,hash2)) != 0 || (bundlei % (bundlesize-1)) == 0)
                {
                    if ( bundlei == 0 && (otherbundlei == -2 || otherbundlei == bundlesize-1) )
                    {
                        if ( otherbp != 0 && iguana_hash2set(coin,"blockadd0_prev",bp,-1,otherbp->hashes[0]) != 0 )
                            err |= 4;
                        if ( otherbp != 0 && iguana_hash2set(coin,"blockadd0_next",otherbp,bundlesize,bp->hashes[0]) != 0 )
                            err |= 8;
                    }
                    else if ( bundlei == bundlesize-1 && (otherbundlei == -2 || otherbundlei == 0) )
                    {
                        if ( otherbp != 0 && iguana_hash2set(coin,"blockaddL_prev",otherbp,-1,bp->hashes[0]) != 0 )
                            err |= 16;
                        if ( otherbp != 0 && iguana_hash2set(coin,"blockaddL_next",bp,bundlesize,otherbp->hashes[0]) != 0 )
                            err |= 32;
                    }
                    //else printf("blockadd warning: %d[%d] bloomfound %d[%d]\n",bp->hdrsi,bundlei,otherbp!=0?otherbp->hdrsi:-1,otherbundlei);
                }
            }
        }
        else if ( setval == 1 )
        {
            if ( bundlei == -1 && iguana_hash2set(coin,"blockadd_m1",bp,-1,hash2) != 0 )
                err |= 4;
            if ( bundlei == bundlesize && iguana_hash2set(coin,"blockaddL_m1",bp,bundlesize,hash2) != 0 )
                err |= 4;
        }
        else if ( setval < 0 )
        {
            printf("neg setval error\n");
            err |= 64;
        }
        if ( err == 0 && blockp != 0 )
            *blockp = block;
    } else err |= 128;
    if ( err != 0 )
    {
        printf("bundlehash2add err.%d\n",err);
        return(0);
        //while ( 1 )
        //    sleep(1);
        //exit(-1);
    }
    return(-err);
}

struct iguana_bundle *iguana_bundlecreate(struct iguana_info *coin,int32_t *bundleip,int32_t bundleheight,bits256 bundlehash2,bits256 allhash,int32_t issueflag)
{
    char str[65],dirname[1024]; struct iguana_bundle *bp = 0;
    if ( bits256_nonz(bundlehash2) > 0 )
    {
        bits256_str(str,bundlehash2);
        if ( iguana_bundlefind(coin,&bp,bundleip,bundlehash2) != 0 )
        {
            if ( bp->bundleheight >= 0 && bp->bundleheight != (bundleheight - *bundleip) )
            {
                printf("bundlecreate warning: bp->bundleheight %d != %d (bundleheight %d - %d bundlei)\n",bp->bundleheight,(bundleheight - *bundleip),bundleheight,*bundleip);
                return(0);
            }
            else if ( bits256_nonz(bp->allhash) == 0 )
                bp->allhash = allhash;
            return(bp);
        }
        bp = mycalloc('b',1,sizeof(*bp));
        bp->n = coin->chain->bundlesize;
        bp->hdrsi = bundleheight / coin->chain->bundlesize;
        bp->bundleheight = bundleheight;
        bp->allhash = allhash;
        iguana_hash2set(coin,"create",bp,0,bundlehash2);
        if ( iguana_bundlehash2add(coin,0,bp,0,bundlehash2) == 0 )
        {
            bp->coin = coin;
            bp->avetime = coin->avetime * 2.;
            coin->bundles[bp->hdrsi] = bp;
            if ( bp->hdrsi > 0 && coin->bundles[bp->hdrsi-1] != 0 )
                coin->bundles[bp->hdrsi-1]->nextbp = bp;
            *bundleip = 0;
            bits256_str(str,bundlehash2);
            sprintf(dirname,"%s/%s/%d",GLOBALTMPDIR,coin->symbol,bp->bundleheight), OS_ensure_directory(dirname);
            //printf("ht.%d alloc.[%d] new hdrs.%s %s\n",bp->bundleheight,coin->bundlescount,str,bits256_str(str2,allhash));
            iguana_bundlehash2add(coin,0,bp,0,bundlehash2);
            if ( issueflag != 0 )
            {
                iguana_blockQ("bundlecreate",coin,bp,0,bundlehash2,1);
                queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(str),1);
            }
            if ( bp->hdrsi >= coin->bundlescount )
                coin->bundlescount = (bp->hdrsi + 1);
        }
        else
        {
            printf("error adding bundlehash2 bundleheight.%d\n",bundleheight);
            myfree(bp,sizeof(*bp));
            bp = 0;
        }
        return(bp);
    } else printf("cant create bundle with zerohash\n");
    //else printf("iguana_hdrscreate cant find hdr with %s or %s\n",bits256_str(bundlehash2),bits256_str2(firstblockhash2));
    return(0);
}

struct iguana_txid *iguana_bundletx(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,struct iguana_txid *tx,int32_t txidind)
{
    static bits256 zero;
    int32_t hdrsi,iter; int64_t Toffset; char fname[1024]; FILE *fp; struct iguana_ramchaindata rdata;
    for (iter=0; iter<2; iter++)
    {
        iguana_peerfname(coin,&hdrsi,iter==0?"DB/ro":"DB",fname,0,bp->hashes[0],zero,bp->n);
        if ( (fp= fopen(fname,"rb")) != 0 )
        {
            fseek(fp,(long)&rdata.Toffset - (long)&rdata,SEEK_SET);
            if ( fread(&Toffset,1,sizeof(Toffset),fp) == sizeof(Toffset) )
            {
                fseek(fp,Toffset + sizeof(struct iguana_txid) * txidind,SEEK_SET);
                if ( fread(tx,1,sizeof(*tx),fp) == sizeof(*tx) )
                {
                    fclose(fp);
                    return(tx);
                } else printf("bundletx read error\n");
            } else printf("bundletx Toffset read error\n");
            fclose(fp);
        }
    }
    printf("bundletx couldnt open.(%s)\n",fname);
    return(0);
}

void iguana_bundlepurge(struct iguana_info *coin,struct iguana_bundle *bp)
{
    static bits256 zero;
    char fname[1024]; int32_t hdrsi,m,j; uint32_t ipbits;
    if ( bp->emitfinish > coin->startutc && bp->purgetime == 0 && time(NULL) > bp->emitfinish+30 )
    {
        for (j=m=0; j<sizeof(coin->peers.active)/sizeof(*coin->peers.active); j++)
        {
            if ( (ipbits= (uint32_t)coin->peers.active[j].ipbits) != 0 )
            {
                if ( iguana_peerfname(coin,&hdrsi,GLOBALTMPDIR,fname,ipbits,bp->hashes[0],zero,1) >= 0 )
                {
                    if ( OS_removefile(fname,0) > 0 )
                        coin->peers.numfiles--, m++;
                }
                else printf("error removing.(%s)\n",fname);
            }
        }
        //printf("purged hdrsi.%d m.%d\n",bp->hdrsi,m);
        bp->purgetime = (uint32_t)time(NULL);
    }
}

int32_t iguana_bundleissue(struct iguana_info *coin,struct iguana_bundle *bp,int32_t max,int32_t timelimit)
{
    int32_t i,j,k,len,starti,lag,doneval,nonz,total=0,maxval,numpeers,laggard,flag=0,finished,peercounts[IGUANA_MAXPEERS],donecounts[IGUANA_MAXPEERS],priority,counter = 0;
    struct iguana_peer *addr; uint32_t now; struct iguana_block *block;
    bits256 hashes[50]; uint8_t serialized[sizeof(hashes) + 256];
    if ( bp == 0 )
        return(0);
    now = (uint32_t)time(NULL);
    memset(peercounts,0,sizeof(peercounts));
    memset(donecounts,0,sizeof(donecounts));
    if ( coin->current != 0 )
        starti = coin->current->hdrsi;
    else starti = 0;
    priority = (bp->hdrsi < starti + coin->peers.numranked);
    /*lag = (bp->hdrsi - starti);
    lag *= lag;
    if ( (i= sqrt(bp->hdrsi)) < 2 )
        i = 2;
    if ( lag < i )
        lag = i;
    else if ( lag > 10*i )
        lag = 10*i;*/
    if ( strcmp("BTC",coin->symbol) == 0 )
        lag = 30;
    else lag = 3;
    if ( (numpeers= coin->peers.numranked) > 3 )//&& bp->currentflag < bp->n )
    {
        if ( numpeers > 0xff )
            numpeers = 0xff; // fit into 8 bitfield
        if ( bp->currentflag == 0 )
            bp->currenttime = now;
        if ( bp->numhashes >= 1 )
        {
            for (j=0; j<numpeers; j++)
            {
                if ( (addr= coin->peers.ranked[j]) != 0 && addr->dead == 0 && addr->usock >= 0 )
                {
                    now = (uint32_t)time(NULL);
                    for (i=j,k=doneval=maxval=0; i<bp->n&&k<sizeof(hashes)/sizeof(*hashes); i+=numpeers)
                    {
                        if ( bits256_nonz(bp->hashes[i]) != 0 )
                        {
                            if ( (block= bp->blocks[i]) != 0 )
                            {
                                if ( block->peerid == 0 )
                                {
                                    //printf("<%d>.%d ",i,j);
                                    if ( block->fpipbits == 0 )
                                    {
                                        hashes[k++] = bp->hashes[i];
                                        bp->issued[i] = now;
                                        block->issued = now;
                                        block->peerid = j + 1;
                                        block->numrequests++;
                                    }
                                    else
                                    {
                                        block->peerid = 1;
                                        block->numrequests++;
                                    }
                                }
                                else if ( block->peerid > 0 )
                                {
                                    total++;
                                    if ( block->fpipbits != 0 )//&& block->fpos >= 0 )
                                    {
                                        donecounts[block->peerid - 1]++;
                                        if ( donecounts[block->peerid - 1] > doneval )
                                            doneval = donecounts[block->peerid - 1];
                                    }
                                    else
                                    {
                                        peercounts[block->peerid - 1]++;
                                        if ( peercounts[block->peerid - 1] > maxval )
                                            maxval = peercounts[block->peerid - 1];
                                    }
                                }
                            }
                        }
                    }
                    if ( k > 0 )
                    {
                        if ( (len= iguana_getdata(coin,serialized,MSG_BLOCK,hashes,k)) > 0 )
                        {
                            iguana_send(coin,addr,serialized,len);
                            counter += k;
                            coin->numreqsent += k;
                            addr->pendblocks += k;
                            addr->pendtime = (uint32_t)time(NULL);
                            bp->currentflag += k;
                        }
                        //printf("a%d/%d ",j,k);
                    }
                }
            }
            //printf("doneval.%d maxval.%d\n",doneval,maxval);
            if ( priority != 0 )
            {
                double threshold;
                for (i=nonz=0; i<numpeers; i++)
                    if ( donecounts[i]+peercounts[i] != 0 )
                        nonz++;
                if ( nonz != 0 && total != 0 )
                {
                    threshold = ((double)total / nonz) - 1.;
                    for (i=laggard=finished=0; i<numpeers; i++)
                    {
                        if ( peercounts[i] > threshold )
                            laggard++;
                        if ( peercounts[i] == 0 && donecounts[i] > threshold )
                            finished++;
                    }
                    if ( finished > laggard*10 && numpeers > 2*laggard && laggard > 0 )
                    {
                        for (i=0; i<numpeers; i++)
                        {
                            if ( peercounts[i] > threshold && (addr= coin->peers.ranked[i]) != 0 && now > bp->currenttime+lag && addr->dead == 0 )
                            {
                                if ( numpeers > 64 || addr->laggard++ > 13 )
                                    addr->dead = (uint32_t)time(NULL);
                                for (j=0; j<bp->n; j++)
                                {
                                    if ( (block= bp->blocks[j]) != 0 && block->peerid == i && block->fpipbits == 0 )
                                    {
                                        printf("%d ",j);
                                        flag++;
                                        counter++;
                                        block->peerid = 0;
                                        iguana_blockQ("kick",coin,bp,j,block->RO.hash2,bp == coin->current);
                                        bp->issued[i] = block->issued = now;
                                    }
                                }
                                printf("slow peer.%d dead.%u (%s) reissued.%d\n",i,addr->dead,addr->ipaddr,flag);
                            }
                        }
                    }
                    if ( 0 && laggard != 0 )
                    {
                        for (i=0; i<numpeers; i++)
                            printf("%d ",peercounts[i]);
                        printf("peercounts.%d: finished %d, laggards.%d threshold %f\n",bp->hdrsi,finished,laggard,threshold);
                    }
                }
            }
            for (i=0; i<bp->n; i++)
            {
                if ( (block= bp->blocks[i]) != 0 && block->fpipbits == 0 )
                {
                    if ( now > block->issued+lag )
                    {
                        counter++;
                        if ( priority != 0 )
                        {
                            //printf("[%d:%d] ",bp->hdrsi,i);
                            iguana_blockQ("kicka",coin,bp,i,block->RO.hash2,bp == coin->current && now > block->issued+lag);
                            if ( bp == coin->current && now > block->issued+lag*3 && (addr= coin->peers.ranked[rand() % numpeers]) != 0 )
                                iguana_sendblockreqPT(coin,addr,bp,i,block->RO.hash2,0);
                        } else iguana_blockQ("kickb",coin,bp,i,block->RO.hash2,0);
                        flag++;
                    } //else printf("%d ",now - block->issued);
                }
            }
            if ( flag != 0 && priority != 0 && laggard != 0 && coin->current == bp )
                printf("[%d] reissued.%d currentflag.%d ht.%d s.%d finished.%d most.%d laggards.%d maxunfinished.%d\n",bp->hdrsi,flag,bp->currentflag,bp->bundleheight,bp->numsaved,finished,doneval,laggard,maxval);
         }
        if ( bp == coin->current )
            return(counter);
    }
    for (i=0; i<bp->n; i++)
    {
        if ( (block= bp->blocks[i]) != 0 )
        {
            if ( block->fpipbits == 0 || block->RO.recvlen == 0 || block->fpos < 0 || ((bp->hdrsi != 0 || i > 0) && bits256_nonz(block->RO.prev_block) == 0) )
            {
                if ( block->issued == 0 || now > block->issued+lag )
                {
                    block->numrequests++;
                    if ( bp == coin->current )
                        printf("[%d:%d].%x ",bp->hdrsi,i,block->fpipbits);
                    iguana_blockQ("kickc",coin,bp,i,block->RO.hash2,bp == coin->current);
                    bp->issued[i] = block->issued = now;
                    counter++;
                    if ( --max <= 0 )
                        break;
                }
                //else if ( block->fpipbits != 0 && ((bp->hdrsi == 0 && i == 0) || bits256_nonz(block->RO.prev_block) != 0) )
                  //  n++;
            }
        }
        else if ( bits256_nonz(bp->hashes[i]) != 0 && now > bp->issued[i]+lag )
        {
            if ( bp == coin->current )
                printf("[%d:%d].%x ",bp->hdrsi,i,block->fpipbits);
            iguana_blockQ("kickd",coin,bp,i,bp->hashes[i],bp == coin->current);
            bp->issued[i] = now;
            counter++;
        }
        else if ( bp->speculative != 0 && bits256_nonz(bp->speculative[i]) != 0 && now > bp->issued[i]+lag )
        {
            if ( bp == coin->current )
                printf("[%d:%d].%x ",bp->hdrsi,i,block->fpipbits);
            iguana_blockQ("kicke",coin,bp,i,bp->speculative[i],0);
            bp->issued[i] = now;
            counter++;
        }
    }
    return(counter);
}

int32_t iguana_bundleready(struct iguana_info *coin,struct iguana_bundle *bp)
{
    int32_t i,ready,valid; struct iguana_block *block;
    for (i=ready=0; i<bp->n; i++)
    {
        if ( (block= bp->blocks[i]) != 0 )
        {
            //printf("(%x:%x) ",(uint32_t)block->RO.hash2.ulongs[3],(uint32_t)bp->hashes[i].ulongs[3]);
            if ( block->fpipbits == 0 || (bp->bundleheight+i > 0 && bits256_nonz(block->RO.prev_block) == 0) || iguana_blockvalidate(coin,&valid,block,1) < 0 )
            {
                char str[65]; printf(">>>>>>> ipbits.%x null prevblock error at ht.%d patch.(%s) and reissue\n",block->fpipbits,bp->bundleheight+i,bits256_str(str,block->RO.prev_block));
                block->fpipbits = 0;
                block->fpos = -1;
                block->queued = 0;
                block->RO.recvlen = 0;
                memset(bp->hashes[i].bytes,0,sizeof(bp->hashes[i]));
                bp->blocks[i] = 0;
                //iguana_blockQ("null retry",coin,bp,i,block->RO.hash2,1);
            } else ready++;
        } else printf("error getting block (%d:%d) %p\n",bp->hdrsi,i,block);
    }
    return(ready);
}

int32_t iguana_bundlehdr(struct iguana_info *coin,struct iguana_bundle *bp,int32_t starti)
{
    int32_t counter=0;
    //if ( bp->speculative != 0 )
    //    printf("hdr ITERATE bundle.%d vs %d: h.%d n.%d r.%d s.%d finished.%d speculative.%p\n",bp->bundleheight,coin->longestchain-coin->chain->bundlesize,bp->numhashes,bp->n,bp->numrecv,bp->numsaved,bp->emitfinish,bp->speculative);
    int32_t i; uint32_t now;
    if ( coin->enableCACHE != 0 && bp->speculative == 0 && bp->numhashes < bp->n )
    {
        char str[64];
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(bits256_str(str,bp->hashes[0])),1);
    }
    if ( bp->speculative != 0 )
    {
        now = (uint32_t)time(NULL);
        for (i=0; i<bp->numspec; i++)
        {
            if ( bits256_nonz(bp->hashes[i]) == 0 && bits256_nonz(bp->speculative[i]) != 0 )
            {
                if ( now > bp->issued[i]+60 )
                {
                    bp->issued[i] = now;
                    //printf("speculative.[%d:%d]\n",bp->hdrsi,i);
                    iguana_blockQ("speculative",coin,0,-1,bp->speculative[i],0);
                }
                //break;
            }
            //else if ( bp->blocks[i] == 0 )
              //  break;
        }
    }
    return(counter);
}

int32_t iguana_bundletweak(struct iguana_info *coin,struct iguana_bundle *bp)
{
    struct iguana_bundle *lastbp;
    if ( coin->current == bp )
        coin->current = coin->bundles[bp->hdrsi+1];
    if ( (lastbp= coin->lastpending) != 0 && lastbp->hdrsi < coin->bundlescount-1 )
        coin->lastpending = coin->bundles[lastbp->hdrsi + 1];
    if ( (rand() % 3) == 0 )
    {
        if ( coin->MAXBUNDLES > coin->endPEND )
            coin->MAXBUNDLES--;
        else if ( coin->MAXBUNDLES < coin->endPEND )
            coin->MAXBUNDLES++;
    }
    return(coin->MAXBUNDLES);
}

int64_t iguana_bundlecalcs(struct iguana_info *coin,struct iguana_bundle *bp)
{
    int32_t bundlei,checki,hdrsi,numhashes,numsaved,numcached,numrecv,minrequests; FILE *fp;
    int64_t datasize; struct iguana_block *block; uint32_t now;  char fname[1024]; static bits256 zero;
    if ( bp->emitfinish > coin->startutc )
    {
        bp->numhashes = bp->numsaved = bp->numcached = bp->numrecv = bp->n;
        return(bp->datasize);
    }
    now = (uint32_t)time(NULL);
    datasize = numhashes = numsaved = numcached = numrecv = minrequests = 0;
    for (bundlei=0; bundlei<bp->n; bundlei++)
    {
        block = bp->blocks[bundlei];
        if ( bits256_nonz(bp->hashes[bundlei]) > 0 && block != 0 )
        {
            checki = iguana_peerfname(coin,&hdrsi,GLOBALTMPDIR,fname,0,bp->hashes[bundlei],bundlei>0?bp->hashes[bundlei-1]:zero,1);
            if ( bits256_cmp(block->RO.hash2,bp->hashes[bundlei]) == 0 )
            {
                if ( checki != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
                {
                    printf("iguana_bundlecalcs.(%s) illegal hdrsi.%d bundlei.%d checki.%d\n",fname,hdrsi,bundlei,checki);
                    continue;
                }
                if ( coin->current == bp )
                {
                    if ( (fp= fopen(fname,"rb")) != 0 )
                    {
                        fseek(fp,0,SEEK_END);
                        block->RO.recvlen = (uint32_t)ftell(fp);
                        block->fpipbits = 1;
                        block->fpos = 0;
                        //printf("fp.[%d:%d] len.%d\n",hdrsi,bundlei,block->RO.recvlen);
                        fclose(fp);
                    }
                    else
                    {
                        //char str[65]; printf("missing.(%s) issue.%s\n",fname,bits256_str(str,bp->hashes[bundlei]));
                        block->RO.recvlen = 0;
                        block->fpipbits = 0;
                        block->fpos = -1;
                        //iguana_blockQ("missing",coin,0,-1,block->RO.hash2,1);
                    }
                }
                block->hdrsi = bp->hdrsi, block->bundlei = bundlei;
                if ( bp->minrequests == 0 || (block->numrequests > 0 && block->numrequests < bp->minrequests) )
                    bp->minrequests = block->numrequests;
                if ( (bp->hdrsi == 0 && bundlei == 0) || bits256_nonz(block->RO.prev_block) > 0 )
                {
                    if ( block->queued != 0 )
                        numcached++;
                    if ( block->fpipbits != 0 && block->fpos >= 0 )
                        numsaved++;
                    if ( block->RO.recvlen != 0 || block->fpipbits != 0 || block->fpos >= 0 )
                    {
                        numrecv++;
                        datasize += block->RO.recvlen;
                     }
                }
                else if ( bp == coin->current )
                {
                    char str[65]; printf("missing [%d:%d] %s\n",bp->hdrsi,bundlei,bits256_str(str,bp->hashes[bundlei]));
                    if ( now > bp->issued[bundlei]+10 )
                        iguana_blockQ("missing",coin,bp,bundlei,bp->hashes[bundlei],0);
                }
            }
            /*else
            {
                char str[65],str2[65]; printf(" mismatched [%d:%d] %s vs %s\n",bp->hdrsi,bundlei,bits256_str(str,bp->hashes[bundlei]),bits256_str(str2,block->RO.hash2));
                //iguana_blockQ("missing",coin,0,-1,block->RO.hash2,1);
                bp->issued[bundlei] = 0;
                bp->blocks[bundlei] = 0;
                memset(bp->hashes[bundlei].bytes,0,sizeof(bp->hashes[bundlei]));
                OS_removefile(fname,0);
            }*/
            numhashes++;
            bp->checkedtmp++;
        }
        else if ( bp == coin->current )
        {
            if ( bp->speculative != 0 && bits256_nonz(bp->speculative[bundlei]) != 0 && bits256_nonz(bp->hashes[bundlei]) == 0 && time(NULL) > bp->issued[bundlei]+60 )
            {
                //char str[65]; printf(" mismatched [%d:%d] %s block.%p\n",bp->hdrsi,bundlei,bits256_str(str,bp->speculative[bundlei]),block);
                iguana_blockQ("missing",coin,0,-1,bp->speculative[bundlei],0);
                bp->issued[bundlei] = (uint32_t)time(NULL);
            }
        }
    }
    bp->datasize = datasize;
    bp->numhashes = numhashes;
    bp-> numsaved = numsaved;
    bp->numcached = numcached;
    bp->numrecv = numrecv;
    bp->minrequests = minrequests;
    bp->estsize = ((int64_t)bp->datasize * bp->n) / (bp->numrecv+1);
    return(bp->estsize);
}

int32_t iguana_bundlefinish(struct iguana_info *coin,struct iguana_bundle *bp)
{
    struct iguana_bundle *prevbp; int32_t i,retval;
    if ( coin->MAXMEM <= 4*(1024L * 1024 * 1024) )
    {
        if ( (prevbp= coin->current) != 0 && prevbp->hdrsi < (coin->longestchain / coin->chain->bundlesize)-0*coin->MAXBUNDLES )
            return(0);
    }
    for (i=0; i<bp->hdrsi; i++)
        if ( (prevbp= coin->bundles[i]) == 0 || prevbp->emitfinish < coin->startutc )
            break;
    if ( i == bp->hdrsi )
    {
        if ( bp->startutxo == 0 )
        {
            bp->startutxo = (uint32_t)time(NULL);
            if ( (retval= iguana_utxogen(coin,bp)) >= 0 )
            {
                if ( retval > 0 )
                {
                    printf("GENERATED UTXO.%d for ht.%d duration %d seconds\n",bp->hdrsi,bp->bundleheight,(uint32_t)time(NULL)-bp->startutxo);
                    bp->utxofinish = (uint32_t)time(NULL);
                    bp->balancefinish = 0;
                }
                if ( bp->balancefinish <= 1 )
                    iguana_balancesQ(coin,bp);
                return(1);
            } else printf("UTXO gen.[%d] utxo error\n",bp->hdrsi);
        }
        else if ( bp->utxofinish != 0 )
        {
            iguana_balancesQ(coin,bp);
            return(1);
        }
    } // else printf("%u notready postfinish.%d startutxo.%u prevbp.%d %u current.%d\n",(uint32_t)time(NULL),bp->hdrsi,bp->startutxo,prevbp!=0?prevbp->hdrsi:-1,prevbp!=0?prevbp->emitfinish:0,coin->current!=0?coin->current->hdrsi:-1);
    return(0);
}

int32_t iguana_bundleiters(struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_bundle *bp,int32_t timelimit)
{
    int32_t range,starti,lasti,checki,retval=0,max,bundlei,hdrsi,counter = 0; char fname[1024]; struct iguana_bundle *currentbp,*lastbp; FILE *fp; static bits256 zero;
    if ( coin->started == 0 )
    {
        printf("%s not ready yet\n",coin->symbol);
        bp->nexttime = (uint32_t)time(NULL) + 3;
        iguana_bundleQ(coin,bp,1000);
        return(retval);
    }
    if ( coin->current == 0 )
        coin->current = coin->bundles[0];
    range = coin->MAXBUNDLES;
    currentbp = coin->current;
    lastbp = coin->lastpending;
    starti = currentbp == 0 ? 0 : currentbp->hdrsi;
    lasti = lastbp == 0 ? coin->bundlescount-1 : lastbp->hdrsi;
    iguana_bundlecalcs(coin,bp);
    //printf("ITER now.%u spec.%-4d bundle.%-4d h.%-4d r.%-4d s.%-4d F.%d T.%d issued.%d mb.%d/%d\n",(uint32_t)time(NULL),bp->numspec,bp->bundleheight/coin->chain->bundlesize,bp->numhashes,bp->numrecv,bp->numsaved,bp->emitfinish,timelimit,counter,coin->MAXBUNDLES,coin->bundlescount);
    bp->nexttime = (uint32_t)(time(NULL) + 1);//(bp->hdrsi - starti) + 1);
    if ( bp->numhashes < bp->n && bp->bundleheight < coin->longestchain-coin->chain->bundlesize )
        iguana_bundlehdr(coin,bp,starti);
    else if ( bp->emitfinish != 0 )
    {
        bp->nexttime += 10;
        if ( bp->emitfinish > 1 )
        {
            if ( (retval= iguana_bundlefinish(coin,bp)) > 0 )
            {
                //printf("moved to balancesQ.%d bundleiters.%d\n",bp->hdrsi,bp->bundleheight);
                bp->queued = 0;
                return(0);
            } //else printf("finish incomplete.%d\n",bp->hdrsi);
        }
    }
    else if ( bp->numsaved >= bp->n )
    {
        if ( iguana_bundleready(coin,bp) == bp->n )
        {
            printf(">>>>>>>>>>>>>>>>>>>>>>> EMIT.%s bundle.%d | 1st.%d h.%d s.[%d] maxbundles.%d NET.(h%d b%d)\n",coin->symbol,bp->bundleheight,coin->current!=0?coin->current->hdrsi:-1,coin->current!=0?coin->current->numhashes:-1,coin->current!=0?coin->current->numsaved:-1,coin->MAXBUNDLES,HDRnet,netBLOCKS);
            bp->emitfinish = 1;
            iguana_bundletweak(coin,bp);
            sleep(1); // just in case data isnt totally sync'ed to HDD
            if ( 0 )
                iguana_emitQ(coin,bp);
            else
            {
                if ( iguana_bundlesaveHT(coin,mem,memB,bp,(uint32_t)time(NULL)) == 0 )
                {
                    //fprintf(stderr,"emitQ done coin.%p bp.[%d] ht.%d\n",coin,bp->hdrsi,bp->bundleheight);
                    bp->emitfinish = (uint32_t)time(NULL) + 1;
                    coin->numemitted++;
                }
                else
                {
                    fprintf(stderr,"emitQ done coin.%p bp.[%d] ht.%d error\n",coin,bp->hdrsi,bp->bundleheight);
                    bp->emitfinish = 0;
                }
            }
        }
        retval = 1;
    }
    else if ( bp->hdrsi >= starti && bp->hdrsi <= starti+range )
    {
        max = bp->n;
        counter = iguana_bundleissue(coin,bp,max,timelimit);
        if ( bp->hdrsi == starti && counter > 0 )
            printf("ITER now.%u spec.%-4d bundle.%-4d h.%-4d r.%-4d s.%-4d F.%d T.%d issued.%d mb.%d/%d\n",(uint32_t)time(NULL),bp->numspec,bp->bundleheight/coin->chain->bundlesize,bp->numhashes,bp->numrecv,bp->numsaved,bp->emitfinish,timelimit,counter,coin->MAXBUNDLES,coin->bundlescount);
        if ( 0 && coin->blocks.hwmchain.height > coin->chain->bundlesize && bp->hdrsi == coin->blocks.hwmchain.height/coin->chain->bundlesize )
        {
            for (bundlei=0; bundlei<bp->n; bundlei++)
            {
                checki = iguana_peerfname(coin,&hdrsi,GLOBALTMPDIR,fname,0,bp->hashes[bundlei],bundlei>0?bp->hashes[bundlei-1]:zero,1);
                if ( checki == bundlei )
                {
                    if ( (fp= fopen(fname,"rb")) != 0 )
                        fclose(fp);
                    else break;
                }
            }
            if ( bp == coin->current && (bp->ramchain.H.data == 0 || bp->ramchain.H.data->numblocks != bundlei) )
            {
                printf("RT bundls\n");
                if ( iguana_bundlesaveHT(coin,mem,memB,bp,(uint32_t)time(NULL)) == 0 )
                {
                    
                }
            }
        }
    }
    iguana_bundleQ(coin,bp,1000);
    return(retval);
}

/*static int _decreasing_double(const void *a,const void *b)
{
#define double_a (*(double *)a)
#define double_b (*(double *)b)
	if ( double_b > double_a )
		return(1);
	else if ( double_b < double_a )
		return(-1);
	return(0);
#undef double_a
#undef double_b
}

static int32_t revsortds(double *buf,uint32_t num,int32_t size)
{
	qsort(buf,num,size,_decreasing_double);
	return(0);
}*/

void iguana_bundlestats(struct iguana_info *coin,char *str)
{
    int32_t i,n,m,j,numv,count,pending,dispflag,numutxo,numbalances,numrecv,done,numhashes,numcached,numsaved,numemit;
    int64_t spaceused=0,estsize = 0; struct iguana_bundle *bp,*lastpending = 0,*firstgap = 0; struct iguana_block *block,*prev; uint32_t now;
    now = (uint32_t)time(NULL);
    dispflag = 1;//(rand() % 1000) == 0;
    numrecv = numhashes = numcached = numsaved = numemit = done = numutxo = numbalances = 0;
    count = coin->bundlescount;
    //sortbuf = calloc(count,sizeof(*sortbuf)*2);
    for (i=n=m=numv=pending=0; i<count; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            if ( bp->emitfinish > 1 )
            {
                for (j=0; j<bp->n; j++)
                    if ( bp->blocks[j] == 0 )
                        bp->blocks[j] = iguana_blockfind(coin,bp->hashes[j]);
            }
            //if ( iguana_blockfind(coin,bp->hashes[0]) == 0 )
            //    printf("UNEXPECTED null block for bundlehash.%d\n",bp->hdrsi);
            if ( bp->numhashes < bp->n && bp->speculative != 0 )
            {
                //for (j=1; j<bp->numspec&&j<bp->n; j++)
                //    iguana_blockhashset(coin,-1,bp->speculative[j],1);
                //char str[65],str2[65];
                for (j=1; j<bp->numspec&&j<bp->n; j++)
                {
                    if ( (block= bp->blocks[j]) == 0 )
                    {
                        if ( bits256_nonz(bp->hashes[j]) != 0 )
                            block = iguana_blockfind(coin,bp->hashes[j]);
                        else if ( bits256_nonz(bp->speculative[j]) != 0 )
                        {
                            if ( (block= iguana_blockfind(coin,bp->speculative[j])) == 0 )
                                block = iguana_blockhashset(coin,-1,bp->speculative[j],1);
                        }
                    }
                    else if ( bits256_nonz(block->RO.prev_block) != 0 && block->fpipbits != 0 )
                        continue;
                    prev = bp->blocks[j-1];
                    //printf("[%d:%d] prev.%p nonz.%d speculative.%d block.%p\n",bp->hdrsi,j,bp->blocks[j-1],bits256_nonz(bp->hashes[j]),bits256_nonz(bp->speculative[j]),bp->blocks[j]);
                    if ( block != 0 && bp->blocks[j] == 0 ) //prev != 0 && 
                    {
                        //char str2[65]; printf("[%d:%d] prev.%p nonz.%d speculative.%d prev.%s vs %s ipbits.%x q.%d\n",bp->hdrsi,j,bp->blocks[j-1],bits256_nonz(bp->hashes[j]),bits256_nonz(bp->speculative[j]),bits256_str(str,prev->RO.hash2),bits256_str(str2,block->RO.prev_block),block->fpipbits,block->queued);
                        if ( block->fpipbits == 0 && block->queued == 0 )
                        {
                            if ( block->req != 0 )
                            {
                                block->queued = 1;
                                queue_enqueue("cacheQ",&coin->cacheQ,&block->req->DL,0);
                                block->req = 0;
                                //printf("submit cached [%d:%d]\n",bp->hdrsi,j);
                            }
                            else if ( now > block->issued+10 )
                            {
                                block->issued = now;
                                //printf("submit speculative [%d:%d]\n",bp->hdrsi,j);
                                iguana_blockQ("spec",coin,0,-1,block->RO.hash2,0);
                            }
                        }
                    } // else break;
                }
            }
            //bp->rank = 0;
            estsize += bp->estsize;//iguana_bundlecalcs(coin,bp,done);
            //bp->metric = bp->numhashes;
            bp->metric = coin->bundlescount - bp->hdrsi;
            if ( done > coin->bundlescount*IGUANA_HEADPERCENTAGE && bp->hdrsi > coin->bundlescount*IGUANA_TAILPERCENTAGE )
                bp->metric *= 1000;
            numhashes += bp->numhashes;
            numcached += bp->numcached;
            numrecv += bp->numrecv;
            numsaved += bp->numsaved;
            if ( bp->utxofinish > 1 )
                numutxo++;
            if ( bp->balancefinish > 1 )
                numbalances++;
            if ( bp->validated != 0 )
                numv++;
            if ( bp->emitfinish > 1 )
            {
                done++;
                numemit++;
                if ( firstgap != 0 && bp->hdrsi > firstgap->hdrsi-3 )
                    iguana_bundlepurge(coin,bp);
            }
            else
            {
                if ( ++pending == coin->MAXBUNDLES )
                {
                    lastpending = bp;
                    //printf("SET MAXBUNDLES.%d pend.%d\n",bp->hdrsi,pending);
                }
                if ( firstgap == 0 && (bp->emitfinish == 0 || bp->n < coin->chain->bundlesize) )
                {
                    //printf("firstgap <- [%d] emit.%u bp->n.%d\n",bp->hdrsi,bp->emitfinish,bp->n);
                    firstgap = bp;
                }
                if ( bp->emitfinish == 0 )
                {
                    spaceused += bp->estsize;
                    //sortbuf[m*2] = bp->metric;
                    //sortbuf[m*2 + 1] = i;
                    m++;
                }
            }
        }
    }
    /*if ( m > 0 )
    {
        revsortds(sortbuf,m,sizeof(*sortbuf)*2);
        for (i=0; i<m; i++)
        {
            if ( (bp= coin->bundles[(int32_t)sortbuf[i*2 + 1]]) != 0 )
            {
                bp->rank = i + 1;
                if ( coin->peers.numranked > 0 && i < coin->peers.numranked && (addr= coin->peers.ranked[i]) != 0 )
                    addr->bp = bp;
            }
        }
    }
    free(sortbuf);*/
    coin->numremain = n;
    coin->blocksrecv = numrecv;
    char str2[65]; uint64_t tmp; int32_t diff,p = 0; struct tai difft,t = tai_now();
    for (i=0; i<IGUANA_MAXPEERS; i++)
        if ( coin->peers.active[i].usock >= 0 )
            p++;
    diff = (int32_t)time(NULL) - coin->startutc;
    difft.x = (t.x - coin->starttime.x), difft.millis = (t.millis - coin->starttime.millis);
    tmp = (difft.millis * 1000000);
    tmp %= 1000000000;
    difft.millis = ((double)tmp / 1000000.);
    if ( (coin->current= firstgap) == 0 )
    {
        firstgap = coin->current = (coin->bundlescount > 0) ? coin->bundles[coin->bundlescount-1] : coin->bundles[0];
        //printf("bundlescount.%d %p[%d]\n",coin->bundlescount,coin->current,coin->current->hdrsi);
    }
    if ( lastpending != 0 )
        coin->lastpending = lastpending;
    else coin->lastpending = coin->bundles[coin->bundlescount - 1];
    coin->numsaved = numsaved;
    coin->spaceused = spaceused;
    coin->numverified = numv;
    char str4[65],str5[65];
    sprintf(str,"%s u.%d b.%d v.%d/%d (%d 1st.%d) to %d N[%d] Q.%d h.%d r.%d c.%s s.%d d.%d E.%d:%d est.%d %s %d:%02d:%02d %03.3f peers.%d/%d Q.(%d %d) L.%d [%d:%d] M.%d %s",coin->symbol,numutxo,numbalances,numv,coin->pendbalances,firstgap!=0?firstgap->numsaved:-1,firstgap!=0?firstgap->hdrsi:-1,coin->lastpending!=0?coin->lastpending->hdrsi:0,count,coin->numbundlesQ,numhashes,coin->blocksrecv,mbstr(str4,spaceused),numsaved,done,numemit,coin->numreqsent,coin->MAXBUNDLES,mbstr(str2,estsize),(int32_t)difft.x/3600,(int32_t)(difft.x/60)%60,(int32_t)difft.x%60,difft.millis,p,coin->MAXPEERS,queue_size(&coin->priorityQ),queue_size(&coin->blocksQ),coin->longestchain,coin->blocks.hwmchain.height/coin->chain->bundlesize,coin->blocks.hwmchain.height%coin->chain->bundlesize,coin->blocks.hwmchain.height,bits256_str(str5,coin->blocks.hwmchain.RO.hash2));
    //sprintf(str+strlen(str),"%s.%-2d %s time %.2f files.%d Q.%d %d\n",coin->symbol,flag,str,(double)(time(NULL)-coin->starttime)/60.,coin->peers.numfiles,queue_size(&coin->priorityQ),queue_size(&coin->blocksQ));
    if ( time(NULL) > coin->lastdisp+10 )
    {
        printf("%s\n",str);
        if ( (rand() % 100) == 0 )
            myallocated(0,0);
        coin->lastdisp = (uint32_t)time(NULL);
        if ( firstgap != 0 && firstgap->queued == 0 )
            iguana_bundleQ(coin,firstgap,1000);
    }
    strcpy(coin->statusstr,str);
    coin->estsize = estsize;
}

