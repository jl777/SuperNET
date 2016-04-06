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
    struct iguana_block *block =0; struct iguana_bundle *otherbp;
    int32_t otherbundlei,setval,bundlesize,err = 0;
    if ( blockp != 0 )
        *blockp = 0;
    if ( bp == 0 || bits256_nonz(hash2) == 0 )
        return(-1111);
    if ( bits256_nonz(hash2) != 0 && (block= iguana_blockhashset("bundlehash2add",coin,-1,hash2,1)) != 0 )
    {
        if ( bp->blocks[bundlei] != 0 && bp->blocks[bundlei] != block )
        {
            printf("bp->blocks[%d] mismatch %p != %p\n",bundlei,bp->blocks[bundlei],block);
            bp->blocks[bundlei] = 0;
            return(-1);
        }
        if ( bits256_nonz(bp->hashes[bundlei]) != 0 && bits256_cmp(bp->hashes[bundlei],block->RO.hash2) != 0 )
        {
            char str[65],str2[65];
            printf("bp->hashes[%d] mismatch %s != %s%s\n",bundlei,bits256_str(str,bp->hashes[bundlei]),bits256_str(str2,block->RO.hash2),block->mainchain?".main":"");
            //if ( block->mainchain != 0 )
              //  bp->hashes[bundlei] = block->RO.hash2;
            
            return(-1);
        }
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
                char str[65]; printf("blockadd warning: %d[%d] <- %d[%d] %s\n",block->hdrsi,block->bundlei,bp->hdrsi,bundlei,bits256_str(str,hash2));
                err |= 2;
                return(-1);
                //exit(-1);
            }
            else
            {
                char str[65];
                block->hdrsi = bp->hdrsi;
                block->bundlei = bundlei;
                bp->hashes[bundlei] = block->RO.hash2;
                if ( bp->speculative != 0 && bundlei < bp->numspec )
                    bp->speculative[bundlei] = bp->hashes[bundlei];
                if ( bp->blocks[bundlei] == 0 )
                    bp->blocks[bundlei] = block;
                else if ( bp->blocks[bundlei] != block )
                    printf(">>>>>>>>>>>>>> bundlehash2.(%s) ht.(%d %d) block.%p there\n",bits256_str(str,hash2),bp->bundleheight,bundlei,bp->blocks[bundlei]);
                otherbp = 0, otherbundlei = -2;
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
    char str[65],dirname[1024]; struct iguana_bundle *prevbp,*bp = 0;
    if ( bits256_nonz(bundlehash2) > 0 )
    {
        bits256_str(str,bundlehash2);
        bp = 0, *bundleip = -2;
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
            if ( bp->hdrsi > 0 )
            {
                if ( (prevbp= coin->bundles[bp->hdrsi-1]) != 0 )
                {
                    prevbp->nextbp = bp;
                    prevbp->nextbundlehash2 = bundlehash2;
                }
            }
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
    static const bits256 zero;
    int32_t hdrsi,iter; int64_t Toffset; char fname[1024]; FILE *fp; struct iguana_ramchaindata rdata;
    for (iter=0; iter<2; iter++)
    {
        iguana_peerfname(coin,&hdrsi,iter==0?"DB/ro":"DB",fname,0,bp->hashes[0],zero,bp->n,1);
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

void iguana_bundlepurgefiles(struct iguana_info *coin,struct iguana_bundle *bp)
{
    static const bits256 zero;
    char fname[1024]; int32_t hdrsi,m,j; uint32_t ipbits;
    if ( bp->purgetime == 0 && time(NULL) > bp->emitfinish+30 )
    {
        for (j=m=0; j<sizeof(coin->peers.active)/sizeof(*coin->peers.active); j++)
        {
            if ( (ipbits= (uint32_t)coin->peers.active[j].ipbits) != 0 )
            {
                if ( iguana_peerfname(coin,&hdrsi,GLOBALTMPDIR,fname,ipbits,bp->hashes[0],zero,1,1) >= 0 )
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

uint8_t iguana_recentpeers(struct iguana_info *coin,int32_t *capacityp,struct iguana_peer *peers[])
{
    struct iguana_peer *addr; uint8_t m; int32_t capacity,i,n = coin->peers.numranked;
    for (i=m=capacity=0; i<n&&m<0xff; i++)
    {
        if ( (addr= coin->peers.ranked[i]) != 0 && addr->dead == 0 && addr->usock >= 0 && addr->msgcounts.verack != 0 && addr->pendblocks < coin->MAXPENDINGREQUESTS )
        {
            if ( peers != 0 )
                peers[m] = addr;
            m++;
            capacity += (coin->MAXPENDINGREQUESTS - addr->pendblocks);
        }
    }
    *capacityp = capacity;
    return(m);
}

struct iguana_block *iguana_bundleblock(struct iguana_info *coin,bits256 *hash2p,struct iguana_bundle *bp,int32_t i)
{
    struct iguana_bundle *nextbp; struct iguana_block *block = 0;
    memset(hash2p,0,sizeof(*hash2p));
    if ( bp == 0 )
        return(0);
    if ( i == bp->n )
    {
        if ( bits256_nonz(bp->nextbundlehash2) != 0 )
        {
            if ( bp->hdrsi < coin->bundlescount && (nextbp= coin->bundles[bp->hdrsi+1]) != 0 )
            {
                *hash2p = nextbp->hashes[0];
                return(nextbp->blocks[0]);
            }
        } else return(0);
    }
    if ( block != 0 || (block= bp->blocks[i]) != 0 )//|| bits256_nonz(bp->hashes[i]) != 0 )//&& (block= iguana_blockfind("bundleblock2",coin,bp->hashes[i])) != 0) )
    {
        *hash2p = block->RO.hash2;
        return(block);
    }
    else if ( bp->speculative != 0 && bits256_nonz(bp->speculative[i]) != 0 )
    {
        *hash2p = bp->speculative[i];
        block = bp->blocks[i];//iguana_blockfind("speculative",coin,bp->speculative[i]);
        //char str[65]; printf("[%d:%d] %s\n",bp->hdrsi,i,bits256_str(str,*hash2p));
    }
    return(block);
}

int32_t iguana_blocksmissing(struct iguana_info *coin,int32_t *nonzp,uint8_t missings[IGUANA_MAXBUNDLESIZE/8+1],bits256 hashes[],double mult,struct iguana_bundle *bp,int32_t capacity)
{
    int32_t i,lag,nonz=0,m = 0; double aveduration; bits256 hash2; struct iguana_block *block; uint32_t now = (uint32_t)time(NULL);
    if ( bp->durationscount != 0 )
        aveduration = (double)bp->totaldurations / bp->durationscount;
    else aveduration = IGUANA_DEFAULTLAG/3 + 1;
    aveduration *= mult;
    lag = aveduration;
    if ( lag > IGUANA_DEFAULTLAG )
        lag = IGUANA_DEFAULTLAG * 8;
    memset(missings,0,IGUANA_MAXBUNDLESIZE/8+1);
    if ( bp->emitfinish == 0 )
    {
        for (i=0; i<bp->n; i++)
        {
            if ( bp->speculativecache[i] != 0 )
            {
                //printf("[%d:%d].havec ",bp->hdrsi,i);
                continue;
            }
            if ( (block= iguana_bundleblock(coin,&hash2,bp,i)) != 0 )
            {
                if ( block->txvalid != 0 || block->fpos < 0 || block->fpipbits != 0 || block->RO.recvlen != 0 )
                {
                    //printf("[%d:%d].block ",bp->hdrsi,i);
                    continue;
                }
            }
            if ( bits256_nonz(hash2) != 0 )
            {
                if ( now > bp->issued[i]+lag )
                {
                    if ( nonz < capacity )
                    {
                        if ( hashes != 0 )
                            hashes[nonz] = hash2;
                        nonz++;
                    }
                }
            }
            SETBIT(missings,i);
            m++;
        }
    } //else printf("[%d] emitfinish.%u\n",bp->hdrsi,bp->emitfinish);
    *nonzp = nonz;
    //printf("missings.[%d] m.%d nonz.%d spec.%p[%d]\n",bp->hdrsi,m,nonz,bp->speculative,bp->numspec);
    return(m);
}

int32_t iguana_sendhashes(struct iguana_info *coin,struct iguana_peer *addr,int32_t msgtype,bits256 hashes[],int32_t n,int32_t priority)
{
    int32_t len; uint8_t *serialized;
    if ( priority > 1 )
    {
        serialized = malloc((sizeof(int32_t) + sizeof(*hashes))*n + 1024);
        if ( (len= iguana_getdata(coin,serialized,MSG_BLOCK,hashes,n)) > 0 )
        {
            if ( len > (sizeof(int32_t) + sizeof(*hashes))*n + 1024 )
            {
                printf("FATAL ERROR iguana_sendhashes: len.%d size.%ld\n",len,(sizeof(int32_t) + sizeof(*hashes))*n + 1024);
                exit(-1);
            }
            iguana_send(coin,addr,serialized,len);
            coin->numreqsent += n;
            addr->pendblocks += n;
            addr->pendtime = (uint32_t)time(NULL);
            //printf("sendhashes[%d] -> %s\n",n,addr->ipaddr);
        } else n = 0;
        free(serialized);
    }
    else
    {
        int32_t i;
        for (i=0; i<n; i++)
        {
            if ( priority == 1 )
                iguana_sendblockreqPT(coin,addr,0,-1,hashes[i],0);
            else iguana_blockQ("sendhash",coin,0,-1,hashes[i],1);
        }
    }
    return(n);
}

int32_t iguana_nextnonz(uint8_t *missings,int32_t i,int32_t max)
{
    for (; i<max; i++)
        if ( GETBIT(missings,i) != 0 )
            break;
    return(i);
}

int32_t iguana_bundlerequests(struct iguana_info *coin,uint8_t missings[IGUANA_MAXBUNDLESIZE/8+1],int32_t *missingp,int32_t *capacityp,double mult,struct iguana_bundle *bp,int32_t priority)
{
    uint8_t numpeers; int32_t i,j,avail,nonz=0,c,n,m=0,max,capacity,numsent; bits256 hashes[500],hash2;
    struct iguana_block *block; struct iguana_peer *peers[256],*addr; uint32_t now = (uint32_t)time(NULL);
    max = (int32_t)(sizeof(hashes) / sizeof(*hashes));
    *missingp = *capacityp = 0;
    if ( (numpeers= iguana_recentpeers(coin,&capacity,peers)) > 0 )
    {
        *capacityp = capacity;
        if ( (n= iguana_blocksmissing(coin,&avail,missings,hashes,mult,bp,capacity < max ? capacity : max)) > 0 && avail > 0 )
        {
            *missingp = n;
            //printf("n.%d avail.%d numpeers.%d\n",n,avail,numpeers);
            for (i=0; i<numpeers && avail>0; i++)
            {
                if ( (addr= peers[i]) != 0 && (c= (coin->MAXPENDINGREQUESTS - addr->pendblocks)) > 0  )
                {
                    if ( c+m > max )
                        c = max - m;
                    if ( avail < c )
                        c = avail;
                    //printf("i.%d c.%d avail.%d m.%d max.%d\n",i,c,avail,m,max);
                    if ( c > 0 && (numsent= iguana_sendhashes(coin,addr,MSG_BLOCK,&hashes[m],c,priority)) > 0 )
                    {
                        for (j=0; j<numsent; j++)
                        {
                            if ( (nonz= iguana_nextnonz(missings,nonz,bp->n)) < bp->n )
                            {
                                if ( (block= iguana_bundleblock(coin,&hash2,bp,nonz)) != 0 )
                                {
                                    hash2 = block->RO.hash2;
                                    if ( addr->addrind < 0x100 )
                                        block->peerid = addr->addrind;
                                    else block->peerid = 0;
                                    block->issued = now;
                                }
                                bp->issued[nonz] = now;
                                //char str[65]; printf("issue.[%d:%d] %s %u\n",bp->hdrsi,nonz,bits256_str(str,hash2),now);
                                nonz++;
                            } else printf("bundlerequests unexpected nonz.%d c.%d m.%d n.%d numsent.%d i.%d\n",nonz,c,m,n,numsent,i);
                        }
                        m += numsent;
                        avail -= numsent;
                    }
                }
            }
        } //else printf("err avail.%d n.%d\n",avail,n);
    } //else printf("numpeers.%d\n",numpeers);
    return(m);
}

int32_t iguana_bundleready(struct iguana_info *coin,struct iguana_bundle *bp)
{
    int32_t i,ready,valid; struct iguana_block *block; int32_t sum[0x100],counts[0x100];
    memset(sum,0,sizeof(sum));
    memset(counts,0,sizeof(counts));
    for (i=ready=0; i<bp->n; i++)
    {
        if ( (block= bp->blocks[i]) != 0 )
        {
            if ( block->lag != 0 && block->peerid != 0 )
            {
                sum[block->peerid] += block->lag;
                counts[block->peerid]++;
            }
            //printf("(%x:%x) ",(uint32_t)block->RO.hash2.ulongs[3],(uint32_t)bp->hashes[i].ulongs[3]);
            if ( iguana_blockvalidate(coin,&valid,block,1) < 0 || block->fpipbits == 0 || block->fpos < 0 || (bp->bundleheight+i > 0 && bits256_nonz(block->RO.prev_block) == 0) )
            {
                printf(">>>>>>> block contents error at ht.%d [%d:%d]\n",bp->bundleheight+i,bp->hdrsi,i);
                //char str[65];  patch.(%s) and reissue %s checki.%d vs %d\n",block->fpipbits,bp->bundleheight+i,bits256_str(str,block->RO.prev_block),fname,checki,i);
                iguana_blockunmark(coin,block,bp,i,1);
            } else ready++;
        }
        else
        {
            printf("error getting block (%d:%d) %p\n",bp->hdrsi,i,block);
            return(-1);
        }
    }
    return(ready);
}

int32_t iguana_bundleissuemissing(struct iguana_info *coin,struct iguana_bundle *bp,uint8_t *missings,int32_t priority,double mult)
{
    int32_t i,tmp,tmp2,n; bits256 hash2; double aveduration;
    if ( bp->emitfinish != 0 || (priority == 0 && time(NULL) < bp->missingstime+30) )
        return(0);
    if ( bp->durationscount != 0 )
        aveduration = (double)bp->totaldurations / bp->durationscount;
    else aveduration = IGUANA_DEFAULTLAG/3 + 1;
    aveduration *= mult;
    n = iguana_bundlerequests(coin,missings,&tmp,&tmp2,mult,bp,priority);
    for (i=0; i<bp->n; i++)
    {
        if ( GETBIT(missings,i) != 0 )
        {
            if ( bits256_nonz(bp->hashes[i]) != 0 )
                hash2 = bp->hashes[i];
            else if ( bp->speculative != 0 && bits256_nonz(bp->speculative[i]) != 0 )
                hash2 = bp->speculative[i];
            else continue;
            if ( bits256_nonz(hash2) != 0 )
            {
                if ( 0 && bp == coin->current )
                    printf("iguana_bundleissuemissing.[%d:%d]\n",bp->hdrsi,i);
                iguana_blockQ("missings",coin,bp,i,hash2,1);
            }
        }
    }
    bp->missingstime = (uint32_t)time(NULL);
    return(n);
}

int32_t iguana_bundlehdr(struct iguana_info *coin,struct iguana_bundle *bp,int32_t starti)
{
    //uint8_t missings[IGUANA_MAXBUNDLESIZE/8+1]; int32_t avail;
    int32_t dist,counter=0;
    if ( 0 && bp->isRT == 0 && (bp->hdrsi == coin->bundlescount-1 || bp == coin->current) )
        printf("hdr ITERATE.%d bundle.%d vs %d: h.%d n.%d r.%d s.%d c.%d finished.%d spec.%p[%d]\n",bp->hdrsi,bp->bundleheight,coin->longestchain-coin->chain->bundlesize,bp->numhashes,bp->n,bp->numrecv,bp->numsaved,bp->numcached,bp->emitfinish,bp->speculative,bp->numspec);
    dist = 30 + (coin->current != 0 ? bp->hdrsi - coin->current->hdrsi : 0);
    if ( bp == coin->current )
        dist = 3;
    if ( time(NULL) > bp->hdrtime+dist && (bp == coin->current || bp->hdrsi >= coin->bundlescount-2 || (coin->enableCACHE != 0 && bp->numhashes < bp->n && (bp->speculative == 0 || bp->hdrsi >= coin->longestchain/bp->n))) )
    {
        char str[64];
        bp->hdrtime = (uint32_t)time(NULL);
        if ( bp == coin->current && bp->speculative != 0 )
        {
            //printf("iguana_bundlehdr.[%d] %d %s\n",bp->hdrsi,bp->numspec,bits256_str(str,bp->hashes[0]));
            //if ( iguana_blocksmissing(coin,&avail,missings,0,bp,0,7) > 0 )
            //    iguana_bundleissuemissing(coin,bp,missings,3);
        }
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(bits256_str(str,bp->hashes[0])),1);
    }
    if ( bp->hdrsi == coin->bundlescount-1 && bp->speculative != 0 && bits256_nonz(bp->nextbundlehash2) == 0 )
    {
        if ( time(NULL) > (bp->issued[1] + 10 + dist) )
        {
            //printf("request speculative[1] numspec.%d for bp.[%d] bp->speculative.%p enable.%d\n",bp->numspec,bp->hdrsi,bp->speculative,coin->enableCACHE);
            //iguana_blockQ("getnexthdr",coin,bp,-1,bp->speculative[1],1);
            //bp->issued[1] = (uint32_t)time(NULL);
        }
    }
    return(counter);
}

int32_t iguana_setmaxbundles(struct iguana_info *coin)
{
    double completed;
    if ( coin->current != 0 && coin->bundlescount != 0 )
    {
        completed = sqrt(((double)coin->current->hdrsi + 1) / coin->bundlescount);
        coin->MAXBUNDLES = (double)(coin->endPEND - coin->startPEND)*completed + coin->startPEND;
        //printf("MAXBUNDLES %d (%d -> %d) completed %.3f\n",coin->MAXBUNDLES,coin->startPEND,coin->endPEND,completed);
    }
    return(coin->MAXBUNDLES);
}

int32_t iguana_bundletweak(struct iguana_info *coin,struct iguana_bundle *bp)
{
    struct iguana_bundle *lastbp; int32_t i,pending;
    if ( coin->current == bp )
        coin->current = coin->bundles[bp->hdrsi+1];
    if ( (lastbp= coin->current) != 0 )
    {
        for (pending=0,i=lastbp->hdrsi+1; i<coin->bundlescount; i++)
        {
            if ( (lastbp= coin->bundles[i]) != 0 && lastbp->emitfinish == 0 )
            {
                if ( ++pending == coin->MAXBUNDLES )
                    break;
            }
        }
        coin->lastpending = lastbp;
    }
    iguana_setmaxbundles(coin);
    return(coin->MAXBUNDLES);
}

int64_t iguana_bundlecalcs(struct iguana_info *coin,struct iguana_bundle *bp,int32_t lag)
{
    int32_t bundlei,numhashes,avail,numsaved,numrecv,minrequests; uint8_t missings[IGUANA_MAXBUNDLESIZE/8+1];
    int64_t datasize; struct iguana_block *block;
    if ( bp->emitfinish > 1 )
    {
        bp->numhashes = bp->numsaved = bp->numcached = bp->numrecv = bp->n;
        return(bp->datasize);
    }
    datasize = numhashes = numsaved = numrecv = minrequests = 0;
    for (bundlei=0; bundlei<bp->n; bundlei++)
    {
        if ( bits256_nonz(bp->hashes[bundlei]) > 0 )
        {
            numhashes++;
            if ( (block= bp->blocks[bundlei]) != 0 && bits256_cmp(block->RO.hash2,bp->hashes[bundlei]) == 0 )
            {
                //if ( bp->minrequests == 0 || (block->numrequests > 0 && block->numrequests < bp->minrequests) )
                //    bp->minrequests = block->numrequests;
                if ( block->fpipbits != 0 && block->fpos >= 0 )
                    numsaved++;
                if ( block->RO.recvlen != 0 )
                {
                    numrecv++;
                    datasize += block->RO.recvlen;
                }
            }
        }
    }
    bp->numcached = bp->n - iguana_blocksmissing(coin,&avail,missings,0,1.,bp,0);
    bp->datasize = datasize;
    bp->numhashes = numhashes;
    bp->numsaved = numsaved;
    bp->numrecv = numrecv;
    bp->minrequests = minrequests;
    bp->estsize = ((int64_t)bp->datasize * bp->n) / (bp->numrecv+1);
    return(bp->estsize);
}

int32_t iguana_bundlefinish(struct iguana_info *coin,struct iguana_bundle *bp)
{
    struct iguana_bundle *prevbp; int32_t i;
#ifdef IGUANA_SERIALIZE_SPENDVECTORGEN
    if ( (prevbp= coin->current) != 0 && prevbp->hdrsi < (coin->longestchain / coin->chain->bundlesize) - 0*coin->MAXBUNDLES )
        return(0);
#endif
    for (i=0; i<bp->hdrsi; i++)
        if ( (prevbp= coin->bundles[i]) == 0 || prevbp->emitfinish <= 1 || (prevbp->utxofinish == 0 && prevbp->tmpspends == 0) )
            break;
    if ( bp->hdrsi < coin->blocks.hwmchain.height/coin->chain->bundlesize && i >= bp->hdrsi-IGUANA_NUMHELPERS && time(NULL) > bp->emitfinish+3 )
    {
        //printf("[%d] vs %d i.%d vs %d emitted.%ld (%d %d %d) s.%u f.%u\n",bp->hdrsi,coin->blocks.hwmchain.height/coin->chain->bundlesize,i,bp->hdrsi-IGUANA_NUMHELPERS/2,time(NULL) - bp->emitfinish,bp->hdrsi < coin->blocks.hwmchain.height/coin->chain->bundlesize,i >= bp->hdrsi-IGUANA_NUMHELPERS, time(NULL) > bp->emitfinish,bp->startutxo,bp->utxofinish);
        if ( bp->startutxo == 0 )
        {
            bp->startutxo = (uint32_t)time(NULL);
            //printf("spendvectorsQ.%d\n",bp->hdrsi);
            iguana_spendvectorsQ(coin,bp);
        }
        else if ( bp->utxofinish != 0 )
        {
            if ( bp->balancefinish == 0 )
                iguana_balancesQ(coin,bp);
        }
        return(1);
    }
    //else printf("%u notready.%d postfinish.%d startutxo.%u prevbp.%d %u current.%d\n",(uint32_t)time(NULL),bp->hdrsi,i,bp->startutxo,prevbp!=0?prevbp->hdrsi:-1,prevbp!=0?prevbp->emitfinish:0,coin->current!=0?coin->current->hdrsi:-1);
    return(0);
}

int32_t iguana_bundlefinalize(struct iguana_info *coin,struct iguana_bundle *bp,struct OS_memspace *mem,struct OS_memspace *memB)
{
    if ( iguana_bundleready(coin,bp) == bp->n )
    {
        printf(">>>>>>>>>>>>>>>>>>>>>>> EMIT.%s bundle.%d | 1st.%d h.%d c.%d s.[%d] maxbundles.%d NET.(h%d b%d)\n",coin->symbol,bp->bundleheight,coin->current!=0?coin->current->hdrsi:-1,coin->current!=0?coin->current->numhashes:-1,coin->current!=0?coin->current->numcached:-1,coin->current!=0?coin->current->numsaved:-1,coin->MAXBUNDLES,HDRnet,netBLOCKS);
        if ( bp->emitfinish != 0 )
        {
            printf("already EMIT for bundle.%d\n",bp->hdrsi);
            return(0);
        }
        bp->emitfinish = 1;
        iguana_bundletweak(coin,bp);
        sleep(1); // just in case data isnt totally sync'ed to HDD
        coin->emitbusy++;
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
        coin->emitbusy--;
    }
    return(1);
}

int32_t iguana_bundleiters(struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_bundle *bp,int32_t timelimit,int32_t lag)
{
    int32_t range,starti,lasti,retval=0,max,counter = 0; struct iguana_bundle *currentbp,*lastbp;
    //serialized[512],
    if ( coin->started == 0 || coin->active == 0 )
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
    iguana_bundlecalcs(coin,bp,lag);
    if ( bp->hdrsi == coin->bundlescount-1 )
        iguana_autoextend(coin,bp);
    //printf("ITER utxo.%u now.%u spec.%-4d bundle.%-4d h.%-4d r.%-4d s.%-4d F.%d T.%d issued.%d mb.%d/%d\n",bp->utxofinish,(uint32_t)time(NULL),bp->numspec,bp->bundleheight/coin->chain->bundlesize,bp->numhashes,bp->numrecv,bp->numsaved,bp->emitfinish,timelimit,counter,coin->MAXBUNDLES,coin->bundlescount);
    bp->nexttime = (uint32_t)time(NULL) + 1;//cbrt(bp->hdrsi - starti)/10;
    if ( bp->hdrsi == coin->bundlescount-1 || (bp->numhashes < bp->n && bp->bundleheight < coin->longestchain-coin->chain->bundlesize) )
        iguana_bundlehdr(coin,bp,starti);
    else if ( bp->emitfinish != 0 )
    {
        if ( bp->utxofinish > 1 )
        {
            if ( bp->balancefinish == 0 )
            {
                //bp->queued = 0;
                iguana_balancesQ(coin,bp);
            }
            return(1);
        }
        if ( bp->emitfinish > 1 )
        {
            if ( (retval= iguana_bundlefinish(coin,bp)) > 0 )
            {
                //printf("moved to balancesQ.%d bundleiters.%d\n",bp->hdrsi,bp->bundleheight);
                //bp->queued = 0;
                return(0);
            } //else printf("finish incomplete.%d\n",bp->hdrsi);
        }
    }
    else if ( bp->numsaved >= bp->n )//&& (bp->isRT == 0 || coin->RTheight > bp->bundleheight+bp->n+coin->minconfirms) )
    {
        if ( iguana_bundlefinalize(coin,bp,mem,memB) >= 0 )
            return(0);
        //else bp->nexttime--;
        retval = 1;
    }
    else if ( bp->hdrsi == starti || (bp->hdrsi >= starti && bp->hdrsi <= starti+range) ) //bits256_nonz(bp->allhash) != 0 &&
    {
        max = bp->n;
        counter = 0;//iguana_bundleissue(coin,bp,max,timelimit);
        //if ( bp == coin->current && coin->isRT == 0 )
        //    bp->nexttime--;
        if ( bp->isRT == 0 && bp == coin->current && counter > 0 )
            printf("ITER.rt%d now.%u spec.%-4d bundle.%-4d h.%-4d r.%-4d s.%-4d F.%d T.%d issued.%d mb.%d/%d\n",bp->isRT,(uint32_t)time(NULL),bp->numspec,bp->bundleheight/coin->chain->bundlesize,bp->numhashes,bp->numrecv,bp->numsaved,bp->emitfinish,timelimit,counter,coin->MAXBUNDLES,coin->bundlescount);
        if ( bp->hdrsi == starti && bp->isRT == 0 )
        {
        }
    } else bp->nexttime += 3;
    //printf("done hdrs.%d\n",bp->hdrsi);
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

int32_t iguana_cacheprocess(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei)
{
    int32_t recvlen; struct iguana_msghdr H; uint8_t *data; struct iguana_block *block;
    if ( (data= bp->speculativecache[bundlei]) != 0 && bp->speculative != 0 && (block= iguana_blockfind("cacheprocess",coin,bp->speculative[bundlei])) != 0 )
    {
        iguana_bundlehash2add(coin,0,bp,bundlei,bp->speculative[bundlei]);
        recvlen = *(int32_t *)data;
        memset(&H,0,sizeof(H));
        iguana_sethdr(&H,coin->chain->netmagic,"block",&data[sizeof(recvlen)],recvlen);
        if ( coin->internaladdr.RAWMEM.ptr == 0 )
            iguana_meminit(&coin->internaladdr.RAWMEM,"cache",0,IGUANA_MAXPACKETSIZE + 65536*3,0);
        if ( coin->TXMEM.ptr == 0 )
            iguana_meminit(&coin->internaladdr.TXDATA,"txdata",0,IGUANA_MAXPACKETSIZE*1.5,0);
        if ( coin->internaladdr.HASHMEM.ptr == 0 )
            iguana_meminit(&coin->internaladdr.HASHMEM,"HASHPTRS",0,256,0);
        if ( iguana_msgparser(coin,&coin->internaladdr,&coin->internaladdr.RAWMEM,&coin->internaladdr.TXDATA,&coin->internaladdr.HASHMEM,&H,&data[sizeof(recvlen)],recvlen) < 0 )
            printf("error parsing speculativecache.[%d:%d]\n",bp->hdrsi,bundlei);
        else block->processed = 1;
        //char str[65]; printf("iguana_cacheprocess [%d:%d] %s fp.%x len.%d:%d\n",bp->hdrsi,bundlei,bits256_str(str,bp->hashes[bundlei]),block->fpipbits,block->RO.recvlen,recvlen);
        //myfree(data,recvlen + sizeof(recvlen));
        //bp->speculativecache[bundlei] = 0;
        return(recvlen);
    }
    return(-1);
}

void iguana_unstickhdr(struct iguana_info *coin,struct iguana_bundle *bp,int32_t lag)
{
    int32_t datalen,m; uint8_t serialized[512]; char str[65]; struct iguana_peer *addr;
    if ( (m= coin->peers.numranked) > 0 && bp->numhashes < bp->n && bp->hdrsi < coin->longestchain/coin->chain->bundlesize && time(NULL) > bp->unsticktime+lag )
    {
        if ( (addr= coin->peers.ranked[rand() % m]) != 0 && (datalen= iguana_gethdrs(coin,serialized,coin->chain->gethdrsmsg,bits256_str(str,bp->hashes[0]))) > 0 )
        {
            //printf("UNSTICK HDR.[%d]\n",bp->hdrsi);
            iguana_send(coin,addr,serialized,datalen);
            addr->pendhdrs++;
            bp->unsticktime = (uint32_t)time(NULL);
        }
    }
}

double iguana_bundlemissings(struct iguana_info *coin,struct iguana_bundle *bp,double aveduration)
{
    uint8_t missings[IGUANA_MAXBUNDLESIZE/8+1]; int32_t lag,tmp,dist=0,missing,priority,avail,n=0,max; double aveduplicates,mult; //bits256 hash2;
    priority = (strcmp("BTC",coin->symbol) != 0) * 2;
    lag = IGUANA_DEFAULTLAG;
    if ( bp->durationscount != 0 )
    {
        aveduration = (double)bp->totaldurations / bp->durationscount;
        if ( bp->duplicatescount != 0 )
            aveduplicates = (double)bp->duplicatedurations / bp->duplicatescount;
        else aveduplicates = 3 * aveduration;
        if ( (rand() % 10000) == 0 )
            printf("priority.%d [%d] dist.%d durations %.2f vs %.2f counts[%d %d] \n",priority,bp->hdrsi,dist,aveduration,aveduplicates,(int32_t)bp->durationscount,bp->duplicatescount);
    }
    if ( aveduration != 0. )
        mult = ((bp == coin->current) ? (strcmp("BTC",coin->symbol) != 0 ? .5 : 2) : 7.);
    else mult = 3.;
    if ( bp->numissued < bp->n )
        max = bp->numissued;
    else max = bp->origmissings;
    missing = iguana_blocksmissing(coin,&avail,missings,0,mult,bp,0);
    /*if ( coin->current != 0 )
    {
        if ( (dist= bp->hdrsi - coin->current->hdrsi) < coin->MAXBUNDLES && (bp == coin->current || netBLOCKS < 50*bp->n) )
        {
            iguana_unstickhdr(coin,bp,60);
            if ( bp->numcached > bp->n - (coin->MAXBUNDLES - dist) )
                priority += 1 + (bp == coin->current);
            if ( bp == coin->current || queue_size(&coin->priorityQ) < (2 * bp->n)/(dist+1) )
            {
                //printf("[%d] dist.%d numcached.%d priority.%d\n",bp->hdrsi,dist,bp->numcached,priority);
                //iguana_bundleissuemissing(coin,bp,missings,((rand() % 100) == 0 && bp == coin->current)*3);
                priority = ((rand() % 20) == 0 && bp == coin->current) * 3;
                if ( (n= iguana_bundlerequests(coin,missings,&bp->origmissings,&tmp,mult,bp,priority)) > 0 )
                {
                    bp->numissued += n;
                    bp->missingstime = (uint32_t)time(NULL);
                }
                return(aveduration);
            }
        }
    }*/
    if ( (n= iguana_bundlerequests(coin,missings,&bp->origmissings,&tmp,mult,bp,priority)) > 0 )
    {
        bp->numissued += n;
        bp->missingstime = (uint32_t)time(NULL);
    }
    return(aveduration);
}
        
void iguana_bundlestats(struct iguana_info *coin,char *str,int32_t lag)
{
    int32_t i,n,m,j,numv,numconverted,count,starti,lasti,pending,capacity,displag,numutxo,numbalances,numrecv,done,numhashes,numcached,numsaved,numemit; struct iguana_block *block; bits256 hash2;
    int64_t spaceused=0,estsize = 0; struct iguana_bundle *currentbp,*lastbp,*bp,*lastpending = 0,*firstgap = 0; uint32_t now; double aveduration,recentduration = 0.;
    now = (uint32_t)time(NULL);
    displag = (now - coin->lastdisp);
    numrecv = numhashes = numcached = numconverted = numsaved = numemit = done = numutxo = numbalances = 0;
    count = coin->bundlescount;
    currentbp = coin->current;
    lastbp = coin->lastpending;
    starti = currentbp == 0 ? 0 : currentbp->hdrsi;
    lasti = lastbp == 0 ? coin->bundlescount-1 : lastbp->hdrsi;
    iguana_recentpeers(coin,&capacity,0);
        //sortbuf = calloc(count,sizeof(*sortbuf)*2);
    for (i=n=m=numv=pending=0; i<count; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            if ( bp->converted != 0 )
                numconverted++;
            if ( bp == coin->current && coin->blocks.hwmchain.height >= bp->bundleheight && coin->blocks.hwmchain.height < bp->bundleheight+bp->n )
            {
                for (j=coin->blocks.hwmchain.height-bp->bundleheight+1; j<=bp->n; j++)
                {
                    if ( (block= iguana_bundleblock(coin,&hash2,bp,j)) == 0 && bits256_nonz(hash2) != 0 )
                        block = iguana_blockfind("bundlestats",coin,hash2);
                    if ( block == 0 || bits256_nonz(block->RO.prev_block) == 0 || _iguana_chainlink(coin,block) == 0 )
                        break;
                }
            }
            if ( bp->emitfinish > 1 )
            {
                for (j=0; j<bp->n; j++)
                {
                    if ( bp->blocks[j] == 0 && bits256_nonz(bp->hashes[j]) != 0 )
                        bp->blocks[j] = iguana_blockfind("bundlestats2",coin,bp->hashes[j]);
                }
            }
            else
            {
                if ( bp->hdrsi >= starti && bp->hdrsi < lasti && (displag % 3) == 2 )
                {
                    if ( (aveduration= iguana_bundlemissings(coin,bp,recentduration)) != 0 )
                        dxblend(&recentduration,aveduration,.5);
                }
                if ( coin->enableCACHE != 0 )
                {
                    for (j=0; j<bp->n; j++)
                    {
                        //if ( bp->blocks[j] == 0 && bp->speculative != 0 && bits256_nonz(bp->speculative[j]) != 0 )
                          //  bp->blocks[j] = iguana_blockhashset("speculative3",coin,bp->bundleheight+j,bp->speculative[j],1);
                        if ( ((block= bp->blocks[j]) == 0 || bp == coin->current) && bp->speculativecache[j] != 0 )
                        {
                            if ( (block != 0 || (block= iguana_blockhashset("bundlestats3",coin,-1,bp->speculative[j],1)) != 0) && block->processed == 0 )
                                iguana_cacheprocess(coin,bp,j);
                            numcached++;
                        }
                    }
                }
            }
            bp->metric = coin->bundlescount - bp->hdrsi;
            if ( done > coin->bundlescount*IGUANA_HEADPERCENTAGE && bp->hdrsi > coin->bundlescount*IGUANA_TAILPERCENTAGE )
                bp->metric *= 1000;
            iguana_bundlecalcs(coin,bp,lag);
            estsize += bp->estsize;
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
                numemit++;
                //printf("finished.[%d]\n",bp->hdrsi);
                if ( firstgap != 0 && bp->hdrsi > firstgap->hdrsi-3 )
                    iguana_bundlepurgefiles(coin,bp);
            }
            else
            {
                if ( firstgap == 0 && bp->numsaved < bp->n && bp->numcached < bp->n && (bp->emitfinish == 0 || bp->hdrsi == coin->longestchain/coin->chain->bundlesize) )
                {
                    //printf("firstgap <- [%d] emit.%u bp->n.%d numsaved.%d numcached.%d numhashes.%d\n",bp->hdrsi,bp->emitfinish,bp->n,bp->numsaved,bp->numcached,bp->numhashes);
                    firstgap = bp;
                }
                //else printf("[%d] emit.%u bp->n.%d numsaved.%d numcached.%d numhashes.%d\n",bp->hdrsi,bp->emitfinish,bp->n,bp->numsaved,bp->numcached,bp->numhashes);

                if ( bp->emitfinish == 0 )
                {
                    if ( firstgap != 0 && ++pending == coin->MAXBUNDLES )
                    {
                        lastpending = bp;
                        //printf("SET MAXBUNDLES.%d pend.%d\n",bp->hdrsi,pending);
                    }
                    spaceused += bp->estsize;
                    //sortbuf[m*2] = bp->metric;
                    //sortbuf[m*2 + 1] = i;
                    m++;
                    if ( 0 && lastpending == 0 )
                        printf("%d ",bp->numsaved);
                } else if ( bp->numsaved == bp->n )
                    done++;
            }
        }
    }
    //printf("lastbp.[%d]\n",lastpending!=0?lastpending->hdrsi:-1);
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
    uint64_t tmp; int32_t diff,p = 0; struct tai difft,t = tai_now();
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
    char str5[65];
    if ( coin->isRT == 0 && firstgap != 0 && firstgap->hdrsi < coin->bundlescount-1 )
    {
        if ( coin->stuckmonitor != (firstgap->hdrsi * coin->chain->bundlesize * 10) + firstgap->numsaved + firstgap->numhashes + firstgap->numcached )
        {
            coin->stuckmonitor = (firstgap->hdrsi * coin->chain->bundlesize * 10) + firstgap->numsaved + firstgap->numhashes + firstgap->numcached;
            coin->stucktime = (uint32_t)time(NULL);
            coin->stuckiters = 0;
        }
        else if ( coin->stucktime != 0 && (displag % 3) == 1 )
        {
            uint8_t missings[IGUANA_MAXBUNDLESIZE/8+1]; struct iguana_blockreq *breq; double aveduration; int32_t tmp,tmp2,n,priority=3,lag;
            lag = (int32_t)time(NULL) - coin->stucktime;
            bp = firstgap;
            //printf("NONZ stucktime.%u lag.%d iters.%d vs %d\n",coin->stucktime,lag,coin->stuckiters,lag/coin->MAXSTUCKTIME);
            if ( (lag/coin->MAXSTUCKTIME) > coin->stuckiters )
            {
                //printf("UNSTICK\n");
                iguana_unstickhdr(coin,bp,6);
                coin->stuckiters = (int32_t)(lag/coin->MAXSTUCKTIME);
                if ( coin->stuckiters > 2 )
                {
                    while ( (breq= queue_dequeue(&coin->blocksQ,0)) != 0 )
                        myfree(breq,sizeof(*breq));
                    while ( (breq= queue_dequeue(&coin->priorityQ,0)) != 0 )
                        myfree(breq,sizeof(*breq));
                    for (i=0; i<bp->n; i++)
                    {
                        if ( (block= bp->blocks[i]) != 0 && block->txvalid == 0 )
                            iguana_blockQ("stuck",coin,bp,i,block->RO.hash2,1);
                    }
                }
                if ( bp->durationscount != 0 )
                    aveduration = (double)bp->totaldurations / bp->durationscount;
                else aveduration = IGUANA_DEFAULTLAG/3 + 1;
                if ( (n= iguana_bundlerequests(coin,missings,&tmp,&tmp2,1.,bp,priority)) > 0 )
                    printf("issued %d priority requests [%d] to unstick stuckiters.%d lag.%d\n",n,bp->hdrsi,coin->stuckiters,lag);
                //else printf("no bundlerequests issued\n");
            }
        }
    }
    if ( coin->isRT != 0 || (firstgap != 0 && firstgap->hdrsi == coin->bundlescount-1) )
        coin->stucktime = coin->stuckiters = 0;
    if ( coin->stucktime != 0 && time(NULL)-coin->stucktime > coin->maxstuck )
        coin->maxstuck = (uint32_t)time(NULL) - coin->stucktime;
    sprintf(str,"%s.RT%d u.%d b.%d/%d v.%d/%d (%d+%d/%d 1st.%d).s%d to %d N[%d] h.%d r.%d c.%d s.%d d.%d E.%d maxB.%d peers.%d/%d Q.(%d %d) L.%d [%d:%d] M.%d %s",coin->symbol,coin->RTheight,numutxo,numbalances,numconverted,numv,coin->pendbalances,firstgap!=0?firstgap->numcached:-1,firstgap!=0?firstgap->numsaved:-1,firstgap!=0?firstgap->numhashes:-1,firstgap!=0?firstgap->hdrsi:-1,firstgap!=0?firstgap->numspec:-1,coin->lastpending!=0?coin->lastpending->hdrsi:0,count,numhashes,coin->blocksrecv,numcached,numsaved,done,numemit,coin->MAXBUNDLES,p,coin->MAXPEERS,queue_size(&coin->priorityQ),queue_size(&coin->blocksQ),coin->longestchain,coin->blocks.hwmchain.height/coin->chain->bundlesize,coin->blocks.hwmchain.height%coin->chain->bundlesize,coin->blocks.hwmchain.height,bits256_str(str5,coin->blocks.hwmchain.RO.hash2));
    // u.202 b.0/202 v.202/202
    if ( coin->current != 0 && numutxo == coin->bundlescount-1 && numutxo == coin->current->hdrsi && numbalances == 0 && numconverted == numutxo )
    {
        for (j=0; j<n; j++)
        {
            if ( (bp= coin->bundles[j]) != 0 )
            {
                //printf("bundleQ.[%d]\n",j);
                bp->balancefinish = bp->startutxo = 0;
                bp->utxofinish = 1;
                iguana_bundleQ(coin,bp,1000);
            }
        }
    }
    //sprintf(str+strlen(str),"%s.%-2d %s time %.2f files.%d Q.%d %d\n",coin->symbol,flag,str,(double)(time(NULL)-coin->starttime)/60.,coin->peers.numfiles,queue_size(&coin->priorityQ),queue_size(&coin->blocksQ));
    if ( time(NULL) > coin->lastdisp+3 && (strcmp(str,coin->lastdispstr) != 0 || time(NULL) > coin->lastdisp+60) )
    {
        printf("\n%s bQ.%d %d:%02d:%02d stuck.%d max.%d\n",str,queue_size(&bundlesQ),(int32_t)difft.x/3600,(int32_t)(difft.x/60)%60,(int32_t)difft.x%60,coin->stucktime!=0?(uint32_t)time(NULL) - coin->stucktime:0,coin->maxstuck);
        strcpy(coin->lastdispstr,str);
        if ( (rand() % 100) == 0 )
            myallocated(0,0);
        coin->lastdisp = (uint32_t)time(NULL);
    }
    if ( (bp= coin->current) != 0 )
    {
        if ( bp->queued == 0 )
            iguana_bundleQ(coin,firstgap,1000);
    }
    iguana_setmaxbundles(coin);
    strcpy(coin->statusstr,str);
    coin->estsize = estsize;
}

