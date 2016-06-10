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

// included from gecko.c

int32_t gecko_blocknonce_verify(struct iguana_info *virt,uint8_t *serialized,int32_t datalen,uint32_t nBits)
{
    bits256 threshold,hash2;
    threshold = bits256_from_compact(nBits);
    hash2 = iguana_calcblockhash(virt->symbol,virt->chain->hashalgo,serialized,datalen);
    if ( bits256_cmp(threshold,hash2) > 0 )
        return(0);
    else return(0);
}

/*uint32_t iguana_targetbits(struct iguana_info *coin,struct iguana_block *hwmchain,struct iguana_block *prev,struct iguana_block *prev2,int32_t PoSflag,int32_t targetspacing,int32_t targettimespan)
{
    // targetspacing NTARGETSPACING, mspacing NINTERVAL_MSPACING, pspacing NINTERVAL_PSPACING
    bits256 mpz_muldivcmp(bits256 oldval,int32_t mulval,int32_t divval,bits256 cmpval);
    bits256 targetval; int32_t gap,mspacing,pspacing;
    if ( hwmchain->height <= 2 || hwmchain->height <= 0 )
        return(hwmchain->RO.bits);
    mspacing = (((targettimespan / targetspacing) - 1) * targetspacing);
    pspacing = (((targettimespan / targetspacing) + 1) * targetspacing);
    targetval = iguana_targetval(coin,hwmchain->height,PoSflag);
    if ( prev != 0 )
    {
        if ( prev2 != 0 && prev->RO.timestamp != 0 && prev2->RO.timestamp != 0 )
        {
            //if ( prev->RO.timestamp != 0 && prev2->RO.timestamp != 0 ) skip check for compatiblity
            {
                if ( (gap= prev->RO.timestamp - prev2->RO.timestamp) < 0 )
                    gap = targetspacing;
                //printf("nBits.%08x gap.%d (%u - %u)\n",prev->RO.bits,gap,prev->RO.timestamp,prev2->RO.timestamp);
                targetval = mpz_muldivcmp(bits256_from_compact(prev->RO.bits),mspacing + (gap << 1),pspacing,targetval);
            }
        }
    }
    return(bits256_to_compact(targetval));
}*/

uint32_t gecko_nBits(struct iguana_info *virt,struct iguana_block *block,int32_t n)
{
    uint32_t nBits = GECKO_DEFAULTDIFF,starttime,endtime,est; struct iguana_block *prev=0; int32_t i,diff; bits256 targetval;
    if ( virt->chain->estblocktime == 0 )
        return(GECKO_EASIESTDIFF);
    for (i=0; i<n; i++)
    {
        if ( (prev= iguana_blockfind("geckotx",virt,block->RO.prev_block)) == 0 || prev->height == 0 )
        {
            i++;
            break;
        }
        if ( i == 0 )
        {
            endtime = prev->RO.timestamp;
            nBits = prev->RO.bits;
        }
        starttime = prev->RO.timestamp;
        block = prev;
    }
    if ( starttime != 0 && endtime > starttime && i > 1 )
    {
        diff = (endtime - starttime);
        est = virt->chain->estblocktime * i;
        targetval = bits256_from_compact(nBits);
        if ( diff > est )
        {
            targetval = bits256_rshift(bits256_add(targetval,bits256_lshift(targetval)));
        }
        else if ( diff < est )
        {
            targetval = bits256_rshift(bits256_add(targetval,bits256_rshift(targetval)));
        }
        //printf("diff.%d est.%d nBits.%08x <- %08x\n",endtime - starttime,virt->chain->estblocktime * i,bits256_to_compact(targetval),nBits);
        nBits = bits256_to_compact(targetval);
    }
    if ( nBits > GECKO_EASIESTDIFF )
    {
        printf("nBits.%08x vs easiest %08x\n",nBits,GECKO_EASIESTDIFF);
        nBits = GECKO_EASIESTDIFF;
    }
  /*if ( newblock->height >= 0 && (prev= iguana_blockfind("geckotx",virt,newblock->RO.prev_block)) != 0 && prev->height > 1 )
    {
        if ( (prev2= iguana_blockfind("prvatetx2",virt,prev->RO.prev_block)) != 0 && prev2->height >= 0 )
        {
            nBits = iguana_targetbits(virt,newblock,prev,prev2,1,virt->chain->targetspacing,virt->chain->targettimespan);
            if ( nBits > GECKO_EASIESTDIFF )
            {
                printf("nBits.%08x vs easiest %08x\n",nBits,GECKO_EASIESTDIFF);
                nBits = GECKO_EASIESTDIFF;
            }
        }
    } else printf("ht.%d prev.%p prevht.%d prev2.%p\n",newblock->height,prev,prev!=0?prev->height:-1,prev2);*/
    return(nBits);
}

int32_t gecko_delayedPoW(struct supernet_info *myinfo,struct iguana_info *btcd,int32_t isPoS,uint8_t *coinbase,bits256 *btcdhashp,uint32_t timestamp,int32_t height)
{
    bits256 btchash; int32_t len = 0;
    len += iguana_rwnum(1,&coinbase[len],sizeof(height),(void *)&height);
    if ( (isPoS & 7) != 0 )
    {
        *btcdhashp = gecko_hashstampscalc(btcd,&btchash,timestamp);
        if ( (isPoS & 2) != 0 && (bits256_cmp(*btcdhashp,GENESIS_PUBKEY) == 0 || bits256_nonz(*btcdhashp) == 0) )
            return(-1);
        if ( (isPoS & 4) != 0 && (bits256_cmp(btchash,GENESIS_PUBKEY) == 0 || bits256_nonz(btchash) == 0) )
            return(-1);
        //len += iguana_rwbignum(1,&coinbase[len],sizeof(*btcdhashp),btcdhashp->bytes);
        len += iguana_rwbignum(1,&coinbase[len],sizeof(btchash),btchash.bytes);
    } else *btcdhashp = GENESIS_PUBKEY;
    return(len);
}

char *gecko_coinbasestr(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,uint8_t *data,int32_t datalen,bits256 coinbasespend,cJSON *coinbasetx)
{
    char *rawtx; cJSON *txjson;
    if ( (txjson= coinbasetx) == 0 )
        txjson = bitcoin_txcreate(1,0,coin->chain->normal_txversion);
    bitcoin_txinput(coin,txjson,coinbasespend,-1,0xffffffff,0,0,data,datalen,0,0);
    //printf("TX.(%s)\n",jprint(txjson,0));
    rawtx = bitcoin_json2hex(myinfo,coin,txidp,txjson,0);
    if ( txjson != coinbasetx )
        free_json(txjson);
    return(rawtx);
}

char *gecko_block(struct supernet_info *myinfo,struct iguana_info *virt,struct iguana_block *newblock,uint32_t *noncep,char **txptrs,int32_t txn_count,uint8_t *coinbase,int32_t coinbaselen,bits256 coinbasespend,cJSON *coinbasetx,double expiration)
{
    struct iguana_info *btcd; uint8_t serialized[sizeof(*newblock)],space[16384],*txdata,*allocptr = 0; int32_t i,n,totaltxlen=0,txlen; char *coinbasestr,*blockstr=0; bits256 *txids=0,txspace[256],threshold;
    //char str[65]; printf("prevblock.%s\n",bits256_str(str,newblock->RO.prev_block));
    if ( (btcd= iguana_coinfind("BTCD")) == 0 )
    {
        printf("basilisk needs BTCD\n");
        return(0);
    }
    if ( txn_count+2 < sizeof(space)/sizeof(*space) )
    {
        txids = txspace;
        memset(txids,0,sizeof(*txids) * (txn_count+2));
    } else txids = calloc(txn_count+2,sizeof(*txids));
    if ( txn_count > 0 )
    {
        for (i=0; i<txn_count; i++)
        {
            if ( (txdata= get_dataptr(BASILISK_HDROFFSET,&allocptr,&txlen,space,sizeof(space),txptrs[i])) == 0 )
            {
                printf("gecko_block error tx.%d\n",i);
                if ( txids != txspace )
                    free(txids);
                return(0);
            }
            totaltxlen += txlen;
            txids[i+1] = bits256_doublesha256(0,txdata,txlen);
            if ( allocptr != 0 )
                free(allocptr);
        }
    }
    if ( (coinbasestr= gecko_coinbasestr(myinfo,virt,&txids[0],coinbase,coinbaselen,coinbasespend,coinbasetx)) != 0 )
    {
        newblock->RO.merkle_root = iguana_merkle(txids,txn_count + 1);
        newblock->RO.txn_count = (txn_count + 1);
        threshold = bits256_from_compact(newblock->RO.bits);
        if ( (newblock->RO.nonce= *noncep) == 0 )
        {
            for (i=0; i<GECKO_MAXMINERITERS; i++)
            {
                newblock->RO.nonce = rand();
                n = iguana_serialize_block(virt->chain,&newblock->RO.hash2,serialized,newblock);
                //char str[65]; printf("nonce.%08x %s\n",block->RO.nonce,bits256_str(str,block->RO.hash2));
                if ( bits256_cmp(threshold,newblock->RO.hash2) > 0 )
                    break;
                if ( (i & 0xff) == 0xff && OS_milliseconds() > expiration )
                    break;
            }
        }
        *noncep = newblock->RO.nonce;
        n = iguana_serialize_block(virt->chain,&newblock->RO.hash2,serialized,newblock);
        if ( bits256_cmp(threshold,newblock->RO.hash2) > 0 )
        {
            blockstr = calloc(1,strlen(coinbasestr) + (totaltxlen+n)*2 + 1);
            init_hexbytes_noT(blockstr,serialized,n);
            //printf("block.(%s) coinbase.(%s) lens.%ld\n",blockstr,coinbasestr,(strlen(blockstr)+strlen(coinbasestr))/2);
            strcat(blockstr,coinbasestr);
            for (i=0; i<txn_count; i++)
                strcat(blockstr,txptrs[i]);
        }
        free(coinbasestr);
    }
    if ( txids != txspace )
        free(txids);
    return(blockstr);
}

char *gecko_createblock(struct supernet_info *myinfo,struct iguana_info *btcd,int32_t isPoS,struct iguana_block *newblock,char *symbol,char **txptrs,int32_t txn_count,cJSON *coinbasetx,int32_t maxmillis)
{
    bits256 btcdhash; uint8_t coinbase[512]; int32_t coinbaselen; uint32_t nonce; double expiration = OS_milliseconds() + maxmillis;
    //char str[65]; printf("create prev.(%s) %p\n",bits256_str(str,newblock->RO.prev_block),&newblock->RO.prev_block);
    if ( btcd != 0 )
    {
        newblock->RO.timestamp = (uint32_t)time(NULL);
        if ( (coinbaselen= gecko_delayedPoW(myinfo,btcd,isPoS,coinbase,&btcdhash,newblock->RO.timestamp,newblock->height)) < 0 )
        {
            printf("error generating coinbase for height.%d\n",newblock->height);
            return(0);
        }
        nonce = 0;
        return(gecko_block(myinfo,btcd,newblock,&nonce,txptrs,txn_count,coinbase,coinbaselen,btcdhash,coinbasetx,expiration));
    } else return(0);
}

/*int32_t basilist_validateblock(cJSON *valsobj)
 {
 uint32_t now,timestamp;
 now = (uint32_t)time(NULL);
 if ( (timestamp= juint(valsobj,"timestamp")) < now-BASILISK_MAXBLOCKLAG || timestamp > now+BASILISK_MAXFUTUREBLOCK )
 return(-1);
 if ( bits256_nonz(prevhash) == 0 )
 prevhash = coin->blocks.hwmchain.RO.hash2;
 if ( (prevblock= iguana_blockfind("setfield",coin,prevhash)) == 0 )
 return(clonestr("{\"error\":\"couldnt find prevhash\"}"));
 if ( (prev2= iguana_blockfind("setfield",coin,prevblock->RO.prev_block)) == 0 )
 return(clonestr("{\"error\":\"couldnt find prevhash2\"}"));
 nonce = juint(valsobj,"nonce");
 nBits = iguana_targetbits(coin,&coin->blocks.hwmchain,prevblock,prev2,1,coin->chain->targetspacing,coin->chain->targettimespan);
 blocktx = basilisk_block(myinfo,coin,&block,1,timestamp,&nonce,prevhash,nBits,prevblock->height+1,0,0,data,datalen,btcdhash,jobj(valsobj,"coinbase"));
 
 return(0);
 }*/

cJSON *gecko_paymentsobj(struct supernet_info *myinfo,cJSON *txjson,cJSON *valsobj,int32_t reusedaddrs)
{
    cJSON *item,*array; char *coinaddr; uint64_t satoshis; uint8_t addrtype,pubkey33[33],rmd160[20],outputscript[512]; int32_t i,n,scriptlen; uint32_t locktime,txversion; struct iguana_waddress *waddr; struct iguana_waccount *wacct;
    locktime = juint(valsobj,"locktime");
    if ( (txversion= juint(valsobj,"txversion")) == 0 )
        txversion = (locktime == 0) ? IGUANA_NORMAL_TXVERSION : IGUANA_LOCKTIME_TXVERSION;
    if ( txjson == 0 )
        txjson = bitcoin_txcreate(1,locktime,txversion);
    if ( (array= jarray(&n,valsobj,"payments")) != 0 && n > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( (coinaddr= jfieldname(item)) != 0 && (satoshis= j64bits(item,coinaddr)) > 0 )
            {
                printf("payment.%s <- %.8f\n",coinaddr,dstr(satoshis));
                bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
                scriptlen = 0;
                if ( reusedaddrs == 0 )
                {
                    if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 )
                    {
                        if ( bitcoin_pubkeylen(waddr->pubkey) > 0 )
                            scriptlen = bitcoin_pubkeyspend(outputscript,0,pubkey33);
                    }
                }
                if ( scriptlen == 0 )
                    scriptlen = bitcoin_standardspend(outputscript,0,rmd160);
                bitcoin_txoutput(txjson,outputscript,scriptlen,satoshis);
            }
        }
    }
    return(txjson);
}

char **gecko_mempool(struct supernet_info *myinfo,struct iguana_info *virt,int64_t *rewardp,int32_t *txn_countp,char **ptrp,void *space,int32_t max)
{
    *ptrp = 0;
    *txn_countp = 0;
    return(0);
}

void gecko_blocksubmit(struct supernet_info *myinfo,struct iguana_info *virt,char *blockstr,bits256 hash2)
{
    uint8_t *data,space[16384],*allocptr=0; int32_t i,len,numranked=0; struct iguana_peers *peers; struct iguana_peer *addr;
    if ( (peers= virt->peers) == 0 || (numranked= peers->numranked) == 0 )
        basilisk_blocksubmit(myinfo,virt,blockstr,hash2);
    else
    {
        if ( (data= get_dataptr(sizeof(struct iguana_msghdr),&allocptr,&len,space,sizeof(space),blockstr)) != 0 )
        {
            for (i=0; i<numranked; i++)
            {
                if ( (addr= peers->ranked[i]) != 0 && addr->usock >= 0 && addr->supernet != 0 )
                    iguana_queue_send(addr,0,data,"block",len);
            }
        }
        if ( allocptr != 0 )
            free(allocptr);
    }
}

void gecko_miner(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_info *virt,int32_t maxmillis,char *mineraddr)
{
    struct iguana_zblock newblock; uint32_t nBits,locktime=0; int64_t reward = 0; int32_t bundlei,txn_count; cJSON *item,*array,*coinbasetx=0; char *blockstr,**txptrs,*ptr,*space[256]; struct iguana_bundle *bp;
    if ( virt->virtualchain == 0 )//|| virt->bundles[virt->blocks.hwmchain.height / virt->chain->bundlesize] == 0 )
        return;
    memset(&newblock,0,sizeof(newblock));
    newblock.height = virt->blocks.hwmchain.height + 1;
    newblock.RO.prev_block = virt->blocks.hwmchain.RO.hash2;
    newblock.RO.version = GECKO_DEFAULTVERSION;
    newblock.RO.allocsize = sizeof(struct iguana_block);
    if ( (nBits= gecko_nBits(virt,(void *)&newblock,GECKO_DIFFITERS)) != 0 )
    {
        newblock.RO.bits = nBits;
        //printf("mine.%s %s nBits.%x\n",virt->symbol,mineraddr,nBits);
        txptrs = gecko_mempool(myinfo,virt,&reward,&txn_count,&ptr,space,(int32_t)(sizeof(space)/sizeof(*space)));
        if ( reward > 0 )
        {
            array = cJSON_CreateArray();
            item = cJSON_CreateObject();
            jaddnum(item,mineraddr,dstr(reward));
            jaddi(array,item);
            coinbasetx = bitcoin_txcreate(1,locktime,virt->chain->normal_txversion);
            jadd(coinbasetx,"payments",array);
        }
        //char str[65]; printf("HWM.%s %p\n",bits256_str(str,newblock.RO.prev_block),&newblock.RO.prev_block);
        if ( (blockstr= gecko_createblock(myinfo,btcd,virt->chain->isPoS,(void *)&newblock,virt->symbol,txptrs,txn_count,coinbasetx,maxmillis)) != 0 )
        {
            if ( (bundlei= (newblock.height % virt->chain->bundlesize)) == 0 )
                iguana_bundlecreate(virt,&bundlei,newblock.height,newblock.RO.hash2,newblock.RO.prev_block,1);
            newblock.RO.allocsize = virt->chain->zcash != 0 ? sizeof(struct iguana_zblock) : sizeof(struct iguana_block);
            if ( (bp= virt->bundles[newblock.height / virt->chain->bundlesize]) != 0 )
            {
                char str[65];
                iguana_hash2set(virt,"miner",bp,bundlei,newblock.RO.hash2);
                if ( iguana_bundlefind(virt,&bp,&bundlei,newblock.RO.hash2) == 0 )
                    printf("cant find ht.%d %s\n",newblock.height,bits256_str(str,newblock.RO.hash2));
                //else printf("found bp.%p bundlei.%d\n",bp,bundlei);
            }
            //virt->blocks.hwmchain = newblock;
            //char str[65]; printf("%s mined.%x %s %u ht.%d\n",virt->symbol,newblock.RO.bits,bits256_str(str,newblock.RO.hash2),newblock.RO.timestamp,newblock.height);
            gecko_blocksubmit(myinfo,virt,blockstr,newblock.RO.hash2);
            free(blockstr);
        }
        if ( txptrs != space )
            free(txptrs);
    }
}

