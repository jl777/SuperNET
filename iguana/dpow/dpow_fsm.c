/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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

struct dpow_entry *dpow_notaryfind(struct supernet_info *myinfo,struct dpow_block *bp,int32_t height,int32_t *senderindp,uint8_t *senderpub)
{
    int32_t i;
    *senderindp = -1;
    for (i=0; i<bp->numnotaries; i++)
    {
        if ( memcmp(bp->notaries[i].pubkey,senderpub,33) == 0 )
        {
            //printf("matches notary.%d\n",i);
            *senderindp = i;
            return(&bp->notaries[i]);
        }
    }
    return(0);
}

void dpow_utxo2entry(struct dpow_block *bp,struct dpow_entry *ep,struct dpow_utxoentry *up)
{
    int32_t i;
    for (i=0; i<bp->numnotaries; i++)
        bp->notaries[i].othermask |= up->othermasks[i];
    ep->commit = up->commit;
    ep->height = up->height;
    ep->recvmask |= up->recvmask;
    ep->bestk = up->bestk;
    ep->src.prev_hash = up->srchash;
    ep->dest.prev_hash = up->desthash;
    ep->src.prev_vout = up->srcvout;
    ep->dest.prev_vout = up->destvout;
}

void dpow_entry2utxo(struct dpow_utxoentry *up,struct dpow_block *bp,struct dpow_entry *ep)
{
    int32_t i;
    up->commit = bp->commit;
    up->hashmsg = bp->hashmsg;
    up->height = bp->height;
    up->recvmask = bp->recvmask;
    up->bestk = bp->bestk;
    for (i=0; i<bp->numnotaries; i++)
        up->othermasks[i] = bp->notaries[i].recvmask;
    for (i=0; i<33; i++)
        up->pubkey[i] = ep->pubkey[i];
    up->commit = ep->commit;
    up->height = ep->height;
    up->recvmask = ep->recvmask;
    up->bestk = ep->bestk;
    up->srchash = ep->src.prev_hash;
    up->desthash = ep->dest.prev_hash;
    up->srcvout = ep->src.prev_vout;
    up->destvout = ep->dest.prev_vout;
}

int32_t dpow_datahandler(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,uint8_t nn_senderind,uint32_t channel,uint32_t height,uint8_t *data,int32_t datalen)
{
    int32_t i,src_or_dest,myind = -1; bits256 txid,srchash; struct iguana_info *coin; char str[65],str2[65];
    memset(srchash.bytes,0,sizeof(srchash));
    dpow_notaryfind(myinfo,bp,height,&myind,dp->minerkey33);
    if ( myind < 0 )
    {
        //printf("couldnt find myind height.%d | this means your pubkey for this node is not registered and needs to be ratified by majority vote of all notaries\n",height);
        return(-1);
    }
    for (i=0; i<32; i++)
        srchash.bytes[i] = dp->minerkey33[i+1];
    if ( channel == DPOW_TXIDCHANNEL || channel == DPOW_BTCTXIDCHANNEL )
    {
        src_or_dest = (channel == DPOW_BTCTXIDCHANNEL);
        coin = (src_or_dest != 0) ? bp->destcoin : bp->srccoin;
        //printf("bp.%p datalen.%d\n",bp,datalen);
        for (i=0; i<32; i++)
            srchash.bytes[i] = data[i];
        txid = bits256_doublesha256(0,&data[32],datalen-32);
        init_hexbytes_noT(bp->signedtx,&data[32],datalen-32);
        if ( bits256_cmp(txid,srchash) == 0 )
        {
            //printf("verify (%s) it is properly signed! set ht.%d signedtxid to %s\n",coin->symbol,height,bits256_str(str,txid));
            /*if ( channel == DPOW_BTCTXIDCHANNEL )
            {
                if ( bp->state < 1000 )
                {
                    bp->desttxid = txid;
                    bp->state = 1000;
                    dp->destupdated = 0;
                    dpow_signedtxgen(myinfo,dp,bp->srccoin,bp,bp->bestk,bp->bestmask,myind,DPOW_SIGCHANNEL,0,bp->isratify);
                    //dpow_sigscheck(myinfo,dp,bp,DPOW_SIGCHANNEL,myind,0);
                }
            }
            else
            {
                if ( bp->state != 0xffffffff )
                {
                    bp->srctxid = txid;
                    printf("set state elapsed %d COMPLETED %s.(%s) %s.(%s)\n",(int32_t)(time(NULL) - bp->starttime),dp->symbol,bits256_str(str,bp->desttxid),dp->dest,bits256_str(str2,txid));
                    bp->state = 0xffffffff;
                }
            }*/
        }
        else
        {
            init_hexbytes_noT(bp->signedtx,data,datalen);
            printf("txidchannel txid %s mismatch %s (%s)\n",bits256_str(str,txid),bits256_str(str2,srchash),bp->signedtx);
            bp->signedtx[0] = 0;
        }
    } //else printf("unhandled channel.%x\n",channel);
    return(0);
}

int32_t dpow_checkutxo(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,struct iguana_info *coin,bits256 *txidp,int32_t *voutp,char *coinaddr)
{
    int32_t haveutxo,completed,minutxo,n; bits256 signedtxid; cJSON *addresses; char *rawtx,*sendtx;
    if ( strcmp("BTC",coin->symbol) == 0 )
    {
        minutxo = 199;
        n = 10;
    }
    else
    {
        minutxo = 49;
        n = 10;
    }
    if ( (haveutxo= dpow_haveutxo(myinfo,coin,txidp,voutp,coinaddr)) <= minutxo && time(NULL) > dp->lastsplit+bp->duration && (bp->myind != 0 || dp->ratifying == 0) )
    {
        addresses = cJSON_CreateArray();
        jaddistr(addresses,coinaddr);
        if ( (rawtx= iguana_utxoduplicates(myinfo,coin,dp->minerkey33,DPOW_UTXOSIZE,n,&completed,&signedtxid,0,addresses)) != 0 )
        {
            if ( (sendtx= dpow_sendrawtransaction(myinfo,coin,rawtx)) != 0 )
            {
                printf("sendrawtransaction.(%s)\n",sendtx);
                free(sendtx);
            }
            free(rawtx);
        }
        free_json(addresses);
        dp->lastsplit = (uint32_t)time(NULL);
    }
    if ( bits256_nonz(*txidp) == 0 )
        return(-1);
    return(haveutxo);
}

void dpow_statemachinestart(void *ptr)
{
    void **ptrs = ptr;
    struct supernet_info *myinfo; struct dpow_info *dp; struct dpow_checkpoint checkpoint;
    int32_t i,j,ht,extralen,destprevvout0,srcprevvout0,numratified=0,kmdheight,myind = -1; uint8_t extras[10000],pubkeys[64][33]; cJSON *ratified=0,*item; struct iguana_info *src,*dest; char *jsonstr,*handle,*hexstr,str[65],str2[65],srcaddr[64],destaddr[64]; bits256 zero,srchash,destprevtxid0,srcprevtxid0; struct dpow_block *bp; struct dpow_entry *ep = 0; uint32_t duration,minsigs,starttime,srctime;
    memset(&zero,0,sizeof(zero));
    srcprevtxid0 = destprevtxid0 = zero;
    srcprevvout0 = destprevvout0 = -1;
    myinfo = ptrs[0];
    dp = ptrs[1];
    minsigs = (uint32_t)(long)ptrs[2];
    duration = (uint32_t)(long)ptrs[3];
    jsonstr = ptrs[4];
    kmdheight = -1;
    memcpy(&checkpoint,&ptrs[5],sizeof(checkpoint));
    src = iguana_coinfind(dp->symbol);
    dest = iguana_coinfind(dp->dest);
    dpow_getchaintip(myinfo,&srchash,&srctime,dp->srctx,&dp->numsrctx,src);
    dpow_getchaintip(myinfo,&srchash,&srctime,dp->desttx,&dp->numdesttx,dest);
    if ( src == 0 || dest == 0 )
    {
        printf("null coin ptr? (%s %p or %s %p)\n",dp->symbol,src,dp->dest,dest);
        return;
    }
    if ( strcmp(src->symbol,"KMD") == 0 )
        kmdheight = checkpoint.blockhash.height;
    else if ( strcmp(dest->symbol,"KMD") == 0 )
        kmdheight = dest->longestchain;
    if ( (bp= dp->blocks[checkpoint.blockhash.height]) == 0 )
    {
        bp = calloc(1,sizeof(*bp));
        bp->minsigs = minsigs;
        bp->duration = duration;
        bp->srccoin = src;
        bp->destcoin = dest;
        bp->myind = -1;
        bp->opret_symbol = dp->symbol;
        if ( jsonstr != 0 && (ratified= cJSON_Parse(jsonstr)) != 0 )
        {
            bp->isratify = 1;
            if ( (numratified= cJSON_GetArraySize(ratified)) > 0 )
            {
                if ( numratified > 64 )
                {
                    fprintf(stderr,"cant ratify more than 64 notaries ratified has %d\n",numratified);
                    return;
                }
                for (i=0; i<numratified; i++)
                {
                    item = jitem(ratified,i);
                    hexstr = handle = 0;
                    if ( (hexstr= jstr(item,"pubkey")) != 0 && is_hexstr(hexstr,0) == 66 )
                    {
                        decode_hex(bp->ratified_pubkeys[i],33,hexstr);
                        for (j=0; j<i; j++)
                            if ( memcmp(bp->ratified_pubkeys[j],bp->ratified_pubkeys[i],33) == 0 )
                            {
                                printf("ratification.%d is the same as %d, reject this donkey\n",j,i);
                                exit(-1);
                            }
                        if ( (handle= jstr(item,"handle")) != 0 )
                            safecopy(bp->handles[i],handle,sizeof(bp->handles[i]));
                        if ( i == 0 )
                        {
                            destprevtxid0 = jbits256(item,"destprevtxid0");
                            destprevvout0 = jint(item,"destprevvout0");
                            srcprevtxid0 = jbits256(item,"srcprevtxid0");
                            srcprevvout0 = jint(item,"srcprevvout0");
                            if ( bits256_nonz(destprevtxid0) != 0 && bits256_nonz(srcprevtxid0) != 0 )
                                bp->require0 = 1;
                        }
                    }
                    else
                    {
                        printf("break loop hexstr.%p handle.%p\n",hexstr,handle);
                        break;
                    }
                }
                if ( i == numratified )
                {
                    bp->numratified = numratified;
                    bp->ratified = ratified;
                    printf("numratified.%d %s\n",numratified,jprint(ratified,0));
                }
                else
                {
                    printf("i.%d numratified.%d\n",i,numratified);
                    free_json(ratified);
                }
            }
        }
        bp->bestk = -1;
        dp->blocks[checkpoint.blockhash.height] = bp;
        bp->beacon = rand256(0);
        vcalc_sha256(0,bp->commit.bytes,bp->beacon.bytes,sizeof(bp->beacon));
        /*if ( checkpoint.blockhash.height >= DPOW_FIRSTRATIFY && dp->blocks[checkpoint.blockhash.height - DPOW_FIRSTRATIFY] != 0 )
        {
            printf("purge %s.%d\n",dp->dest,checkpoint.blockhash.height - DPOW_FIRSTRATIFY);
            free(dp->blocks[checkpoint.blockhash.height - DPOW_FIRSTRATIFY]);
            dp->blocks[checkpoint.blockhash.height - DPOW_FIRSTRATIFY] = 0;
        }*/
    }
    if ( bp->isratify != 0 && dp->ratifying != 0 )
    {
        printf("new ratification starting dp->ratifying.%d\n",dp->ratifying);
        dp->ratifying++;
        while ( dp->ratifying > 1 )
            sleep(3);
        printf("other ratifications stopped\n");
    }
    if ( dp->ratifying != 0 && bp->isratify == 0 )
    {
        printf("skip notarization ht.%d when ratifying\n",bp->height);
        free(ptr);
        return;
    }
    dp->ratifying += bp->isratify;
    bitcoin_address(srcaddr,src->chain->pubtype,dp->minerkey33,33);
    bitcoin_address(destaddr,dest->chain->pubtype,dp->minerkey33,33);
    if ( kmdheight >= 0 )
    {
        ht = kmdheight;///strcmp("KMD",src->symbol) == 0 ? kmdheight : bp->height;
        if ( strcmp("KMD",dest->symbol) == 0 )
        {
            bp->numnotaries = komodo_notaries(dest->symbol,pubkeys,ht);
        }
        else
        {
            if ( ht == 0 )
                ht = strcmp("KMD",src->symbol) == 0 ? src->longestchain : dest->longestchain;
            bp->numnotaries = komodo_notaries(src->symbol,pubkeys,ht);
        }
        for (i=0; i<bp->numnotaries; i++)
        {
            //int32_t j; for (j=0; j<33; j++)
            //    printf("%02x",pubkeys[i][j]);
            //printf(" <= pubkey[%d]\n",i);
            memcpy(bp->notaries[i].pubkey,pubkeys[i],33);
            if ( strcmp("KMD",src->symbol) == 0 )
                memcpy(myinfo->notaries[i],pubkeys[i],33);
            if ( memcmp(bp->notaries[i].pubkey,dp->minerkey33,33) == 0 )
            {
                myind = i;
                ep = &bp->notaries[myind];
                for (j=0; j<33; j++)
                    printf("%02x",dp->minerkey33[j]);
                printf(" MYIND.%d <<<<<<<<<<<<<<<<<<<<<<\n",myind);
            }
        }
        if ( strcmp("KMD",src->symbol) == 0 )
            myinfo->numnotaries = bp->numnotaries;
        if ( myind < 0 || ep == 0 )
        {
            printf("minerkey33-> ");
            for (i=0; i<33; i++)
                printf("%02x",dp->minerkey33[i]);
            printf(" statemachinestart this node %s %s is not official notary numnotaries.%d kmdht.%d bpht.%d\n",srcaddr,destaddr,bp->numnotaries,kmdheight,bp->height);
            free(ptr);
            dp->ratifying -= bp->isratify;
            return;
        }
        printf("myind.%d\n",myind);
    }
    else
    {
        printf("statemachinestart no kmdheight.%d\n",kmdheight);
        free(ptr);
        dp->ratifying -= bp->isratify;
        return;
    }
    bp->myind = myind;
    printf("[%d] notarize %s->%s %s ht.%d minsigs.%d duration.%d start.%u\n",bp->myind,dp->symbol,dp->dest,bits256_str(str,checkpoint.blockhash.hash),checkpoint.blockhash.height,minsigs,duration,checkpoint.timestamp);
    if ( bp->isratify != 0 && memcmp(bp->notaries[0].pubkey,bp->ratified_pubkeys[0],33) != 0 )
    {
        for (i=0; i<33; i++)
            printf("%02x",bp->notaries[0].pubkey[i]);
        printf(" current vs ");
        for (i=0; i<33; i++)
            printf("%02x",bp->ratified_pubkeys[0][i]);
        printf(" new, cant change notary0\n");
        dp->ratifying -= bp->isratify;
        return;
    }
    //printf(" myind.%d myaddr.(%s %s)\n",myind,srcaddr,destaddr);
    if ( myind == 0 && bits256_nonz(destprevtxid0) != 0 && bits256_nonz(srcprevtxid0) != 0 && destprevvout0 >= 0 && srcprevvout0 >= 0 )
    {
        ep->dest.prev_hash = destprevtxid0;
        ep->dest.prev_vout = destprevvout0;
        ep->src.prev_hash = srcprevtxid0;
        ep->src.prev_vout = srcprevvout0;
        bp->notaries[myind].ratifysrcutxo = srcprevtxid0;
        bp->notaries[myind].ratifysrcvout = srcprevvout0;
        bp->notaries[myind].ratifydestutxo = destprevtxid0;
        bp->notaries[myind].ratifydestvout = destprevvout0;
        printf("Use override utxo %s/v%d %s/v%d\n",bits256_str(str,destprevtxid0),destprevvout0,bits256_str(str2,srcprevtxid0),srcprevvout0);
    }
    else
    {
        if ( dpow_checkutxo(myinfo,dp,bp,bp->destcoin,&ep->dest.prev_hash,&ep->dest.prev_vout,destaddr) < 0 )
        {
            printf("dont have %s %s utxo, please send funds\n",dp->dest,destaddr);
            free(ptr);
            dp->ratifying -= bp->isratify;
            return;
        }
        if ( dpow_checkutxo(myinfo,dp,bp,bp->srccoin,&ep->src.prev_hash,&ep->src.prev_vout,srcaddr) < 0 )
        {
            printf("dont have %s %s utxo, please send funds\n",dp->symbol,srcaddr);
            free(ptr);
            dp->ratifying -= bp->isratify;
            return;
        }
        if ( bp->isratify != 0 )
        {
            bp->notaries[myind].ratifysrcutxo = ep->src.prev_hash;
            bp->notaries[myind].ratifysrcvout = ep->src.prev_vout;
            bp->notaries[myind].ratifydestutxo = ep->dest.prev_hash;
            bp->notaries[myind].ratifydestvout = ep->dest.prev_vout;
        }
    }
    bp->recvmask |= (1LL << myind);
    bp->notaries[myind].othermask |= (1LL << myind);
    dp->checkpoint = checkpoint;
    bp->height = checkpoint.blockhash.height;
    bp->timestamp = checkpoint.timestamp;
    bp->hashmsg = checkpoint.blockhash.hash;
    bp->myind = myind;
    while ( bp->isratify == 0 && dp->destupdated == 0 )
    {
        if ( dp->checkpoint.blockhash.height > checkpoint.blockhash.height )
        {
            printf("abort %s ht.%d due to new checkpoint.%d\n",dp->symbol,checkpoint.blockhash.height,dp->checkpoint.blockhash.height);
            dp->ratifying -= bp->isratify;
            return;
        }
        sleep(1);
    }
    starttime = (uint32_t)time(NULL);
    if ( bp->isratify == 0 )
    {
        //if ( (starttime= checkpoint.timestamp) == 0 )
            bp->starttime = starttime;
        extralen = dpow_paxpending(extras,&bp->paxwdcrc);
        bp->notaries[bp->myind].paxwdcrc = bp->paxwdcrc;
    }
    printf("PAXWDCRC.%x myind.%d isratify.%d DPOW.%s statemachine checkpoint.%d %s start.%u+dur.%d vs %ld\n",bp->paxwdcrc,bp->myind,bp->isratify,src->symbol,checkpoint.blockhash.height,bits256_str(str,checkpoint.blockhash.hash),starttime,bp->duration,time(NULL));
    for (i=0; i<sizeof(srchash); i++)
        srchash.bytes[i] = dp->minerkey33[i+1];
    //printf("start utxosync start.%u %u\n",starttime,(uint32_t)time(NULL));
    //dpow_utxosync(myinfo,dp,bp,0,myind,srchash);
    //printf("done utxosync start.%u %u\n",starttime,(uint32_t)time(NULL));
    while ( time(NULL) < starttime+bp->duration && src != 0 && dest != 0 && bp->state != 0xffffffff )
    {
        if ( bp->isratify == 0 )
        {
            if ( myinfo->DPOWS[0].ratifying != 0 )
            {
                printf("break due to already ratifying\n");
                break;
            }
            extralen = dpow_paxpending(extras,&bp->paxwdcrc);
            bp->notaries[bp->myind].paxwdcrc = bp->paxwdcrc;
        }
        sleep(13);
        if ( dp->checkpoint.blockhash.height > checkpoint.blockhash.height )
        {
            if ( bp->isratify == 0 )
            {
                printf("abort %s ht.%d due to new checkpoint.%d\n",dp->symbol,checkpoint.blockhash.height,dp->checkpoint.blockhash.height);
                break;
            }
        }
        if ( dp->ratifying > 1 )
        {
            printf("new ratification started. abort ht.%d\n",bp->height);
            break;
        }
        if ( bp->isratify == 0 )
        {
            bits256 checkhash;
            checkhash = dpow_getblockhash(myinfo,bp->srccoin,bp->height);
            if ( bits256_cmp(checkhash,bp->hashmsg) != 0 )
            {
                printf("%s ht.%d %s got reorged to %s, abort notarization\n",bp->srccoin->symbol,bp->height,bits256_str(str,bp->hashmsg),bits256_str(str2,checkhash));
                bp->state = 0xffffffff;
            }
        }
        if ( bp->state != 0xffffffff )
        {
            dpow_send(myinfo,dp,bp,srchash,bp->hashmsg,0,bp->height,(void *)"ping",0);
            dpow_nanomsg_update(myinfo);
        }
        else
        {
            dp->lastnotarized = checkpoint.blockhash.hash;
            printf("notarized %s %s\n",dp->symbol,bits256_str(str,checkpoint.blockhash.hash));
        }
        if ( 0 && dp->cancelratify != 0 && bp->isratify != 0 )
        {
            printf("abort pending ratify\n");
            break;
        }
    }
    printf("END isratify.%d:%d bestk.%d %llx sigs.%llx state.%x machine ht.%d completed state.%x %s.%s %s.%s recvmask.%llx paxwdcrc.%x %p %p\n",bp->isratify,dp->ratifying,bp->bestk,(long long)bp->bestmask,(long long)(bp->bestk>=0?bp->destsigsmasks[bp->bestk]:0),bp->state,bp->height,bp->state,dp->dest,bits256_str(str,bp->desttxid),dp->symbol,bits256_str(str2,bp->srctxid),(long long)bp->recvmask,bp->paxwdcrc,src,dest);
    bp->state = 0xffffffff;
    dp->lastrecvmask = bp->recvmask;
    dp->ratifying -= bp->isratify;
    dp->blocks[bp->height] = 0;
    free(ptr);
}

