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

struct dpow_entry *dpow_notaryfind(struct supernet_info *myinfo,struct dpow_block *bp,int32_t *senderindp,uint8_t *senderpub)
{
    int32_t i;
    *senderindp = -1;
    for (i=0; i<bp->numnotaries; i++)
    {
        if ( memcmp(bp->notaries[i].pubkey,senderpub,33) == 0 )
        {
            *senderindp = i;
            return(&bp->notaries[i]);
        }
    }
    return(0);
}

void dpow_utxosync(struct supernet_info *myinfo,struct dpow_block *bp,uint64_t recvmask,int32_t myind,bits256 srchash,uint32_t channel)
{
    uint32_t i,j,r; int32_t len; uint8_t utxodata[sizeof(struct dpow_entry)+2];
    if ( (bp->recvmask ^ recvmask) != 0 )
    {
        if ( ((1LL << myind) & recvmask) == 0 )
            i = myind;
        else
        {
            r = (rand() % bp->numnotaries);
            for (j=0; j<DPOW_M(bp); j++)
            {
                i = ((bp->height % bp->numnotaries) + j + r) % bp->numnotaries;
                if ( ((1LL << i) & bp->recvmask) != 0 && ((1LL << i) & recvmask) == 0 )
                    break;
            }
        }
        if ( (len= dpow_rwutxobuf(1,utxodata,&bp->hashmsg,&bp->notaries[i])) > 0 )
            dpow_send(myinfo,bp,srchash,bp->hashmsg,channel,bp->height,utxodata,len,bp->utxocrcs);
    }
}

void dpow_sync(struct supernet_info *myinfo,struct dpow_block *bp,uint64_t refmask,int32_t myind,bits256 srchash,uint32_t channel)
{
    int8_t lastk; uint64_t mask;
    mask = dpow_maskmin(refmask,bp,&lastk);
    dpow_utxosync(myinfo,bp,mask,myind,srchash,channel);
    if ( bp->notaries[myind].masks[lastk] == 0 )
        dpow_signedtxgen(myinfo,bp->coin,bp,lastk,mask,myind,bp->opret_symbol,bits256_nonz(bp->btctxid) == 0 ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL);
}

void dpow_datahandler(struct supernet_info *myinfo,uint32_t channel,uint32_t height,uint8_t *data,int32_t datalen)
{
    bits256 hashmsg,txid,commit,srchash; struct dpow_block *bp = 0; uint32_t flag = 0; int32_t senderind,i,myind = -1; char str[65],str2[65]; struct dpow_sigentry dsig; struct dpow_entry *ep,E;
    if ( channel == DPOW_UTXOCHANNEL || channel == DPOW_UTXOBTCCHANNEL )
    {
        memset(&E,0,sizeof(E));
        if ( dpow_rwutxobuf(0,data,&hashmsg,&E) < 0 )
            return;
        if ( (bp= dpow_heightfind(myinfo,height,channel == DPOW_UTXOBTCCHANNEL)) != 0 )
        {
            dpow_notaryfind(myinfo,bp,&myind,myinfo->DPOW.minerkey33);
            if ( myind < 0 )
                return;
            if ( bits256_cmp(hashmsg,bp->hashmsg) != 0 )
            {
                printf("unexpected mismatch hashmsg.%s vs %s\n",bits256_str(str,hashmsg),bits256_str(str2,bp->hashmsg));
                return;
            }
            if ( (ep= dpow_notaryfind(myinfo,bp,&senderind,E.pubkey)) != 0 )
            {
                if ( bits256_nonz(ep->prev_hash) == 0 )
                {
                    *ep = E;
                    bp->recvmask |= (1LL << senderind);
                }
                ep->recvmask = E.recvmask;
                dpow_sync(myinfo,bp,ep->recvmask,myind,srchash,channel);
                flag = 1;
            }
        }
        if ( 0 && flag == 0 && bp != 0 )
            printf("UTXO.%d hashmsg.(%s) txid.(%s) v%d\n",height,bits256_str(str,hashmsg),bits256_str(str2,E.prev_hash),E.prev_vout);
    }
    else if ( channel == DPOW_SIGCHANNEL || channel == DPOW_SIGBTCCHANNEL )
    {
        if ( dpow_rwsigentry(0,data,&dsig) < 0 )
            return;
        if ( dsig.senderind >= 0 && dsig.senderind < DPOW_MAXRELAYS && (bp= dpow_heightfind(myinfo,height,channel == DPOW_SIGBTCCHANNEL)) != 0 )
        {
            dpow_notaryfind(myinfo,bp,&myind,myinfo->DPOW.minerkey33);
            if ( myind < 0 )
                return;
            if ( dsig.lastk < bp->numnotaries && dsig.senderind < bp->numnotaries && (ep= dpow_notaryfind(myinfo,bp,&senderind,dsig.senderpub)) != 0 )
            {
                vcalc_sha256(0,commit.bytes,dsig.beacon.bytes,sizeof(dsig.beacon));
                if ( memcmp(dsig.senderpub,bp->notaries[dsig.senderind].pubkey,33) == 0 )
                {
                    if ( ep->masks[dsig.lastk] == 0 )
                    {
                        ep->masks[dsig.lastk] = dsig.mask;
                        ep->siglens[dsig.lastk] = dsig.siglen;
                        memcpy(ep->sigs[dsig.lastk],dsig.sig,dsig.siglen);
                        ep->beacon = dsig.beacon;
                        printf(" <<<<<<<< %s from.%d got lastk.%d %llx siglen.%d >>>>>>>>>\n",bp->coin->symbol,dsig.senderind,dsig.lastk,(long long)dsig.mask,dsig.siglen);
                        dpow_sync(myinfo,bp,dsig.mask,myind,srchash,channel);
                        flag = 1;
                    }
                } else printf("%s pubkey mismatch for senderind.%d %llx vs %llx\n",bp->coin->symbol,dsig.senderind,*(long long *)dsig.senderpub,*(long long *)bp->notaries[dsig.senderind].pubkey);
            } else printf("%s illegal lastk.%d or senderind.%d or senderpub.%llx\n",bp->coin->symbol,dsig.lastk,dsig.senderind,*(long long *)dsig.senderpub);
        } else printf("couldnt find senderind.%d height.%d channel.%x\n",dsig.senderind,height,channel);
        if ( 0 && bp != 0 )
            printf(" SIG.%d sender.%d lastk.%d mask.%llx siglen.%d recv.%llx\n",height,dsig.senderind,dsig.lastk,(long long)dsig.mask,dsig.siglen,(long long)bp->recvmask);
    }
    else if ( channel == DPOW_TXIDCHANNEL || channel == DPOW_BTCTXIDCHANNEL )
    {
        printf("handle txid channel.%x\n",channel);
        if ( (bp= dpow_heightfind(myinfo,height,channel == DPOW_BTCTXIDCHANNEL)) != 0 )
        {
            //printf("bp.%p datalen.%d\n",bp,datalen);
            for (i=0; i<32; i++)
                srchash.bytes[i] = data[i];
            /*if ( srchash.ulongs[0] == 0 )
             {
             init_hexbytes_noT(bp->rawtx,&data[32],datalen-32);
             //printf("got bestk.%d %llx rawtx.(%s) set utxo\n",srchash.bytes[31],(long long)srchash.ulongs[1],bp->rawtx);
             dpow_rawtxsign(myinfo,bp->coin,bp,bp->rawtx,0,srchash.bytes[31],srchash.ulongs[1],myind,bits256_nonz(bp->btctxid) == 0 ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL);
             }
             else*/
            {
                txid = bits256_doublesha256(0,&data[32],datalen-32);
                init_hexbytes_noT(bp->signedtx,&data[32],datalen-32);
                printf("signedtx.(%s)\n",bp->signedtx);
                if ( bits256_cmp(txid,srchash) == 0 )
                {
                    printf("verify (%s) it is properly signed! set ht.%d signedtxid to %s\n",bp->coin->symbol,height,bits256_str(str,txid));
                    bp->signedtxid = txid;
                    bp->state = 0xffffffff;
                }
                else
                {
                    init_hexbytes_noT(bp->signedtx,data,datalen);
                    printf("txidchannel txid %s mismatch %s (%s)\n",bits256_str(str,txid),bits256_str(str2,srchash),bp->signedtx);
                    bp->signedtx[0] = 0;
                }
            }
        } else printf("txidchannel cant find bp for %d\n",height);
    }
}

int32_t dpow_update(struct supernet_info *myinfo,struct dpow_block *bp,uint32_t utxochannel,uint32_t sigchannel,uint32_t txidchannel,bits256 srchash,int32_t myind)
{
    struct dpow_entry *ep; int32_t i,k,len,sendutxo = 1; bits256 hash; uint8_t data[sizeof(struct dpow_entry)+2];
    ep = &bp->notaries[myind];
    if ( (bp->bestk= dpow_bestk(bp,&bp->bestmask)) >= 0 )
    {
        sendutxo = 0;
        for (i=0; i<bp->numnotaries; i++)
        {
            k = ((bp->height % bp->numnotaries) + i) % bp->numnotaries;
            if ( ((1LL << k) & bp->bestmask) != 0 && (bp->notaries[k].recvmask & (1LL << myind)) == 0 )
            {
                printf("other notary.%d doesnt have our.%d utxo yet\n",k,myind);
                sendutxo = 1;
                break;
            }
        }
        if ( ep->masks[bp->bestk] == 0 )
            dpow_signedtxgen(myinfo,bp->coin,bp,bp->bestk,bp->bestmask,myind,bp->opret_symbol,sigchannel);
        else dpow_sigsend(myinfo,bp,myind,bp->bestk,bp->bestmask,srchash,sigchannel);
    }
    if ( sendutxo != 0 )
    {
        hash = srchash;
        hash.uints[0] = rand();
        if ( (len= dpow_rwutxobuf(1,data,&bp->hashmsg,&bp->notaries[myind])) > 0 )
            dpow_send(myinfo,bp,hash,bp->hashmsg,utxochannel,bp->height,data,len,bp->utxocrcs);
    }
    if ( bp->state != 0xffffffff )
    {
        if ( ep->masks[bp->bestk] == 0 )
            dpow_signedtxgen(myinfo,bp->coin,bp,bp->bestk,bp->bestmask,myind,bp->opret_symbol,sigchannel);
        else dpow_sigsend(myinfo,bp,myind,bp->bestk,bp->bestmask,srchash,sigchannel);
    }
    return(bp->state);
}

uint32_t dpow_statemachineiterate(struct supernet_info *myinfo,struct dpow_info *dp,struct iguana_info *coin,struct dpow_block *bp,int32_t myind)
{
    int32_t j,match,sigmatch,len,vout,incr,haveutxo = 0; cJSON *addresses; char *sendtx,*rawtx,*opret_symbol,coinaddr[64]; uint32_t channel,sigchannel,txidchannel; bits256 txid,srchash,zero; uint8_t data[4096]; int8_t lastk; uint64_t sigsmask;
    if ( bp->numnotaries > 8 )
        incr = sqrt(bp->numnotaries) + 1;
    else incr = 1;
    memset(zero.bytes,0,sizeof(zero));
    if ( bits256_nonz(bp->btctxid) == 0 )
    {
        channel = DPOW_UTXOBTCCHANNEL;
        sigchannel = DPOW_SIGBTCCHANNEL;
        txidchannel = DPOW_BTCTXIDCHANNEL;
        opret_symbol = "";
    }
    else
    {
        channel = DPOW_UTXOCHANNEL;
        sigchannel = DPOW_SIGCHANNEL;
        txidchannel = DPOW_TXIDCHANNEL;
        opret_symbol = dp->symbol;
    }
    bitcoin_address(coinaddr,coin->chain->pubtype,myinfo->DPOW.minerkey33,33);
    if ( bits256_nonz(bp->hashmsg) == 0 )
        return(0xffffffff);
    for (j=0; j<sizeof(srchash); j++)
        srchash.bytes[j] = myinfo->DPOW.minerkey33[j+1];
    if ( bits256_nonz(bp->signedtxid) != 0 )
        bp->state = 0xffffffff;
    sigsmask = match = sigmatch = 0;
    if ( (bp->bestk= dpow_bestk(bp,&bp->bestmask)) >= 0 )
    {
        for (j=0; j<bp->numnotaries; j++)
        {
            if ( bp->notaries[j].masks[bp->bestk] == bp->bestmask )
            {
                match++;
                if ( bp->notaries[j].siglens[bp->bestk] > 0 )
                {
                    sigmatch++;
                    sigsmask |= (1LL << j);
                }
            }
        }
    }
    if ( (rand() % 10) == 0 )
        printf("[%d] %s ht.%d FSM.%d %s BTC.%d masks.%llx best.(%d %llx) match.(%d sigs.%d) sigsmask.%llx\n",myind,coin->symbol,bp->height,bp->state,coinaddr,bits256_nonz(bp->btctxid)==0,(long long)bp->recvmask,bp->bestk,(long long)bp->bestmask,match,sigmatch,(long long)sigsmask);
    if ( sigmatch == DPOW_M(bp) )
    {
        printf("sigmatch.%d\n",sigmatch);
        dpow_sigscheck(myinfo,bp,sigchannel,myind);
    }
    switch ( bp->state )
    {
        case 0:
            if ( (haveutxo= dpow_haveutxo(myinfo,coin,&txid,&vout,coinaddr)) != 0 && bits256_nonz(txid) != 0 )
            {
                bp->notaries[myind].prev_hash = txid;
                bp->notaries[myind].prev_vout = vout;
                bp->recvmask |= (1LL << myind);
                bp->state = 1;
            }
            if ( haveutxo < 10 && time(NULL) > dp->lastsplit+600 )
            {
                addresses = cJSON_CreateArray();
                jaddistr(addresses,coinaddr);
                if ( (rawtx= iguana_utxoduplicates(myinfo,coin,myinfo->DPOW.minerkey33,DPOW_UTXOSIZE,10,&bp->completed,&bp->signedtxid,0,addresses)) != 0 )
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
            break;
        case 1:
            dpow_lastk_mask(bp,&lastk);
            if ( (len= dpow_rwutxobuf(1,data,&bp->hashmsg,&bp->notaries[myind])) > 0 )
                dpow_send(myinfo,bp,srchash,bp->hashmsg,channel,bp->height,data,len,bp->utxocrcs);
            bp->recvmask |= (1LL << myind);
            bp->state = 2;
            break;
        default:
            dpow_update(myinfo,bp,channel,sigchannel,txidchannel,srchash,myind);
            break;
    }
    if ( bits256_nonz(bp->signedtxid) != 0 )
    {
        bp->state = 0xffffffff;
    }
    return(bp->state);
}

void dpow_statemachinestart(void *ptr)
{
    struct supernet_info *myinfo; struct dpow_info *dp; struct dpow_checkpoint checkpoint; void **ptrs = ptr;
    int32_t i,n,myind = -1; struct iguana_info *src,*dest; char str[65],coinaddr[64]; bits256 zero; struct dpow_block *srcbp,*destbp,*bp; uint32_t starttime = (uint32_t)time(NULL);
    memset(&zero,0,sizeof(zero));
    myinfo = ptrs[0];
    dp = ptrs[1];
    dp->destupdated = 0; // prevent another state machine till next BTC block
    memcpy(&checkpoint,&ptrs[2],sizeof(checkpoint));
    printf("statemachinestart %s->%s %s ht.%d\n",dp->symbol,dp->dest,bits256_str(str,checkpoint.blockhash.hash),checkpoint.blockhash.height);
    src = iguana_coinfind(dp->symbol);
    dest = iguana_coinfind(dp->dest);
    if ( (destbp= dp->destblocks[checkpoint.blockhash.height]) == 0 )
    {
        destbp = calloc(1,sizeof(*destbp));
        destbp->coin = iguana_coinfind(dp->dest);
        destbp->opret_symbol = dp->symbol;
        destbp->bestk = -1;
        dp->destblocks[checkpoint.blockhash.height] = destbp;
        destbp->beacon = rand256(0);
        vcalc_sha256(0,destbp->commit.bytes,destbp->beacon.bytes,sizeof(destbp->beacon));
        if ( (bp= dp->destblocks[checkpoint.blockhash.height - 100]) != 0 )
        {
            printf("purge %s.%d\n",dp->dest,checkpoint.blockhash.height - 100);
            dp->destblocks[checkpoint.blockhash.height - 100] = 0;
            free(bp);
        }
    }
    if ( (srcbp= dp->srcblocks[checkpoint.blockhash.height]) == 0 )
    {
        srcbp = calloc(1,sizeof(*srcbp));
        srcbp->coin = iguana_coinfind(dp->symbol);
        srcbp->opret_symbol = dp->symbol;
        srcbp->bestk = -1;
        dp->srcblocks[checkpoint.blockhash.height] = srcbp;
        srcbp->beacon = destbp->beacon;
        srcbp->commit = destbp->commit;
        printf("create srcbp[%d]\n",checkpoint.blockhash.height);
        if ( (bp= dp->srcblocks[checkpoint.blockhash.height - 1000]) != 0 )
        {
            printf("purge %s.%d\n",dp->symbol,checkpoint.blockhash.height - 1000);
            dp->srcblocks[checkpoint.blockhash.height - 1000] = 0;
            free(bp);
        }
    }
    n = (int32_t)(sizeof(Notaries)/sizeof(*Notaries));
    srcbp->numnotaries = destbp->numnotaries = n;
    for (i=0; i<n; i++)
    {
        decode_hex(srcbp->notaries[i].pubkey,33,Notaries[i][1]);
        decode_hex(destbp->notaries[i].pubkey,33,Notaries[i][1]);
        if ( memcmp(destbp->notaries[i].pubkey,myinfo->DPOW.minerkey33,33) == 0 )
            myind = i;
    }
    bitcoin_address(coinaddr,src->chain->pubtype,myinfo->DPOW.minerkey33,33);
    printf(" myaddr.%s\n",coinaddr);
    if ( myind < 0 )
    {
        printf("statemachinestart this node %s is not official notary\n",coinaddr);
        free(ptr);
        return;
    }
    dp->checkpoint = checkpoint;
    srcbp->height = destbp->height = checkpoint.blockhash.height;
    srcbp->timestamp = destbp->timestamp = checkpoint.timestamp;
    srcbp->hashmsg = destbp->hashmsg = checkpoint.blockhash.hash;
    printf("DPOW statemachine checkpoint.%d %s\n",checkpoint.blockhash.height,bits256_str(str,checkpoint.blockhash.hash));
    while ( time(NULL) < starttime+300 && src != 0 && dest != 0 && (srcbp->state != 0xffffffff || destbp->state != 0xffffffff) )
    {
        sleep(1);
        if ( dp->checkpoint.blockhash.height > checkpoint.blockhash.height )
        {
            printf("abort ht.%d due to new checkpoint.%d\n",checkpoint.blockhash.height,dp->checkpoint.blockhash.height);
            break;
        }
        if ( destbp->state != 0xffffffff )
        {
            //printf("dp->ht.%d ht.%d DEST.%08x %s\n",dp->checkpoint.blockhash.height,checkpoint.blockhash.height,deststate,bits256_str(str,srchash.hash));
            destbp->state = dpow_statemachineiterate(myinfo,dp,dest,destbp,myind);
            if ( destbp->state == 0xffffffff )
            {
                srcbp->btctxid = destbp->signedtxid;
                printf("SET BTCTXID.(%s)\n",bits256_str(str,srcbp->btctxid));
            }
        }
        if ( destbp->state == 0xffffffff && bits256_nonz(srcbp->btctxid) != 0 )
        {
            if ( dp->checkpoint.blockhash.height > checkpoint.blockhash.height )
            {
                printf("abort ht.%d due to new checkpoint.%d\n",checkpoint.blockhash.height,dp->checkpoint.blockhash.height);
                break;
            }
            if ( srcbp->state != 0xffffffff )
            {
                //printf("dp->ht.%d ht.%d SRC.%08x %s\n",dp->checkpoint.blockhash.height,checkpoint.blockhash.height,srcbp->state,bits256_str(str,srcbp->btctxid));
                srcbp->state = dpow_statemachineiterate(myinfo,dp,src,srcbp,myind);
            }
        }
    }
    free(ptr);
}
