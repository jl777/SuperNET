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
    ep->recvmask = up->recvmask;
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

void dpow_utxosync(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,uint64_t recvmask,int32_t myind,bits256 srchash)
{
    uint32_t i,j,r; int32_t len; struct dpow_utxoentry U; uint8_t utxodata[sizeof(U)+2];
    if ( (bp->recvmask ^ recvmask) != 0 )
    {
        if ( ((1LL << myind) & recvmask) == 0 )
        {
            i = myind;
            //printf("utxosync bp->%llx != %llx, myind.%d\n",(long long)bp->recvmask,(long long)recvmask,myind);
        }
        else
        {
            r = (rand() % bp->numnotaries);
            for (j=0; j<DPOW_M(bp); j++)
            {
                i = DPOW_MODIND(bp,j+r);
                if ( ((1LL << i) & bp->recvmask) != 0 && ((1LL << i) & recvmask) == 0 )
                    break;
            }
            //printf("utxosync bp->%llx != %llx, random pick.%d\n",(long long)bp->recvmask,(long long)recvmask,i);
        }
        memset(&U,0,sizeof(U));
        dpow_entry2utxo(&U,bp,&bp->notaries[i]);
        //char str[65],str2[65];
        //printf("send.(%s %s)\n",bits256_str(str,bp->notaries[i].dest.prev_hash),bits256_str(str2,bp->notaries[i].src.prev_hash));
        if ( (len= dpow_rwutxobuf(1,utxodata,&U,bp)) > 0 )
            dpow_send(myinfo,dp,bp,srchash,bp->hashmsg,DPOW_UTXOCHANNEL,bp->height,utxodata,len);
    }
}

void dpow_sync(struct supernet_info *myinfo,int32_t forceflag,struct dpow_info *dp,struct dpow_block *bp,int8_t bestk,uint64_t refmask,int32_t myind,bits256 srchash,uint32_t channel,int32_t src_or_dest)
{
    int8_t lastk; uint64_t mask;
    if ( bestk < 0 )
        mask = dpow_maskmin(refmask,bp,&lastk);
    else
    {
        lastk = bestk;
        mask = refmask;
    }
    //dpow_utxosync(myinfo,bp,mask,myind,srchash);
    if ( forceflag || bp->notaries[myind].masks[lastk] == 0 )
        dpow_signedtxgen(myinfo,dp,(src_or_dest != 0) ? bp->destcoin : bp->srccoin,bp,lastk,mask,myind,src_or_dest != 0 ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL,src_or_dest);
}

int32_t dpow_datahandler(struct supernet_info *myinfo,struct dpow_info *dp,uint32_t channel,uint32_t height,uint8_t *data,int32_t datalen)
{
    bits256 txid,commit,srchash,hashmsg; struct dpow_block *bp = 0; uint32_t flag = 0; int32_t src_or_dest,senderind,i,iter,rlen,myind = -1; char str[65],str2[65]; struct dpow_sigentry dsig; struct dpow_entry *ep; struct dpow_coinentry *cp; struct dpow_utxoentry U; struct iguana_info *coin;
    if ( (bp= dpow_heightfind(myinfo,dp,height)) == 0 )
    {
        if ( 0 && (rand() % 100) == 0 && height > 0 )
            printf("couldnt find height.%d | if you just started notary dapp this is normal\n",height);
        return(-1);
    }
    dpow_notaryfind(myinfo,bp,&myind,dp->minerkey33);
    if ( myind < 0 )
    {
        printf("couldnt find myind height.%d | this means your pubkey for this node is not registered and needs to be ratified by majority vote of all notaries\n",height);
        return(-1);
    }
    for (i=0; i<32; i++)
        srchash.bytes[i] = dp->minerkey33[i+1];
    if ( channel == DPOW_ENTRIESCHANNEL )
    {
        struct dpow_entry notaries[DPOW_MAXRELAYS]; uint8_t n; int8_t bestk; struct dpow_coinentry *ptr,*refptr;
        rlen = 0;
        bestk = data[rlen++];
        n = data[rlen++];
        rlen += iguana_rwbignum(0,&data[rlen],sizeof(hashmsg),hashmsg.bytes);
        //printf("got ENTRIES bestk.%d (%d %llx) recv.%llx numnotaries.%d\n",bestk,bp->bestk,(long long)bp->bestmask,(long long)bp->recvmask,n);
        if ( bits256_cmp(hashmsg,bp->hashmsg) == 0 )
        {
            memset(notaries,0,sizeof(notaries));
            for (i=0; i<64; i++)
                notaries[i].bestk = -1;
            rlen += dpow_rwcoinentrys(0,&data[rlen],notaries,n,bestk);
            //printf("matched hashmsg rlen.%d vs datalen.%d\n",rlen,datalen);
            for (i=0; i<n; i++)
            {
                for (iter=0; iter<2; iter++)
                {
                    ptr = iter != 0 ? &notaries[i].dest : &notaries[i].src;
                    refptr = iter != 0 ? &bp->notaries[i].dest : &bp->notaries[i].src;
                    if ( bits256_nonz(ptr->prev_hash) != 0 )
                    {
                        if ( bits256_nonz(refptr->prev_hash) == 0 )
                        {
                            printf(">>>>>>>>> %s got utxo.[%d] indirectly <<<<<<<<<<<\n",iter!=0?"dest":"src",i);
                            refptr->prev_hash = ptr->prev_hash;
                            refptr->prev_vout = ptr->prev_vout;
                            if ( iter == 1 && bits256_nonz(notaries[i].src.prev_hash) != 0 )
                                bp->recvmask |= (1LL << i);
                        }
                    }
                    if ( (bestk= notaries[i].bestk) >= 0 )
                    {
                        if ( ptr->siglens[bestk] > 0 && refptr->siglens[bestk] == 0 )
                        {
                            printf(">>>>>>>>>> got %s siglen.%d for [%d] indirectly bestk.%d <<<<<<<<<<\n",iter!=0?"dest":"src",ptr->siglens[bestk],i,bestk);
                            memcpy(refptr->sigs[bestk],ptr->sigs[bestk],ptr->siglens[bestk]);
                            refptr->siglens[bestk] = ptr->siglens[bestk];
                            if ( iter != 0 )
                                bp->destsigsmasks[bestk] |= (1LL << i);
                            else bp->srcsigsmasks[bestk] |= (1LL << i);
                        }
                    }
                }
            }
        }
    }
    else if ( channel == DPOW_UTXOCHANNEL )
    {
        src_or_dest = 1;
        coin = (src_or_dest != 0) ? bp->destcoin : bp->srccoin;
        memset(&U,0,sizeof(U));
        if ( dpow_rwutxobuf(0,data,&U,bp) < 0 )
        {
            printf("error from rwutxobuf\n");
            return(0);
        }
        if ( bits256_cmp(U.hashmsg,bp->hashmsg) != 0 && bits256_nonz(bp->hashmsg) != 0 )
        {
            printf("unexpected mismatch hashmsg.%s vs %s\n",bits256_str(str,U.hashmsg),bits256_str(str2,bp->hashmsg));
            return(0);
        }
        if ( (ep= dpow_notaryfind(myinfo,bp,&senderind,U.pubkey)) != 0 )
        {
            dpow_utxo2entry(bp,ep,&U);
            if ( ((1LL << senderind) & bp->recvmask) == 0 )
            {
                dpow_utxosync(myinfo,dp,bp,0,myind,srchash);
                bp->recvmask |= (1LL << senderind);
            }
            dpow_sync(myinfo,1,dp,bp,-1,ep->recvmask,myind,srchash,channel,src_or_dest);
            flag = 1;
        }
        //printf("bestk.%d %llx vs recv.%llx\n",bp->bestk,(long long)bp->bestmask,(long long)bp->recvmask);
        if ( 0 && flag == 0 && bp != 0 )
            printf("ep.%p sender.%d UTXO.%d hashmsg.(%s) txid.(%s) v%d %llx\n",ep,senderind,height,bits256_str(str,U.hashmsg),bits256_str(str2,src_or_dest!=0?U.desthash:U.srchash),src_or_dest!=0?U.destvout:U.srcvout,(long long)bp->recvmask);
    }
    else if ( channel == DPOW_SIGCHANNEL || channel == DPOW_SIGBTCCHANNEL )
    {
        if ( dpow_rwsigentry(0,data,&dsig) < 0 )
        {
            printf("rwsigentry error\n");
            return(0);
        }
        //printf("got sig.%x (%d %d) <<<<<<<<<< from.%d (%d %llx) sigs.%llx\n",channel,channel == DPOW_SIGCHANNEL,channel == DPOW_SIGBTCCHANNEL,dsig.senderind,dsig.lastk,(long long)dsig.mask,(long long)(dsig.lastk>=0?bp->destsigsmasks[dsig.lastk]:0));
        if ( channel == DPOW_SIGBTCCHANNEL )
        {
            src_or_dest = 1;
            coin = bp->destcoin;
            cp = &bp->notaries[dsig.senderind].dest;
            //printf("gotsig %s channel.%x from %d bestk.%d %llx\n",coin->symbol,channel,dsig.senderind,dsig.lastk,(long long)dsig.mask);
        }
        else
        {
            src_or_dest = 0;
            coin = bp->srccoin;
            cp = &bp->notaries[dsig.senderind].src;
        }
        if ( dsig.senderind >= 0 && dsig.senderind < DPOW_MAXRELAYS )
        {
            if ( dsig.lastk < bp->numnotaries && dsig.senderind < bp->numnotaries && (ep= dpow_notaryfind(myinfo,bp,&senderind,dsig.senderpub)) != 0 )
            {
                vcalc_sha256(0,commit.bytes,dsig.beacon.bytes,sizeof(dsig.beacon));
                if ( memcmp(dsig.senderpub,bp->notaries[dsig.senderind].pubkey,33) == 0 )
                {
                    //if ( ep->masks[dsig.lastk] == 0 )
                    {
                        ep->masks[src_or_dest][dsig.lastk] = dsig.mask;
                        cp->siglens[dsig.lastk] = dsig.siglen;
                        memcpy(cp->sigs[dsig.lastk],dsig.sig,dsig.siglen);
                        ep->beacon = dsig.beacon;
                        if ( src_or_dest != 0 )
                        {
                            bp->destsigsmasks[dsig.lastk] |= (1LL << dsig.senderind);
                            if ( bp->bestk >= 0 && bp->bestk == dsig.lastk && (bp->bestmask & bp->destsigsmasks[dsig.lastk]) == bp->bestmask )
                            {
                                dpow_sigscheck(myinfo,dp,bp,DPOW_SIGBTCCHANNEL,myind,1);
                            }
                        }
                        else
                        {
                            bp->srcsigsmasks[dsig.lastk] |= (1LL << dsig.senderind);
                            if ( bp->bestk >= 0 && bp->bestk == dsig.lastk && (bp->bestmask & bp->srcsigsmasks[dsig.lastk]) == bp->bestmask )
                            {
                                dpow_sigscheck(myinfo,dp,bp,DPOW_SIGCHANNEL,myind,0);
                            }
                        }
                        //printf(" ht.%d (%d %llx) <<<<<<<< %s from.%d got lastk.%d %llx/%llx siglen.%d >>>>>>>>>\n",bp->height,bp->bestk,(long long)bp->bestmask,coin->symbol,dsig.senderind,dsig.lastk,(long long)dsig.mask,(long long)bp->destsigsmasks[dsig.lastk],dsig.siglen);
                        dpow_sync(myinfo,1,dp,bp,dsig.lastk,dsig.mask,myind,srchash,channel,src_or_dest);
                        flag = 1;
                    }
                } else printf("%s pubkey mismatch for senderind.%d %llx vs %llx\n",coin->symbol,dsig.senderind,*(long long *)dsig.senderpub,*(long long *)bp->notaries[dsig.senderind].pubkey);
            } else printf("%s illegal lastk.%d or senderind.%d or senderpub.%llx\n",coin->symbol,dsig.lastk,dsig.senderind,*(long long *)dsig.senderpub);
        } else printf("couldnt find senderind.%d height.%d channel.%x\n",dsig.senderind,height,channel);
        //if ( 0 && bp != 0 )
        //    printf("%s SIG.%d sender.%d lastk.%d mask.%llx siglen.%d recv.%llx\n",coin->symbol,height,dsig.senderind,dsig.lastk,(long long)dsig.mask,dsig.siglen,(long long)bp->recvmask);
    }
    else if ( channel == DPOW_TXIDCHANNEL || channel == DPOW_BTCTXIDCHANNEL )
    {
        src_or_dest = (channel == DPOW_BTCTXIDCHANNEL);
        coin = (src_or_dest != 0) ? bp->destcoin : bp->srccoin;
        printf("handle txid channel.%x\n",channel);
        //printf("bp.%p datalen.%d\n",bp,datalen);
        for (i=0; i<32; i++)
            srchash.bytes[i] = data[i];
        txid = bits256_doublesha256(0,&data[32],datalen-32);
        init_hexbytes_noT(bp->signedtx,&data[32],datalen-32);
        printf("signedtx.(%s)\n",bp->signedtx);
        if ( bits256_cmp(txid,srchash) == 0 )
        {
            printf("verify (%s) it is properly signed! set ht.%d signedtxid to %s\n",coin->symbol,height,bits256_str(str,txid));
            if ( src_or_dest != 0 )
            {
                bp->desttxid = txid;
                bp->state = 1000;
                dp->destupdated = 0;
                dpow_signedtxgen(myinfo,dp,bp->srccoin,bp,bp->bestk,bp->bestmask,myind,DPOW_SIGCHANNEL,0);
                //dpow_sigscheck(myinfo,dp,bp,DPOW_SIGCHANNEL,myind,0);
            }
            else
            {
                bp->srctxid = txid;
                printf("set state COMPLETED\n");
                bp->state = 0xffffffff;
            }
        }
        else
        {
            init_hexbytes_noT(bp->signedtx,data,datalen);
            printf("txidchannel txid %s mismatch %s (%s)\n",bits256_str(str,txid),bits256_str(str2,srchash),bp->signedtx);
            bp->signedtx[0] = 0;
        }
    } else printf("unhandled channel.%x\n",channel);
    return(0);
}

int32_t dpow_update(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,uint32_t txidchannel,bits256 srchash,int32_t myind)
{
    struct dpow_entry *ep; int32_t i,k,len,src_or_dest,sendutxo = 0; uint8_t data[sizeof(struct dpow_entry)+2]; struct dpow_utxoentry U;
    ep = &bp->notaries[myind];
    if ( bp->state < 1000 )
    {
        src_or_dest = 1;
        bp->bestmask = dpow_maskmin(bp->recvmask,bp,&bp->bestk);
        if ( bp->bestk >= 0 )
        {
            sendutxo = 0;
            for (i=0; i<bp->numnotaries; i++)
            {
                k = DPOW_MODIND(bp,i);
                if ( k == myind )
                    continue;
                if ( ((1LL << k) & bp->recvmask) != 0 && (bp->notaries[k].recvmask & (1LL << myind)) == 0 )
                {
                    //printf("other notary.%d doesnt have our.%d utxo yet\n",k,myind);
                    sendutxo = 1;
                    break;
                }
            }
            if ( ep->masks[src_or_dest][bp->bestk] == 0 )
                dpow_signedtxgen(myinfo,dp,(src_or_dest != 0) ? bp->destcoin : bp->srccoin,bp,bp->bestk,bp->bestmask,myind,DPOW_SIGBTCCHANNEL,src_or_dest);
            if ( bp->bestk >= 0 && (rand() % 10) == 0 )
                dpow_sigsend(myinfo,dp,bp,myind,bp->bestk,bp->bestmask,srchash,DPOW_SIGBTCCHANNEL);
        } else sendutxo = 1;
        if ( sendutxo != 0 )
        {
            memset(&U,0,sizeof(U));
            dpow_entry2utxo(&U,bp,&bp->notaries[myind]);
            if ( (len= dpow_rwutxobuf(1,data,&U,bp)) > 0 )
                dpow_send(myinfo,dp,bp,srchash,bp->hashmsg,DPOW_UTXOCHANNEL,bp->height,data,len);
        }
        if ( bp->bestk >= 0 && ep->masks[src_or_dest][bp->bestk] == 0 )
            dpow_signedtxgen(myinfo,dp,(src_or_dest != 0) ? bp->destcoin : bp->srccoin,bp,bp->bestk,bp->bestmask,myind,DPOW_SIGBTCCHANNEL,src_or_dest);
        if ( bp->bestk >= 0 && (rand() % 10) == 0 )
        {
            dpow_sigsend(myinfo,dp,bp,myind,bp->bestk,bp->bestmask,srchash,DPOW_SIGBTCCHANNEL);
            for (i=0; i<bp->numnotaries; i++)
                if ( bp->notaries[i].bestk >= 0 && bp->notaries[i].bestk != bp->bestk && bitweight(bp->notaries[i].recvmask & bp->recvmask) >= 7 )
                    dpow_sigsend(myinfo,dp,bp,myind,bp->notaries[i].bestk,bp->recvmask,srchash,DPOW_SIGBTCCHANNEL);
        }
    }
    else if ( bp->state != 0xffffffff )
    {
        src_or_dest = 0;
        if ( bp->bestk >= 0 && ep->masks[src_or_dest][bp->bestk] == 0 )
            dpow_signedtxgen(myinfo,dp,(src_or_dest != 0) ? bp->destcoin : bp->srccoin,bp,bp->bestk,bp->bestmask,myind,DPOW_SIGCHANNEL,src_or_dest);
        if ( bp->bestk >= 0 && (rand() % 10) == 0 )
            dpow_sigsend(myinfo,dp,bp,myind,bp->bestk,bp->bestmask,srchash,DPOW_SIGCHANNEL);
    }
    if ( (rand() % 10) == 0 )
    {
        if ( bp->isratify != 0 )
        {
            uint64_t sigsmask,srcmask;
            if ( bp->bestk < 0 )
                sigsmask = srcmask = 0;
            else sigsmask = bp->destsigsmasks[bp->bestk], srcmask = bp->srcsigsmasks[bp->bestk];
            printf("notary[%d] %s numips.%d isratify.%d ht.%d FSM.%08x masks.%llx best.(%d %llx) sigsmask.%llx %llx src.%llx\n",myind,src_or_dest != 0 ? bp->destcoin->symbol : bp->srccoin->symbol,myinfo->numdpowipbits,bp->isratify,bp->height,bp->state,(long long)bp->recvmask,bp->bestk,(long long)bp->bestmask,(long long)sigsmask,(long long)(sigsmask & bp->bestmask),(long long)srcmask);
        }
        if ( bp->isratify != 0 )
        {
            bp->bestmask = dpow_maskmin(bp->recvmask,bp,&bp->bestk);
            dpow_sendcoinentrys(myinfo,dp,bp);
            if ( bp->bestk >= 0 )
                dpow_signedtxgen(myinfo,dp,(bp->state < 1000) ? bp->destcoin : bp->srccoin,bp,bp->bestk,bp->bestmask,myind,bp->state < 1000 ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL,bp->state < 1000);
            printf("ht.%d numnotaries.%d BEST.%llx from RECV.%llx bestk.%d sigsmask.%llx missing.%llx\n",bp->height,bp->numnotaries,(long long)bp->bestmask,(long long)bp->recvmask,bp->bestk,bp->bestk>=0?(long long)bp->destsigsmasks[bp->bestk]:0,bp->bestk>=0?(long long)(bp->bestmask & ~bp->destsigsmasks[bp->bestk]):0);
            if ( bp->height < DPOW_FIRSTRATIFY )
                dp->blocks[bp->height] = bp;
        }
    }
    if ( bp->state < 1000 && bp->bestk >= 0 && (bp->destsigsmasks[bp->bestk] & bp->bestmask) == bp->bestmask )
    {
        dpow_sigscheck(myinfo,dp,bp,DPOW_SIGBTCCHANNEL,myind,1);
    }
    else if ( bp->state != 0xffffffff && bp->bestk >= 0 && (bp->srcsigsmasks[bp->bestk] & bp->bestmask) == bp->bestmask )
    {
        dpow_sigscheck(myinfo,dp,bp,DPOW_SIGCHANNEL,myind,0);
    }
    return(bp->state);
}

uint32_t dpow_statemachineiterate(struct supernet_info *myinfo,struct dpow_info *dp,struct iguana_info *coin,struct dpow_block *bp,int32_t myind,int32_t src_or_dest)
{
    int32_t j,incr; char *opret_symbol,coinaddr[64]; uint32_t channel,sigchannel,txidchannel; bits256 srchash,zero;
    if ( 0 && bp->numnotaries > 8 )
        incr = sqrt(bp->numnotaries) + 1;
    else incr = 1;
    memset(zero.bytes,0,sizeof(zero));
    channel = DPOW_UTXOCHANNEL;
    if ( bits256_nonz(bp->desttxid) == 0 )
    {
        sigchannel = DPOW_SIGBTCCHANNEL;
        txidchannel = DPOW_BTCTXIDCHANNEL;
        opret_symbol = "";
    }
    else
    {
        sigchannel = DPOW_SIGCHANNEL;
        txidchannel = DPOW_TXIDCHANNEL;
        opret_symbol = dp->symbol;
    }
    bitcoin_address(coinaddr,coin->chain->pubtype,dp->minerkey33,33);
    if ( bits256_nonz(bp->hashmsg) == 0 && bp->height >= DPOW_FIRSTRATIFY )
    {
        printf("null hashmsg\n");
        return(0);
    }
    for (j=0; j<sizeof(srchash); j++)
        srchash.bytes[j] = dp->minerkey33[j+1];
    bp->bestk = dpow_bestk(bp,&bp->bestmask);
    if ( bp->state < 7 )
    {
        dpow_utxosync(myinfo,dp,bp,0,myind,srchash);
        bp->state++;
    }
    else
    {
        dpow_update(myinfo,dp,bp,txidchannel,srchash,myind);
        if ( bits256_nonz(bp->srctxid) != 0 )
            bp->state = 0xffffffff;
    }
    return(bp->state);
}

int32_t dpow_checkutxo(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,struct iguana_info *coin,bits256 *txidp,int32_t *voutp,char *coinaddr)
{
    int32_t haveutxo,completed; bits256 signedtxid; cJSON *addresses; char *rawtx,*sendtx;
    if ( (haveutxo= dpow_haveutxo(myinfo,coin,txidp,voutp,coinaddr)) <= 9 && time(NULL) > dp->lastsplit+bp->duration )
    {
        addresses = cJSON_CreateArray();
        jaddistr(addresses,coinaddr);
        if ( (rawtx= iguana_utxoduplicates(myinfo,coin,dp->minerkey33,DPOW_UTXOSIZE,strcmp(coin->symbol,"BTC") == 0 ? 50 : 10,&completed,&signedtxid,0,addresses)) != 0 )
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
    int32_t i,destprevvout0,srcprevvout0,numratified=0,kmdheight,myind = -1; uint8_t pubkeys[64][33]; cJSON *ratified=0,*item; struct iguana_info *src,*dest; char *jsonstr,*handle,*hexstr,str[65],str2[65],srcaddr[64],destaddr[64]; bits256 zero,srchash,destprevtxid0,srcprevtxid0; struct dpow_block *bp; struct dpow_entry *ep = 0; uint32_t duration,minsigs,starttime;
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
    printf("statemachinestart %s->%s %s ht.%d minsigs.%d duration.%d start.%u\n",dp->symbol,dp->dest,bits256_str(str,checkpoint.blockhash.hash),checkpoint.blockhash.height,minsigs,duration,checkpoint.timestamp);
    src = iguana_coinfind(dp->symbol);
    dest = iguana_coinfind(dp->dest);
    if ( strcmp(src->symbol,"KMD") == 0 )
        kmdheight = checkpoint.blockhash.height;
    else if ( strcmp(dest->symbol,"KMD") == 0 )
        kmdheight = dest->longestchain;
    if ( (bp= dp->blocks[checkpoint.blockhash.height]) == 0 )
    {
        bp = calloc(1,sizeof(*bp));
        bp->minsigs = minsigs;
        if ( (bp->duration= duration) == DPOW_RATIFYDURATION )
            bp->isratify = 1;
        bp->srccoin = src;
        bp->destcoin = dest;
        bp->opret_symbol = dp->symbol;
        if ( jsonstr != 0 && (ratified= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (numratified= cJSON_GetArraySize(ratified)) > 0 )
            {
                for (i=0; i<numratified; i++)
                {
                    item = jitem(ratified,i);
                    hexstr = handle = 0;
                    if ( (hexstr= jstr(item,"pubkey")) != 0 && is_hexstr(hexstr,0) == 66 && (handle= jstr(item,"handle")) != 0 )
                    {
                        decode_hex(bp->ratified_pubkeys[i],33,hexstr);
                        safecopy(bp->handles[i],handle,sizeof(bp->handles[i]));
                        if ( i == 0 )
                        {
                            destprevtxid0 = jbits256(item,"destprevtxid0");
                            destprevvout0 = jint(item,"destprevvout0");
                            srcprevtxid0 = jbits256(item,"srcprevtxid0");
                            srcprevvout0 = jint(item,"srcprevvout0");
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
    bitcoin_address(srcaddr,src->chain->pubtype,dp->minerkey33,33);
    bitcoin_address(destaddr,dest->chain->pubtype,dp->minerkey33,33);
    if ( kmdheight >= 0 )
    {
        bp->numnotaries = komodo_notaries(pubkeys,kmdheight);
        for (i=0; i<bp->numnotaries; i++)
        {
            //for (j=0; j<33; j++)
            //    printf("%02x",pubkeys[i][j]);
            //printf(" <= pubkey[%d]\n",i);
            memcpy(bp->notaries[i].pubkey,pubkeys[i],33);
            if ( memcmp(bp->notaries[i].pubkey,dp->minerkey33,33) == 0 )
            {
                myind = i;
                ep = &bp->notaries[myind];
            }
        }
        if ( myind < 0 || ep == 0 )
        {
            printf("minerkey33-> ");
            for (i=0; i<33; i++)
                printf("%02x",dp->minerkey33[i]);
            printf(" statemachinestart this node %s %s is not official notary numnotaries.%d\n",srcaddr,destaddr,bp->numnotaries);
            free(ptr);
            return;
        }
    }
    else
    {
        printf("statemachinestart no kmdheight.%d\n",kmdheight);
        free(ptr);
        return;
    }
    printf(" myind.%d myaddr.(%s %s)\n",myind,srcaddr,destaddr);
    if ( myind == 0 && bits256_nonz(destprevtxid0) != 0 && bits256_nonz(srcprevtxid0) != 0 && destprevvout0 >= 0 && srcprevvout0 >= 0 )
    {
        ep->dest.prev_hash = destprevtxid0;
        ep->dest.prev_vout = destprevvout0;
        ep->src.prev_hash = srcprevtxid0;
        ep->src.prev_vout = srcprevvout0;
        printf("Use override utxo %s/v%d %s/v%d\n",bits256_str(str,destprevtxid0),destprevvout0,bits256_str(str2,srcprevtxid0),srcprevvout0);
    }
    else
    {
        if ( dpow_checkutxo(myinfo,dp,bp,bp->destcoin,&ep->dest.prev_hash,&ep->dest.prev_vout,destaddr) < 0 )
        {
            printf("dont have %s %s utxo, please send funds\n",dp->dest,destaddr);
            free(ptr);
            return;
        }
        if ( dpow_checkutxo(myinfo,dp,bp,bp->srccoin,&ep->src.prev_hash,&ep->src.prev_vout,srcaddr) < 0 )
        {
            printf("dont have %s %s utxo, please send funds\n",dp->symbol,srcaddr);
            free(ptr);
            return;
        }
    }
    bp->recvmask |= (1LL << myind);
    bp->notaries[myind].othermask |= (1LL << myind);
    dp->checkpoint = checkpoint;
    bp->height = checkpoint.blockhash.height;
    bp->timestamp = checkpoint.timestamp;
    bp->hashmsg = checkpoint.blockhash.hash;
    while ( bp->isratify == 0 && dp->destupdated == 0 )
    {
        if ( dp->checkpoint.blockhash.height > checkpoint.blockhash.height )
        {
            printf("abort ht.%d due to new checkpoint.%d\n",checkpoint.blockhash.height,dp->checkpoint.blockhash.height);
            return;
        }
        sleep(1);
    }
    if ( bp->isratify == 0 || (starttime= checkpoint.timestamp) == 0 )
        starttime = (uint32_t)time(NULL);
    printf("isratify.%d DPOW.%s statemachine checkpoint.%d %s start.%u\n",bp->isratify,src->symbol,checkpoint.blockhash.height,bits256_str(str,checkpoint.blockhash.hash),checkpoint.timestamp);
    for (i=0; i<sizeof(srchash); i++)
        srchash.bytes[i] = dp->minerkey33[i+1];
    //printf("start utxosync start.%u %u\n",starttime,(uint32_t)time(NULL));
    dpow_utxosync(myinfo,dp,bp,0,myind,srchash);
    //printf("done utxosync start.%u %u\n",starttime,(uint32_t)time(NULL));
    while ( time(NULL) < starttime+bp->duration && src != 0 && dest != 0 && bp->state != 0xffffffff )
    {
        sleep(1);
        if ( dp->checkpoint.blockhash.height > checkpoint.blockhash.height )
        {
            if ( bp->isratify == 0 )
            {
                printf("abort ht.%d due to new checkpoint.%d\n",checkpoint.blockhash.height,dp->checkpoint.blockhash.height);
                break;
            }
            else
            {
                bp->bestk = -1;
                bp->bestmask = bp->recvmask = 0;
                bp->height = ((dp->checkpoint.blockhash.height / 10) % (DPOW_FIRSTRATIFY/10)) * 10;
                printf("new rotation ht.%d\n",bp->height);
                dp->blocks[checkpoint.blockhash.height] = 0;
                checkpoint.blockhash.height = dp->checkpoint.blockhash.height;
                dp->blocks[checkpoint.blockhash.height] = bp;
                /*for (i=0; i<64; i++)
                {
                    bp->notaries[i].recvmask = 0;
                    bp->notaries[i].bestk = -1;
                }
                memset(bp->destsigsmasks,0,sizeof(bp->destsigsmasks));
                memset(bp->notaries[myind].masks,0,sizeof(bp->notaries[myind].masks));*/
            }
        }
        if ( bp->state != 0xffffffff )
        {
            //printf("dp->ht.%d ht.%d DEST.%08x %s\n",dp->checkpoint.blockhash.height,checkpoint.blockhash.height,bp->state,bits256_str(str,srchash));
            bp->state = dpow_statemachineiterate(myinfo,dp,dest,bp,myind,1);
        }
        if ( 0 && dp->cancelratify != 0 && bp->isratify != 0 )
        {
            printf("abort pending ratify\n");
            break;
        }
    }
    printf("bestk.%d %llx sigs.%llx state machine ht.%d completed state.%x %s.%s %s.%s recvmask.%llx\n",bp->bestk,(long long)bp->bestmask,(long long)(bp->bestk>=0?bp->destsigsmasks[bp->bestk]:0),bp->height,bp->state,dp->dest,bits256_str(str,bp->desttxid),dp->symbol,bits256_str(str2,bp->srctxid),(long long)bp->recvmask);
    dp->lastrecvmask = bp->recvmask;
    free(ptr);
}

