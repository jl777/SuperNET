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
    up->commit = ep->commit;
    up->height = ep->height;
    up->recvmask = ep->recvmask;
    up->bestk = ep->bestk;
    up->srchash = ep->src.prev_hash;
    up->desthash = ep->dest.prev_hash;
    up->srcvout = ep->src.prev_vout;
    up->destvout = ep->dest.prev_vout;
}

void dpow_utxosync(struct supernet_info *myinfo,struct dpow_block *bp,uint64_t recvmask,int32_t myind,bits256 srchash)
{
    uint32_t i,j,r; int32_t len; struct dpow_utxoentry U; uint8_t utxodata[sizeof(U)+2];
    if ( (bp->recvmask ^ recvmask) != 0 )
    {
        if ( ((1LL << myind) & recvmask) == 0 )
        {
            i = myind;
            printf("utxosync bp->%llx != %llx, myind.%d\n",(long long)bp->recvmask,(long long)recvmask,myind);
        }
        else
        {
            r = (rand() % bp->numnotaries);
            for (j=0; j<DPOW_M(bp); j++)
            {
                i = ((bp->height % bp->numnotaries) + j + r) % bp->numnotaries;
                if ( ((1LL << i) & bp->recvmask) != 0 && ((1LL << i) & recvmask) == 0 )
                    break;
            }
            printf("utxosync bp->%llx != %llx, random pick.%d\n",(long long)bp->recvmask,(long long)recvmask,i);
        }
        memset(&U,0,sizeof(U));
        dpow_entry2utxo(&U,bp,&bp->notaries[i]);
        char str[65],str2[65];
        printf("send.(%s %s)\n",bits256_str(str,bp->notaries[i].dest.prev_hash),bits256_str(str2,bp->notaries[i].src.prev_hash));
        if ( (len= dpow_rwutxobuf(1,utxodata,&U,bp)) > 0 )
            dpow_send(myinfo,bp,srchash,bp->hashmsg,DPOW_UTXOCHANNEL,bp->height,utxodata,len,bp->utxocrcs);
    }
}

void dpow_sync(struct supernet_info *myinfo,struct dpow_block *bp,uint64_t refmask,int32_t myind,bits256 srchash,uint32_t channel,int32_t src_or_dest)
{
    int8_t lastk; uint64_t mask;
    mask = dpow_maskmin(refmask,bp,&lastk);
    dpow_utxosync(myinfo,bp,mask,myind,srchash);
    if ( bp->notaries[myind].masks[lastk] == 0 )
        dpow_signedtxgen(myinfo,(src_or_dest != 0) ? bp->destcoin : bp->srccoin,bp,lastk,mask,myind,bp->opret_symbol,bits256_nonz(bp->desttxid) == 0 ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL,src_or_dest);
}

int32_t dpow_datahandler(struct supernet_info *myinfo,uint32_t channel,uint32_t height,uint8_t *data,int32_t datalen,int32_t src_or_dest)
{
    bits256 hashmsg,txid,commit,srchash; struct dpow_block *bp = 0; uint32_t flag = 0; int32_t senderind,i,myind = -1; char str[65],str2[65]; struct dpow_sigentry dsig; struct dpow_entry *ep; struct dpow_coinentry *cp; struct dpow_utxoentry U; struct iguana_info *coin;
    if ( (bp= dpow_heightfind(myinfo,height)) == 0 )
        return(-1);
    dpow_notaryfind(myinfo,bp,&myind,myinfo->DPOW.minerkey33);
    if ( myind < 0 )
        return(-1);
    coin = (src_or_dest != 0) ? bp->destcoin : bp->srccoin;
    if ( channel == DPOW_UTXOCHANNEL )
    {
        memset(&U,0,sizeof(U));
        if ( dpow_rwutxobuf(0,data,&U,bp) < 0 )
        {
            printf("error from rwutxobuf\n");
            return(0);
        }
        if ( bits256_cmp(hashmsg,bp->hashmsg) != 0 )
        {
            printf("unexpected mismatch hashmsg.%s vs %s\n",bits256_str(str,hashmsg),bits256_str(str2,bp->hashmsg));
            return(0);
        }
        if ( (ep= dpow_notaryfind(myinfo,bp,&senderind,U.pubkey)) != 0 )
        {
            dpow_utxo2entry(bp,ep,&U);
            bp->recvmask |= (1LL << senderind);
            dpow_sync(myinfo,bp,ep->recvmask,myind,srchash,channel,src_or_dest);
            flag = 1;
        }
        //if ( 0 && flag == 0 && bp != 0 )
            printf("UTXO.%d hashmsg.(%s) txid.(%s) v%d\n",height,bits256_str(str,hashmsg),bits256_str(str2,src_or_dest!=0?U.desthash:U.srchash),src_or_dest!=0?U.destvout:U.srcvout);
    }
    else if ( channel == DPOW_SIGCHANNEL || channel == DPOW_SIGBTCCHANNEL )
    {
        if ( dpow_rwsigentry(0,data,&dsig) < 0 )
            return(0);
        if ( dsig.senderind >= 0 && dsig.senderind < DPOW_MAXRELAYS )
        {
            if ( dsig.lastk < bp->numnotaries && dsig.senderind < bp->numnotaries && (ep= dpow_notaryfind(myinfo,bp,&senderind,dsig.senderpub)) != 0 )
            {
                cp = (src_or_dest != 0) ? &bp->notaries[myind].dest : &bp->notaries[myind].src;
                vcalc_sha256(0,commit.bytes,dsig.beacon.bytes,sizeof(dsig.beacon));
                if ( memcmp(dsig.senderpub,bp->notaries[dsig.senderind].pubkey,33) == 0 )
                {
                    if ( ep->masks[dsig.lastk] == 0 )
                    {
                        ep->masks[dsig.lastk] = dsig.mask;
                        cp->siglens[dsig.lastk] = dsig.siglen;
                        memcpy(cp->sigs[dsig.lastk],dsig.sig,dsig.siglen);
                        ep->beacon = dsig.beacon;
                        printf(" <<<<<<<< %s from.%d got lastk.%d %llx siglen.%d >>>>>>>>>\n",coin->symbol,dsig.senderind,dsig.lastk,(long long)dsig.mask,dsig.siglen);
                        dpow_sync(myinfo,bp,dsig.mask,myind,srchash,channel,src_or_dest);
                        flag = 1;
                    }
                } else printf("%s pubkey mismatch for senderind.%d %llx vs %llx\n",coin->symbol,dsig.senderind,*(long long *)dsig.senderpub,*(long long *)bp->notaries[dsig.senderind].pubkey);
            } else printf("%s illegal lastk.%d or senderind.%d or senderpub.%llx\n",coin->symbol,dsig.lastk,dsig.senderind,*(long long *)dsig.senderpub);
        } else printf("couldnt find senderind.%d height.%d channel.%x\n",dsig.senderind,height,channel);
        //if ( 0 && bp != 0 )
            printf(" SIG.%d sender.%d lastk.%d mask.%llx siglen.%d recv.%llx\n",height,dsig.senderind,dsig.lastk,(long long)dsig.mask,dsig.siglen,(long long)bp->recvmask);
    }
    else if ( channel == DPOW_TXIDCHANNEL || channel == DPOW_BTCTXIDCHANNEL )
    {
        printf("handle txid channel.%x\n",channel);
        //printf("bp.%p datalen.%d\n",bp,datalen);
        for (i=0; i<32; i++)
            srchash.bytes[i] = data[i];
        /*if ( srchash.ulongs[0] == 0 )
         {
         init_hexbytes_noT(bp->rawtx,&data[32],datalen-32);
         //printf("got bestk.%d %llx rawtx.(%s) set utxo\n",srchash.bytes[31],(long long)srchash.ulongs[1],bp->rawtx);
         dpow_rawtxsign(myinfo,bp->coin,bp,bp->rawtx,0,srchash.bytes[31],srchash.ulongs[1],myind,bits256_nonz(bp->desttxid) == 0 ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL);
         }
         else*/
        {
            txid = bits256_doublesha256(0,&data[32],datalen-32);
            init_hexbytes_noT(bp->signedtx,&data[32],datalen-32);
            printf("signedtx.(%s)\n",bp->signedtx);
            if ( bits256_cmp(txid,srchash) == 0 )
            {
                printf("verify (%s) it is properly signed! set ht.%d signedtxid to %s\n",coin->symbol,height,bits256_str(str,txid));
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
    } else printf("unhandled channel.%x\n",channel);
    return(0);
}

int32_t dpow_update(struct supernet_info *myinfo,struct dpow_block *bp,uint32_t utxochannel,uint32_t sigchannel,uint32_t txidchannel,bits256 srchash,int32_t myind,int32_t src_or_dest)
{
    struct dpow_entry *ep; int32_t i,k,len,sendutxo = 1; uint8_t data[sizeof(struct dpow_entry)+2]; struct dpow_utxoentry U;
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
            dpow_signedtxgen(myinfo,(src_or_dest != 0) ? bp->destcoin : bp->srccoin,bp,bp->bestk,bp->bestmask,myind,bp->opret_symbol,sigchannel,src_or_dest);
        //else dpow_sigsend(myinfo,bp,myind,bp->bestk,bp->bestmask,srchash,sigchannel);
    }
    if ( 0 && sendutxo != 0 )
    {
        memset(&U,0,sizeof(U));
        dpow_entry2utxo(&U,bp,&bp->notaries[myind]);
        if ( (len= dpow_rwutxobuf(1,data,&U,bp)) > 0 )
            dpow_send(myinfo,bp,srchash,bp->hashmsg,utxochannel,bp->height,data,len,bp->utxocrcs);
    }
    if ( bp->state != 0xffffffff )
    {
        if ( ep->masks[bp->bestk] == 0 )
            dpow_signedtxgen(myinfo,(src_or_dest != 0) ? bp->destcoin : bp->srccoin,bp,bp->bestk,bp->bestmask,myind,bp->opret_symbol,sigchannel,src_or_dest);
        //else dpow_sigsend(myinfo,bp,myind,bp->bestk,bp->bestmask,srchash,sigchannel);
    }
    return(bp->state);
}

uint32_t dpow_statemachineiterate(struct supernet_info *myinfo,struct dpow_info *dp,struct iguana_info *coin,struct dpow_block *bp,int32_t myind,int32_t src_or_dest)
{
    int32_t j,match,sigmatch,incr; char *opret_symbol,coinaddr[64]; uint32_t channel,sigchannel,txidchannel; bits256 srchash,zero; uint64_t sigsmask; struct dpow_coinentry *cp;
    if ( bp->numnotaries > 8 )
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
                cp = (src_or_dest != 0) ? &bp->notaries[j].dest : &bp->notaries[j].src;
                if ( cp->siglens[bp->bestk] > 0 )
                {
                    sigmatch++;
                    sigsmask |= (1LL << j);
                }
            }
        }
    }
    if ( (rand() % 10) == 0 )
        printf("[%d] %s ht.%d FSM.%d %s BTC.%d masks.%llx best.(%d %llx) match.(%d sigs.%d) sigsmask.%llx\n",myind,coin->symbol,bp->height,bp->state,coinaddr,bits256_nonz(bp->desttxid)==0,(long long)bp->recvmask,bp->bestk,(long long)bp->bestmask,match,sigmatch,(long long)sigsmask);
    if ( sigmatch == DPOW_M(bp) )
    {
        printf("sigmatch.%d\n",sigmatch);
        dpow_sigscheck(myinfo,bp,sigchannel,myind,src_or_dest);
    }
    switch ( bp->state )
    {
        case 0:
            dpow_utxosync(myinfo,bp,0,myind,srchash);
            bp->state = 1;
            break;
        case 1:
            dpow_utxosync(myinfo,bp,0,myind,srchash);
            //dpow_lastk_mask(bp,&lastk);
            //memset(&U,0,sizeof(U));
            //dpow_entry2utxo(&U,bp,&bp->notaries[myind]);
            //if ( (len= dpow_rwutxobuf(1,data,&U,bp)) > 0 )
            //    dpow_send(myinfo,bp,srchash,bp->hashmsg,channel,bp->height,data,len,bp->utxocrcs);
            //bp->recvmask |= (1LL << myind);
            bp->state = 2;
            break;
        default:
            dpow_update(myinfo,bp,channel,sigchannel,txidchannel,srchash,myind,src_or_dest);
            break;
    }
    if ( bits256_nonz(bp->signedtxid) != 0 )
        bp->state = 0xffffffff;
    return(bp->state);
}

int32_t dpow_checkutxo(struct supernet_info *myinfo,struct dpow_block *bp,struct iguana_info *coin,bits256 *txidp,int32_t *voutp,char *coinaddr)
{
    int32_t haveutxo,completed; bits256 signedtxid; cJSON *addresses; char *rawtx,*sendtx;
    if ( (haveutxo= dpow_haveutxo(myinfo,coin,txidp,voutp,coinaddr)) <= 10 && time(NULL) > myinfo->DPOW.lastsplit+300 )
    {
        addresses = cJSON_CreateArray();
        jaddistr(addresses,coinaddr);
        if ( (rawtx= iguana_utxoduplicates(myinfo,coin,myinfo->DPOW.minerkey33,DPOW_UTXOSIZE,10,&completed,&signedtxid,0,addresses)) != 0 )
        {
            if ( (sendtx= dpow_sendrawtransaction(myinfo,coin,rawtx)) != 0 )
            {
                printf("sendrawtransaction.(%s)\n",sendtx);
                free(sendtx);
            }
            free(rawtx);
        }
        free_json(addresses);
        myinfo->DPOW.lastsplit = (uint32_t)time(NULL);
    }
    if ( bits256_nonz(*txidp) == 0 )
        return(-1);
    return(haveutxo);
}

void dpow_statemachinestart(void *ptr)
{
    struct supernet_info *myinfo; struct dpow_info *dp; struct dpow_checkpoint checkpoint; void **ptrs = ptr;
    int32_t i,n,myind = -1; struct iguana_info *src,*dest; char str[65],str2[65],srcaddr[64],destaddr[64]; bits256 zero,srchash; struct dpow_block *bp; struct dpow_entry *ep = 0; uint32_t starttime = (uint32_t)time(NULL);
    memset(&zero,0,sizeof(zero));
    myinfo = ptrs[0];
    dp = ptrs[1];
    dp->destupdated = 0; // prevent another state machine till next BTC block
    memcpy(&checkpoint,&ptrs[2],sizeof(checkpoint));
    printf("statemachinestart %s->%s %s ht.%d\n",dp->symbol,dp->dest,bits256_str(str,checkpoint.blockhash.hash),checkpoint.blockhash.height);
    src = iguana_coinfind(dp->symbol);
    dest = iguana_coinfind(dp->dest);
    if ( (bp= dp->blocks[checkpoint.blockhash.height]) == 0 )
    {
        bp = calloc(1,sizeof(*bp));
        bp->srccoin = src;
        bp->destcoin = dest;
        bp->opret_symbol = dp->symbol;
        bp->bestk = -1;
        dp->blocks[checkpoint.blockhash.height] = bp;
        bp->beacon = rand256(0);
        vcalc_sha256(0,bp->commit.bytes,bp->beacon.bytes,sizeof(bp->beacon));
        if ( dp->blocks[checkpoint.blockhash.height - 1000] != 0 )
        {
            printf("purge %s.%d\n",dp->dest,checkpoint.blockhash.height - 1000);
            free(dp->blocks[checkpoint.blockhash.height - 1000]);
            dp->blocks[checkpoint.blockhash.height - 1000] = 0;
        }
    }
    n = (int32_t)(sizeof(Notaries)/sizeof(*Notaries));
    bp->numnotaries = n;
    for (i=0; i<n; i++)
    {
        decode_hex(bp->notaries[i].pubkey,33,Notaries[i][1]);
        if ( memcmp(bp->notaries[i].pubkey,myinfo->DPOW.minerkey33,33) == 0 )
        {
            myind = i;
            ep = &bp->notaries[myind];
        }
    }
    if ( myind < 0 || ep == 0 )
    {
        printf("statemachinestart this node %s %s is not official notary\n",srcaddr,destaddr);
        free(ptr);
        return;
    }
    bitcoin_address(srcaddr,src->chain->pubtype,myinfo->DPOW.minerkey33,33);
    bitcoin_address(destaddr,dest->chain->pubtype,myinfo->DPOW.minerkey33,33);
    printf(" myaddr.(%s %s)\n",srcaddr,destaddr);
    if ( dpow_checkutxo(myinfo,bp,bp->destcoin,&ep->dest.prev_hash,&ep->dest.prev_vout,destaddr) < 0 )
    {
        printf("dont have %s %s utxo, please send funds\n",dp->dest,destaddr);
        free(ptr);
        return;
    }
    if ( dpow_checkutxo(myinfo,bp,bp->srccoin,&ep->src.prev_hash,&ep->src.prev_vout,srcaddr) < 0 )
    {
        printf("dont have %s %s utxo, please send funds\n",dp->symbol,srcaddr);
        free(ptr);
        return;
    }
    bp->recvmask |= (1LL << myind);
    dp->checkpoint = checkpoint;
    bp->height = checkpoint.blockhash.height;
    bp->timestamp = checkpoint.timestamp;
    bp->hashmsg = checkpoint.blockhash.hash;
    printf("DPOW statemachine checkpoint.%d %s\n",checkpoint.blockhash.height,bits256_str(str,checkpoint.blockhash.hash));
    for (i=0; i<sizeof(srchash); i++)
        srchash.bytes[i] = myinfo->DPOW.minerkey33[i+1];
    dpow_utxosync(myinfo,bp,0,myind,srchash);
    while ( time(NULL) < starttime+300 && src != 0 && dest != 0 && bp->state != 0xffffffff )
    {
        sleep(2);
        if ( dp->checkpoint.blockhash.height > checkpoint.blockhash.height )
        {
            printf("abort ht.%d due to new checkpoint.%d\n",checkpoint.blockhash.height,dp->checkpoint.blockhash.height);
            break;
        }
        if ( bp->state != 0xffffffff )
        {
            //printf("dp->ht.%d ht.%d DEST.%08x %s\n",dp->checkpoint.blockhash.height,checkpoint.blockhash.height,deststate,bits256_str(str,srchash.hash));
            bp->state = dpow_statemachineiterate(myinfo,dp,dest,bp,myind,1);
        }
    }
    printf("state machine ht.%d completed %s.%s %s.%s\n",bp->height,dp->dest,bits256_str(str,bp->desttxid),dp->symbol,bits256_str(str2,bp->srctxid));
    free(ptr);
}
