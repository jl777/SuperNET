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

#define DPOW_BLACKLIST -100000

void dpow_bestmask_update(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,uint8_t nn_senderind,int8_t nn_bestk,uint64_t nn_bestmask,uint64_t nn_recvmask)
{
    int32_t startscore;
    if ( nn_senderind < 0 || nn_senderind >= bp->numnotaries )
        return;
    bp->notaries[nn_senderind].bestk = nn_bestk;
    bp->notaries[nn_senderind].bestmask = nn_bestmask;
    bp->notaries[nn_senderind].recvmask = nn_recvmask;
    startscore = bp->scores[nn_senderind];
    if ( bp->bestk >= 0 )
    {
        if ( nn_bestk < 0 )
            bp->scores[nn_senderind] -= 10;
        else if ( nn_bestk != bp->bestk )
            bp->scores[nn_senderind]--;
        else if ( nn_bestmask != bp->bestmask )
            bp->scores[nn_senderind]--;
        else if ( bp->scores[nn_senderind] < 1 )
            bp->scores[nn_senderind] = 1;
        else bp->scores[nn_senderind]++;
        if ( startscore > DPOW_BLACKLIST && bp->scores[nn_senderind] <= DPOW_BLACKLIST )
            printf(">>>>>>>>>>>>> nn_senderind.%d %llx MIA, skip this node for now\n",nn_senderind,(long long)(1LL << nn_senderind));
    }
}

uint64_t dpow_lastk_mask(struct dpow_block *bp,int8_t *lastkp)
{
    int32_t j,m,k; uint64_t mask = bp->require0;
    *lastkp = -1;
    m = bp->require0;
    for (j=0; j<bp->numnotaries; j++)
    {
        k = DPOW_MODIND(bp,j);
        if ( (bp->require0 == 0 || k != 0) && bp->scores[k] < DPOW_BLACKLIST )
            continue;
        if ( bits256_nonz(bp->notaries[k].src.prev_hash) != 0 && bits256_nonz(bp->notaries[k].dest.prev_hash) != 0 )
        {
            bp->recvmask |= (1LL << k);
            mask |= (1LL << k);
            if ( ++m >= bp->minsigs )
            {
                *lastkp = k;
                break;
            }
        }
    }
    return(mask);
}

int32_t dpow_bestk(struct dpow_block *bp,uint64_t *maskp)
{
    int8_t lastk; uint64_t mask;
    *maskp = 0;
    mask = dpow_lastk_mask(bp,&lastk);
    if ( lastk < 0 )
        return(-1);
    *maskp = mask;
    return(lastk);
}

uint64_t dpow_ratifybest(uint64_t refmask,struct dpow_block *bp,int8_t *lastkp)
{
    int32_t m,j,k; uint64_t bestmask,mask = bp->require0;
    bestmask = 0;
    *lastkp = -1;
    if ( (m= bp->require0) != 0 )
        mask = 1;
    for (j=m; j<bp->numnotaries; j++)
    {
        k = DPOW_MODIND(bp,j);
        if ( bits256_nonz(bp->notaries[k].ratifysrcutxo) != 0 && bits256_nonz(bp->notaries[k].ratifydestutxo) != 0 )
        {
            mask |= (1LL << k);
            if ( ++m == bp->minsigs )
            {
                *lastkp = k;
                bestmask = mask;
            }
        }
    }
    return(bestmask);
}

uint64_t dpow_maskmin(uint64_t refmask,struct dpow_block *bp,int8_t *lastkp)
{
    int32_t j,m,k; uint64_t bestmask,mask = 0;//bp->require0;
    bestmask = 0;
    *lastkp = -1;
    m = 0;//bp->require0;
    for (j=0; j<bp->numnotaries; j++)
    {
        k = DPOW_MODIND(bp,j);
        //if ( (bp->require0 == 0 || k != 0) && bp->scores[k] < DPOW_BLACKLIST )
        //    continue;
        if ( bits256_nonz(bp->notaries[k].src.prev_hash) != 0 && bits256_nonz(bp->notaries[k].dest.prev_hash) != 0 )
        {
            mask |= (1LL << k);
            if ( ++m == bp->minsigs )
            {
                *lastkp = k;
                bestmask = mask;
            }
        }
    }
    bp->recvmask |= mask;
    if ( *lastkp >= 0 )
    {
        for (mask=j=0; j<bp->numnotaries; j++)
        {
            if ( bp->notaries[j].src.siglens[*lastkp] > 0 )
                mask |= (1LL << j);
        }
        bp->srcsigsmasks[*lastkp] |= mask;
        for (mask=j=0; j<bp->numnotaries; j++)
        {
            if ( bp->notaries[j].dest.siglens[*lastkp] > 0 )
                mask |= (1LL << j);
        }
        bp->destsigsmasks[*lastkp] |= mask;
   }
    return(bestmask);
}

struct dpow_block *dpow_heightfind(struct supernet_info *myinfo,struct dpow_info *dp,int32_t height)
{
    int32_t r,h,incr = 100000; struct dpow_block *bp = 0;
    if ( height > dp->maxblocks )
    {
        dp->blocks = realloc(dp->blocks,sizeof(*dp->blocks) * (dp->maxblocks + incr));
        memset(&dp->blocks[dp->maxblocks],0,sizeof(*dp->blocks) * incr);
        dp->maxblocks += incr;
    }
    if ( height < dp->maxblocks )
        bp = dp->blocks!=0 ? dp->blocks[height] : 0;
    if ( bp == 0 && height < DPOW_FIRSTRATIFY )
    {
        r = (rand() % DPOW_FIRSTRATIFY);
        for (h=0; h<DPOW_FIRSTRATIFY; h++)
        {
            height = (r + h) % DPOW_FIRSTRATIFY;
            if ( (bp= dp->blocks[height]) != 0 )
                return(bp);
        }
    }
    return(bp);
}

int32_t dpow_voutratify(struct dpow_block *bp,uint8_t *serialized,int32_t m,uint8_t pubkeys[][33],int32_t numratified)
{
    uint64_t satoshis; uint32_t locktime = 0; uint32_t numvouts; int32_t i,len = 0;
    numvouts = numratified + 1;
    len += iguana_rwvarint32(1,&serialized[len],&numvouts);
    satoshis = DPOW_UTXOSIZE;
    len += iguana_rwnum(1,&serialized[len],sizeof(satoshis),&satoshis);
    serialized[len++] = 35;
    serialized[len++] = 33;
    decode_hex(&serialized[len],33,CRYPTO777_PUBSECPSTR), len += 33;
    serialized[len++] = CHECKSIG;
    satoshis = DPOW_MINOUTPUT;
    for (i=0; i<numratified; i++)
    {
        len += iguana_rwnum(1,&serialized[len],sizeof(satoshis),&satoshis);
        serialized[len++] = 35;
        serialized[len++] = 33;
        memcpy(&serialized[len],pubkeys[i],33), len += 33;
        serialized[len++] = CHECKSIG;
    }
    len += iguana_rwnum(1,&serialized[len],sizeof(locktime),&locktime);
    return(len);
}

int32_t dpow_voutstandard(struct dpow_block *bp,uint8_t *serialized,int32_t m,int32_t src_or_dest)
{
    uint32_t locktime=0,numvouts; uint64_t satoshis,satoshisB; int32_t opretlen,len=0; uint8_t opret[1024],data[4096];
    numvouts = 2;
    len += iguana_rwvarint32(1,&serialized[len],&numvouts);
    satoshis = DPOW_UTXOSIZE * m * .76;
    if ( (satoshisB= DPOW_UTXOSIZE * m - 10000) < satoshis )
        satoshis = satoshisB;
    len += iguana_rwnum(1,&serialized[len],sizeof(satoshis),&satoshis);
    serialized[len++] = 35;
    serialized[len++] = 33;
    decode_hex(&serialized[len],33,CRYPTO777_PUBSECPSTR), len += 33;
    serialized[len++] = CHECKSIG;
    satoshis = 0;
    len += iguana_rwnum(1,&serialized[len],sizeof(satoshis),&satoshis);
    if ( src_or_dest != 0 )
        opretlen = dpow_rwopret(1,opret,&bp->hashmsg,&bp->height,bp->srccoin->symbol,bp,src_or_dest);
    else opretlen = dpow_rwopret(1,opret,&bp->hashmsg,&bp->height,bp->srccoin->symbol,bp,src_or_dest);
    if ( opretlen < 0 )
    {
        printf("negative opretlen src_or_dest.%d\n",src_or_dest);
        return(-1);
    }
    opretlen = dpow_opreturnscript(data,opret,opretlen);
    if ( opretlen < 0xfd )
        serialized[len++] = opretlen;
    else
    {
        serialized[len++] = 0xfd;
        serialized[len++] = opretlen & 0xff;
        serialized[len++] = (opretlen >> 8) & 0xff;
    }
    memcpy(&serialized[len],data,opretlen), len += opretlen;
    len += iguana_rwnum(1,&serialized[len],sizeof(locktime),&locktime);
    return(len);
}

bits256 dpow_notarytx(char *signedtx,int32_t *numsigsp,int32_t isPoS,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t usesigs,int32_t src_or_dest,uint8_t pubkeys[][33],int32_t numratified)
{
    uint32_t k,j,m,numsigs,version,sequenceid = 0xffffffff; bits256 zero; int32_t n,siglen,len; uint8_t serialized[32768],*sig; struct dpow_entry *ep; struct dpow_coinentry *cp;
    signedtx[0] = 0;
    *numsigsp = 0;
    memset(zero.bytes,0,sizeof(zero));
    len = numsigs = 0;
    version = 1;
    len += iguana_rwnum(1,&serialized[len],sizeof(version),&version);
    if ( isPoS != 0 )
        len += iguana_rwnum(1,&serialized[len],sizeof(bp->timestamp),&bp->timestamp);
    m = bp->minsigs;
    len += iguana_rwvarint32(1,&serialized[len],(uint32_t *)&m);
    for (j=m=0; j<bp->numnotaries; j++)
    {
        k = j;//DPOW_MODIND(bp,j);
        if ( ((1LL << k) & bestmask) != 0 )
        {
            if ( pubkeys != 0 && numratified > 0 )
            {
                if ( src_or_dest != 0 )
                {
                    char str[65]; printf("k.%d RATIFY DEST.%s\n",k,bits256_str(str,bp->notaries[k].ratifydestutxo));
                    len += iguana_rwbignum(1,&serialized[len],sizeof(bp->notaries[k].ratifydestutxo),bp->notaries[k].ratifydestutxo.bytes);
                    len += iguana_rwnum(1,&serialized[len],sizeof(bp->notaries[k].ratifydestvout),&bp->notaries[k].ratifydestvout);
                }
                else
                {
                    len += iguana_rwbignum(1,&serialized[len],sizeof(bp->notaries[k].ratifysrcutxo),bp->notaries[k].ratifysrcutxo.bytes);
                    len += iguana_rwnum(1,&serialized[len],sizeof(bp->notaries[k].ratifysrcvout),&bp->notaries[k].ratifysrcvout);
                }
                siglen = bp->notaries[k].ratifysiglens[src_or_dest];
                sig = bp->notaries[k].ratifysigs[src_or_dest];
            }
            else
            {
                ep = &bp->notaries[k];
                cp = (src_or_dest != 0) ? &bp->notaries[k].dest : &bp->notaries[k].src;
                if ( bits256_nonz(cp->prev_hash) == 0 )
                {
                    printf("null prevhash k.%d j.%d src_or_dest.%d\n",k,j,src_or_dest);
                    return(zero);
                }
                len += iguana_rwbignum(1,&serialized[len],sizeof(cp->prev_hash),cp->prev_hash.bytes);
                len += iguana_rwnum(1,&serialized[len],sizeof(cp->prev_vout),&cp->prev_vout);
                siglen = cp->siglens[bestk];
                sig = cp->sigs[bestk];
            }
            if ( usesigs != 0 )
            {
                len += iguana_rwvarint32(1,&serialized[len],(uint32_t *)&siglen);
                if ( siglen > 0 && siglen <= sizeof(cp->sigs[bestk]) )
                {
                    memcpy(&serialized[len],sig,siglen);
                    len += siglen;
                    numsigs++;
                }
            } else serialized[len++] = 0;
            len += iguana_rwnum(1,&serialized[len],sizeof(sequenceid),&sequenceid);
            //printf("height.%d mod.%d VINI.%d <- i.%d j.%d\n",height,height % numnotaries,m,i,j);
            m++;
            if ( m == bp->minsigs && k == bestk )
                break;
        }
    }
    if ( pubkeys != 0 && numratified > 0 )
    {
        printf("VOUTRATIFY\n");
        if ( (n= dpow_voutratify(bp,&serialized[len],m,pubkeys,numratified)) < 0 )
            return(zero);
        len += n;
    }
    else
    {
        if ( (n= dpow_voutstandard(bp,&serialized[len],m,src_or_dest)) < 0 )
        {
            printf("error dpow_voutstandard m.%d src_or_dest.%d\n",m,src_or_dest);
            return(zero);
        }
        len += n;
    }
    init_hexbytes_noT(signedtx,serialized,len);
    //printf("notarytx.(%s) opretlen.%d\n",signedtx,opretlen);
    *numsigsp = numsigs;
    return(bits256_doublesha256(0,serialized,len));
}

cJSON *dpow_vins(struct iguana_info *coin,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t usesigs,int32_t src_or_dest,int32_t useratified)
{
    int32_t k,j,m=0; bits256 txid; uint16_t vout; uint8_t script[35]; char scriptstr[256]; cJSON *vins=0,*item; struct dpow_entry *ep; struct dpow_coinentry *cp;
    vins = cJSON_CreateArray();
    for (j=0; j<bp->numnotaries; j++)
    {
        k = DPOW_MODIND(bp,j);
        if ( ((1LL << k) & bestmask) != 0 )
        {
            ep = &bp->notaries[k];
            if ( useratified != 0 )
            {
                if ( src_or_dest != 0 )
                {
                    txid = bp->notaries[k].ratifydestutxo;
                    vout = bp->notaries[k].ratifydestvout;
                }
                else
                {
                    txid = bp->notaries[k].ratifysrcutxo;
                    vout = bp->notaries[k].ratifysrcvout;
                }
            }
            else
            {
                cp = (src_or_dest != 0) ? &bp->notaries[k].dest : &bp->notaries[k].src;
                txid = cp->prev_hash;
                vout = cp->prev_vout;
            }
            if ( bits256_nonz(cp->prev_hash) != 0 )
            {
                item = cJSON_CreateObject();
                jaddbits256(item,"txid",txid);
                jaddnum(item,"vout",vout);
                script[0] = 33;
                memcpy(script+1,ep->pubkey,33);
                script[34] = CHECKSIG;
                init_hexbytes_noT(scriptstr,script,35);
                jaddstr(item,"scriptPubKey",scriptstr);
                jaddi(vins,item);
                //printf("height.%d mod.%d VINI.%d <- i.%d j.%d\n",height,height % numnotaries,m,i,j);
                m++;
                if ( m == bp->minsigs && k == bestk )
                    break;
            }
            else
            {
                free_json(vins);
                return(0);
            }
        }
    }
    return(vins);
}

void dpow_rawtxsign(struct supernet_info *myinfo,struct dpow_info *dp,struct iguana_info *coin,struct dpow_block *bp,char *rawtx,cJSON *vins,int8_t bestk,uint64_t bestmask,int32_t myind,int32_t src_or_dest)
{
    int32_t j,m=0,retval=-1; char *jsonstr,*signedtx,*rawtx2,*sigstr; cJSON *signobj,*sobj,*txobj2,*item,*vin; bits256 srchash; struct dpow_entry *ep; struct dpow_coinentry *cp;
    if ( bestk < 0 )
        return;
    for (j=0; j<sizeof(srchash); j++)
        srchash.bytes[j] = dp->minerkey33[j+1];
    m = 0;
    ep = &bp->notaries[myind];
    cp = (src_or_dest != 0) ? &bp->notaries[myind].dest : &bp->notaries[myind].src;
    if ( (jsonstr= dpow_signrawtransaction(myinfo,coin,rawtx,vins)) != 0 )
    {
        if ( (signobj= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( ((signedtx= jstr(signobj,"hex")) != 0 || (signedtx= jstr(signobj,"result")) != 0) && (rawtx2= dpow_decoderawtransaction(myinfo,coin,signedtx)) != 0 )
            {
                if ( (txobj2= cJSON_Parse(rawtx2)) != 0 )
                {
                    if ( (vin= jarray(&m,txobj2,"vin")) != 0 )
                    {
                        for (j=0; j<m; j++)
                        {
                            item = jitem(vin,j);
                            if ( (sobj= jobj(item,"scriptSig")) != 0 && (sigstr= jstr(sobj,"hex")) != 0 && strlen(sigstr) > 32 )
                            {
                                //printf("bestk.%d %llx %s height.%d mod.%d VINI.%d myind.%d MINE.(%s) j.%d\n",bestk,(long long)bestmask,(src_or_dest != 0) ? bp->destcoin->symbol : bp->srccoin->symbol,bp->height,DPOW_MODIND(bp,0),j,myind,jprint(item,0),j);
                                cp->siglens[bestk] = (int32_t)strlen(sigstr) >> 1;
                                if ( src_or_dest != 0 )
                                    bp->destsigsmasks[bestk] |= (1LL << myind);
                                else bp->srcsigsmasks[bestk] |= (1LL << myind);
                                decode_hex(cp->sigs[bestk],cp->siglens[bestk],sigstr);
                                ep->masks[src_or_dest][bestk] = bestmask;
                                ep->beacon = bp->beacon;
                                dpow_sigsend(myinfo,dp,bp,myind,bestk,bestmask,srchash,src_or_dest != 0 ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL);
                                retval = 0;
                                break;
                            } // else printf("notmine.(%s)\n",jprint(item,0));
                        }
                    } else printf("no vin[] (%s)\n",jprint(txobj2,0));
                    free_json(txobj2);
                } else printf("cant parse.(%s)\n",rawtx2);
                free(rawtx2);
            } //else printf("error decoding (%s) %s\n",signedtx==0?"":signedtx,jsonstr);
            free_json(signobj);
        } else printf("error parsing.(%s)\n",jsonstr);
        free(jsonstr);
    }
}

int32_t dpow_signedtxgen(struct supernet_info *myinfo,struct dpow_info *dp,struct iguana_info *coin,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t myind,uint32_t deprec,int32_t src_or_dest,int32_t useratified)
{
    int32_t j,m,numsigs,retval=-1; char rawtx[32768],*jsonstr,*rawtx2,*signedtx,*sigstr; cJSON *item,*sobj,*vins,*vin,*txobj2,*signobj; bits256 txid,srchash,zero; struct dpow_entry *ep;
    ep = &bp->notaries[myind];
    memset(&zero,0,sizeof(zero));
    if ( bestk < 0 )
        return(-1);
    for (j=0; j<sizeof(srchash); j++)
        srchash.bytes[j] = dp->minerkey33[j+1];
    printf("signedtxgen src_or_dest.%d (%d %llx) useratified.%d\n",src_or_dest,bestk,(long long)bestmask,useratified);
    if ( (vins= dpow_vins(coin,bp,bestk,bestmask,1,src_or_dest,useratified)) != 0 )
    {
        printf("call notarytx\n");
        txid = dpow_notarytx(rawtx,&numsigs,coin->chain->isPoS,bp,bestk,bestmask,0,src_or_dest,bp->numratified!=0?bp->ratified_pubkeys:0,useratified);
        printf("got notarytx (%s)\n",rawtx);
        if ( bits256_nonz(txid) != 0 && rawtx[0] != 0 ) // send tx to share utxo set
        {
            if ( useratified != 0 )
            {
                if ( (jsonstr= dpow_signrawtransaction(myinfo,coin,rawtx,vins)) != 0 )
                {
                    if ( (signobj= cJSON_Parse(jsonstr)) != 0 )
                    {
                        printf("signobj.(%s)\n",jsonstr);
                        if ( ((signedtx= jstr(signobj,"hex")) != 0 || (signedtx= jstr(signobj,"result")) != 0) && (rawtx2= dpow_decoderawtransaction(myinfo,coin,signedtx)) != 0 )
                        {
                            if ( (txobj2= cJSON_Parse(rawtx2)) != 0 )
                            {
                                if ( (vin= jarray(&m,txobj2,"vin")) != 0 )
                                {
                                    for (j=0; j<m; j++)
                                    {
                                        item = jitem(vin,j);
                                        if ( (sobj= jobj(item,"scriptSig")) != 0 && (sigstr= jstr(sobj,"hex")) != 0 && strlen(sigstr) > 32 )
                                        {
                                            bp->ratifysiglens[src_or_dest] = (int32_t)strlen(sigstr) >> 1;
                                            decode_hex(bp->ratifysigs[src_or_dest],bp->ratifysiglens[src_or_dest],sigstr);
                                            bp->ratifysigmasks[src_or_dest] |= (1LL << bp->myind);
                                            printf("RATIFYSIG[%d] <- set notaryid.%d\n",src_or_dest,bp->myind);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else dpow_rawtxsign(myinfo,dp,coin,bp,rawtx,vins,bestk,bestmask,myind,src_or_dest);
        } else printf("signedtxgen zero txid or null rawtx\n");
        free_json(vins);
    }
    else if ( (bestmask & bp->recvmask) != bestmask )
        printf("signedtxgen error generating vins bestk.%d %llx recv.%llx need to recv %llx\n",bestk,(long long)bestmask,(long long)bp->recvmask,(long long)(bestmask & ~bp->recvmask));
    return(retval);
}

void dpow_sigscheck(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,int32_t myind,int32_t src_or_dest)
{
    bits256 txid,srchash,zero,signedtxid; struct iguana_info *coin; int32_t j,len,numsigs; char *retstr=0,str[65],str2[65]; uint8_t txdata[32768]; uint32_t channel;
    coin = (src_or_dest != 0) ? bp->destcoin : bp->srccoin;
    memset(zero.bytes,0,sizeof(zero));
    channel = (src_or_dest != 0) ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL;
    printf("dpow_sigscheck myind.%d src_dest.%d state.%x coin.%s\n",myind,src_or_dest,bp->state,coin->symbol);
    if ( bp->state != 0xffffffff && coin != 0 )
    {
        signedtxid = dpow_notarytx(bp->signedtx,&numsigs,coin->chain->isPoS,bp,bp->bestk,bp->bestmask,1,src_or_dest,bp->numratified!=0?bp->ratified_pubkeys:0,bp->numratified);
        printf("src_or_dest.%d bestk.%d %llx %s numsigs.%d signedtx.(%s)\n",src_or_dest,bp->bestk,(long long)bp->bestmask,bits256_str(str,signedtxid),numsigs,bp->signedtx);
        bp->state = 1;
        if ( bits256_nonz(signedtxid) != 0 && numsigs == bp->minsigs )
        {
            if ( (retstr= dpow_sendrawtransaction(myinfo,coin,bp->signedtx)) != 0 )
            {
                printf("sendrawtransaction.(%s)\n",retstr);
                if ( is_hexstr(retstr,0) == sizeof(txid)*2 )
                {
                    decode_hex(txid.bytes,sizeof(txid),retstr);
                    if ( bits256_cmp(txid,signedtxid) == 0 )
                    {
                        if ( src_or_dest != 0 )
                        {
                            bp->desttxid = txid;
                            dpow_signedtxgen(myinfo,dp,bp->srccoin,bp,bp->bestk,bp->bestmask,myind,DPOW_SIGCHANNEL,0,bp->isratify);
                        } else bp->srctxid = txid;
                        len = (int32_t)strlen(bp->signedtx) >> 1;
                        decode_hex(txdata+32,len,bp->signedtx);
                        for (j=0; j<sizeof(srchash); j++)
                            txdata[j] = txid.bytes[j];
                        dpow_send(myinfo,dp,bp,txid,bp->hashmsg,(src_or_dest != 0) ? DPOW_BTCTXIDCHANNEL : DPOW_TXIDCHANNEL,bp->height,txdata,len+32);
                        bp->state = src_or_dest != 0 ? 1000 : 0xffffffff;
                        printf("complete statemachine.%s ht.%d state.%d (%x %x)\n",coin->symbol,bp->height,bp->state,bp->hashmsg.uints[0],txid.uints[0]);
                    } else printf("sendtxid mismatch got %s instead of %s\n",bits256_str(str,txid),bits256_str(str2,signedtxid));
                }
                free(retstr);
                retstr = 0;
            }
            else
            {
                printf("NULL return from sendrawtransaction. abort\n");
                bp->state = 0xffffffff;
            }
        }
    }
}

