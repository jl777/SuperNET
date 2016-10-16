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

uint64_t dpow_lastk_mask(struct dpow_block *bp,int8_t *lastkp)
{
    int32_t j,m,k; uint64_t mask = 0;
    *lastkp = -1;
    for (j=m=0; j<bp->numnotaries; j++)
    {
        k = ((bp->height % bp->numnotaries) + j) % bp->numnotaries;
        if ( bits256_nonz(bp->notaries[k].src.prev_hash) != 0 && bits256_nonz(bp->notaries[k].dest.prev_hash) != 0 )
        {
            bp->recvmask |= (1LL << k);
            mask |= (1LL << k);
            if ( ++m >= DPOW_M(bp) )
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

uint64_t dpow_maskmin(uint64_t refmask,struct dpow_block *bp,int8_t *lastkp)
{
    int32_t j,m,k; uint64_t mask = 0;
    for (j=m=0; j<bp->numnotaries; j++)
    {
        k = ((bp->height % bp->numnotaries) + j) % bp->numnotaries;
        if ( bits256_nonz(bp->notaries[k].src.prev_hash) != 0 && bits256_nonz(bp->notaries[k].dest.prev_hash) != 0 )
        {
            mask |= (1LL << k);
            if ( ++m >= DPOW_M(bp) )
            {
                *lastkp = k;
                break;
            }
        }
    }
    return(mask);
}

struct dpow_block *dpow_heightfind(struct supernet_info *myinfo,int32_t height)
{
    return(myinfo->DPOW.blocks!=0?myinfo->DPOW.blocks[height]:0);
}

bits256 dpow_notarytx(char *signedtx,int32_t *numsigsp,int32_t isPoS,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t usesigs,int32_t src_or_dest)
{
    uint32_t k,j,m,numsigs,locktime,numvouts,version,sequenceid = 0xffffffff;
    uint64_t satoshis,satoshisB; bits256 zero; int32_t opretlen,siglen,len; uint8_t serialized[32768],opret[1024],data[4096]; struct dpow_entry *ep; struct dpow_coinentry *cp;
    signedtx[0] = 0;
    *numsigsp = 0;
    memset(zero.bytes,0,sizeof(zero));
    len = locktime = numsigs = 0;
    version = 1;
    len += iguana_rwnum(1,&serialized[len],sizeof(version),&version);
    if ( isPoS != 0 )
        len += iguana_rwnum(1,&serialized[len],sizeof(bp->timestamp),&bp->timestamp);
    m = DPOW_M(bp);
    len += iguana_rwvarint32(1,&serialized[len],(uint32_t *)&m);
    for (j=m=0; j<bp->numnotaries; j++)
    {
        k = ((bp->height % bp->numnotaries) + j) % bp->numnotaries;
        if ( ((1LL << k) & bestmask) != 0 )
        {
            ep = &bp->notaries[k];
            cp = (src_or_dest != 0) ? &bp->notaries[k].dest : &bp->notaries[k].src;
            if ( bits256_nonz(cp->prev_hash) == 0 )
                return(cp->prev_hash);
            len += iguana_rwbignum(1,&serialized[len],sizeof(cp->prev_hash),cp->prev_hash.bytes);
            len += iguana_rwnum(1,&serialized[len],sizeof(cp->prev_vout),&cp->prev_vout);
            siglen = cp->siglens[bestk];
            if ( usesigs != 0 )
            {
                len += iguana_rwvarint32(1,&serialized[len],(uint32_t *)&siglen);
                if ( siglen > 0 && siglen <= sizeof(cp->sigs[bestk]) )
                {
                    memcpy(&serialized[len],cp->sigs[bestk],siglen);
                    len += siglen;
                    numsigs++;
                }
            } else serialized[len++] = 0;
            len += iguana_rwnum(1,&serialized[len],sizeof(sequenceid),&sequenceid);
            //printf("height.%d mod.%d VINI.%d <- i.%d j.%d\n",height,height % numnotaries,m,i,j);
            m++;
            if ( m == DPOW_M(bp) && k == bestk )
                break;
        }
    }
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
        opretlen = dpow_rwopret(1,opret,&bp->hashmsg,&bp->height,0,bp,src_or_dest);
    else opretlen = dpow_rwopret(1,opret,&bp->hashmsg,&bp->height,bp->srccoin->symbol,bp,src_or_dest);
    if ( opretlen < 0 )
        return(zero);
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
    init_hexbytes_noT(signedtx,serialized,len);
    //printf("notarytx.(%s) opretlen.%d\n",signedtx,opretlen);
    *numsigsp = numsigs;
    return(bits256_doublesha256(0,serialized,len));
}

cJSON *dpow_vins(struct iguana_info *coin,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t usesigs,int32_t src_or_dest)
{
    int32_t k,j,m=0; uint8_t script[35]; char scriptstr[256]; cJSON *vins=0,*item; struct dpow_entry *ep; struct dpow_coinentry *cp;
    vins = cJSON_CreateArray();
    for (j=0; j<bp->numnotaries; j++)
    {
        k = ((bp->height % bp->numnotaries) + j) % bp->numnotaries;
        if ( ((1LL << k) & bestmask) != 0 )
        {
            ep = &bp->notaries[k];
            cp = (src_or_dest != 0) ? &bp->notaries[k].dest : &bp->notaries[k].src;
            if ( bits256_nonz(cp->prev_hash) != 0 )
            {
                item = cJSON_CreateObject();
                jaddbits256(item,"txid",cp->prev_hash);
                jaddnum(item,"vout",cp->prev_vout);
                script[0] = 33;
                memcpy(script+1,ep->pubkey,33);
                script[34] = CHECKSIG;
                init_hexbytes_noT(scriptstr,script,35);
                jaddstr(item,"scriptPubKey",scriptstr);
                jaddi(vins,item);
                //printf("height.%d mod.%d VINI.%d <- i.%d j.%d\n",height,height % numnotaries,m,i,j);
                m++;
                if ( m == DPOW_M(bp) && k == bestk )
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

void dpow_rawtxsign(struct supernet_info *myinfo,struct iguana_info *coin,struct dpow_block *bp,char *rawtx,cJSON *vins,int8_t bestk,uint64_t bestmask,int32_t myind,int32_t src_or_dest)
{
    int32_t j,m=0,retval=-1; char *jsonstr,*signedtx,*rawtx2,*sigstr; cJSON *signobj,*sobj,*txobj2,*item,*vin; bits256 srchash; struct dpow_entry *ep; struct dpow_coinentry *cp;
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
                                printf("%s height.%d mod.%d VINI.%d myind.%d MINE.(%s) j.%d\n",(src_or_dest != 0) ? bp->destcoin->symbol : bp->srccoin->symbol,bp->height,bp->height%bp->numnotaries,j,myind,jprint(item,0),j);
                                cp->siglens[bestk] = (int32_t)strlen(sigstr) >> 1;
                                if ( src_or_dest != 0 )
                                    bp->destsigsmasks[bestk] |= (1LL << myind);
                                else bp->srcsigsmasks[bestk] |= (1LL << myind);
                                decode_hex(cp->sigs[bestk],cp->siglens[bestk],sigstr);
                                ep->masks[src_or_dest][bestk] = bestmask;
                                ep->beacon = bp->beacon;
                                dpow_sigsend(myinfo,bp,myind,bestk,bestmask,srchash,src_or_dest != 0 ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL);
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

int32_t dpow_signedtxgen(struct supernet_info *myinfo,struct iguana_info *coin,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t myind,uint32_t sigchannel,int32_t src_or_dest)
{
    int32_t j,incr,numsigs,retval=-1; char rawtx[32768]; cJSON *vins; bits256 txid,srchash,zero; struct dpow_entry *ep;
    if ( bp->numnotaries < 8 )
        incr = 1;
    else incr = sqrt(bp->numnotaries) + 1;
    bestmask = dpow_maskmin(bestmask,bp,&bestk);
    ep = &bp->notaries[myind];
    memset(&zero,0,sizeof(zero));
    if ( bestk < 0 )
        return(-1);
    for (j=0; j<sizeof(srchash); j++)
        srchash.bytes[j] = myinfo->DPOW.minerkey33[j+1];
    if ( (vins= dpow_vins(coin,bp,bestk,bestmask,1,src_or_dest)) != 0 )
    {
        txid = dpow_notarytx(rawtx,&numsigs,coin->chain->isPoS,bp,bestk,bestmask,0,src_or_dest);
        if ( bits256_nonz(txid) != 0 && rawtx[0] != 0 ) // send tx to share utxo set
        {
            /*memset(&tmp,0,sizeof(tmp));
             tmp.ulongs[1] = bestmask;
             tmp.bytes[31] = bestk;
             len = (int32_t)strlen(rawtx) >> 1;
             decode_hex(txdata+32,len,rawtx);
             for (j=0; j<sizeof(srchash); j++)
             txdata[j] = tmp.bytes[j];
             dpow_send(myinfo,bp,zero,bp->hashmsg,(bits256_nonz(bp->btctxid) == 0) ? DPOW_BTCTXIDCHANNEL : DPOW_TXIDCHANNEL,bp->height,txdata,len+32,bp->txidcrcs);*/
            dpow_rawtxsign(myinfo,coin,bp,rawtx,vins,bestk,bestmask,myind,src_or_dest);
        } else printf("signedtxgen zero txid or null rawtx\n");
        free_json(vins);
    } else printf("signedtxgen error generating vins\n");
    return(retval);
}

void dpow_sigscheck(struct supernet_info *myinfo,struct dpow_block *bp,uint32_t channel,int32_t myind,int32_t src_or_dest)
{
    bits256 txid,srchash,zero,signedtxid; struct iguana_info *coin; int32_t j,len,numsigs; char *retstr=0,str[65],str2[65]; uint8_t txdata[32768];
    coin = (src_or_dest != 0) ? bp->destcoin : bp->srccoin;
    memset(zero.bytes,0,sizeof(zero));
    //printf("sigscheck myind.%d src_dest.%d state.%x\n",myind,src_or_dest,bp->state);
    if ( bp->state != 0xffffffff && coin != 0 )
    {
        signedtxid = dpow_notarytx(bp->signedtx,&numsigs,coin->chain->isPoS,bp,bp->bestk,bp->bestmask,1,src_or_dest);
        printf("src_or_dest.%d bestk.%d %llx %s numsigs.%d signedtx.(%s)\n",src_or_dest,bp->bestk,(long long)bp->bestmask,bits256_str(str,signedtxid),numsigs,bp->signedtx);
        bp->state = 1;
        if ( bits256_nonz(signedtxid) != 0 && numsigs == DPOW_M(bp) )
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
                            printf("send out KMD sig\n");
                            dpow_signedtxgen(myinfo,bp->srccoin,bp,bp->bestk,bp->bestmask,myind,DPOW_SIGCHANNEL,0);
                        }
                        else bp->srctxid = txid;
                        len = (int32_t)strlen(bp->signedtx) >> 1;
                        decode_hex(txdata+32,len,bp->signedtx);
                        for (j=0; j<sizeof(srchash); j++)
                            txdata[j] = txid.bytes[j];
                        dpow_send(myinfo,bp,txid,bp->hashmsg,(src_or_dest != 0) ? DPOW_BTCTXIDCHANNEL : DPOW_TXIDCHANNEL,bp->height,txdata,len+32,bp->txidcrcs);
                        printf("complete statemachine.%s ht.%d\n",coin->symbol,bp->height);
                        bp->state = src_or_dest != 0 ? 1000 : 0xffffffff;
                    } else printf("sendtxid mismatch got %s instead of %s\n",bits256_str(str,txid),bits256_str(str2,signedtxid));
                }
                free(retstr);
                retstr = 0;
            }
        }
    }
}

