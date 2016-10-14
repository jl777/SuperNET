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
        if ( bits256_nonz(bp->notaries[k].prev_hash) != 0 )
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
        if ( bits256_nonz(bp->notaries[k].prev_hash) != 0 )
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

struct dpow_block *dpow_heightfind(struct supernet_info *myinfo,int32_t height,int32_t destflag)
{
    if ( destflag != 0 )
        return(myinfo->DPOW.destblocks!=0?myinfo->DPOW.destblocks[height]:0);
    else return(myinfo->DPOW.srcblocks!=0?myinfo->DPOW.srcblocks[height]:0);
}

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

bits256 dpow_notarytx(char *signedtx,int32_t *numsigsp,int32_t isPoS,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,char *src)
{
    uint32_t i,j,m,numsigs,locktime,numvouts,version,opretlen,siglen,len,sequenceid = 0xffffffff;
    uint64_t satoshis,satoshisB; uint8_t serialized[32768],opret[1024],data[4096];
    len = locktime = numsigs = 0;
    version = 1;
    len += iguana_rwnum(1,&serialized[len],sizeof(version),&version);
    if ( isPoS != 0 )
        len += iguana_rwnum(1,&serialized[len],sizeof(bp->timestamp),&bp->timestamp);
    m = DPOW_M(bp);
    len += iguana_rwvarint32(1,&serialized[len],(uint32_t *)&m);
    for (j=m=0; j<bp->numnotaries; j++)
    {
        i = ((bp->height % bp->numnotaries) + j) % bp->numnotaries;
        if ( ((1LL << i) & bestmask) != 0 )
        {
            if ( bits256_nonz(bp->notaries[i].prev_hash) == 0 )
                return(bp->notaries[i].prev_hash);
            len += iguana_rwbignum(1,&serialized[len],sizeof(bp->notaries[i].prev_hash),bp->notaries[i].prev_hash.bytes);
            len += iguana_rwnum(1,&serialized[len],sizeof(bp->notaries[i].prev_vout),&bp->notaries[i].prev_vout);
            siglen = bp->notaries[i].siglens[bestk];
            len += iguana_rwvarint32(1,&serialized[len],&siglen);
            if ( siglen > 0 && siglen <= sizeof(bp->notaries[i].sigs[bestk]) )
            {
                memcpy(&serialized[len],bp->notaries[i].sigs[bestk],siglen);
                len += siglen;
                numsigs++;
            }
            len += iguana_rwnum(1,&serialized[len],sizeof(sequenceid),&sequenceid);
            //printf("height.%d mod.%d VINI.%d <- i.%d j.%d\n",height,height % numnotaries,m,i,j);
            m++;
            if ( m == DPOW_M(bp) && i == bestk )
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
    opretlen = dpow_rwopret(1,opret,&bp->hashmsg,&bp->height,&bp->btctxid,src);
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

cJSON *dpow_createtx(struct iguana_info *coin,cJSON **vinsp,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t usesigs)
{
    int32_t i,j,m=0,siglen; char scriptstr[256]; cJSON *txobj=0,*vins=0,*item; uint64_t satoshis; uint8_t script[35],*sig;
    if ( (txobj= bitcoin_txcreate(coin->chain->isPoS,0,1,0)) != 0 )
    {
        jaddnum(txobj,"suppress",1);
        jaddnum(txobj,"timestamp",bp->timestamp);
        vins = cJSON_CreateArray();
        for (j=0; j<bp->numnotaries; j++)
        {
            i = ((bp->height % bp->numnotaries) + j) % bp->numnotaries;
            if ( ((1LL << i) & bestmask) != 0 )
            {
                if ( bits256_nonz(bp->notaries[i].prev_hash) != 0 )
                {
                    item = cJSON_CreateObject();
                    jaddbits256(item,"txid",bp->notaries[i].prev_hash);
                    jaddnum(item,"vout",bp->notaries[i].prev_vout);
                    script[0] = 33;
                    memcpy(script+1,bp->notaries[i].pubkey,33);
                    script[34] = CHECKSIG;
                    init_hexbytes_noT(scriptstr,script,35);
                    jaddstr(item,"scriptPubKey",scriptstr);
                    sig = 0, siglen = 0;
                    if ( usesigs != 0 && bp->notaries[i].siglens[bestk] > 0 )
                    {
                        init_hexbytes_noT(scriptstr,bp->notaries[i].sigs[bestk],bp->notaries[i].siglens[bestk]);
                        jaddstr(item,"scriptSig",scriptstr);
                        //printf("sig%d.(%s)\n",i,scriptstr);
                        sig = bp->notaries[i].sigs[bestk];
                        siglen = bp->notaries[i].siglens[bestk];
                    }
                    jaddi(vins,item);
                    bitcoin_txinput(coin,txobj,bp->notaries[i].prev_hash,bp->notaries[i].prev_vout,0xffffffff,script,sizeof(script),0,0,0,0,sig,siglen);
                    //printf("height.%d mod.%d VINI.%d <- i.%d j.%d\n",height,height % numnotaries,m,i,j);
                    m++;
                    if ( m == DPOW_M(bp) && i == bestk )
                        break;
                }
                else
                {
                    free_json(vins), vins = 0;
                    free_json(txobj);
                    return(0);
                }
            }
        }
        satoshis = DPOW_UTXOSIZE * m * .76;
        script[0] = 33;
        decode_hex(script+1,33,CRYPTO777_PUBSECPSTR);
        script[34] = CHECKSIG;
        txobj = bitcoin_txoutput(txobj,script,sizeof(script),satoshis);
    }
    *vinsp = vins;
    if ( 0 && usesigs != 0 )
        printf("%s createtx.(%s)\n",coin->symbol,jprint(txobj,0));
    return(txobj);
}


void dpow_rawtxsign(struct supernet_info *myinfo,struct iguana_info *coin,struct dpow_block *bp,char *rawtx,cJSON *vins,int8_t bestk,uint64_t bestmask,int32_t myind,uint32_t sigchannel)
{
    int32_t j,m=0,flag=0,retval=-1; char *jsonstr,*signedtx,*rawtx2,*sigstr; cJSON *signobj,*sobj,*txobj2,*item,*vin; bits256 srchash; struct dpow_entry *ep = &bp->notaries[myind];
    /*if ( vins == 0 && bitweight(bestmask) == DPOW_M(bp) )
     {
     if ( (rawtx2= dpow_decoderawtransaction(myinfo,coin,rawtx)) != 0 )
     {
     if ( (txobj= cJSON_Parse(rawtx2)) != 0 )
     {
     vins = jduplicate(jobj(txobj,"vin"));
     free_json(txobj);
     //printf("generated vins.(%s)\n",jprint(vins,0));
     }
     free(rawtx2);
     }
     if ( vins != 0 )
     {
     flag = 1;
     n = cJSON_GetArraySize(vins);
     k = (bp->height % bp->numnotaries) % bp->numnotaries;
     for (i=0; i<n; i++)
     {
     while ( ((1LL << k) & bestmask) == 0 )
     if ( ++k >= bp->numnotaries )
     k = 0;
     item = jitem(vins,i);
     //printf("(%s) i.%d of %d, (%d) k.%d bestmask.%llx\n",jprint(item,0),i,n,(bp->height % bp->numnotaries) % bp->numnotaries,k,(long long)bestmask);
     if ( bits256_nonz(bp->notaries[k].prev_hash) == 0 )
     {
     bp->notaries[k].prev_hash = jbits256(item,"txid");
     if ( bits256_nonz(bp->notaries[k].prev_hash) != 0 )
     {
     bp->notaries[k].prev_vout = jint(item,"vout");
     bp->recvmask |= (1LL << k);
     printf(">>>>>>>> rawtx utxo.%d %s/v%d %llx\n",k,bits256_str(str,bp->notaries[k].prev_hash),bp->notaries[k].prev_vout,(long long)bp->recvmask);
     }
     }
     if ( i < n-1 )
     k++;
     }
     if ( k != bestk )
     printf("extracted uxto k.%d != bestk.%d %llx\n",k,bestk,(long long)bestmask);
     }
     }*/
    m = 0;
    if ( (jsonstr= dpow_signrawtransaction(myinfo,coin,rawtx,vins)) != 0 )
    {
        printf("bestk.%d mask.%llx dpowsign.(%s)\n",bestk,(long long)bestmask,jsonstr);
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
                                printf("height.%d mod.%d VINI.%d myind.%d MINE.(%s) j.%d\n",bp->height,bp->height%bp->numnotaries,j,myind,jprint(item,0),j);
                                ep->siglens[bestk] = (int32_t)strlen(sigstr) >> 1;
                                decode_hex(ep->sigs[bestk],ep->siglens[bestk],sigstr);
                                ep->masks[bestk] = bestmask;
                                ep->siglens[bestk] = ep->siglens[bestk];
                                ep->beacon = bp->beacon;
                                dpow_sigsend(myinfo,bp,myind,bestk,bestmask,srchash,sigchannel);
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
    if ( flag != 0 && vins != 0 )
        free_json(vins);
}

int32_t dpow_signedtxgen(struct supernet_info *myinfo,struct iguana_info *coin,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t myind,char *opret_symbol,uint32_t sigchannel)
{
    int32_t j,incr,numsigs,retval=-1; char rawtx[32768]; cJSON *txobj,*vins; bits256 txid,srchash,zero; struct dpow_entry *ep;
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
    if ( (txobj= dpow_createtx(coin,&vins,bp,bestk,bestmask,1)) != 0 )
    {
        txid = dpow_notarytx(rawtx,&numsigs,coin->chain->isPoS,bp,bestk,bestmask,opret_symbol);
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
            dpow_rawtxsign(myinfo,coin,bp,rawtx,vins,bestk,bestmask,myind,sigchannel);
        }
        free_json(txobj);
        //fprintf(stderr,"free vins\n");
        //free_json(vins);
    }
    return(retval);
}

void dpow_sigscheck(struct supernet_info *myinfo,struct dpow_block *bp,uint32_t channel,int32_t myind)
{
    bits256 txid,srchash,zero; int32_t j,len,numsigs; char *retstr=0,str[65],str2[65]; uint8_t txdata[32768];
    memset(zero.bytes,0,sizeof(zero));
    if ( bp->state != 0xffffffff && bp->coin != 0 )
    {
        bp->signedtxid = dpow_notarytx(bp->signedtx,&numsigs,bp->coin->chain->isPoS,bp,bp->bestk,bp->bestmask,bp->opret_symbol);
        printf("%s numsigs.%d signedtx.(%s)\n",bits256_str(str,bp->signedtxid),numsigs,bp->signedtx);
        bp->state = 1;
        if ( bits256_nonz(bp->signedtxid) != 0 && numsigs == DPOW_M(bp) )
        {
            if ( (retstr= dpow_sendrawtransaction(myinfo,bp->coin,bp->signedtx)) != 0 )
            {
                printf("sendrawtransaction.(%s)\n",retstr);
                if ( is_hexstr(retstr,0) == sizeof(txid)*2 )
                {
                    decode_hex(txid.bytes,sizeof(txid),retstr);
                    if ( bits256_cmp(txid,bp->signedtxid) == 0 )
                    {
                        len = (int32_t)strlen(bp->signedtx) >> 1;
                        decode_hex(txdata+32,len,bp->signedtx);
                        for (j=0; j<sizeof(srchash); j++)
                            txdata[j] = txid.bytes[j];
                        dpow_send(myinfo,bp,txid,bp->hashmsg,(channel == DPOW_SIGBTCCHANNEL) ? DPOW_BTCTXIDCHANNEL : DPOW_TXIDCHANNEL,bp->height,txdata,len+32,bp->txidcrcs);
                        printf("complete statemachine.%s ht.%d\n",bp->coin->symbol,bp->height);
                        bp->state = 0xffffffff;
                    } else printf("sendtxid mismatch got %s instead of %s\n",bits256_str(str,txid),bits256_str(str2,bp->signedtxid));
                }
                free(retstr);
                retstr = 0;
            }
        }
    }
}

