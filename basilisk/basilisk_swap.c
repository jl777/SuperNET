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

// included from basilisk.c

struct basilisk_rawtx *basilisk_swapdata_rawtx(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx)
{
    if ( rawtx->txbytes != 0 && rawtx->datalen <= maxlen )
    {
        memcpy(data,rawtx->txbytes,rawtx->datalen);
        return(rawtx);
    }
    return(0);
}

int32_t basilisk_verify_otherfee(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    return(0);
}

int32_t basilisk_verify_bobdeposit(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    return(0);
}

int32_t basilisk_verify_bobpaid(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    return(0);
}

int32_t basilisk_verify_alicepaid(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    return(0);
}

int32_t basilisk_numconfirms(struct supernet_info *myinfo,struct basilisk_rawtx *rawtx)
{
    return(10);
}

bits256 basilisk_swap_broadcast(struct supernet_info *myinfo,struct basilisk_swap *swap,struct iguana_info *coin,uint8_t *data,int32_t datalen)
{
    bits256 txid;
    memset(txid.bytes,0,sizeof(txid));
    return(txid);
}

/*reclaim_tx
{
    find vout of (re)claim
    construct vin spend
    splice together tx
}*/

// end of coin protocol dependent


bits256 instantdex_derivekeypair(struct supernet_info *myinfo,bits256 *newprivp,uint8_t pubkey[33],bits256 privkey,bits256 orderhash)
{
    bits256 sharedsecret;
    sharedsecret = curve25519_shared(privkey,orderhash);
    vcalc_sha256cat(newprivp->bytes,orderhash.bytes,sizeof(orderhash),sharedsecret.bytes,sizeof(sharedsecret));
    return(bitcoin_pubkey33(myinfo->ctx,pubkey,*newprivp));
}

int32_t instantdex_pubkeyargs(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t numpubs,bits256 privkey,bits256 hash,int32_t firstbyte)
{
    char buf[3]; int32_t i,n,m,len=0; bits256 pubi; uint64_t txid; uint8_t secret160[20],pubkey[33];
    sprintf(buf,"%c0",'A' - 0x02 + firstbyte);
    if ( numpubs > 2 )
    {
        if ( swap->numpubs+2 >= numpubs )
            return(numpubs);
        printf(">>>>>> start generating %s\n",buf);
    }
    for (i=n=m=0; i<numpubs*100 && n<numpubs; i++)
    {
        pubi = instantdex_derivekeypair(myinfo,&privkey,pubkey,privkey,hash);
        //printf("i.%d n.%d numpubs.%d %02x vs %02x\n",i,n,numpubs,pubkey[0],firstbyte);
        if ( pubkey[0] != firstbyte )
            continue;
        if ( n < 2 )
        {
            if ( bits256_nonz(swap->mypubs[n]) == 0 )
            {
                swap->myprivs[n] = privkey;
                memcpy(swap->mypubs[n].bytes,pubkey+1,sizeof(bits256));
            }
        }
        if ( m < INSTANTDEX_DECKSIZE )
        {
            swap->privkeys[m] = privkey;
            calc_rmd160_sha256(secret160,privkey.bytes,sizeof(privkey));
            memcpy(&txid,secret160,sizeof(txid));
            len += iguana_rwnum(1,(uint8_t *)&swap->deck[m][0],sizeof(txid),&txid);
            len += iguana_rwnum(1,(uint8_t *)&swap->deck[m][1],sizeof(pubi.txid),&pubi.txid);
            m++;
            if ( m > swap->numpubs )
                swap->numpubs = m;
        }
        n++;
    }
    if ( n > 2 || m > 2 )
        printf("n.%d m.%d len.%d numpubs.%d\n",n,m,len,swap->numpubs);
    return(n);
}

int32_t basilisk_rawtx_gen(char *str,struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t lockinputs,struct basilisk_rawtx *rawtx,uint32_t locktime,uint8_t *script,int32_t scriptlen,int64_t txfee,int32_t minconf)
{
    struct iguana_waddress *waddr; struct iguana_waccount *wacct; char coinaddr[64],wifstr[64],*txbytes=0,*signedtx,*retstr,scriptstr[1024]; bits256 signedtxid; uint32_t basilisktag; int32_t flag,completed,retval = -1; cJSON *valsobj,*vins=0,*retjson=0,*privkeyarray,*addresses;
    if ( (waddr= iguana_getaccountaddress(myinfo,rawtx->coin,0,0,rawtx->coin->changeaddr,"change")) == 0 )
    {
        printf("no change addr error\n");
        return(-1);
    }
    init_hexbytes_noT(scriptstr,script,scriptlen);
    privkeyarray = cJSON_CreateArray();
    addresses = cJSON_CreateArray();
    if ( rawtx->coin->changeaddr[0] == 0 )
        bitcoin_address(rawtx->coin->changeaddr,rawtx->coin->chain->pubtype,waddr->rmd160,20);
    //bitcoin_pubkey33(myinfo->ctx,pubkey33,myinfo->persistent_priv);
    bitcoin_address(coinaddr,rawtx->coin->chain->pubtype,myinfo->persistent_pubkey33,33);
    //printf("%s persistent.(%s) (%s) change.(%s) scriptstr.(%s)\n",coin->symbol,myinfo->myaddr.BTC,coinaddr,coin->changeaddr,scriptstr);
    if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 )
    {
        bitcoin_priv2wif(wifstr,waddr->privkey,rawtx->coin->chain->wiftype);
        jaddistr(privkeyarray,waddr->wifstr);
    }
    basilisktag = (uint32_t)rand();
    jaddistr(addresses,coinaddr);
    valsobj = cJSON_CreateObject();
    jadd(valsobj,"addresses",addresses);
    jaddstr(valsobj,"coin",rawtx->coin->symbol);
    jaddstr(valsobj,"spendscript",scriptstr);
    jaddstr(valsobj,"changeaddr",rawtx->coin->changeaddr);
    jadd64bits(valsobj,"satoshis",rawtx->amount);
    jadd64bits(valsobj,"txfee",txfee);
    jaddnum(valsobj,"minconf",minconf);
    jaddnum(valsobj,"locktime",locktime);
    jaddnum(valsobj,"timeout",30000);
    if ( (retstr= basilisk_rawtx(myinfo,rawtx->coin,0,0,myinfo->myaddr.persistent,valsobj,"")) != 0 )
    {
        //printf("%s got.(%s)\n",str,retstr);
        flag = 0;
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (txbytes= jstr(retjson,"rawtx")) != 0 && (vins= jobj(retjson,"vins")) != 0 )
                flag = 1;
            else printf("missing rawtx.%p or vins.%p (%s)\n",txbytes,vins,retstr);
        } else printf("error parsing.(%s)\n",retstr);
        if ( txbytes != 0 && vins != 0 )
        {
            //printf("vins.(%s)\n",jprint(vins,0));
            if ( (signedtx= iguana_signrawtx(myinfo,rawtx->coin,&signedtxid,&completed,vins,txbytes,privkeyarray)) != 0 )
            {
                if ( lockinputs != 0 )
                    iguana_unspentslock(myinfo,rawtx->coin,vins);
                rawtx->datalen = (int32_t)strlen(signedtx) >> 1;
                rawtx->txbytes = calloc(1,rawtx->datalen);
                decode_hex(rawtx->txbytes,rawtx->datalen,signedtx);
                printf("%s %s.%s\n",swap->iambob != 0 ? "BOB" : "ALICE",str,signedtx);
                free(signedtx);
                retval = 0;
            } else printf("error signrawtx\n"); //do a very short timeout so it finishes via local poll
        }
        if ( retjson != 0 )
            free_json(retjson);
        free(retstr);
    } else printf("error creating %s feetx\n",swap->iambob != 0 ? "BOB" : "ALICE");
    free_json(valsobj);
    free_json(privkeyarray);
    return(retval);
}

void basilisk_rawtx_setparms(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *rawtx,struct iguana_info *coin,int32_t numconfirms,int32_t vintype,uint64_t satoshis,int32_t vouttype,uint8_t *pubkey33)
{
    rawtx->coin = coin;
    rawtx->numconfirms = numconfirms;
    rawtx->amount = satoshis;
    rawtx->vintype = vintype; // 0 -> std, 2 -> 2of2, 3 -> spend bobpayment, 4 -> spend bobdeposit
    rawtx->vouttype = vouttype; // 0 -> fee, 1 -> std, 2 -> 2of2, 3 -> bobpayment, 4 -> bobdeposit
    if ( rawtx->vouttype == 0 )
    {
        if ( strcmp(coin->symbol,"BTC") == 0 && (swap->req.quoteid % 10) == 0 )
            decode_hex(rawtx->rmd160,20,TIERNOLAN_RMD160);
        else decode_hex(rawtx->rmd160,20,INSTANTDEX_RMD160);
        bitcoin_address(rawtx->destaddr,rawtx->coin->chain->pubtype,rawtx->rmd160,20);
    }
    if ( pubkey33 != 0 )
    {
        memcpy(rawtx->pubkey33,pubkey33,33);
        bitcoin_address(rawtx->destaddr,rawtx->coin->chain->pubtype,rawtx->pubkey33,33);
        bitcoin_addr2rmd160(&rawtx->addrtype,rawtx->rmd160,rawtx->destaddr);
    }
    if ( rawtx->vouttype <= 1 && rawtx->destaddr[0] != 0 )
    {
        rawtx->spendlen = bitcoin_standardspend(rawtx->spendscript,0,rawtx->rmd160);
        if ( 0 && vintype == 0 && basilisk_rawtx_gen("setparms",myinfo,swap,1,rawtx,0,rawtx->spendscript,rawtx->spendlen,coin->chain->txfee,1) < 0 )
            printf("error generating vintype.%d vouttype.%d -> %s\n",vintype,vouttype,rawtx->destaddr);
    }
}

struct basilisk_swap *bitcoin_swapinit(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    struct iguana_info *coin; uint8_t *alicepub33=0,*bobpub33=0; int32_t x = -1;
    if ( strcmp("BTC",swap->req.src) == 0 )
    {
        swap->bobcoin = iguana_coinfind("BTC");
        swap->bobsatoshis = swap->req.srcamount;
        swap->bobconfirms = (1 + sqrt(dstr(swap->bobsatoshis) * .1));
        swap->alicecoin = iguana_coinfind(swap->req.dest);
        swap->alicesatoshis = swap->req.destamount;
        swap->aliceconfirms = swap->bobconfirms * 3;
    }
    else if ( strcmp("BTC",swap->req.dest) == 0 )
    {
        swap->bobcoin = iguana_coinfind("BTC");
        swap->bobsatoshis = swap->req.destamount;
        swap->bobconfirms = (1 + sqrt(dstr(swap->bobsatoshis) * .1));
        swap->alicecoin = iguana_coinfind(swap->req.src);
        swap->alicesatoshis = swap->req.srcamount;
        swap->aliceconfirms = swap->bobconfirms * 3;
    }
    else
    {
        if ( (coin= iguana_coinfind(swap->req.src)) != 0 )
        {
            if ( coin->chain->havecltv != 0 )
            {
                swap->bobcoin = coin;
                swap->bobsatoshis = swap->req.srcamount;
                swap->alicecoin = iguana_coinfind(swap->req.dest);
                swap->alicesatoshis = swap->req.destamount;
            }
            else if ( (coin= iguana_coinfind(swap->req.dest)) != 0 )
            {
                if ( coin->chain->havecltv != 0 )
                {
                    swap->bobcoin = coin;
                    swap->bobsatoshis = swap->req.destamount;
                    swap->alicecoin = iguana_coinfind(swap->req.src);
                    swap->alicesatoshis = swap->req.srcamount;
                }
            }
        }
    }
    if ( swap->bobcoin == 0 || swap->alicecoin == 0 )
    {
        printf("missing BTC.%p or missing alicecoin.%p\n",swap->bobcoin,swap->alicecoin);
        free(swap);
        return(0);
    }
    if ( swap->bobconfirms == 0 )
        swap->bobconfirms = swap->bobcoin->chain->minconfirms;
    if ( swap->aliceconfirms == 0 )
        swap->aliceconfirms = swap->alicecoin->chain->minconfirms;
    swap->bobinsurance = (swap->bobsatoshis / INSTANTDEX_INSURANCEDIV);
    swap->aliceinsurance = (swap->alicesatoshis / INSTANTDEX_INSURANCEDIV);
    strcpy(swap->bobstr,swap->bobcoin->symbol);
    strcpy(swap->alicestr,swap->alicecoin->symbol);
    swap->started = (uint32_t)time(NULL);
    swap->expiration = swap->req.timestamp + INSTANTDEX_LOCKTIME*2;
    swap->locktime = swap->expiration + INSTANTDEX_LOCKTIME;
    OS_randombytes((uint8_t *)&swap->choosei,sizeof(swap->choosei));
    if ( swap->choosei < 0 )
        swap->choosei = -swap->choosei;
    swap->choosei %= INSTANTDEX_DECKSIZE;
    swap->otherchoosei = -1;
    swap->myhash = myinfo->myaddr.persistent;
    if ( bits256_cmp(swap->myhash,swap->req.hash) == 0 )
    {
        swap->otherhash = swap->req.desthash;
        if ( strcmp(swap->req.src,swap->bobstr) == 0 )
            swap->iambob = 1;
        else if ( strcmp(swap->req.dest,swap->alicestr) == 0 )
        {
            printf("neither bob nor alice error\n");
            return(0);
        }
    }
    else if ( bits256_cmp(swap->myhash,swap->req.desthash) == 0 )
    {
        swap->otherhash = swap->req.hash;
        if ( strcmp(swap->req.dest,swap->bobstr) == 0 )
            swap->iambob = 1;
        else if ( strcmp(swap->req.src,swap->alicestr) != 0 )
        {
            printf("neither alice nor bob error\n");
            return(0);
        }
    }
    else
    {
        printf("neither src nor dest error\n");
        return(0);
    }
    if ( bits256_nonz(myinfo->persistent_priv) == 0 || (x= instantdex_pubkeyargs(myinfo,swap,2 + INSTANTDEX_DECKSIZE,myinfo->persistent_priv,swap->myhash,0x02+swap->iambob)) != 2 + INSTANTDEX_DECKSIZE )
    {
        printf("couldnt generate privkeys %d\n",x);
        return(0);
    }
    if ( swap->iambob != 0 )
    {
        basilisk_rawtx_setparms(myinfo,swap,&swap->myfee,swap->bobcoin,0,0,swap->bobsatoshis/INSTANTDEX_DECKSIZE,0,0);
        basilisk_rawtx_setparms(myinfo,swap,&swap->otherfee,swap->alicecoin,0,0,swap->alicesatoshis/INSTANTDEX_DECKSIZE,0,0);
        bobpub33 = myinfo->persistent_pubkey33;
    }
    else
    {
        basilisk_rawtx_setparms(myinfo,swap,&swap->otherfee,swap->bobcoin,0,0,swap->bobsatoshis/INSTANTDEX_DECKSIZE,0,0);
        basilisk_rawtx_setparms(myinfo,swap,&swap->myfee,swap->alicecoin,0,0,swap->alicesatoshis/INSTANTDEX_DECKSIZE,0,0);
        alicepub33 = myinfo->persistent_pubkey33;
    }
    basilisk_rawtx_setparms(myinfo,swap,&swap->bobdeposit,swap->bobcoin,swap->bobconfirms,0,swap->bobsatoshis*1.1,4,0);
    basilisk_rawtx_setparms(myinfo,swap,&swap->bobpayment,swap->bobcoin,swap->bobconfirms,0,swap->bobsatoshis,3,0);
    basilisk_rawtx_setparms(myinfo,swap,&swap->alicespend,swap->bobcoin,swap->bobconfirms,3,swap->bobsatoshis - swap->bobcoin->txfee,1,alicepub33);
    basilisk_rawtx_setparms(myinfo,swap,&swap->bobreclaim,swap->bobcoin,swap->bobconfirms,4,swap->bobsatoshis*1.1 - swap->bobcoin->txfee,1,bobpub33);
    basilisk_rawtx_setparms(myinfo,swap,&swap->alicepayment,swap->alicecoin,swap->aliceconfirms,0,swap->alicesatoshis,2,0);
    basilisk_rawtx_setparms(myinfo,swap,&swap->alicereclaim,swap->alicecoin,swap->aliceconfirms,2,swap->alicesatoshis-swap->alicecoin->txfee,1,alicepub33);
    basilisk_rawtx_setparms(myinfo,swap,&swap->bobspend,swap->alicecoin,swap->aliceconfirms,2,swap->alicesatoshis-swap->alicecoin->txfee,1,bobpub33);
    return(swap);
}
// end of alice/bob code

void basilisk_rawtx_purge(struct basilisk_rawtx *rawtx)
{
    if ( rawtx->txbytes != 0 )
        free(rawtx->txbytes), rawtx->txbytes = 0;
}

void basilisk_swap_finished(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    swap->finished = (uint32_t)time(NULL);
    // save to permanent storage
    basilisk_rawtx_purge(&swap->bobdeposit);
    basilisk_rawtx_purge(&swap->bobpayment);
    basilisk_rawtx_purge(&swap->alicepayment);
    basilisk_rawtx_purge(&swap->myfee);
    basilisk_rawtx_purge(&swap->otherfee);
    basilisk_rawtx_purge(&swap->alicereclaim);
    basilisk_rawtx_purge(&swap->alicespend);
    basilisk_rawtx_purge(&swap->bobreclaim);
    basilisk_rawtx_purge(&swap->bobspend);
}

void basilisk_swap_purge(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    int32_t i,n;
    portable_mutex_lock(&myinfo->DEX_swapmutex);
    n = myinfo->numswaps;
    for (i=0; i<n; i++)
        if ( myinfo->swaps[i] == swap )
        {
            myinfo->swaps[i] = myinfo->swaps[--myinfo->numswaps];
            myinfo->swaps[myinfo->numswaps] = 0;
            basilisk_swap_finished(myinfo,swap);
            break;
        }
    portable_mutex_unlock(&myinfo->DEX_swapmutex);
}

uint32_t basilisk_swapsend(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t nextbits)
{
    if ( basilisk_channelsend(myinfo,swap->otherhash,swap->req.quoteid,msgbits,data,datalen) == 0 )
        return(nextbits);
    else return(0);
}

int32_t basilisk_verify_statebits(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    iguana_rwnum(0,data,sizeof(swap->otherstatebits),&swap->otherstatebits);
    return(0);
}

int32_t basilisk_verify_choosei(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t otherchoosei;
    iguana_rwnum(0,data,sizeof(otherchoosei),&otherchoosei);
    if ( otherchoosei >= 0 && otherchoosei < INSTANTDEX_DECKSIZE )
    {
        printf("otherchoosei.%d\n",otherchoosei);
        swap->otherchoosei = otherchoosei;
        return(0);
    }
    printf("illegal otherchoosei.%d\n",otherchoosei);
    return(-1);
}

int32_t basilisk_swapdata_deck(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen = 0;
    for (i=0; i<sizeof(swap->deck)/sizeof(swap->deck[0][0]); i++)
        datalen += iguana_rwnum(1,&data[datalen],sizeof(swap->deck[i>>1][i&1]),&swap->deck[i>>1][i&1]);
    return(datalen);
}

int32_t basilisk_verify_otherdeck(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t i,len = 0;
    printf("verify otherdeck\n");
    for (i=0; i<sizeof(swap->otherdeck)/sizeof(swap->otherdeck[0][0]); i++)
        len += iguana_rwnum(0,&data[len],sizeof(swap->otherdeck[i>>1][i&1]),&swap->otherdeck[i>>1][i&1]);
    return(0);
}

int32_t basilisk_verify_pubpair(int32_t *wrongfirstbytep,struct basilisk_swap *swap,int32_t ind,uint8_t pub0,bits256 pubi,uint64_t txid)
{
    if ( pub0 != (swap->iambob ^ 1) + 0x02 )
    {
        (*wrongfirstbytep)++;
        printf("wrongfirstbyte[%d] %02x\n",ind,pub0);
        return(-1);
    }
    else if ( swap->otherdeck[ind][1] != pubi.txid )
    {
        printf("otherdeck[%d] priv ->pub mismatch %llx != %llx\n",ind,(long long)swap->otherdeck[ind][1],(long long)pubi.txid);
        return(-1);
    }
    else if ( swap->otherdeck[ind][0] != txid )
    {
        printf("otherdeck[%d] priv mismatch %llx != %llx\n",ind,(long long)swap->otherdeck[ind][0],(long long)txid);
        return(-1);
    }
    return(0);
}

int32_t basilisk_verify_privkeys(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t i,j,wrongfirstbyte,errs=0,len = 0; bits256 otherpriv,pubi; uint8_t secret160[20],otherpubkey[33],pubkey[33]; uint64_t txid;
    printf("verify privkeys\n");
    if ( swap->cutverified == 0 && swap->choosei >= 0 && datalen == sizeof(swap->privkeys) )
    {
        for (i=wrongfirstbyte=errs=0; i<sizeof(swap->privkeys)/sizeof(*swap->privkeys); i++)
        {
            for (j=0; j<32; j++)
                otherpriv.bytes[j] = data[len++];
            pubi = bitcoin_pubkey33(myinfo->ctx,otherpubkey,otherpriv);
            calc_rmd160_sha256(secret160,otherpriv.bytes,sizeof(otherpriv));
            memcpy(&txid,secret160,sizeof(txid));
            if ( i == swap->choosei )
            {
                if ( bits256_nonz(otherpriv) != 0 )
                {
                    printf("got privkey in slot.%d my choosei??\n",i);
                    errs++;
                }
                if ( swap->iambob != 0 )
                {
                    if ( otherpubkey[0] == 0x02 )
                    {
                        if ( bits256_nonz(swap->privkeys[i]) != 0 )
                        {
                            swap->privBn = swap->privkeys[i];
                            calc_rmd160_sha256(swap->secretBn,swap->privBn.bytes,sizeof(swap->privBn));
                            printf("set secretBn\n");
                            swap->pubBn = bitcoin_pubkey33(myinfo->ctx,pubkey,swap->privBn);
                        }
                    } else printf("wrong first byte.%02x\n",otherpubkey[0]);
                }
                else
                {
                    if ( otherpubkey[0] == 0x03 )
                    {
                        if ( bits256_nonz(swap->privkeys[i]) != 0 )
                        {
                            swap->privAm = swap->privkeys[i];
                            calc_rmd160_sha256(swap->secretAm,swap->privAm.bytes,sizeof(swap->privAm));
                            printf("set secretAm\n");
                            swap->pubAm = bitcoin_pubkey33(myinfo->ctx,pubkey,swap->privAm);
                        }
                    } else printf("wrong first byte.%02x\n",otherpubkey[0]);
                }
                continue;
            }
            errs += basilisk_verify_pubpair(&wrongfirstbyte,swap,i,otherpubkey[0],pubi,txid);
        }
        if ( errs == 0 && wrongfirstbyte == 0 )
            swap->cutverified = 1, printf("CUT VERIFIED\n");
        else printf("failed verification: wrong firstbyte.%d errs.%d\n",wrongfirstbyte,errs);
    }
    return(errs);
}

int32_t basilisk_verify_privi(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t j,wrongfirstbyte,len = 0; bits256 privkey,pubi; uint8_t secret160[20],pubkey33[33]; uint64_t txid;
    if ( datalen == sizeof(bits256) )
    {
        for (j=0; j<32; j++)
            privkey.bytes[j] = data[len++];
        calc_rmd160_sha256(secret160,privkey.bytes,sizeof(privkey));
        memcpy(&txid,secret160,sizeof(txid));
        pubi = bitcoin_pubkey33(myinfo->ctx,pubkey33,privkey);
        return(basilisk_verify_pubpair(&wrongfirstbyte,swap,swap->choosei,pubkey33[0],pubi,txid));
    } else return(-1);
}

int32_t basilisk_swapget(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,int32_t (*basilisk_verify_func)(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen))
{
    int32_t datalen;
    if ( (datalen= basilisk_channelget(myinfo,myinfo->myaddr.persistent,swap->req.quoteid,msgbits,data,maxlen)) > 0 )
        return((*basilisk_verify_func)(myinfo,swap,data,datalen));
    else return(-1);
}

uint32_t basilisk_swapdata_rawtxsend(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx,uint32_t nextbits)
{
    if ( basilisk_swapdata_rawtx(myinfo,swap,data,maxlen,rawtx) != 0 )
    {
        rawtx->actualtxid = basilisk_swap_broadcast(myinfo,swap,rawtx->coin,rawtx->txbytes,rawtx->datalen);
        if ( bits256_nonz(rawtx->actualtxid) != 0 && msgbits != 0 )
            return(basilisk_swapsend(myinfo,swap,msgbits,rawtx->txbytes,rawtx->datalen,nextbits));
    }
    return(0);
}

void basilisk_swaploop(void *_swap)
{
    uint8_t *data; int32_t i,j,maxlen,datalen,numconfirms; struct supernet_info *myinfo; struct basilisk_swap *swap = _swap;
    myinfo = swap->myinfo;
    fprintf(stderr,"start swap\n");
    maxlen = 1024*1024 + sizeof(*swap);
    data = malloc(maxlen);
    while ( time(NULL) < swap->expiration )
    {
        fprintf(stderr,"swapstate.%x\n",swap->statebits);
        iguana_rwnum(1,data,sizeof(swap->statebits),&swap->statebits);
        basilisk_swapsend(myinfo,swap,0,data,datalen,0);
        if ( basilisk_swapget(myinfo,swap,0,data,maxlen,basilisk_verify_statebits) == 0 )
        {
            printf("got other statebits.%x\n",swap->otherstatebits);
            if ( (swap->otherstatebits & 0x02) == 0 )
            {
                datalen = basilisk_swapdata_deck(myinfo,swap,data,maxlen);
                swap->statebits |= basilisk_swapsend(myinfo,swap,0x02,data,datalen,0);
            }
            if ( (swap->otherstatebits & 0x08) == 0 )
            {
                iguana_rwnum(1,data,sizeof(swap->choosei),&swap->choosei);
                basilisk_swapsend(myinfo,swap,0x08,data,datalen,0);
            }
        }
        if ( (swap->statebits & 0x01) == 0 ) // send pubkeys
        {
            datalen = basilisk_swapdata_deck(myinfo,swap,data,maxlen);
            swap->statebits |= basilisk_swapsend(myinfo,swap,0x02,data,datalen,0x01);
        }
        else if ( (swap->statebits & 0x02) == 0 ) // wait for pubkeys
        {
            if ( basilisk_swapget(myinfo,swap,0x02,data,maxlen,basilisk_verify_otherdeck) == 0 )
                swap->statebits |= 0x02;
        }
        else if ( (swap->statebits & 0x04) == 0 ) // send choosei
        {
            iguana_rwnum(1,data,sizeof(swap->choosei),&swap->choosei);
            swap->statebits |= basilisk_swapsend(myinfo,swap,0x08,data,datalen,0x04);
        }
        else if ( (swap->statebits & 0x08) == 0 ) // wait for choosei
        {
            if ( basilisk_swapget(myinfo,swap,0x08,data,maxlen,basilisk_verify_choosei) == 0 )
                swap->statebits |= 0x08;
        }
        else if ( (swap->statebits & 0x10) == 0 && swap->otherchoosei >= 0 && swap->otherchoosei < INSTANTDEX_DECKSIZE ) // send all but one privkeys
        {
            for (i=0; i<INSTANTDEX_DECKSIZE; i++)
            {
                for (j=0; j<32; j++)
                    data[datalen++] = (i == swap->otherchoosei) ? 0 : swap->privkeys[i].bytes[j];
            }
            swap->statebits |= basilisk_swapsend(myinfo,swap,0x20,data,datalen,0x10);
        }
        else if ( (swap->statebits & 0x20) == 0 ) // wait for all but one privkeys
        {
            if ( basilisk_swapget(myinfo,swap,0x20,data,maxlen,basilisk_verify_privkeys) == 0 )
                swap->statebits |= 0x20;
        }
        else if ( (swap->statebits & 0x40) == 0 ) // send fee
        {
            if ( swap->myfee.txbytes != 0 || basilisk_rawtx_gen("setparms",myinfo,swap,1,&swap->myfee,0,swap->myfee.spendscript,swap->myfee.spendlen,swap->myfee.coin->chain->txfee,1) == 0 )
                swap->statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x80,data,maxlen,&swap->myfee,0x40);
        }
        else if ( (swap->statebits & 0x80) == 0 ) // wait for fee
        {
            if ( basilisk_swapget(myinfo,swap,0x80,data,maxlen,basilisk_verify_otherfee) == 0 )
            {
                // verify and submit otherfee
                swap->statebits |= 0x80;
            }
        }
        else // both sides have setup required data and paid txfee
        {
            if ( swap->iambob != 0 )
            {
                swap->bobdeposit.spendlen = basilisk_bobscript(swap->bobdeposit.spendscript,0,&swap->bobdeposit.locktime,&swap->bobdeposit.secretstart,swap,1);
                basilisk_rawtx_gen("deposit",myinfo,swap,1,&swap->bobdeposit,swap->bobdeposit.locktime,swap->bobdeposit.spendscript,swap->bobdeposit.spendlen,swap->bobdeposit.coin->chain->txfee,1);
                swap->bobpayment.spendlen = basilisk_bobscript(swap->bobpayment.spendscript,0,&swap->bobpayment.locktime,&swap->bobpayment.secretstart,swap,0);
                basilisk_rawtx_gen("payment",myinfo,swap,1,&swap->bobpayment,swap->bobpayment.locktime,swap->bobpayment.spendscript,swap->bobpayment.spendlen,swap->bobpayment.coin->chain->txfee,1);
                if ( (swap->statebits & 0x100) == 0 )
                    swap->statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x200,data,maxlen,&swap->bobdeposit,0x100);
                // [BLOCKING: altfound] make sure altpayment is confirmed and send payment
                else if ( (swap->statebits & 0x1000) == 0 )
                {
                    if ( basilisk_swapget(myinfo,swap,0x1000,data,maxlen,basilisk_verify_alicepaid) == 0 )
                    {
                        // verify alicepayment and submit, set confirmed height
                        swap->statebits |= 0x1000;
                    }
                }
                else if ( (swap->statebits & 0x2000) == 0 )
                {
                    if ( basilisk_numconfirms(myinfo,&swap->alicepayment) >= swap->aliceconfirms )
                        swap->statebits |= 0x2000;
                }
                else if ( (swap->statebits & 0x4000) == 0 )
                    swap->statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x8000,data,maxlen,&swap->bobpayment,0x4000);
                 // [BLOCKING: privM] Bob waits for privM either from Alice or alice blockchain
                else if ( (swap->statebits & 0x40000) == 0 )
                {
                    if ( basilisk_swapget(myinfo,swap,0x40000,data,maxlen,basilisk_verify_privi) == 0 )
                    {
                        // submit claim
                        swap->statebits |= 0x40000;
                    }
                    else if ( basilisk_numconfirms(myinfo,&swap->alicespend) >= 0 )
                    {
                        // submit claim
                        swap->statebits |= 0x40000;
                    }
                    else if ( time(NULL) > (swap->started+swap->locktime) )
                    {
                        // submit reclaim of deposittxid
                        swap->statebits |= 0x40000;
                    }
                }
                else if ( (swap->statebits & 0x80000) == 0 )
                {
                    if ( (numconfirms= basilisk_numconfirms(myinfo,&swap->alicepayment)) >= 0 )
                    {
                        if ( numconfirms >= swap->aliceconfirms )
                            swap->statebits |= 0x80000;
                        else printf("detected alicepayment claim numconfirms.%d\n",numconfirms);
                    }
                }
            }
            else
            {
                swap->alicepayment.spendlen = basilisk_alicescript(swap->alicepayment.spendscript,0,swap->alicepayment.destaddr,swap->alicepayment.coin->chain->p2shtype,swap->pubAm,swap->pubBn);
                basilisk_rawtx_gen("alicepayment",myinfo,swap,1,&swap->alicepayment,swap->alicepayment.locktime,swap->alicepayment.spendscript,swap->alicepayment.spendlen,swap->alicepayment.coin->chain->txfee,1);
                // [BLOCKING: depfound] Alice waits for deposit to confirm and sends altpayment
                if ( (swap->statebits & 0x200) == 0 )
                {
                    if ( basilisk_swapget(myinfo,swap,0x200,data,maxlen,basilisk_verify_bobdeposit) == 0 )
                    {
                        // verify deposit and submit, set confirmed height
                        swap->statebits |= 0x200;
                    }
                }
                else if ( (swap->statebits & 0x400) == 0 )
                {
                    if ( basilisk_numconfirms(myinfo,&swap->bobdeposit) >= swap->bobconfirms )
                        swap->statebits |= 0x400;
                }
                else if ( (swap->statebits & 0x800) == 0 )
                    swap->statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x1000,data,maxlen,&swap->alicepayment,0x800);
                // [BLOCKING: payfound] make sure payment is confrmed and send in claim or see bob's reclaim and reclaim
                else if ( (swap->statebits & 0x8000) == 0 )
                {
                    if ( basilisk_swapget(myinfo,swap,0x8000,data,maxlen,basilisk_verify_bobpaid) == 0 )
                    {
                        // verify payment and submit, set confirmed height
                        swap->statebits |= 0x8000;
                    }
                    else if ( basilisk_numconfirms(myinfo,&swap->bobreclaim) >= 0 )
                    {
                        // reclaim and exit
                        swap->reclaimed = 1;
                        swap->statebits |= 0x8000;
                    }
                }
                else if ( (swap->statebits & 0x10000) == 0 )
                {
                    if ( swap->reclaimed != 0 )
                    {
                        if ( basilisk_numconfirms(myinfo,&swap->alicereclaim) >= swap->aliceconfirms )
                            swap->statebits |= 0x10000;
                    }
                    else if ( basilisk_numconfirms(myinfo,&swap->bobpayment) >= swap->bobconfirms )
                        swap->statebits |= 0x10000;
                }
                else if ( (swap->statebits & 0x20000) == 0 )
                {
                   if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->alicespend,0x20000) != 0 )
                    {
                        for (j=datalen=0; j<32; j++)
                            data[datalen++] = swap->privAm.bytes[j];
                        swap->statebits |= basilisk_swapsend(myinfo,swap,0x40000,data,datalen,0x20000);
                    }
                }
                else if ( (swap->statebits & 0x40000) == 0 )
                {
                    if ( basilisk_numconfirms(myinfo,&swap->bobpayment) >= swap->bobconfirms )
                        swap->statebits |= 0x40000;
                }
            }
        }
        sleep(3);
    }
    printf("swap finished statebits %x\n",swap->statebits);
    basilisk_swap_purge(myinfo,swap);
}

struct basilisk_swap *basilisk_thread_start(struct supernet_info *myinfo,struct basilisk_request *rp)
{
    int32_t i; struct basilisk_swap *swap = 0;
    portable_mutex_lock(&myinfo->DEX_swapmutex);
    for (i=0; i<myinfo->numswaps; i++)
        if ( myinfo->swaps[i]->req.requestid == rp->requestid )
        {
            printf("basilisk_thread_start error trying to start requestid.%u which is already started\n",rp->requestid);
            break;
        }
    if ( i == myinfo->numswaps && i < sizeof(myinfo->swaps)/sizeof(*myinfo->swaps) )
    {
        swap = calloc(1,sizeof(*swap));
        swap->req = *rp;
        swap->myinfo = myinfo;
        printf("START swap requestid.%u\n",rp->requestid);
        if ( bitcoin_swapinit(myinfo,swap) != 0 )
        {
//#ifdef __APPLE__
            fprintf(stderr,"launch\n");
            iguana_launch(iguana_coinfind("BTCD"),"basilisk_swaploop",basilisk_swaploop,swap,IGUANA_PERMTHREAD);
//#endif
            myinfo->swaps[myinfo->numswaps++] = swap;
        }
    }
    portable_mutex_unlock(&myinfo->DEX_swapmutex);
    return(swap);
}

struct basilisk_swap *basilisk_request_started(struct supernet_info *myinfo,uint32_t requestid)
{
    int32_t i; struct basilisk_swap *active = 0;
    portable_mutex_lock(&myinfo->DEX_swapmutex);
    for (i=0; i<myinfo->numswaps; i++)
        if ( myinfo->swaps[i]->req.requestid == requestid )
        {
            //printf("REQUEST STARTED.[%d] <- req.%u\n",i,requestid);
            active = myinfo->swaps[i];
            break;
        }
    portable_mutex_unlock(&myinfo->DEX_swapmutex);
    return(active);
}
