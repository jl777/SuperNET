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

int32_t iguana_numconfirms(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid)
{
    return(10);
}

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
        if ( swap->numpubs < INSTANTDEX_DECKSIZE )
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

char *instantdex_choosei(struct basilisk_swap *swap,cJSON *newjson,cJSON *argjson,uint8_t *serdata,int32_t datalen)
{
    int32_t i,j,max,len = 0; uint64_t x;
    if ( swap->choosei < 0 && serdata != 0 && datalen == sizeof(swap->deck) )
    {
        max = (int32_t)(sizeof(swap->otherdeck) / sizeof(*swap->otherdeck));
        for (i=0; i<max; i++)
            for (j=0; j<2; j++)
                len += iguana_rwnum(1,(uint8_t *)&swap->otherdeck[i][j],sizeof(x),&serdata[len]);
        OS_randombytes((uint8_t *)&swap->choosei,sizeof(swap->choosei));
        if ( swap->choosei < 0 )
            swap->choosei = -swap->choosei;
        swap->choosei %= max;
        jaddnum(newjson,"mychoosei",swap->choosei);
        printf(" %s send mychoosei.%d of max.%d deck.(%llx %llx)\n",swap->iambob!=0?"BOB":"alice",swap->choosei,max,(long long)swap->otherdeck[0][0],(long long)swap->otherdeck[0][1]);
        return(0);
    }
    else
    {
        printf("choosei.%d or null serdata.%p or invalid datalen.%d vs %d\n",swap->choosei,serdata,datalen,(int32_t)sizeof(swap->deck));
        return(clonestr("{\"error\":\"instantdex_BTCswap offer no cut\"}"));
    }
}

void instantdex_privkeyextract(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *serdata,int32_t serdatalen)
{
    int32_t i,j,wrongfirstbyte,errs,len = 0; bits256 otherpriv,pubi; uint8_t secret160[20],otherpubkey[33],pubkey[33]; uint64_t txid;
    if ( swap->cutverified == 0 && swap->choosei >= 0 && serdatalen == sizeof(swap->privkeys) )
    {
        for (i=wrongfirstbyte=errs=0; i<sizeof(swap->privkeys)/sizeof(*swap->privkeys); i++)
        {
            for (j=0; j<32; j++)
                otherpriv.bytes[j] = serdata[len++];
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
            pubi = bitcoin_pubkey33(myinfo->ctx,otherpubkey,otherpriv);
            calc_rmd160_sha256(secret160,otherpriv.bytes,sizeof(otherpriv));
            memcpy(&txid,secret160,sizeof(txid));
            if ( otherpubkey[0] != (swap->iambob ^ 1) + 0x02 )
            {
                wrongfirstbyte++;
                printf("wrongfirstbyte[%d] %02x\n",i,otherpubkey[0]);
            }
            else if ( swap->otherdeck[i][1] != pubi.txid )
            {
                printf("otherdeck[%d] priv ->pub mismatch %llx != %llx\n",i,(long long)swap->otherdeck[i][1],(long long)pubi.txid);
                errs++;
            }
            else if ( swap->otherdeck[i][0] != txid )
            {
                printf("otherdeck[%d] priv mismatch %llx != %llx\n",i,(long long)swap->otherdeck[i][0],(long long)txid);
                errs++;
            }
        }
        if ( errs == 0 && wrongfirstbyte == 0 )
            swap->cutverified = 1, printf("CUT VERIFIED\n");
        else printf("failed verification: wrong firstbyte.%d errs.%d\n",wrongfirstbyte,errs);
    }
}

struct basilisk_swap *bitcoin_swapinit(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    struct iguana_info *coin;
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
    swap->choosei = swap->otherchoosei = -1;
    swap->myhash = myinfo->myaddr.persistent;
    if ( bits256_cmp(swap->myhash,swap->req.hash) == 0 )
    {
        swap->otherhash = swap->req.desthash;
        if ( strcmp(swap->req.src,swap->bobstr) == 0 )
            swap->iambob = 1;
        else if ( strcmp(swap->req.dest,swap->alicestr) != 0 )
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
    if ( bits256_nonz(myinfo->persistent_priv) == 0 || instantdex_pubkeyargs(myinfo,swap,2 + INSTANTDEX_DECKSIZE,myinfo->persistent_priv,swap->myhash,0x02+swap->iambob) != 2 + INSTANTDEX_DECKSIZE )
    {
        printf("couldnt generate privkeys\n");
        return(0);
    }
    return(swap);
}
// end of alice/bob code

void basilisk_swap_finished(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    swap->finished = (uint32_t)time(NULL);
    // save to permanent storage
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

void basilisk_swaploop(void *_swap)
{
    uint8_t *data; int32_t maxlen,datalen,numconfirms; struct supernet_info *myinfo; struct basilisk_swap *swap = _swap;
    myinfo = swap->myinfo;
    printf("start swap\n");
    maxlen = sizeof(*swap);
    data = malloc(maxlen);
    while ( time(NULL) < swap->expiration )
    {
        // iterate swap statemachine
        if ( (swap->statebits & 0x01) == 0 ) // wait for pubkeys
        {
            if ( (datalen= basilisk_channelget(myinfo,myinfo->myaddr.persistent,swap->req.quoteid,0x01,data,maxlen)) == sizeof(swap->otherdeck) )
            {
                swap->statebits |= 0x01;
            }
        }
        else if ( (swap->statebits & 0x02) == 0 ) // send pubkeys
        {
            datalen = sizeof(swap->deck);
            if ( basilisk_channelsend(myinfo,swap->otherhash,swap->req.quoteid,0x01,data,datalen) == 0 )
                swap->statebits |= 0x02;
        }
        else if ( (swap->statebits & 0x04) == 0 ) // wait for choosei
        {
            datalen = sizeof(swap->otherchoosei);
            if ( (datalen= basilisk_channelget(myinfo,myinfo->myaddr.persistent,swap->req.quoteid,0x04,data,maxlen)) > 0 )
            {
                // set otherchoosei
                swap->statebits |= 0x04;
            }
        }
        else if ( (swap->statebits & 0x08) == 0 ) // send choosei
        {
            datalen = sizeof(swap->choosei);
            if ( basilisk_channelsend(myinfo,swap->otherhash,swap->req.quoteid,0x04,data,datalen) == 0 )
                swap->statebits |= 0x08;
        }
        else if ( (swap->statebits & 0x10) == 0 ) // wait for all but one privkeys
        {
            if ( (datalen= basilisk_channelget(myinfo,myinfo->myaddr.persistent,swap->req.quoteid,0x10,data,maxlen)) == sizeof(swap->privkeys) )
            {
                // verify privkeys
                swap->statebits |= 0x10;
            }
        }
        else if ( (swap->statebits & 0x20) == 0 ) // send all but one privkeys
        {
            datalen = sizeof(swap->privkeys);
            if ( basilisk_channelsend(myinfo,swap->otherhash,swap->req.quoteid,0x10,data,datalen) == 0 )
                swap->statebits |= 0x20;
        }
        else if ( (swap->statebits & 0x40) == 0 ) // send fee
        {
            datalen = strlen(swap->myfee->txbytes);
            if ( basilisk_channelsend(myinfo,swap->otherhash,swap->req.quoteid,0x80,data,datalen) == 0 )
                swap->statebits |= 0x40;
        }
        else if ( (swap->statebits & 0x80) == 0 ) // wait for fee
        {
            if ( (datalen= basilisk_channelget(myinfo,myinfo->myaddr.persistent,swap->req.quoteid,0x80,data,maxlen)) > 0 )
            {
                // verify and submit otherfee
                swap->statebits |= 0x80;
            }
        }
        else // both sides have setup required data and paid txfee
        {
            if ( swap->iambob != 0 )
            {
                if ( (swap->statebits & 0x100) == 0 )
                {
                    datalen = strlen(swap->deposit->txbytes);
                    if ( basilisk_channelsend(myinfo,swap->otherhash,swap->req.quoteid,0x200,data,datalen) == 0 )
                        swap->statebits |= 0x100;
                }
                // [BLOCKING: altfound] make sure altpayment is confirmed and send payment
                else if ( (swap->statebits & 0x1000) == 0 )
                {
                    if ( (datalen= basilisk_channelget(myinfo,myinfo->myaddr.persistent,swap->req.quoteid,0x1000,data,maxlen)) > 0 )
                    {
                        // verify alicepayment and submit, set confirmed height
                        swap->statebits |= 0x1000;
                    }
                }
                else if ( (swap->statebits & 0x2000) == 0 )
                {
                    if ( iguana_numconfirms(myinfo,swap->alicecoin,swap->alicepayment->txid) >= swap->aliceconfirms )
                        swap->statebits |= 0x2000;
                }
                else if ( (swap->statebits & 0x4000) == 0 )
                {
                    datalen = strlen(swap->payment->txbytes);
                    if ( basilisk_channelsend(myinfo,swap->otherhash,swap->req.quoteid,0x8000,data,datalen) == 0 )
                        swap->statebits |= 0x4000;
                }
                // [BLOCKING: privM] Bob waits for privM either from Alice or alice blockchain
                else if ( (swap->statebits & 0x40000) == 0 )
                {
                    if ( (datalen= basilisk_channelget(myinfo,myinfo->myaddr.persistent,swap->req.quoteid,0x40000,data,maxlen)) > 0 )
                    {
                        // submit claim
                        swap->statebits |= 0x40000;
                    }
                    else if ( iguana_numconfirms(myinfo,swap->alicecoin,swap->alicepayment->txid) >= 0 )
                    {
                        // submit claim
                        swap->statebits |= 0x40000;
                    }
                    else if ( time(NULL) > swap->locktime )
                    {
                        // submit reclaim of deposittxid
                        swap->statebits |= 0x40000;
                    }
                }
                else if ( (swap->statebits & 0x80000) == 0 )
                {
                    if ( (numconfirms= iguana_numconfirms(myinfo,swap->alicecoin,swap->alicepayment->txid)) >= 0 )
                    {
                        if ( numconfirms >= swap->aliceconfirms )
                            swap->statebits |= 0x80000;
                        else printf("detected alicepayment claim numconfirms.%d\n",numconfirms);
                    }
                }
            }
            else
            {
                // [BLOCKING: depfound] Alice waits for deposit to confirm and sends altpayment
                if ( (swap->statebits & 0x200) == 0 )
                {
                    if ( (datalen= basilisk_channelget(myinfo,myinfo->myaddr.persistent,swap->req.quoteid,0x200,data,maxlen)) > 0 )
                    {
                        // verify deposit and submit, set confirmed height
                        swap->statebits |= 0x200;
                    }
                }
                else if ( (swap->statebits & 0x400) == 0 )
                {
                    if ( iguana_numconfirms(myinfo,swap->bobcoin,swap->deposit->txid) >= swap->bobconfirms )
                        swap->statebits |= 0x400;
                }
                else if ( (swap->statebits & 0x800) == 0 )
                {
                    datalen = strlen(swap->alicepayment->txbytes);
                    if ( basilisk_channelsend(myinfo,swap->otherhash,swap->req.quoteid,0x1000,data,datalen) == 0 )
                        swap->statebits |= 0x800;
                }
                // [BLOCKING: payfound] make sure payment is confrmed and send in claim or see bob's reclaim and reclaim
                else if ( (swap->statebits & 0x8000) == 0 )
                {
                    if ( (datalen= basilisk_channelget(myinfo,myinfo->myaddr.persistent,swap->req.quoteid,0x8000,data,maxlen)) > 0 )
                    {
                        // verify payment and submit, set confirmed height
                        swap->statebits |= 0x8000;
                    }
                    else if ( iguana_numconfirms(myinfo,swap->bobcoin,swap->deposit->txid) >= 0 )
                    {
                        // reclaim and exit
                        swap->reclaimed = 1;
                        swap->statebits |= 0x8000;
                    }
                }
                else if ( (swap->statebits & 0x10000) == 0 )
                {
                    if ( swap->reclaim != 0 )
                    {
                        if ( iguana_numconfirms(myinfo,swap->alicecoin,swap->reclaim->txid) >= swap->aliceconfirms )
                            swap->statebits |= 0x10000;
                    }
                    else if ( iguana_numconfirms(myinfo,swap->bobcoin,swap->payment->txid) >= swap->bobconfirms )
                        swap->statebits |= 0x10000;
                }
                else if ( (swap->statebits & 0x20000) == 0 )
                {
                    // send privM
                    // submit claim
                    datalen = sizeof(swap->privAm);
                    if ( basilisk_channelsend(myinfo,swap->otherhash,swap->req.quoteid,0x40000,data,datalen) == 0 )
                        swap->statebits |= 0x20000;
                }
                else if ( (swap->statebits & 0x40000) == 0 )
                {
                    if ( iguana_numconfirms(myinfo,swap->alicecoin,swap->payment->txid) >= swap->bobconfirms )
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
        if ( bitcoin_swapinit(myinfo,swap) != 0 )
        {
            myinfo->swaps[myinfo->numswaps++] = swap;
            iguana_launch(iguana_coinfind("BTCD"),"basilisk_swaploop",basilisk_swaploop,swap,IGUANA_PERMTHREAD);
        } else free(swap), swap = 0;
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
            active = myinfo->swaps[i];
            break;
        }
    portable_mutex_unlock(&myinfo->DEX_swapmutex);
    return(active);
}
