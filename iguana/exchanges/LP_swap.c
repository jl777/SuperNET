
/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
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
//
//  LP_swap.c
//  marketmaker
//

// included from basilisk.c
/* https://bitcointalk.org/index.php?topic=1340621.msg13828271#msg13828271
 https://bitcointalk.org/index.php?topic=1364951
 Tier Nolan's approach is followed with the following changes:
 a) instead of cutting 1000 keypairs, only INSTANTDEX_DECKSIZE are a
 b) instead of sending the entire 256 bits, it is truncated to 64 bits. With odds of collision being so low, it is dwarfed by the ~0.1% insurance factor.
 c) D is set to ~100x the insurance rate of 1/777 12.87% + BTC amount
 d) insurance is added to Bob's payment, which is after the deposit and bailin
 e) BEFORE Bob broadcasts deposit, Alice broadcasts BTC denominated fee in cltv so if trade isnt done fee is reclaimed
 */

/*
 both fees are standard payments: OP_DUP OP_HASH160 FEE_RMD160 OP_EQUALVERIFY OP_CHECKSIG
 
 
 Bob deposit:
 OP_IF
 <now + LOCKTIME*2> OP_CLTV OP_DROP <alice_pubA0> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <bob_pubB0> OP_CHECKSIG
 OP_ENDIF
 
 Alice altpayment: OP_2 <alice_pubM> <bob_pubN> OP_2 OP_CHECKMULTISIG

 Bob paytx:
 OP_IF
 <now + LOCKTIME> OP_CLTV OP_DROP <bob_pubB1> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
 OP_ENDIF
 
 Naming convention are pubAi are alice's pubkeys (seems only pubA0 and not pubA1)
 pubBi are Bob's pubkeys
 
 privN is Bob's privkey from the cut and choose deck as selected by Alice
 privM is Alice's counterpart
 pubN and pubM are the corresponding pubkeys for these chosen privkeys
 
 Alice timeout event is triggered if INSTANTDEX_LOCKTIME elapses from the start of a FSM instance. Bob timeout event is triggered after INSTANTDEX_LOCKTIME*2
 
 Based on https://gist.github.com/markblundeberg/7a932c98179de2190049f5823907c016 and to enable bob to spend alicepayment when alice does a claim for bob deposit, the scripts are changed to the following:
 
 Bob deposit:
 OP_IF
 OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <now + INSTANTDEX_LOCKTIME*2> OP_CLTV OP_DROP <alice_pubA0> OP_CHECKSIG
 OP_ELSE
 OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <bob_pubB0> OP_CHECKSIG
 OP_ENDIF
 
 Bob paytx:
 OP_IF
 <now + INSTANTDEX_LOCKTIME> OP_CLTV OP_DROP <bob_pubB1> OP_CHECKSIG
 OP_ELSE
 OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
 OP_ENDIF

 */

/*
 Bob sends bobdeposit and waits for alicepayment to confirm before sending bobpayment
 Alice waits for bobdeposit to confirm and sends alicepayment
 
 Alice spends bobpayment immediately divulging privAm
 Bob spends alicepayment immediately after getting privAm and divulges privBn
 
 Bob will spend bobdeposit after end of trade or INSTANTDEX_LOCKTIME, divulging privBn
 Alice spends alicepayment as soon as privBn is seen
 
 Bob will spend bobpayment after INSTANTDEX_LOCKTIME
 Alice spends bobdeposit in 2*INSTANTDEX_LOCKTIME
 */

//Bobdeposit includes a covered put option for alicecoin, duration INSTANTDEX_LOCKTIME
//alicepayment includes a covered call option for alicecoin, duration (2*INSTANTDEX_LOCKTIME - elapsed)


/* in case of following states, some funds remain unclaimable, but all identified cases are due to one or both sides not spending when they were the only eligible party:
 
 Bob failed to claim deposit during exclusive period and since alice put in the claim, the alicepayment is unspendable. if alice is nice, she can send privAm to Bob.
 Apaymentspent.(0000000000000000000000000000000000000000000000000000000000000000) alice.0 bob.0
 paymentspent.(f91da4e001360b95276448e7b01904d9ee4d15862c5af7f5c7a918df26030315) alice.0 bob.1
 depositspent.(f34e04ad74e290f63f3d0bccb7d0d50abfa54eea58de38816fdc596a19767add) alice.1 bob.0
 
 */
#define TX_WAIT_TIMEOUT 1800 // hard to increase this without hitting protocol limits (2/4 hrs)

uint32_t LP_atomic_locktime(char *base,char *rel)
{
    if ( strcmp(base,"BTC") == 0 && strcmp(rel,"BTC") == 0 )
        return(INSTANTDEX_LOCKTIME * 10);
    else if ( LP_is_slowcoin(base) > 0 || LP_is_slowcoin(rel) > 0 )
        return(INSTANTDEX_LOCKTIME * 4);
    else return(INSTANTDEX_LOCKTIME);
}

void basilisk_rawtx_purge(struct basilisk_rawtx *rawtx)
{
    if ( rawtx->vins != 0 )
        free_json(rawtx->vins), rawtx->vins = 0;
    //if ( rawtx->txbytes != 0 )
    //    free(rawtx->txbytes), rawtx->txbytes = 0;
}

void basilisk_swap_finished(struct basilisk_swap *swap)
{
    /*int32_t i;
    if ( swap->utxo != 0 && swap->sentflag == 0 )
    {
        LP_availableset(swap->utxo);
        swap->utxo = 0;
        //LP_butxo_swapfields_set(swap->utxo);
    }
    swap->I.finished = (uint32_t)time(NULL);*/
    if ( swap->I.finished == 0 )
    {
        if ( swap->I.iambob != 0 )
        {
            LP_availableset(swap->bobdeposit.utxotxid,swap->bobdeposit.utxovout);
            LP_availableset(swap->bobpayment.utxotxid,swap->bobpayment.utxovout);
        }
        else
        {
            LP_availableset(swap->alicepayment.utxotxid,swap->alicepayment.utxovout);
            LP_availableset(swap->myfee.utxotxid,swap->myfee.utxovout);
        }
    }
    // save to permanent storage
    basilisk_rawtx_purge(&swap->bobdeposit);
    basilisk_rawtx_purge(&swap->bobpayment);
    basilisk_rawtx_purge(&swap->alicepayment);
    basilisk_rawtx_purge(&swap->myfee);
    basilisk_rawtx_purge(&swap->otherfee);
    basilisk_rawtx_purge(&swap->aliceclaim);
    basilisk_rawtx_purge(&swap->alicespend);
    basilisk_rawtx_purge(&swap->bobreclaim);
    basilisk_rawtx_purge(&swap->bobspend);
    basilisk_rawtx_purge(&swap->bobrefund);
    basilisk_rawtx_purge(&swap->alicereclaim);
    /*for (i=0; i<swap->nummessages; i++)
        if ( swap->messages[i].data != 0 )
            free(swap->messages[i].data), swap->messages[i].data = 0;
    free(swap->messages), swap->messages = 0;
    swap->nummessages = 0;*/
    if ( swap->N.pair >= 0 )
        nn_close(swap->N.pair), swap->N.pair = -1;
}

uint32_t basilisk_quoteid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.unused = R.requestid = R.quoteid = R.DEXselector = 0;
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

uint32_t basilisk_requestid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.requestid = R.quoteid = R.quotetime = R.DEXselector = 0;
    R.destamount = R.unused = 0;
    memset(R.desthash.bytes,0,sizeof(R.desthash.bytes));
    if ( 0 )
    {
        int32_t i;
        for (i=0; i<sizeof(R); i++)
            printf("%02x",((uint8_t *)&R)[i]);
        printf(" <- crc.%u\n",calc_crc32(0,(void *)&R,sizeof(R)));
        char str[65],str2[65]; printf("B REQUESTID: t.%u r.%u q.%u %s %.8f %s -> %s %.8f %s crc.%u q%u\n",R.timestamp,R.requestid,R.quoteid,R.src,dstr(R.srcamount),bits256_str(str,R.srchash),R.dest,dstr(R.destamount),bits256_str(str2,R.desthash),calc_crc32(0,(void *)&R,sizeof(R)),basilisk_quoteid(&R));
    }
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

int32_t basilisk_verify_pubpair(int32_t *wrongfirstbytep,struct basilisk_swap *swap,int32_t ind,uint8_t pub0,bits256 pubi,uint64_t txid)
{
    if ( pub0 != (swap->I.iambob ^ 1) + 0x02 )
    {
        (*wrongfirstbytep)++;
        printf("wrongfirstbyte[%d] %02x\n",ind,pub0);
        return(-1);
    }
    return(0);
}

void LP_swapsfp_update(uint32_t requestid,uint32_t quoteid)
{
    static FILE *swapsfp;
    portable_mutex_lock(&LP_listmutex);
    if ( swapsfp == 0 )
    {
        char fname[512];
        sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
        if ( (swapsfp= fopen(fname,"rb+")) == 0 )
            swapsfp = fopen(fname,"wb+");
        else fseek(swapsfp,0,SEEK_END);
        //printf("LIST fp.%p\n",swapsfp);
    }
    if ( swapsfp != 0 )
    {
        fwrite(&requestid,1,sizeof(requestid),swapsfp);
        fwrite(&quoteid,1,sizeof(quoteid),swapsfp);
        fflush(swapsfp);
    }
    portable_mutex_unlock(&LP_listmutex);
}

uint32_t LP_swapwait(uint32_t expiration,uint32_t requestid,uint32_t quoteid,int32_t duration,int32_t sleeptime)
{
    char *retstr; uint32_t finished = 0; cJSON *retjson=0;
    if ( sleeptime != 0 )
    {
        printf("wait %d:%d for SWAP.(r%u/q%u) to complete\n",duration,sleeptime,requestid,quoteid);
        sleep(sleeptime/3);
    }
    while ( expiration == 0 || time(NULL) < expiration )
    {
        if ( (retstr= basilisk_swapentry(0,requestid,quoteid,1)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( jstr(retjson,"status") != 0 && strcmp(jstr(retjson,"status"),"finished") == 0 )
                {
                    finished = (uint32_t)time(NULL);
                    free(retstr), retstr = 0;
                    break;
                }
                else if ( expiration != 0 && time(NULL) > expiration )
                    printf("NOT FINISHED.(%s)\n",jprint(retjson,0));
                free_json(retjson), retjson = 0;
            }
            free(retstr);
        }
        if ( sleeptime != 0 )
            sleep(sleeptime);
        if ( duration < 0 )
            break;
    }
    if ( retjson != 0 )
    {
        free_json(retjson);
        if ( (retstr= basilisk_swapentry(0,requestid,quoteid,1)) != 0 )
        {
            printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>\nSWAP completed! %u-%u %s\n",requestid,quoteid,retstr);
            free(retstr);
        }
        return(finished);
    }
    else
    {
        if ( expiration != 0 && time(NULL) > expiration )
            printf("\nSWAP did not complete! %u-%u %s\n",requestid,quoteid,jprint(retjson,0));
        if ( duration > 0 )
            LP_pendswap_add(expiration,requestid,quoteid);
        return(0);
    }
}

int32_t LP_calc_waittimeout(char *symbol)
{
    int32_t waittimeout = TX_WAIT_TIMEOUT;
    if ( strcmp(symbol,"BTC") == 0 )
        waittimeout *= 8;
    else if ( LP_is_slowcoin(symbol) != 0 )
        waittimeout *= 4;
    return(waittimeout);
}

bits256 instantdex_derivekeypair(void *ctx,bits256 *newprivp,uint8_t pubkey[33],bits256 privkey,bits256 orderhash)
{
    bits256 sharedsecret;
    sharedsecret = curve25519_shared(privkey,orderhash);
    vcalc_sha256cat(newprivp->bytes,orderhash.bytes,sizeof(orderhash),sharedsecret.bytes,sizeof(sharedsecret));
    return(bitcoin_pubkey33(ctx,pubkey,*newprivp));
}

int32_t instantdex_pubkeyargs(struct basilisk_swap *swap,int32_t numpubs,bits256 privkey,bits256 hash,int32_t firstbyte)
{
    char buf[3]; int32_t i,n,m,len=0; bits256 pubi; uint64_t txid; uint8_t secret160[20],pubkey[33];
    sprintf(buf,"%c0",'A' - 0x02 + firstbyte);
    if ( numpubs > 2 )
    {
        if ( swap->I.numpubs+2 >= numpubs )
            return(numpubs);
        //printf(">>>>>> start generating %s\n",buf);
    }
    for (i=n=m=0; i<numpubs*100 && n<numpubs; i++)
    {
        pubi = instantdex_derivekeypair(swap->ctx,&privkey,pubkey,privkey,hash);
        //printf("i.%d n.%d numpubs.%d %02x vs %02x\n",i,n,numpubs,pubkey[0],firstbyte);
        if ( pubkey[0] != firstbyte )
            continue;
        if ( n < 2 )
        {
            if ( bits256_nonz(swap->I.mypubs[n]) == 0 )
            {
                swap->I.myprivs[n] = privkey;
                memcpy(swap->I.mypubs[n].bytes,pubkey+1,sizeof(bits256));
                if ( swap->I.iambob != 0 )
                {
                    if ( n == 0 )
                        memcpy(swap->I.pubB0, pubkey, 33);
                    else if ( n == 1 )
                        memcpy(swap->I.pubB1, pubkey, 33);
                }
                else if ( swap->I.iambob == 0 )
                {
                    if ( n == 0 )
                        memcpy(swap->I.pubA0, pubkey, 33);
                    else if ( n == 1 )
                        memcpy(swap->I.pubA1, pubkey, 33);
                }
            }
        }
        if ( m < INSTANTDEX_DECKSIZE )
        {
            swap->privkeys[m] = privkey;
            revcalc_rmd160_sha256(secret160,privkey);//.bytes,sizeof(privkey));
            memcpy(&txid,secret160,sizeof(txid));
            m++;
            if ( m > swap->I.numpubs )
                swap->I.numpubs = m;
        }
        n++;
    }
    //if ( n > 2 || m > 2 )
    //    printf("n.%d m.%d len.%d numpubs.%d\n",n,m,len,swap->I.numpubs);
    return(n);
}

void basilisk_rawtx_setparms(char *name,uint32_t quoteid,struct basilisk_rawtx *rawtx,struct iguana_info *coin,int32_t numconfirms,int32_t vintype,uint64_t satoshis,int32_t vouttype,uint8_t *pubkey33,int32_t jumblrflag)
{
#ifdef BASILISK_DISABLEWAITTX
    numconfirms = 0;
#endif
    strcpy(rawtx->name,name);
    //printf("set coin.%s %s -> %s\n",coin->symbol,coin->smartaddr,name);
    strcpy(rawtx->symbol,coin->symbol);
    rawtx->I.numconfirms = numconfirms;
    if ( (rawtx->I.amount= satoshis) < LP_MIN_TXFEE )
        rawtx->I.amount = LP_MIN_TXFEE;
    rawtx->I.vintype = vintype; // 0 -> std, 2 -> 2of2, 3 -> spend bobpayment, 4 -> spend bobdeposit
    rawtx->I.vouttype = vouttype; // 0 -> fee, 1 -> std, 2 -> 2of2, 3 -> bobpayment, 4 -> bobdeposit
    if ( rawtx->I.vouttype == 0 )
    {
        if ( strcmp(coin->symbol,"BTC") == 0 && (quoteid % 10) == 0 )
            decode_hex(rawtx->I.rmd160,20,TIERNOLAN_RMD160);
        else decode_hex(rawtx->I.rmd160,20,INSTANTDEX_RMD160);
        bitcoin_address(coin->symbol,rawtx->I.destaddr,coin->taddr,coin->pubtype,rawtx->I.rmd160,20);
    }
    if ( pubkey33 != 0 )
    {
        memcpy(rawtx->I.pubkey33,pubkey33,33);
        bitcoin_address(coin->symbol,rawtx->I.destaddr,coin->taddr,coin->pubtype,rawtx->I.pubkey33,33);
        bitcoin_addr2rmd160(coin->symbol,coin->taddr,&rawtx->I.addrtype,rawtx->I.rmd160,rawtx->I.destaddr);
    }
    if ( rawtx->I.vouttype <= 1 && rawtx->I.destaddr[0] != 0 )
    {
        rawtx->I.spendlen = bitcoin_standardspend(rawtx->spendscript,0,rawtx->I.rmd160);
        //printf("%s spendlen.%d %s <- %.8f\n",name,rawtx->I.spendlen,rawtx->I.destaddr,dstr(rawtx->I.amount));
    } //else printf("%s vouttype.%d destaddr.(%s)\n",name,rawtx->I.vouttype,rawtx->I.destaddr);
}

struct basilisk_swap *bitcoin_swapinit(bits256 privkey,uint8_t *pubkey33,bits256 pubkey25519,struct basilisk_swap *swap,int32_t optionduration,uint32_t statebits,struct LP_quoteinfo *qp,int32_t dynamictrust)
{
    //FILE *fp; char fname[512];
    uint8_t *alicepub33=0,*bobpub33=0; int32_t jumblrflag=-2,x = -1; struct iguana_info *bobcoin,*alicecoin;
    strcpy(swap->I.bobstr,swap->I.req.src);
    strcpy(swap->I.alicestr,swap->I.req.dest);
    if ( (alicecoin= LP_coinfind(swap->I.alicestr)) == 0 )
    {
        printf("missing alicecoin %s\n",swap->I.alicestr);
        return(0);
    }
    if ( (bobcoin= LP_coinfind(swap->I.bobstr)) == 0 )
    {
        printf("missing bobcoin %s \n",swap->I.bobstr);
        return(0);
    }
    if ( (swap->I.Atxfee= qp->desttxfee) < 0 )
    {
        printf("bitcoin_swapinit %s Atxfee %.8f rejected\n",swap->I.req.dest,dstr(swap->I.Atxfee));
        return(0);
    }
    if ( (swap->I.Btxfee= qp->txfee) < 0 )
    {
        printf("bitcoin_swapinit %s Btxfee %.8f rejected\n",swap->I.req.src,dstr(swap->I.Btxfee));
        return(0);
    }
    swap->I.putduration = swap->I.callduration = LP_atomic_locktime(swap->I.bobstr,swap->I.alicestr);
    if ( optionduration < 0 )
        swap->I.putduration -= optionduration;
    else if ( optionduration > 0 )
        swap->I.callduration += optionduration;
    if ( (swap->I.bobsatoshis= swap->I.req.srcamount) <= 0 )
    {
        printf("bitcoin_swapinit %s bobsatoshis %.8f rejected\n",swap->I.req.src,dstr(swap->I.bobsatoshis));
        return(0);
    }
    if ( (swap->I.alicesatoshis= swap->I.req.destamount) <= 0 )
    {
        printf("bitcoin_swapinit %s alicesatoshis %.8f rejected\n",swap->I.req.dest,dstr(swap->I.alicesatoshis));
        return(0);
    }
    if ( (swap->I.bobinsurance= (swap->I.bobsatoshis / INSTANTDEX_INSURANCEDIV)) < LP_MIN_TXFEE )
        swap->I.bobinsurance = LP_MIN_TXFEE;
    if ( (swap->I.aliceinsurance= (swap->I.alicesatoshis / INSTANTDEX_INSURANCEDIV)) < LP_MIN_TXFEE )
        swap->I.aliceinsurance = LP_MIN_TXFEE;
    swap->I.started = qp->timestamp;//(uint32_t)time(NULL);
    swap->I.expiration = swap->I.req.timestamp + swap->I.putduration + swap->I.callduration;
    OS_randombytes((uint8_t *)&swap->I.choosei,sizeof(swap->I.choosei));
    if ( swap->I.choosei < 0 )
        swap->I.choosei = -swap->I.choosei;
    swap->I.choosei %= INSTANTDEX_DECKSIZE;
    swap->I.otherchoosei = -1;
    swap->I.myhash = pubkey25519;
    if ( statebits != 0 )
    {
        swap->I.iambob = 0;
        swap->I.otherhash = swap->I.req.desthash;
        swap->I.aliceistrusted = 1;
        if ( dynamictrust == 0 && LP_pubkey_istrusted(swap->I.req.srchash) != 0 )
            dynamictrust = 1;
        swap->I.otheristrusted = swap->I.bobistrusted = dynamictrust;
    }
    else
    {
        swap->I.iambob = 1;
        swap->I.otherhash = swap->I.req.srchash;
        swap->I.bobistrusted = 1;
        if ( dynamictrust == 0 && LP_pubkey_istrusted(swap->I.req.desthash) != 0 )
            dynamictrust = 1;
        swap->I.otheristrusted = swap->I.aliceistrusted = dynamictrust;
    }
    if ( bits256_nonz(privkey) == 0 || (x= instantdex_pubkeyargs(swap,2 + INSTANTDEX_DECKSIZE,privkey,swap->I.orderhash,0x02+swap->I.iambob)) != 2 + INSTANTDEX_DECKSIZE )
    {
        char str[65]; printf("couldnt generate privkeys %d %s\n",x,bits256_str(str,privkey));
        return(0);
    }
    if ( strcmp("BTC",swap->I.bobstr) == 0 )
    {
        swap->I.bobconfirms = 1;//(1 + sqrt(dstr(swap->I.bobsatoshis) * .1));
        swap->I.aliceconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
    }
    else if ( strcmp("BTC",swap->I.alicestr) == 0 )
    {
        swap->I.aliceconfirms = 1;//(1 + sqrt(dstr(swap->I.alicesatoshis) * .1));
        swap->I.bobconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
    }
    else
    {
        swap->I.bobconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
        swap->I.aliceconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
    }
    if ( bobcoin->userconfirms > 0 )
        swap->I.bobconfirms = bobcoin->userconfirms;
    if ( alicecoin->userconfirms > 0 )
        swap->I.aliceconfirms = alicecoin->userconfirms;
    if ( (swap->I.bobmaxconfirms= bobcoin->maxconfirms) == 0 )
        swap->I.bobmaxconfirms = BASILISK_DEFAULT_MAXCONFIRMS;
    if ( (swap->I.alicemaxconfirms= alicecoin->maxconfirms) == 0 )
        swap->I.alicemaxconfirms = BASILISK_DEFAULT_MAXCONFIRMS;
    if ( swap->I.bobconfirms > swap->I.bobmaxconfirms )
        swap->I.bobconfirms = swap->I.bobmaxconfirms;
    if ( swap->I.aliceconfirms > swap->I.alicemaxconfirms )
        swap->I.aliceconfirms = swap->I.alicemaxconfirms;
    if ( bobcoin->isassetchain != 0 ) {
        if (strcmp(swap->I.bobstr, "ETOMIC") != 0) {
            swap->I.bobconfirms = BASILISK_DEFAULT_MAXCONFIRMS / 2;
        } else {
            swap->I.bobconfirms = 1;
        }
    }
    if ( alicecoin->isassetchain != 0 ) {
        if (strcmp(swap->I.alicestr, "ETOMIC") != 0) {
            swap->I.aliceconfirms = BASILISK_DEFAULT_MAXCONFIRMS / 2;
        } else {
            swap->I.aliceconfirms = 1;
        }
    }
    if ( strcmp("BAY",swap->I.req.src) != 0 && strcmp("BAY",swap->I.req.dest) != 0 )
    {
        swap->I.bobconfirms *= !swap->I.bobistrusted;
        swap->I.aliceconfirms *= !swap->I.aliceistrusted;
    }
    printf(">>>>>>>>>> jumblrflag.%d <<<<<<<<< r.%u q.%u, %.8f bobconfs.%d, %.8f aliceconfs.%d taddr.%d %d\n",jumblrflag,swap->I.req.requestid,swap->I.req.quoteid,dstr(swap->I.bobsatoshis),swap->I.bobconfirms,dstr(swap->I.alicesatoshis),swap->I.aliceconfirms,bobcoin->taddr,alicecoin->taddr);
    if ( swap->I.etomicsrc[0] != 0 || swap->I.etomicdest[0] != 0 )
        printf("etomic src (%s %s) dest (%s %s)\n",swap->I.bobtomic,swap->I.etomicsrc,swap->I.alicetomic,swap->I.etomicdest);
    //char str[65],str2[65],str3[65]; printf("IAMBOB.%d %s %s %s [%s %s]\n",swap->I.iambob,bits256_str(str,qp->txid),bits256_str(str2,qp->txid2),bits256_str(str3,qp->feetxid),bobstr,alicestr);
    return(swap);
}

struct basilisk_swap *LP_swapinit(int32_t iambob,int32_t optionduration,bits256 privkey,struct basilisk_request *rp,struct LP_quoteinfo *qp,int32_t dynamictrust)
{
    static void *ctx;
    struct basilisk_swap *swap; bits256 pubkey25519; uint8_t pubkey33[33];
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    swap = calloc(1,sizeof(*swap));
    memcpy(swap->uuidstr,qp->uuidstr,sizeof(swap->uuidstr));
    swap->aliceid = qp->aliceid;
    swap->I.req.quoteid = rp->quoteid;
    swap->ctx = ctx;
    vcalc_sha256(0,swap->I.orderhash.bytes,(uint8_t *)rp,sizeof(*rp));
    swap->I.req = *rp;
    G.LP_skipstatus[G.LP_numskips] = ((uint64_t)rp->requestid << 32) | rp->quoteid;
    if ( G.LP_numskips < sizeof(G.LP_skipstatus)/sizeof(*G.LP_skipstatus) )
        G.LP_numskips++;
    //printf("LP_swapinit request.%u iambob.%d (%s/%s) quoteid.%u\n",rp->requestid,iambob,rp->src,rp->dest,rp->quoteid);
    bitcoin_pubkey33(swap->ctx,pubkey33,privkey);
    pubkey25519 = curve25519(privkey,curve25519_basepoint9());
    swap->persistent_pubkey = pubkey25519;
    swap->persistent_privkey = privkey;
    memcpy(swap->persistent_pubkey33,pubkey33,33);
    calc_rmd160_sha256(swap->changermd160,pubkey33,33);
    if ( bitcoin_swapinit(privkey,pubkey33,pubkey25519,swap,optionduration,!iambob,qp,dynamictrust) == 0 )
    {
        printf("error doing swapinit\n");
        free(swap);
        swap = 0;
    }
    return(swap);
}

