
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
//
//  LP_swap.c
//  marketmaker
//
/*
 resume handling: list of tx broadcast, tx pending + required items, reconnect state machine or have statemachine assume off by one or state/otherstate specific handling
 make sure to broadcast deposit before claiming refund, or to just skip it if neither is done
 */


// Todo: monitor blockchains, ie complete extracting scriptsig
// mode to autocreate required outputs
// more better LP commands

// depends on just three external functions:
//     - basilisk_sendrawtransaction(coin,signedtx);
//     - basilisk_value(rawtx->coin,0,0,myinfo->myaddr.persistent,argjson,0)
//      basilisk_bitcoinrawtx(rawtx->coin,"",basilisktag,jint(valsobj,"timeout"),valsobj,V)


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

//#define DISABLE_CHECKSIG // unsolved MITM (evil peer)

/*
 both fees are standard payments: OP_DUP OP_HASH160 FEE_RMD160 OP_EQUALVERIFY OP_CHECKSIG
 
 Alice altpayment: OP_2 <alice_pubM> <bob_pubN> OP_2 OP_CHECKMULTISIG
 
 Bob deposit:
 #ifndef DISABLE_CHECKSIG
 OP_IF
 <now + INSTANTDEX_LOCKTIME*2> OP_CLTV OP_DROP <alice_pubA0> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <bob_pubB0> OP_CHECKSIG
 OP_ENDIF
 #else
 OP_IF
 <now + INSTANTDEX_LOCKTIME*2> OP_CLTV OP_DROP OP_SHA256 <sha256(alice_privA0)> OP_EQUAL
 OP_ELSE
 OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY OP_SHA256 <sha256(bob_privB0)> OP_EQUAL
 OP_ENDIF
 #endif
 
 Bob paytx:
 #ifndef DISABLE_CHECKSIG
 OP_IF
 <now + INSTANTDEX_LOCKTIME> OP_CLTV OP_DROP <bob_pubB1> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
 OP_ENDIF
 #else
 OP_IF
 <now + INSTANTDEX_LOCKTIME> OP_CLTV OP_DROP OP_SHA256 <sha256(bob_privB1)> OP_EQUAL
 OP_ELSE
 OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY OP_SHA256 <sha256(alice_privA0)> OP_EQUAL
 OP_ENDIF
 #endif
 
 Naming convention are pubAi are alice's pubkeys (seems only pubA0 and not pubA1)
 pubBi are Bob's pubkeys
 
 privN is Bob's privkey from the cut and choose deck as selected by Alice
 privM is Alice's counterpart
 pubN and pubM are the corresponding pubkeys for these chosen privkeys
 
 Alice timeout event is triggered if INSTANTDEX_LOCKTIME elapses from the start of a FSM instance. Bob timeout event is triggered after INSTANTDEX_LOCKTIME*2
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


int32_t bitcoin_coinptrs(bits256 pubkey,struct iguana_info **bobcoinp,struct iguana_info **alicecoinp,char *src,char *dest,bits256 srchash,bits256 desthash)
{
    struct iguana_info *coin = LP_coinfind(src);
    if ( coin == 0 || LP_coinfind(dest) == 0 )
        return(0);
    *bobcoinp = *alicecoinp = 0;
    *bobcoinp = LP_coinfind(dest);
    *alicecoinp = LP_coinfind(src);
    if ( bits256_cmp(pubkey,srchash) == 0 )
    {
        if ( strcmp(src,(*bobcoinp)->symbol) == 0 )
            return(1);
        else if ( strcmp(dest,(*alicecoinp)->symbol) == 0 )
            return(-1);
        else return(0);
    }
    else if ( bits256_cmp(pubkey,desthash) == 0 )
    {
        if ( strcmp(src,(*bobcoinp)->symbol) == 0 )
            return(-1);
        else if ( strcmp(dest,(*alicecoinp)->symbol) == 0 )
            return(1);
        else return(0);
    }
    return(0);
}

void basilisk_rawtx_purge(struct basilisk_rawtx *rawtx)
{
    if ( rawtx->vins != 0 )
        free_json(rawtx->vins);
    //if ( rawtx->txbytes != 0 )
    //    free(rawtx->txbytes), rawtx->txbytes = 0;
}

void basilisk_swap_finished(struct basilisk_swap *swap)
{
    int32_t i;
    swap->I.finished = (uint32_t)time(NULL);
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
    for (i=0; i<swap->nummessages; i++)
        if ( swap->messages[i].data != 0 )
            free(swap->messages[i].data), swap->messages[i].data = 0;
    free(swap->messages), swap->messages = 0;
    swap->nummessages = 0;
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
        char str[65],str2[65]; printf("B REQUESTID: t.%u r.%u q.%u %s %.8f %s -> %s %.8f %s crc.%u\n",R.timestamp,R.requestid,R.quoteid,R.src,dstr(R.srcamount),bits256_str(str,R.srchash),R.dest,dstr(R.destamount),bits256_str(str2,R.desthash),calc_crc32(0,(void *)&R,sizeof(R)));
    }
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

uint32_t basilisk_quoteid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.requestid = R.quoteid = R.unused = R.DEXselector = 0;
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

int32_t LP_pubkeys_data(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen = 0;
    for (i=0; i<sizeof(swap->deck)/sizeof(swap->deck[0][0]); i++)
        datalen += iguana_rwnum(1,&data[datalen],sizeof(swap->deck[i>>1][i&1]),&swap->deck[i>>1][i&1]);
    return(datalen);
}

int32_t LP_pubkeys_verify(struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t i,len = 0;
    if ( datalen == sizeof(swap->otherdeck) )
    {
        for (i=0; i<sizeof(swap->otherdeck)/sizeof(swap->otherdeck[0][0]); i++)
            len += iguana_rwnum(0,&data[len],sizeof(swap->otherdeck[i>>1][i&1]),&swap->otherdeck[i>>1][i&1]);
        return(0);
    } else return(-1);
}

int32_t LP_choosei_data(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen; char str[65];
    datalen = iguana_rwnum(1,data,sizeof(swap->I.choosei),&swap->I.choosei);
    if ( swap->I.iambob != 0 )
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubB0.bytes[i];
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubB1.bytes[i];
        printf("SEND pubB0/1 %s\n",bits256_str(str,swap->I.pubB0));
    }
    else
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubA0.bytes[i];
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubA1.bytes[i];
        printf("SEND pubA0/1 %s\n",bits256_str(str,swap->I.pubA0));
    }
    return(datalen);
}

int32_t LP_choosei_verify(struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t otherchoosei=-1,i,len = 0; uint8_t pubkey33[33]; char str[65],str2[65];
    if ( datalen == sizeof(otherchoosei)+sizeof(bits256)*2 )
    {
        len += iguana_rwnum(0,data,sizeof(otherchoosei),&otherchoosei);
        if ( otherchoosei >= 0 && otherchoosei < INSTANTDEX_DECKSIZE )
        {
            swap->I.otherchoosei = otherchoosei;
            if ( swap->I.iambob != 0 )
            {
                for (i=0; i<32; i++)
                    swap->I.pubA0.bytes[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.pubA1.bytes[i] = data[len++];
                printf("GOT pubA0/1 %s\n",bits256_str(str,swap->I.pubA0));
                swap->I.privBn = swap->privkeys[swap->I.otherchoosei];
                memset(&swap->privkeys[swap->I.otherchoosei],0,sizeof(swap->privkeys[swap->I.otherchoosei]));
                revcalc_rmd160_sha256(swap->I.secretBn,swap->I.privBn);//.bytes,sizeof(swap->privBn));
                vcalc_sha256(0,swap->I.secretBn256,swap->I.privBn.bytes,sizeof(swap->I.privBn));
                swap->I.pubBn = bitcoin_pubkey33(swap->ctx,pubkey33,swap->I.privBn);
                printf("set privBn.%s %s\n",bits256_str(str,swap->I.privBn),bits256_str(str2,*(bits256 *)swap->I.secretBn256));
                basilisk_bobscripts_set(swap,1,1);
            }
            else
            {
                for (i=0; i<32; i++)
                    swap->I.pubB0.bytes[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.pubB1.bytes[i] = data[len++];
                printf("GOT pubB0/1 %s\n",bits256_str(str,swap->I.pubB0));
                swap->I.privAm = swap->privkeys[swap->I.otherchoosei];
                memset(&swap->privkeys[swap->I.otherchoosei],0,sizeof(swap->privkeys[swap->I.otherchoosei]));
                revcalc_rmd160_sha256(swap->I.secretAm,swap->I.privAm);//.bytes,sizeof(swap->privAm));
                vcalc_sha256(0,swap->I.secretAm256,swap->I.privAm.bytes,sizeof(swap->I.privAm));
                swap->I.pubAm = bitcoin_pubkey33(swap->ctx,pubkey33,swap->I.privAm);
                printf("set privAm.%s %s\n",bits256_str(str,swap->I.privAm),bits256_str(str2,*(bits256 *)swap->I.secretAm256));
                //basilisk_bobscripts_set(swap,0);
            }
            return(0);
        }
    }
    printf("illegal otherchoosei.%d datalen.%d vs %d\n",otherchoosei,datalen,(int32_t)(sizeof(otherchoosei)+sizeof(bits256)*2));
    return(-1);
}

int32_t LP_mostprivs_data(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,j,datalen;
    datalen = 0;
    for (i=0; i<sizeof(swap->privkeys)/sizeof(*swap->privkeys); i++)
    {
        for (j=0; j<32; j++)
            data[datalen++] = (i == swap->I.otherchoosei) ? 0 : swap->privkeys[i].bytes[j];
    }
    if ( swap->I.iambob != 0 )
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubBn.bytes[i];
        for (i=0; i<20; i++)
            data[datalen++] = swap->I.secretBn[i];
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.secretBn256[i];
    }
    else
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubAm.bytes[i];
        for (i=0; i<20; i++)
            data[datalen++] = swap->I.secretAm[i];
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.secretAm256[i];
    }
    return(datalen);
}

int32_t basilisk_verify_pubpair(int32_t *wrongfirstbytep,struct basilisk_swap *swap,int32_t ind,uint8_t pub0,bits256 pubi,uint64_t txid)
{
    if ( pub0 != (swap->I.iambob ^ 1) + 0x02 )
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

int32_t basilisk_verify_privi(void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t j,wrongfirstbyte,len = 0; bits256 privkey,pubi; char str[65],str2[65]; uint8_t secret160[20],pubkey33[33]; uint64_t txid; struct basilisk_swap *swap = ptr;
    memset(privkey.bytes,0,sizeof(privkey));
    if ( datalen == sizeof(bits256) )
    {
        for (j=0; j<32; j++)
            privkey.bytes[j] = data[len++];
        revcalc_rmd160_sha256(secret160,privkey);//.bytes,sizeof(privkey));
        memcpy(&txid,secret160,sizeof(txid));
        pubi = bitcoin_pubkey33(swap->ctx,pubkey33,privkey);
        if ( basilisk_verify_pubpair(&wrongfirstbyte,swap,swap->I.choosei,pubkey33[0],pubi,txid) == 0 )
        {
            if ( swap->I.iambob != 0 )
            {
                swap->I.privAm = privkey;
                vcalc_sha256(0,swap->I.secretAm256,privkey.bytes,sizeof(privkey));
                printf("set privAm.%s %s\n",bits256_str(str,swap->I.privAm),bits256_str(str2,*(bits256 *)swap->I.secretAm256));
                basilisk_bobscripts_set(swap,0,1);
            }
            else
            {
                swap->I.privBn = privkey;
                vcalc_sha256(0,swap->I.secretBn256,privkey.bytes,sizeof(privkey));
                printf("set privBn.%s %s\n",bits256_str(str,swap->I.privBn),bits256_str(str2,*(bits256 *)swap->I.secretBn256));
            }
            basilisk_dontforget_update(swap,0);
            char str[65]; printf("privi verified.(%s)\n",bits256_str(str,privkey));
            return(0);
        }
    }
    return(-1);
}

int32_t LP_mostprivs_verify(struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t i,j,wrongfirstbyte=0,errs=0,len = 0; bits256 otherpriv,pubi; uint8_t secret160[20],otherpubkey[33]; uint64_t txid;
    //printf("verify privkeys choosei.%d otherchoosei.%d datalen.%d vs %d\n",swap->choosei,swap->otherchoosei,datalen,(int32_t)sizeof(swap->privkeys)+20+32);
    memset(otherpriv.bytes,0,sizeof(otherpriv));
    if ( swap->I.cutverified == 0 && swap->I.otherchoosei >= 0 && datalen == sizeof(swap->privkeys)+20+2*32 )
    {
        for (i=errs=0; i<sizeof(swap->privkeys)/sizeof(*swap->privkeys); i++)
        {
            for (j=0; j<32; j++)
                otherpriv.bytes[j] = data[len++];
            if ( i != swap->I.choosei )
            {
                pubi = bitcoin_pubkey33(swap->ctx,otherpubkey,otherpriv);
                revcalc_rmd160_sha256(secret160,otherpriv);//.bytes,sizeof(otherpriv));
                memcpy(&txid,secret160,sizeof(txid));
                errs += basilisk_verify_pubpair(&wrongfirstbyte,swap,i,otherpubkey[0],pubi,txid);
            }
        }
        if ( errs == 0 && wrongfirstbyte == 0 )
        {
            swap->I.cutverified = 1, printf("CUT VERIFIED\n");
            if ( swap->I.iambob != 0 )
            {
                for (i=0; i<32; i++)
                    swap->I.pubAm.bytes[i] = data[len++];
                for (i=0; i<20; i++)
                    swap->I.secretAm[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.secretAm256[i] = data[len++];
                basilisk_bobscripts_set(swap,1,1);
            }
            else
            {
                for (i=0; i<32; i++)
                    swap->I.pubBn.bytes[i] = data[len++];
                for (i=0; i<20; i++)
                    swap->I.secretBn[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.secretBn256[i] = data[len++];
                //basilisk_bobscripts_set(swap,0);
            }
        } else printf("failed verification: wrong firstbyte.%d errs.%d\n",wrongfirstbyte,errs);
    }
    //printf("privkeys errs.%d wrongfirstbyte.%d\n",errs,wrongfirstbyte);
    return(errs);
}

int32_t LP_waitfor(int32_t pairsock,struct basilisk_swap *swap,int32_t timeout,int32_t (*verify)(struct basilisk_swap *swap,uint8_t *data,int32_t datalen))
{
    void *data; int32_t datalen,retval = -1; uint32_t expiration = (uint32_t)time(NULL) + timeout;
    while ( time(NULL) < expiration )
    {
        if ( (datalen= nn_recv(pairsock,&data,NN_MSG,0)) >= 0 )
        {
            retval = (*verify)(swap,data,datalen);
            nn_freemsg(data);
        }
    }
    return(retval);
}

int32_t LP_waitsend(char *statename,int32_t timeout,int32_t pairsock,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen,int32_t (*verify)(struct basilisk_swap *swap,uint8_t *data,int32_t datalen),int32_t (*datagen)(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen))
{
    int32_t datalen,sendlen,retval = -1;
    if ( LP_waitfor(pairsock,swap,timeout,verify) == 0 )
    {
        if ( (datalen= (*datagen)(swap,data,maxlen)) > 0 )
        {
            if ( (sendlen= nn_send(pairsock,data,datalen,0)) == datalen )
            {
                retval = 0;
            } else printf("send %s error\n",statename);
        }
    } else printf("didnt get pubkeys\n");
    return(retval);
}

int32_t LP_sendwait(char *statename,int32_t timeout,int32_t pairsock,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen,int32_t (*verify)(struct basilisk_swap *swap,uint8_t *data,int32_t datalen),int32_t (*datagen)(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen))
{
    int32_t datalen,sendlen,retval = -1;
    if ( (datalen= (*datagen)(swap,data,maxlen)) > 0 )
    {
        if ( (sendlen= nn_send(pairsock,data,datalen,0)) == datalen )
        {
            if ( LP_waitfor(pairsock,swap,timeout,verify) == 0 )
                retval = 0;
            else printf("didnt get %s\n",statename);
        } else printf("send pubkeys error\n");
    }
    return(retval);
}

void LP_swapsfp_update(struct basilisk_request *rp)
{
    static FILE *swapsfp;
    if ( swapsfp == 0 )
    {
        char fname[512];
        sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
        if ( (swapsfp= fopen(fname,"rb+")) == 0 )
            swapsfp = fopen(fname,"wb+");
        else fseek(swapsfp,0,SEEK_END);
        printf("LIST fp.%p\n",swapsfp);
    }
    if ( swapsfp != 0 )
    {
        fwrite(&rp->requestid,1,sizeof(rp->requestid),swapsfp);
        fwrite(&rp->quoteid,1,sizeof(rp->quoteid),swapsfp);
        fflush(swapsfp);
    }
}

void LP_bobloop(void *_utxo)
{
    uint8_t *data; int32_t maxlen; uint32_t expiration; struct basilisk_swap *swap; struct LP_utxoinfo *utxo = _utxo;
    fprintf(stderr,"start swap iambob\n");
    maxlen = 1024*1024 + sizeof(*swap);
    data = malloc(maxlen);
    expiration = (uint32_t)time(NULL) + 10;
    while ( (swap= utxo->swap) == 0 && time(NULL) < expiration )
        sleep(1);
    if ( (utxo->swap= swap) != 0 )
    {
        if ( LP_waitsend("pubkeys",10,utxo->pair,swap,data,maxlen,LP_pubkeys_verify,LP_pubkeys_data) < 0 )
            printf("error waitsend pubkeys\n");
        else if ( LP_waitsend("choosei",10,utxo->pair,swap,data,maxlen,LP_choosei_verify,LP_choosei_data) < 0 )
            printf("error waitsend choosei\n");
        else if ( LP_waitsend("mostprivs",10,utxo->pair,swap,data,maxlen,LP_mostprivs_verify,LP_mostprivs_data) < 0 )
            printf("error waitsend mostprivs\n");
        else if ( basilisk_bobscripts_set(swap,1,1) < 0 )
            printf("error bobscripts\n");
        else
        {
            LP_swapsfp_update(&swap->I.req);
            // wait alicefee
            // send bobdeposit
            // wait alicepayment
            // send bobpayment
            // bobspend
            // bobrefund
            // done
        }
    } else printf("swap timed out\n");
    basilisk_swap_finished(swap);
    free(utxo->swap);
    utxo->swap = 0;
    nn_close(utxo->pair);
    utxo->pair = -1;
}

void LP_aliceloop(void *_utxo)
{
    uint8_t *data; int32_t maxlen; uint32_t expiration; struct basilisk_swap *swap; struct LP_utxoinfo *utxo = _utxo;
    fprintf(stderr,"start swap iambob\n");
    maxlen = 1024*1024 + sizeof(*swap);
    data = malloc(maxlen);
    expiration = (uint32_t)time(NULL) + 10;
    while ( (swap= utxo->swap) == 0 && time(NULL) < expiration )
        sleep(1);
    if ( (utxo->swap= swap) != 0 )
    {
        if ( LP_sendwait("pubkeys",10,utxo->pair,swap,data,maxlen,LP_pubkeys_verify,LP_pubkeys_data) < 0 )
            printf("error LP_sendwait pubkeys\n");
        else if ( LP_sendwait("choosei",10,utxo->pair,swap,data,maxlen,LP_choosei_verify,LP_choosei_data) < 0 )
            printf("error LP_sendwait choosei\n");
        else if ( LP_sendwait("mostprivs",10,utxo->pair,swap,data,maxlen,LP_mostprivs_verify,LP_mostprivs_data) < 0 )
            printf("error LP_sendwait mostprivs\n");
        else if ( basilisk_alicetxs(swap,data,maxlen) != 0 )
            printf("basilisk_alicetxs error\n");
        else
        {
            LP_swapsfp_update(&swap->I.req);
            // send alicefee
            // wait bobdeposit
            // send alicepayment
            // wait bobpayment
            // alicespend
            // done
        }
    } else printf("swap timed out\n");
    basilisk_swap_finished(swap);
    free(utxo->swap);
    utxo->swap = 0;
    nn_close(utxo->pair);
    utxo->pair = -1;
}

#ifdef old
void basilisk_swaploop(void *_utxo)
{
    uint8_t *data; uint32_t expiration,savestatebits=0,saveotherbits=0; uint32_t channel; int32_t iters,retval=0,j,datalen,maxlen; struct basilisk_swap *swap; struct LP_utxoinfo *utxo = _utxo;
    swap = utxo->swap;
    fprintf(stderr,"start swap iambob.%d\n",swap->I.iambob);
    maxlen = 1024*1024 + sizeof(*swap);
    data = malloc(maxlen);
    expiration = (uint32_t)time(NULL) + 300;
    //myinfo->DEXactive = expiration;
    channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
    while ( swap->aborted == 0 && (swap->I.statebits & (0x08|0x02)) != (0x08|0x02) && time(NULL) < expiration )
    {
        LP_channelsend(swap->I.req.srchash,swap->I.req.desthash,channel,0x4000000,(void *)&swap->I.req.requestid,sizeof(swap->I.req.requestid)); //,60);
        if ( swap->connected == 0 )
            basilisk_psockinit(swap,swap->I.iambob != 0);
        if ( swap->connected > 0 )
        {
            printf("A r%u/q%u swapstate.%x\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits);
            basilisk_sendstate(swap,data,maxlen);
            basilisk_sendpubkeys(swap,data,maxlen); // send pubkeys
            if ( basilisk_checkdeck(swap,data,maxlen) == 0) // check for other deck 0x02
                basilisk_sendchoosei(swap,data,maxlen);
            basilisk_waitchoosei(swap,data,maxlen); // wait for choosei 0x08
            if ( (swap->I.statebits & (0x08|0x02)) == (0x08|0x02) )
                break;
        }
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
    }
    if ( swap->connected == 0 )
    {
        printf("couldnt establish connection\n");
        retval = -1;
    }
    while ( swap->aborted == 0 && retval == 0 && (swap->I.statebits & 0x20) == 0 )
    {
        if ( swap->connected == 0 )
            basilisk_psockinit(swap,swap->I.iambob != 0);
        printf("B r%u/q%u swapstate.%x\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits);
        basilisk_sendstate(swap,data,maxlen);
        basilisk_sendchoosei(swap,data,maxlen);
        basilisk_sendmostprivs(swap,data,maxlen);
        if ( basilisk_swapget(swap,0x20,data,maxlen,basilisk_verify_privkeys) == 0 )
        {
            swap->I.statebits |= 0x20;
            break;
        }
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
        if ( time(NULL) > expiration )
            break;
    }
    //myinfo->DEXactive = swap->I.expiration;
    if ( time(NULL) >= expiration )
    {
        retval = -1;
        //myinfo->DEXactive = 0;
    }
    if ( swap->aborted != 0 )
    {
        printf("swap aborted before tx sent\n");
        retval = -1;
    }
    printf("C r%u/q%u swapstate.%x retval.%d\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits,retval);
    iters = 0;
    while ( swap->aborted == 0 && retval == 0 && (swap->I.statebits & 0x40) == 0 && iters++ < 10 ) // send fee
    {
        if ( swap->connected == 0 )
            basilisk_psockinit(swap,swap->I.iambob != 0);
        //printf("sendstate.%x\n",swap->I.statebits);
        basilisk_sendstate(swap,data,maxlen);
        //printf("swapget\n");
        basilisk_swapget(swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        //printf("after swapget\n");
        if ( swap->I.iambob != 0 && swap->bobdeposit.I.datalen == 0 )
        {
            printf("bobscripts set\n");
            if ( basilisk_bobscripts_set(swap,1,1) < 0 )
            {
                sleep(DEX_SLEEP);
                printf("bobscripts set error\n");
                continue;
            }
        }
        if ( swap->I.iambob == 0 )
        {
            /*for (i=0; i<20; i++)
             printf("%02x",swap->secretAm[i]);
             printf(" <- secretAm\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->secretAm256[i]);
             printf(" <- secretAm256\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->pubAm.bytes[i]);
             printf(" <- pubAm\n");
             for (i=0; i<20; i++)
             printf("%02x",swap->secretBn[i]);
             printf(" <- secretBn\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->secretBn256[i]);
             printf(" <- secretBn256\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->pubBn.bytes[i]);
             printf(" <- pubBn\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->pubA0.bytes[i]);
             printf(" <- pubA0\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->pubA1.bytes[i]);
             printf(" <- pubA1\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->pubB0.bytes[i]);
             printf(" <- pubB0\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->pubB1.bytes[i]);
             printf(" <- pubB1\n");*/
            if ( (retval= basilisk_alicetxs(swap,data,maxlen)) != 0 )
            {
                printf("basilisk_alicetxs error\n");
                break;
            }
        }
    }
    if ( swap->I.iambob == 0 && (swap->I.statebits & 0x40) == 0 )
    {
        printf("couldnt send fee\n");
        retval = -8;
    }
    if ( retval == 0 )
    {
        if ( swap->I.iambob == 0 && (swap->myfee.I.datalen == 0 || swap->alicepayment.I.datalen == 0 || swap->alicepayment.I.datalen == 0) )
        {
            printf("ALICE's error %d %d %d\n",swap->myfee.I.datalen,swap->alicepayment.I.datalen,swap->alicepayment.I.datalen);
            retval = -7;
        }
        else if ( swap->I.iambob != 0 && swap->bobdeposit.I.datalen == 0 ) //swap->bobpayment.I.datalen == 0
        {
            printf("BOB's error %d %d %d\n",swap->myfee.I.datalen,swap->bobpayment.I.datalen,swap->bobdeposit.I.datalen);
            retval = -7;
        }
    }
    while ( swap->aborted == 0 && retval == 0 && basilisk_swapiteration(swap,data,maxlen) == 0 )
    {
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
        basilisk_sendstate(swap,data,maxlen);
        basilisk_swapget(swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        basilisk_swap_saveupdate(swap);
        if ( time(NULL) > swap->I.expiration )
            break;
    }
    if ( swap->I.iambob != 0 && swap->bobdeposit.I.datalen != 0 && bits256_nonz(swap->bobdeposit.I.actualtxid) != 0 )
    {
        printf("BOB waiting for confirm state.%x\n",swap->I.statebits);
        sleep(60); // wait for confirm/propagation of msig
        printf("BOB reclaims refund\n");
        basilisk_bobdeposit_refund(swap,0);
        if ( LP_swapdata_rawtxsend(swap,0,data,maxlen,&swap->bobrefund,0x40000000,0) == 0 ) // use secretBn
        {
            printf("Bob submit error getting refund of deposit\n");
        }
        else
        {
            // maybe wait for bobrefund to be confirmed
            for (j=datalen=0; j<32; j++)
                data[datalen++] = swap->I.privBn.bytes[j];
            LP_swapsend(swap,0x40000000,data,datalen,0x40000000,swap->I.crcs_mypriv);
        }
        basilisk_swap_saveupdate(swap);
    }
    if ( retval != 0 )
        basilisk_swap_sendabort(swap);
    printf("end of atomic swap\n");
    if ( swapcompleted(swap) > 0 ) // only if swap completed
    {
        if ( swap->I.iambob != 0 )
            tradebot_pendingadd(swapjson(swap),swap->I.req.src,dstr(swap->I.req.srcamount),swap->I.req.dest,dstr(swap->I.req.destamount));
        else tradebot_pendingadd(swapjson(swap),swap->I.req.dest,dstr(swap->I.req.destamount),swap->I.req.src,dstr(swap->I.req.srcamount));
    }
    printf("%s swap finished statebits %x\n",swap->I.iambob!=0?"BOB":"ALICE",swap->I.statebits);
    //basilisk_swap_purge(swap);
    free(data);
}
#endif

bits256 instantdex_derivekeypair(void *ctx,bits256 *newprivp,uint8_t pubkey[33],bits256 privkey,bits256 orderhash)
{
    bits256 sharedsecret;
    sharedsecret = curve25519_shared(privkey,orderhash);
    vcalc_sha256cat(newprivp->bytes,orderhash.bytes,sizeof(orderhash),sharedsecret.bytes,sizeof(sharedsecret));
    return(bitcoin_pubkey33(ctx,pubkey,*newprivp));
}

bits256 basilisk_revealkey(bits256 privkey,bits256 pubkey)
{
    bits256 reveal;
#ifdef DISABLE_CHECKSIG
    vcalc_sha256(0,reveal.bytes,privkey.bytes,sizeof(privkey));
    //reveal = revcalc_sha256(privkey);
    char str[65],str2[65]; printf("priv.(%s) -> reveal.(%s)\n",bits256_str(str,privkey),bits256_str(str2,reveal));
#else
    reveal = pubkey;
#endif
    return(reveal);
}

int32_t instantdex_pubkeyargs(struct basilisk_swap *swap,int32_t numpubs,bits256 privkey,bits256 hash,int32_t firstbyte)
{
    char buf[3]; int32_t i,n,m,len=0; bits256 pubi,reveal; uint64_t txid; uint8_t secret160[20],pubkey[33];
    sprintf(buf,"%c0",'A' - 0x02 + firstbyte);
    if ( numpubs > 2 )
    {
        if ( swap->I.numpubs+2 >= numpubs )
            return(numpubs);
        //fprintf(stderr,">>>>>> start generating %s\n",buf);
    }
    for (i=n=m=0; i<numpubs*100 && n<numpubs; i++)
    {
        pubi = instantdex_derivekeypair(swap->ctx,&privkey,pubkey,privkey,hash);
        //fprintf(stderr,"i.%d n.%d numpubs.%d %02x vs %02x\n",i,n,numpubs,pubkey[0],firstbyte);
        if ( pubkey[0] != firstbyte )
            continue;
        if ( n < 2 )
        {
            if ( bits256_nonz(swap->I.mypubs[n]) == 0 )
            {
                swap->I.myprivs[n] = privkey;
                memcpy(swap->I.mypubs[n].bytes,pubkey+1,sizeof(bits256));
                reveal = basilisk_revealkey(privkey,swap->I.mypubs[n]);
                if ( swap->I.iambob != 0 )
                {
                    if ( n == 0 )
                        swap->I.pubB0 = reveal;
                    else if ( n == 1 )
                        swap->I.pubB1 = reveal;
                }
                else if ( swap->I.iambob == 0 )
                {
                    if ( n == 0 )
                        swap->I.pubA0 = reveal;
                    else if ( n == 1 )
                        swap->I.pubA1 = reveal;
                }
            }
        }
        if ( m < INSTANTDEX_DECKSIZE )
        {
            swap->privkeys[m] = privkey;
            revcalc_rmd160_sha256(secret160,privkey);//.bytes,sizeof(privkey));
            memcpy(&txid,secret160,sizeof(txid));
            len += iguana_rwnum(1,(uint8_t *)&swap->deck[m][0],sizeof(txid),&txid);
            len += iguana_rwnum(1,(uint8_t *)&swap->deck[m][1],sizeof(pubi.txid),&pubi.txid);
            m++;
            if ( m > swap->I.numpubs )
                swap->I.numpubs = m;
        }
        n++;
    }
    if ( n > 2 || m > 2 )
        printf("n.%d m.%d len.%d numpubs.%d\n",n,m,len,swap->I.numpubs);
    return(n);
}

void basilisk_rawtx_setparms(char *name,uint32_t quoteid,struct basilisk_rawtx *rawtx,struct iguana_info *coin,int32_t numconfirms,int32_t vintype,uint64_t satoshis,int32_t vouttype,uint8_t *pubkey33,int32_t jumblrflag)
{
    strcpy(rawtx->name,name);
    rawtx->coin = coin;
    strcpy(rawtx->I.coinstr,coin->symbol);
    rawtx->I.numconfirms = numconfirms;
    if ( (rawtx->I.amount= satoshis) < 50000 )
        rawtx->I.amount = 50000;
    rawtx->I.vintype = vintype; // 0 -> std, 2 -> 2of2, 3 -> spend bobpayment, 4 -> spend bobdeposit
    rawtx->I.vouttype = vouttype; // 0 -> fee, 1 -> std, 2 -> 2of2, 3 -> bobpayment, 4 -> bobdeposit
    if ( rawtx->I.vouttype == 0 )
    {
        if ( strcmp(coin->symbol,"BTC") == 0 && (quoteid % 10) == 0 )
            decode_hex(rawtx->I.rmd160,20,TIERNOLAN_RMD160);
        else decode_hex(rawtx->I.rmd160,20,INSTANTDEX_RMD160);
        bitcoin_address(rawtx->I.destaddr,rawtx->coin->pubtype,rawtx->I.rmd160,20);
    }
    if ( pubkey33 != 0 )
    {
        memcpy(rawtx->I.pubkey33,pubkey33,33);
        bitcoin_address(rawtx->I.destaddr,rawtx->coin->pubtype,rawtx->I.pubkey33,33);
        bitcoin_addr2rmd160(&rawtx->I.addrtype,rawtx->I.rmd160,rawtx->I.destaddr);
    }
    if ( rawtx->I.vouttype <= 1 && rawtx->I.destaddr[0] != 0 )
    {
        rawtx->I.spendlen = bitcoin_standardspend(rawtx->spendscript,0,rawtx->I.rmd160);
        printf("%s spendlen.%d %s <- %.8f\n",name,rawtx->I.spendlen,rawtx->I.destaddr,dstr(rawtx->I.amount));
    } else printf("%s vouttype.%d destaddr.(%s)\n",name,rawtx->I.vouttype,rawtx->I.destaddr);
}

struct basilisk_swap *bitcoin_swapinit(bits256 privkey,uint8_t *pubkey33,bits256 pubkey25519,struct basilisk_swap *swap,int32_t optionduration,uint32_t statebits)
{
    //FILE *fp; char fname[512];
    uint8_t *alicepub33=0,*bobpub33=0; int32_t jumblrflag=-2,x = -1; struct iguana_info *coin;
    swap->I.putduration = swap->I.callduration = INSTANTDEX_LOCKTIME;
    if ( optionduration < 0 )
        swap->I.putduration -= optionduration;
    else if ( optionduration > 0 )
        swap->I.callduration += optionduration;
    swap->I.bobsatoshis = swap->I.req.destamount;
    swap->I.alicesatoshis = swap->I.req.srcamount;
    if ( (swap->I.bobinsurance= (swap->I.bobsatoshis / INSTANTDEX_INSURANCEDIV)) < 50000 )
        swap->I.bobinsurance = 50000;
    if ( (swap->I.aliceinsurance= (swap->I.alicesatoshis / INSTANTDEX_INSURANCEDIV)) < 50000 )
        swap->I.aliceinsurance = 50000;
    strcpy(swap->I.bobstr,swap->I.req.dest);
    strcpy(swap->I.alicestr,swap->I.req.src);
    swap->I.started = (uint32_t)time(NULL);
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
    }
    else
    {
        swap->I.iambob = 1;
        swap->I.otherhash = swap->I.req.srchash;
    }
    if ( bits256_nonz(privkey) == 0 || (x= instantdex_pubkeyargs(swap,2 + INSTANTDEX_DECKSIZE,privkey,swap->I.orderhash,0x02+swap->I.iambob)) != 2 + INSTANTDEX_DECKSIZE )
    {
        char str[65]; printf("couldnt generate privkeys %d %s\n",x,bits256_str(str,privkey));
        return(0);
    }
    if ( (coin= LP_coinfind(swap->I.req.dest)) != 0 )
        swap->bobcoin = *coin;
    else
    {
        printf("missing bobcoin.%p or missing alicecoin.%p src.%p dest.%p\n",&swap->bobcoin,&swap->alicecoin,LP_coinfind(swap->I.req.src),LP_coinfind(swap->I.req.dest));
        free(swap);
        return(0);
    }
    if ( (coin= LP_coinfind(swap->I.req.src)) != 0 )
        swap->alicecoin = *coin;
    else
    {
        printf("missing bobcoin.%p or missing alicecoin.%p src.%p dest.%p\n",&swap->bobcoin,&swap->alicecoin,LP_coinfind(swap->I.req.src),LP_coinfind(swap->I.req.dest));
        free(swap);
        return(0);
    }
    if ( strcmp("BTC",swap->bobcoin.symbol) == 0 )
    {
        swap->I.bobconfirms = (1*0 + sqrt(dstr(swap->I.bobsatoshis) * .1));
        swap->I.aliceconfirms = MIN(BASILISK_DEFAULT_NUMCONFIRMS,swap->I.bobconfirms * 3);
    }
    else if ( strcmp("BTC",swap->alicecoin.symbol) == 0 )
    {
        swap->I.aliceconfirms = (1*0 + sqrt(dstr(swap->I.alicesatoshis) * .1));
        swap->I.bobconfirms = MIN(BASILISK_DEFAULT_NUMCONFIRMS,swap->I.bobconfirms * 3);
    }
    else
    {
        swap->I.bobconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
        swap->I.aliceconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
    }
    /*if ( swap->I.bobconfirms == 0 )
     swap->I.bobconfirms = swap->bobcoin->chain->minconfirms;
     if ( swap->I.aliceconfirms == 0 )
     swap->I.aliceconfirms = swap->alicecoin->chain->minconfirms;*/
    //jumblrflag = (bits256_cmp(pubkey25519,myinfo->jumblr_pubkey) == 0 || bits256_cmp(pubkey25519,myinfo->jumblr_depositkey) == 0);
    printf(">>>>>>>>>> jumblrflag.%d <<<<<<<<< use smart address, %.8f bobconfs.%d, %.8f aliceconfs.%d\n",jumblrflag,dstr(swap->I.bobsatoshis),swap->I.bobconfirms,dstr(swap->I.alicesatoshis),swap->I.aliceconfirms);
    if ( swap->I.iambob != 0 )
    {
        basilisk_rawtx_setparms("myfee",swap->I.req.quoteid,&swap->myfee,&swap->bobcoin,0,0,swap->I.bobsatoshis/INSTANTDEX_INSURANCEDIV,0,0,jumblrflag);
        basilisk_rawtx_setparms("otherfee",swap->I.req.quoteid,&swap->otherfee,&swap->alicecoin,0,0,swap->I.alicesatoshis/INSTANTDEX_INSURANCEDIV,0,0,jumblrflag);
        bobpub33 = pubkey33;
    }
    else
    {
        basilisk_rawtx_setparms("otherfee",swap->I.req.quoteid,&swap->otherfee,&swap->bobcoin,0,0,swap->I.bobsatoshis/INSTANTDEX_INSURANCEDIV,0,0,jumblrflag);
        basilisk_rawtx_setparms("myfee",swap->I.req.quoteid,&swap->myfee,&swap->alicecoin,0,0,swap->I.alicesatoshis/INSTANTDEX_INSURANCEDIV,0,0,jumblrflag);
        alicepub33 = pubkey33;
    }
    basilisk_rawtx_setparms("bobdeposit",swap->I.req.quoteid,&swap->bobdeposit,&swap->bobcoin,swap->I.bobconfirms,0,swap->I.bobsatoshis + (swap->I.bobsatoshis>>3) + swap->bobcoin.txfee,4,0,jumblrflag);
    basilisk_rawtx_setparms("bobrefund",swap->I.req.quoteid,&swap->bobrefund,&swap->bobcoin,1,4,swap->I.bobsatoshis + (swap->I.bobsatoshis>>3),1,bobpub33,jumblrflag);
    swap->bobrefund.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("aliceclaim",swap->I.req.quoteid,&swap->aliceclaim,&swap->bobcoin,1,4,swap->I.bobsatoshis + (swap->I.bobsatoshis>>3),1,alicepub33,jumblrflag);
    swap->aliceclaim.I.suppress_pubkeys = 1;
    swap->aliceclaim.I.locktime = swap->I.started + swap->I.putduration+swap->I.callduration + 1;
    
    basilisk_rawtx_setparms("bobpayment",swap->I.req.quoteid,&swap->bobpayment,&swap->bobcoin,swap->I.bobconfirms,0,swap->I.bobsatoshis + swap->bobcoin.txfee,3,0,jumblrflag);
    basilisk_rawtx_setparms("alicespend",swap->I.req.quoteid,&swap->alicespend,&swap->bobcoin,swap->I.bobconfirms,3,swap->I.bobsatoshis,1,alicepub33,jumblrflag);
    swap->alicespend.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("bobreclaim",swap->I.req.quoteid,&swap->bobreclaim,&swap->bobcoin,swap->I.bobconfirms,3,swap->I.bobsatoshis,1,bobpub33,jumblrflag);
    swap->bobreclaim.I.suppress_pubkeys = 1;
    swap->bobreclaim.I.locktime = swap->I.started + swap->I.putduration + 1;
    basilisk_rawtx_setparms("alicepayment",swap->I.req.quoteid,&swap->alicepayment,&swap->alicecoin,swap->I.aliceconfirms,0,swap->I.alicesatoshis+swap->alicecoin.txfee,2,0,jumblrflag);
    basilisk_rawtx_setparms("bobspend",swap->I.req.quoteid,&swap->bobspend,&swap->alicecoin,swap->I.aliceconfirms,2,swap->I.alicesatoshis,1,bobpub33,jumblrflag);
    swap->bobspend.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("alicereclaim",swap->I.req.quoteid,&swap->alicereclaim,&swap->alicecoin,swap->I.aliceconfirms,2,swap->I.alicesatoshis,1,alicepub33,jumblrflag);
    swap->alicereclaim.I.suppress_pubkeys = 1;
    printf("IAMBOB.%d\n",swap->I.iambob);
    return(swap);
}

struct basilisk_swap *LP_swapinit(int32_t iambob,int32_t optionduration,bits256 privkey,struct basilisk_request *rp)
{
    struct basilisk_swap *swap; bits256 pubkey25519; uint8_t pubkey33[33];
    swap = calloc(1,sizeof(*swap));
    swap->ctx = bitcoin_ctx();
    vcalc_sha256(0,swap->I.orderhash.bytes,(uint8_t *)rp,sizeof(*rp));
    swap->I.req = *rp;
    printf("basilisk_thread_start request.%u iambob.%d (%s/%s)\n",rp->requestid,iambob,rp->src,rp->dest);
    bitcoin_pubkey33(swap->ctx,pubkey33,privkey);
    pubkey25519 = curve25519(privkey,curve25519_basepoint9());
    swap->persistent_pubkey = pubkey25519;
    swap->persistent_privkey = privkey;
    memcpy(swap->persistent_pubkey33,pubkey33,33);
    if ( bitcoin_swapinit(privkey,pubkey33,pubkey25519,swap,optionduration,!iambob) == 0 )
    {
        printf("error doing swapinit\n");
        free(swap);
        swap = 0;
    }
    return(swap);
}

#ifdef notanymore
struct basilisk_swap *basilisk_thread_start(bits256 privkey,struct basilisk_request *rp,uint32_t statebits,int32_t optionduration,int32_t reinit)
{
    int32_t i,m,n,iter; uint8_t pubkey33[33]; bits256 pubkey25519; uint32_t channel,starttime; cJSON *retarray,*item,*msgobj; struct iguana_info *coin; double pending=0.; struct basilisk_swap *swap = 0;
    // statebits 1 -> client, 0 -> LP
    /*if ( myinfo->numswaps > 0 )
    {
        if ( (coin= LP_coinfind(rp->src)) == 0 || coin->FULLNODE >= 0 )
        {
            printf("dont have SRC coin.%s or not native and already swap pending\n",rp->src);
            return(0);
        }
        if ( (coin= LP_coinfind(rp->dest)) == 0 || coin->FULLNODE >= 0 )
        {
            printf("dont have DEST coin.%s or not native and already swap pending\n",rp->dest);
            return(0);
        }
    }
    portable_mutex_lock(&myinfo->DEX_swapmutex);
    for (i=0; i<myinfo->numswaps; i++)
        if ( myinfo->swaps[i]->I.req.requestid == rp->requestid )
        {
            printf("basilisk_thread_start error trying to start requestid.%u which is already started\n",rp->requestid);
            break;
        }
    if ( i == myinfo->numswaps && i < sizeof(myinfo->swaps)/sizeof(*myinfo->swaps) )*/
    {
        swap = calloc(1,sizeof(*swap));
        swap->ctx = bitcoin_ctx();
        swap->subsock = swap->pushsock = -1;
        vcalc_sha256(0,swap->I.orderhash.bytes,(uint8_t *)rp,sizeof(*rp));
        swap->I.req = *rp;
        //swap->myinfoptr = myinfo;
        printf("basilisk_thread_start request.%u statebits.%d (%s/%s) reinit.%d\n",rp->requestid,statebits,rp->src,rp->dest,reinit);
        bitcoin_pubkey33(swap->ctx,pubkey33,privkey);
        pubkey25519 = curve25519(privkey,curve25519_basepoint9());
        swap->persistent_pubkey = pubkey25519;
        swap->persistent_privkey = privkey;
        memcpy(swap->persistent_pubkey33,pubkey33,33);
        m = n = 0;
        if ( bitcoin_swapinit(privkey,pubkey33,pubkey25519,swap,optionduration,statebits,reinit) != 0 )
        {
            for (iter=0; iter<16; iter++)
            {
                basilisk_psockinit(swap,statebits == 0);
                sleep(3);
                if ( swap->connected > 0 )
                    break;
                sleep(10);
                /*basilisk_sendstate(swap,data,sizeof(data));
                 basilisk_swapget(swap,0x80000000,data,sizeof(data),basilisk_verify_statebits);
                 if ( swap->connected > 0 )
                 break;
                 printf("loopback didntwork with %d %d\n",swap->pushsock,swap->subsock);*/
            }
            if ( reinit != 0 )
            {
                if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)basilisk_swaploop,(void *)swap) != 0 )
                {
                    
                }
                //myinfo->swaps[myinfo->numswaps++] = swap;
            }
            else
            {
                starttime = (uint32_t)time(NULL);
                printf("statebits.%x m.%d n.%d\n",statebits,m,n);
                while ( statebits == 0 && m <= n/2 && time(NULL) < starttime+7*BASILISK_MSGDURATION )
                {
                    uint32_t msgid; uint8_t data[1024]; int32_t datalen;
                    m = n = 0;
                    sleep(DEX_SLEEP);
                    printf("waiting for offer to be accepted\n");
                    channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
                    datalen = basilisk_rwDEXquote(1,data,rp);
                    msgid = (uint32_t)time(NULL);
                    printf("other req.%d >>>>>>>>>>> send response (%llx -> %llx) r.%u quoteid.%u\n",i,(long long)rp->desthash.txid,(long long)rp->srchash.txid,rp->requestid,rp->quoteid);
                    LP_channelsend(rp->desthash,rp->srchash,channel,msgid,data,datalen);
                    if ( (retarray= basilisk_channelget(rp->srchash,rp->desthash,channel,0x4000000,30)) != 0 )
                    {
                        if ( is_cJSON_Array(retarray) != 0 && (n= cJSON_GetArraySize(retarray)) > 0 )
                        {
                            for (i=0; i<n; i++)
                            {
                                item = jitem(retarray,i);
                                if ( (msgobj= jarray(&n,item,"messages")) != 0 && n > 0 )
                                {
                                    item = jitem(msgobj,0);
                                    if ( jobj(item,"data") != 0 && jobj(item,"key") != 0 )
                                        m++;
                                    else printf("(%s)\n",jprint(item,0));
                                } //else printf("msgobj.%p m.%d n.%d\n",msgobj,m,n);
                            }
                        }
                    } else printf("no retarray\n");
                }
                printf("LAUNCH check.%d m.%d\n",statebits,m);
                if ( statebits != 0 || m > 0 )//n/2 )
                {
                    //for (i=0; i<sizeof(swap->I.req); i++)
                    //    fprintf(stderr,"%02x",((uint8_t *)&swap->I.req)[i]);
                    if ( (swap->fp= basilisk_swap_save(swap,privkey,rp,statebits,optionduration,reinit)) != 0 )
                    {
                    }
                    if ( reinit == 0 )
                    {
                        static FILE *swapsfp;
                        if ( swapsfp == 0 )
                        {
                            char fname[512];
                            sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
                            if ( (swapsfp= fopen(fname,"rb+")) == 0 )
                                swapsfp = fopen(fname,"wb+");
                            else fseek(swapsfp,0,SEEK_END);
                            printf("LIST fp.%p\n",swapsfp);
                        }
                        if ( swapsfp != 0 )
                        {
                            fwrite(&rp->requestid,1,sizeof(rp->requestid),swapsfp);
                            fwrite(&rp->quoteid,1,sizeof(rp->quoteid),swapsfp);
                            fflush(swapsfp);
                        }
                    }
                    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)basilisk_swaploop,(void *)swap) != 0 )
                    {
                        
                    }
                    //myinfo->swaps[myinfo->numswaps++] = swap;
                }
                else
                {
                    if ( statebits != 0 )
                    {
                        if ( (coin= LP_coinfind(rp->src)) != 0 )
                        {
                            
                        }
                    }
                    printf("%u/%u offer wasnt accepted statebits.%d m.%d n.%d pending %.8f\n",rp->requestid,rp->quoteid,statebits,m,n,pending);
                }
            }
        }
    }
    //portable_mutex_unlock(&myinfo->DEX_swapmutex);
    return(swap);
}
#endif


