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
/* https://bitcointalk.org/index.php?topic=1340621.msg13828271#msg13828271
 https://bitcointalk.org/index.php?topic=1364951
 Tier Nolan's approach is followed with the following changes:
 a) instead of cutting 1000 keypairs, only INSTANTDEX_DECKSIZE are a
 b) instead of sending the entire 256 bits, it is truncated to 64 bits. With odds of collision being so low, it is dwarfed by the ~0.1% insurance factor.
 c) D is set to 100x the insurance rate of 1/777 12.87% + BTC amount
 d) insurance is added to Bob's payment, which is after the deposit and bailin
 e) BEFORE Bob broadcasts deposit, Alice broadcasts BTC denominated fee in cltv so if trade isnt done fee is reclaimed
 */

/*
 both fees are standard payments: OP_DUP OP_HASH160 FEE_RMD160 OP_EQUALVERIFY OP_CHECKSIG
 
 Alice altpayment: OP_2 <alice_pubM> <bob_pubN> OP_2 OP_CHECKMULTISIG
 
 Bob deposit:
 OP_IF
 <now + INSTANTDEX_LOCKTIME*2> OP_CLTV OP_DROP <alice_pubA0> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <bob_pubB0> OP_CHECKSIG
 OP_ENDIF
 
 Bob paytx:
 OP_IF
 <now + INSTANTDEX_LOCKTIME> OP_CLTV OP_DROP <bob_pubB1> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
 OP_ENDIF
 
 Naming convention are pubAi are alice's pubkeys (seems only pubA0 and not pubA1)
 pubBi are Bob's pubkeys
 
 privN is Bob's privkey from the cut and choose deck as selected by Alice
 privM is Alice's counterpart
 pubN and pubM are the corresponding pubkeys for these chosen privkeys
 
 Alice timeout event is triggered if INSTANTDEX_LOCKTIME elapses from the start of a FSM instance. Bob timeout event is triggered after INSTANTDEX_LOCKTIME*2
 */

//#define BASILISK_DISABLETX
#define SCRIPT_OP_IF 0x63
#define SCRIPT_OP_ELSE 0x67
#define SCRIPT_OP_ENDIF 0x68

int32_t basilisk_bobscript(uint8_t *rmd160,uint8_t *redeemscript,int32_t *redeemlenp,uint8_t *script,int32_t n,uint32_t *locktimep,int32_t *secretstartp,struct basilisk_swap *swap,int32_t depositflag)
{
    uint8_t pubkeyA[33],pubkeyB[33],*secret160; bits256 cltvpub,destpub; int32_t i;
    *locktimep = swap->locktime;
    if ( depositflag != 0 )
    {
        *locktimep += INSTANTDEX_LOCKTIME;
        cltvpub = swap->pubA0;
        destpub = swap->pubB0;
        secret160 = swap->secretBn;
        pubkeyA[0] = 0x02;
        pubkeyB[0] = 0x03;
    }
    else
    {
        cltvpub = swap->pubB1;
        destpub = swap->pubA0;
        secret160 = swap->secretAm;
        pubkeyA[0] = 0x03;
        pubkeyB[0] = 0x02;
    }
    char str[65]; printf("bobtx dflag.%d %s\n",depositflag,bits256_str(str,cltvpub));
    if ( bits256_nonz(cltvpub) == 0 || bits256_nonz(destpub) == 0 )
        return(-1);
    for (i=0; i<20; i++)
        if ( secret160[i] != 0 )
            break;
    if ( i == 20 )
        return(-1);
    memcpy(pubkeyA+1,cltvpub.bytes,sizeof(cltvpub));
    memcpy(pubkeyB+1,destpub.bytes,sizeof(destpub));
    redeemscript[n++] = SCRIPT_OP_IF;
    n = bitcoin_checklocktimeverify(redeemscript,n,*locktimep);
    n = bitcoin_pubkeyspend(redeemscript,n,pubkeyA);
    redeemscript[n++] = SCRIPT_OP_ELSE;
    if ( secretstartp != 0 )
        *secretstartp = n + 2;
    n = bitcoin_revealsecret160(redeemscript,n,secret160);
    n = bitcoin_pubkeyspend(redeemscript,n,pubkeyB);
    redeemscript[n++] = SCRIPT_OP_ENDIF;
    *redeemlenp = n;
    calc_rmd160_sha256(rmd160,redeemscript,n);
    n = bitcoin_p2shspend(script,0,rmd160);
    return(n);
}

int32_t basilisk_alicescript(uint8_t *script,int32_t n,char *msigaddr,uint8_t altps2h,bits256 pubAm,bits256 pubBn)
{
    uint8_t p2sh160[20]; struct vin_info V;
    memset(&V,0,sizeof(V));
    memcpy(&V.signers[0].pubkey[1],pubAm.bytes,sizeof(pubAm)), V.signers[0].pubkey[0] = 0x02;
    memcpy(&V.signers[1].pubkey[1],pubBn.bytes,sizeof(pubBn)), V.signers[1].pubkey[0] = 0x03;
    V.M = V.N = 2;
    n = bitcoin_MofNspendscript(p2sh160,script,n,&V);
    bitcoin_address(msigaddr,altps2h,p2sh160,sizeof(p2sh160));
    return(n);
}

int32_t basilisk_numconfirms(struct supernet_info *myinfo,struct basilisk_rawtx *rawtx)
{
    cJSON *argjson,*valuearray=0,*item; char *valstr; int32_t numconfirms,height,i,n;
#ifdef BASILISK_DISABLETX
    return(10);
#endif
    argjson = cJSON_CreateObject();
    jaddbits256(argjson,"txid",rawtx->actualtxid);
    jaddnum(argjson,"vout",0);
    jaddstr(argjson,"coin",rawtx->coin->symbol);
    if ( (valstr= basilisk_value(myinfo,rawtx->coin,0,0,myinfo->myaddr.persistent,argjson,0)) != 0 )
    {
        char str[65]; printf("%s %s valstr.(%s)\n",rawtx->name,bits256_str(str,rawtx->actualtxid),valstr);
        if ( (valuearray= cJSON_Parse(valstr)) != 0 )
        {
            if ( is_cJSON_Array(valuearray) != 0 )
            {
                n = cJSON_GetArraySize(valuearray);
                for (i=0; i<n; i++)
                {
                    item = jitem(valuearray,i);
                    height = jint(item,"height");
                    numconfirms = jint(item,"numconfirms");
                    printf("i.%d of %d: %s height.%d -> numconfirms.%d\n",i,n,bits256_str(str,rawtx->actualtxid),height,numconfirms);
                    if ( height > 0 && numconfirms >= 0 )
                    {
                        free_json(argjson);
                        free_json(valuearray);
                        free(valstr);
                    }
                }
            } else printf("valstr not array\n");
        } else printf("parse error\n");
    }
    free_json(argjson);
    if ( valuearray != 0 )
        free_json(valuearray);
    free(valstr);
    return(-1);
}

bits256 basilisk_swap_broadcast(char *name,struct supernet_info *myinfo,struct basilisk_swap *swap,struct iguana_info *coin,uint8_t *data,int32_t datalen)
{
    bits256 txid; char *signedtx;
    memset(txid.bytes,0,sizeof(txid));
    if ( data != 0 && datalen != 0 )
    {
#ifdef BASILISK_DISABLETX
        txid = bits256_doublesha256(0,data,datalen);
        return(txid);
#endif
        signedtx = malloc(datalen*2 + 1);
        init_hexbytes_noT(signedtx,data,datalen);
        txid = iguana_sendrawtransaction(myinfo,coin,signedtx);
        char str[65]; printf("%s <- sendrawtransaction %s.(%s)\n",name,signedtx,bits256_str(str,txid));
        free(signedtx);
    }
    return(txid);
}

int32_t basilisk_rawtx_spend(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *dest,struct basilisk_rawtx *rawtx,bits256 privkey,bits256 *privkey2,uint8_t *userdata,int32_t userdatalen)
{
    char *rawtxbytes,*signedtx,hexstr[999],wifstr[128]; cJSON *txobj,*vins,*item,*sobj,*privkeys; int32_t retval = -1; struct vin_info V; uint32_t locktime=0;
    memset(&V,0,sizeof(V));
    if ( dest == &swap->aliceclaim )
        locktime = swap->locktime + INSTANTDEX_LOCKTIME;
    V.signers[0].privkey = privkey;
    bitcoin_pubkey33(myinfo->ctx,V.signers[0].pubkey,privkey);
    privkeys = cJSON_CreateArray();
    bitcoin_priv2wif(wifstr,privkey,rawtx->coin->chain->wiftype);
    jaddistr(privkeys,wifstr);
    if ( privkey2 != 0 )
    {
        V.signers[1].privkey = *privkey2;
        bitcoin_pubkey33(myinfo->ctx,V.signers[1].pubkey,*privkey2);
        bitcoin_priv2wif(wifstr,*privkey2,rawtx->coin->chain->wiftype);
        jaddistr(privkeys,wifstr);
        V.N = V.M = 2;
        char str[65]; printf("add second privkey.(%s) %s\n",jprint(privkeys,0),bits256_str(str,*privkey2));
    } else V.N = V.M = 1;
    V.suppress_pubkeys = dest->suppress_pubkeys;
    if ( userdata != 0 && userdatalen > 0 )
    {
        memcpy(V.userdata,userdata,userdatalen);
        V.userdatalen = userdatalen;
    }
    txobj = bitcoin_txcreate(rawtx->coin->chain->isPoS,locktime,rawtx->coin->chain->locktime_txversion);
    vins = cJSON_CreateArray();
    item = cJSON_CreateObject();
    if ( bits256_nonz(rawtx->actualtxid) != 0 )
        jaddbits256(item,"txid",rawtx->actualtxid);
    else jaddbits256(item,"txid",rawtx->signedtxid);
    jaddnum(item,"vout",0);
    sobj = cJSON_CreateObject();
    init_hexbytes_noT(hexstr,rawtx->spendscript,rawtx->spendlen);
    jaddstr(sobj,"hex",hexstr);
    jadd(item,"scriptPubKey",sobj);
    if ( locktime != 0 )
        jaddnum(item,"sequence",0);
    jaddi(vins,item);
    jdelete(txobj,"vin");
    jadd(txobj,"vin",vins);
    printf("basilisk_rawtx_spend locktime.%u/%u for %s spendscript.%s -> %s, suppress.%d\n",rawtx->locktime,dest->locktime,rawtx->name,hexstr,dest->name,dest->suppress_pubkeys);
    txobj = bitcoin_txoutput(txobj,dest->spendscript,dest->spendlen,dest->amount);
    if ( (rawtxbytes= bitcoin_json2hex(myinfo,rawtx->coin,&dest->txid,txobj,&V)) != 0 )
    {
        //printf("spend rawtx.(%s) userdatalen.%d\n",rawtxbytes,userdatalen);
        if ( (signedtx= iguana_signrawtx(myinfo,rawtx->coin,&dest->signedtxid,&dest->completed,vins,rawtxbytes,privkeys,&V)) != 0 )
        {
            //printf("rawtx spend signedtx.(%s)\n",signedtx);
            dest->datalen = (int32_t)strlen(signedtx) >> 1;
            dest->txbytes = calloc(1,dest->datalen);
            decode_hex(dest->txbytes,dest->datalen,signedtx);
            free(signedtx);
            retval = 0;
        }
        free(rawtxbytes);
    }
    free_json(privkeys);
    free_json(txobj);
    return(retval);
}

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
    // add verification
    swap->otherfee.txbytes = calloc(1,datalen);
    memcpy(swap->otherfee.txbytes,data,datalen);
    swap->otherfee.actualtxid = swap->otherfee.signedtxid = bits256_doublesha256(0,data,datalen);
    return(0);
}

int32_t basilisk_rawtx_spendscript(struct supernet_info *myinfo,struct basilisk_rawtx *rawtx,int32_t v,uint8_t *data,int32_t datalen)
{
    int32_t retval=-1,hexlen,n; cJSON *txobj,*skey,*vouts,*vout; char *hexstr;
    if ( rawtx->txbytes == 0 )
    {
        rawtx->txbytes = calloc(1,datalen);
        memcpy(rawtx->txbytes,data,datalen);
        rawtx->datalen = datalen;
    }
    else if ( datalen != rawtx->datalen || memcmp(rawtx->txbytes,data,datalen) != 0 )
    {
        printf("%s rawtx data compare error, len %d vs %d\n",rawtx->name,rawtx->datalen,datalen);
        return(-1);
    }
    if ( (txobj= bitcoin_data2json(rawtx->coin,&rawtx->signedtxid,&rawtx->msgtx,rawtx->extraspace,sizeof(rawtx->extraspace),rawtx->txbytes,rawtx->datalen)) != 0 )
    {
        rawtx->actualtxid = rawtx->signedtxid;
        char str[65]; printf("got txid.%s\n",bits256_str(str,rawtx->signedtxid));
        rawtx->locktime = rawtx->msgtx.lock_time;
        if ( (vouts= jarray(&n,txobj,"vout")) != 0 && v < n )
        {
            vout = jitem(vouts,v);
            if ( j64bits(vout,"satoshis") == rawtx->amount && (skey= jobj(vout,"scriptPubKey")) != 0 && (hexstr= jstr(skey,"hex")) != 0 )
            {
                if ( (hexlen= (int32_t)strlen(hexstr) >> 1) < sizeof(rawtx->spendscript) )
                {
                    decode_hex(rawtx->spendscript,hexlen,hexstr);
                    rawtx->spendlen = hexlen;
                    retval = 0;
                }
            } else printf("%s ERROR.(%s)\n",rawtx->name,jprint(txobj,0));
        }
        free_json(txobj);
    }
    return(retval);
}

int32_t basilisk_verify_bobdeposit(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    uint8_t userdata[512]; int32_t len = 0;
    if ( basilisk_rawtx_spendscript(myinfo,&swap->bobdeposit,0,data,datalen) == 0 )
    {
        userdata[len++] = 0x51; // true -> if path
        return(basilisk_rawtx_spend(myinfo,swap,&swap->aliceclaim,&swap->bobdeposit,swap->myprivs[0],0,userdata,len));
    } else return(-1);
}

int32_t basilisk_bobdeposit_refund(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    uint8_t userdata[512]; int32_t i,len = 0;
    userdata[len++] = sizeof(swap->privBn);
    for (i=0; i<sizeof(swap->privBn); i++)
        userdata[len++] = swap->privBn.bytes[sizeof(swap->privBn) - 1 - i];
    userdata[len++] = 0; // false -> else path
    return(basilisk_rawtx_spend(myinfo,swap,&swap->bobrefund,&swap->bobdeposit,swap->myprivs[0],0,userdata,len));
}

int32_t basilisk_bobpayment_reclaim(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    uint8_t userdata[512]; int32_t len = 0;
    userdata[len++] = 0x51; // true -> if path
    return(basilisk_rawtx_spend(myinfo,swap,&swap->bobreclaim,&swap->bobpayment,swap->myprivs[1],0,userdata,len));
}

int32_t basilisk_verify_bobpaid(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    uint8_t userdata[512]; int32_t i,len = 0;
    if ( basilisk_rawtx_spendscript(myinfo,&swap->bobpayment,0,data,datalen) == 0 )
    {
        // OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
        userdata[len++] = sizeof(swap->privAm);
        for (i=0; i<sizeof(swap->privAm); i++)
            userdata[len++] = swap->privAm.bytes[sizeof(swap->privAm) - 1 - i];
        userdata[len++] = 0; // false -> else path
        char str[65]; printf("bobpaid.(%s)\n",bits256_str(str,swap->privAm));
        return(basilisk_rawtx_spend(myinfo,swap,&swap->alicespend,&swap->bobpayment,swap->myprivs[0],0,userdata,len));
    } else return(-1);
}

int32_t basilisk_alicepayment_spend(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *dest)
{
    return(basilisk_rawtx_spend(myinfo,swap,dest,&swap->alicepayment,swap->privAm,&swap->privBn,0,0));
}

int32_t basilisk_verify_alicepaid(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    if ( basilisk_rawtx_spendscript(myinfo,&swap->alicepayment,0,data,datalen) == 0 )
        return(0);
    else return(-1);
}

int32_t basilisk_privAm_extract(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    // need to scan blockchain for alicespend of bobpayment
    // search for swap->bobpayment.actualtxid in spends
    if ( bits256_nonz(swap->privAm) != 0 && swap->bobspend.txbytes == 0 )
    {
        char str[65]; printf("have privAm.%s\n",bits256_str(str,swap->privAm));
        return(basilisk_alicepayment_spend(myinfo,swap,&swap->bobspend));
    }
    return(-1);
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
        if ( basilisk_verify_pubpair(&wrongfirstbyte,swap,swap->choosei,pubkey33[0],pubi,txid) == 0 )
        {
            if ( swap->iambob != 0 )
                swap->privAm = privkey;
            else swap->privBn = privkey;
            char str[65]; printf("privi verified.(%s)\n",bits256_str(str,privkey));
            return(0);
        }
    }
    return(-1);
}

int32_t basilisk_swapget(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,int32_t (*basilisk_verify_func)(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen))
{
    int32_t datalen;
    if ( (datalen= basilisk_channelget(myinfo,myinfo->myaddr.persistent,swap->req.quoteid,msgbits,data,maxlen)) > 0 )
        return((*basilisk_verify_func)(myinfo,swap,data,datalen));
    else return(-1);
}

int32_t basilisk_privBn_extract(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    // need to scan blockchain for bobrefund
    // search for swap->bobrefund.actualtxid in spends
    if ( basilisk_swapget(myinfo,swap,0x80000000,data,maxlen,basilisk_verify_privi) == 0 )
    {
        if ( bits256_nonz(swap->privBn) != 0 && swap->alicereclaim.txbytes == 0 )
        {
            char str[65]; printf("have privBn.%s\n",bits256_str(str,swap->privBn));
            return(basilisk_alicepayment_spend(myinfo,swap,&swap->alicereclaim));
        }
    }
    return(-1);
}
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
                if ( swap->iambob != 0 )
                {
                    if ( n == 0 )
                        swap->pubB0 = swap->mypubs[n];
                    else if ( n == 1 )
                        swap->pubB1 = swap->mypubs[n];
                }
                else if ( swap->iambob == 0 )
                {
                    if ( n == 0 )
                        swap->pubA0 = swap->mypubs[n];
                    else if ( n == 1 )
                        swap->pubA1 = swap->mypubs[n];
                }
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

int32_t basilisk_rawtx_return(struct supernet_info *myinfo,struct basilisk_rawtx *rawtx,cJSON *item,cJSON *privkeyarray,int32_t lockinputs)
{
    char *signedtx,*txbytes; cJSON *vins; int32_t i,n,retval = -1;
    if ( (txbytes= jstr(item,"rawtx")) != 0 && (vins= jobj(item,"vins")) != 0 )
    {
        if ( (signedtx= iguana_signrawtx(myinfo,rawtx->coin,&rawtx->signedtxid,&rawtx->completed,vins,txbytes,privkeyarray,0)) != 0 )
        {
            if ( lockinputs != 0 )
            {
                iguana_unspentslock(myinfo,rawtx->coin,vins);
                if ( (n= cJSON_GetArraySize(vins)) != 0 )
                {
                    bits256 txid; int32_t vout;
                    for (i=0; i<n; i++)
                    {
                        item = jitem(vins,i);
                        txid = jbits256(item,"txid");
                        vout = jint(item,"vout");
                        if ( bits256_nonz(txid) != 0 )
                        {
                            char str[65]; printf("call addspend.(%s) v.%d\n",bits256_str(str,txid),vout);
                            basilisk_addspend(myinfo,rawtx->coin->symbol,txid,vout,1);
                        }
                    }
                }
            }
            rawtx->datalen = (int32_t)strlen(signedtx) >> 1;
            rawtx->txbytes = calloc(1,rawtx->datalen);
            decode_hex(rawtx->txbytes,rawtx->datalen,signedtx);
            //printf("SIGNEDTX.(%s)\n",signedtx);
            free(signedtx);
            retval = 0;
        } else printf("error signrawtx\n"); //do a very short timeout so it finishes via local poll
    }
    return(retval);
}

int32_t basilisk_rawtx_gen(char *str,struct supernet_info *myinfo,int32_t iambob,int32_t lockinputs,struct basilisk_rawtx *rawtx,uint32_t locktime,uint8_t *script,int32_t scriptlen,int64_t txfee,int32_t minconf)
{
    struct iguana_waddress *waddr; struct iguana_waccount *wacct; char coinaddr[64],wifstr[64],*retstr,scriptstr[1024]; uint32_t basilisktag; int32_t flag,i,n,retval = -1; cJSON *valsobj,*retarray=0,*privkeyarray,*addresses;
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
    //jadd(valsobj,"addresses",addresses);
    jaddstr(valsobj,"coin",rawtx->coin->symbol);
    jaddstr(valsobj,"spendscript",scriptstr);
    jaddstr(valsobj,"changeaddr",rawtx->coin->changeaddr);
    jadd64bits(valsobj,"satoshis",rawtx->amount);
    jadd64bits(valsobj,"txfee",txfee);
    jaddnum(valsobj,"minconf",minconf);
    jaddnum(valsobj,"locktime",locktime);
    jaddnum(valsobj,"timeout",30000);
    rawtx->locktime = locktime;
    printf("%s locktime.%u\n",rawtx->name,locktime);
    if ( (retstr= basilisk_bitcoinrawtx(myinfo,rawtx->coin,"",basilisktag,jint(valsobj,"timeout"),valsobj)) != 0 )
    {
        printf("%s got.(%s)\n",str,retstr);
        flag = 0;
        if ( (retarray= cJSON_Parse(retstr)) != 0 )
        {
            if ( is_cJSON_Array(retarray) != 0 )
            {
                n = cJSON_GetArraySize(retarray);
                for (i=0; i<n; i++)
                {
                    if ( (retval= basilisk_rawtx_return(myinfo,rawtx,jitem(retarray,i),privkeyarray,lockinputs)) == 0 )
                        break;
                }
            } else retval = basilisk_rawtx_return(myinfo,rawtx,retarray,privkeyarray,lockinputs);
            free(retarray);
        } else printf("error parsing.(%s)\n",retstr);
        free(retstr);
    } else printf("error creating %s feetx\n",iambob != 0 ? "BOB" : "ALICE");
    free_json(privkeyarray);
    free_json(valsobj);
    printf("rawtx retval.%d\n",retval);
    return(retval);
}

void basilisk_rawtx_setparms(char *name,struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *rawtx,struct iguana_info *coin,int32_t numconfirms,int32_t vintype,uint64_t satoshis,int32_t vouttype,uint8_t *pubkey33)
{
    strcpy(rawtx->name,name);
    rawtx->coin = coin;
    rawtx->numconfirms = numconfirms;
    if ( (rawtx->amount= satoshis) < 10000 )
        rawtx->amount = 10000;
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
        printf("%s spendlen.%d %s <- %.8f\n",name,rawtx->spendlen,rawtx->destaddr,dstr(rawtx->amount));
    } else printf("%s vouttype.%d destaddr.(%s)\n",name,rawtx->vouttype,rawtx->destaddr);
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
    if ( (swap->bobinsurance= (swap->bobsatoshis / INSTANTDEX_INSURANCEDIV)) < 10000 )
        swap->bobinsurance = 10000;
    if ( (swap->aliceinsurance= (swap->alicesatoshis / INSTANTDEX_INSURANCEDIV)) < 10000 )
        swap->aliceinsurance = 10000;
    strcpy(swap->bobstr,swap->bobcoin->symbol);
    strcpy(swap->alicestr,swap->alicecoin->symbol);
    swap->started = (uint32_t)time(NULL);
    swap->expiration = swap->req.timestamp + INSTANTDEX_LOCKTIME*2;
    swap->locktime = swap->req.timestamp + INSTANTDEX_LOCKTIME;
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
        basilisk_rawtx_setparms("myfee",myinfo,swap,&swap->myfee,swap->bobcoin,0,0,swap->bobsatoshis/INSTANTDEX_DECKSIZE,0,0);
        basilisk_rawtx_setparms("otherfee",myinfo,swap,&swap->otherfee,swap->alicecoin,0,0,swap->alicesatoshis/INSTANTDEX_DECKSIZE,0,0);
        bobpub33 = myinfo->persistent_pubkey33;
    }
    else
    {
        basilisk_rawtx_setparms("otherfee",myinfo,swap,&swap->otherfee,swap->bobcoin,0,0,swap->bobsatoshis/INSTANTDEX_DECKSIZE,0,0);
        basilisk_rawtx_setparms("myfee",myinfo,swap,&swap->myfee,swap->alicecoin,0,0,swap->alicesatoshis/INSTANTDEX_DECKSIZE,0,0);
        alicepub33 = myinfo->persistent_pubkey33;
    }
    basilisk_rawtx_setparms("bobdeposit",myinfo,swap,&swap->bobdeposit,swap->bobcoin,swap->bobconfirms,0,swap->bobsatoshis*1.1,4,0);
    basilisk_rawtx_setparms("bobrefund",myinfo,swap,&swap->bobrefund,swap->bobcoin,1,4,swap->bobsatoshis*1.1-swap->bobcoin->txfee,1,bobpub33);
    swap->bobrefund.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("aliceclaim",myinfo,swap,&swap->aliceclaim,swap->bobcoin,1,4,swap->bobsatoshis*1.1-swap->bobcoin->txfee,1,alicepub33);
    swap->aliceclaim.suppress_pubkeys = 1;

    basilisk_rawtx_setparms("bobpayment",myinfo,swap,&swap->bobpayment,swap->bobcoin,swap->bobconfirms,0,swap->bobsatoshis,3,0);
    basilisk_rawtx_setparms("alicespend",myinfo,swap,&swap->alicespend,swap->bobcoin,swap->bobconfirms,3,swap->bobsatoshis - swap->bobcoin->txfee,1,alicepub33);
    swap->alicespend.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("bobreclaim",myinfo,swap,&swap->bobreclaim,swap->bobcoin,swap->bobconfirms,3,swap->bobsatoshis - swap->bobcoin->txfee,1,bobpub33);
    swap->bobreclaim.suppress_pubkeys = 1;

    basilisk_rawtx_setparms("alicepayment",myinfo,swap,&swap->alicepayment,swap->alicecoin,swap->aliceconfirms,0,swap->alicesatoshis,2,0);
    basilisk_rawtx_setparms("bobspend",myinfo,swap,&swap->bobspend,swap->alicecoin,swap->aliceconfirms,2,swap->alicesatoshis-swap->alicecoin->txfee,1,bobpub33);
    swap->bobspend.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("alicereclaim",myinfo,swap,&swap->alicereclaim,swap->alicecoin,swap->aliceconfirms,2,swap->alicesatoshis-swap->alicecoin->txfee,1,alicepub33);
    swap->alicereclaim.suppress_pubkeys = 1;
    swap->sleeptime = 3 - swap->iambob;
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
    basilisk_rawtx_purge(&swap->bobrefund);
}

void basilisk_swap_purge(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    int32_t i,n;
    // while still in orderbook, wait
    return;
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

int32_t basilisk_verify_statebits(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    iguana_rwnum(0,data,sizeof(swap->otherstatebits),&swap->otherstatebits);
    return(0);
}

int32_t basilisk_verify_choosei(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t otherchoosei=-1,i,len = 0;
    if ( datalen == sizeof(otherchoosei)+sizeof(bits256)*2 )
    {
        len += iguana_rwnum(0,data,sizeof(otherchoosei),&otherchoosei);
        if ( otherchoosei >= 0 && otherchoosei < INSTANTDEX_DECKSIZE )
        {
            printf("otherchoosei.%d\n",otherchoosei);
            swap->otherchoosei = otherchoosei;
            if ( swap->iambob != 0 )
            {
                for (i=0; i<32; i++)
                    swap->pubA0.bytes[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->pubA1.bytes[i] = data[len++];
                char str[65]; printf("GOT pubA0/1 %s\n",bits256_str(str,swap->pubA0));
            }
            else
            {
                for (i=0; i<32; i++)
                    swap->pubB0.bytes[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->pubB1.bytes[i] = data[len++];
            }
            return(0);
        }
    }
    printf("illegal otherchoosei.%d datalen.%d vs %d\n",otherchoosei,datalen,(int32_t)(sizeof(otherchoosei)+sizeof(bits256)*2));
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
    for (i=0; i<sizeof(swap->otherdeck)/sizeof(swap->otherdeck[0][0]); i++)
        len += iguana_rwnum(0,&data[len],sizeof(swap->otherdeck[i>>1][i&1]),&swap->otherdeck[i>>1][i&1]);
    return(0);
}

int32_t basilisk_verify_privkeys(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t i,j,wrongfirstbyte=0,errs=0,len = 0; bits256 otherpriv,pubi; uint8_t secret160[20],otherpubkey[33]; uint64_t txid;
    printf("verify privkeys choosei.%d otherchoosei.%d datalen.%d vs %d\n",swap->choosei,swap->otherchoosei,datalen,(int32_t)sizeof(swap->privkeys)+20+32);
    if ( swap->cutverified == 0 && swap->otherchoosei >= 0 && datalen == sizeof(swap->privkeys)+20+32 )
    {
        for (i=errs=0; i<sizeof(swap->privkeys)/sizeof(*swap->privkeys); i++)
        {
            for (j=0; j<32; j++)
                otherpriv.bytes[j] = data[len++];
            if ( i != swap->choosei )
            {
                pubi = bitcoin_pubkey33(myinfo->ctx,otherpubkey,otherpriv);
                calc_rmd160_sha256(secret160,otherpriv.bytes,sizeof(otherpriv));
                memcpy(&txid,secret160,sizeof(txid));
                errs += basilisk_verify_pubpair(&wrongfirstbyte,swap,i,otherpubkey[0],pubi,txid);
            }
        }
        if ( errs == 0 && wrongfirstbyte == 0 )
        {
            swap->cutverified = 1, printf("CUT VERIFIED\n");
            if ( swap->iambob != 0 )
            {
                for (i=0; i<32; i++)
                    swap->pubAm.bytes[i] = data[len++];
                for (i=0; i<20; i++)
                    swap->secretAm[i] = data[len++];
            }
            else
            {
                for (i=0; i<32; i++)
                    swap->pubBn.bytes[i] = data[len++];
                for (i=0; i<20; i++)
                    swap->secretBn[i] = data[len++];
            }
        } else printf("failed verification: wrong firstbyte.%d errs.%d\n",wrongfirstbyte,errs);
    }
    printf("privkeys errs.%d wrongfirstbyte.%d\n",errs,wrongfirstbyte);
    return(errs);
}

uint32_t basilisk_swapsend(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t nextbits)
{
    if ( basilisk_channelsend(myinfo,swap->otherhash,swap->req.quoteid,msgbits,data,datalen) == 0 )
        return(nextbits);
    else return(0);
}

uint32_t basilisk_swapdata_rawtxsend(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx,uint32_t nextbits)
{
    if ( basilisk_swapdata_rawtx(myinfo,swap,data,maxlen,rawtx) != 0 )
    {
        rawtx->actualtxid = basilisk_swap_broadcast(rawtx->name,myinfo,swap,rawtx->coin,rawtx->txbytes,rawtx->datalen);
        char str[65],str2[65]; printf("rawtxsend %s vs %s\n",bits256_str(str,rawtx->signedtxid),bits256_str(str2,rawtx->actualtxid));
        if ( bits256_nonz(rawtx->actualtxid) != 0 && msgbits != 0 )
            return(basilisk_swapsend(myinfo,swap,msgbits,rawtx->txbytes,rawtx->datalen,nextbits));
        else return(nextbits);
    } else printf("error from basilisk_swapdata_rawtx %p len.%d\n",rawtx->txbytes,rawtx->datalen);
    return(0);
}

void basilisk_swap01(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t datalen;
    datalen = basilisk_swapdata_deck(myinfo,swap,data,maxlen);
    printf("send deck.%d\n",datalen);
    swap->statebits |= basilisk_swapsend(myinfo,swap,0x02,data,datalen,0x01);
}

void basilisk_swap02(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    if ( (swap->statebits & 0x02) == 0 )
    {
        printf("check for other deck\n");
        if ( basilisk_swapget(myinfo,swap,0x02,data,maxlen,basilisk_verify_otherdeck) == 0 )
            swap->statebits |= 0x02;
    }
}

void basilisk_swap04(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen; char str[65];
    datalen = iguana_rwnum(1,data,sizeof(swap->choosei),&swap->choosei);
    if ( swap->iambob != 0 )
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->pubB0.bytes[i];
        for (i=0; i<32; i++)
            data[datalen++] = swap->pubB1.bytes[i];
        printf("SEND pubB0/1 %s\n",bits256_str(str,swap->pubB0));
    }
    else
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->pubA0.bytes[i];
        for (i=0; i<32; i++)
            data[datalen++] = swap->pubA1.bytes[i];
        printf("SEND pubA0/1 %s\n",bits256_str(str,swap->pubA0));
    }
    swap->statebits |= basilisk_swapsend(myinfo,swap,0x08,data,datalen,0x04);
}

void basilisk_swap08(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    uint8_t pubkey33[33]; char str[65];
    printf("check otherchoosei\n");
    if ( basilisk_swapget(myinfo,swap,0x08,data,maxlen,basilisk_verify_choosei) == 0 )
    {
        if ( swap->iambob != 0 )
        {
            if ( bits256_nonz(swap->privBn) == 0 )
            {
                swap->privBn = swap->privkeys[swap->otherchoosei];
                memset(&swap->privkeys[swap->otherchoosei],0,sizeof(swap->privkeys[swap->otherchoosei]));
                calc_rmd160_sha256(swap->secretBn,swap->privBn.bytes,sizeof(swap->privBn));
                swap->pubBn = bitcoin_pubkey33(myinfo->ctx,pubkey33,swap->privBn);
                printf("set privBn.%s\n",bits256_str(str,swap->privBn));
            }
        }
        else
        {
            if ( bits256_nonz(swap->privAm) == 0 )
            {
                swap->privAm = swap->privkeys[swap->otherchoosei];
                memset(&swap->privkeys[swap->otherchoosei],0,sizeof(swap->privkeys[swap->otherchoosei]));
                calc_rmd160_sha256(swap->secretAm,swap->privAm.bytes,sizeof(swap->privAm));
                swap->pubAm = bitcoin_pubkey33(myinfo->ctx,pubkey33,swap->privAm);
                printf("set privAm.%s\n",bits256_str(str,swap->privAm));
            }
        }
        swap->statebits |= 0x08;
    }
}

void basilisk_swap10(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,j,datalen;
    datalen = 0;
    for (i=0; i<sizeof(swap->privkeys)/sizeof(*swap->privkeys); i++)
    {
        for (j=0; j<32; j++)
            data[datalen++] = (i == swap->otherchoosei) ? 0 : swap->privkeys[i].bytes[j];
    }
    if ( swap->iambob != 0 )
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->pubBn.bytes[i];
        for (i=0; i<20; i++)
            data[datalen++] = swap->secretBn[i];
    }
    else
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->pubAm.bytes[i];
        for (i=0; i<20; i++)
            data[datalen++] = swap->secretAm[i];
    }
    printf("send privkeys.%d\n",datalen);
    swap->statebits |= basilisk_swapsend(myinfo,swap,0x20,data,datalen,0x10);
}

void basilisk_alicepayment(struct supernet_info *myinfo,struct iguana_info *coin,struct basilisk_rawtx *alicepayment,bits256 pubAm,bits256 pubBn)
{
    alicepayment->spendlen = basilisk_alicescript(alicepayment->spendscript,0,alicepayment->destaddr,coin->chain->p2shtype,pubAm,pubBn);
    basilisk_rawtx_gen("alicepayment",myinfo,0,1,alicepayment,alicepayment->locktime,alicepayment->spendscript,alicepayment->spendlen,coin->chain->txfee,1);
}

void basilisk_swaploop(void *_swap)
{
    uint8_t *data; int32_t i,j,maxlen,datalen; struct supernet_info *myinfo; struct basilisk_swap *swap = _swap;
    myinfo = swap->myinfo;
    fprintf(stderr,"start swap\n");
    maxlen = 1024*1024 + sizeof(*swap);
    data = malloc(maxlen);
    while ( time(NULL) < swap->expiration )
    {
        printf("r%u/q%u swapstate.%x\n",swap->req.requestid,swap->req.quoteid,swap->statebits);
        if ( (swap->statebits & 0x08) == 0 )
        {
            basilisk_swap01(myinfo,swap,data,maxlen); // send pubkeys
            basilisk_swap08(myinfo,swap,data,maxlen); // wait for choosei
        }
        if ( (swap->statebits & 0x10) == 0 )
        {
            basilisk_swap02(myinfo,swap,data,maxlen); // check for other deck
            basilisk_swap04(myinfo,swap,data,maxlen); // send choosei
            if ( (swap->statebits & 0x10) == 0 && swap->otherchoosei >= 0 && swap->otherchoosei < INSTANTDEX_DECKSIZE ) // send all but one privkeys
                basilisk_swap10(myinfo,swap,data,maxlen);
        }
        if ( (swap->statebits & 0x1f) != 0x1f )
        {
            printf("initial setup incomplete state.%x\n",swap->statebits);
            sleep(1);
            continue;
        }
        if ( (swap->statebits & 0x20) == 0 ) // wait for all but one privkeys
        {
            if ( basilisk_swapget(myinfo,swap,0x20,data,maxlen,basilisk_verify_privkeys) == 0 )
                swap->statebits |= 0x20;
        }
        else if ( (swap->statebits & 0x40) == 0 ) // send fee
        {
            if ( swap->myfee.txbytes == 0 )
            {
                for (i=0; i<20; i++)
                    printf("%02x",swap->secretAm[i]);
                printf(" <- secretAm\n");
                for (i=0; i<32; i++)
                    printf("%02x",swap->pubAm.bytes[i]);
                printf(" <- pubAm\n");
                for (i=0; i<20; i++)
                    printf("%02x",swap->secretBn[i]);
                printf(" <- secretBn\n");
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
                printf(" <- pubB1\n");
                if ( swap->iambob != 0 )
                {
                    swap->bobpayment.spendlen = basilisk_bobscript(swap->bobpayment.rmd160,swap->bobpayment.redeemscript,&swap->bobpayment.redeemlen,swap->bobpayment.spendscript,0,&swap->bobpayment.locktime,&swap->bobpayment.secretstart,swap,0);
                    swap->bobdeposit.spendlen = basilisk_bobscript(swap->bobdeposit.rmd160,swap->bobdeposit.redeemscript,&swap->bobdeposit.redeemlen,swap->bobdeposit.spendscript,0,&swap->bobdeposit.locktime,&swap->bobdeposit.secretstart,swap,1);
                    basilisk_rawtx_gen("deposit",myinfo,1,1,&swap->bobdeposit,swap->bobdeposit.locktime,swap->bobdeposit.spendscript,swap->bobdeposit.spendlen,swap->bobdeposit.coin->chain->txfee,1);
                    basilisk_rawtx_gen("payment",myinfo,1,1,&swap->bobpayment,swap->bobpayment.locktime,swap->bobpayment.spendscript,swap->bobpayment.spendlen,swap->bobpayment.coin->chain->txfee,1);
                    if ( swap->bobdeposit.txbytes == 0 || swap->bobdeposit.spendlen == 0 || swap->bobpayment.txbytes == 0 || swap->bobpayment.spendlen == 0 )
                    {
                        printf("error bob generating deposit.%d or payment.%d\n",swap->bobdeposit.spendlen,swap->bobpayment.spendlen);
                        break;
                    }
                }
                else
                {
                    basilisk_alicepayment(myinfo,swap->alicepayment.coin,&swap->alicepayment,swap->pubAm,swap->pubBn);
                    if ( swap->alicepayment.txbytes == 0 || swap->alicepayment.spendlen == 0 )
                    {
                        printf("error alice generating payment.%d\n",swap->alicepayment.spendlen);
                        break;
                    }
                }
                if ( basilisk_rawtx_gen("myfee",myinfo,swap->iambob,1,&swap->myfee,0,swap->myfee.spendscript,swap->myfee.spendlen,swap->myfee.coin->chain->txfee,1) == 0 )
                    swap->statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x80,data,maxlen,&swap->myfee,0x40);
                else
                {
                    printf("error creating myfee\n");
                    break;
                }
            }
        }
        else if ( (swap->statebits & 0x80) == 0 ) // wait for fee
        {
            if ( basilisk_swapget(myinfo,swap,0x80,data,maxlen,basilisk_verify_otherfee) == 0 )
            {
                // verify and submit otherfee
                swap->statebits |= 0x80;
                swap->sleeptime = 1;
            }
            else if ( swap->sleeptime < 60 )
                swap->sleeptime++;
        }
        else // both sides have setup required data and paid txfee
        {
            //if ( swap->sleeptime < 60 )
            //    swap->sleeptime++;
            if ( swap->iambob != 0 )
            {
                if ( (swap->statebits & 0x100) == 0 )
                {
                    swap->statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x200,data,maxlen,&swap->bobdeposit,0x100);
                    basilisk_bobdeposit_refund(myinfo,swap);
                    swap->sleeptime = 1;
                }
                // [BLOCKING: altfound] make sure altpayment is confirmed and send payment
                else if ( (swap->statebits & 0x1000) == 0 )
                {
                    if ( basilisk_swapget(myinfo,swap,0x1000,data,maxlen,basilisk_verify_alicepaid) == 0 )
                    {
                        swap->statebits |= 0x1000;
                        swap->sleeptime = 1;
                    }
                }
                else if ( (swap->statebits & 0x2000) == 0 )
                {
                    if ( basilisk_numconfirms(myinfo,&swap->alicepayment) >= swap->aliceconfirms )
                    {
                        swap->statebits |= 0x2000;
                        swap->sleeptime = 1;
                    }
                }
                else if ( (swap->statebits & 0x4000) == 0 )
                {
                    swap->statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x8000,data,maxlen,&swap->bobpayment,0x4000);
                    basilisk_bobpayment_reclaim(myinfo,swap);
                    swap->sleeptime = 1;
                }
                 // [BLOCKING: privM] Bob waits for privAm either from Alice or alice blockchain
                else if ( (swap->statebits & 0x40000) == 0 )
                {
                    if ( basilisk_swapget(myinfo,swap,0x40000,data,maxlen,basilisk_verify_privi) == 0 ) // divulges privAm
                    {
                        swap->sleeptime = 1;
                        swap->statebits |= 0x40000;
                        basilisk_alicepayment_spend(myinfo,swap,&swap->bobspend);
                        if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->bobspend,0x40000) == 0 )
                            printf("Bob error spending alice payment\n");
                        else
                        {
                            basilisk_swap_balancingtrade(myinfo,swap,1);
                            printf("Bob spends alicepayment\n");
                        }
                        break;
                    }
                    else if ( basilisk_privAm_extract(myinfo,swap) == 0 )
                    {
                        swap->sleeptime = 1;
                        swap->statebits |= 0x40000;
                        if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->bobspend,0x40000) == 0 )
                            printf("Bob error spending alice payment after privAm\n");
                        else
                        {
                            basilisk_swap_balancingtrade(myinfo,swap,1);
                            printf("Bob spends alicepayment\n");
                        }
                        break;
                    }
                    else if ( swap->bobpayment.locktime != 0 && time(NULL) > swap->bobpayment.locktime )
                    {
                        // submit reclaim of payment
                        swap->sleeptime = 1;
                        swap->statebits |= (0x40000 | 0x80000);
                        if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->bobreclaim,0) == 0 )
                            printf("Bob error reclaiming own payment after alice timed out\n");
                        else printf("Bob reclaimed own payment\n");
                        break;
                    }
                }
                else if ( (swap->statebits & 0x80000) == 0 )
                {
                    if ( basilisk_numconfirms(myinfo,&swap->bobspend) >= swap->aliceconfirms )
                    {
                        swap->sleeptime = 1;
                        swap->statebits |= 0x80000 | 0x100000;
                        printf("Bob confirms spend of Alice's payment\n");
                        break;
                    }
                }
                else if ( (swap->statebits & 0x100000) == 0 )
                {
                    if ( basilisk_numconfirms(myinfo,&swap->bobreclaim) >= 1 )
                    {
                        swap->sleeptime = 1;
                        swap->statebits |= 0x100000;
                        printf("Bob confirms reclain of payment\n");
                        break;
                    }
                }
            }
            else
            {
                // [BLOCKING: depfound] Alice waits for deposit to confirm and sends altpayment
                if ( swap->bobdeposit.locktime != 0 && time(NULL) > swap->bobdeposit.locktime )
                {
                    if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->aliceclaim,0) == 0 )
                        printf("Alice couldnt claim deposit\n");
                    else printf("Alice claimed deposit\n");
                    break;
                }
                else if ( basilisk_privBn_extract(myinfo,swap,data,maxlen) == 0 )
                {
                    swap->sleeptime = 1;
                    swap->statebits |= 0x80000000;
                    if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->alicereclaim,0x80000000) == 0 )
                        printf("Alice error sending alicereclaim\n");
                    else printf("Alice reclaimed her payment\n");
                    break;
                }
                else if ( (swap->statebits & 0x200) == 0 )
                {
                    swap->sleeptime = 1;
                    if ( basilisk_swapget(myinfo,swap,0x200,data,maxlen,basilisk_verify_bobdeposit) == 0 )
                    {
                        // verify deposit and submit, set confirmed height
                        swap->statebits |= 0x200;
                    }
                }
                else if ( (swap->statebits & 0x400) == 0 )
                {
                    if ( basilisk_numconfirms(myinfo,&swap->bobdeposit) >= swap->bobconfirms )
                    {
                        swap->statebits |= 0x400;
                        swap->sleeptime = 1;
                    }
                }
                else if ( (swap->statebits & 0x800) == 0 )
                {
                    swap->sleeptime = 1;
                    swap->statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x1000,data,maxlen,&swap->alicepayment,0x800);
                }
                // [BLOCKING: payfound] make sure payment is confrmed and send in spend or see bob's reclaim and claim
                else if ( (swap->statebits & 0x8000) == 0 )
                {
                    if ( basilisk_swapget(myinfo,swap,0x8000,data,maxlen,basilisk_verify_bobpaid) == 0 )
                    {
                        // verify payment and submit, set confirmed height
                        swap->sleeptime = 1;
                        swap->statebits |= 0x8000;
                    }
                }
                else if ( (swap->statebits & 0x10000) == 0 )
                {
                    if ( basilisk_numconfirms(myinfo,&swap->bobpayment) >= swap->bobconfirms )
                    {
                        swap->statebits |= 0x10000;
                        swap->sleeptime = 1;
                    }
                }
                else if ( (swap->statebits & 0x20000) == 0 )
                {
                   if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->alicespend,0x20000) != 0 )
                    {
                        for (j=datalen=0; j<32; j++)
                            data[datalen++] = swap->privAm.bytes[j];
                        swap->statebits |= basilisk_swapsend(myinfo,swap,0x40000,data,datalen,0x20000);
                        swap->sleeptime = 1;
                        basilisk_swap_balancingtrade(myinfo,swap,0);
                    }
                }
                else if ( (swap->statebits & 0x40000) == 0 )
                {
                    if ( basilisk_numconfirms(myinfo,&swap->alicespend) >= swap->bobconfirms )
                    {
                        swap->sleeptime = 1;
                        swap->statebits |= 0x40000;
                        printf("Alice confirms spend of Bob's payment\n");
                        break;
                    }
                }
            }
        }
        printf("finished swapstate.%x\n",swap->statebits);
        sleep(10);
    }
    if ( swap->iambob != 0 )
    {
        for (j=datalen=0; j<32; j++)
            data[datalen++] = swap->privBn.bytes[j];
        basilisk_swapsend(myinfo,swap,0x80000000,data,datalen,0x80000000);
        printf("BOB reclaims refund\n");
        if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->bobrefund,0x80000000) == 0 ) // use secretBn
        {
            printf("Bob submit error getting refund of deposit\n");
        }
    }
    printf("%s swap finished statebits %x\n",swap->iambob!=0?"BOB":"ALICE",swap->statebits);
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
            fprintf(stderr,"launch.%d %d\n",myinfo->numswaps,(int32_t)(sizeof(myinfo->swaps)/sizeof(*myinfo->swaps)));
            if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)basilisk_swaploop,(void *)swap) != 0 )
            {
                
            }
            myinfo->swaps[myinfo->numswaps++] = swap;
        }
    }
    portable_mutex_unlock(&myinfo->DEX_swapmutex);
    return(swap);
}
