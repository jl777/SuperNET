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

/*use external privkey to sign
make sure to broadcast deposit before claiming refund, or to just skip it if neither is done
*/

#define DEX_SLEEP 1

// Todo: monitor blockchains, ie complete extracting scriptsig
// mode to autocreate required outputs
// more better LP commands

// depends on just three external functions:
//     - basilisk_sendrawtransaction(myinfo,coin,signedtx);
//     - basilisk_value(myinfo,rawtx->coin,0,0,myinfo->myaddr.persistent,argjson,0)
//      basilisk_bitcoinrawtx(myinfo,rawtx->coin,"",basilisktag,jint(valsobj,"timeout"),valsobj,V)


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

void revcalc_rmd160_sha256(uint8_t rmd160[20],bits256 revhash)
{
    bits256 hash; int32_t i;
    for (i=0; i<32; i++)
        hash.bytes[i] = revhash.bytes[31-i];
    calc_rmd160_sha256(rmd160,hash.bytes,sizeof(hash));
}

bits256 revcalc_sha256(bits256 revhash)
{
    bits256 hash,dest; int32_t i;
    for (i=0; i<32; i++)
        hash.bytes[i] = revhash.bytes[31-i];
    vcalc_sha256(0,dest.bytes,hash.bytes,sizeof(hash));
    return(dest);
}

#define SCRIPT_OP_IF 0x63
#define SCRIPT_OP_ELSE 0x67
#define SCRIPT_OP_ENDIF 0x68

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

int32_t basilisk_bobscript(uint8_t *rmd160,uint8_t *redeemscript,int32_t *redeemlenp,uint8_t *script,int32_t n,uint32_t *locktimep,int32_t *secretstartp,struct basilisk_swapinfo *swap,int32_t depositflag)
{
    uint8_t pubkeyA[33],pubkeyB[33],*secret160,*secret256; bits256 privkey,cltvpub,destpub; int32_t i;
    if ( depositflag != 0 )
    {
        *locktimep = swap->started + swap->putduration + swap->callduration;
        pubkeyA[0] = 0x02, cltvpub = swap->pubA0;
        pubkeyB[0] = 0x03, destpub = swap->pubB0;
        privkey = swap->privBn;
        secret160 = swap->secretBn;
        secret256 = swap->secretBn256;
    }
    else
    {
        *locktimep = swap->started + swap->putduration;
        pubkeyA[0] = 0x03, cltvpub = swap->pubB1;
        pubkeyB[0] = 0x02, destpub = swap->pubA0;
        privkey = swap->privAm;
        secret160 = swap->secretAm;
        secret256 = swap->secretAm256;
    }
    //for (i=0; i<32; i++)
    //    printf("%02x",secret256[i]);
    //printf(" <- secret256 depositflag.%d\n",depositflag);
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
#ifdef DISABLE_CHECKSIG
    n = bitcoin_secret256spend(redeemscript,n,cltvpub);
#else
    n = bitcoin_pubkeyspend(redeemscript,n,pubkeyA);
#endif
    redeemscript[n++] = SCRIPT_OP_ELSE;
    if ( secretstartp != 0 )
        *secretstartp = n + 2;
    if ( 1 )
    {
        if ( 1 && bits256_nonz(privkey) != 0 )
        {
            uint8_t bufA[20],bufB[20];
            revcalc_rmd160_sha256(bufA,privkey);
            calc_rmd160_sha256(bufB,privkey.bytes,sizeof(privkey));
            /*if ( memcmp(bufA,secret160,sizeof(bufA)) == 0 )
                printf("MATCHES BUFA\n");
            else if ( memcmp(bufB,secret160,sizeof(bufB)) == 0 )
                printf("MATCHES BUFB\n");
            else printf("secret160 matches neither\n");
            for (i=0; i<20; i++)
                printf("%02x",bufA[i]);
            printf(" <- revcalc\n");
            for (i=0; i<20; i++)
                printf("%02x",bufB[i]);
            printf(" <- calc\n");*/
            memcpy(secret160,bufB,20);
        }
        n = bitcoin_secret160verify(redeemscript,n,secret160);
    }
    else
    {
        redeemscript[n++] = 0xa8;//IGUANA_OP_SHA256;
        redeemscript[n++] = 0x20;
        memcpy(&redeemscript[n],secret256,0x20), n += 0x20;
        redeemscript[n++] = 0x88; //SCRIPT_OP_EQUALVERIFY;
    }
#ifdef DISABLE_CHECKSIG
    n = bitcoin_secret256spend(redeemscript,n,destpub);
#else
    n = bitcoin_pubkeyspend(redeemscript,n,pubkeyB);
#endif
    redeemscript[n++] = SCRIPT_OP_ENDIF;
    *redeemlenp = n;
    calc_rmd160_sha256(rmd160,redeemscript,n);
    n = bitcoin_p2shspend(script,0,rmd160);
    //for (i=0; i<n; i++)
    //    printf("%02x",script[i]);
    //char str[65]; printf(" <- redeem.%d bobtx dflag.%d %s\n",n,depositflag,bits256_str(str,cltvpub));
    return(n);
}

int32_t basilisk_alicescript(uint8_t *redeemscript,int32_t *redeemlenp,uint8_t *script,int32_t n,char *msigaddr,uint8_t altps2h,bits256 pubAm,bits256 pubBn)
{
    uint8_t p2sh160[20]; struct vin_info V;
    memset(&V,0,sizeof(V));
    memcpy(&V.signers[0].pubkey[1],pubAm.bytes,sizeof(pubAm)), V.signers[0].pubkey[0] = 0x02;
    memcpy(&V.signers[1].pubkey[1],pubBn.bytes,sizeof(pubBn)), V.signers[1].pubkey[0] = 0x03;
    V.M = V.N = 2;
    *redeemlenp = bitcoin_MofNspendscript(p2sh160,redeemscript,n,&V);
    bitcoin_address(msigaddr,altps2h,p2sh160,sizeof(p2sh160));
    n = bitcoin_p2shspend(script,0,p2sh160);
    //for (i=0; i<*redeemlenp; i++)
    //    printf("%02x",redeemscript[i]);
    //printf(" <- redeemscript alicetx\n");
    return(n);
}

int32_t basilisk_confirmsobj(cJSON *item)
{
    int32_t height,numconfirms;
    height = jint(item,"height");
    numconfirms = jint(item,"numconfirms");
    if ( height > 0 && numconfirms >= 0 )
        return(numconfirms);
    return(-1);
}

int32_t basilisk_numconfirms(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *rawtx)
{
    cJSON *argjson,*valuearray=0; char *valstr; int32_t i,n,retval = -1;
#ifdef BASILISK_DISABLEWAITTX
    return(10);
#endif
    argjson = cJSON_CreateObject();
    jaddbits256(argjson,"txid",rawtx->I.actualtxid);
    jaddnum(argjson,"vout",0);
    jaddstr(argjson,"coin",rawtx->coin->symbol);
    if ( (valstr= basilisk_value(myinfo,rawtx->coin,0,0,swap->persistent_pubkey,argjson,0)) != 0 )
    {
        //char str[65]; printf("%s %s valstr.(%s)\n",rawtx->name,bits256_str(str,rawtx->I.actualtxid),valstr);
        if ( (valuearray= cJSON_Parse(valstr)) != 0 )
        {
            if ( is_cJSON_Array(valuearray) != 0 )
            {
                n = cJSON_GetArraySize(valuearray);
                for (i=0; i<n; i++)
                {
                    if ( (retval= basilisk_confirmsobj(jitem(valuearray,i))) >= 0 )
                        break;
               }
            } else retval = basilisk_confirmsobj(valuearray);
            free_json(valuearray);
        } else printf("parse error\n");
        free(valstr);
    }
    free_json(argjson);
    return(retval);
}

bits256 basilisk_swap_broadcast(char *name,struct supernet_info *myinfo,struct basilisk_swap *swap,struct iguana_info *coin,uint8_t *data,int32_t datalen)
{
    bits256 txid; char *signedtx,*retstr;
    memset(txid.bytes,0,sizeof(txid));
    if ( data != 0 && datalen != 0 )
    {
        char str[65];
#ifdef BASILISK_DISABLESENDTX
        txid = bits256_doublesha256(0,data,datalen);
        printf("%s <- dont sendrawtransaction (%s)\n",name,bits256_str(str,txid));
        return(txid);
#endif
        signedtx = malloc(datalen*2 + 1);
        init_hexbytes_noT(signedtx,data,datalen);
        if ( (retstr= basilisk_sendrawtransaction(myinfo,coin,signedtx)) != 0 )
        {
            if ( is_hexstr(retstr,0) == 64 )
            {
                decode_hex(txid.bytes,32,retstr);
                free(retstr);
                printf("sendrawtransaction %s.(%s)\n",name,bits256_str(str,txid));
            }
            else
            {
                printf("sendrawtransaction %s error.(%s)\n",name,retstr);
                free(retstr);
            }
        } else printf("sendrawtransaction %s got null return\n",name);
        free(signedtx);
    }
    return(txid);
}

int32_t basilisk_rawtx_sign(struct supernet_info *myinfo,int32_t height,struct basilisk_swap *swap,struct basilisk_rawtx *dest,struct basilisk_rawtx *rawtx,bits256 privkey,bits256 *privkey2,uint8_t *userdata,int32_t userdatalen,int32_t ignore_cltverr)
{
    char *rawtxbytes=0,*signedtx=0,hexstr[999],wifstr[128]; cJSON *txobj,*vins,*item,*sobj,*privkeys; int32_t needsig=1,retval = -1; uint32_t timestamp,sequenceid=0xffffffff; struct vin_info *V; uint32_t locktime=0;
    V = calloc(16,sizeof(*V));
    timestamp = swap->I.started;
    if ( dest == &swap->aliceclaim )
        locktime = swap->bobdeposit.I.locktime + 1, sequenceid = 0;
    else if ( dest == &swap->bobreclaim )
        locktime = swap->bobpayment.I.locktime + 1, sequenceid = 0;
    V[0].signers[0].privkey = privkey;
    bitcoin_pubkey33(myinfo->ctx,V[0].signers[0].pubkey,privkey);
    privkeys = cJSON_CreateArray();
    bitcoin_priv2wif(wifstr,privkey,rawtx->coin->chain->wiftype);
    jaddistr(privkeys,wifstr);
    if ( privkey2 != 0 )
    {
        V[0].signers[1].privkey = *privkey2;
        bitcoin_pubkey33(myinfo->ctx,V[0].signers[1].pubkey,*privkey2);
        bitcoin_priv2wif(wifstr,*privkey2,rawtx->coin->chain->wiftype);
        jaddistr(privkeys,wifstr);
        V[0].N = V[0].M = 2;
        //char str[65]; printf("add second privkey.(%s) %s\n",jprint(privkeys,0),bits256_str(str,*privkey2));
    } else V[0].N = V[0].M = 1;
    V[0].suppress_pubkeys = dest->I.suppress_pubkeys;
    V[0].ignore_cltverr = ignore_cltverr;
    if ( dest->I.redeemlen != 0 )
        memcpy(V[0].p2shscript,dest->redeemscript,dest->I.redeemlen), V[0].p2shlen = dest->I.redeemlen;
    txobj = bitcoin_txcreate(rawtx->coin->symbol,rawtx->coin->chain->isPoS,locktime,userdata == 0 ? 1 : 1,timestamp);//rawtx->coin->chain->locktime_txversion);
    vins = cJSON_CreateArray();
    item = cJSON_CreateObject();
    if ( userdata != 0 && userdatalen > 0 )
    {
        memcpy(V[0].userdata,userdata,userdatalen);
        V[0].userdatalen = userdatalen;
        init_hexbytes_noT(hexstr,userdata,userdatalen);
        jaddstr(item,"userdata",hexstr);
#ifdef DISABLE_CHECKSIG
        needsig = 0;
#endif
    }
    if ( bits256_nonz(rawtx->I.actualtxid) != 0 )
        jaddbits256(item,"txid",rawtx->I.actualtxid);
    else jaddbits256(item,"txid",rawtx->I.signedtxid);
    jaddnum(item,"vout",0);
    sobj = cJSON_CreateObject();
    init_hexbytes_noT(hexstr,rawtx->spendscript,rawtx->I.spendlen);
    jaddstr(sobj,"hex",hexstr);
    jadd(item,"scriptPubKey",sobj);
    jaddnum(item,"suppress",dest->I.suppress_pubkeys);
    jaddnum(item,"sequence",sequenceid);
    if ( (dest->I.redeemlen= rawtx->I.redeemlen) != 0 )
    {
        init_hexbytes_noT(hexstr,rawtx->redeemscript,rawtx->I.redeemlen);
        memcpy(dest->redeemscript,rawtx->redeemscript,rawtx->I.redeemlen);
        jaddstr(item,"redeemScript",hexstr);
    }
    jaddi(vins,item);
    jdelete(txobj,"vin");
    jadd(txobj,"vin",vins);
    //printf("basilisk_rawtx_sign locktime.%u/%u for %s spendscript.%s -> %s, suppress.%d\n",rawtx->locktime,dest->locktime,rawtx->name,hexstr,dest->name,dest->suppress_pubkeys);
    txobj = bitcoin_txoutput(txobj,dest->spendscript,dest->I.spendlen,dest->I.amount);
    if ( (rawtxbytes= bitcoin_json2hex(myinfo,rawtx->coin,&dest->I.txid,txobj,V)) != 0 )
    {
        if ( needsig == 0 )
            signedtx = rawtxbytes;
        if ( signedtx != 0 || (signedtx= iguana_signrawtx(myinfo,rawtx->coin,height,&dest->I.signedtxid,&dest->I.completed,vins,rawtxbytes,privkeys,V)) != 0 )
        {
            dest->I.datalen = (int32_t)strlen(signedtx) >> 1;
            dest->txbytes = calloc(1,dest->I.datalen);
            decode_hex(dest->txbytes,dest->I.datalen,signedtx);
            if ( signedtx != rawtxbytes )
                free(signedtx);
            if ( dest->I.completed != 0 )
                retval = 0;
            else printf("couldnt sign transaction %s\n",rawtx->name);
        } else printf("error signing\n");
        free(rawtxbytes);
    } else printf("error making rawtx\n");
    free_json(privkeys);
    free_json(txobj);
    return(retval);
}

struct basilisk_rawtx *basilisk_swapdata_rawtx(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx)
{
    if ( rawtx->txbytes != 0 && rawtx->I.datalen <= maxlen )
    {
        memcpy(data,rawtx->txbytes,rawtx->I.datalen);
        return(rawtx);
    }
    return(0);
}

int32_t basilisk_verify_otherfee(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    struct basilisk_swap *swap = ptr;
    // add verification and broadcast
    swap->otherfee.txbytes = calloc(1,datalen);
    memcpy(swap->otherfee.txbytes,data,datalen);
    swap->otherfee.I.actualtxid = swap->otherfee.I.signedtxid = bits256_doublesha256(0,data,datalen);
    basilisk_txlog(myinfo,swap,&swap->otherfee,-1);
    return(0);
}

int32_t basilisk_rawtx_spendscript(struct basilisk_swap *swap,int32_t height,struct basilisk_rawtx *rawtx,int32_t v,uint8_t *recvbuf,int32_t recvlen,int32_t suppress_pubkeys)
{
    int32_t datalen=0,retval=-1,hexlen,n; uint8_t *data; cJSON *txobj,*skey,*vouts,*vout; char *hexstr;
    datalen = recvbuf[0];
    datalen += (int32_t)recvbuf[1] << 8;
    if ( datalen > 65536 )
        return(-1);
    rawtx->I.redeemlen = recvbuf[2];
    data = &recvbuf[3];
    if ( rawtx->I.redeemlen > 0 && rawtx->I.redeemlen < 0x100 )
        memcpy(rawtx->redeemscript,&data[datalen],rawtx->I.redeemlen);
    //printf("recvlen.%d datalen.%d redeemlen.%d\n",recvlen,datalen,rawtx->redeemlen);
    if ( rawtx->txbytes == 0 )
    {
        rawtx->txbytes = calloc(1,datalen);
        memcpy(rawtx->txbytes,data,datalen);
        rawtx->I.datalen = datalen;
    }
    else if ( datalen != rawtx->I.datalen || memcmp(rawtx->txbytes,data,datalen) != 0 )
    {
        int32_t i; for (i=0; i<datalen; i++)
            printf("%02x",data[i]);
        printf(" <- received\n");
        for (i=0; i<rawtx->I.datalen; i++)
            printf("%02x",rawtx->txbytes[i]);
        printf(" <- rawtx\n");
        printf("%s rawtx data compare error, len %d vs %d <<<<<<<<<< warning\n",rawtx->name,rawtx->I.datalen,datalen);
        return(-1);
    }
    if ( (txobj= bitcoin_data2json(rawtx->coin,height,&rawtx->I.signedtxid,&rawtx->msgtx,rawtx->extraspace,sizeof(rawtx->extraspace),data,datalen,0,suppress_pubkeys)) != 0 )
    {
        rawtx->I.actualtxid = rawtx->I.signedtxid;
        //char str[65]; printf("got txid.%s (%s)\n",bits256_str(str,rawtx->signedtxid),jprint(txobj,0));
        rawtx->I.locktime = rawtx->msgtx.lock_time;
        if ( (vouts= jarray(&n,txobj,"vout")) != 0 && v < n )
        {
            vout = jitem(vouts,v);
            if ( j64bits(vout,"satoshis") == rawtx->I.amount && (skey= jobj(vout,"scriptPubKey")) != 0 && (hexstr= jstr(skey,"hex")) != 0 )
            {
                if ( (hexlen= (int32_t)strlen(hexstr) >> 1) < sizeof(rawtx->spendscript) )
                {
                    decode_hex(rawtx->spendscript,hexlen,hexstr);
                    rawtx->I.spendlen = hexlen;
                    basilisk_txlog(swap->myinfoptr,swap,rawtx,-1); // bobdeposit, bobpayment or alicepayment
                    retval = 0;
                }
            } else printf("%s ERROR.(%s)\n",rawtx->name,jprint(txobj,0));
        }
        free_json(txobj);
    }
    return(retval);
}

int32_t basilisk_swapuserdata(struct basilisk_swap *swap,uint8_t *userdata,bits256 privkey,int32_t ifpath,bits256 signpriv,uint8_t *redeemscript,int32_t redeemlen)
{
    int32_t i,len = 0;
#ifdef DISABLE_CHECKSIG
    userdata[len++] = sizeof(signpriv);
    for (i=0; i<sizeof(privkey); i++)
        userdata[len++] = signpriv.bytes[i];
#endif
    if ( bits256_nonz(privkey) != 0 )
    {
        userdata[len++] = sizeof(privkey);
        for (i=0; i<sizeof(privkey); i++)
            userdata[len++] = privkey.bytes[i];
    }
    userdata[len++] = 0x51 * ifpath; // ifpath == 1 -> if path, 0 -> else path
    return(len);
}

/*    Bob deposit:
 OP_IF
 <now + INSTANTDEX_LOCKTIME*2> OP_CLTV OP_DROP <alice_pubA0> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <bob_pubB0> OP_CHECKSIG
 OP_ENDIF*/

int32_t basilisk_verify_bobdeposit(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    uint8_t userdata[512]; int32_t i,retval,len = 0; static bits256 zero; struct basilisk_swap *swap = ptr;
    if ( basilisk_rawtx_spendscript(swap,swap->bobcoin->blocks.hwmchain.height,&swap->bobdeposit,0,data,datalen,0) == 0 )
    {
        len = basilisk_swapuserdata(swap,userdata,zero,1,swap->I.myprivs[0],swap->bobdeposit.redeemscript,swap->bobdeposit.I.redeemlen);
        if ( (retval= basilisk_rawtx_sign(myinfo,swap->bobcoin->blocks.hwmchain.height,swap,&swap->aliceclaim,&swap->bobdeposit,swap->I.myprivs[0],0,userdata,len,1)) == 0 )
        {
            for (i=0; i<swap->bobdeposit.I.datalen; i++)
                printf("%02x",swap->bobdeposit.txbytes[i]);
            printf(" <- bobdeposit\n");
            for (i=0; i<swap->aliceclaim.I.datalen; i++)
                printf("%02x",swap->aliceclaim.txbytes[i]);
            printf(" <- aliceclaim\n");
            basilisk_txlog(myinfo,swap,&swap->aliceclaim,swap->I.putduration+swap->I.callduration);
            return(retval);
        }
    }
    printf("error with bobdeposit\n");
    return(-1);
}

int32_t basilisk_bobdeposit_refund(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t delay)
{
    uint8_t userdata[512]; int32_t i,retval,len = 0; char str[65];
    len = basilisk_swapuserdata(swap,userdata,swap->I.privBn,0,swap->I.myprivs[0],swap->bobdeposit.redeemscript,swap->bobdeposit.I.redeemlen);
    if ( (retval= basilisk_rawtx_sign(myinfo,swap->bobcoin->blocks.hwmchain.height,swap,&swap->bobrefund,&swap->bobdeposit,swap->I.myprivs[0],0,userdata,len,0)) == 0 )
    {
        for (i=0; i<swap->bobrefund.I.datalen; i++)
            printf("%02x",swap->bobrefund.txbytes[i]);
        printf(" <- bobrefund.(%s)\n",bits256_str(str,swap->bobrefund.I.txid));
        basilisk_txlog(myinfo,swap,&swap->bobrefund,delay);
        return(retval);
    }
    return(-1);
}

/*Bob paytx:
 OP_IF
 <now + INSTANTDEX_LOCKTIME> OP_CLTV OP_DROP <bob_pubB1> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
 OP_ENDIF*/

int32_t basilisk_bobpayment_reclaim(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t delay)
{
    uint8_t userdata[512]; int32_t i,retval,len = 0; static bits256 zero;
    printf("basilisk_bobpayment_reclaim\n");
    len = basilisk_swapuserdata(swap,userdata,zero,1,swap->I.myprivs[1],swap->bobpayment.redeemscript,swap->bobpayment.I.redeemlen);
    if ( (retval= basilisk_rawtx_sign(myinfo,swap->bobcoin->blocks.hwmchain.height,swap,&swap->bobreclaim,&swap->bobpayment,swap->I.myprivs[1],0,userdata,len,1)) == 0 )
    {
        for (i=0; i<swap->bobreclaim.I.datalen; i++)
            printf("%02x",swap->bobreclaim.txbytes[i]);
        printf(" <- bobreclaim\n");
        basilisk_txlog(myinfo,swap,&swap->bobreclaim,delay);
        return(retval);
    }
    return(-1);
}

int32_t basilisk_verify_bobpaid(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    uint8_t userdata[512]; int32_t i,retval,len = 0; bits256 revAm; struct basilisk_swap *swap = ptr;
    memset(revAm.bytes,0,sizeof(revAm));
    if ( basilisk_rawtx_spendscript(swap,swap->bobcoin->blocks.hwmchain.height,&swap->bobpayment,0,data,datalen,0) == 0 )
    {
        for (i=0; i<32; i++)
            revAm.bytes[i] = swap->I.privAm.bytes[31-i];
        len = basilisk_swapuserdata(swap,userdata,revAm,0,swap->I.myprivs[0],swap->bobpayment.redeemscript,swap->bobpayment.I.redeemlen);
        char str[65]; printf("bobpaid.(%s)\n",bits256_str(str,swap->I.privAm));
        if ( (retval= basilisk_rawtx_sign(myinfo,swap->bobcoin->blocks.hwmchain.height,swap,&swap->alicespend,&swap->bobpayment,swap->I.myprivs[0],0,userdata,len,1)) == 0 )
        {
            for (i=0; i<swap->bobpayment.I.datalen; i++)
                printf("%02x",swap->bobpayment.txbytes[i]);
            printf(" <- bobpayment\n");
            for (i=0; i<swap->alicespend.I.datalen; i++)
                printf("%02x",swap->alicespend.txbytes[i]);
            printf(" <- alicespend\n\n");
            swap->I.alicespent = 1;
            basilisk_txlog(myinfo,swap,&swap->alicespend,-1);
            return(retval);
        }
    }
    return(-1);
}

int32_t basilisk_alicepayment_spend(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *dest)
{
    int32_t i,retval;
    //printf("alicepayment_spend\n");
    swap->alicepayment.I.spendlen = basilisk_alicescript(swap->alicepayment.redeemscript,&swap->alicepayment.I.redeemlen,swap->alicepayment.spendscript,0,swap->alicepayment.I.destaddr,swap->alicecoin->chain->p2shtype,swap->I.pubAm,swap->I.pubBn);
    if ( (retval= basilisk_rawtx_sign(myinfo,swap->alicecoin->blocks.hwmchain.height,swap,dest,&swap->alicepayment,swap->I.privAm,&swap->I.privBn,0,0,1)) == 0 )
    {
        for (i=0; i<dest->I.datalen; i++)
            printf("%02x",dest->txbytes[i]);
        printf(" <- msigspend\n\n");
        swap->I.bobspent = 1;
        basilisk_txlog(myinfo,swap,dest,0); // bobspend or alicereclaim
        return(retval);
    }
    return(-1);
}

int32_t basilisk_verify_alicepaid(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    struct basilisk_swap *swap = ptr;
    if ( basilisk_rawtx_spendscript(swap,swap->alicecoin->blocks.hwmchain.height,&swap->alicepayment,0,data,datalen,0) == 0 )
        return(0);
    else return(-1);
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

cJSON *basilisk_privkeyarray(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *vins)
{
    cJSON *privkeyarray,*item,*sobj; struct iguana_waddress *waddr; struct iguana_waccount *wacct; char coinaddr[64],account[128],wifstr[64],str[65],*hexstr; uint8_t script[1024]; int32_t i,n,len,vout; bits256 txid,privkey;
    privkeyarray = cJSON_CreateArray();
    //printf("%s persistent.(%s) (%s) change.(%s) scriptstr.(%s)\n",coin->symbol,myinfo->myaddr.BTC,coinaddr,coin->changeaddr,scriptstr);
    if ( (n= cJSON_GetArraySize(vins)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(vins,i);
            txid = jbits256(item,"txid");
            vout = jint(item,"vout");
            if ( bits256_nonz(txid) != 0 && vout >= 0 )
            {
                iguana_txidcategory(myinfo,coin,account,coinaddr,txid,vout);
                if ( coinaddr[0] == 0 && (sobj= jobj(item,"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 && is_hexstr(hexstr,0) > 0 )
                {
                    len = (int32_t)strlen(hexstr) >> 1;
                    if ( len < (sizeof(script) << 1) )
                    {
                        decode_hex(script,len,hexstr);
                        if ( len == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 )
                            bitcoin_address(coinaddr,coin->chain->pubtype,script+3,20);
                    }
                }
                if ( coinaddr[0] != 0 )
                {
                    if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 )
                    {
                        bitcoin_priv2wif(wifstr,waddr->privkey,coin->chain->wiftype);
                        jaddistr(privkeyarray,waddr->wifstr);
                    }
                    else if ( smartaddress(myinfo,&privkey,coinaddr) >= 0 )
                    {
                        bitcoin_priv2wif(wifstr,privkey,coin->chain->wiftype);
                        jaddistr(privkeyarray,wifstr);
                    }
                    else printf("cant find (%s) in wallet\n",coinaddr);
                } else printf("cant coinaddr from (%s).v%d\n",bits256_str(str,txid),vout);
            } else printf("invalid txid/vout %d of %d\n",i,n);
        }
    }
    return(privkeyarray);
}

int32_t basilisk_rawtx_return(struct supernet_info *myinfo,int32_t height,struct basilisk_rawtx *rawtx,cJSON *item,int32_t lockinputs,struct vin_info *V)
{
    char *signedtx,*txbytes; cJSON *vins,*privkeyarray; int32_t i,n,retval = -1;
    if ( (txbytes= jstr(item,"rawtx")) != 0 && (vins= jobj(item,"vins")) != 0 )
    {
        privkeyarray = basilisk_privkeyarray(myinfo,rawtx->coin,vins);
        if ( (signedtx= iguana_signrawtx(myinfo,rawtx->coin,height,&rawtx->I.signedtxid,&rawtx->I.completed,vins,txbytes,privkeyarray,V)) != 0 )
        {
            if ( lockinputs != 0 )
            {
                //printf("lockinputs\n");
                iguana_RTunspentslock(myinfo,rawtx->coin,vins);
                if ( (n= cJSON_GetArraySize(vins)) != 0 )
                {
                    bits256 txid; int32_t vout;
                    for (i=0; i<n; i++)
                    {
                        item = jitem(vins,i);
                        txid = jbits256(item,"txid");
                        vout = jint(item,"vout");
                    }
                }
            }
            rawtx->I.datalen = (int32_t)strlen(signedtx) >> 1;
            rawtx->txbytes = calloc(1,rawtx->I.datalen);
            decode_hex(rawtx->txbytes,rawtx->I.datalen,signedtx);
            printf("%s SIGNEDTX.(%s)\n",rawtx->name,signedtx);
            free(signedtx);
            retval = 0;
        } else printf("error signrawtx\n"); //do a very short timeout so it finishes via local poll
        free_json(privkeyarray);
    }
    return(retval);
}

int32_t basilisk_rawtx_gen(char *str,struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t iambob,int32_t lockinputs,struct basilisk_rawtx *rawtx,uint32_t locktime,uint8_t *script,int32_t scriptlen,int64_t txfee,int32_t minconf,int32_t delay)
{
    char *retstr,scriptstr[1024],coinaddr[64]; uint32_t basilisktag; int32_t flag,i,n,retval = -1; cJSON *addresses,*valsobj,*retarray=0; struct vin_info *V;
    //bitcoin_address(coinaddr,rawtx->coin->chain->pubtype,myinfo->persistent_pubkey33,33);
    if ( rawtx->coin->changeaddr[0] == 0 )
    {
        bitcoin_address(rawtx->coin->changeaddr,rawtx->coin->chain->pubtype,swap->persistent_pubkey33,33);
        printf("set change address.(%s)\n",rawtx->coin->changeaddr);
    }
    init_hexbytes_noT(scriptstr,script,scriptlen);
    basilisktag = (uint32_t)rand();
    valsobj = cJSON_CreateObject();
    jaddstr(valsobj,"coin",rawtx->coin->symbol);
    jaddstr(valsobj,"spendscript",scriptstr);
    jaddstr(valsobj,"changeaddr",rawtx->coin->changeaddr);
    jadd64bits(valsobj,"satoshis",rawtx->I.amount);
    jadd64bits(valsobj,"txfee",txfee);
    jaddnum(valsobj,"minconf",minconf);
    jaddnum(valsobj,"locktime",locktime);
    jaddnum(valsobj,"timeout",30000);
    jaddnum(valsobj,"timestamp",swap->I.started+delay);
    addresses = cJSON_CreateArray();
    bitcoin_address(coinaddr,rawtx->coin->chain->pubtype,swap->persistent_pubkey33,33);
    jaddistr(addresses,coinaddr);
    jadd(valsobj,"addresses",addresses);
    rawtx->I.locktime = locktime;
    //printf("%s locktime.%u\n",rawtx->name,locktime);
    V = calloc(256,sizeof(*V));
    if ( (retstr= basilisk_bitcoinrawtx(myinfo,rawtx->coin,"",basilisktag,jint(valsobj,"timeout"),valsobj,V)) != 0 )
    {
        //printf("%s %s basilisk_bitcoinrawtx.(%s)\n",rawtx->name,str,retstr);
        flag = 0;
        if ( (retarray= cJSON_Parse(retstr)) != 0 )
        {
            if ( is_cJSON_Array(retarray) != 0 )
            {
                n = cJSON_GetArraySize(retarray);
                for (i=0; i<n; i++)
                {
                    if ( (retval= basilisk_rawtx_return(myinfo,rawtx->coin->blocks.hwmchain.height,rawtx,jitem(retarray,i),lockinputs,V)) == 0 )
                    {
                        rawtx->vins = jobj(jitem(retarray,i),"vins");
                        break;
                    }
                }
            }
            else
            {
                retval = basilisk_rawtx_return(myinfo,rawtx->coin->blocks.hwmchain.height,rawtx,retarray,lockinputs,V);
                rawtx->vins = jobj(retarray,"vins");
            }
            free(retarray);
        } else printf("error parsing.(%s)\n",retstr);
        free(retstr);
    } else printf("error creating %s feetx\n",iambob != 0 ? "BOB" : "ALICE");
    free_json(valsobj);
    free(V);
    return(retval);
}

int32_t basilisk_bobscripts_set(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t depositflag,int32_t genflag)
{
    int32_t i,j; //char str[65];
    if ( genflag != 0 && swap->I.iambob == 0 )
        printf("basilisk_bobscripts_set WARNING: alice generating BOB tx\n");
    if ( depositflag == 0 )
    {
        swap->bobpayment.I.spendlen = basilisk_bobscript(swap->bobpayment.I.rmd160,swap->bobpayment.redeemscript,&swap->bobpayment.I.redeemlen,swap->bobpayment.spendscript,0,&swap->bobpayment.I.locktime,&swap->bobpayment.I.secretstart,&swap->I,0);
        //for (i=0; i<swap->bobpayment.redeemlen; i++)
        //    printf("%02x",swap->bobpayment.redeemscript[i]);
        //printf(" <- bobpayment.%d\n",i);
        if ( genflag != 0 && bits256_nonz(*(bits256 *)swap->I.secretBn256) != 0 && swap->bobpayment.txbytes == 0 )
        {
            for (i=0; i<3; i++)
            {
                //if ( swap->bobpayment.txbytes != 0 && swap->bobpayment.I.spendlen != 0 )
                //    break;
                basilisk_rawtx_gen("payment",myinfo,swap,1,1,&swap->bobpayment,swap->bobpayment.I.locktime,swap->bobpayment.spendscript,swap->bobpayment.I.spendlen,swap->bobpayment.coin->chain->txfee,1,0);
                if ( swap->bobpayment.txbytes == 0 || swap->bobpayment.I.spendlen == 0 )
                {
                    printf("error bob generating %p payment.%d\n",swap->bobpayment.txbytes,swap->bobpayment.I.spendlen);
                    sleep(DEX_SLEEP);
                }
                else
                {
                    for (j=0; j<swap->bobpayment.I.datalen; j++)
                        printf("%02x",swap->bobpayment.txbytes[j]);
                    //printf(" <- bobpayment.%d\n",swap->bobpayment.datalen);
                    //for (j=0; j<swap->bobpayment.redeemlen; j++)
                    //    printf("%02x",swap->bobpayment.redeemscript[j]);
                    //printf(" <- redeem.%d\n",swap->bobpayment.redeemlen);
                    printf(" <- GENERATED BOB PAYMENT.%d\n",swap->bobpayment.I.datalen);
                    iguana_unspents_mark(myinfo,swap->bobcoin,swap->bobpayment.vins);
                    basilisk_bobpayment_reclaim(myinfo,swap,swap->I.callduration);
                    printf("bobscripts set completed\n");
                    return(0);
                }
            }
        }
        return(0);
    }
    else
    {
        swap->bobdeposit.I.spendlen = basilisk_bobscript(swap->bobdeposit.I.rmd160,swap->bobdeposit.redeemscript,&swap->bobdeposit.I.redeemlen,swap->bobdeposit.spendscript,0,&swap->bobdeposit.I.locktime,&swap->bobdeposit.I.secretstart,&swap->I,1);
        if ( genflag != 0 && (swap->bobdeposit.txbytes == 0 || swap->bobrefund.txbytes == 0) )
        {
            for (i=0; i<3; i++)
            {
                //if ( swap->bobdeposit.txbytes != 0 && swap->bobdeposit.I.spendlen != 0 )
                //    break;
                basilisk_rawtx_gen("deposit",myinfo,swap,1,1,&swap->bobdeposit,swap->bobdeposit.I.locktime,swap->bobdeposit.spendscript,swap->bobdeposit.I.spendlen,swap->bobdeposit.coin->chain->txfee,1,0);
                if ( swap->bobdeposit.txbytes == 0 || swap->bobdeposit.I.spendlen == 0 )
                {
                    printf("error bob generating %p deposit.%d\n",swap->bobdeposit.txbytes,swap->bobdeposit.I.spendlen);
                    sleep(DEX_SLEEP);
                }
                else
                {
                    for (j=0; j<swap->bobdeposit.I.datalen; j++)
                        printf("%02x",swap->bobdeposit.txbytes[j]);
                    printf(" <- GENERATED BOB DEPOSIT.%d\n",swap->bobdeposit.I.datalen);
                    //for (j=0; j<swap->bobdeposit.redeemlen; j++)
                    //    printf("%02x",swap->bobdeposit.redeemscript[j]);
                    //printf(" <- redeem.%d\n",swap->bobdeposit.redeemlen);
                    //printf("GENERATED BOB DEPOSIT\n");
                    iguana_unspents_mark(myinfo,swap->bobcoin,swap->bobdeposit.vins);
                    basilisk_bobdeposit_refund(myinfo,swap,swap->I.putduration);
                    printf("bobscripts set completed\n");
                    return(0);
                }
            }
        }
        return(0);
        //for (i=0; i<swap->bobdeposit.redeemlen; i++)
        //    printf("%02x",swap->bobdeposit.redeemscript[i]);
        //printf(" <- bobdeposit.%d\n",i);
    }
    return(-1);
}

int32_t basilisk_verify_privi(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t j,wrongfirstbyte,len = 0; bits256 privkey,pubi; char str[65],str2[65]; uint8_t secret160[20],pubkey33[33]; uint64_t txid; struct basilisk_swap *swap = ptr;
    memset(privkey.bytes,0,sizeof(privkey));
    if ( datalen == sizeof(bits256) )
    {
        for (j=0; j<32; j++)
            privkey.bytes[j] = data[len++];
        revcalc_rmd160_sha256(secret160,privkey);//.bytes,sizeof(privkey));
        memcpy(&txid,secret160,sizeof(txid));
        pubi = bitcoin_pubkey33(myinfo->ctx,pubkey33,privkey);
        if ( basilisk_verify_pubpair(&wrongfirstbyte,swap,swap->I.choosei,pubkey33[0],pubi,txid) == 0 )
        {
            if ( swap->I.iambob != 0 )
            {
                swap->I.privAm = privkey;
                vcalc_sha256(0,swap->I.secretAm256,privkey.bytes,sizeof(privkey));
                printf("set privAm.%s %s\n",bits256_str(str,swap->I.privAm),bits256_str(str2,*(bits256 *)swap->I.secretAm256));
                basilisk_bobscripts_set(myinfo,swap,0,1);
            }
            else
            {
                swap->I.privBn = privkey;
                vcalc_sha256(0,swap->I.secretBn256,privkey.bytes,sizeof(privkey));
                printf("set privBn.%s %s\n",bits256_str(str,swap->I.privBn),bits256_str(str2,*(bits256 *)swap->I.secretBn256));
            }
            char str[65]; printf("privi verified.(%s)\n",bits256_str(str,privkey));
            return(0);
        }
    }
    return(-1);
}

int32_t basilisk_process_swapverify(struct supernet_info *myinfo,void *ptr,int32_t (*internal_func)(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen),uint32_t channel,uint32_t msgid,uint8_t *data,int32_t datalen,uint32_t expiration,uint32_t duration)
{
    struct basilisk_swap *swap = ptr;
    if ( internal_func != 0 )
        return((*internal_func)(myinfo,swap,data,datalen));
    else return(0);
}

void basilisk_swapgotdata(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t crc32,bits256 srchash,bits256 desthash,uint32_t quoteid,uint32_t msgbits,uint8_t *data,int32_t datalen)
{
    int32_t i; struct basilisk_swapmessage *mp;
    for (i=0; i<swap->nummessages; i++)
        if ( crc32 == swap->messages[i].crc32 )
            return;
    printf(" new message.[%d] datalen.%d Q.%x msg.%x\n",swap->nummessages,datalen,quoteid,msgbits);
    swap->messages = realloc(swap->messages,sizeof(*swap->messages) * (swap->nummessages + 1));
    mp = &swap->messages[swap->nummessages++];
    mp->crc32 = crc32;
    mp->srchash = srchash;
    mp->desthash = desthash;
    mp->msgbits = msgbits;
    mp->quoteid = quoteid;
    mp->data = malloc(datalen);
    memcpy(mp->data,data,datalen);
    mp->datalen = datalen;
}

int32_t basilisk_swapget(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,int32_t (*basilisk_verify_func)(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen))
{
    uint8_t *ptr; bits256 srchash,desthash; uint32_t crc32,_msgbits,quoteid; int32_t i,size,offset,retval = -1;
    while ( (size= nn_recv(swap->subsock,&ptr,NN_MSG,0)) >= 0 )
    {
        memset(srchash.bytes,0,sizeof(srchash));
        memset(desthash.bytes,0,sizeof(desthash));
        crc32 = calc_crc32(0,ptr,size);
        printf("gotmsg.[%d] crc.%x\n",size,crc32);
        offset = 0;
        for (i=0; i<32; i++)
             srchash.bytes[i] = ptr[offset++];
        for (i=0; i<32; i++)
            desthash.bytes[i] = ptr[offset++];
        offset += iguana_rwnum(0,&ptr[offset],sizeof(uint32_t),&quoteid);
        offset += iguana_rwnum(0,&ptr[offset],sizeof(uint32_t),&_msgbits);
        if ( size > offset )
            basilisk_swapgotdata(myinfo,swap,crc32,srchash,desthash,quoteid,_msgbits,&ptr[offset],size-offset);
        if ( ptr != 0 )
            nn_freemsg(ptr), ptr = 0;
    }
    //char str[65],str2[65];
    for (i=0; i<swap->nummessages; i++)
    {
        //printf("%d: %s vs %s\n",i,bits256_str(str,swap->messages[i].srchash),bits256_str(str2,swap->messages[i].desthash));
        if ( swap->messages[i].msgbits == msgbits && bits256_cmp(swap->messages[i].desthash,swap->I.myhash) == 0 )
        {
            retval = (*basilisk_verify_func)(myinfo,swap,swap->messages[i].data,swap->messages[i].datalen);
            break;
        }
    }
    //printf("mine/other %s vs %s\n",bits256_str(str,swap->I.myhash),bits256_str(str2,swap->I.otherhash));
    return(retval);
}

uint32_t basilisk_swapsend(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t nextbits,uint32_t crcs[2])
{
    uint8_t *buf; int32_t sentbytes,offset=0,i;
    //if ( (rand() % 10) == 0 )
    //    basilisk_channelsend(myinfo,swap->I.myhash,swap->I.otherhash,swap->I.req.quoteid,msgbits,data,datalen,INSTANTDEX_LOCKTIME*2);
    //if ( basilisk_crcsend(myinfo,0,swap->verifybuf,sizeof(swap->verifybuf),swap->I.myhash,swap->I.otherhash,swap->I.req.quoteid,msgbits,data,datalen,crcs) != 0 )
        //return(nextbits);
    //dex_channelsend(myinfo,swap->I.myhash,swap->I.otherhash,swap->I.req.quoteid,msgbits,data,datalen); //INSTANTDEX_LOCKTIME*2
    buf = malloc(datalen + sizeof(msgbits) + sizeof(swap->I.req.quoteid) + sizeof(bits256)*2);
    for (i=0; i<32; i++)
        buf[offset++] = swap->I.myhash.bytes[i];
    for (i=0; i<32; i++)
        buf[offset++] = swap->I.otherhash.bytes[i];
    offset += iguana_rwnum(1,&buf[offset],sizeof(swap->I.req.quoteid),&swap->I.req.quoteid);
    offset += iguana_rwnum(1,&buf[offset],sizeof(msgbits),&msgbits);
    if ( datalen > 0 )
        memcpy(&buf[offset],data,datalen), offset += datalen;
    if ( (sentbytes= nn_send(swap->pushsock,buf,offset,0)) != offset )
        printf("sentbytes.%d vs offset.%d\n",sentbytes,offset);
    else printf("send.[%d] %x\n",sentbytes,msgbits);
    free(buf);
    return(0);
}

int32_t basilisk_priviextract(struct supernet_info *myinfo,struct iguana_info *coin,char *name,bits256 *destp,uint8_t secret160[20],bits256 srctxid,int32_t srcvout)
{
    bits256 txid,privkey; char str[65]; int32_t i,vini,scriptlen; uint8_t rmd160[20],scriptsig[IGUANA_MAXSCRIPTSIZE];
    memset(privkey.bytes,0,sizeof(privkey));
    if ( (vini= iguana_vinifind(myinfo,coin,&txid,srctxid,srcvout)) >= 0 )
    {
        if ( (scriptlen= iguana_scriptsigextract(myinfo,coin,scriptsig,sizeof(scriptsig),txid,vini)) > 0 )
        {
            for (i=0; i<32; i++)
                privkey.bytes[i] = scriptsig[scriptlen - 33 + i];
            revcalc_rmd160_sha256(rmd160,privkey);//.bytes,sizeof(privkey));
            if ( memcmp(secret160,rmd160,sizeof(rmd160)) == sizeof(rmd160) )
            {
                *destp = privkey;
                printf("found %s (%s)\n",name,bits256_str(str,privkey));
                return(0);
            }
        }
    }
    return(-1);
}

int32_t basilisk_privBn_extract(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    if ( basilisk_priviextract(myinfo,swap->bobcoin,"privBn",&swap->I.privBn,swap->I.secretBn,swap->bobrefund.I.actualtxid,0) == 0 )
    {
        
    }
    if ( basilisk_swapget(myinfo,swap,0x40000000,data,maxlen,basilisk_verify_privi) == 0 )
    {
        if ( bits256_nonz(swap->I.privBn) != 0 && swap->alicereclaim.txbytes == 0 )
        {
            char str[65]; printf("have privBn.%s\n",bits256_str(str,swap->I.privBn));
            return(basilisk_alicepayment_spend(myinfo,swap,&swap->alicereclaim));
        }
    }
    return(-1);
}

int32_t basilisk_privAm_extract(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    if ( basilisk_priviextract(myinfo,swap->bobcoin,"privAm",&swap->I.privAm,swap->I.secretAm,swap->bobpayment.I.actualtxid,0) == 0 )
    {
        
    }
    if ( bits256_nonz(swap->I.privAm) != 0 && swap->bobspend.txbytes == 0 )
    {
        char str[65]; printf("have privAm.%s\n",bits256_str(str,swap->I.privAm));
        return(basilisk_alicepayment_spend(myinfo,swap,&swap->bobspend));
    }
    return(-1);
}

bits256 instantdex_derivekeypair(void *ctx,bits256 *newprivp,uint8_t pubkey[33],bits256 privkey,bits256 orderhash)
{
    bits256 sharedsecret;
    sharedsecret = curve25519_shared(privkey,orderhash);
    vcalc_sha256cat(newprivp->bytes,orderhash.bytes,sizeof(orderhash),sharedsecret.bytes,sizeof(sharedsecret));
    return(bitcoin_pubkey33(ctx,pubkey,*newprivp));
}

int32_t instantdex_pubkeyargs(void *ctx,struct basilisk_swap *swap,int32_t numpubs,bits256 privkey,bits256 hash,int32_t firstbyte)
{
    char buf[3]; int32_t i,n,m,len=0; bits256 pubi,reveal; uint64_t txid; uint8_t secret160[20],pubkey[33];
    sprintf(buf,"%c0",'A' - 0x02 + firstbyte);
    if ( numpubs > 2 )
    {
        if ( swap->I.numpubs+2 >= numpubs )
            return(numpubs);
        printf(">>>>>> start generating %s\n",buf);
    }
    for (i=n=m=0; i<numpubs*100 && n<numpubs; i++)
    {
        pubi = instantdex_derivekeypair(ctx,&privkey,pubkey,privkey,hash);
        //printf("i.%d n.%d numpubs.%d %02x vs %02x\n",i,n,numpubs,pubkey[0],firstbyte);
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

void basilisk_rawtx_setparms(char *name,struct basilisk_swap *swap,struct basilisk_rawtx *rawtx,struct iguana_info *coin,int32_t numconfirms,int32_t vintype,uint64_t satoshis,int32_t vouttype,uint8_t *pubkey33)
{
    strcpy(rawtx->name,name);
    rawtx->coin = coin;
    rawtx->I.numconfirms = numconfirms;
    if ( (rawtx->I.amount= satoshis) < 10000 )
        rawtx->I.amount = 10000;
    rawtx->I.vintype = vintype; // 0 -> std, 2 -> 2of2, 3 -> spend bobpayment, 4 -> spend bobdeposit
    rawtx->I.vouttype = vouttype; // 0 -> fee, 1 -> std, 2 -> 2of2, 3 -> bobpayment, 4 -> bobdeposit
    if ( rawtx->I.vouttype == 0 )
    {
        if ( strcmp(coin->symbol,"BTC") == 0 && (swap->I.req.quoteid % 10) == 0 )
            decode_hex(rawtx->I.rmd160,20,TIERNOLAN_RMD160);
        else decode_hex(rawtx->I.rmd160,20,INSTANTDEX_RMD160);
        bitcoin_address(rawtx->I.destaddr,rawtx->coin->chain->pubtype,rawtx->I.rmd160,20);
    }
    if ( pubkey33 != 0 )
    {
        memcpy(rawtx->I.pubkey33,pubkey33,33);
        bitcoin_address(rawtx->I.destaddr,rawtx->coin->chain->pubtype,rawtx->I.pubkey33,33);
        bitcoin_addr2rmd160(&rawtx->I.addrtype,rawtx->I.rmd160,rawtx->I.destaddr);
    }
    if ( rawtx->I.vouttype <= 1 && rawtx->I.destaddr[0] != 0 )
    {
        rawtx->I.spendlen = bitcoin_standardspend(rawtx->spendscript,0,rawtx->I.rmd160);
        printf("%s spendlen.%d %s <- %.8f\n",name,rawtx->I.spendlen,rawtx->I.destaddr,dstr(rawtx->I.amount));
    } else printf("%s vouttype.%d destaddr.(%s)\n",name,rawtx->I.vouttype,rawtx->I.destaddr);
}

int32_t bitcoin_coinptrs(bits256 pubkey,struct iguana_info **bobcoinp,struct iguana_info **alicecoinp,char *src,char *dest,bits256 srchash,bits256 desthash)
{
    struct iguana_info *coin = iguana_coinfind(src);
    if ( coin == 0 || iguana_coinfind(dest) == 0 )
        return(0);
    *bobcoinp = *alicecoinp = 0;
    /*if ( strcmp("BTC",src) == 0 )
    {
        *bobcoinp = iguana_coinfind(src);
        *alicecoinp = iguana_coinfind(dest);
    }
    else if ( strcmp("BTC",dest) == 0 )
    {
        *bobcoinp = iguana_coinfind(dest);
        *alicecoinp = iguana_coinfind(src);
    }
    else if ( (coin= iguana_coinfind(src)) != 0 && coin->chain->havecltv != 0 )
    {
        *bobcoinp = iguana_coinfind(src);
        *alicecoinp = iguana_coinfind(dest);
    }
    else if ( (coin= iguana_coinfind(dest)) != 0 && coin->chain->havecltv != 0 )
    {
        *bobcoinp = iguana_coinfind(dest);
        *alicecoinp = iguana_coinfind(src);
    }
    else return(0);*/
    *bobcoinp = iguana_coinfind(dest);
    *alicecoinp = iguana_coinfind(src);
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

struct basilisk_swap *bitcoin_swapinit(void *ctx,bits256 privkey,uint8_t *pubkey33,bits256 pubkey25519,struct basilisk_swap *swap,int32_t optionduration,uint32_t statebits)
{
    //struct iguana_info *bobcoin,*alicecoin;
    uint8_t *alicepub33=0,*bobpub33=0; int32_t x = -1;
    swap->I.putduration = swap->I.callduration = INSTANTDEX_LOCKTIME;
    if ( optionduration < 0 )
        swap->I.putduration -= optionduration;
    else if ( optionduration > 0 )
        swap->I.callduration += optionduration;
    swap->bobcoin = iguana_coinfind(swap->I.req.dest);
    swap->I.bobsatoshis = swap->I.req.destamount;
    swap->I.bobconfirms = (1*0 + sqrt(dstr(swap->I.bobsatoshis) * .1));
    swap->alicecoin = iguana_coinfind(swap->I.req.src);
    swap->I.alicesatoshis = swap->I.req.srcamount;
    swap->I.aliceconfirms = swap->I.bobconfirms * 3;
    /*if ( strcmp("BTC",swap->I.req.src) == 0 )
    {
        swap->bobcoin = iguana_coinfind("BTC");
        swap->I.bobsatoshis = swap->I.req.srcamount;
        swap->I.bobconfirms = (1*0 + sqrt(dstr(swap->I.bobsatoshis) * .1));
        swap->alicecoin = iguana_coinfind(swap->I.req.dest);
        swap->I.alicesatoshis = swap->I.req.destamount;
        swap->I.aliceconfirms = swap->I.bobconfirms * 3;
    }
    else if ( strcmp("BTC",swap->I.req.dest) == 0 )
    {
        swap->bobcoin = iguana_coinfind("BTC");
        swap->I.bobsatoshis = swap->I.req.destamount;
        swap->I.bobconfirms = (1*0 + sqrt(dstr(swap->I.bobsatoshis) * .1));
        swap->alicecoin = iguana_coinfind(swap->I.req.src);
        swap->I.alicesatoshis = swap->I.req.srcamount;
        swap->I.aliceconfirms = swap->I.bobconfirms * 3;
    }
    else
    {
        if ( (coin= iguana_coinfind(swap->I.req.src)) != 0 )
        {
            if ( coin->chain->havecltv != 0 )
            {
                swap->bobcoin = coin;
                swap->I.bobsatoshis = swap->I.req.srcamount;
                swap->alicecoin = iguana_coinfind(swap->I.req.dest);
                swap->I.alicesatoshis = swap->I.req.destamount;
            }
            else if ( (coin= iguana_coinfind(swap->I.req.dest)) != 0 )
            {
                if ( coin->chain->havecltv != 0 )
                {
                    swap->bobcoin = coin;
                    swap->I.bobsatoshis = swap->I.req.destamount;
                    swap->alicecoin = iguana_coinfind(swap->I.req.src);
                    swap->I.alicesatoshis = swap->I.req.srcamount;
                } else printf("neither coin handles ctlv %s %s\n",swap->I.req.src,swap->I.req.dest);
            } else printf("cant find src or dest coin.(%s %s)\n",swap->I.req.src,swap->I.req.dest);
        } else printf("cant find src coin.(%s)\n",swap->I.req.src);
    }*/
    if ( swap->bobcoin == 0 || swap->alicecoin == 0 )
    {
        printf("missing bobcoin.%p or missing alicecoin.%p src.%p dest.%p\n",swap->bobcoin,swap->alicecoin,iguana_coinfind(swap->I.req.src),iguana_coinfind(swap->I.req.dest));
        free(swap);
        return(0);
    }
    if ( swap->I.bobconfirms == 0 )
        swap->I.bobconfirms = swap->bobcoin->chain->minconfirms;
    if ( swap->I.aliceconfirms == 0 )
        swap->I.aliceconfirms = swap->alicecoin->chain->minconfirms;
    if ( (swap->I.bobinsurance= (swap->I.bobsatoshis / INSTANTDEX_INSURANCEDIV)) < 10000 )
        swap->I.bobinsurance = 10000;
    if ( (swap->I.aliceinsurance= (swap->I.alicesatoshis / INSTANTDEX_INSURANCEDIV)) < 10000 )
        swap->I.aliceinsurance = 10000;
    strcpy(swap->I.bobstr,swap->bobcoin->symbol);
    strcpy(swap->I.alicestr,swap->alicecoin->symbol);
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
    /*if ( bits256_cmp(swap->I.myhash,swap->I.req.srchash) == 0 )
    {
        swap->I.otherhash = swap->I.req.desthash;
        if ( strcmp(swap->I.req.src,swap->I.bobstr) == 0 )
            swap->I.iambob = 1;
    }
    else if ( bits256_cmp(swap->I.myhash,swap->I.req.desthash) == 0 )
    {
        swap->I.otherhash = swap->I.req.srchash;
        if ( strcmp(swap->I.req.dest,swap->I.bobstr) == 0 )
            swap->I.iambob = 1;
    }
    else
    {
        printf("neither src nor dest error\n");
        return(0);
    }
    if ( (bitcoin_coinptrs(pubkey25519,&bobcoin,&alicecoin,swap->I.req.src,swap->I.req.dest,swap->I.req.srchash,swap->I.req.desthash)+1)/2 != swap->I.iambob )
    {
        printf("error iambob.%d != %d\n",swap->I.iambob,bitcoin_coinptrs(pubkey25519,&bobcoin,&alicecoin,swap->I.req.src,swap->I.req.dest,swap->I.req.srchash,swap->I.req.desthash));
        return(0);
    }*/
    if ( bits256_nonz(privkey) == 0 || (x= instantdex_pubkeyargs(ctx,swap,2 + INSTANTDEX_DECKSIZE,privkey,swap->I.orderhash,0x02+swap->I.iambob)) != 2 + INSTANTDEX_DECKSIZE )
    {
        char str[65]; printf("couldnt generate privkeys %d %s\n",x,bits256_str(str,privkey));
        return(0);
    }
    if ( swap->I.iambob != 0 )
    {
        basilisk_rawtx_setparms("myfee",swap,&swap->myfee,swap->bobcoin,0,0,swap->I.bobsatoshis/INSTANTDEX_DECKSIZE,0,0);
        basilisk_rawtx_setparms("otherfee",swap,&swap->otherfee,swap->alicecoin,0,0,swap->I.alicesatoshis/INSTANTDEX_DECKSIZE,0,0);
        bobpub33 = pubkey33;
    }
    else
    {
        basilisk_rawtx_setparms("otherfee",swap,&swap->otherfee,swap->bobcoin,0,0,swap->I.bobsatoshis/INSTANTDEX_DECKSIZE,0,0);
        basilisk_rawtx_setparms("myfee",swap,&swap->myfee,swap->alicecoin,0,0,swap->I.alicesatoshis/INSTANTDEX_DECKSIZE,0,0);
        alicepub33 = pubkey33;
    }
    basilisk_rawtx_setparms("bobdeposit",swap,&swap->bobdeposit,swap->bobcoin,swap->I.bobconfirms,0,swap->I.bobsatoshis + (swap->I.bobsatoshis>>3) + swap->bobcoin->txfee,4,0);
    basilisk_rawtx_setparms("bobrefund",swap,&swap->bobrefund,swap->bobcoin,1,4,swap->I.bobsatoshis + (swap->I.bobsatoshis>>3),1,bobpub33);
    swap->bobrefund.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("aliceclaim",swap,&swap->aliceclaim,swap->bobcoin,1,4,swap->I.bobsatoshis + (swap->I.bobsatoshis>>3),1,alicepub33);
    swap->aliceclaim.I.suppress_pubkeys = 1;
    swap->aliceclaim.I.locktime = swap->I.started + swap->I.putduration+swap->I.callduration + 1;

    basilisk_rawtx_setparms("bobpayment",swap,&swap->bobpayment,swap->bobcoin,swap->I.bobconfirms,0,swap->I.bobsatoshis + swap->bobcoin->txfee,3,0);
    basilisk_rawtx_setparms("alicespend",swap,&swap->alicespend,swap->bobcoin,swap->I.bobconfirms,3,swap->I.bobsatoshis,1,alicepub33);
    swap->alicespend.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("bobreclaim",swap,&swap->bobreclaim,swap->bobcoin,swap->I.bobconfirms,3,swap->I.bobsatoshis,1,bobpub33);
    swap->bobreclaim.I.suppress_pubkeys = 1;
    swap->bobreclaim.I.locktime = swap->I.started + swap->I.putduration + 1;

    basilisk_rawtx_setparms("alicepayment",swap,&swap->alicepayment,swap->alicecoin,swap->I.aliceconfirms,0,swap->I.alicesatoshis+swap->alicecoin->txfee,2,0);
    basilisk_rawtx_setparms("bobspend",swap,&swap->bobspend,swap->alicecoin,swap->I.aliceconfirms,2,swap->I.alicesatoshis,1,bobpub33);
    swap->bobspend.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("alicereclaim",swap,&swap->alicereclaim,swap->alicecoin,swap->I.aliceconfirms,2,swap->I.alicesatoshis,1,alicepub33);
    swap->alicereclaim.I.suppress_pubkeys = 1;
    printf("IAMBOB.%d\n",swap->I.iambob);
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
    int32_t i;
    swap->I.finished = (uint32_t)time(NULL);
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
    for (i=0; i<swap->nummessages; i++)
        if ( swap->messages[i].data != 0 )
            free(swap->messages[i].data), swap->messages[i].data = 0;
    free(swap->messages), swap->messages = 0;
    swap->nummessages = 0;
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

int32_t basilisk_verify_otherstatebits(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t retval; struct basilisk_swap *swap = ptr;
    if ( datalen == sizeof(swap->I.otherstatebits) )
    {
        retval = iguana_rwnum(0,data,sizeof(swap->I.otherstatebits),&swap->I.otherstatebits);
        //printf("got sendstate.%x\n",swap->I.otherstatebits);
        return(retval);
    } else return(-1);
}
               
int32_t basilisk_verify_choosei(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t otherchoosei=-1,i,len = 0; struct basilisk_swap *swap = ptr;
    if ( datalen == sizeof(otherchoosei)+sizeof(bits256)*2 )
    {
        len += iguana_rwnum(0,data,sizeof(otherchoosei),&otherchoosei);
        if ( otherchoosei >= 0 && otherchoosei < INSTANTDEX_DECKSIZE )
        {
            //printf("otherchoosei.%d\n",otherchoosei);
            swap->I.otherchoosei = otherchoosei;
            if ( swap->I.iambob != 0 )
            {
                for (i=0; i<32; i++)
                    swap->I.pubA0.bytes[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.pubA1.bytes[i] = data[len++];
                char str[65]; printf("GOT pubA0/1 %s\n",bits256_str(str,swap->I.pubA0));
            }
            else
            {
                for (i=0; i<32; i++)
                    swap->I.pubB0.bytes[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.pubB1.bytes[i] = data[len++];
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

int32_t basilisk_verify_otherdeck(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t i,len = 0; struct basilisk_swap *swap = ptr;
    for (i=0; i<sizeof(swap->otherdeck)/sizeof(swap->otherdeck[0][0]); i++)
        len += iguana_rwnum(0,&data[len],sizeof(swap->otherdeck[i>>1][i&1]),&swap->otherdeck[i>>1][i&1]);
    return(0);
}

int32_t basilisk_verify_privkeys(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t i,j,wrongfirstbyte=0,errs=0,len = 0; bits256 otherpriv,pubi; uint8_t secret160[20],otherpubkey[33]; uint64_t txid; struct basilisk_swap *swap = ptr;
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
                pubi = bitcoin_pubkey33(myinfo->ctx,otherpubkey,otherpriv);
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
                basilisk_bobscripts_set(myinfo,swap,1,1);
            }
            else
            {
                for (i=0; i<32; i++)
                    swap->I.pubBn.bytes[i] = data[len++];
                for (i=0; i<20; i++)
                    swap->I.secretBn[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.secretBn256[i] = data[len++];
                //basilisk_bobscripts_set(myinfo,swap,0);
            }
        } else printf("failed verification: wrong firstbyte.%d errs.%d\n",wrongfirstbyte,errs);
    }
    //printf("privkeys errs.%d wrongfirstbyte.%d\n",errs,wrongfirstbyte);
    return(errs);
}

uint32_t basilisk_swapdata_rawtxsend(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx,uint32_t nextbits)
{
    uint8_t sendbuf[32768]; int32_t sendlen;
    if ( basilisk_swapdata_rawtx(myinfo,swap,data,maxlen,rawtx) != 0 )
    {
        if ( bits256_nonz(rawtx->I.signedtxid) != 0 && bits256_nonz(rawtx->I.actualtxid) == 0 )
        {
            char str[65],str2[65];
            rawtx->I.actualtxid = basilisk_swap_broadcast(rawtx->name,myinfo,swap,rawtx->coin,rawtx->txbytes,rawtx->I.datalen);
            if ( bits256_cmp(rawtx->I.actualtxid,rawtx->I.signedtxid) != 0 )
                printf("%s rawtxsend %s vs %s\n",rawtx->name,bits256_str(str,rawtx->I.signedtxid),bits256_str(str2,rawtx->I.actualtxid));
            if ( bits256_nonz(rawtx->I.actualtxid) != 0 && msgbits != 0 )
            {
                sendlen = 0;
                sendbuf[sendlen++] = rawtx->I.datalen & 0xff;
                sendbuf[sendlen++] = (rawtx->I.datalen >> 8) & 0xff;
                sendbuf[sendlen++] = rawtx->I.redeemlen;
                memcpy(&sendbuf[sendlen],rawtx->txbytes,rawtx->I.datalen), sendlen += rawtx->I.datalen;
                if ( rawtx->I.redeemlen > 0 && rawtx->I.redeemlen < 0x100 )
                {
                    memcpy(&sendbuf[sendlen],rawtx->redeemscript,rawtx->I.redeemlen);
                    sendlen += rawtx->I.redeemlen;
                }
                //printf("sendlen.%d datalen.%d redeemlen.%d\n",sendlen,rawtx->datalen,rawtx->redeemlen);
                return(basilisk_swapsend(myinfo,swap,msgbits,sendbuf,sendlen,nextbits,rawtx->I.crcs));
            }
        }
        return(nextbits);
    } else printf("error from basilisk_swapdata_rawtx %p len.%d\n",rawtx->txbytes,rawtx->I.datalen);
    return(0);
}

void basilisk_sendpubkeys(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t datalen;
    datalen = basilisk_swapdata_deck(myinfo,swap,data,maxlen);
    printf("send deck.%d\n",datalen);
    swap->I.statebits |= basilisk_swapsend(myinfo,swap,0x02,data,datalen,0x01,swap->I.crcs_mypub);
}

int32_t basilisk_checkdeck(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    if ( (swap->I.statebits & 0x02) == 0 )
    {
        //printf("check for other deck\n");
        if ( basilisk_swapget(myinfo,swap,0x02,data,maxlen,basilisk_verify_otherdeck) == 0 )
            swap->I.statebits |= 0x02;
        else return(-1);
    }
    return(0);
}

void basilisk_sendstate(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t datalen;
    //printf("sendstate.%x\n",swap->I.statebits);
    datalen = iguana_rwnum(1,data,sizeof(swap->I.statebits),&swap->I.statebits);
    basilisk_swapsend(myinfo,swap,0x80000000,data,datalen,0,0);
}

void basilisk_sendchoosei(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
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
    swap->I.statebits |= basilisk_swapsend(myinfo,swap,0x08,data,datalen,0x04,swap->I.crcs_mychoosei);
}

void basilisk_waitchoosei(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    uint8_t pubkey33[33]; //char str[65],str2[65];
    //printf("check otherchoosei\n");
    if ( basilisk_swapget(myinfo,swap,0x08,data,maxlen,basilisk_verify_choosei) == 0 )
    {
        if ( swap->I.iambob != 0 )
        {
            if ( bits256_nonz(swap->I.privBn) == 0 )
            {
                swap->I.privBn = swap->privkeys[swap->I.otherchoosei];
                memset(&swap->privkeys[swap->I.otherchoosei],0,sizeof(swap->privkeys[swap->I.otherchoosei]));
                revcalc_rmd160_sha256(swap->I.secretBn,swap->I.privBn);//.bytes,sizeof(swap->privBn));
                vcalc_sha256(0,swap->I.secretBn256,swap->I.privBn.bytes,sizeof(swap->I.privBn));
                swap->I.pubBn = bitcoin_pubkey33(myinfo->ctx,pubkey33,swap->I.privBn);
                //printf("set privBn.%s %s\n",bits256_str(str,swap->privBn),bits256_str(str2,*(bits256 *)swap->secretBn256));
                basilisk_bobscripts_set(myinfo,swap,1,1);
             }
        }
        else
        {
            if ( bits256_nonz(swap->I.privAm) == 0 )
            {
                swap->I.privAm = swap->privkeys[swap->I.otherchoosei];
                memset(&swap->privkeys[swap->I.otherchoosei],0,sizeof(swap->privkeys[swap->I.otherchoosei]));
                revcalc_rmd160_sha256(swap->I.secretAm,swap->I.privAm);//.bytes,sizeof(swap->privAm));
                vcalc_sha256(0,swap->I.secretAm256,swap->I.privAm.bytes,sizeof(swap->I.privAm));
                swap->I.pubAm = bitcoin_pubkey33(myinfo->ctx,pubkey33,swap->I.privAm);
                char str[65],str2[65]; printf("set privAm.%s %s\n",bits256_str(str,swap->I.privAm),bits256_str(str2,*(bits256 *)swap->I.secretAm256));
                //basilisk_bobscripts_set(myinfo,swap,0);
            }
        }
        swap->I.statebits |= 0x08;
    }
}

void basilisk_sendmostprivs(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
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
    //printf("send privkeys.%d\n",datalen);
    swap->I.statebits |= basilisk_swapsend(myinfo,swap,0x20,data,datalen,0x10,swap->I.crcs_myprivs);
}

void basilisk_alicepayment(struct supernet_info *myinfo,struct basilisk_swap *swap,struct iguana_info *coin,struct basilisk_rawtx *alicepayment,bits256 pubAm,bits256 pubBn)
{
    alicepayment->I.spendlen = basilisk_alicescript(alicepayment->redeemscript,&alicepayment->I.redeemlen,alicepayment->spendscript,0,alicepayment->I.destaddr,coin->chain->p2shtype,pubAm,pubBn);
    basilisk_rawtx_gen("alicepayment",myinfo,swap,0,1,alicepayment,alicepayment->I.locktime,alicepayment->spendscript,alicepayment->I.spendlen,coin->chain->txfee,1,0);
}

int32_t basilisk_swapiteration(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t j,datalen,retval = 0;
    while ( ((swap->I.otherstatebits & 0x80) == 0 || (swap->I.statebits & 0x80) == 0) && retval == 0 && time(NULL) < swap->I.expiration )
    {
        printf("D r%u/q%u swapstate.%x otherstate.%x\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits,swap->I.otherstatebits);
        if ( (swap->I.statebits & 0x80) == 0 ) // wait for fee
        {
            if ( basilisk_swapget(myinfo,swap,0x80,data,maxlen,basilisk_verify_otherfee) == 0 )
            {
                // verify and submit otherfee
                swap->I.statebits |= 0x80;
                basilisk_sendstate(myinfo,swap,data,maxlen);
            }
        }
        basilisk_sendstate(myinfo,swap,data,maxlen);
        basilisk_swapget(myinfo,swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        if ( (swap->I.otherstatebits & 0x80) != 0 && (swap->I.statebits & 0x80) != 0 )
            break;
        sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        basilisk_swapget(myinfo,swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        basilisk_sendstate(myinfo,swap,data,maxlen);
        if ( (swap->I.otherstatebits & 0x80) == 0 )
            basilisk_swapdata_rawtxsend(myinfo,swap,0x80,data,maxlen,&swap->myfee,0x40);
    }
    while ( retval == 0 && time(NULL) < swap->I.expiration )  // both sides have setup required data and paid txfee
    {
        //if ( (rand() % 30) == 0 )
            printf("E r%u/q%u swapstate.%x otherstate.%x\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits,swap->I.otherstatebits);
        if ( swap->I.iambob != 0 )
        {
            //printf("BOB\n");
            if ( (swap->I.statebits & 0x100) == 0 )
            {
                printf("send bobdeposit\n");
                swap->I.statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x200,data,maxlen,&swap->bobdeposit,0x100);
            }
            // [BLOCKING: altfound] make sure altpayment is confirmed and send payment
            else if ( (swap->I.statebits & 0x1000) == 0 )
            {
                printf("check alicepayment\n");
                if ( basilisk_swapget(myinfo,swap,0x1000,data,maxlen,basilisk_verify_alicepaid) == 0 )
                {
                    swap->I.statebits |= 0x1000;
                    printf("got alicepayment\n");
                }
            }
            else if ( (swap->I.statebits & 0x2000) == 0 )
            {
                if ( basilisk_numconfirms(myinfo,swap,&swap->alicepayment) >= swap->I.aliceconfirms )
                {
                    swap->I.statebits |= 0x2000;
                    printf("alicepayment confirmed\n");
                }
            }
            else if ( (swap->I.statebits & 0x4000) == 0 )
            {
                basilisk_bobscripts_set(myinfo,swap,0,1);
                printf("send bobpayment\n");
                swap->I.statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x8000,data,maxlen,&swap->bobpayment,0x4000);
            }
            // [BLOCKING: privM] Bob waits for privAm either from Alice or alice blockchain
            else if ( (swap->I.statebits & 0x40000) == 0 )
            {
                if ( basilisk_swapget(myinfo,swap,0x40000,data,maxlen,basilisk_verify_privi) == 0 || basilisk_privAm_extract(myinfo,swap) == 0 ) // divulges privAm
                {
                    printf("got privi spend alicepayment\n");
                    basilisk_alicepayment_spend(myinfo,swap,&swap->bobspend);
                    if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->bobspend,0x40000) == 0 )
                        printf("Bob error spending alice payment\n");
                    else
                    {
                        tradebot_swap_balancingtrade(myinfo,swap,1);
                        printf("Bob spends alicepayment\n");
                        swap->I.statebits |= 0x40000;
                        while ( basilisk_numconfirms(myinfo,swap,&swap->bobspend) < swap->I.aliceconfirms )
                        {
                            printf("bobspend confirmed\n");
                            swap->I.statebits |= 0x80000;
                            printf("Bob confirms spend of Alice's payment\n");
                            sleep(DEX_SLEEP);
                        }
                        retval = 1;
                    }
                }
            }
            if ( swap->bobpayment.I.locktime != 0 && time(NULL) > swap->bobpayment.I.locktime )
            {
                // submit reclaim of payment
                printf("bob reclaims bobpayment\n");
                swap->I.statebits |= (0x40000 | 0x80000);
                if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->bobreclaim,0) == 0 )
                    printf("Bob error reclaiming own payment after alice timed out\n");
                else
                {
                    printf("Bob reclaimed own payment\n");
                    while ( 0 && (swap->I.statebits & 0x100000) == 0 ) // why wait for own tx?
                    {
                        if ( basilisk_numconfirms(myinfo,swap,&swap->bobreclaim) >= 1 )
                        {
                            printf("bobreclaim confirmed\n");
                            swap->I.statebits |= 0x100000;
                            printf("Bob confirms reclain of payment\n");
                            break;
                        }
                    }
                    retval = 1;
                }
            }
        }
        else
        {
            //printf("ALICE\n");
            // [BLOCKING: depfound] Alice waits for deposit to confirm and sends altpayment
            if ( (swap->I.statebits & 0x200) == 0 )
            {
                printf("checkfor deposit\n");
                if ( basilisk_swapget(myinfo,swap,0x200,data,maxlen,basilisk_verify_bobdeposit) == 0 )
                {
                    // verify deposit and submit, set confirmed height
                    printf("got bobdeposit\n");
                    swap->I.statebits |= 0x200;
                } else printf("no valid deposit\n");
            }
            else if ( (swap->I.statebits & 0x400) == 0 )
            {
                if ( basilisk_numconfirms(myinfo,swap,&swap->bobdeposit) >= swap->I.bobconfirms )
                {
                    printf("bobdeposit confirmed\n");
                    swap->I.statebits |= 0x400;
                }
            }
            else if ( (swap->I.statebits & 0x800) == 0 )
            {
                printf("send alicepayment\n");
                swap->I.statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x1000,data,maxlen,&swap->alicepayment,0x800);
            }
            // [BLOCKING: payfound] make sure payment is confrmed and send in spend or see bob's reclaim and claim
            else if ( (swap->I.statebits & 0x8000) == 0 )
            {
                if ( basilisk_swapget(myinfo,swap,0x8000,data,maxlen,basilisk_verify_bobpaid) == 0 )
                {
                    printf("got bobpayment\n");
                    tradebot_swap_balancingtrade(myinfo,swap,0);
                    // verify payment and submit, set confirmed height
                    swap->I.statebits |= 0x8000;
                }
            }
            else if ( (swap->I.statebits & 0x10000) == 0 )
            {
                if ( basilisk_numconfirms(myinfo,swap,&swap->bobpayment) >= swap->I.bobconfirms )
                {
                    printf("bobpayment confirmed\n");
                    swap->I.statebits |= 0x10000;
                }
            }
            else if ( (swap->I.statebits & 0x20000) == 0 )
            {
                printf("alicespend bobpayment\n");
                if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->alicespend,0x20000) != 0 && basilisk_numconfirms(myinfo,swap,&swap->alicespend) > 0 )
                {
                    for (j=datalen=0; j<32; j++)
                        data[datalen++] = swap->I.privAm.bytes[j];
                    printf("send privAm\n");
                    swap->I.statebits |= basilisk_swapsend(myinfo,swap,0x40000,data,datalen,0x20000,swap->I.crcs_mypriv);
                }
            }
            else if ( (swap->I.statebits & 0x40000) == 0 )
            {
                if ( basilisk_numconfirms(myinfo,swap,&swap->alicespend) >= swap->I.bobconfirms )
                {
                    swap->I.statebits |= 0x40000;
                    printf("Alice confirms spend of Bob's payment\n");
                    retval = 1;
                }
            }
            if ( swap->bobdeposit.I.locktime != 0 && time(NULL) > swap->bobdeposit.I.locktime )
            {
                printf("Alice claims deposit\n");
                if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->aliceclaim,0) == 0 )
                    printf("Alice couldnt claim deposit\n");
                else
                {
                    printf("Alice claimed deposit\n");
                    retval = 1;
                }
            }
            else if ( basilisk_privBn_extract(myinfo,swap,data,maxlen) == 0 )
            {
                printf("Alice reclaims her payment\n");
                swap->I.statebits |= 0x40000000;
                if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->alicereclaim,0x40000000) == 0 )
                    printf("Alice error sending alicereclaim\n");
                else
                {
                    printf("Alice reclaimed her payment\n");
                    retval = 1;
                }
            }
        }
        if ( (rand() % 30) == 0 )
            printf("finished swapstate.%x other.%x\n",swap->I.statebits,swap->I.otherstatebits);
        sleep(DEX_SLEEP + (swap->I.iambob == 0));
        basilisk_sendstate(myinfo,swap,data,maxlen);
        basilisk_swapget(myinfo,swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
    }
    return(retval);
}

int32_t swapcompleted(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    if ( swap->I.iambob != 0 )
        return(swap->I.bobspent);
    else return(swap->I.alicespent);
}

cJSON *swapjson(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    cJSON *retjson = cJSON_CreateObject();
    return(retjson);
}

void basilisk_psockinit(struct supernet_info *myinfo,struct basilisk_swap *swap,char *pushaddr,char *subaddr)
{
    char keystr[64],databuf[1024],*retstr,*datastr; cJSON *retjson,*addrjson; uint8_t data[512]; int32_t datalen,timeout,pushsock = -1,subsock = -1;
    if ( swap->connected == 1 )
        return;
    if ( swap->pushsock < 0 && swap->subsock < 0 && (pushsock= nn_socket(AF_SP,NN_PUSH)) >= 0 && (subsock= nn_socket(AF_SP,NN_SUB)) >= 0 )
    {
        timeout = 100;
        nn_setsockopt(pushsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
        timeout = 1;
        nn_setsockopt(subsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
        nn_setsockopt(subsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
        swap->pushsock = pushsock;
        swap->subsock = subsock;
    }
    sprintf(keystr,"%08x-%08x",swap->I.req.requestid,swap->I.req.quoteid);
    if ( pushaddr != 0 && subaddr != 0 )
    {
        if ( nn_connect(pushsock,pushaddr) >= 0 && nn_connect(subsock,subaddr) >= 0 )
            swap->connected = 1;
        sprintf((char *)data,"{\"push\":\"%s\",\"sub\":\"%s\"}",pushaddr,subaddr);
        datalen = (int32_t)strlen((char *)data) + 1;
        printf("datalen.%d (%s)\n",datalen,(char *)data);
        init_hexbytes_noT(databuf,data,datalen);
        printf("%s -> %s\n",keystr,databuf);
        if ( (retstr= _dex_kvupdate(myinfo,"KV",keystr,databuf,1)) != 0 )
        {
            printf("KVupdate.(%s)\n",retstr);
            free(retstr);
        }
    }
    else
    {
        printf("connected.%d\n",swap->connected);
        if ( (retstr= _dex_kvsearch(myinfo,"KV",keystr)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( (datastr= jstr(retjson,"value")) != 0 )
                {
                    datalen = (int32_t)strlen(datastr) >> 1;
                    decode_hex((uint8_t *)databuf,datalen,datastr);
                    if ( (addrjson= cJSON_Parse(databuf)) != 0 )
                    {
                        pushaddr = jstr(addrjson,"push");
                        subaddr = jstr(addrjson,"sub");
                        if ( pushaddr != 0 && subaddr != 0 )
                        {
                            printf("KV decoded (%s and %s) %d %d\n",pushaddr,subaddr,swap->pushsock,swap->subsock);
                            if ( nn_connect(swap->pushsock,pushaddr) >= 0 && nn_connect(swap->subsock,subaddr) >= 0 )
                                swap->connected = 1;
                        }
                        free_json(addrjson);
                    }
                }
                free_json(retjson);
            }
            printf("KVsearch.(%s) connected.%d socks.(%d %d)\n",retstr,swap->connected,swap->pushsock,swap->subsock);
            free(retstr);
        }
    }
}

void basilisk_swaploop(void *_swap)
{
    uint8_t *data; uint32_t expiration; uint32_t channel; int32_t retval=0,i,j,datalen,maxlen; struct supernet_info *myinfo; struct basilisk_swap *swap = _swap;
    myinfo = swap->myinfoptr;
    fprintf(stderr,"start swap\n");
    maxlen = 1024*1024 + sizeof(*swap);
    data = malloc(maxlen);
    expiration = (uint32_t)time(NULL) + 600;
    myinfo->DEXactive = expiration;
    channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
    while ( (swap->I.statebits & (0x08|0x02)) != (0x08|0x02) && time(NULL) < expiration )
    {
        dex_channelsend(myinfo,swap->I.req.srchash,swap->I.req.desthash,channel,0x4000000,(void *)&swap->I.req.requestid,sizeof(swap->I.req.requestid)); //,60);
        if ( swap->I.iambob == 0 && swap->connected == 0 )
            basilisk_psockinit(myinfo,swap,0,0);
        if ( swap->connected != 0 )
        {
            printf("A r%u/q%u swapstate.%x\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits);
            basilisk_sendstate(myinfo,swap,data,maxlen);
            basilisk_sendpubkeys(myinfo,swap,data,maxlen); // send pubkeys
            if ( basilisk_checkdeck(myinfo,swap,data,maxlen) == 0) // check for other deck 0x02
                basilisk_sendchoosei(myinfo,swap,data,maxlen);
            basilisk_waitchoosei(myinfo,swap,data,maxlen); // wait for choosei 0x08
            if ( (swap->I.statebits & (0x08|0x02)) == (0x08|0x02) )
                break;
        }
        sleep(DEX_SLEEP);
        //dpow_nanomsg_update(myinfo);
        //dex_updateclient(myinfo);
    }
    if ( swap->connected == 0 )
    {
        printf("couldnt establish connection\n");
        retval = -1;
    }
    while ( retval == 0 && (swap->I.statebits & 0x20) == 0 && time(NULL) < expiration )
    {
        printf("B r%u/q%u swapstate.%x\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits);
        basilisk_sendstate(myinfo,swap,data,maxlen);
        basilisk_sendchoosei(myinfo,swap,data,maxlen);
        basilisk_sendmostprivs(myinfo,swap,data,maxlen);
        if ( basilisk_swapget(myinfo,swap,0x20,data,maxlen,basilisk_verify_privkeys) == 0 )
        {
            swap->I.statebits |= 0x20;
            break;
        }
        sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        //dpow_nanomsg_update(myinfo);
        //dex_updateclient(myinfo);
    }
    myinfo->DEXactive = swap->I.expiration;
    if ( time(NULL) >= expiration )
    {
        retval = -1;
        myinfo->DEXactive = 0;
    }
    printf("C r%u/q%u swapstate.%x retval.%d\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits,retval);
    while ( retval == 0 && (swap->I.statebits & 0x40) == 0 ) // send fee
    {
        //dpow_nanomsg_update(myinfo);
        //dex_updateclient(myinfo);
        //printf("sendstate.%x\n",swap->I.statebits);
        basilisk_sendstate(myinfo,swap,data,maxlen);
        //printf("swapget\n");
        basilisk_swapget(myinfo,swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        //printf("after swapget\n");
        if ( swap->myfee.txbytes == 0 )
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
            basilisk_txlog(myinfo,swap,0,-1);
            if ( swap->I.iambob != 0 )
            {
                printf("bobscripts set\n");
                if ( basilisk_bobscripts_set(myinfo,swap,1,1) < 0 )
                {
                    sleep(DEX_SLEEP);
                    printf("bobscripts set error\n");
                    continue;
                }
            }
            else
            {
                for (i=0; i<3; i++)
                {
                    //if ( swap->alicepayment.txbytes != 0 && swap->alicepayment.I.spendlen != 0 )
                    //    break;
                    basilisk_alicepayment(myinfo,swap,swap->alicepayment.coin,&swap->alicepayment,swap->I.pubAm,swap->I.pubBn);
                    if ( swap->alicepayment.txbytes == 0 || swap->alicepayment.I.spendlen == 0 )
                    {
                        printf("error alice generating payment.%d\n",swap->alicepayment.I.spendlen);
                        sleep(DEX_SLEEP);
                    }
                    else
                    {
                        retval = 0;
                        for (i=0; i<swap->alicepayment.I.spendlen; i++)
                            printf("%02x",swap->alicepayment.txbytes[i]);
                        printf(" ALICE PAYMENT created\n");
                        iguana_unspents_mark(myinfo,swap->alicecoin,swap->alicepayment.vins);
                        basilisk_txlog(myinfo,swap,&swap->alicepayment,-1);
                        break;
                    }
                }
            }
            printf("generate fee\n");
            if ( basilisk_rawtx_gen("myfee",myinfo,swap,swap->I.iambob,1,&swap->myfee,0,swap->myfee.spendscript,swap->myfee.I.spendlen,swap->myfee.coin->chain->txfee,1,0) == 0 )
            {
                printf("done generate fee\n");
                swap->I.statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x80,data,maxlen,&swap->myfee,0x40);
                iguana_unspents_mark(myinfo,swap->I.iambob!=0?swap->bobcoin:swap->alicecoin,swap->myfee.vins);
                basilisk_txlog(myinfo,swap,&swap->myfee,-1);
                for (i=0; i<swap->myfee.I.spendlen; i++)
                    printf("%02x",swap->myfee.txbytes[i]);
                printf(" fee %p %x\n",swap->myfee.txbytes,swap->I.statebits);
                swap->I.statebits |= 0x40;
                if ( swap->alicepayment.txbytes != 0 && swap->alicepayment.I.spendlen > 0 )
                    break;
            }
            else
            {
                printf("error creating myfee\n");
                retval = -6;
            }
        }
    }
    while ( retval == 0 && basilisk_swapiteration(myinfo,swap,data,maxlen) == 0 )
    {
        sleep(DEX_SLEEP);
        basilisk_sendstate(myinfo,swap,data,maxlen);
        basilisk_swapget(myinfo,swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        if ( time(NULL) > swap->I.expiration )
            break;
        //dpow_nanomsg_update(myinfo);
        //dex_updateclient(myinfo);
    }
    printf("end of atomic swap\n");
    if ( swap->I.iambob != 0 && swap->bobdeposit.txbytes != 0 )
    {
        printf("BOB reclaims refund\n");
        basilisk_bobdeposit_refund(myinfo,swap,0);
        if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->bobrefund,0x40000000) == 0 ) // use secretBn
        {
            printf("Bob submit error getting refund of deposit\n");
        }
        else
        {
            // maybe wait for bobrefund to be confirmed
            for (j=datalen=0; j<32; j++)
                data[datalen++] = swap->I.privBn.bytes[j];
            basilisk_swapsend(myinfo,swap,0x40000000,data,datalen,0x40000000,swap->I.crcs_mypriv);
        }
    }
    if ( swapcompleted(myinfo,swap) > 0 ) // only if swap completed
    {
        if ( swap->I.iambob != 0 )
            tradebot_pendingadd(myinfo,swapjson(myinfo,swap),swap->I.req.src,dstr(swap->I.req.srcamount),swap->I.req.dest,dstr(swap->I.req.destamount));
        else tradebot_pendingadd(myinfo,swapjson(myinfo,swap),swap->I.req.dest,dstr(swap->I.req.destamount),swap->I.req.src,dstr(swap->I.req.srcamount));
    }
    printf("%s swap finished statebits %x\n",swap->I.iambob!=0?"BOB":"ALICE",swap->I.statebits);
    basilisk_swap_purge(myinfo,swap);
    free(data);
}

struct basilisk_swap *basilisk_thread_start(struct supernet_info *myinfo,bits256 privkey,struct basilisk_request *rp,uint32_t statebits,int32_t optionduration)
{
    int32_t i,m,n; char *retstr; uint8_t pubkey33[33]; bits256 pubkey25519; uint32_t channel,starttime; cJSON *retarray,*item,*msgobj,*retjson; struct basilisk_swap *swap = 0;
    // statebits 1 -> client, 0 -> LP
    portable_mutex_lock(&myinfo->DEX_swapmutex);
    for (i=0; i<myinfo->numswaps; i++)
        if ( myinfo->swaps[i]->I.req.requestid == rp->requestid )
        {
            printf("basilisk_thread_start error trying to start requestid.%u which is already started\n",rp->requestid);
            break;
        }
    if ( i == myinfo->numswaps && i < sizeof(myinfo->swaps)/sizeof(*myinfo->swaps) )
    {
        printf("basilisk_thread_start request.%u statebits.%d\n",rp->requestid,statebits);
        swap = calloc(1,sizeof(*swap));
        swap->subsock = swap->pushsock = -1;
        vcalc_sha256(0,swap->I.orderhash.bytes,(uint8_t *)rp,sizeof(*rp));
        swap->I.req = *rp;
        swap->myinfoptr = myinfo;
        bitcoin_pubkey33(myinfo->ctx,pubkey33,privkey);
        pubkey25519 = curve25519(privkey,curve25519_basepoint9());
        swap->persistent_pubkey = pubkey25519;
        swap->persistent_privkey = privkey;
        memcpy(swap->persistent_pubkey33,pubkey33,33);
        m = n = 0;
        if ( bitcoin_swapinit(myinfo->ctx,privkey,pubkey33,pubkey25519,swap,optionduration,statebits) != 0 )
        {
            if ( statebits == 0 )
            {
                if ( (retstr= _dex_psock(myinfo,"{}")) != 0 )
                {
                    // {"result":"success","pushaddr":"tcp://5.9.102.210:30002","subaddr":"tcp://5.9.102.210:30003","randipbits":3606291758,"coin":"KMD","tag":"6952562460568228137"}
                    if ( (retjson= cJSON_Parse(retstr)) != 0 )
                    {
                        basilisk_psockinit(myinfo,swap,jstr(retjson,"pushaddr"),jstr(retjson,"subaddr"));
                        free_json(retjson);
                    }
                    free(retstr);
                }
            } else basilisk_psockinit(myinfo,swap,0,0);

            starttime = (uint32_t)time(NULL);
            printf("statebits.%x m.%d n.%d\n",statebits,m,n);
            while ( statebits == 0 && m <= n/2 && time(NULL) < starttime+BASILISK_MSGDURATION )
            {
                m = n = 0;
                //dpow_nanomsg_update(myinfo);
                //dex_updateclient(myinfo);
                sleep(DEX_SLEEP);
                printf("waiting for offer to be accepted\n");
                channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
                if ( (retarray= basilisk_channelget(myinfo,rp->srchash,rp->desthash,channel,0x4000000,30)) != 0 )
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
                fprintf(stderr," M.%d N.%d launch.%d %d %p\n",m,n,myinfo->numswaps,(int32_t)(sizeof(myinfo->swaps)/sizeof(*myinfo->swaps)),&swap->I.req);
                if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)basilisk_swaploop,(void *)swap) != 0 )
                {
                    
                }
                myinfo->swaps[myinfo->numswaps++] = swap;
            } else printf("%u/%u offer wasnt accepted statebits.%d m.%d n.%d\n",rp->requestid,rp->quoteid,statebits,m,n);
        }
    }
    portable_mutex_unlock(&myinfo->DEX_swapmutex);
    return(swap);
}
