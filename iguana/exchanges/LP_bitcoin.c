
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
//  LP_bitcoin.c
//  marketmaker
//

#define IGUANA_MAXSCRIPTSIZE 10001

struct iguana_msgvin { bits256 prev_hash; uint8_t *vinscript,*userdata,*spendscript,*redeemscript; uint32_t prev_vout,sequence; uint16_t scriptlen,p2shlen,userdatalen,spendlen; }; //PACKEDSTRUCT;

struct vin_signer { bits256 privkey; char coinaddr[64]; uint8_t siglen,sig[80],rmd160[20],pubkey[66]; };

struct vin_info
{
    struct iguana_msgvin vin; uint64_t amount; cJSON *extras; bits256 sigtxid;
    int32_t M,N,validmask,spendlen,type,p2shlen,numpubkeys,numsigs,height,hashtype,userdatalen,suppress_pubkeys,ignore_cltverr;
    uint32_t sequence,unspentind; struct vin_signer signers[16]; char coinaddr[65];
    uint8_t rmd160[20],spendscript[IGUANA_MAXSCRIPTSIZE],p2shscript[IGUANA_MAXSCRIPTSIZE],userdata[IGUANA_MAXSCRIPTSIZE];
};

#define SIGHASH_ALL 1
#define SIGHASH_NONE 2
#define SIGHASH_SINGLE 3
#define SIGHASH_ANYONECANPAY 0x80

#define SCRIPT_OP_NOP 0x00
#define SCRIPT_OP_TRUE 0x51
#define SCRIPT_OP_2 0x52
#define SCRIPT_OP_3 0x53
#define SCRIPT_OP_4 0x54
#define SCRIPT_OP_IF 0x63
#define SCRIPT_OP_ELSE 0x67
#define SCRIPT_OP_RETURN 0x6a
#define SCRIPT_OP_DUP 0x76
#define SCRIPT_OP_ENDIF 0x68
#define SCRIPT_OP_DROP 0x75
#define SCRIPT_OP_EQUALVERIFY 0x88
#define SCRIPT_OP_SHA256 0xa8
#define SCRIPT_OP_HASH160 0xa9

#define SCRIPT_OP_EQUAL 0x87
#define SCRIPT_OP_CHECKSIG 0xac
#define SCRIPT_OP_CHECKMULTISIG 0xae
#define SCRIPT_OP_CHECKSEQUENCEVERIFY	0xb2
#define SCRIPT_OP_CHECKLOCKTIMEVERIFY 0xb1

void calc_rmd160_sha256(uint8_t rmd160[20],uint8_t *data,int32_t datalen)
{
    bits256 hash;
    vcalc_sha256(0,hash.bytes,data,datalen);
    calc_rmd160(0,rmd160,hash.bytes,sizeof(hash));
}

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

int32_t bitcoin_pubkeylen(const uint8_t *pubkey)
{
    if ( pubkey[0] == 2 || pubkey[0] == 3 )
        return(33);
    else if ( pubkey[0] == 4 )
        return(65);
    else
    {
        //printf("illegal pubkey.[%02x] %llx\n",pubkey[0],*(long long *)pubkey);
        return(-1);
    }
}

int32_t bitcoin_pubkeyspend(uint8_t *script,int32_t n,uint8_t pubkey[66])
{
    int32_t plen = bitcoin_pubkeylen(pubkey);
    script[n++] = plen;
    memcpy(&script[n],pubkey,plen);
    n += plen;
    script[n++] = SCRIPT_OP_CHECKSIG;
    return(n);
}

int32_t bitcoin_p2shspend(uint8_t *script,int32_t n,uint8_t rmd160[20])
{
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14; memcpy(&script[n],rmd160,0x14); n += 0x14;
    script[n++] = SCRIPT_OP_EQUAL;
    return(n);
}

int32_t bitcoin_secret160verify(uint8_t *script,int32_t n,uint8_t secret160[20])
{
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14;
    memcpy(&script[n],secret160,0x14);
    n += 0x14;
    script[n++] = SCRIPT_OP_EQUALVERIFY;
    return(n);
}

int32_t bitcoin_secret256spend(uint8_t *script,int32_t n,bits256 secret)
{
    script[n++] = SCRIPT_OP_SHA256;
    script[n++] = 0x20;
    memcpy(&script[n],secret.bytes,0x20);
    n += 0x20;
    script[n++] = SCRIPT_OP_EQUAL;
    return(n);
}

// OP_DUP OP_HASH160 <hash of pubkey> OP_EQUALVERIFY OP_CHECKSIG
int32_t bitcoin_standardspend(uint8_t *script,int32_t n,uint8_t rmd160[20])
{
    script[n++] = SCRIPT_OP_DUP;
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14; memcpy(&script[n],rmd160,0x14); n += 0x14;
    script[n++] = SCRIPT_OP_EQUALVERIFY;
    script[n++] = SCRIPT_OP_CHECKSIG;
    return(n);
}

int32_t bitcoin_checklocktimeverify(uint8_t *script,int32_t n,uint32_t locktime)
{
    script[n++] = 4;
    script[n++] = locktime & 0xff, locktime >>= 8;
    script[n++] = locktime & 0xff, locktime >>= 8;
    script[n++] = locktime & 0xff, locktime >>= 8;
    script[n++] = locktime & 0xff;
    script[n++] = SCRIPT_OP_CHECKLOCKTIMEVERIFY;
    script[n++] = SCRIPT_OP_DROP;
    return(n);
}

int32_t bitcoin_timelockspend(uint8_t *script,int32_t n,uint8_t rmd160[20],uint32_t timestamp)
{
    n = bitcoin_checklocktimeverify(script,n,timestamp);
    n = bitcoin_standardspend(script,n,rmd160);
    return(n);
}

int32_t bitcoin_MofNspendscript(uint8_t p2sh_rmd160[20],uint8_t *script,int32_t n,const struct vin_info *vp)
{
    int32_t i,plen;
    script[n++] = 0x50 + vp->M;
    for (i=0; i<vp->N; i++)
    {
        if ( (plen= bitcoin_pubkeylen(vp->signers[i].pubkey)) < 0 )
            return(-1);
        script[n++] = plen;
        memcpy(&script[n],vp->signers[i].pubkey,plen);
        n += plen;
    }
    script[n++] = 0x50 + vp->N;
    script[n++] = SCRIPT_OP_CHECKMULTISIG;
    calc_rmd160_sha256(p2sh_rmd160,script,n);
    return(n);
}

int32_t bitcoin_p2shscript(uint8_t *script,int32_t n,const uint8_t *p2shscript,const int32_t p2shlen)
{
    if ( p2shlen >= 0xfd )
    {
        script[n++] = 0x4d;
        script[n++] = (p2shlen & 0xff);
        script[n++] = ((p2shlen >> 8) & 0xff);
    }
    else if ( p2shlen > 76 )
    {
        script[n++] = 0x4c;
        script[n++] = p2shlen;
    } else script[n++] = p2shlen;
    memcpy(&script[n],p2shscript,p2shlen), n += p2shlen;
    return(n);
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

int32_t basilisk_swap_bobredeemscript(int32_t depositflag,int32_t *secretstartp,uint8_t *redeemscript,uint32_t locktime,bits256 pubA0,bits256 pubB0,bits256 pubB1,bits256 privAm,bits256 privBn,uint8_t *secretAm,uint8_t *secretAm256,uint8_t *secretBn,uint8_t *secretBn256)
{
    int32_t i,n=0; bits256 cltvpub,destpub,privkey; uint8_t pubkeyA[33],pubkeyB[33],secret160[20],secret256[32];
    if ( depositflag != 0 )
    {
        pubkeyA[0] = 0x02, cltvpub = pubA0;
        pubkeyB[0] = 0x03, destpub = pubB0;
        privkey = privBn;
        memcpy(secret160,secretBn,20);
        memcpy(secret256,secretBn256,32);
    }
    else
    {
        pubkeyA[0] = 0x03, cltvpub = pubB1;
        pubkeyB[0] = 0x02, destpub = pubA0;
        privkey = privAm;
        memcpy(secret160,secretAm,20);
        memcpy(secret256,secretAm256,32);
    }
    //for (i=0; i<32; i++)
    //    printf("%02x",secret256[i]);
    //printf(" <- secret256 depositflag.%d nonz.%d\n",depositflag,bits256_nonz(privkey));
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
    n = bitcoin_checklocktimeverify(redeemscript,n,locktime);
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
    return(n);
}

int32_t basilisk_bobscript(uint8_t *rmd160,uint8_t *redeemscript,int32_t *redeemlenp,uint8_t *script,int32_t n,uint32_t *locktimep,int32_t *secretstartp,struct basilisk_swapinfo *swap,int32_t depositflag)
{
    if ( depositflag != 0 )
        *locktimep = swap->started + swap->putduration + swap->callduration;
    else *locktimep = swap->started + swap->putduration;
    *redeemlenp = n = basilisk_swap_bobredeemscript(depositflag,secretstartp,redeemscript,*locktimep,swap->pubA0,swap->pubB0,swap->pubB1,swap->privAm,swap->privBn,swap->secretAm,swap->secretAm256,swap->secretBn,swap->secretBn256);
    if ( n > 0 )
    {
        calc_rmd160_sha256(rmd160,redeemscript,n);
        n = bitcoin_p2shspend(script,0,rmd160);
        //for (i=0; i<n; i++)
        //    printf("%02x",script[i]);
        //char str[65]; printf(" <- redeem.%d bobtx dflag.%d %s\n",n,depositflag,bits256_str(str,cltvpub));
    }
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

int32_t basilisk_priviextract(struct supernet_info *myinfo,struct iguana_info *coin,char *name,bits256 *destp,uint8_t secret160[20],bits256 srctxid,int32_t srcvout)
{
    bits256 txid,privkey; char str[65]; int32_t i,vini,scriptlen; uint8_t rmd160[20],scriptsig[IGUANA_MAXSCRIPTSIZE];
    memset(privkey.bytes,0,sizeof(privkey));
    // use dex_listtransactions!
    if ( (vini= iguana_vinifind(myinfo,coin,&txid,srctxid,srcvout)) >= 0 )
    {
        if ( (scriptlen= iguana_scriptsigextract(myinfo,coin,scriptsig,sizeof(scriptsig),txid,vini)) > 32 )
        {
            for (i=0; i<32; i++)
                privkey.bytes[i] = scriptsig[scriptlen - 33 + i];
            revcalc_rmd160_sha256(rmd160,privkey);//.bytes,sizeof(privkey));
            if ( memcmp(secret160,rmd160,sizeof(rmd160)) == sizeof(rmd160) )
            {
                *destp = privkey;
                printf("basilisk_priviextract found privi %s (%s)\n",name,bits256_str(str,privkey));
                return(0);
            }
        }
    }
    return(-1);
}

int32_t basilisk_confirmsobj(cJSON *item)
{
    int32_t height,numconfirms;
    height = jint(item,"height");
    numconfirms = jint(item,"numconfirms");
    if ( height > 0 && numconfirms >= 0 )
        return(numconfirms);
    printf("basilisk_confirmsobj height.%d numconfirms.%d (%s)\n",height,numconfirms,jprint(item,0));
    return(-1);
}

int32_t basilisk_numconfirms(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *rawtx)
{
    cJSON *argjson,*valuearray=0; char *valstr; int32_t i,n,retval = -1;
#ifdef BASILISK_DISABLEWAITTX
    return(100);
#endif
    argjson = cJSON_CreateObject();
    jaddbits256(argjson,"txid",rawtx->I.actualtxid);
    jaddnum(argjson,"vout",0);
    jaddstr(argjson,"coin",rawtx->coin->symbol);
    if ( (valstr= basilisk_value(myinfo,rawtx->coin,0,0,swap->persistent_pubkey,argjson,0)) != 0 )
    {
        char str[65]; printf("basilisk_numconfirms required.%d %s %s valstr.(%s)\n",rawtx->I.numconfirms,rawtx->name,bits256_str(str,rawtx->I.actualtxid),valstr);
        //basilisk_numconfirms required.0 alicespend 29a2a6b4a61b1da82096d533c71b6762d61a82ca771a633269d97c0ccb94fe85 valstr.({"result":"success","numconfirms":0,"address":"1JGvZ67oTdM7kCya4J8kj1uErbSRAoq3wH","satoshis":"1413818","value":0.01413818,"height":462440,"txid":"29a2a6b4a61b1da82096d533c71b6762d61a82ca771a633269d97c0ccb94fe85","vout":0,"coin":"BTC"})
        
        if ( (valuearray= cJSON_Parse(valstr)) != 0 )
        {
            if ( valstr[0] == '[' && is_cJSON_Array(valuearray) != 0 )
            {
                n = cJSON_GetArraySize(valuearray);
                for (i=0; i<n; i++)
                {
                    printf("i.%d of n.%d\n",i,n);
                    if ( (retval= basilisk_confirmsobj(jitem(valuearray,i))) >= 0 )
                        break;
                }
            } else retval = basilisk_confirmsobj(valuearray);
            free_json(valuearray);
        } else printf("parse error\n");
        free(valstr);
    }
    free_json(argjson);
    printf("numconfirms.%d returned\n",retval);
    return(retval);
}

bits256 basilisk_swap_broadcast(char *name,struct supernet_info *myinfo,struct basilisk_swap *swap,struct iguana_info *coin,uint8_t *data,int32_t datalen)
{
    bits256 txid; char *signedtx,*retstr; int32_t i;
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
        for (i=0; i<3; i++)
        {
            if ( (retstr= basilisk_sendrawtransaction(myinfo,coin,signedtx)) != 0 )
            {
                if ( is_hexstr(retstr,0) == 64 )
                {
                    decode_hex(txid.bytes,32,retstr);
                    free(retstr);
                    printf("sendrawtransaction %s.(%s)\n",name,bits256_str(str,txid));
                    break;
                }
                else
                {
                    printf("sendrawtransaction %s error.(%s)\n",name,retstr);
                    free(retstr);
                }
            } else printf("sendrawtransaction %s got null return\n",name);
        }
        free(signedtx);
    }
    return(txid);
}

int32_t _basilisk_rawtx_sign(struct supernet_info *myinfo,int32_t height,uint32_t timestamp,uint32_t locktime,uint32_t sequenceid,struct basilisk_rawtx *dest,struct basilisk_rawtx *rawtx,bits256 privkey,bits256 *privkey2,uint8_t *userdata,int32_t userdatalen,int32_t ignore_cltverr)
{
    char *rawtxbytes=0,*signedtx=0,hexstr[999],wifstr[128]; cJSON *txobj,*vins,*item,*sobj,*privkeys; int32_t needsig=1,retval = -1; struct vin_info *V;
    V = calloc(256,sizeof(*V));
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
    //printf("rawtx B\n");
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
    //printf("basilisk_rawtx_sign locktime.%u/%u for %s spendscript.%s -> %s, suppress.%d\n",rawtx->I.locktime,dest->I.locktime,rawtx->name,hexstr,dest->name,dest->I.suppress_pubkeys);
    txobj = bitcoin_txoutput(txobj,dest->spendscript,dest->I.spendlen,dest->I.amount);
    if ( (rawtxbytes= bitcoin_json2hex(myinfo,rawtx->coin,&dest->I.txid,txobj,V)) != 0 )
    {
        //printf("rawtx.(%s) vins.%p\n",rawtxbytes,vins);
        if ( needsig == 0 )
            signedtx = rawtxbytes;
        if ( signedtx != 0 || (signedtx= iguana_signrawtx(myinfo,rawtx->coin,height,&dest->I.signedtxid,&dest->I.completed,vins,rawtxbytes,privkeys,V)) != 0 )
        {
            dest->I.datalen = (int32_t)strlen(signedtx) >> 1;
            if ( dest->I.datalen <= sizeof(dest->txbytes) )
                decode_hex(dest->txbytes,dest->I.datalen,signedtx);
            else printf("DEX tx is too big %d vs %d\n",dest->I.datalen,(int32_t)sizeof(dest->txbytes));
            if ( signedtx != rawtxbytes )
                free(signedtx);
            if ( dest->I.completed != 0 )
                retval = 0;
            else printf("couldnt complete sign transaction %s\n",rawtx->name);
        } else printf("error signing\n");
        free(rawtxbytes);
    } else printf("error making rawtx\n");
    free_json(privkeys);
    free_json(txobj);
    free(V);
    return(retval);
}

int32_t basilisk_rawtx_sign(struct supernet_info *myinfo,int32_t height,struct basilisk_swap *swap,struct basilisk_rawtx *dest,struct basilisk_rawtx *rawtx,bits256 privkey,bits256 *privkey2,uint8_t *userdata,int32_t userdatalen,int32_t ignore_cltverr)
{
    uint32_t timestamp,locktime=0,sequenceid = 0xffffffff;
    timestamp = swap->I.started;
    if ( dest == &swap->aliceclaim )
        locktime = swap->bobdeposit.I.locktime + 1, sequenceid = 0;
    else if ( dest == &swap->bobreclaim )
        locktime = swap->bobpayment.I.locktime + 1, sequenceid = 0;
    return(_basilisk_rawtx_sign(myinfo,height,timestamp,locktime,sequenceid,dest,rawtx,privkey,privkey2,userdata,userdatalen,ignore_cltverr));
}

cJSON *basilisk_privkeyarray(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *vins)
{
    cJSON *privkeyarray,*item,*sobj; struct iguana_waddress *waddr; struct iguana_waccount *wacct; char coinaddr[64],account[128],wifstr[64],str[65],typestr[64],*hexstr; uint8_t script[1024]; int32_t i,n,len,vout; bits256 txid,privkey; double bidasks[2];
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
                    else if ( smartaddress(myinfo,typestr,bidasks,&privkey,coin->symbol,coinaddr) >= 0 )
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
            //rawtx->txbytes = calloc(1,rawtx->I.datalen);
            decode_hex(rawtx->txbytes,rawtx->I.datalen,signedtx);
            //printf("%s SIGNEDTX.(%s)\n",rawtx->name,signedtx);
            free(signedtx);
            retval = 0;
        } else printf("error signrawtx\n"); //do a very short timeout so it finishes via local poll
        free_json(privkeyarray);
    }
    return(retval);
}

int32_t _basilisk_rawtx_gen(char *str,struct supernet_info *myinfo,uint32_t swapstarted,uint8_t *pubkey33,int32_t iambob,int32_t lockinputs,struct basilisk_rawtx *rawtx,uint32_t locktime,uint8_t *script,int32_t scriptlen,int64_t txfee,int32_t minconf,int32_t delay)
{
    char *retstr,*jsonstr,scriptstr[1024],coinaddr[64]; uint32_t basilisktag; int32_t flag,i,n,retval = -1; cJSON *addresses,*valsobj,*retarray=0; struct vin_info *V;
    //bitcoin_address(coinaddr,rawtx->coin->chain->pubtype,myinfo->persistent_pubkey33,33);
    if ( rawtx->coin->changeaddr[0] == 0 )
    {
        bitcoin_address(rawtx->coin->changeaddr,rawtx->coin->chain->pubtype,pubkey33,33);
        printf("set change address.(%s)\n",rawtx->coin->changeaddr);
    }
    init_hexbytes_noT(scriptstr,script,scriptlen);
    basilisktag = (uint32_t)rand();
    valsobj = cJSON_CreateObject();
    jaddstr(valsobj,"coin",rawtx->coin->symbol);
    jaddstr(valsobj,"spendscript",scriptstr);
    jaddstr(valsobj,"changeaddr",rawtx->coin->changeaddr);
    jadd64bits(valsobj,"satoshis",rawtx->I.amount);
    if ( strcmp(rawtx->coin->symbol,"BTC") == 0 && txfee > 0 && txfee < 50000 )
        txfee = 50000;
    jadd64bits(valsobj,"txfee",txfee);
    jaddnum(valsobj,"minconf",minconf);
    if ( locktime == 0 )
        locktime = (uint32_t)time(NULL) - 777;
    jaddnum(valsobj,"locktime",locktime);
    jaddnum(valsobj,"timeout",30000);
    jaddnum(valsobj,"timestamp",swapstarted+delay);
    addresses = cJSON_CreateArray();
    bitcoin_address(coinaddr,rawtx->coin->chain->pubtype,pubkey33,33);
    jaddistr(addresses,coinaddr);
    jadd(valsobj,"addresses",addresses);
    rawtx->I.locktime = locktime;
    printf("%s locktime.%u\n",rawtx->name,locktime);
    V = calloc(256,sizeof(*V));
    if ( (retstr= basilisk_bitcoinrawtx(myinfo,rawtx->coin,"",basilisktag,jint(valsobj,"timeout"),valsobj,V)) != 0 )
    {
        printf("%s %s basilisk_bitcoinrawtx.(%s) txfee %.8f\n",rawtx->name,str,retstr,dstr(txfee));
        flag = 0;
        if ( (retarray= cJSON_Parse(retstr)) != 0 )
        {
            if ( is_cJSON_Array(retarray) != 0 )
            {
                n = cJSON_GetArraySize(retarray);
                for (i=0; i<n; i++)
                {
                    if ( (retval= basilisk_rawtx_return(myinfo,rawtx->coin->longestchain,rawtx,jitem(retarray,i),lockinputs,V)) == 0 )
                    {
                        rawtx->vins = jduplicate(jobj(jitem(retarray,i),"vins"));
                        jsonstr = jprint(rawtx->vins,0);
                        safecopy(rawtx->vinstr,jsonstr,sizeof(rawtx->vinstr));
                        free(jsonstr);
                        break;
                    }
                }
            }
            else
            {
                retval = basilisk_rawtx_return(myinfo,rawtx->coin->longestchain,rawtx,retarray,lockinputs,V);
                rawtx->vins = jduplicate(jobj(retarray,"vins"));
                jsonstr = jprint(rawtx->vins,0);
                safecopy(rawtx->vinstr,jsonstr,sizeof(rawtx->vinstr));
                free(jsonstr);
            }
            free(retarray);
        } else printf("error parsing.(%s)\n",retstr);
        free(retstr);
    } else printf("error creating %s %s\n",iambob != 0 ? "BOB" : "ALICE",rawtx->name);
    free_json(valsobj);
    free(V);
    return(retval);
}

int32_t basilisk_rawtx_gen(char *str,struct supernet_info *myinfo,uint32_t swapstarted,uint8_t *pubkey33,int32_t iambob,int32_t lockinputs,struct basilisk_rawtx *rawtx,uint32_t locktime,uint8_t *script,int32_t scriptlen,int64_t txfee,int32_t minconf,int32_t delay)
{
    int32_t retval,len; uint64_t newtxfee; struct iguana_info *coin;
    if ( (coin= rawtx->coin) == 0 || strcmp(coin->symbol,"BTC") != 0 )
        return(_basilisk_rawtx_gen(str,myinfo,swapstarted,pubkey33,iambob,lockinputs,rawtx,locktime,script,scriptlen,txfee,minconf,delay));
    retval = _basilisk_rawtx_gen(str,myinfo,swapstarted,pubkey33,iambob,0,rawtx,locktime,script,scriptlen,txfee,minconf,delay);
    len = rawtx->I.datalen;
    if ( coin->estimatedfee == 0 )
        coin->estimatedfee = iguana_getestimatedfee(myinfo,coin);
    newtxfee = coin->estimatedfee * len;
    if ( newtxfee > txfee )
    {
        retval = _basilisk_rawtx_gen(str,myinfo,swapstarted,pubkey33,iambob,lockinputs,rawtx,locktime,script,scriptlen,newtxfee,minconf,delay);
        printf("txfee %.8f -> newtxfee %.8f\n",dstr(txfee),dstr(newtxfee));
    }
    return(retval);
}
