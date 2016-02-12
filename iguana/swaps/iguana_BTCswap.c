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

#include "../exchanges/bitcoin.h"
/* https://bitcointalk.org/index.php?topic=1340621.msg13828271#msg13828271
Tier Nolan's approach is followed with the following changes:
  a) instead of cutting 1000 keypairs, only 777 are a
  b) instead of sending the entire 256 bits, it is truncated to 64 bits. With odds of collision being so low, it is dwarfed by the ~0.1% insurance factor.
  c) D is set to 100x the insurance rate of 1/777 12.87% + BTC amount
  d) insurance is added to Bob's payment, which is after the deposit and bailin
  e) BEFORE Bob broadcasts deposit, Alice broadcasts BTC denominated fee in cltv so if trade isnt done fee is reclaimed
*/

#define INSTANTDEX_INSURANCERATE (1. / 777.)
#define INSTANTDEX_PUBEY "03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06"
#define INSTANTDEX_RMD160 "ca1e04745e8ca0c60d8c5881531d51bec470743f"
#define TIERNOLAN_RMD160 "daedddd8dbe7a2439841ced40ba9c3d375f98146"
#define INSTANTDEX_BTC "1KRhTPvoxyJmVALwHFXZdeeWFbcJSbkFPu"
#define INSTANTDEX_BTCD "RThtXup6Zo7LZAi8kRWgjAyi1s4u6U9Cpf"
#define INSTANTDEX_MINPERC 50.

struct bitcoin_swapinfo
{
    bits256 privkeys[777],mypubs[2],otherpubs[2],pubBn,pubAm,dtxid,ptxid,aptxid,astxid,stxid,ftxid,othertrader;
    uint64_t otherscut[777][2],deck[777][2];
    int32_t isbob,choosei,otherschoosei,state,cutverified,otherverifiedcut;
    char altmsigaddr[64],*deposit,*payment,*altpayment,*altspend,*spendtx,*feetx;
};

int32_t instantdex_outputinsurance(struct iguana_info *coin,cJSON *txobj,int64_t insurance,uint64_t nonce)
{
    uint8_t rmd160[20],script[128]; int32_t n;
    decode_hex(rmd160,sizeof(rmd160),(nonce % 10) == 0 ? TIERNOLAN_RMD160 : INSTANTDEX_RMD160);
    n = bitcoin_standardspend(script,0,rmd160);
    bitcoin_addoutput(coin,txobj,script,n,insurance);
    return(n);
}

/*
 Alice fee:
 OP_IF
    <now + 1 days> OP_CLTV OP_DROP INSTANTDEX OP_CHECKSIG
 OP_ELSE
    <now + 2 days> OP_CLTV OP_DROP OP_HASH160 <hash(alice_priv_m)> OP_EQUALVERIFY <alice_pub_key_1001> OP_CHECKSIG
 OP_ENDIF
 
 Bob deposit:
 instantdex_bobscript(script,0,(uint32_t)(time(NULL)+INSTANTDEX_LOCKTIME*2),pubA0,privBn,pubB0);
 OP_IF
    <now + 2 days> OP_CLTV OP_DROP <alice_pub_1001> OP_CHECKSIG
 OP_ELSE
    OP_HASH160 <hash(bob_priv_n)> OP_EQUALVERIFY <bob_pub_1001> OP_CHECKSIG
 OP_ENDIF
 
Bobpays:
 instantdex_bobscript(script,0,(uint32_t)(time(NULL)+INSTANTDEX_LOCKTIME),pubB1,privAm,pubA0);
OP_IF
    <now + 1 day> OP_CLTV OP_DROP <bob_pub_1002> OP_CHECKSIG
OP_ELSE
    OP_HASH160 <hash(alice_priv_m)> OP_EQUALVERIFY <alice_pub_key_1001> OP_CHECKSIG
OP_ENDIF
*/

int32_t instantdex_bobscript(uint8_t *script,int32_t n,int32_t *secretstartp,uint32_t locktime,bits256 cltvpub,uint8_t secret160[20],bits256 destpub)
{
    uint8_t pubkeyA[33],pubkeyB[33];
    memcpy(pubkeyA+1,cltvpub.bytes,sizeof(cltvpub)), pubkeyA[0] = 0x02;
    memcpy(pubkeyB+1,destpub.bytes,sizeof(destpub)), pubkeyB[0] = 0x03;
    script[n++] = SCRIPT_OP_IF;
        n = bitcoin_checklocktimeverify(script,n,locktime);
        n = bitcoin_pubkeyspend(script,n,pubkeyA);
    script[n++] = SCRIPT_OP_ELSE;
    if ( secretstartp != 0 )
        *secretstartp = n + 2;
        n = bitcoin_revealsecret160(script,n,secret160);
        n = bitcoin_pubkeyspend(script,n,pubkeyB);
    script[n++] = SCRIPT_OP_ENDIF;
    return(n);
}

// OP_2 <alice_pub_m> <bob_pub_n> OP_2 OP_CHECKMULTISIG
int32_t instantdex_alicescript(uint8_t *script,int32_t n,char *msigaddr,uint8_t altps2h,bits256 pubAm,bits256 pubBn)
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

char *instantdex_bobtx(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,bits256 pubA0,bits256 pubB0,bits256 privBn,uint32_t reftime,int64_t amount,int32_t depositflag)
{
    cJSON *txobj; int32_t n,secretstart; char *signedtx = 0;
    uint8_t script[1024],secret[20]; struct bitcoin_spend *spend; int64_t insurance; uint32_t locktime;
    locktime = (uint32_t)(reftime + INSTANTDEX_LOCKTIME * (1 + depositflag));
    txobj = bitcoin_createtx(coin,locktime);
    insurance = (amount * INSTANTDEX_INSURANCERATE + coin->chain->txfee); // txfee prevents dust attack
    if ( (spend= iguana_spendset(myinfo,coin,amount + insurance,coin->chain->txfee)) != 0 )
    {
        calc_rmd160_sha256(secret,privBn.bytes,sizeof(privBn));
        n = instantdex_bobscript(script,0,&secretstart,locktime,pubA0,secret,pubB0);
        bitcoin_addoutput(coin,txobj,script,n,amount + depositflag*insurance*100);
        if ( depositflag == 0 )
            instantdex_outputinsurance(coin,txobj,insurance,pubB0.txid);
        txobj = iguana_signtx(coin,txidp,&signedtx,spend,txobj);
        if ( signedtx != 0  )
            printf("bob deposit.%s\n",signedtx);
        else printf("error signing bobdeposit numinputs.%d\n",spend->numinputs);
        free(spend);
    }
    free_json(txobj);
    return(signedtx);
}

uint64_t instantdex_relsatoshis(uint64_t price,uint64_t volume)
{
    if ( volume > price )
        return(price * dstr(volume));
    else return(dstr(price) * volume);
}

int32_t instantdex_paymentverify(struct supernet_info *myinfo,struct iguana_info *coin,struct bitcoin_swapinfo *swap,struct instantdex_accept *A,cJSON *argjson,int32_t depositflag)
{
    cJSON *txobj; bits256 txid; uint32_t n,locktime; int32_t i,secretstart,retval = -1; uint64_t x;
    struct iguana_msgtx msgtx; uint8_t script[512],rmd160[20]; int64_t insurance,relsatoshis,amount;
    if ( jstr(argjson,depositflag != 0 ? "deposit" : "payment") != 0 )
    {
        relsatoshis = instantdex_relsatoshis(A->offer.price64,A->offer.basevolume64);
        insurance = (relsatoshis * INSTANTDEX_INSURANCERATE + coin->chain->txfee); // txfee prevents dust attack
        if ( depositflag != 0 )
        {
            swap->deposit = clonestr(jstr(argjson,"deposit"));
            swap->dtxid = jbits256(argjson,"dtxid");
            swap->pubBn = jbits256(argjson,"pubBn");
            insurance *= 100;
        }
        amount = relsatoshis + insurance;
        if ( (txobj= bitcoin_hex2json(coin,&txid,&msgtx,swap->deposit)) != 0 )
        {
            locktime = A->offer.expiration;
            if ( depositflag == 0 )
                memset(rmd160,0,sizeof(rmd160));
            else calc_rmd160_sha256(rmd160,swap->privkeys[0].bytes,sizeof(rmd160));
            n = instantdex_bobscript(script,0,&secretstart,locktime,swap->mypubs[0],rmd160,swap->otherpubs[0]);
            if ( msgtx.lock_time == locktime && msgtx.vouts[0].value == amount && n == msgtx.vouts[0].pk_scriptlen )
            {
                memcpy(&script[secretstart],&msgtx.vouts[0].pk_script[secretstart],20);
                if ( memcmp(script,msgtx.vouts[0].pk_script,n) == 0 )
                {
                    iguana_rwnum(0,&script[secretstart],sizeof(x),&x);
                    printf("deposit script verified x.%llx vs otherscut %llx\n",(long long)x,(long long)swap->otherscut[swap->choosei][0]);
                    if ( x == swap->otherscut[swap->choosei][0] )
                    {
                        if ( depositflag == 0 )
                        {
                            decode_hex(rmd160,sizeof(rmd160),(swap->otherpubs[0].txid % 10) == 0 ? TIERNOLAN_RMD160 : INSTANTDEX_RMD160);
                            n = bitcoin_standardspend(script,0,rmd160);
                            if ( msgtx.vouts[1].value == insurance && n == msgtx.vouts[1].pk_scriptlen && memcmp(script,msgtx.vouts[1].pk_script,n) == 0 )
                                retval = 0;
                        } else retval = 0;
                    }
                    else printf("deposit script verified but secret mismatch x.%llx vs otherscut %llx\n",(long long)x,(long long)swap->otherscut[swap->choosei][0]);
                }
                else
                {
                    for (i=0; i<n; i++)
                        printf("%02x ",script[i]);
                    printf("script\n");
                    for (i=0; i<n; i++)
                        printf("%02x ",msgtx.vouts[0].pk_script[i]);
                    printf("deposit\n");
                }
            }
            free_json(txobj);
        }
    }
    return(retval);
}

char *instantdex_alicetx(struct supernet_info *myinfo,struct iguana_info *altcoin,char *msigaddr,bits256 *txidp,bits256 pubAm,bits256 pubBn,int64_t amount)
{
    cJSON *txobj; int32_t n; char *signedtx = 0;
    uint8_t script[1024]; struct bitcoin_spend *spend; int64_t insurance;
    txobj = bitcoin_createtx(altcoin,0);
    insurance = (amount * INSTANTDEX_INSURANCERATE + altcoin->chain->txfee); // txfee prevents dust attack
    if ( (spend= iguana_spendset(myinfo,altcoin,amount + insurance,altcoin->chain->txfee)) != 0 )
    {
        //instantdex_outputinsurance(altcoin,txobj,insurance);
        n = instantdex_alicescript(script,0,msigaddr,altcoin->chain->p2shtype,pubAm,pubBn);
        bitcoin_addoutput(altcoin,txobj,script,n,amount);
        txobj = iguana_signtx(altcoin,txidp,&signedtx,spend,txobj);
        if ( signedtx != 0 )
            printf("alice payment.%s\n",signedtx);
        else printf("error signing alicetx numinputs.%d\n",spend->numinputs);
        free(spend);
    }
    free_json(txobj);
    return(signedtx);
}

int32_t instantdex_altpaymentverify(struct supernet_info *myinfo,struct iguana_info *coin,struct bitcoin_swapinfo *swap,struct instantdex_accept *A,cJSON *argjson)
{
    cJSON *txobj; bits256 txid; uint32_t n; int32_t i,retval = -1;
    struct iguana_msgtx msgtx; uint8_t script[512]; char *altmsigaddr,msigaddr[64];
    if ( jstr(argjson,"altpayment") != 0 && (altmsigaddr= jstr(argjson,"altmsigaddr")) != 0 )
    {
        swap->altpayment = clonestr(jstr(argjson,"altpayment"));
        swap->aptxid = jbits256(argjson,"aptxid");
        swap->pubAm = jbits256(argjson,"pubAm");
        if ( (txobj= bitcoin_hex2json(coin,&txid,&msgtx,swap->altpayment)) != 0 )
        {
            n = instantdex_alicescript(script,0,msigaddr,coin->chain->p2shtype,swap->pubAm,swap->pubBn);
            if ( strcmp(msigaddr,altmsigaddr) == 0 && n == msgtx.vouts[0].pk_scriptlen )
            {
                if ( memcmp(script,msgtx.vouts[0].pk_script,n) == 0 )
                {
                    printf("deposit script verified\n");
                }
                else
                {
                    for (i=0; i<n; i++)
                        printf("%02x ",script[i]);
                    printf("altscript\n");
                    for (i=0; i<n; i++)
                        printf("%02x ",msgtx.vouts[0].pk_script[i]);
                    printf("altpayment\n");
                }
            }
            free_json(txobj);
        }
    }
    return(retval);
}

void instantdex_pendingnotice(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *ap,struct instantdex_accept *A)
{
    printf("need to start monitoring thread\n");
    ap->pendingvolume64 -= A->offer.basevolume64;
}

bits256 instantdex_derivekeypair(bits256 *newprivp,uint8_t pubkey[33],bits256 privkey,bits256 orderhash)
{
    bits256 sharedsecret;
    sharedsecret = curve25519_shared(privkey,orderhash);
    vcalc_sha256cat(newprivp->bytes,orderhash.bytes,sizeof(orderhash),sharedsecret.bytes,sizeof(sharedsecret));
    return(bitcoin_pubkey33(pubkey,*newprivp));
}

int32_t instantdex_pubkeyargs(struct bitcoin_swapinfo *swap,cJSON *newjson,int32_t numpubs,bits256 privkey,bits256 hash,int32_t firstbyte)
{
    char buf[3]; int32_t i,n,m,len=0; bits256 pubi; uint64_t txid; uint8_t secret160[20],pubkey[33];
    sprintf(buf,"%c0",'A' - 0x02 + firstbyte);
    for (i=n=m=0; i<numpubs*100 && n<numpubs; i++)
    {
        pubi = instantdex_derivekeypair(&swap->privkeys[n],pubkey,privkey,hash);
        privkey = swap->privkeys[n];
        //printf("i.%d n.%d numpubs.%d %02x vs %02x\n",i,n,numpubs,pubkey[0],firstbyte);
        if ( pubkey[0] != firstbyte )
            continue;
        if ( n < 2 && numpubs > 2 )
        {
            sprintf(buf+1,"%d",n);
            jaddbits256(newjson,buf,pubi);
        }
        else
        {
            calc_rmd160_sha256(secret160,swap->privkeys[n].bytes,sizeof(swap->privkeys[n]));
            memcpy(&txid,secret160,sizeof(txid));
            len += iguana_rwnum(1,(uint8_t *)&swap->deck[m][0],sizeof(txid),&txid);
            len += iguana_rwnum(1,(uint8_t *)&swap->deck[m][1],sizeof(pubi.txid),&pubi.txid);
            m++;
        }
        n++;
    }
    return(n);
}

char *instantdex_choosei(struct bitcoin_swapinfo *swap,cJSON *newjson,cJSON *argjson,uint8_t *serdata,int32_t datalen)
{
    int32_t i,j,max,len = 0; uint64_t x;
    if ( swap->choosei < 0 && serdata != 0 && datalen == sizeof(swap->deck) )
    {
        max = (int32_t)(sizeof(swap->otherscut) / sizeof(*swap->otherscut));
        for (i=0; i<max; i++)
            for (j=0; j<2; j++)
                len += iguana_rwnum(1,(uint8_t *)&swap->otherscut[i][j],sizeof(x),&serdata[len]);
        OS_randombytes((uint8_t *)&swap->choosei,sizeof(swap->choosei));
        swap->choosei %= max;
        jaddnum(newjson,"mychoosei",swap->choosei);
        return(0);
    }
    else
    {
        printf("invalid datalen.%d\n",datalen);
        return(clonestr("{\"error\":\"instantdex_BTCswap offer no cut\"}"));
    }
}

void instantdex_getpubs(struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson)
{
    char fields[2][2][3]; int32_t i,j,myind,otherind;
    memset(fields,0,sizeof(fields));
    fields[0][0][0] = fields[0][1][0] = 'A';
    fields[1][0][0] = fields[1][1][0] = 'B';
    for (i=0; i<2; i++)
        for (j=0; j<2; j++)
            fields[i][j][1] = '0' + j;
    myind = swap->isbob;
    otherind = (myind ^ 1);
    for (j=0; j<2; j++)
    {
        if ( bits256_nonz(swap->mypubs[j]) == 0 && jobj(argjson,fields[myind][j]) != 0 )
            swap->mypubs[j] = jbits256(newjson,fields[myind][j]);
        if ( bits256_nonz(swap->otherpubs[j]) == 0 && jobj(argjson,fields[otherind][j]) != 0 )
            swap->otherpubs[j] = jbits256(argjson,fields[otherind][j]);
    }
}

cJSON *instantdex_newjson(struct supernet_info *myinfo,struct bitcoin_swapinfo *swap,cJSON *argjson,bits256 hash,struct instantdex_accept *A,int32_t flag777,int32_t sendprivs)
{
    cJSON *newjson; char serstr[sizeof(bits256)*2+1],*hexstr=0; int32_t i,wrongfirstbyte,errs;
    bits256 hashpriv,pubi,otherpriv,*privs=0; uint8_t serialized[sizeof(bits256)],otherpubkey[33];
    newjson = cJSON_CreateObject();//instantdex_acceptsendjson(A);
    printf("acceptsend.(%s)\n",jprint(newjson,0));
    if ( swap->otherschoosei < 0 && jobj(argjson,"mychoosei") != 0 )
    {
        printf("otherschoosei.%d\n",swap->otherschoosei);
        if ( (swap->otherschoosei= juint(argjson,"mychoosei")) >= sizeof(swap->otherscut)/sizeof(*swap->otherscut) )
            swap->otherschoosei = -1;
    }
    if ( juint(argjson,"verified") != 0 )
        swap->otherverifiedcut = 1;
    printf("otherverified.%d\n",swap->otherverifiedcut);
    if ( jobj(argjson,"myprivs") != 0 && swap->cutverified == 0 )
    {
        printf("got privs\n");
        if ( (privs= calloc(1,sizeof(*swap->privkeys))) == 0 )
            printf("instantdex_newjson couldnt allocate hex\n");
        else if ( (hexstr= jstr(argjson,"myprivs")) == 0 || strlen(hexstr) != sizeof(swap->privkeys)*2 )
            printf("instantdex_newjson other's privkeys wrong size\n");
        else
        {
            for (i=wrongfirstbyte=errs=0; i<sizeof(swap->privkeys)/sizeof(*swap->privkeys); i++)
            {
                memcpy(serstr,&hexstr[i * sizeof(bits256)],sizeof(bits256));
                decode_hex(serialized,sizeof(bits256),serstr);
                iguana_rwbignum(0,serialized,sizeof(otherpriv),otherpriv.bytes);
                if ( i == swap->choosei )
                {
                    if ( bits256_nonz(otherpriv) != 0 )
                    {
                        printf("got privkey in slot.%d my choosi??\n",i);
                        errs++;
                    }
                    continue;
                }
                pubi = bitcoin_pubkey33(otherpubkey,otherpriv);
                vcalc_sha256(0,hashpriv.bytes,otherpriv.bytes,sizeof(otherpriv));
                if ( otherpubkey[0] != (swap->isbob ^ 1) + 0x02 )
                {
                    wrongfirstbyte++;
                    printf("wrongfirstbyte[%d] %02x\n",i,otherpubkey[0]);
                }
                else if ( swap->otherscut[i][0] != hashpriv.txid )
                {
                    printf("otherscut[%d] priv mismatch %llx != %llx\n",i,(long long)swap->otherscut[i][0],(long long)hashpriv.txid);
                    errs++;
                }
                else if ( swap->otherscut[i][1] != pubi.txid )
                {
                    printf("otherscut[%d] priv mismatch %llx != %llx\n",i,(long long)swap->otherscut[i][1],(long long)pubi.txid);
                    errs++;
                }
            }
            if ( errs == 0 && wrongfirstbyte == 0 )
                swap->cutverified = 1;
            else printf("failed verification: wrong firstbyte.%d errs.%d\n",wrongfirstbyte,errs);
        }
    }
    jaddnum(newjson,"verified",swap->otherverifiedcut);
    printf("otherverified.%d\n",swap->otherverifiedcut);
    if ( instantdex_pubkeyargs(swap,newjson,2+flag777*777,myinfo->persistent_priv,hash,0x02 + swap->isbob) != 2+flag777*777 )
    {
        printf("error generating pubkeyargs\n");
        return(0);
    }
    printf("call getpubs\n");
    instantdex_getpubs(swap,argjson,newjson);
    if ( sendprivs != 0 )
    {
        printf("sendprivs.%d\n",sendprivs);
        if ( swap->otherschoosei < 0 )
            printf("instantdex_newjson otherschoosei < 0 when sendprivs != 0\n");
        else
        {
            if ( privs == 0 && (privs= calloc(1,sizeof(*swap->privkeys))) == 0 )
                printf("instantdex_newjson couldnt allocate hex\n");
            else if ( hexstr == 0 && (hexstr= malloc(sizeof(*swap->privkeys) * 2 + 1)) == 0 )
                printf("instantdex_newjson couldnt allocate hexstr\n");
            else
            {
                memcpy(privs,swap->privkeys,sizeof(*swap->privkeys));
                memset(privs[swap->otherschoosei].bytes,0,sizeof(*privs));
                for (i=0; i<sizeof(swap->privkeys)/sizeof(*swap->privkeys); i++)
                {
                    iguana_rwbignum(1,serialized,sizeof(privs[i]),privs[i].bytes);
                    memcpy(privs[i].bytes,serialized,sizeof(privs[i]));
                }
                init_hexbytes_noT(hexstr,privs[0].bytes,sizeof(swap->privkeys));
                jaddstr(newjson,"myprivs",hexstr);
            }
        }
    }
    if ( privs != 0 )
        free(privs);
    if ( hexstr != 0 )
        free(hexstr);
    return(newjson);
}

char *instantdex_btcoffer(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A) // Bob sending to network (Alice)
{
    struct iguana_info *other; int32_t isbob = 1; struct bitcoin_swapinfo *swap;
    cJSON *newjson; bits256 orderhash; struct instantdex_accept *ap = 0;
     //orderhash = instantdex_acceptset(&A,othercoin,"BTC",INSTANTDEX_LOCKTIME*2,dir > 0 ? 1 : 0,-dir,price,othervolume,myinfo->myaddr.nxt64bits,nonce);
    //A.orderid = orderhash.txid;
    if ( strcmp(A->offer.rel,"BTC") != 0 )
    {
        printf("rel not BTC?!\n");
        return(clonestr("{\"error\":\"invalid othercoin\"}"));
    }
    else if ( (other= iguana_coinfind(A->offer.base)) == 0 )
        return(clonestr("{\"error\":\"invalid othercoin\"}"));
    else if ( A->offer.price64 <= 0 || A->offer.basevolume64 <= 0 )
    {
        printf("illegal price %.8f or volume %.8f\n",dstr(A->offer.price64),dstr(A->offer.basevolume64));
        return(clonestr("{\"error\":\"illegal price or volume\"}"));
    }
    isbob = A->offer.myside == 1;
    newjson = cJSON_CreateObject();
    swap = calloc(1,sizeof(struct bitcoin_swapinfo)), swap->isbob = isbob, swap->choosei = swap->otherschoosei = -1;
    vcalc_sha256(0,orderhash.bytes,(uint8_t *)&A->offer,sizeof(A->offer));
    if ( instantdex_pubkeyargs(swap,newjson,777+2,myinfo->persistent_priv,orderhash,0x02+isbob) != 777+2 )
    {
        printf("error from pubkeyargs\n");
        return(clonestr("{\"error\":\"highly unlikely run of 02 pubkeys\"}"));
    }
    if ( A->offer.price64 != 0 )
    {
        if ( (ap= instantdex_offerfind(myinfo,exchange,0,0,A->orderid,"*","*")) != 0 )
        {
            swap->state++;
            ap->info = swap;
            printf(">>>>>>>>>> PENDING ORDER %llu\n",(long long)A->orderid);
        }
    }
    if ( ap == 0 )
    {
        printf("couldnt find accept?? dir.%d orderid.%llu\n",ap->offer.acceptdir,(long long)A->orderid);
        free(swap);
        return(clonestr("{\"error\":\"couldnt find order just created\"}"));
    }
    else return(instantdex_sendcmd(myinfo,&ap->offer,newjson,"BTCoffer",GENESIS_PUBKEY,INSTANTDEX_HOPS,swap->deck,sizeof(swap->deck)));
}

char *instantdex_BTCswap(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,char *cmdstr,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *serdata,int32_t datalen) // receiving side
{
    char *retstr=0; uint64_t satoshis[2]; int32_t reftime,offerdir = 0; double minperc;
    struct instantdex_accept *ap; struct bitcoin_swapinfo *swap = 0; bits256 orderhash,traderpub;
    struct iguana_info *coinbtc,*altcoin; cJSON *newjson=0; uint8_t pubkey[33];
    if ( exchange == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap null exchange ptr\"}"));
    offerdir = instantdex_bidaskdir(A);
    coinbtc = iguana_coinfind("BTC");
    if ( (altcoin= iguana_coinfind(A->offer.base)) == 0 || coinbtc == 0 )
    {
        printf("other.%p coinbtc.%p (%s/%s)\n",altcoin,coinbtc,A->offer.base,A->offer.rel);
        return(clonestr("{\"error\":\"instantdex_BTCswap cant find btc or other coin info\"}"));
    }
    reftime = (uint32_t)(A->offer.expiration - INSTANTDEX_LOCKTIME*2);
    if ( strcmp(A->offer.rel,"BTC") != 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap offer non BTC rel\"}"));
    vcalc_sha256(0,orderhash.bytes,(void *)&A->offer,sizeof(ap->offer));
    if ( orderhash.txid != A->orderid )
        return(clonestr("{\"error\":\"txid mismatches orderid\"}"));
    satoshis[0] = A->offer.basevolume64;
    satoshis[1] = instantdex_relsatoshis(A->offer.price64,A->offer.basevolume64);
    swap = A->info;
    traderpub = jbits256(argjson,"traderpub");
    if ( (minperc= jdouble(argjson,"p")) < INSTANTDEX_MINPERC )
        minperc = INSTANTDEX_MINPERC;
    if ( swap == 0 && strcmp(cmdstr,"offer") != 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap no swap info after offer\"}"));
    printf("got offer.(%s/%s) %.8f vol %.8f %llu offerside.%d offerdir.%d swap.%p decksize.%ld\n",A->offer.base,A->offer.rel,dstr(A->offer.price64),dstr(A->offer.basevolume64),(long long)A->orderid,A->offer.myside,A->offer.acceptdir,A->info,sizeof(swap->deck));
    if ( swap != 0 )
        printf("found existing trade to match isbob.%d state.%d\n",swap->isbob,swap->state);
    if ( strcmp(cmdstr,"offer") == 0 ) // sender is Bob, receiver is network (Alice)
    {
        if ( A->offer.expiration < (time(NULL) + INSTANTDEX_DURATION) )
            return(clonestr("{\"error\":\"instantdex_BTCswap offer too close to expiration\"}"));
        if ( (ap= instantdex_acceptable(myinfo,exchange,A,acct777_nxt64bits(traderpub),minperc)) != 0 )
        {
            char str[65]; printf("FOUND MATCH! %p (%s/%s) other.%s\n",A->info,A->offer.base,A->offer.rel,bits256_str(str,traderpub));
            if ( A->info == 0 )
            {
                swap = calloc(1,sizeof(struct bitcoin_swapinfo));
                swap->choosei = swap->otherschoosei = -1;
                swap->state++;
                swap->othertrader = traderpub;
            }
            if ( (A->info= swap) != 0 )
            {
                if ( (newjson= instantdex_newjson(myinfo,swap,argjson,orderhash,A,1,0)) == 0 )
                    return(clonestr("{\"error\":\"instantdex_BTCswap offer null newjson\"}"));
                else
                {
                    //printf("NEWJSON.(%s)\n",jprint(newjson,0));
                    instantdex_pendingnotice(myinfo,exchange,ap,A);
                    if ( (retstr= instantdex_choosei(swap,argjson,newjson,serdata,datalen)) != 0 )
                    {
                        printf("Choosei.%s\n",retstr);
                        return(retstr);
                    }
                    else return(instantdex_sendcmd(myinfo,&A->offer,newjson,"BTCstep1",traderpub,INSTANTDEX_HOPS,swap->deck,sizeof(swap->deck)));
                }
            }
        }
        else
        {
            printf("no matching trade for %llu -> InstantDEX_minaccept\n",(long long)A->orderid);
            ap = calloc(1,sizeof(*ap));
            *ap = *A;
            queue_enqueue("acceptableQ",&exchange->acceptableQ,&ap->DL,0);
            retstr = clonestr("{\"result\":\"added new order to orderbook\"}");
        }
    }
    else if ( strcmp(cmdstr,"step1") == 0 && swap->state == 1 ) // either
    {
        printf("got step1, should have other's choosei\n");
        if ( (newjson= instantdex_newjson(myinfo,swap,argjson,orderhash,A,0,1)) == 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap step1 null newjson\"}"));
        else if ( swap->otherschoosei < 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap step1, no didnt choosei\"}"));
        else
        {
            swap->state++;
            if ( (retstr= instantdex_choosei(swap,argjson,newjson,serdata,datalen)) != 0 )
                return(retstr);
            if ( swap->isbob == 0 )
            {
                int64_t insurance = (satoshis[1] * INSTANTDEX_INSURANCERATE + coinbtc->chain->txfee); // txfee prevents dust attack
                if ( (swap->feetx= instantdex_bobtx(myinfo,coinbtc,&swap->ftxid,swap->otherpubs[0],swap->mypubs[0],swap->privkeys[swap->otherschoosei],reftime,insurance,1)) != 0 )
                {
                    jaddstr(newjson,"feetx",swap->feetx);
                    jaddbits256(newjson,"ftxid",swap->ftxid);
                    // broadcast to network
                }
            }
            return(instantdex_sendcmd(myinfo,&A->offer,newjson,swap->isbob != 0 ? "BTCstep1" : "BTCstep2",swap->othertrader,INSTANTDEX_HOPS,swap->deck,sizeof(swap->deck)));
        }
    }
    else if ( strcmp(cmdstr,"step2") == 0 && swap->isbob != 0 && swap->state == 2 ) // Bob
    {
        printf("got step2, should have other's privkeys\n");
        if ( (newjson= instantdex_newjson(myinfo,swap,argjson,orderhash,A,0,0)) == 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap step2 null newjson\"}"));
        else if ( swap->cutverified == 0 || swap->otherverifiedcut == 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap step2, both sides didnt validate\"}"));
        else //if ( instantdex_feeverify() == 0 )
        {
            swap->state++;
            //char *instantdex_bobtx(myinfo,coin,&paytxid,pubA0,pubB0,privAm,reftime,relsatoshis,0);
            if ( (swap->deposit= instantdex_bobtx(myinfo,coinbtc,&swap->dtxid,swap->otherpubs[0],swap->mypubs[0],swap->privkeys[swap->otherschoosei],reftime,satoshis[swap->isbob],1)) != 0 )
            {
                jaddstr(newjson,"deposit",swap->deposit);
                jaddbits256(newjson,"dtxid",swap->dtxid);
                jaddbits256(newjson,"pubBn",bitcoin_pubkey33(pubkey,swap->privkeys[swap->otherschoosei]));
                // broadcast to network
                return(instantdex_sendcmd(myinfo,&A->offer,newjson,"BTCstep3",swap->othertrader,INSTANTDEX_HOPS,0,0));
            } else return(clonestr("{\"error\":\"instantdex_BTCswap Bob step2, cant create deposit\"}"));
        } //else return(clonestr("{\"error\":\"instantdex_BTCswap step2 invalid fee\"}"));
    }
    else if ( strcmp(cmdstr,"step3") == 0 && swap->isbob == 0 && swap->state == 2 ) // Alice
    {
        printf("Alice got step3 should have Bob's choosei\n");
        if ( (newjson= instantdex_newjson(myinfo,swap,argjson,orderhash,A,0,0)) == 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap Alice step3 null newjson\"}"));
        else if ( swap->cutverified == 0 || swap->otherverifiedcut == 0 || bits256_nonz(swap->pubBn) == 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap step3, both sides didnt validate\"}"));
        else if ( instantdex_paymentverify(myinfo,coinbtc,swap,A,argjson,1) == 0 )
        {
            swap->state++;
            //char *instantdex_alicetx(myinfo,altcoin,&alicetxid,pubAm,pubBn,satoshis);
            swap->pubAm = bitcoin_pubkey33(pubkey,swap->privkeys[swap->otherschoosei]);
            if ( (swap->altpayment= instantdex_alicetx(myinfo,altcoin,swap->altmsigaddr,&swap->aptxid,swap->pubAm,swap->pubBn,satoshis[swap->isbob])) != 0 )
            {
                jaddstr(newjson,"altpayment",swap->altpayment);
                jaddstr(newjson,"altmsigaddr",swap->altmsigaddr);
                jaddbits256(newjson,"aptxid",swap->aptxid);
                jaddbits256(newjson,"pubAm",swap->pubAm);
                // broadcast to network
                return(instantdex_sendcmd(myinfo,&A->offer,newjson,"BTCstep4",swap->othertrader,INSTANTDEX_HOPS,0,0));
            } else return(clonestr("{\"error\":\"instantdex_BTCswap Alice step3, error making altpay\"}"));
        } else return(clonestr("{\"error\":\"instantdex_BTCswap Alice step3, invalid deposit\"}"));
    }
    else if ( strcmp(cmdstr,"step4") == 0 && swap->isbob != 0 && swap->state == 3 ) // Bob
    {
        printf("Bob got step4 should have Alice's altpayment\n");
        if ( (newjson= instantdex_newjson(myinfo,swap,argjson,orderhash,A,0,0)) == 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap Bob step4 null newjson\"}"));
        else if ( bits256_nonz(swap->pubAm) == 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap step4, no pubAm\"}"));
        else if ( instantdex_altpaymentverify(myinfo,altcoin,swap,A,argjson) == 0 )
        {
            swap->state++;
            if ( (swap->deposit= instantdex_bobtx(myinfo,coinbtc,&swap->ptxid,swap->mypubs[1],swap->otherpubs[0],swap->privkeys[swap->otherschoosei],reftime,satoshis[swap->isbob],0)) != 0 )
            {
                jaddstr(newjson,"payment",swap->payment);
                jaddbits256(newjson,"ptxid",swap->ptxid);
                // broadcast to network
                return(instantdex_sendcmd(myinfo,&A->offer,newjson,"BTCstep5",swap->othertrader,INSTANTDEX_HOPS,0,0));
            } else return(clonestr("{\"error\":\"instantdex_BTCswap Bob step4, cant create payment\"}"));
        } else return(clonestr("{\"error\":\"instantdex_BTCswap Alice step3, invalid deposit\"}"));
    }
    else if ( strcmp(cmdstr,"step5") == 0 && swap->isbob == 0 && swap->state == 4 ) // Alice
    {
        printf("Alice got step5 should have Bob's payment\n");
        if ( (newjson= instantdex_newjson(myinfo,swap,argjson,orderhash,A,0,0)) == 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap Alice step5 null newjson\"}"));
        else if ( instantdex_paymentverify(myinfo,coinbtc,swap,A,argjson,0) == 0 )
        {
            swap->state++;
            /*if ( (swap->spendtx= instantdex_spendpayment(myinfo,coinbtc,&swap->stxid,swap,argjson,newjson)) != 0 )
            {
                // broadcast to network
                return(instantdex_sendcmd(myinfo,&A->A,newjson,"BTCstep6",swap->othertrader,INSTANTDEX_HOPS));
            } else return(clonestr("{\"error\":\"instantdex_BTCswap Alice step5, cant spend payment\"}"));*/
        } else return(clonestr("{\"error\":\"instantdex_BTCswap Bob step6, invalid payment\"}"));
    }
    else if ( strcmp(cmdstr,"step6") == 0 ) // Bob
    {
        printf("Bob got step6 should have Alice's privkey\n");
        if ( (newjson= instantdex_newjson(myinfo,swap,argjson,orderhash,A,0,0)) == 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap Bob step6 null newjson\"}"));
        /*else if ( instantdex_spendverify(myinfo,coinbtc,swap,A,argjson,0) == 0 )
        {
            if ( (swap->altspend= instantdex_spendaltpayment(myinfo,altcoin,&swap->astxid,swap,argjson,newjson)) != 0 )
            {
                jaddstr(newjson,"altspend",swap->altspend);
                jaddbits256(newjson,"astxid",swap->astxid);
                // broadcast to network
                return(clonestr("{\"result\":\"Bob finished atomic swap\"}"));
            } else return(clonestr("{\"error\":\"instantdex_BTCswap Bob step6, cant spend altpayment\"}"));
        } else return(clonestr("{\"error\":\"instantdex_BTCswap Bob step6, invalid spend\"}"));*/
    }
    else retstr = clonestr("{\"error\":\"BTC swap got unrecognized command\"}");
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"BTC swap null retstr\"}");
    if ( swap != 0 )
        printf("BTCSWAP.(%s) isbob.%d state.%d verified.(%d %d)\n",retstr,swap->isbob,swap->state,swap->cutverified,swap->otherverifiedcut);
    else printf("BTCSWAP.(%s)\n",retstr);
    return(retstr);
}

#ifdef oldway
// https://github.com/TierNolan/bips/blob/bip4x/bip-atom.mediawiki

int32_t bitcoin_2of2spendscript(int32_t *paymentlenp,uint8_t *paymentscript,uint8_t *msigscript,bits256 pub0,bits256 pub1)
{
    struct vin_info V; uint8_t p2sh_rmd160[20]; int32_t p2shlen;
    memset(&V,0,sizeof(V));
    V.M = V.N = 2;
    memcpy(V.signers[0].pubkey+1,pub0.bytes,sizeof(pub0)), V.signers[0].pubkey[0] = 0x02;
    memcpy(V.signers[1].pubkey+1,pub1.bytes,sizeof(pub1)), V.signers[1].pubkey[0] = 0x03;
    p2shlen = bitcoin_MofNspendscript(p2sh_rmd160,msigscript,0,&V);
    *paymentlenp = bitcoin_p2shspend(paymentscript,0,p2sh_rmd160);
    return(p2shlen);
}

/*
 Name: Bob.Bail.In
 Input value:     B + 2*fb + change
 Input source:    (From Bob's coins, multiple inputs are allowed)
 vout0 value:  B,  ScriptPubKey 0:  OP_HASH160 Hash160(P2SH Redeem) OP_EQUAL
 vout1 value:  fb, ScriptPubKey 1:  OP_HASH160 Hash160(x) OP_EQUALVERIFY pub-A1 OP_CHECKSIG
 vout2 value:  change, ScriptPubKey 2:  <= 100 bytes
 P2SH Redeem:  OP_2 pub-A1 pub-B1 OP_2 OP_CHECKMULTISIG
 Name: Alice.Bail.In
 vins:  A + 2*fa + change, Input source: (From Alice's altcoins, multiple inputs are allowed)
 vout0 value: A,  ScriptPubKey 0: OP_HASH160 Hash160(P2SH Redeem) OP_EQUAL
 vout1 value: fa, ScriptPubKey 1: OP_HASH160 Hash160(x) OP_EQUAL
 vout2 value: change, ScriptPubKey 2: <= 100 bytes
 */
char *instantdex_bailintx(struct iguana_info *coin,bits256 *txidp,struct bitcoin_spend *spend,bits256 A0,bits256 B0,uint8_t x[20],int32_t isbob)
{
    uint64_t change; char *rawtxstr,*signedtx; struct vin_info *V; bits256 txid,signedtxid;
    int32_t p2shlen,i; cJSON *txobj;  int32_t scriptv0len,scriptv1len,scriptv2len;
    uint8_t p2shscript[256],scriptv0[128],scriptv1[128],changescript[128],pubkey[35];
    p2shlen = bitcoin_2of2spendscript(&scriptv0len,scriptv0,p2shscript,A0,B0);
    txobj = bitcoin_createtx(coin,0);
    bitcoin_addoutput(coin,txobj,scriptv0,scriptv0len,spend->satoshis);
    if ( isbob != 0 )
    {
        scriptv1len = bitcoin_revealsecret160(scriptv1,0,x);
        scriptv1len = bitcoin_pubkeyspend(scriptv1,scriptv1len,pubkey);
    } else scriptv1len = bitcoin_p2shspend(scriptv1,0,x);
    bitcoin_addoutput(coin,txobj,scriptv1,scriptv1len,spend->txfee);
    if ( (scriptv2len= bitcoin_changescript(coin,changescript,0,&change,spend->changeaddr,spend->input_satoshis,spend->satoshis,spend->txfee)) > 0 )
        bitcoin_addoutput(coin,txobj,changescript,scriptv2len,change);
    for (i=0; i<spend->numinputs; i++)
        bitcoin_addinput(coin,txobj,spend->inputs[i].txid,spend->inputs[i].vout,0xffffffff);
    rawtxstr = bitcoin_json2hex(coin,&txid,txobj);
    char str[65]; printf("%s_bailin.%s (%s)\n",isbob!=0?"bob":"alice",bits256_str(str,txid),rawtxstr);
    V = calloc(spend->numinputs,sizeof(*V));
    for (i=0; i<spend->numinputs; i++)
        V[i].signers[0].privkey = spend->inputs[i].privkey;
    bitcoin_verifytx(coin,&signedtxid,&signedtx,rawtxstr,V);
    free(rawtxstr), free(V);
    if ( signedtx != 0 )
        printf("signed %s_bailin.%s (%s)\n",isbob!=0?"bob":"alice",bits256_str(str,signedtxid),signedtx);
    else printf("error generating signedtx\n");
    free_json(txobj);
    *txidp = txid;
    return(signedtx);
}

cJSON *instantdex_bailinspend(struct iguana_info *coin,bits256 privkey,uint64_t amount)
{
    int32_t n; cJSON *txobj;
    int32_t scriptv0len; uint8_t p2shscript[256],rmd160[20],scriptv0[128],pubkey[35];
    bitcoin_pubkey33(pubkey,privkey);
    n = bitcoin_pubkeyspend(p2shscript,0,pubkey);
    calc_rmd160_sha256(rmd160,p2shscript,n);
    scriptv0len = bitcoin_p2shspend(scriptv0,0,rmd160);
    txobj = bitcoin_createtx(coin,0);
    bitcoin_addoutput(coin,txobj,scriptv0,scriptv0len,amount);
    return(txobj);
}

/*
 Name: Bob.Payout
 vin0:  A, Input source: Alice.Bail.In:0
 vin1:  fa, Input source: Alice.Bail.In:1
 vout0: A, ScriptPubKey: OP_HASH160 Hash160(P2SH Redeem) OP_EQUAL; P2SH Redeem:  pub-B2 OP_CHECKSIG
 
 Name: Alice.Payout
 vin0:  B, Input source: Bob.Bail.In:0
 vin1:  fb, Input source: Bob.Bail.In:1
 vout0: B, ScriptPubKey: OP_HASH160 Hash160(P2SH Redeem) OP_EQUAL; P2SH Redeem:  pub-A2 OP_CHECKSIG
 */

char *instantdex_bailinsign(struct iguana_info *coin,bits256 bailinpriv,char *sigstr,int32_t *siglenp,bits256 *txidp,struct vin_info *V,cJSON *txobj,int32_t isbob)
{
    char *rawtxstr,*signedtx;
    rawtxstr = bitcoin_json2hex(coin,txidp,txobj);
    char str[65]; printf("%s_payout.%s (%s)\n",isbob!=0?"bob":"alice",bits256_str(str,*txidp),rawtxstr);
    V->signers[isbob].privkey = bailinpriv;
    bitcoin_verifytx(coin,txidp,&signedtx,rawtxstr,V);
    *siglenp = V->signers[isbob].siglen;
    init_hexbytes_noT(sigstr,V->signers[isbob].sig,*siglenp);
    free(rawtxstr);
    if ( signedtx != 0 )
        printf("signed %s_payout.%s (%s) sig.%s\n",isbob!=0?"bob":"alice",bits256_str(str,*txidp),signedtx,sigstr);
    else printf("error generating signedtx\n");
    free_json(txobj);
    return(signedtx);
}

char *instantdex_payouttx(struct iguana_info *coin,char *sigstr,int32_t *siglenp,bits256 *txidp,bits256 *sharedprivs,bits256 bailintxid,int64_t amount,int64_t txfee,int32_t isbob,char *othersigstr)
{
    struct vin_info V; cJSON *txobj;
    txobj = instantdex_bailinspend(coin,sharedprivs[1],amount);
    bitcoin_addinput(coin,txobj,bailintxid,0,0xffffffff);
    bitcoin_addinput(coin,txobj,bailintxid,1,0xffffffff);
    memset(&V,0,sizeof(V));
    if ( othersigstr != 0 )
    {
        printf("OTHERSIG.(%s)\n",othersigstr);
        V.signers[isbob ^ 1].siglen = (int32_t)strlen(othersigstr) >> 1;
        decode_hex(V.signers[isbob ^ 1].sig,V.signers[isbob ^ 1].siglen,othersigstr);
    }
    return(instantdex_bailinsign(coin,sharedprivs[0],sigstr,siglenp,txidp,&V,txobj,isbob));
}

/*
 Name: Alice.Refund
 vin0: A, Input source: Alice.Bail.In:0
 vout0: A - fa, ScriptPubKey: OP_HASH160 Hash160(P2SH) OP_EQUAL; P2SH Redeem:  pub-A3 OP_CHECKSIG
 Locktime: current block height + ((T/2)/(altcoin block rate))
 
 Name: Bob.Refund
 vin0:  B, Input source: Bob.Bail.In:0
 vout0: B - fb, ScriptPubKey: OP_HASH160 Hash160(P2SH Redeem) OP_EQUAL; P2SH Redeem:  pub-B3 OP_CHECKSIG
 Locktime:     (current block height) + (T / 10 minutes)
 */
char *instantdex_refundtx(struct iguana_info *coin,bits256 *txidp,bits256 bailinpriv,bits256 priv2,bits256 bailintxid,int64_t amount,int64_t txfee,int32_t isbob)
{
    char sigstr[256]; int32_t siglen; struct vin_info V; cJSON *txobj;
    txobj = instantdex_bailinspend(coin,priv2,amount - txfee);
    bitcoin_addinput(coin,txobj,bailintxid,0,0xffffffff);
    return(instantdex_bailinsign(coin,bailinpriv,sigstr,&siglen,txidp,&V,txobj,isbob));
}

int32_t instantdex_calcx20(char hexstr[41],uint8_t *p2shscript,uint8_t firstbyte,bits256 pub)
{
    uint8_t pubkey[33],rmd160[20]; int32_t n;
    memcpy(pubkey+1,pub.bytes,sizeof(pub)), pubkey[0] = firstbyte;
    n = bitcoin_pubkeyspend(p2shscript,0,pubkey);
    calc_rmd160_sha256(rmd160,p2shscript,n);
    init_hexbytes_noT(hexstr,rmd160,sizeof(rmd160));
    return(n);
}

char *instantdex_bailinrefund(struct supernet_info *myinfo,struct iguana_info *coin,struct exchange_info *exchange,struct instantdex_accept *A,char *nextcmd,uint8_t secret160[20],cJSON *newjson,int32_t isbob,bits256 A0,bits256 B0,bits256 *sharedprivs)
{
    struct bitcoin_spend *spend; char *bailintx,*refundtx,field[64]; bits256 bailintxid,refundtxid;
    if ( bits256_nonz(A0) > 0 && bits256_nonz(B0) > 0 )
    {
        if ( (spend= instantdex_spendset(myinfo,coin,A->offer.basevolume64,INSTANTDEX_DONATION)) != 0 )
        {
            bailintx = instantdex_bailintx(coin,&bailintxid,spend,A0,B0,secret160,0);
            refundtx = instantdex_refundtx(coin,&refundtxid,sharedprivs[0],sharedprivs[2],bailintxid,A->offer.basevolume64,coin->chain->txfee,isbob);
            if ( A->statusjson == 0 )
                A->statusjson = cJSON_CreateObject();
            sprintf(field,"bailin%c",'A'+isbob), jaddstr(A->statusjson,field,bailintx), free(bailintx);
            sprintf(field,"refund%c",'A'+isbob), jaddstr(A->statusjson,field,refundtx), free(refundtx);
            sprintf(field,"bailintx%c",'A'+isbob), jaddbits256(A->statusjson,field,bailintxid);
            sprintf(field,"bailintxid%c",'A'+isbob), jaddbits256(newjson,field,bailintxid);
            free(spend);
            return(instantdex_sendcmd(myinfo,&A->A,newjson,nextcmd,swap->othertrader,INSTANTDEX_HOPS));
        } else return(clonestr("{\"error\":\"couldnt create bailintx\"}"));
    } else return(clonestr("{\"error\":\"dont have pubkey0 pair\"}"));
}

cJSON *instantdex_payout(struct supernet_info *myinfo,struct iguana_info *coin,struct exchange_info *exchange,struct instantdex_accept *A,uint8_t secret160[20],int32_t isbob,bits256 *A0p,bits256 *B0p,bits256 *sharedprivs,bits256 hash,uint64_t satoshis[2],cJSON *argjson)
{
    cJSON *newjson; char field[32],payoutsigstr[256],*signedpayout; int32_t payoutsiglen; bits256 payouttxid,bailintxid;
    if ( (newjson= instantdex_newjson(myinfo,A0p,B0p,sharedprivs,secret160,isbob,argjson,hash,A)) == 0 )
        return(0);
    sprintf(field,"bailintxid%c",'A' + (isbob^1)), bailintxid = jbits256(argjson,field);
    sprintf(field,"payoutsig%c",'A' + (isbob^1));
    if ( (signedpayout= instantdex_payouttx(coin,payoutsigstr,&payoutsiglen,&payouttxid,sharedprivs,bailintxid,satoshis[isbob],coin->chain->txfee,isbob,jstr(argjson,field))) != 0 )
    {
        sprintf(field,"payoutsig%c",'A'+isbob), jaddstr(newjson,field,payoutsigstr);
        if ( A->statusjson == 0 )
            A->statusjson = cJSON_CreateObject();
        sprintf(field,"payout%c",'A'+isbob), jaddstr(A->statusjson,field,signedpayout);
        free(signedpayout);
    }
    return(newjson);
}

char *instantdex_advance(struct supernet_info *myinfo,bits256 *sharedprivs,int32_t isbob,cJSON *argjson,bits256 hash,char *addfield,char *nextstate,struct instantdex_accept *A)
{
    cJSON *newjson; bits256 A0,B0; uint8_t secret160[20];
    if ( (newjson= instantdex_newjson(myinfo,&A0,&B0,sharedprivs,secret160,isbob,argjson,hash,A)) == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap offer null newjson\"}"));
    if ( A->statusjson != 0 && jstr(A->statusjson,addfield) != 0 )
    {
        jaddstr(newjson,addfield,jstr(A->statusjson,addfield));
        if ( nextstate != 0 )
            return(instantdex_sendcmd(myinfo,&A->A,newjson,nextstate,swap->othertrader,INSTANTDEX_HOPS));
        else return(clonestr("{\"result\":\"instantdex_BTCswap advance complete, wait or refund\"}"));
    } else return(clonestr("{\"error\":\"instantdex_BTCswap advance cant find statusjson\"}"));
}

char *instantdex_BTCswap(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,char *cmdstr,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen) // receiving side
{
    uint8_t secret160[20]; bits256 hash,traderpub,A0,B0,sharedprivs[4]; uint64_t satoshis[2];
    cJSON *newjson; struct instantdex_accept *ap; char *retstr=0,*str;
    int32_t locktime,isbob=0,offerdir = 0; struct iguana_info *coinbtc,*other;
    if ( exchange == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap null exchange ptr\"}"));
    offerdir = instantdex_bidaskdir(A);
    if ( (other= iguana_coinfind(A->offer.base)) == 0 || (coinbtc= iguana_coinfind("BTC")) == 0 )
    {
        printf("other.%p coinbtc.%p (%s/%s)\n",other,coinbtc,A->offer.base,A->offer.rel);
        return(clonestr("{\"error\":\"instantdex_BTCswap cant find btc or other coin info\"}"));
    }
    locktime = (uint32_t)(A->offer.expiration + INSTANTDEX_LOCKTIME);
    if ( strcmp(A->offer.rel,"BTC") != 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap offer non BTC rel\"}"));
    vcalc_sha256(0,hash.bytes,(void *)&A->A,sizeof(ap->offer));
    if ( hash.txid != A->orderid )
        return(clonestr("{\"error\":\"txid mismatches orderid\"}"));
    satoshis[0] = A->offer.basevolume64;
    satoshis[1] = instantdex_relsatoshis(A->offer.price64,A->offer.basevolume64);
    printf("got offer.(%s) offerside.%d offerdir.%d\n",jprint(argjson,0),A->offer.myside,A->offer.acceptdir);
    if ( strcmp(cmdstr,"offer") == 0 ) // sender is Bob, receiver is network (Alice)
    {
        if ( A->offer.expiration < (time(NULL) + INSTANTDEX_DURATION) )
            return(clonestr("{\"error\":\"instantdex_BTCswap offer too close to expiration\"}"));
        if ( (ap= instantdex_acceptable(exchange,A,myinfo->myaddr.nxt64bits)) != 0 )
        {
            isbob = 0;
            if ( (newjson= instantdex_newjson(myinfo,&A0,&B0,sharedprivs,secret160,isbob,argjson,hash,A)) == 0 )
                return(clonestr("{\"error\":\"instantdex_BTCswap offer null newjson\"}"));
            else
            {
                // should add to orderbook if not accepted
                instantdex_pendingnotice(myinfo,exchange,ap,A);
                return(instantdex_bailinrefund(myinfo,other,exchange,A,"proposal",secret160,newjson,isbob,A0,B0,sharedprivs));
            }
        }
        else
        {
            printf("no matching trade.(%s)\n",jprint(argjson,0));
            if ( (str= InstantDEX_minaccept(myinfo,0,argjson,0,A->offer.base,"BTC",dstr(A->offer.price64),dstr(A->offer.basevolume64))) != 0 )
                free(str);
        }
    }
    else if ( strcmp(cmdstr,"proposal") == 0 ) // sender is Alice, receiver is Bob
    {
        isbob = 1;
        newjson = instantdex_payout(myinfo,coinbtc,exchange,A,secret160,isbob,&A0,&B0,sharedprivs,hash,satoshis,argjson);
        return(instantdex_bailinrefund(myinfo,coinbtc,exchange,A,"BTCaccept",secret160,newjson,isbob,A0,B0,sharedprivs));
    }
    else if ( strcmp(cmdstr,"accept") == 0 ) // sender is Bob, receiver is Alice
    {
        isbob = 0;
        newjson = instantdex_payout(myinfo,other,exchange,A,secret160,isbob,&A0,&B0,sharedprivs,hash,satoshis,argjson);
        return(instantdex_sendcmd(myinfo,&A->A,newjson,"BTCconfirm",swap->othertrader,INSTANTDEX_HOPS));
    }
    else if ( strcmp(cmdstr,"confirm") == 0 ) // sender is Alice, receiver is Bob
    {
        isbob = 1;
        newjson = instantdex_payout(myinfo,coinbtc,exchange,A,secret160,isbob,&A0,&B0,sharedprivs,hash,satoshis,argjson);
        return(instantdex_sendcmd(myinfo,&A->A,newjson,"BTCbroadcast",swap->othertrader,INSTANTDEX_HOPS));
    }
    else if ( strcmp(cmdstr,"broadcast") == 0 ) // sender is Bob, receiver is Alice
    {
        isbob = 0;
        return(instantdex_advance(myinfo,sharedprivs,isbob,argjson,hash,"bailintxA","BTCcommit",A));
    }
    else if ( strcmp(cmdstr,"commit") == 0 ) // sender is Alice, receiver is Bob
    {
        isbob = 1;
        // go into refund state, ie watch for payouts to complete or get refund
        return(instantdex_advance(myinfo,sharedprivs,isbob,argjson,hash,"payoutB","BTCcomplete",A));
    }
    else if ( strcmp(cmdstr,"complete") == 0 ) // sender is Bob, receiver is Alice
    {
        isbob = 0;
        // go into refund state, ie watch for payouts to complete or get refund
        return(instantdex_advance(myinfo,sharedprivs,isbob,argjson,hash,"payoutA",0,A));
    }
    else retstr = clonestr("{\"error\":\"BTC swap got unrecognized command\"}");
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"BTC swap null retstr\"}");
    return(retstr);
}

#endif

