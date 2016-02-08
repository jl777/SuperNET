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
/*
bitcoin_pubkey33(pubkey,myinfo->persistent_priv);
bitcoin_address(coinaddr,other->chain->pubtype,pubkey,sizeof(pubkey));
bitcoin_addr2rmd160(&addrtype,secret160,coinaddr);
scriptlen = bitcoin_cltvscript(coinbtc->chain->p2shtype,p2sh_coinaddr,p2sh_rmd160,script,0,senderaddr,otheraddr,secret160,locktime);
if ( jobj(argjson,"p2sh") != 0 )
{
    if ( strcmp(jstr(argjson,"p2sh"),p2sh_coinaddr) != 0 )
    {
        printf("mismatched p2sh.(%s) vs (%s)\n",jstr(argjson,"p2sh"),p2sh_coinaddr);
        return(clonestr("{\"error\":\"instantdex_BTCswap base or rel mismatch\"}"));
    }
}
*/
#define INSTANTDEX_DONATION 2000

// https://github.com/TierNolan/bips/blob/bip4x/bip-atom.mediawiki

uint64_t instantdex_relsatoshis(uint64_t price,uint64_t volume)
{
    if ( volume > price )
        return(price * dstr(volume));
    else return(dstr(price) * volume);
}

bits256 instantdex_sharedpub256(bits256 *sharedprivp,uint8_t pubkey[33],bits256 privkey,bits256 hash,int32_t n)
{
    bits256 shared,iters; int32_t i;
    iters = shared = curve25519_shared(privkey,hash);
    for (i=0; i<n; i++)
        iters = curve25519(iters,curve25519(iters,curve25519_basepoint9()));
    vcalc_sha256cat(sharedprivp->bytes,shared.bytes,sizeof(shared),iters.bytes,sizeof(iters));
    return(bitcoin_pubkey33(pubkey,*sharedprivp));
}

int32_t instantdex_pubkeyargs(bits256 *sharedprivs,cJSON *argjson,int32_t numpubs,bits256 privkey,bits256 hash,int32_t firstbyte)
{
    char buf[3]; int32_t i,n; bits256 tmp; uint8_t pubkey[33];
    sprintf(buf,"%c0",'A' - 0x02 + firstbyte);
    for (i=n=0; i<numpubs*100&&n<numpubs; i++)
    {
        tmp = instantdex_sharedpub256(&sharedprivs[n],pubkey,privkey,hash,i+1);
        if ( pubkey[0] != firstbyte )
            continue;
        buf[1] = '0' + n++;
        jaddbits256(argjson,buf,tmp);
    }
    return(n);
}

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

struct bitcoin_unspent *instantdex_bestfit(struct iguana_info *coin,struct bitcoin_unspent *unspents,int32_t numunspents,uint64_t value,int32_t mode)
{
    int32_t i; uint64_t above,below,gap,atx_value; struct bitcoin_unspent *vin,*abovevin,*belowvin;
    abovevin = belowvin = 0;
    for (above=below=i=0; i<numunspents; i++)
    {
        vin = &unspents[i];
        atx_value = vin->value;
        //printf("(%.8f vs %.8f)\n",dstr(atx_value),dstr(value));
        if ( atx_value == value )
            return(vin);
        else if ( atx_value > value )
        {
            gap = (atx_value - value);
            if ( above == 0 || gap < above )
            {
                above = gap;
                abovevin = vin;
            }
        }
        else if ( mode == 0 )
        {
            gap = (value - atx_value);
            if ( below == 0 || gap < below )
            {
                below = gap;
                belowvin = vin;
            }
        }
    }
    if ( (vin= (abovevin != 0) ? abovevin : belowvin) == 0 && mode == 1 )
        vin = unspents;
    return(vin);
}

struct bitcoin_unspent *iguana_unspentsget(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *numunspentsp)
{
    struct bitcoin_unspent *ups = calloc(1,sizeof(*ups));
    // struct bitcoin_unspent { bits256 txid,privkey; uint64_t value; int32_t vout; };
    *numunspentsp = 0;
    return(ups);
}

struct bitcoin_spend *instantdex_spendset(struct supernet_info *myinfo,struct iguana_info *coin,uint64_t satoshis,uint64_t donation)
{
    int32_t i,mode,numunspents,maxinputs = 1024; int64_t remains; struct bitcoin_unspent *ptr,*up;
    struct bitcoin_unspent *ups; struct bitcoin_spend *spend;
    if ( (ups= iguana_unspentsget(myinfo,coin,&numunspents)) == 0 )
        return(0);
    spend = calloc(1,sizeof(*spend) + sizeof(*spend->inputs) * maxinputs);
    spend->satoshis = satoshis;
    spend->txfee = coin->chain->txfee;
    if ( strcmp(coin->symbol,"BTC") == 0 )
        remains = spend->txfee + spend->satoshis + donation;
    ptr = spend->inputs;
    for (i=0; i<maxinputs; i++,ptr++)
    {
        for (mode=1; mode>=0; mode--)
            if ( (up= instantdex_bestfit(coin,ups,numunspents,remains,mode)) != 0 )
                break;
        if ( up != 0 )
        {
            spend->input_satoshis += up->value;
            spend->inputs[spend->numinputs++] = *up;
            if ( spend->input_satoshis >= satoshis )
            {
                spend->netamount = (spend->input_satoshis - spend->txfee - donation);
                spend->change = (spend->input_satoshis - spend->netamount);
                printf("numinputs %d sum %.8f vs satoshis %.8f change %.8f -> txfee %.8f\n",spend->numinputs,dstr(spend->input_satoshis),dstr(satoshis),dstr(spend->change),dstr(spend->input_satoshis - spend->change - spend->netamount));
                break;
            }
            remains -= up->value;
        } else break;
    }
    if ( spend->input_satoshis >= (satoshis + spend->txfee) )
    {
        realloc(spend,sizeof(*spend) + sizeof(*spend->inputs) * spend->numinputs);
        return(spend);
    }
    else
    {
        free(spend);
        return(0);
    }
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
    bits256 hash; int32_t n; cJSON *txobj;
    int32_t scriptv0len; uint8_t p2shscript[256],rmd160[20],scriptv0[128],pubkey[35];
    bitcoin_pubkey33(pubkey,privkey);
    n = bitcoin_pubkeyspend(p2shscript,0,pubkey);
    vcalc_sha256(0,hash.bytes,p2shscript,n);
    calc_rmd160(0,rmd160,hash.bytes,sizeof(hash.bytes));
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
    uint8_t pubkey[33],rmd160[20]; int32_t n; bits256 hash;
    memcpy(pubkey+1,pub.bytes,sizeof(pub)), pubkey[0] = firstbyte;
    n = bitcoin_pubkeyspend(p2shscript,0,pubkey);
    vcalc_sha256(0,hash.bytes,p2shscript,n);
    calc_rmd160(0,rmd160,hash.bytes,sizeof(hash.bytes));
    init_hexbytes_noT(hexstr,rmd160,sizeof(rmd160));
    return(n);
}

char *instantdex_btcoffer(struct supernet_info *myinfo,struct exchange_info *exchange,char *othercoin,double othervolume,double maxprice) // Bob sending to network (Alice)
{
    char *str,coinaddr[64],xstr[41]; uint8_t xscript[64]; struct iguana_info *other; int32_t isbob = 1;
    struct instantdex_accept A; cJSON *newjson; bits256 hash,pub3,sharedprivs[4];
    if ( othercoin == 0 || (other= iguana_coinfind(othercoin)) == 0 )
        return(clonestr("{\"error\":\"invalid othercoin\"}"));
    hash = instantdex_acceptset(&A,othercoin,"BTC",INSTANTDEX_OFFERDURATION,1,-1,maxprice,othervolume,myinfo->myaddr.nxt64bits);
    newjson = instantdex_acceptsendjson(&A);
    if ( instantdex_pubkeyargs(sharedprivs,newjson,4,myinfo->persistent_priv,hash,0x02+isbob) != 4 )
        return(clonestr("{\"error\":\"highly unlikely run of 02 pubkeys\"}"));
    pub3 = jbits256(newjson,"B3");
    jdelete(newjson,"B3");
    instantdex_calcx20(xstr,xscript,0x02+isbob,pub3);
    jaddstr(newjson,"x",xstr);
    if ( coinaddr[0] != 0 )
        jaddstr(newjson,othercoin,coinaddr);
    if ( maxprice > 0. )
    {
        if ( (str= InstantDEX_maxaccept(myinfo,0,newjson,0,othercoin,"BTC",maxprice,othervolume)) != 0 )
            free(str);
    }
    return(instantdex_sendcmd(myinfo,newjson,"BTCoffer",myinfo->ipaddr,INSTANTDEX_HOPS));
}

void instantdex_pendingnotice(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *ap,struct instantdex_accept *A)
{
    printf("need to start monitoring thread\n");
    ap->pendingvolume64 -= A->A.basevolume64;
}

cJSON *instantdex_newjson(struct supernet_info *myinfo,bits256 *A0p,bits256 *B0p,bits256 *sharedprivs,uint8_t secret160[20],int32_t isbob,cJSON *argjson,bits256 hash)
{
    cJSON *newjson = cJSON_CreateObject(); char *xstr;
    if ( instantdex_pubkeyargs(sharedprivs,newjson,3+isbob,myinfo->persistent_priv,hash,0x02+isbob) != 3 )
        return(0);
    if ( isbob == 0 )
        *A0p = jbits256(newjson,"A0");
    else *A0p = jbits256(argjson,"A0");
    *B0p = jbits256(argjson,"B0");
    if ( (xstr= jstr(argjson,"x")) != 0 )
    {
        decode_hex(secret160,20,xstr);
        jaddstr(newjson,"x",xstr);
    }
    return(newjson);
}

char *instantdex_bailinrefund(struct supernet_info *myinfo,struct iguana_info *coin,struct exchange_info *exchange,struct instantdex_accept *A,char *nextcmd,uint8_t secret160[20],cJSON *newjson,int32_t isbob,bits256 A0,bits256 B0,bits256 *sharedprivs)
{
    struct bitcoin_spend *spend; char *bailintx,*refundtx,field[64]; bits256 bailintxid,refundtxid;
    if ( bits256_nonz(A0) > 0 && bits256_nonz(B0) > 0 )
    {
        if ( (spend= instantdex_spendset(myinfo,coin,A->A.basevolume64,INSTANTDEX_DONATION)) != 0 )
        {
            bailintx = instantdex_bailintx(coin,&bailintxid,spend,A0,B0,secret160,0);
            refundtx = instantdex_refundtx(coin,&refundtxid,sharedprivs[0],sharedprivs[2],bailintxid,A->A.basevolume64,coin->chain->txfee,isbob);
            if ( A->statusjson == 0 )
                A->statusjson = cJSON_CreateObject();
            sprintf(field,"bailin%c",'A'+isbob), jaddstr(A->statusjson,field,bailintx), free(bailintx);
            sprintf(field,"refund%c",'A'+isbob), jaddstr(A->statusjson,field,refundtx), free(refundtx);
            sprintf(field,"bailintx%c",'A'+isbob), jaddbits256(A->statusjson,field,bailintxid);
            sprintf(field,"bailintxid%c",'A'+isbob), jaddbits256(newjson,field,bailintxid);
            free(spend);
            return(instantdex_sendcmd(myinfo,newjson,nextcmd,myinfo->ipaddr,INSTANTDEX_HOPS));
        } else return(clonestr("{\"error\":\"couldnt create bailintx\"}"));
    } else return(clonestr("{\"error\":\"dont have pubkey0 pair\"}"));
}

cJSON *instantdex_payout(struct supernet_info *myinfo,struct iguana_info *coin,struct exchange_info *exchange,struct instantdex_accept *A,uint8_t secret160[20],int32_t isbob,bits256 *A0p,bits256 *B0p,bits256 *sharedprivs,bits256 hash,uint64_t satoshis[2],cJSON *argjson)
{
    cJSON *newjson; char field[32],payoutsigstr[256],*signedpayout; int32_t payoutsiglen; bits256 payouttxid,bailintxid;
    if ( (newjson= instantdex_newjson(myinfo,A0p,B0p,sharedprivs,secret160,isbob,argjson,hash)) == 0 )
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
    if ( (newjson= instantdex_newjson(myinfo,&A0,&B0,sharedprivs,secret160,isbob,argjson,hash)) == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap offer null newjson\"}"));
    if ( A->statusjson != 0 && jstr(A->statusjson,addfield) != 0 )
    {
        jaddstr(newjson,addfield,jstr(A->statusjson,addfield));
        if ( nextstate != 0 )
            return(instantdex_sendcmd(myinfo,newjson,nextstate,myinfo->ipaddr,INSTANTDEX_HOPS));
        else return(clonestr("{\"result\":\"instantdex_BTCswap advance complete, wait or refund\"}"));
    } else return(clonestr("{\"error\":\"instantdex_BTCswap advance cant find statusjson\"}"));
}

char *instantdex_BTCswap(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,char *cmdstr,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen) // receiving side
{
    uint8_t secret160[20]; bits256 hash,A0,B0,sharedprivs[4]; uint64_t satoshis[2]; cJSON *newjson;
    struct instantdex_accept *ap; char *retstr=0,*str;
    int32_t locktime,isbob=0,offerdir = 0; struct iguana_info *coinbtc,*other;
    if ( exchange == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap null exchange ptr\"}"));
    offerdir = instantdex_bidaskdir(A);
    if ( (other= iguana_coinfind(A->A.base)) == 0 || (coinbtc= iguana_coinfind("BTC")) == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap cant find btc or other coin info\"}"));
    locktime = (uint32_t)(A->A.expiration + INSTANTDEX_OFFERDURATION);
    if ( A->A.rel == 0 || strcmp(A->A.rel,"BTC") != 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap offer non BTC rel\"}"));
    vcalc_sha256(0,hash.bytes,(void *)&A->A,sizeof(ap->A));
    if ( hash.txid != A->orderid )
        return(clonestr("{\"error\":\"txid mismatches orderid\"}"));
    satoshis[0] = A->A.basevolume64;
    satoshis[1] = instantdex_relsatoshis(A->A.price64,A->A.basevolume64);
    printf("got offer.(%s) offerside.%d offerdir.%d\n",jprint(argjson,0),A->A.myside,A->A.acceptdir);
    if ( strcmp(cmdstr,"offer") == 0 ) // sender is Bob, receiver is network (Alice)
    {
        if ( A->A.expiration < (time(NULL) + INSTANTDEX_DURATION) )
            return(clonestr("{\"error\":\"instantdex_BTCswap offer too close to expiration\"}"));
        if ( (ap= instantdex_acceptable(exchange,A,myinfo->myaddr.nxt64bits)) != 0 )
        {
            isbob = 0;
            if ( (newjson= instantdex_newjson(myinfo,&A0,&B0,sharedprivs,secret160,isbob,argjson,hash)) == 0 )
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
            if ( (str= InstantDEX_minaccept(myinfo,0,argjson,0,A->A.base,"BTC",dstr(A->A.price64),dstr(A->A.basevolume64))) != 0 )
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
        return(instantdex_sendcmd(myinfo,newjson,"BTCconfirm",myinfo->ipaddr,INSTANTDEX_HOPS));
    }
    else if ( strcmp(cmdstr,"confirm") == 0 ) // sender is Alice, receiver is Bob
    {
        isbob = 1;
        newjson = instantdex_payout(myinfo,coinbtc,exchange,A,secret160,isbob,&A0,&B0,sharedprivs,hash,satoshis,argjson);
        return(instantdex_sendcmd(myinfo,newjson,"BTCbroadcast",myinfo->ipaddr,INSTANTDEX_HOPS));
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
