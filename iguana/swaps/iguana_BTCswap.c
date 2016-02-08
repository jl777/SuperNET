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

// https://github.com/TierNolan/bips/blob/bip4x/bip-atom.mediawiki

uint64_t instantdex_relsatoshis(uint64_t price,uint64_t volume)
{
    if ( volume > price )
        return(price * dstr(volume));
    else return(dstr(price) * volume);
}

bits256 instantdex_sharedpub256(uint8_t pubkey[33],bits256 privkey,bits256 hash,int32_t n)
{
    bits256 tmppriv,shared,iters; int32_t i;
    iters = shared = curve25519_shared(privkey,hash);
    for (i=0; i<n; i++)
        iters = curve25519(iters,curve25519(iters,curve25519_basepoint9()));
    vcalc_sha256cat(tmppriv.bytes,shared.bytes,sizeof(shared),iters.bytes,sizeof(iters));
    return(bitcoin_pubkey33(pubkey,tmppriv));
}

int32_t instantdex_pubkeyargs(cJSON *argjson,int32_t numpubs,bits256 privkey,bits256 hash,int32_t firstbyte)
{
    char buf[3]; int32_t i,n; bits256 tmp; uint8_t pubkey[33];
    sprintf(buf,"%c0",'A' - 0x02 + firstbyte);
    for (i=n=0; i<numpubs*100&&n<numpubs; i++)
    {
        tmp = instantdex_sharedpub256(pubkey,privkey,hash,i+1);
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

/*struct bitcoin_unspent { bits256 txid,privkey; uint64_t value; int32_t vout; };
struct bitcoin_spend
{
    char changeaddr[64];
    int32_t numinputs;
    uint64_t txfee,input_satoshis,satoshis;
    struct bitcoin_unspent inputs[];
};*/

char *instantdex_bailintx(struct iguana_info *coin,bits256 *txidp,struct bitcoin_spend *spend,bits256 A0,bits256 B0,uint8_t x[20],int32_t isbob)
{
/*Input value:     B + 2*fb + change
Input source:    (From Bob's coins, multiple inputs are allowed)
                  Output 0 value:  B
                  ScriptPubKey 0:  OP_HASH160 Hash160(P2SH Redeem) OP_EQUAL
                  Output 1 value:  fb
                  ScriptPubKey 1:  OP_HASH160 Hash160(x) OP_EQUALVERIFY pub-A1 OP_CHECKSIG
                  Output 2 value:  change
                  ScriptPubKey 2:  <= 100 bytes
                  P2SH Redeem:  OP_2 pub-A1 pub-B1 OP_2 OP_CHECKMULTISIG
Name: Alice.Bail.In
    Input value:  A + 2*fa + change
    Input source: (From Alice's altcoins, multiple inputs are allowed)
                   Output 0 value: A
                   ScriptPubKey 0: OP_HASH160 Hash160(P2SH Redeem) OP_EQUAL
                   Output 1 value: fa
                   ScriptPubKey 1: OP_HASH160 Hash160(x) OP_EQUAL
                   Output 2 value: change
                   ScriptPubKey 2: <= 100 bytes*/
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
        printf("signed bob_bailin.%s (%s)\n",bits256_str(str,signedtxid),signedtx);
    else printf("error generating signedtx\n");
    free_json(txobj);
    *txidp = txid;
    return(signedtx);
}

int32_t instantdex_calcx20(char hexstr[41],uint8_t *p2shscript,uint8_t firstbyte,bits256 pub3)
{
    uint8_t pubkey[33],script[64],rmd160[20]; int32_t n; bits256 hash;
    memcpy(pubkey+1,pub3.bytes,sizeof(pub3)), pubkey[0] = firstbyte;
    n = bitcoin_pubkeyspend(p2shscript,0,pubkey);
    vcalc_sha256(0,hash.bytes,script,n);
    calc_rmd160(0,rmd160,hash.bytes,sizeof(hash.bytes));
    init_hexbytes_noT(hexstr,rmd160,sizeof(rmd160));
    return(n);
}

char *instantdex_btcoffer(struct supernet_info *myinfo,struct exchange_info *exchange,char *othercoin,double othervolume,double maxprice) // Bob sending to network (Alice)
{
    char *str,coinaddr[64],xstr[41]; uint8_t xscript[64]; struct iguana_info *other;
    struct instantdex_accept A; cJSON *newjson; bits256 hash,pub3;
    if ( othercoin == 0 || (other= iguana_coinfind(othercoin)) == 0 )
        return(clonestr("{\"error\":\"invalid othercoin\"}"));
    hash = instantdex_acceptset(&A,othercoin,"BTC",INSTANTDEX_OFFERDURATION,1,-1,maxprice,othervolume,myinfo->myaddr.nxt64bits);
    newjson = instantdex_acceptsendjson(&A);
    if ( instantdex_pubkeyargs(newjson,4,myinfo->persistent_priv,hash,0x03) != 4 )
        return(clonestr("{\"error\":\"highly unlikely run of 02 pubkeys\"}"));
    pub3 = jbits256(newjson,"B3");
    jdelete(newjson,"B3");
    instantdex_calcx20(xstr,xscript,0x03,pub3);
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

char *instantdex_BTCswap(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,char *cmdstr,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen) // receiving side
{
    uint8_t script[999],p2sh_rmd160[20],secret160[20],pubkey[36],addrtype;
    bits256 hash,bailintxid,A0,B0; struct bitcoin_spend SPEND;
    struct instantdex_accept *ap; uint64_t satoshis,othersatoshis,orderid;
    char p2sh_coinaddr[64],*senderaddr,otheraddr[64],base[24],coinaddr[64],*retstr,*bailintx;
    int32_t scriptlen,locktime,offerdir = 0; struct iguana_info *coinbtc,*other; cJSON *newjson;
    retstr = 0;
    memset(&SPEND,0,sizeof(SPEND));
    if ( exchange == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap null exchange ptr\"}"));
    offerdir = instantdex_bidaskdir(A);
    if ( (other= iguana_coinfind(A->A.base)) == 0 || (coinbtc= iguana_coinfind("BTC")) == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap cant find btc or other coin info\"}"));
    locktime = (uint32_t)(A->A.expiration + INSTANTDEX_OFFERDURATION);
    if ( A->A.rel == 0 || strcmp(A->A.rel,"BTC") != 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap offer non BTC rel\"}"));
    if ( strcmp(cmdstr,"offer") == 0 ) // sender is Bob, receiver is network (Alice)
    {
        // should add to orderbook if not accepted
        if ( A->A.expiration < (time(NULL) + INSTANTDEX_DURATION) )
            return(clonestr("{\"error\":\"instantdex_BTCswap offer too close to expiration\"}"));
        printf("got offer.(%s) offerside.%d offerdir.%d\n",jprint(argjson,0),A->A.myside,A->A.acceptdir);
        if ( (ap= instantdex_acceptable(exchange,A,myinfo->myaddr.nxt64bits)) != 0 )
        {
            ap->pendingvolume64 -= A->A.basevolume64;
            satoshis = instantdex_relsatoshis(A->A.price64,A->A.basevolume64);
            newjson = cJSON_CreateObject();
            if ( instantdex_pubkeyargs(argjson,3,myinfo->persistent_priv,hash,0x02) != 3 )
                return(clonestr("{\"error\":\"highly unlikely run of 03 pubkeys\"}"));
            jadd64bits(newjson,"id",A->orderid);
            jadd64bits(newjson,"BTC",satoshis);
            jadd64bits(newjson,"v",A->A.basevolume64);
            jaddstr(newjson,"b",other->symbol);
            jaddstr(newjson,other->symbol,otheraddr);
            jaddstr(newjson,"p2sh",p2sh_coinaddr);
            bailintx = instantdex_bailintx(coinbtc,&bailintxid,&SPEND,A0,B0,secret160,1);
            jaddstr(newjson,"bailin",bailintx);
            jaddbits256(newjson,"bailintxid",bailintxid);
            free(bailintx);
            return(instantdex_sendcmd(myinfo,newjson,"proposal",myinfo->ipaddr,INSTANTDEX_HOPS));
        } else printf("no matching trade.(%s)\n",jprint(argjson,0));
    }
    else if ( strcmp(cmdstr,"proposal") == 0 ) // sender is Alice, receiver is Bob
    {
        satoshis = j64bits(argjson,"BTC");
        orderid = j64bits(argjson,"id");
        othersatoshis = j64bits(argjson,"v");
        senderaddr = myinfo->myaddr.BTC;
        if ( jobj(argjson,other->symbol) != 0 )
            safecopy(otheraddr,jstr(argjson,other->symbol),sizeof(otheraddr));
        if ( jobj(argjson,"b") != 0 )
            safecopy(base,jstr(argjson,"b"),sizeof(base));
        printf("proposal orderid.%llu BTC satoshis %.8f for %s vol %.8f ps2h.%s\n",A->orderid,dstr(satoshis),base,dstr(othersatoshis),p2sh_coinaddr);
        if ( A->orderid != orderid )
        {
            printf("orderid mismatch %llu vs %llu\n",(long long)orderid,(long long)A->orderid);
            return(clonestr("{\"error\":\"instantdex_BTCswap orderid mismatch\"}"));
        }
        if ( senderaddr == 0 || strcmp(A->A.base,base) != 0 || strcmp(A->A.rel,"BTC") != 0 )
        {
            printf("senderaddr.%p base.(%s vs %s) rel.(%s vs %s)\n",senderaddr,A->A.base,base,A->A.rel,"BTC");
            return(clonestr("{\"error\":\"instantdex_BTCswap base or rel mismatch\"}"));
        }
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
        if ( satoshis != instantdex_relsatoshis(A->A.price64,A->A.basevolume64) )
        {
            printf("satoshis mismatch %llu vs %llu\n",(long long)satoshis,(long long)instantdex_relsatoshis(A->A.price64,A->A.basevolume64));
            return(clonestr("{\"error\":\"instantdex_BTCswap satoshis mismatch\"}"));
        }
        if ( othersatoshis != A->A.basevolume64 )
        {
            printf("othersatoshis mismatch %llu vs %llu\n",(long long)satoshis,(long long)A->A.basevolume64);
            return(clonestr("{\"error\":\"instantdex_BTCswap satoshis mismatch\"}"));
        }
 //        return(instantdex_sendcmd(myinfo,newjson,"accept",myinfo->ipaddr,INSTANTDEX_HOPS));
    }
    else if ( strcmp(cmdstr,"accept") == 0 ) // sender is Bob, receiver is Alice
    {
        
    }
    else if ( strcmp(cmdstr,"confirm") == 0 ) // both send and receive
    {
        
    }
    else retstr = clonestr("{\"error\":\"BTC swap got unrecognized command\"}");
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"BTC swap null retstr\"}");
    return(retstr);
}
