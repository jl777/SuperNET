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

int32_t instantdex_bobscript(uint8_t *script,int32_t n,uint32_t *locktimep,int32_t *secretstartp,struct bitcoin_swapinfo *swap,int32_t depositflag)
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
    if ( bits256_nonz(cltvpub) == 0 || bits256_nonz(destpub) == 0 )
        return(-1);
    for (i=0; i<20; i++)
        if ( secret160[i] != 0 )
            break;
    if ( i == 20 )
        return(-1);
    memcpy(pubkeyA+1,cltvpub.bytes,sizeof(cltvpub));
    memcpy(pubkeyB+1,destpub.bytes,sizeof(destpub));
    script[n++] = SCRIPT_OP_IF;
    n = bitcoin_checklocktimeverify(script,n,*locktimep);
    n = bitcoin_pubkeyspend(script,n,pubkeyA);
    script[n++] = SCRIPT_OP_ELSE;
    if ( secretstartp != 0 )
        *secretstartp = n + 2;
    n = bitcoin_revealsecret160(script,n,secret160);
    n = bitcoin_pubkeyspend(script,n,pubkeyB);
    script[n++] = SCRIPT_OP_ENDIF;
    return(n);
}

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

int32_t instantdex_outputinsurance(char *coinaddr,uint8_t addrtype,uint8_t *script,int64_t insurance,uint64_t r,uint64_t dest)
{
    uint8_t rmd160[20]; int32_t n = 0;
    decode_hex(rmd160,sizeof(rmd160),(dest % 10) == 9 ? TIERNOLAN_RMD160 : INSTANTDEX_RMD160);
    //script[n++] = sizeof(r);
    //n += iguana_rwnum(1,&script[n],sizeof(r),&r);
    //script[n++] = SCRIPT_OP_DROP;
    bitcoin_address(coinaddr,addrtype,rmd160,20);
    n = bitcoin_standardspend(script,n,rmd160);
    return(n);
}

void disp_tx(struct supernet_info *myinfo,struct iguana_info *coin,char *str,char *txbytes)
{
    cJSON *txobj; bits256 txid;
    txobj = bitcoin_hex2json(coin,&txid,0,txbytes);
    printf("disp_tx (%s) -> %s.(%s)\n",txbytes,str,jprint(txobj,1));
}

struct bitcoin_statetx *instantdex_getstatetx(struct bitcoin_swapinfo *swap,char *txname)
{
    //char *txnames[] = { "fee", "dep", "alt", "acl", "bre", "bcl", "bfr", "are", "adp" };
    if ( strcmp(txname,"fee") == 0 )
        return(swap->otherfee);
    else if ( strcmp(txname,"dep") == 0 )
        return(swap->deposit);
    else if ( strcmp(txname,"alt") == 0 )
        return(swap->altpayment);
    else if ( strcmp(txname,"acl") == 0 )
        return(swap->payment);
    else if ( strcmp(txname,"bre") == 0 )
        return(swap->deposit);
    else if ( strcmp(txname,"bcl") == 0 )
        return(swap->altpayment);
    else if ( strcmp(txname,"bfr") == 0 )
        return(swap->myfee);
    else if ( strcmp(txname,"are") == 0 )
        return(swap->altpayment);
    else if ( strcmp(txname,"adp") == 0 )
        return(swap->deposit);
    printf("unrecognized txname.(%s)\n",txname);
    return(0);
}

void iguana_addinputs(struct iguana_info *coin,struct bitcoin_spend *spend,cJSON *txobj,uint32_t sequence)
{
    int32_t i,j,plen; uint8_t *pubkeyptrs[16];
    for (i=0; i<spend->numinputs; i++)
    {
        spend->inputs[i].sequence = sequence;
        for (j=0; j<16; j++)
        {
            if ( (plen= bitcoin_pubkeylen(spend->inputs[i].pubkeys[j])) < 0 )
                break;
            pubkeyptrs[j] = spend->inputs[i].pubkeys[j];
        }
        bitcoin_txinput(coin,txobj,spend->inputs[i].txid,spend->inputs[i].vout,spend->inputs[i].sequence,spend->inputs[i].spendscript,spend->inputs[i].spendlen,spend->inputs[i].p2shscript,spend->inputs[i].p2shlen,j>0?pubkeyptrs:0,j);
    }
}

struct bitcoin_statetx *instantdex_signtx(char *str,struct supernet_info *myinfo,struct iguana_info *coin,uint32_t locktime,char *scriptstr,int64_t satoshis,int64_t txfee,int32_t minconf,int32_t myside)
{
    struct iguana_waddress *waddr; struct iguana_waccount *wacct; struct bitcoin_statetx *tx=0; uint8_t pubkey33[33]; char coinaddr[64],wifstr[64]; char *rawtx,*signedtx,*retstr; bits256 signedtxid; uint32_t rawtxtag; int32_t flag,completed; cJSON *valsobj,*vins,*retjson=0,*privkey,*argjson,*addresses;
    if ( (waddr= iguana_getaccountaddress(myinfo,coin,0,0,coin->changeaddr,"change")) == 0 )
        return(0);
    privkey = cJSON_CreateArray();
    addresses = cJSON_CreateArray();
    if ( coin->changeaddr[0] == 0 )
        bitcoin_address(coin->changeaddr,coin->chain->pubtype,waddr->rmd160,20);
    bitcoin_pubkey33(myinfo->ctx,pubkey33,myinfo->persistent_priv);
    bitcoin_address(coinaddr,coin->chain->pubtype,pubkey33,33);
    //printf("%s persistent.(%s) (%s) change.(%s) scriptstr.(%s)\n",coin->symbol,myinfo->myaddr.BTC,coinaddr,coin->changeaddr,scriptstr);
    if ( (waddr= iguana_waddresssearch(myinfo,coin,&wacct,coinaddr)) != 0 )
    {
        bitcoin_priv2wif(wifstr,waddr->privkey,coin->chain->wiftype);
        jaddistr(privkey,waddr->wifstr);
    }
    jaddistr(addresses,coinaddr);
    valsobj = cJSON_CreateObject();
    jaddstr(valsobj,"coin",coin->symbol);
    jadd64bits(valsobj,"amount",satoshis);
    jadd64bits(valsobj,"txfee",txfee);
    jaddnum(valsobj,"minconf",minconf);
    rawtxtag = (uint32_t)rand();
    jaddnum(valsobj,"rawtxtag",rawtxtag);
    jaddnum(valsobj,"locktime",locktime);
    argjson = cJSON_CreateObject();
    jaddnum(argjson,"timeout",15000);
    if ( (retstr= iguana_rawtx(myinfo,coin,argjson,0,coin->changeaddr,addresses,valsobj,scriptstr)) != 0 )
    {
        //printf("feetx got.(%s)\n",retstr);
        flag = 0;
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (rawtx= jstr(retjson,"result")) != 0 && (vins= jobj(retjson,"vins")) != 0 )
                flag = 1;
        }
        if ( flag == 0 )
        {
            vins = 0;
            if ( (rawtx= iguana_pollrawtx(&myinfo->rawtxQ,&vins,rawtxtag,OS_milliseconds() + 10000)) != 0 )
            {
                if ( vins != 0 )
                    flag = 2;
            }
        }
        if ( flag != 0 && vins != 0 )
        {
            //printf("vins.(%s)\n",jprint(vins,0));
            if ( (signedtx= iguana_signrawtx(myinfo,coin,&signedtxid,&completed,vins,rawtx,privkey)) != 0 )
            {
                iguana_unspentslock(myinfo,coin,vins);
                tx = calloc(1,sizeof(*tx) + strlen(signedtx) + 1);
                strcpy(tx->txbytes,signedtx);
                tx->txid = signedtxid;
                printf("%s %s.%s\n",myside != 0 ? "BOB" : "ALICE",str,signedtx);
                free(signedtx);
            }
        }
        if ( retjson != 0 )
            free_json(retjson);
        if ( flag == 2 )
        {
            free_json(vins);
            printf("Free rawtx\n");
            free(rawtx);
        }
        free(retstr);
    } else printf("error creating %s feetx\n",myside != 0 ? "BOB" : "ALICE");
    free_json(addresses);
    free_json(argjson);
    return(tx);
}

struct bitcoin_statetx *instantdex_feetx(struct supernet_info *myinfo,struct instantdex_accept *A,struct bitcoin_swapinfo *swap,struct iguana_info *coin)
{
    int32_t n; uint8_t paymentscript[128]; char scriptstr[512],coinaddr[64]; struct bitcoin_statetx *ptr = 0; uint64_t r;
    r = swap->mine.orderid;
    n = instantdex_outputinsurance(coinaddr,coin->chain->pubtype,paymentscript,swap->insurance + swap->coinbtc->chain->txfee,r,r * (strcmp("BTC",coin->symbol) == 0));
    init_hexbytes_noT(scriptstr,paymentscript,n);
    printf("instantdex_feetx %s %.8f (%s)\n",coin->symbol,dstr(swap->insurance + swap->coinbtc->chain->txfee),scriptstr);
    if ( (ptr= instantdex_signtx("feetx",myinfo,coin,0,scriptstr,swap->insurance + swap->coinbtc->chain->txfee,coin->txfee,0,A->offer.myside)) != 0 )
        strcpy(ptr->destaddr,coinaddr);
    return(ptr);
}

int32_t instantdex_feetxverify(struct supernet_info *myinfo,struct iguana_info *coin,struct bitcoin_swapinfo *swap,cJSON *argjson)
{
    cJSON *txobj; bits256 txid; uint32_t n; int32_t i,retval = -1; int64_t insurance; uint64_t r;
    struct iguana_msgtx msgtx; uint8_t script[512]; char coinaddr[64];
    if ( swap->otherfee != 0 )
    {
        if ( (txobj= bitcoin_hex2json(coin,&txid,&msgtx,swap->otherfee->txbytes)) != 0 )
        {
            r = swap->other.orderid;
            if ( strcmp(coin->symbol,"BTC") == 0 )
                insurance = swap->insurance + swap->coinbtc->chain->txfee;
            else insurance = swap->altinsurance + swap->altcoin->chain->txfee;
            n = instantdex_outputinsurance(coinaddr,coin->chain->pubtype,script,insurance,r,r * (strcmp("BTC",coin->symbol) == 0));
            if ( n == msgtx.vouts[0].pk_scriptlen )
            {
                if ( memcmp(script,msgtx.vouts[0].pk_script,n) == 0 )
                {
                    printf("feetx script verified.(%s)\n",swap->otherfee->txbytes);
                    retval = 0;
                }
                else
                {
                    for (i=0; i<n; i++)
                        printf("%02x",script[i]);
                    printf(" fee script\n");
                    for (i=0; i<n; i++)
                        printf("%02x",msgtx.vouts[0].pk_script[i]);
                    printf(" feetx mismatched\n");
                    printf("FEETX.(%s)\n",jprint(txobj,0));
                }
            } else printf("pk_scriptlen %d mismatch %d\n",msgtx.vouts[0].pk_scriptlen,n);
            free_json(txobj);
        } else printf("error converting (%s) txobj\n",swap->otherfee->txbytes);
    } else printf("no feetx to verify\n");
    return(retval);
}

struct bitcoin_statetx *instantdex_bobtx(struct supernet_info *myinfo,struct bitcoin_swapinfo *swap,struct iguana_info *coin,int64_t amount,int32_t depositflag)
{
    int32_t n,secretstart; struct bitcoin_statetx *ptr = 0; uint8_t script[1024]; uint32_t locktime; int64_t satoshis; char scriptstr[512];
    if ( coin == 0 )
        return(0);
    satoshis = amount + depositflag*swap->insurance*100 + swap->coinbtc->chain->txfee;
    n = instantdex_bobscript(script,0,&locktime,&secretstart,swap,depositflag);
    if ( n < 0 )
    {
        printf("instantdex_bobtx couldnt generate bobscript deposit.%d\n",depositflag);
        return(0);
    }
    printf("locktime.%u amount %.8f satoshis %.8f\n",locktime,dstr(amount),dstr(satoshis));
    init_hexbytes_noT(scriptstr,script,n);
    if ( (ptr= instantdex_signtx(depositflag != 0 ? "deposit" : "payment",myinfo,coin,locktime,scriptstr,satoshis,coin->txfee,swap->mine.minconfirms,swap->mine.offer.myside)) != 0 )
    {
        bitcoin_address(ptr->destaddr,coin->chain->p2shtype,script,n);
        printf("BOBTX.%d (%s) -> %s\n",depositflag,ptr->txbytes,ptr->destaddr);
    }
    return(ptr);
}

int32_t instantdex_paymentverify(struct supernet_info *myinfo,struct iguana_info *coin,struct bitcoin_swapinfo *swap,cJSON *argjson,int32_t depositflag)
{
    cJSON *txobj; bits256 txid; uint32_t n,locktime; int32_t i,secretstart,retval = -1; uint64_t x;
    struct iguana_msgtx msgtx; uint8_t script[512]; int64_t amount;
    if ( coin != 0 && swap->deposit != 0 )
    {
        amount = swap->BTCsatoshis + depositflag*swap->insurance*100 + swap->coinbtc->chain->txfee;
        if ( (n= instantdex_bobscript(script,0,&locktime,&secretstart,swap,depositflag)) <= 0 )
            return(retval);
        if ( (txobj= bitcoin_hex2json(coin,&txid,&msgtx,swap->deposit->txbytes)) != 0 )
        {
            memcpy(&script[secretstart],&msgtx.vouts[0].pk_script[secretstart],20);
            printf("locktime.%u amount %.8f satoshis %.8f\n",locktime,dstr(amount),dstr(amount));
            if ( msgtx.lock_time == locktime && msgtx.vouts[0].value == amount && n == msgtx.vouts[0].pk_scriptlen )
            {
                if ( memcmp(script,msgtx.vouts[0].pk_script,n) == 0 )
                {
                    iguana_rwnum(0,&script[secretstart],sizeof(x),&x);
                    printf("deposit script verified\n");
                    if ( x == swap->otherdeck[swap->choosei][0] )
                        retval = 0;
                    else printf("deposit script verified but secret mismatch x.%llx vs otherdeck %llx\n",(long long)x,(long long)swap->otherdeck[swap->choosei][0]);
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

int32_t instantdex_altpaymentverify(struct supernet_info *myinfo,struct iguana_info *coin,struct bitcoin_swapinfo *swap,cJSON *argjson)
{
    cJSON *txobj; bits256 txid; uint32_t n; int32_t i,retval = -1;
    struct iguana_msgtx msgtx; uint8_t script[512]; char *altmsigaddr=0,msigaddr[64];
    if ( swap->altpayment != 0 && (altmsigaddr= jstr(argjson,"altmsigaddr")) != 0 )
    {
        if ( (txobj= bitcoin_hex2json(coin,&txid,&msgtx,swap->altpayment->txbytes)) != 0 )
        {
            n = instantdex_alicescript(script,0,msigaddr,coin->chain->p2shtype,swap->pubAm,swap->pubBn);
            if ( strcmp(msigaddr,altmsigaddr) == 0 && n == msgtx.vouts[0].pk_scriptlen )
            {
                if ( memcmp(script,msgtx.vouts[0].pk_script,n) == 0 )
                {
                    printf("altpayment script verified\n");
                    retval = 0;
                }
                else
                {
                    for (i=0; i<n; i++)
                        printf("%02x ",script[i]);
                    printf(" altscript\n");
                    for (i=0; i<n; i++)
                        printf("%02x ",msgtx.vouts[0].pk_script[i]);
                    printf(" altpayment\n");
                }
            } else printf("msig mismatch.(%s %s) or n.%d != %d\n",msigaddr,altmsigaddr,n,msgtx.vouts[0].pk_scriptlen);
            free_json(txobj);
        } else printf("bitcoin_hex2json error\n");
    } else printf("no altpayment.%p or no altmsig.%s\n",swap->altpayment,altmsigaddr!=0?altmsigaddr:"");
    return(retval);
}

struct bitcoin_statetx *instantdex_alicetx(struct supernet_info *myinfo,struct iguana_info *altcoin,char *msigaddr,bits256 pubAm,bits256 pubBn,int64_t amount,struct bitcoin_swapinfo *swap)
{
    int32_t n; uint8_t script[1024]; char scriptstr[2048]; struct bitcoin_statetx *ptr = 0;
    if ( altcoin != 0 )
    {
        if ( bits256_nonz(pubAm) == 0 || bits256_nonz(pubBn) == 0 )
        {
            printf("instantdex_bobtx null pubAm.%llx or pubBn.%llx\n",(long long)pubAm.txid,(long long)pubBn.txid);
            return(0);
        }
        n = instantdex_alicescript(script,0,msigaddr,altcoin->chain->p2shtype,pubAm,pubBn);
        init_hexbytes_noT(scriptstr,script,n);
        if ( (ptr= instantdex_signtx("altpayment",myinfo,altcoin,0,scriptstr,amount,altcoin->txfee,swap->mine.minconfirms,swap->mine.offer.myside)) != 0 )
        {
            strcpy(ptr->destaddr,msigaddr);
            printf("ALICETX (%s) -> %s\n",ptr->txbytes,ptr->destaddr);
        }
    }
    return(ptr);
}

cJSON *BTC_makeclaimfunc(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    int32_t got_payment=1,bob_reclaimed=0;
    *serdatap = 0, *serdatalenp = 0;
    if ( instantdex_isbob(swap) == 0 )
    {
        // [BLOCKING: payfound] now Alice's turn to make sure payment is confrmed and send in claim or see bob's reclaim and reclaim
        if ( got_payment != 0 )
        {
            //swap->privAm = swap->privkeys[swap->otherchoosei];
            // sign if/else payment
        }
        else if ( bob_reclaimed != 0 )
        {
            
        }
    }
    else
    {
        // [BLOCKING: privM] Bob waits for privM either from Alice or alt blockchain
        if ( bits256_nonz(swap->privAm) != 0 )
        {
            // a multisig tx for altcoin
        }
    }
    return(newjson);
}

bits256 instantdex_derivekeypair(struct supernet_info *myinfo,bits256 *newprivp,uint8_t pubkey[33],bits256 privkey,bits256 orderhash)
{
    bits256 sharedsecret;
    sharedsecret = curve25519_shared(privkey,orderhash);
    vcalc_sha256cat(newprivp->bytes,orderhash.bytes,sizeof(orderhash),sharedsecret.bytes,sizeof(sharedsecret));
    return(bitcoin_pubkey33(myinfo->ctx,pubkey,*newprivp));
}

int32_t instantdex_pubkeyargs(struct supernet_info *myinfo,struct bitcoin_swapinfo *swap,int32_t numpubs,bits256 privkey,bits256 hash,int32_t firstbyte)
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

char *instantdex_choosei(struct bitcoin_swapinfo *swap,cJSON *newjson,cJSON *argjson,uint8_t *serdata,int32_t datalen)
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
        printf("%llu/%llu %s send mychoosei.%d of max.%d deck.(%llx %llx)\n",(long long)swap->mine.orderid,(long long)swap->other.orderid,instantdex_isbob(swap)!=0?"BOB":"alice",swap->choosei,max,(long long)swap->otherdeck[0][0],(long long)swap->otherdeck[0][1]);
        return(0);
    }
    else
    {
        printf("choosei.%d or null serdata.%p or invalid datalen.%d vs %d\n",swap->choosei,serdata,datalen,(int32_t)sizeof(swap->deck));
        return(clonestr("{\"error\":\"instantdex_BTCswap offer no cut\"}"));
    }
}

void instantdex_privkeyextract(struct supernet_info *myinfo,struct bitcoin_swapinfo *swap,uint8_t *serdata,int32_t serdatalen)
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
                if ( instantdex_isbob(swap) != 0 )
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
            if ( otherpubkey[0] != (instantdex_isbob(swap) ^ 1) + 0x02 )
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

int32_t instantdex_swaptxupdate(struct iguana_info *coin,struct bitcoin_statetx **ptrp,cJSON *argjson,char *txname,char *txidfield)
{
    char *str; int32_t retval = 0;
    if ( (str= jstr(argjson,txname)) != 0 )
    {
        if ( *ptrp != 0 )
        {
            if ( strcmp((*ptrp)->txbytes,str) != 0 )
            {
                printf("got replacement %s?\n",txname);
                free(*ptrp);
            } else return(0);
        } else printf("instantdex_swaptxupdate got (%s) %s\n",txname,str);
        *ptrp = calloc(1,sizeof(**ptrp) + strlen(str) + 1);
        strcpy((*ptrp)->txbytes,str);
        (*ptrp)->txid = jbits256(argjson,txidfield);
        iguana_txidmonitor(coin,(*ptrp)->txid);
        if ( strcmp("feetx",txname) == 0 )
            retval = INSTANTDEX_ORDERSTATE_HAVEOTHERFEE;
        else if ( strcmp("deposit",txname) == 0 )
            retval = INSTANTDEX_ORDERSTATE_HAVEDEPOSIT;
        else if ( strcmp("payment",txname) == 0 )
            retval = INSTANTDEX_ORDERSTATE_HAVEPAYMENT;
        else if ( strcmp("altpayment",txname) == 0 )
            retval = INSTANTDEX_ORDERSTATE_HAVEALTPAYMENT;
    }
    return(retval);
}

void instantdex_swapbits256update(bits256 *txidp,cJSON *argjson,char *fieldname)
{
    bits256 txid; char str[65];
    txid = jbits256(argjson,fieldname);
    if ( bits256_nonz(txid) > 0 )
    {
        if ( 0 && bits256_nonz(*txidp) > 0 )
            printf("swapbits256: %s sent again\n",bits256_str(str,*txidp));
        *txidp = txid;
    }
}

void instantdex_newjson(struct supernet_info *myinfo,struct bitcoin_swapinfo *swap,cJSON *newjson)
{
    uint8_t pubkey[33],*secret160; int32_t i,deckflag; char secretstr[41],*field;
    deckflag = (newjson != 0 && swap->otherchoosei < 0) ? 1 : 0;
    if ( instantdex_pubkeyargs(myinfo,swap,2 + deckflag*INSTANTDEX_DECKSIZE,myinfo->persistent_priv,swap->myorderhash,0x02+instantdex_isbob(swap)) != 2 + deckflag*INSTANTDEX_DECKSIZE )
        printf("ERROR: couldnt generate pubkeys deckflag.%d\n",deckflag);
    jaddnum(newjson,"have",swap->havestate);
    if ( swap->choosei >= 0 )
        jaddnum(newjson,"mychoosei",swap->choosei);
    if ( swap->otherchoosei >= 0 )
    {
        jaddnum(newjson,"otherchoosei",swap->otherchoosei);
        if ( instantdex_isbob(swap) != 0 )
        {
            for (i=0; i<20; i++)
                if ( swap->secretBn[i] != 0 )
                    break;
            if ( i == 20 )
            {
                calc_rmd160_sha256(swap->secretBn,swap->privBn.bytes,sizeof(swap->privBn));
                swap->pubBn = bitcoin_pubkey33(myinfo->ctx,pubkey,swap->privBn);
            }
            secret160 = swap->secretBn;
            field = "secretBn";
        }
        else
        {
            for (i=0; i<20; i++)
                if ( swap->secretAm[i] != 0 )
                    break;
            if ( i == 20 )
            {
                calc_rmd160_sha256(swap->secretAm,swap->privAm.bytes,sizeof(swap->privAm));
                swap->pubAm = bitcoin_pubkey33(myinfo->ctx,pubkey,swap->privAm);
            }
            secret160 = swap->secretAm;
            field = "secretAm";
        }
        init_hexbytes_noT(secretstr,secret160,20);
        jaddstr(newjson,field,secretstr);
        printf("send secretstr.(%s)\n",secretstr);
    }
    if ( jobj(newjson,"feetx") == 0 && swap->myfee != 0 ) // &&  (swap->otherhavestate & INSTANTDEX_ORDERSTATE_HAVEOTHERFEE) == 0 )
    {
        jaddbits256(newjson,"feetxid",swap->myfee->txid);
        jaddstr(newjson,"feetx",swap->myfee->txbytes);
        //printf("add feetx to newjson have.%x\n",swap->havestate);
    }
    if ( instantdex_isbob(swap) == 0 )
    {
        if ( (swap->otherhavestate & INSTANTDEX_ORDERSTATE_HAVEALTPAYMENT) == 0 && swap->altpayment != 0 && jobj(newjson,"altpayment") == 0 )
        {
            jaddbits256(newjson,"altpaymenttxid",swap->altpayment->txid);
            jaddstr(newjson,"altpayment",swap->altpayment->txbytes);
            jaddstr(newjson,"altmsigaddr",swap->altpayment->destaddr);
            printf("add altpayment.(%s) have.%x\n",swap->altpayment->txbytes,swap->havestate);
        }
        jaddbits256(newjson,"A0",swap->mypubs[0]);
        jaddbits256(newjson,"A1",swap->mypubs[1]);
        swap->pubA0 = swap->mypubs[0];
        //swap->pubA1 = swap->mypubs[1];
        if ( bits256_nonz(swap->pubAm) == 0 && swap->otherchoosei >= 0 && bits256_nonz(swap->privkeys[swap->otherchoosei]) != 0 )
        {
            swap->pubAm = bitcoin_pubkey33(myinfo->ctx,pubkey,swap->privkeys[swap->otherchoosei]);
            swap->privAm = swap->privkeys[swap->otherchoosei];
            calc_rmd160_sha256(swap->secretAm,swap->privAm.bytes,sizeof(swap->privAm));
            memset(&swap->privkeys[swap->otherchoosei],0,sizeof(swap->privkeys[swap->otherchoosei]));
        }
    }
    else
    {
        if ( bits256_nonz(swap->pubBn) == 0 && swap->otherchoosei >= 0 && bits256_nonz(swap->privkeys[swap->otherchoosei]) != 0 )
        {
            swap->pubBn = bitcoin_pubkey33(myinfo->ctx,pubkey,swap->privkeys[swap->otherchoosei]);
            swap->privBn = swap->privkeys[swap->otherchoosei];
            calc_rmd160_sha256(swap->secretBn,swap->privBn.bytes,sizeof(swap->privBn));
            memset(&swap->privkeys[swap->otherchoosei],0,sizeof(swap->privkeys[swap->otherchoosei]));
        }
        jaddbits256(newjson,"B0",swap->mypubs[0]);
        jaddbits256(newjson,"B1",swap->mypubs[1]);
        swap->pubB0 = swap->mypubs[0];
        swap->pubB1 = swap->mypubs[1];
        if ( (swap->otherhavestate & INSTANTDEX_ORDERSTATE_HAVEDEPOSIT) == 0 && swap->deposit != 0 && jobj(newjson,"deposit") == 0 )
        {
            jaddbits256(newjson,"deposittxid",swap->deposit->txid);
            jaddstr(newjson,"deposit",swap->deposit->txbytes);
            printf("add deposit.(%s) have.%x\n",swap->deposit->txbytes,swap->havestate);
        }
        else if ( (swap->otherhavestate & INSTANTDEX_ORDERSTATE_HAVEPAYMENT) == 0 && swap->payment != 0 && jobj(newjson,"payment") == 0 )
        {
            jaddbits256(newjson,"paymenttxid",swap->payment->txid);
            jaddstr(newjson,"payment",swap->payment->txbytes);
            printf("add payment.(%s) have.%x\n",swap->payment->txbytes,swap->havestate);
        }
    }
    if ( bits256_nonz(swap->pubAm) != 0 )
        jaddbits256(newjson,"pubAm",swap->pubAm);
    if ( bits256_nonz(swap->privAm) != 0 )
        jaddbits256(newjson,"privAm",swap->privAm);
    if ( bits256_nonz(swap->pubBn) != 0 )
        jaddbits256(newjson,"pubBn",swap->pubBn);
}

cJSON *instantdex_parseargjson(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,int32_t deckflag)
{
    cJSON *newjson;
    newjson = cJSON_CreateObject();
    if ( swap == 0 )
        jaddstr(newjson,"error","missing swap info");
    else
    {
        if ( instantdex_isbob(swap) != 0 )
        {
            if ( jobj(argjson,"secretAm") != 0 )
                decode_hex(swap->secretAm,20,jstr(argjson,"secretAm"));
            instantdex_swapbits256update(&swap->otherpubs[0],argjson,"A0");
            instantdex_swapbits256update(&swap->otherpubs[1],argjson,"A1");
            if ( bits256_nonz(swap->otherpubs[0]) != 0 )
                swap->pubA0 = swap->otherpubs[0];
            //if ( bits256_nonz(swap->otherpubs[1]) != 0 )
            //    swap->pubA1 = swap->otherpubs[1];
            instantdex_swapbits256update(&swap->pubAm,argjson,"pubAm");
            instantdex_swapbits256update(&swap->privAm,argjson,"privAm");
            swap->havestate |= instantdex_swaptxupdate(swap->altcoin,&swap->altpayment,argjson,"altpayment","altpaymenttxid");
        }
        else
        {
            if ( jobj(argjson,"secretBn") != 0 )
                decode_hex(swap->secretBn,20,jstr(argjson,"secretBn"));
            instantdex_swapbits256update(&swap->otherpubs[0],argjson,"B0");
            instantdex_swapbits256update(&swap->otherpubs[1],argjson,"B1");
            if ( bits256_nonz(swap->otherpubs[0]) != 0 )
                swap->pubB0 = swap->otherpubs[0];
            if ( bits256_nonz(swap->otherpubs[1]) != 0 )
                swap->pubB1 = swap->otherpubs[1];
            instantdex_swapbits256update(&swap->pubBn,argjson,"pubBn");
            instantdex_swapbits256update(&swap->privBn,argjson,"privBn");
            swap->havestate |= instantdex_swaptxupdate(swap->coinbtc,&swap->deposit,argjson,"deposit","deposittxid");
            swap->havestate |= instantdex_swaptxupdate(swap->coinbtc,&swap->payment,argjson,"payment","paymenttxid");
        }
        swap->havestate |= instantdex_swaptxupdate(swap->coinbtc,&swap->otherfee,argjson,"feetx","feetxid");
        if ( swap->otherchoosei < 0 && jobj(argjson,"mychoosei") != 0 )
        {
            printf("otherschoosei.%d\n",swap->otherchoosei);
            if ( (swap->otherchoosei= juint(argjson,"mychoosei")) >= sizeof(swap->otherdeck)/sizeof(*swap->otherdeck) )
                swap->otherchoosei = -1;
        }
        if ( swap->otherchoosei >= 0 )
        {
            char str[65],str2[65];
            if ( instantdex_isbob(swap) != 0 )
            {
                if ( bits256_nonz(swap->pubAm) == 0 )
                    swap->pubAm = jbits256(argjson,"pubAm");
                else if ( bits256_cmp(swap->pubAm,jbits256(argjson,"pubAm")) != 0 )
                {
                    printf("mismatched pubAm %s vs %s\n",bits256_str(str,swap->pubAm),bits256_str(str2,jbits256(argjson,"pubAm")));
                }
            }
            else
            {
                if ( bits256_nonz(swap->pubBn) == 0 )
                    swap->pubBn = jbits256(argjson,"pubBn");
                else if ( bits256_cmp(swap->pubBn,jbits256(argjson,"pubBn")) != 0 )
                {
                    printf("mismatched pubBn %s vs %s\n",bits256_str(str,swap->pubBn),bits256_str(str2,jbits256(argjson,"pubBn")));
                }
            }
        }
        if ( jobj(argjson,"mychoosei") != 0 )
        {
            if ( swap->otherchoosei < 0 )
                swap->otherchoosei = jnum(argjson,"mychoosei");
            else if ( swap->otherchoosei != jnum(argjson,"mychoosei") )
            {
                printf("otherchoosei mismatch %d vs %d\n",swap->otherchoosei,jnum(argjson,"mychoosei"));
            }
        }
        if ( juint(argjson,"verified") != 0 )
            swap->otherverifiedcut = 1;
        if ( juint(argjson,"have") != 0 )
            swap->otherhavestate |= juint(argjson,"have");
        //printf("got other.%x myhave.%x choosei.(%d %d)\n",swap->otherhavestate,swap->havestate,swap->choosei,swap->otherchoosei);
    }
    return(newjson);
}

cJSON *BTC_checkdeckfunc(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    *serdatap = 0, *serdatalenp = 0; struct iguana_info *coin = iguana_coinfind("BTC");
    if ( coin != 0 )
    {
        if ( swap->choosei >= 0 && swap->otherchoosei >= 0 )
            jaddstr(newjson,"virtevent","gotdeck");
    }
    return(newjson);
}

cJSON *BTC_waitfeefunc(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    *serdatap = 0, *serdatalenp = 0;
    if ( swap->otherfee != 0 && iguana_txidstatus(swap->coinbtc,swap->otherfee->txid) >= 0. )
    {
        if ( instantdex_feetxverify(myinfo,swap->coinbtc,swap,argjson) < 0 )
        {
            printf("fee didnt verify\n");
            return(cJSON_Parse("{\"error\":\"fee didnt verify\"}"));
        }
        if ( instantdex_isbob(swap) != 0 )
            jaddstr(newjson,"virtevent","gendep");
        else jaddstr(newjson,"virtevent","waitdep");
    }
    return(newjson);
}

cJSON *BTC_gendepositfunc(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    int32_t i;
    *serdatap = 0, *serdatalenp = 0;
    if ( instantdex_isbob(swap) != 0 )
    {
        for (i=0; i<20; i++)
            if ( swap->secretBn[i] != 0 )
                break;
        if ( i != 20 )
        {
            if ( bits256_nonz(swap->pubA0) != 0 && bits256_nonz(swap->pubB0) != 0 )
            {
                if ( swap->deposit == 0 && (swap->deposit= instantdex_bobtx(myinfo,swap,swap->coinbtc,swap->BTCsatoshis,1)) == 0 )
                    printf("bobtx deposit couldnt be created\n");
                else jaddstr(newjson,"virtevent","depmade");
            } else printf("null pubA0.%llx or pubB0.%llx\n",(long long)swap->pubA0.txid,(long long)swap->pubB0.txid);
        }
    }
    return(newjson);
}

cJSON *BTC_waitdepositfunc(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    char msigaddr[64];
    *serdatap = 0, *serdatalenp = 0;
    if ( instantdex_isbob(swap) == 0 )
    {
        if ( swap->deposit != 0 && iguana_txidstatus(swap->coinbtc,swap->deposit->txid) >= swap->btcconfirms )
        {
            if ( instantdex_paymentverify(myinfo,swap->coinbtc,swap,argjson,1) < 0 )
            {
                printf("deposit didnt verify\n");
                return(cJSON_Parse("{\"error\":\"deposit didnt verify\"}"));
            }
            printf("deposit verified\n");
            if ( swap->altpayment == 0 && (swap->altpayment= instantdex_alicetx(myinfo,swap->altcoin,msigaddr,swap->pubAm,swap->pubBn,swap->altsatoshis,swap)) == 0 )
                printf("error creating altpayment\n");
            else jaddstr(newjson,"virtevent","depfound");
        }
    }
    return(newjson);
}

cJSON *BTC_waitaltpaymentfunc(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    *serdatap = 0, *serdatalenp = 0;
    if ( swap->altpayment != 0 && iguana_txidstatus(swap->altcoin,swap->altpayment->txid) >= swap->altconfirms )
    {
        if ( instantdex_isbob(swap) != 0 )
        {
            if ( instantdex_altpaymentverify(myinfo,swap->altcoin,swap,argjson) == 0 )
            {
                if ( swap->payment == 0 && (swap->payment= instantdex_bobtx(myinfo,swap,swap->coinbtc,swap->BTCsatoshis,0)) == 0 )
                    printf("couldnt create Bob's payment\n");
                jaddstr(newjson,"virtevent","altfound");
            } else printf("alt payment didnt verify\n");
        } else jaddstr(newjson,"virtevent","altfound");
    }
    return(newjson);
}

cJSON *BTC_waitpaymentfunc(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    *serdatap = 0, *serdatalenp = 0;
    if ( swap->payment != 0 && iguana_txidstatus(swap->coinbtc,swap->payment->txid) >= swap->btcconfirms  )
    {
        if ( instantdex_isbob(swap) == 0 )
        {
            if ( instantdex_paymentverify(myinfo,iguana_coinfind(swap->mine.offer.base),swap,argjson,0) == 0 )
                jaddstr(newjson,"virtevent","payfound");
        } else jaddstr(newjson,"virtevent","payfound");
    }
    return(newjson);
}

cJSON *BTC_cashmsigfunc(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    *serdatap = 0, *serdatalenp = 0;
    return(newjson);
}

cJSON *BTC_donefunc(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    *serdatap = 0, *serdatalenp = 0;
    return(newjson);
}

cJSON *BTC_cleanupfunc(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    *serdatap = 0, *serdatalenp = 0;
    swap->dead = (uint32_t)time(NULL);
    swap->mine.dead = (uint32_t)time(NULL);
    swap->other.dead = (uint32_t)time(NULL);
    portable_mutex_lock(&exchange->mutexS);
    DL_DELETE(exchange->statemachines,swap);
    portable_mutex_unlock(&exchange->mutexS);
    instantdex_historyadd(exchange,swap);
    printf("delete from statemachines, add to history\n");
    return(newjson);
}

struct instantdex_stateinfo *BTC_initFSM(int32_t *n)
{
    struct instantdex_stateinfo *s = 0;
    // Two initial states are BOB_idle and ALICE_idle
    // Inconvenient to start statemachines before this as typically after posting something in the orderbook, it is possible for multiple offers to come in. In that case the user or designated tradebot will need to choose among the acceptable offers and also to determine how much longer to wait. Also, an orderbook entry is technically a state, but there is no assurance it will ever proceed beyond the initial state and not just expire. Once an incoming offer is accepted, then the statemachine is created to push the swap toward completion.
    
    // the initiator includes a deck of INSTANTDEX_DECKSIZE keypairs
    //
    // "BTC<msg> are message events from other party (message events capped at length 8)
    // "<lowercase msg>" are special events
    // <TX> types: <fee>, <dep>osit, <alt>payment, <acl> is altcoin claim, <bre>claim and <are>claim are bob's and alice's reclaiming of their payments, <bfr> and <afr>claim are bob's and alice's reclaim of fee for failed trade, <adp> is alice claiming the deposit
    // "<TX>found" means the other party's is confirmed at user specified confidence level
    
    // BTC_cleanup state just unwinds pending swap as nothing has been committed yet
    
    // states instantdex_statecreate(s,n,<Name of State>,handlerfunc,errorhandler,<Timeout State>,<Error State>
    // a given state has a couple of handlers and custom events, with timeouts and errors invoking a bypass
    // events instantdex_addevent(s,*n,<Current State>,<event>,<message to send>,<Next State>)
    *n = 2; // start with state 2
    s = instantdex_statecreate(s,n,"BTC_cleanup",BTC_cleanupfunc,0,0,0,-1); // from states without any commits
    memset(s,0,sizeof(*s) * 2); // make sure state 0 and 1 are cleared
    // terminal [BLOCKING] states for the corresponding transaction
    // if all goes well both alice and bob get to claim the other's payments
 
    // after offer is sent, wait for other side to choose and sent their deck, then send privs
    s = instantdex_statecreate(s,n,"BTC_idle",BTC_checkdeckfunc,0,"BTC_cleanup",0,1);
    s = instantdex_statecreate(s,n,"BTC_waitdeck",BTC_checkdeckfunc,0,"BTC_cleanup",0,0);
    s = instantdex_statecreate(s,n,"BTC_gotdeck",BTC_checkdeckfunc,0,"BTC_cleanup",0,0);
    s = instantdex_statecreate(s,n,"BTC_waitfee",BTC_waitfeefunc,0,"BTC_cleanup",0,0);
    s = instantdex_statecreate(s,n,"BTC_gendeposit",BTC_gendepositfunc,0,"BTC_cleanup",0,0);
    s = instantdex_statecreate(s,n,"BTC_waitdeposit",BTC_waitdepositfunc,0,"BTC_cleanup",0,0);
    s = instantdex_statecreate(s,n,"BTC_waitaltpayment",BTC_waitaltpaymentfunc,0,"BTC_cleanup",0,0);
    s = instantdex_statecreate(s,n,"BTC_waitpayment",BTC_waitpaymentfunc,0,"BTC_cleanup",0,0);
    s = instantdex_statecreate(s,n,"BTC_makeclaim",BTC_makeclaimfunc,0,"BTC_cleanup",0,0);
    s = instantdex_statecreate(s,n,"BTC_cashmsig",BTC_cashmsigfunc,0,"BTC_cleanup",0,0);
    s = instantdex_statecreate(s,n,"BTC_done",BTC_donefunc,0,"BTC_cleanup",0,0);

    instantdex_addevent(s,*n,"BTC_idle","BTCoffer","poll","BTC_waitdeck"); // send deck + Chose
    instantdex_addevent(s,*n,"BTC_waitdeck","gotdeck","havedeck","BTC_gotdeck"); // virt event
    instantdex_addevent(s,*n,"BTC_waitdeck","havedeck","poll","BTC_waitdeck"); // other side gotdeck
    instantdex_addevent(s,*n,"BTC_waitdeck","sentprivs","poll","BTC_waitdeck");
    instantdex_addevent(s,*n,"BTC_waitdeck","poll","sentprivs","BTC_waitdeck");
    
    // to goto BTC_waitfee, both must have sent/recv deck and Chosen and verified cut and choose
    instantdex_addevent(s,*n,"BTC_gotdeck","gotdeck","sentprivs","BTC_waitfee"); // other gotdeck
    instantdex_addevent(s,*n,"BTC_gotdeck","havedeck","poll","BTC_gotdeck");
    instantdex_addevent(s,*n,"BTC_gotdeck","sentprivs","poll","BTC_gotdeck");
    instantdex_addevent(s,*n,"BTC_gotdeck","poll","sentprivs","BTC_gotdeck");
    
    // [BLOCKING: feefound] Bob waits for fee and sends deposit when it appears, alice skips past
    instantdex_addevent(s,*n,"BTC_waitfee","gendep","poll","BTC_gendeposit"); // bob's virt
    instantdex_addevent(s,*n,"BTC_waitfee","waitdep","poll","BTC_waitdeposit"); // alice's virt
    instantdex_addevent(s,*n,"BTC_waitfee","sentprivs","poll","BTC_waitfee");
    instantdex_addevent(s,*n,"BTC_waitfee","poll","sentprivs","BTC_waitfee");

    instantdex_addevent(s,*n,"BTC_gendeposit","depmade","poll","BTC_waitaltpayment");
    instantdex_addevent(s,*n,"BTC_gendeposit","sentprivs","poll","BTC_gendeposit");
    instantdex_addevent(s,*n,"BTC_gendeposit","poll","sentprivs","BTC_gendeposit");

    // [BLOCKING: depfound] Alice waits for deposit to confirm and sends altpayment, bob skips
    instantdex_addevent(s,*n,"BTC_waitdeposit","depfound","gotdep","BTC_waitpayment"); // alice virt
    instantdex_addevent(s,*n,"BTC_waitdeposit","gotdep","poll","BTC_waitdeposit");
    instantdex_addevent(s,*n,"BTC_waitdeposit","sentprivs","poll","BTC_waitdeposit");
    instantdex_addevent(s,*n,"BTC_waitdeposit","poll","sentprivs","BTC_waitdeposit");

    // [BLOCKING: altfound] now Bob's turn to make sure altpayment is confirmed and send payment
    instantdex_addevent(s,*n,"BTC_waitaltpayment","altfound","gotalt","BTC_waitpayment"); // virt
    instantdex_addevent(s,*n,"BTC_waitaltpayment","gotalt","poll","BTC_waitaltpayment");
    instantdex_addevent(s,*n,"BTC_waitaltpayment","sentprivs","poll","BTC_waitaltpayment");
    instantdex_addevent(s,*n,"BTC_waitaltpayment","poll","sentprivs","BTC_waitaltpayment");
    
    // [BLOCKING: payfound] now Alice's turn to make sure payment is confrmed and send in claim or see bob's reclaim and reclaim
    instantdex_addevent(s,*n,"BTC_waitpayment","payfound","gotpaytx","BTC_makeclaim"); // virt
    instantdex_addevent(s,*n,"BTC_waitpayment","gotpaytx","poll","BTC_waitpayment");
    instantdex_addevent(s,*n,"BTC_waitpayment","sentprivs","poll","BTC_waitpayment");
    instantdex_addevent(s,*n,"BTC_waitpayment","poll","sentprivs","BTC_waitpayment");
    
    // [BLOCKING: privM] Bob waits for privM either from Alice or alt blockchain
    instantdex_addevent(s,*n,"BTC_makeclaim","claimed","didclaim","BTC_done");
    instantdex_addevent(s,*n,"BTC_makeclaim","didclaim","poll","BTC_cashmsig");
    instantdex_addevent(s,*n,"BTC_makeclaim","poll","sentprivs","BTC_makeclaim");

    instantdex_addevent(s,*n,"BTC_cashmsig","gotprivM","didmsig","BTC_done");
    instantdex_addevent(s,*n,"BTC_cashmsig","poll","sentprivs","BTC_cashmsig");

    /*s = instantdex_statecreate(s,n,"ALICE_checkbobreclaim",ALICE_checkbobreclaimfunc,0,"ALICE_reclaimed",0,0);
    instantdex_addevent(s,*n,"ALICE_checkbobreclaim","brefound","poll","ALICE_reclaimed");
    instantdex_addevent(s,*n,"ALICE_checkbobreclaim","poll","poll","ALICE_waitconfirms");
    
    s = instantdex_statecreate(s,n,"BOB_sentpayment",BOB_waitprivMfunc,0,"BOB_reclaimed",0,0);
    instantdex_addevent(s,*n,"BOB_sentpayment","aclfound","BTCdone","BOB_claimedalt");
    instantdex_addevent(s,*n,"BOB_sentpayment","BTCprivM","BTCdone","BOB_claimedalt");
    instantdex_addevent(s,*n,"BOB_sentpayment","poll","poll","BOB_sentpayment");*/
    {
        double startmillis = OS_milliseconds();
        instantdex_FSMtest(s,*n,1000);
        printf("elapsed %.3f ave %.6f\n",OS_milliseconds() - startmillis,(OS_milliseconds() - startmillis)/1000);
    }
    return(s);
}

struct bitcoin_eventitem *instantdex_event(char *cmdstr,cJSON *argjson,cJSON *newjson,uint8_t *serdata,int32_t serdatalen)
{
    struct bitcoin_eventitem *ptr;
    ptr = calloc(1,sizeof(*ptr) + serdatalen);
    strcpy(ptr->cmd,cmdstr);
    ptr->newjson = jduplicate(newjson);
    ptr->argjson = jduplicate(argjson);
    if ( serdatalen != 0 )
    {
        memcpy(ptr->serdata,serdata,serdatalen);
        ptr->serdatalen = serdatalen;
    }
    return(ptr);
}

void instantdex_eventfree(struct bitcoin_eventitem *ptr)
{
    if ( ptr != 0 )
    {
        if ( ptr->argjson != 0 )
            free_json(ptr->argjson);
        if ( ptr->newjson != 0 )
            free_json(ptr->newjson);
        free(ptr);
    }
}

char *instantdex_statemachine(struct instantdex_stateinfo *states,int32_t numstates,struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,char *cmdstr,cJSON *argjson,cJSON *newjson,uint8_t *serdata,int32_t serdatalen)
{
    uint32_t i; struct instantdex_stateinfo *state=0;
    if ( swap == 0 || (state= swap->state) == 0 )
    {
        printf("state.%s (%s)\n",state->name,swap->mine.offer.base);
        return(clonestr("{\"error\":\"instantdex_BTCswap missing coin info\"}"));
    }
    printf("%llu/%llu cmd.(%s) state.(%s) newlen.%d isbob.%d have.%x myhave.%x otherfee.%p\n",(long long)swap->mine.orderid,(long long)swap->other.orderid,cmdstr,swap->state->name,(int32_t)strlen(jprint(newjson,0)),instantdex_isbob(swap),juint(argjson,"have"),swap->havestate,swap->otherfee);
    if ( jobj(argjson,"have") != 0 )
        swap->otherhavestate |= juint(argjson,"have");
    if ( jobj(argjson,"mychoosei") != 0 )
        swap->otherchoosei |= juint(argjson,"mychoosei");
    if ( swap->state->name[0] == 0 || (swap->expiration != 0 && time(NULL) > swap->expiration) )
    {
        swap->state = &states[state->timeoutind];
        swap->dead = (uint32_t)time(NULL);
        if ( state->timeout == 0 || (newjson= (*state->timeout)(myinfo,exchange,swap,argjson,newjson,&serdata,&serdatalen)) == 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap null return from timeoutfunc\"}"));
        else return(jprint(newjson,0));
    }
    for (i=0; i<state->numevents; i++)
    {
        if ( strcmp(cmdstr,state->events[i].cmdstr) == 0 )
        {
            if ( state->process != 0 && (newjson= (*state->process)(myinfo,exchange,swap,argjson,newjson,&serdata,&serdatalen)) == 0 )
            {
                if ( strcmp("poll",state->events[i].sendcmd) == 0 )
                {
                    printf("POLL for pending tx\n");
                    //return(instantdex_sendcmd(myinfo,&swap->mine.offer,newjson,state->events[i].sendcmd,myinfo->myaddr.persistent,0,serdata,serdatalen,0));
                }
                else
                {
                    printf("null return from non-poll event\n");
                    swap->state = &states[state->errorind];
                    return(clonestr("{\"error\":\"instantdex_statemachine: null return\"}"));
                }
            }
            else
            {
                if ( 0 && strcmp(cmdstr,"poll") != 0 )
                {
                    if ( swap->pollevent != 0 )
                        instantdex_eventfree(swap->pollevent);
                    swap->pollevent = instantdex_event("poll",argjson,newjson,serdata,serdatalen);
                }
                if ( jstr(newjson,"virtevent") != 0 )
                {
                    printf("VIRTEVENT.(%s)\n",jstr(newjson,"virtevent"));
                    for (i=0; i<state->numevents; i++)
                        if ( strcmp(jstr(newjson,"virtevent"),state->events[i].cmdstr) == 0 )
                        {
                            cmdstr = state->events[i].cmdstr;
                            break;
                        }
                    if ( i == state->numevents )
                    {
                        printf("error cant find.(%s)\n",jstr(newjson,"virtevent"));
                        return(clonestr("{\"error\":\"instantdex_statemachine: unexpected virtevent\"}"));
                    }
                    else
                    {
                        //printf("found.%d event.%s -> %s next.%d\n",i,state->events[i].cmdstr,states[state->events[i].nextstateind].name,state->events[i].nextstateind);
                    }
                }
                if ( state->events[i].sendcmd[0] != 0 )
                {
                    //printf("i.%d send.%s, next state.%s.[%d] %p\n",i,state->events[i].sendcmd,states[state->events[i].nextstateind].name,state->events[i].nextstateind,&states[state->events[i].nextstateind]);
                    if ( state->events[i].nextstateind > 1 )
                    {
                        instantdex_newjson(myinfo,swap,newjson);
                        //printf("i.%d (%s) %s %s.%d -> %s.%d send.(%s) %p\n",i,jprint(newjson,0),cmdstr,swap->state->name,state->ind,states[state->events[i].nextstateind].name,state->events[i].nextstateind,state->events[i].sendcmd,&states[state->events[i].nextstateind]);
                        swap->state = &states[state->events[i].nextstateind];
                        return(instantdex_sendcmd(myinfo,&swap->mine.offer,newjson,state->events[i].sendcmd,swap->othertrader,INSTANTDEX_HOPS,serdata,serdatalen,0,swap));
                    } else return(clonestr("{\"error\":\"instantdex_statemachine: illegal state\"}"));
                } else return(clonestr("{\"result\":\"instantdex_statemachine: processed\"}"));
            }
        }
    }
    return(clonestr("{\"error\":\"instantdex_statemachine: unexpected state\"}"));
}

void instantdex_statemachine_iter(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap)
{
    char *str; struct bitcoin_eventitem *ptr; cJSON *newjson; int32_t flag = 0;
    if ( swap->dead != 0 || swap->mine.dead != 0 || swap->other.dead != 0 )
        return;
    if ( swap->myfee == 0 )
        swap->myfee = instantdex_feetx(myinfo,&swap->mine,swap,swap->coinbtc);
    //printf("state(%s) %llx/%llx\n",swap->state->name,(long long)swap->mine.orderid,(long long)swap->other.orderid);
    while ( (ptr= queue_dequeue(&swap->eventsQ,0)) != 0 )
    {
        //printf("dequeued (%s)\n",ptr->cmd);
        if ( (str= instantdex_statemachine(BTC_states,BTC_numstates,myinfo,exchange,swap,ptr->cmd,ptr->argjson,ptr->newjson,ptr->serdata,ptr->serdatalen)) != 0 )
            free(str);
        instantdex_eventfree(ptr);
        flag++;
    }
    if ( flag == 0 && swap->dead == 0 && swap->pollevent != 0 )
    {
        //printf("send poll event\n");
        newjson = jduplicate(swap->pollevent->newjson);
        if ( (str= instantdex_statemachine(BTC_states,BTC_numstates,myinfo,exchange,swap,"poll",swap->pollevent->argjson,newjson,swap->pollevent->serdata,swap->pollevent->serdatalen)) != 0 )
            free(str);
        free_json(newjson);
    }
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
    bitcoin_txoutput(coin,txobj,scriptv0,scriptv0len,spend->satoshis);
    if ( isbob != 0 )
    {
        scriptv1len = bitcoin_revealsecret160(scriptv1,0,x);
        scriptv1len = bitcoin_pubkeyspend(scriptv1,scriptv1len,pubkey);
    } else scriptv1len = bitcoin_p2shspend(scriptv1,0,x);
    bitcoin_txoutput(coin,txobj,scriptv1,scriptv1len,spend->txfee);
    if ( (scriptv2len= bitcoin_changescript(coin,changescript,0,&change,spend->changeaddr,spend->input_satoshis,spend->satoshis,spend->txfee)) > 0 )
        bitcoin_txoutput(coin,txobj,changescript,scriptv2len,change);
    for (i=0; i<spend->numinputs; i++)
        bitcoin_txinput(coin,txobj,spend->inputs[i].txid,spend->inputs[i].vout,0xffffffff);
    rawtxstr = bitcoin_json2hex(coin,&txid,txobj,0);
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
    bitcoin_pubkey33(coin->ctx,pubkey,privkey);
    n = bitcoin_pubkeyspend(p2shscript,0,pubkey);
    calc_rmd160_sha256(rmd160,p2shscript,n);
    scriptv0len = bitcoin_p2shspend(scriptv0,0,rmd160);
    txobj = bitcoin_createtx(coin,0);
    bitcoin_txoutput(coin,txobj,scriptv0,scriptv0len,amount);
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
    rawtxstr = bitcoin_json2hex(coin,txidp,txobj,0);
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
    bitcoin_txinput(coin,txobj,bailintxid,0,0xffffffff);
    bitcoin_txinput(coin,txobj,bailintxid,1,0xffffffff);
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
    bitcoin_txinput(coin,txobj,bailintxid,0,0xffffffff);
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

void instantdex_pendingnotice(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,uint64_t basevolume64)
{
    //    printf("need to start monitoring thread\n");
    ap->pendingvolume64 -= basevolume64;
}

char *instantdex_BTCswap(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,char *cmdstr,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen) // receiving side
{
    uint8_t secret160[20]; bits256 hash,traderpub,A0,B0,sharedprivs[4]; uint64_t satoshis[2];
    cJSON *newjson; char *retstr=0,*str;
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
    satoshis[1] = instantdex_BTCsatoshis(A->offer.price64,A->offer.basevolume64);
    //printf("got offer.(%s) offerside.%d offerdir.%d\n",jprint(argjson,0),A->offer.myside,A->offer.acceptdir);
    if ( strcmp(cmdstr,"offer") == 0 ) // sender is Bob, receiver is network (Alice)
    {
        if ( A->offer.expiration < (time(NULL) + INSTANTDEX_DURATION) )
        {
            printf("too close to expiration: %u >= %lu\n",A->offer.expiration,(time(NULL) + INSTANTDEX_DURATION));
            return(clonestr("{\"error\":\"instantdex_BTCswap offer too close to expiration\"}"));
        }
        if ( (ap= instantdex_acceptable(exchange,A,myinfo->myaddr.nxt64bits)) != 0 )
        {
            isbob = 0;
            if ( (newjson= instantdex_newjson(myinfo,&A0,&B0,sharedprivs,secret160,isbob,argjson,hash,A)) == 0 )
                return(clonestr("{\"error\":\"instantdex_BTCswap offer null newjson\"}"));
            else
            {
                //instantdex_pendingnotice(myinfo,exchange,ap,A);
                return(instantdex_bailinrefund(myinfo,other,exchange,A,"proposal",secret160,newjson,isbob,A0,B0,sharedprivs));
            }
        }
        else
        {
            printf("Ano matching trade.(%s)\n",jprint(argjson,0));
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

