
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
//  LP_remember.c
//  marketmaker
//


cJSON *basilisk_nullretjson(cJSON *retjson)
{
    char *outstr;
    if ( retjson != 0 )
    {
        outstr = jprint(retjson,0);
        if ( strcmp(outstr,"{}") == 0 )
        {
            free_json(retjson);
            retjson = 0;
        }
        free(outstr);
    }
    return(retjson);
}

cJSON *basilisk_swapgettxout(struct supernet_info *myinfo,char *symbol,bits256 trigger,int32_t vout)
{
    char *retstr; cJSON *retjson=0; struct iguana_info *coin;
    if ( ((coin= iguana_coinfind(symbol)) == 0 || coin->FULLNODE == 0) && iguana_isnotarychain(symbol) >= 0 )
    {
        if ( (retstr= dex_gettxout(myinfo,0,0,0,trigger,symbol,vout)) != 0 )
        {
            //printf("dexgettxout.(%s)\n",retstr);
            retjson = cJSON_Parse(retstr);
            free(retstr);
        }
        if ( 0 && strcmp("BTC",symbol) == 0 )
            printf("%s gettxout.(%s)\n",symbol,jprint(retjson,0));
    }
    else
    {
        retjson = dpow_gettxout(myinfo,coin,trigger,vout);
        //printf("need to verify passthru has this info\n");
        //printf("dpowgettxout.(%s)\n",jprint(retjson,0));
    }
    return(basilisk_nullretjson(retjson));
}

cJSON *basilisk_swapgettx(struct supernet_info *myinfo,char *symbol,bits256 txid)
{
    char *retstr; cJSON *retjson=0; struct iguana_info *coin;
    if ( ((coin= iguana_coinfind(symbol)) == 0 || coin->FULLNODE == 0) && iguana_isnotarychain(symbol) >= 0 )
    {
        if ( (retstr= dex_gettransaction(myinfo,0,0,0,txid,symbol)) != 0 )
        {
            retjson = cJSON_Parse(retstr);
            free(retstr);
        }
        //if ( strcmp("BTC",symbol) == 0 )
        //    printf("%s gettx.(%s)\n",symbol,jprint(retjson,0));
    } else retjson = dpow_gettransaction(myinfo,coin,txid);
    return(basilisk_nullretjson(retjson));
}

int32_t basilisk_swap_txdestaddr(char *destaddr,bits256 txid,int32_t vout,cJSON *txobj)
{
    int32_t n,m,retval = -1; cJSON *vouts,*item,*addresses,*skey; char *addr;
    if ( (vouts= jarray(&n,txobj,"vout")) != 0 && vout < n )
    {
        item = jitem(vouts,vout);
        if ( (skey= jobj(item,"scriptPubKey")) != 0 && (addresses= jarray(&m,skey,"addresses")) != 0 )
        {
            item = jitem(addresses,0);
            if ( (addr= jstr(item,0)) != 0 )
            {
                safecopy(destaddr,addr,64);
                retval = 0;
            }
            //printf("item.(%s) -> dest.(%s)\n",jprint(item,0),destaddr);
        }
    }
    return(retval);
}

int32_t basilisk_swap_getcoinaddr(struct supernet_info *myinfo,char *symbol,char *coinaddr,bits256 txid,int32_t vout)
{
    cJSON *retjson;
    coinaddr[0] = 0;
    if ( (retjson= basilisk_swapgettx(myinfo,symbol,txid)) != 0 )
    {
        basilisk_swap_txdestaddr(coinaddr,txid,vout,retjson);
        free_json(retjson);
    }
    return(coinaddr[0] != 0);
}

int32_t basilisk_swap_getsigscript(struct supernet_info *myinfo,char *symbol,uint8_t *script,int32_t maxlen,bits256 txid,int32_t vini)
{
    cJSON *retjson,*vins,*item,*skey; int32_t n,scriptlen = 0; char *hexstr;
    if ( (retjson= basilisk_swapgettx(myinfo,symbol,txid)) != 0 )
    {
        if ( (vins= jarray(&n,retjson,"vin")) != 0 && vini < n )
        {
            item = jitem(vins,vini);
            if ( (skey= jobj(item,"scriptSig")) != 0 && (hexstr= jstr(skey,"hex")) != 0 && (scriptlen= (int32_t)strlen(hexstr)) < maxlen*2 )
            {
                scriptlen >>= 1;
                decode_hex(script,scriptlen,hexstr);
                //char str[65]; printf("%s/v%d sigscript.(%s)\n",bits256_str(str,txid),vini,hexstr);
            }
        }
        free_json(retjson);
    }
    return(scriptlen);
}

int64_t basilisk_txvalue(struct supernet_info *myinfo,char *symbol,bits256 txid,int32_t vout)
{
    cJSON *txobj,*vouts,*item; int32_t n; int64_t value = 0;
    //char str[65]; printf("%s txvalue.(%s)\n",symbol,bits256_str(str,txid));
    if ( (txobj= basilisk_swapgettx(myinfo,symbol,txid)) != 0 )
    {
        //printf("txobj.(%s)\n",jprint(txobj,0));
        if ( (vouts= jarray(&n,txobj,"vout")) != 0 )
        {
            item = jitem(vouts,vout);
            if ( (value= jdouble(item,"amount") * SATOSHIDEN) == 0 )
                value = jdouble(item,"value") * SATOSHIDEN;
        }
        free_json(txobj);
    }
    return(value);
}

bits256 dex_swap_spendtxid(struct supernet_info *myinfo,char *symbol,char *destaddr,char *coinaddr,bits256 utxotxid,int32_t vout)
{
    char *retstr,*addr; cJSON *array,*item,*array2; int32_t i,n,m; bits256 spendtxid,txid;
    memset(&spendtxid,0,sizeof(spendtxid));
    if ( (retstr= dex_listtransactions(myinfo,0,0,0,symbol,coinaddr,100,0)) != 0 )
    {
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (item= jitem(array,i)) == 0 )
                        continue;
                    txid = jbits256(item,"txid");
                    if ( bits256_nonz(txid) == 0 )
                    {
                        if ( (array2= jarray(&m,item,"inputs")) != 0 && m == 1 )
                        {
                            //printf("found inputs with %s\n",bits256_str(str,spendtxid));
                            txid = jbits256(jitem(array2,0),"output_hash");
                            if ( bits256_cmp(txid,utxotxid) == 0 )
                            {
                                //printf("matched %s\n",bits256_str(str,txid));
                                if ( (array2= jarray(&m,item,"outputs")) != 0 && m == 1 && (addr= jstr(jitem(array2,0),"address")) != 0 )
                                {
                                    spendtxid = jbits256(item,"hash");
                                    strcpy(destaddr,addr);
                                    //printf("set spend addr.(%s) <- %s\n",addr,jprint(item,0));
                                    break;
                                }
                            }
                        }
                    }
                    else if ( bits256_cmp(txid,utxotxid) == 0 )
                    {
                        spendtxid = jbits256(item,"spendtxid");
                        if ( bits256_nonz(spendtxid) != 0 )
                        {
                            basilisk_swap_getcoinaddr(myinfo,symbol,destaddr,spendtxid,0);
                            //char str[65]; printf("found spendtxid.(%s) -> %s\n",bits256_str(str,spendtxid),destaddr);
                            break;
                        }
                    }
                }
            }
            free_json(array);
        }
        free(retstr);
    }
    return(spendtxid);
}

bits256 basilisk_swap_spendtxid(struct supernet_info *myinfo,char *symbol,char *destaddr,bits256 utxotxid,int32_t vout)
{
    bits256 spendtxid,txid; char *catstr,*addr; cJSON *array,*item,*item2,*txobj,*vins; int32_t i,n,m; char coinaddr[64],str[65]; struct iguana_info *coin = iguana_coinfind(symbol);
    // listtransactions or listspents
    destaddr[0] = 0;
    coinaddr[0] = 0;
    memset(&spendtxid,0,sizeof(spendtxid));
    //char str[65]; printf("swap %s spendtxid.(%s)\n",symbol,bits256_str(str,utxotxid));
    if ( (coin == 0 || coin->FULLNODE >= 0) && iguana_isnotarychain(symbol) >= 0 )
    {
        //[{"type":"sent","confirmations":379,"height":275311,"timestamp":1492084664,"txid":"8703c5517bc57db38134058370a14e99b8e662b99ccefa2061dea311bbd02b8b","vout":0,"amount":117.50945263,"spendtxid":"cf2509e076fbb9b22514923df916b7aacb1391dce9c7e1460b74947077b12510","vin":0,"paid":{"type":"paid","txid":"cf2509e076fbb9b22514923df916b7aacb1391dce9c7e1460b74947077b12510","height":275663,"timestamp":1492106024,"vouts":[{"RUDpN6PEBsE7ZFbGjUxk1W3QVsxnjBLYw6":117.50935263}]}}]
        basilisk_swap_getcoinaddr(myinfo,symbol,coinaddr,utxotxid,vout);
        if ( coinaddr[0] != 0 )
            spendtxid = dex_swap_spendtxid(myinfo,symbol,destaddr,coinaddr,utxotxid,vout);
    }
    else if ( coin != 0 )
    {
        if ( (array= dpow_listtransactions(myinfo,coin,destaddr,1000,0)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (item= jitem(array,i)) == 0 )
                        continue;
                    txid = jbits256(item,"txid");
                    if ( vout == juint(item,"vout") && bits256_cmp(txid,utxotxid) == 0 && (addr= jstr(item,"address")) != 0 )
                    {
                        if ( (catstr= jstr(item,"category")) != 0 )
                        {
                            if (strcmp(catstr,"send") == 0 )
                            {
                                strncpy(destaddr,addr,63);
                                //printf("(%s) <- (%s) item.%d.[%s]\n",destaddr,coinaddr,i,jprint(item,0));
                                if ( coinaddr[0] != 0 )
                                    break;
                            }
                            if (strcmp(catstr,"receive") == 0 )
                            {
                                strncpy(coinaddr,addr,63);
                                //printf("receive dest.(%s) <- (%s)\n",destaddr,coinaddr);
                                if ( destaddr[0] != 0 )
                                    break;
                            }
                        }
                    }
                }
            }
            free_json(array);
        }
        if ( destaddr[0] != 0 )
        {
            if ( (array= dpow_listtransactions(myinfo,coin,destaddr,1000,0)) != 0 )
            {
                if ( (n= cJSON_GetArraySize(array)) > 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        if ( (item= jitem(array,i)) == 0 )
                            continue;
                        if ( (catstr= jstr(item,"category")) != 0 && strcmp(catstr,"send") == 0 )
                        {
                            txid = jbits256(item,"txid");
                            if ( (txobj= dpow_gettransaction(myinfo,coin,txid)) != 0 )
                            {
                                if ( (vins= jarray(&m,txobj,"vin")) != 0 && m > jint(item,"vout") )
                                {
                                    item2 = jitem(vins,jint(item,"vout"));
                                    if ( bits256_cmp(utxotxid,jbits256(item2,"txid")) == 0 && vout == jint(item2,"vout") )
                                    {
                                        spendtxid = txid;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if ( i == n )
                        printf("dpowlist: native couldnt find spendtxid for %s\n",bits256_str(str,utxotxid));
                }
                free_json(array);
            }
            if ( bits256_nonz(spendtxid) != 0 )
                return(spendtxid);
        }
        if ( iguana_isnotarychain(symbol) >= 0 )
        {
            basilisk_swap_getcoinaddr(myinfo,symbol,coinaddr,utxotxid,vout);
            printf("fallback use DEX for native (%s) (%s)\n",coinaddr,bits256_str(str,utxotxid));
            if ( coinaddr[0] != 0 )
            {
                spendtxid = dex_swap_spendtxid(myinfo,symbol,destaddr,coinaddr,utxotxid,vout);
                printf("spendtxid.(%s)\n",bits256_str(str,spendtxid));
            }
        }
    }
    return(spendtxid);
}

bits256 basilisk_swap_sendrawtransaction(struct supernet_info *myinfo,char *txname,char *symbol,char *txbytes)
{
    char *retstr; bits256 txid; int32_t i,sentflag = 0;
    memset(&txid,0,sizeof(txid));
    for (i=0; i<3; i++)
    {
        if ( (retstr= _dex_sendrawtransaction(myinfo,symbol,txbytes)) != 0 )
        {
            if ( is_hexstr(retstr,0) == 64 )
            {
                decode_hex(txid.bytes,32,retstr);
                sentflag = 1;
            }
            char str[65]; printf("[%s] %s RETSTR.(%s) %s.%s\n",txname,txbytes,retstr,symbol,bits256_str(str,txid));
            free(retstr);
        }
        if ( sentflag != 0 )
            break;
    }
    return(txid);
}

char *basilisk_swap_bobtxspend(char *name,struct supernet_info *myinfo,char *symbol,bits256 privkey,bits256 *privkey2p,uint8_t *redeemscript,int32_t redeemlen,uint8_t *userdata,int32_t userdatalen,bits256 utxotxid,int32_t vout,uint8_t *pubkey33,int32_t finalseqid,uint32_t expiration,int64_t *destamountp)
{
    char *rawtxbytes=0,*signedtx=0,str[65],hexstr[999],wifstr[128],destaddr[64]; uint8_t spendscript[512],addrtype,rmd160[20]; cJSON *utxoobj,*txobj,*vins,*item,*sobj,*privkeys; int32_t height,completed,spendlen,ignore_cltverr=1,suppress_pubkeys=1; struct vin_info *V; uint32_t timestamp,locktime = 0,sequenceid = 0xffffffff * finalseqid; struct iguana_info *coin; bits256 txid,signedtxid; uint64_t destamount;
    *destamountp = 0;
    if ( finalseqid == 0 )
        locktime = expiration;
    //printf("bobtxspend.%s redeem.[%d]\n",symbol,redeemlen);
    if ( redeemlen < 0 || (coin= iguana_coinfind(symbol)) == 0 )
        return(0);
    if ( (utxoobj= basilisk_swapgettxout(myinfo,symbol,utxotxid,vout)) == 0 )
    {
        printf("basilisk_swap_bobtxspend.%s utxo already spent or doesnt exist\n",name);
        return(0);
    }
    if ( (destamount= jdouble(utxoobj,"amount")*SATOSHIDEN) == 0 && (destamount= jdouble(utxoobj,"value")*SATOSHIDEN) == 0 )
    {
        printf("%s %s basilisk_swap_bobtxspend.%s strange utxo.(%s)\n",symbol,bits256_str(str,utxotxid),name,jprint(utxoobj,0));
        free_json(utxoobj);
        return(0);
    } else free_json(utxoobj);
    *destamountp = destamount;
    if ( destamount > 10000 )
        destamount -= 10000;
    if ( strcmp(symbol,"BTC") == 0 )
    {
        if ( destamount > 40000 )
            destamount -= 40000;
    }
    height = coin->longestchain;
    timestamp = (uint32_t)time(NULL);
    V = calloc(256,sizeof(*V));
    privkeys = cJSON_CreateArray();
    if ( privkey2p != 0 )
    {
        V[0].signers[1].privkey = *privkey2p;
        bitcoin_pubkey33(myinfo->ctx,V[0].signers[1].pubkey,*privkey2p);
        bitcoin_priv2wif(wifstr,*privkey2p,coin->chain->wiftype);
        jaddistr(privkeys,wifstr);
        V[0].N = V[0].M = 2;
    } else V[0].N = V[0].M = 1;
    V[0].signers[0].privkey = privkey;
    bitcoin_pubkey33(myinfo->ctx,V[0].signers[0].pubkey,privkey);
    bitcoin_priv2wif(wifstr,privkey,coin->chain->wiftype);
    jaddistr(privkeys,wifstr);
    V[0].suppress_pubkeys = suppress_pubkeys;
    V[0].ignore_cltverr = ignore_cltverr;
    if ( redeemlen != 0 )
        memcpy(V[0].p2shscript,redeemscript,redeemlen), V[0].p2shlen = redeemlen;
    txobj = bitcoin_txcreate(coin->symbol,coin->chain->isPoS,locktime,1,timestamp);
    vins = cJSON_CreateArray();
    item = cJSON_CreateObject();
    if ( userdata != 0 && userdatalen > 0 )
    {
        memcpy(V[0].userdata,userdata,userdatalen);
        V[0].userdatalen = userdatalen;
        init_hexbytes_noT(hexstr,userdata,userdatalen);
        jaddstr(item,"userdata",hexstr);
    }
    jaddbits256(item,"txid",utxotxid);
    jaddnum(item,"vout",vout);
    sobj = cJSON_CreateObject();
    bitcoin_address(destaddr,coin->chain->pubtype,pubkey33,33);
    bitcoin_addr2rmd160(&addrtype,rmd160,destaddr);
    /*int32_t i;
     for (i=0; i<33; i++)
     printf("%02x",pubkey33[i]);
     printf(" pubkey33 ->\n");
     for (i=0; i<20; i++)
     printf("%02x",rmd160[i]);
     printf(" destaddr.(%s)\n",destaddr);
     calc_rmd160_sha256(rmd160,pubkey33,33);
     for (i=0; i<20; i++)
     printf("%02x",rmd160[i]);
     printf(" <- vs direct calc\n");*/
    spendlen = bitcoin_standardspend(spendscript,0,rmd160);
    init_hexbytes_noT(hexstr,spendscript,spendlen);
    jaddstr(sobj,"hex",hexstr);
    jadd(item,"scriptPubKey",sobj);
    jaddnum(item,"suppress",suppress_pubkeys);
    jaddnum(item,"sequence",sequenceid);
    if ( redeemlen != 0 )
    {
        init_hexbytes_noT(hexstr,redeemscript,redeemlen);
        jaddstr(item,"redeemScript",hexstr);
    }
    jaddi(vins,item);
    jdelete(txobj,"vin");
    jadd(txobj,"vin",vins);
    txobj = bitcoin_txoutput(txobj,spendscript,spendlen,destamount);
    if ( (rawtxbytes= bitcoin_json2hex(myinfo,coin,&txid,txobj,V)) != 0 )
    {
        //printf("locktime.%u sequenceid.%x rawtx.(%s) vins.(%s)\n",locktime,sequenceid,rawtxbytes,jprint(vins,0));
        if ( (signedtx= iguana_signrawtx(myinfo,coin,height,&signedtxid,&completed,vins,rawtxbytes,privkeys,V)) == 0 )
            printf("couldnt sign transaction\n");
        else if ( completed == 0 )
            printf("incomplete signing\n");
        else printf("%s -> %s\n",name,bits256_str(str,signedtxid));
        free(rawtxbytes);
    } else printf("error making rawtx\n");
    free_json(privkeys);
    free_json(txobj);
    free(V);
    return(signedtx);
}

char *basilisk_swap_Aspend(char *name,struct supernet_info *myinfo,char *symbol,bits256 privAm,bits256 privBn,bits256 utxotxid,int32_t vout,uint8_t pubkey33[33],uint32_t expiration,int64_t *destamountp)
{
    char msigaddr[64],*signedtx = 0; int32_t spendlen,redeemlen; uint8_t tmp33[33],redeemscript[512],spendscript[128]; bits256 pubAm,pubBn; struct iguana_info *coin = iguana_coinfind(symbol);
    if ( coin != 0 && bits256_nonz(privAm) != 0 && bits256_nonz(privBn) != 0 )
    {
        pubAm = bitcoin_pubkey33(myinfo->ctx,tmp33,privAm);
        pubBn = bitcoin_pubkey33(myinfo->ctx,tmp33,privBn);
        //char str[65];
        //printf("pubAm.(%s)\n",bits256_str(str,pubAm));
        //printf("pubBn.(%s)\n",bits256_str(str,pubBn));
        spendlen = basilisk_alicescript(redeemscript,&redeemlen,spendscript,0,msigaddr,coin->chain->p2shtype,pubAm,pubBn);
        //char str[65]; printf("%s utxo.(%s) redeemlen.%d spendlen.%d\n",msigaddr,bits256_str(str,utxotxid),redeemlen,spendlen);
        /*rev = privAm;
         for (i=0; i<32; i++)
         privAm.bytes[i] = rev.bytes[31 - i];
         rev = privBn;
         for (i=0; i<32; i++)
         privBn.bytes[i] = rev.bytes[31 - i];*/
        signedtx = basilisk_swap_bobtxspend(name,myinfo,symbol,privAm,&privBn,redeemscript,redeemlen,0,0,utxotxid,vout,pubkey33,1,expiration,destamountp);
    }
    return(signedtx);
}

bits256 basilisk_swap_privbob_extract(struct supernet_info *myinfo,char *symbol,bits256 spendtxid,int32_t vini,int32_t revflag)
{
    bits256 privkey; int32_t i,scriptlen,siglen; uint8_t script[1024]; // from Bob refund of Bob deposit
    memset(&privkey,0,sizeof(privkey));
    if ( (scriptlen= basilisk_swap_getsigscript(myinfo,symbol,script,(int32_t)sizeof(script),spendtxid,vini)) > 0 )
    {
        siglen = script[0];
        for (i=0; i<32; i++)
        {
            if ( revflag != 0 )
                privkey.bytes[31 - i] = script[siglen+2+i];
            else privkey.bytes[i] = script[siglen+2+i];
        }
        char str[65]; printf("extracted privbob.(%s)\n",bits256_str(str,privkey));
    }
    return(privkey);
}

bits256 basilisk_swap_privBn_extract(struct supernet_info *myinfo,bits256 *bobrefundp,char *bobcoin,bits256 bobdeposit,bits256 privBn)
{
    char destaddr[64];
    if ( bits256_nonz(privBn) == 0 )
    {
        if ( bits256_nonz(bobdeposit) != 0 )
            *bobrefundp = basilisk_swap_spendtxid(myinfo,bobcoin,destaddr,bobdeposit,0);
        if ( bits256_nonz(*bobrefundp) != 0 )
            privBn = basilisk_swap_privbob_extract(myinfo,bobcoin,*bobrefundp,0,0);
    }
    return(privBn);
}

bits256 basilisk_swap_spendupdate(struct supernet_info *myinfo,char *symbol,int32_t *sentflags,bits256 *txids,int32_t utxoind,int32_t alicespent,int32_t bobspent,int32_t vout,char *aliceaddr,char *bobaddr)
{
    bits256 spendtxid,txid; char destaddr[64];
    txid = txids[utxoind];
    memset(&spendtxid,0,sizeof(spendtxid));
    /*if ( aliceaddr != 0 )
     printf("aliceaddr.(%s)\n",aliceaddr);
     if ( bobaddr != 0 )
     printf("bobaddr.(%s)\n",bobaddr);*/
    if ( bits256_nonz(txid) != 0 )
    {
        //char str[65];
        spendtxid = basilisk_swap_spendtxid(myinfo,symbol,destaddr,txid,vout);
        if ( bits256_nonz(spendtxid) != 0 )
        {
            sentflags[utxoind] = 1;
            if ( aliceaddr != 0 && strcmp(destaddr,aliceaddr) == 0 )
            {
                //printf("ALICE spent.(%s) -> %s\n",bits256_str(str,txid),destaddr);
                sentflags[alicespent] = 1;
                txids[alicespent] = spendtxid;
            }
            else if ( bobaddr != 0 && strcmp(destaddr,bobaddr) == 0 )
            {
                //printf("BOB spent.(%s) -> %s\n",bits256_str(str,txid),destaddr);
                sentflags[bobspent] = 1;
                txids[bobspent] = spendtxid;
            }
            else
            {
                //printf("OTHER dest spent.(%s) -> %s\n",bits256_str(str,txid),destaddr);
                if ( aliceaddr != 0 )
                {
                    sentflags[bobspent] = 1;
                    txids[bobspent] = spendtxid;
                }
                else if ( bobaddr != 0 )
                {
                    sentflags[alicespent] = 1;
                    txids[alicespent] = spendtxid;
                }
            }
        }
    } else printf("utxoind.%d null txid\n",utxoind);
    return(spendtxid);
}

#define BASILISK_ALICESPEND 0
#define BASILISK_BOBSPEND 1
#define BASILISK_BOBPAYMENT 2
#define BASILISK_ALICEPAYMENT 3
#define BASILISK_BOBDEPOSIT 4
#define BASILISK_OTHERFEE 5
#define BASILISK_MYFEE 6
#define BASILISK_BOBREFUND 7
#define BASILISK_BOBRECLAIM 8
#define BASILISK_ALICERECLAIM 9
#define BASILISK_ALICECLAIM 10
//0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0
char *txnames[] = { "alicespend", "bobspend", "bobpayment", "alicepayment", "bobdeposit", "otherfee", "myfee", "bobrefund", "bobreclaim", "alicereclaim", "aliceclaim" };

int32_t basilisk_isbobcoin(int32_t iambob,int32_t ind)
{
    switch ( ind  )
    {
        case BASILISK_MYFEE: return(iambob); break;
        case BASILISK_OTHERFEE: return(!iambob); break;
        case BASILISK_BOBSPEND:
        case BASILISK_ALICEPAYMENT:
        case BASILISK_ALICERECLAIM:
        case BASILISK_ALICECLAIM: return(0);
            break;
        case BASILISK_BOBDEPOSIT:
        case BASILISK_ALICESPEND:
        case BASILISK_BOBPAYMENT:
        case BASILISK_BOBREFUND:
        case BASILISK_BOBRECLAIM: return(1);
            break;
        default: return(-1); break;
    }
}

// add blocktrail presence requirement for BTC
int32_t basilisk_swap_isfinished(int32_t iambob,bits256 *txids,int32_t *sentflags,bits256 paymentspent,bits256 Apaymentspent,bits256 depositspent)
{
    int32_t i,n = 0;
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        if ( i != BASILISK_OTHERFEE && i != BASILISK_MYFEE && sentflags[i] != 0 )
            n++;
    if ( n == 0 )
    {
        printf("if nothing sent, it is finished\n");
        return(1);
    }
    if ( iambob != 0 )
    {
        if ( bits256_nonz(txids[BASILISK_BOBDEPOSIT]) == 0 && sentflags[BASILISK_BOBDEPOSIT] == 0 )
            return(1);
        else if ( bits256_nonz(txids[BASILISK_BOBPAYMENT]) == 0 && sentflags[BASILISK_BOBPAYMENT] == 0 )
        {
            if ( bits256_nonz(depositspent) != 0 )
                return(1);
        }
        else if ( bits256_nonz(paymentspent) != 0 )
            return(1);
    }
    else
    {
        if ( bits256_nonz(txids[BASILISK_ALICEPAYMENT]) == 0 && sentflags[BASILISK_ALICEPAYMENT] == 0 )
            return(1);
        else
        {
            if ( sentflags[BASILISK_ALICERECLAIM] != 0 || sentflags[BASILISK_ALICESPEND] != 0 )
                return(1);
            else if ( sentflags[BASILISK_BOBSPEND] != 0 ) // without ALICECLAIM this is loss due to inactivity
                return(1);
        }
    }
    return(0);
}

cJSON *basilisk_remember(struct supernet_info *myinfo,int64_t *KMDtotals,int64_t *BTCtotals,uint32_t requestid,uint32_t quoteid)
{
    FILE *fp; struct iguana_info *coin; int32_t sentflags[sizeof(txnames)/sizeof(*txnames)],i,n,j,len,needflag,secretstart,redeemlen,addflag,origfinishedflag = 0,finishedflag = 0,iambob = -1; int64_t srcamount,destamount=0,value,values[sizeof(txnames)/sizeof(*txnames)]; uint8_t secretAm[20],secretAm256[32],secretBn[20],secretBn256[32],pubkey33[33],redeemscript[1024],userdata[1024]; uint32_t plocktime,dlocktime,expiration=0,r,q,state,otherstate; char *secretstr,*srcstr,*deststr,str[65],src[64],dest[64],fname[512],*fstr,*dest33,*symbol,*txname,*Adest,*Bdest,*AAdest,*ABdest,destaddr[64],Adestaddr[64],alicecoin[64],bobcoin[64],*txbytes[sizeof(txnames)/sizeof(*txnames)]; long fsize; cJSON *txobj,*item,*sentobj,*array; bits256 checktxid,txid,pubA0,pubB0,pubB1,privAm,privBn,paymentspent,Apaymentspent,depositspent,zero,privkey,rev,myprivs[2],txids[sizeof(txnames)/sizeof(*txnames)];
    memset(values,0,sizeof(values));
    memset(txids,0,sizeof(txids));
    memset(secretAm,0,sizeof(secretAm));
    memset(secretAm256,0,sizeof(secretAm256));
    memset(secretBn,0,sizeof(secretBn));
    memset(secretBn256,0,sizeof(secretBn256));
    memset(pubkey33,0,sizeof(pubkey33));
    memset(txbytes,0,sizeof(txbytes));
    memset(sentflags,0,sizeof(sentflags));
    memset(myprivs,0,sizeof(myprivs));
    Apaymentspent = paymentspent = depositspent = rev = zero = pubA0 = pubB0 = pubB1 = privAm = privBn = myprivs[0];
    plocktime = dlocktime = 0;
    src[0] = dest[0] = bobcoin[0] = alicecoin[0] = 0;
    sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
    {
        if ( (item= cJSON_Parse(fstr)) != 0 )
        {
            iambob = jint(item,"iambob");
            if ( (secretstr= jstr(item,"secretAm")) != 0 && strlen(secretstr) == 40 )
                decode_hex(secretAm,20,secretstr);
            if ( (secretstr= jstr(item,"secretAm256")) != 0 && strlen(secretstr) == 64 )
                decode_hex(secretAm256,32,secretstr);
            if ( (secretstr= jstr(item,"secretBn")) != 0 && strlen(secretstr) == 40 )
                decode_hex(secretBn,20,secretstr);
            if ( (secretstr= jstr(item,"secretBn256")) != 0 && strlen(secretstr) == 64 )
                decode_hex(secretBn256,32,secretstr);
            if ( (srcstr= jstr(item,"src")) != 0 )
                safecopy(src,srcstr,sizeof(src));
            if ( (deststr= jstr(item,"dest")) != 0 )
                safecopy(dest,deststr,sizeof(dest));
            if ( (dest33= jstr(item,"dest33")) != 0 && strlen(dest33) == 66 )
            {
                decode_hex(pubkey33,33,dest33);
                //for (i=0; i<33; i++)
                //    printf("%02x",pubkey33[i]);
                //printf(" <- %s dest33\n",dest33);
            }
            plocktime = juint(item,"plocktime");
            dlocktime = juint(item,"dlocktime");
            r = juint(item,"requestid");
            q = juint(item,"quoteid");
            pubA0 = jbits256(item,"pubA0");
            pubB0 = jbits256(item,"pubB0");
            pubB1 = jbits256(item,"pubB1");
            privkey = jbits256(item,"myprivs0");
            if ( bits256_nonz(privkey) != 0 )
                myprivs[0] = privkey;
            privkey = jbits256(item,"myprivs1");
            if ( bits256_nonz(privkey) != 0 )
                myprivs[1] = privkey;
            privkey = jbits256(item,"privAm");
            if ( bits256_nonz(privkey) != 0 )
            {
                privAm = privkey;
                //printf("set privAm <- %s\n",bits256_str(str,privAm));
            }
            privkey = jbits256(item,"privBn");
            if ( bits256_nonz(privkey) != 0 )
            {
                privBn = privkey;
                //printf("set privBn <- %s\n",bits256_str(str,privBn));
            }
            expiration = juint(item,"expiration");
            state = jint(item,"state");
            otherstate = jint(item,"otherstate");
            srcamount = SATOSHIDEN * jdouble(item,"srcamount");
            destamount = SATOSHIDEN * jdouble(item,"destamount");
            txids[BASILISK_BOBDEPOSIT] = jbits256(item,"Bdeposit");
            txids[BASILISK_BOBREFUND] = jbits256(item,"Brefund");
            txids[BASILISK_ALICECLAIM] = jbits256(item,"Aclaim");
            txids[BASILISK_BOBPAYMENT] = jbits256(item,"Bpayment");
            txids[BASILISK_ALICESPEND] = jbits256(item,"Aspend");
            txids[BASILISK_BOBRECLAIM] = jbits256(item,"Breclaim");
            txids[BASILISK_ALICEPAYMENT] = jbits256(item,"Apayment");
            txids[BASILISK_BOBSPEND] = jbits256(item,"Bspend");
            txids[BASILISK_ALICERECLAIM] = jbits256(item,"Areclaim");
            txids[BASILISK_MYFEE] = jbits256(item,"myfee");
            txids[BASILISK_OTHERFEE] = jbits256(item,"otherfee");
            free_json(item);
        }
        free(fstr);
    }
    sprintf(fname,"%s/SWAPS/%u-%u.finished",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
    {
        //printf("%s -> (%s)\n",fname,fstr);
        if ( (txobj= cJSON_Parse(fstr)) != 0 )
        {
            paymentspent = jbits256(txobj,"paymentspent");
            Apaymentspent = jbits256(txobj,"Apaymentspent");
            depositspent = jbits256(txobj,"depositspent");
            if ( (array= jarray(&n,txobj,"values")) != 0 )
                for (i=0; i<n&&i<sizeof(txnames)/sizeof(*txnames); i++)
                    values[i] = SATOSHIDEN * jdouble(jitem(array,i),0);
            if ( (array= jarray(&n,txobj,"sentflags")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (txname= jstri(array,i)) != 0 )
                    {
                        for (j=0; j<sizeof(txnames)/sizeof(*txnames); j++)
                            if ( strcmp(txname,txnames[j]) == 0 )
                            {
                                sentflags[j] = 1;
                                //printf("finished.%s\n",txnames[j]);
                                break;
                            }
                    }
                }
            }
        }
        origfinishedflag = finishedflag = 1;
        free(fstr);
    }
    if ( iambob < 0 )
        return(0);
    item = cJSON_CreateObject();
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
    {
        needflag = addflag = 0;
        sprintf(fname,"%s/SWAPS/%u-%u.%s",GLOBAL_DBDIR,requestid,quoteid,txnames[i]), OS_compatible_path(fname);
        if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
        {
            if ( finishedflag == 0 )
                printf("%s\n",fname);
            //printf("%s -> (%s)\n",fname,fstr);
            if ( (txobj= cJSON_Parse(fstr)) != 0 )
            {
                //printf("TXOBJ.(%s)\n",jprint(txobj,0));
                iambob = jint(txobj,"iambob");
                txid = jbits256(txobj,"txid");
                if ( bits256_nonz(txid) == 0 )
                    continue;
                txids[i] = txid;
                if ( jobj(txobj,"tx") != 0 )
                {
                    txbytes[i] = clonestr(jstr(txobj,"tx"));
                    //printf("[%s] TX.(%s)\n",txnames[i],txbytes[i]);
                }
                if ( (value= jdouble(txobj,"amount") * SATOSHIDEN) == 0 )
                    value = jdouble(txobj,"value") * SATOSHIDEN;
                values[i] = value;
                if ( (symbol= jstr(txobj,"coin")) != 0 )
                {
                    if ( i == BASILISK_ALICESPEND || i == BASILISK_BOBPAYMENT || i == BASILISK_BOBDEPOSIT || i == BASILISK_BOBREFUND || i == BASILISK_BOBRECLAIM || i == BASILISK_ALICECLAIM )
                        safecopy(bobcoin,symbol,sizeof(bobcoin));
                    else if ( i == BASILISK_BOBSPEND || i == BASILISK_ALICEPAYMENT || i == BASILISK_ALICERECLAIM )
                        safecopy(alicecoin,symbol,sizeof(alicecoin));
                    if ( finishedflag == 0 )
                    {
                        if ( (sentobj= basilisk_swapgettx(myinfo,symbol,txid)) == 0 )
                        {
                            //printf("%s %s ready to broadcast\n",symbol,bits256_str(str2,txid));
                        }
                        else
                        {
                            checktxid = jbits256(sentobj,"txid");
                            if ( bits256_nonz(checktxid) == 0 )
                                checktxid = jbits256(sentobj,"hash");
                            if ( bits256_cmp(checktxid,txid) == 0 )
                            {
                                //printf(">>>>>> %s txid %s\n",jprint(sentobj,0),bits256_str(str,txid));
                                sentflags[i] = 1;
                            }
                            free_json(sentobj);
                        }
                        printf("%s %s %.8f\n",txnames[i],bits256_str(str,txid),dstr(value));
                    }
                }
            } //else printf("no symbol\n");
            free(fstr);
        } else if ( finishedflag == 0 )
            printf("%s not finished\n",fname);
    }
    //printf("iambob.%d src.%s dest.%s bob.%s alice.%s pubA0.(%s)\n",iambob,src,dest,bobcoin,alicecoin,bits256_str(str,pubA0));
    Adestaddr[0] = destaddr[0] = 0;
    Adest = Bdest = AAdest = ABdest = 0;
    if ( bobcoin[0] == 0 || alicecoin[0] == 0 )
        return(0);
    //printf("privAm.(%s) %p/%p\n",bits256_str(str,privAm),Adest,AAdest);
    //printf("privBn.(%s) %p/%p\n",bits256_str(str,privBn),Bdest,ABdest);
    if ( finishedflag == 0 && bobcoin[0] != 0 && alicecoin[0] != 0 )
    {
        if ( iambob == 0 )
        {
            if ( (coin= iguana_coinfind(alicecoin)) != 0 )
            {
                bitcoin_address(Adestaddr,coin->chain->pubtype,pubkey33,33);
                AAdest = Adestaddr;
            }
            if ( (coin= iguana_coinfind(bobcoin)) != 0 )
            {
                bitcoin_address(destaddr,coin->chain->pubtype,pubkey33,33);
                Adest = destaddr;
            }
        }
        else
        {
            if ( (coin= iguana_coinfind(bobcoin)) != 0 )
            {
                bitcoin_address(destaddr,coin->chain->pubtype,pubkey33,33);
                Bdest = destaddr;
            }
            if ( (coin= iguana_coinfind(alicecoin)) != 0 )
            {
                bitcoin_address(Adestaddr,coin->chain->pubtype,pubkey33,33);
                ABdest = Adestaddr;
            }
        }
        if ( sentflags[BASILISK_ALICEPAYMENT] == 0 && bits256_nonz(txids[BASILISK_ALICEPAYMENT]) != 0 )
        {
            printf("txbytes.%p Apayment.%s\n",txbytes[BASILISK_ALICEPAYMENT],bits256_str(str,txids[BASILISK_ALICEPAYMENT]));
            if ( txbytes[BASILISK_ALICEPAYMENT] != 0 )
                sentflags[BASILISK_ALICEPAYMENT] = 1;
            else if ( (sentobj= basilisk_swapgettx(myinfo,alicecoin,txids[BASILISK_ALICEPAYMENT])) != 0 )
            {
                sentflags[BASILISK_ALICEPAYMENT] = 1;
                free_json(sentobj);
            }
        }
        paymentspent = basilisk_swap_spendupdate(myinfo,bobcoin,sentflags,txids,BASILISK_BOBPAYMENT,BASILISK_ALICESPEND,BASILISK_BOBRECLAIM,0,Adest,Bdest);
        Apaymentspent = basilisk_swap_spendupdate(myinfo,alicecoin,sentflags,txids,BASILISK_ALICEPAYMENT,BASILISK_ALICERECLAIM,BASILISK_BOBSPEND,0,AAdest,ABdest);
        depositspent = basilisk_swap_spendupdate(myinfo,bobcoin,sentflags,txids,BASILISK_BOBDEPOSIT,BASILISK_ALICECLAIM,BASILISK_BOBREFUND,0,Adest,Bdest);
        finishedflag = basilisk_swap_isfinished(iambob,txids,sentflags,paymentspent,Apaymentspent,depositspent);
        if ( iambob == 0 )
        {
            if ( sentflags[BASILISK_ALICESPEND] == 0 )
            {
                if ( sentflags[BASILISK_BOBPAYMENT] != 0 && bits256_nonz(paymentspent) == 0 )
                {
                    //if ( txbytes[BASILISK_ALICESPEND] == 0 )
                    {
                        if ( bits256_nonz(txids[BASILISK_BOBPAYMENT]) != 0 )
                        {
                            // alicespend
                            for (j=0; j<32; j++)
                                rev.bytes[j] = privAm.bytes[31 - j];
                            revcalc_rmd160_sha256(secretAm,rev);//privAm);
                            vcalc_sha256(0,secretAm256,rev.bytes,sizeof(rev));
                            redeemlen = basilisk_swap_bobredeemscript(0,&secretstart,redeemscript,plocktime,pubA0,pubB0,pubB1,rev,privBn,secretAm,secretAm256,secretBn,secretBn256);
                            len = basilisk_swapuserdata(userdata,rev,0,myprivs[0],redeemscript,redeemlen);
                            printf("alicespend len.%d redeemlen.%d\n",len,redeemlen);
                            if ( (txbytes[BASILISK_ALICESPEND]= basilisk_swap_bobtxspend("alicespend",myinfo,bobcoin,myprivs[0],0,redeemscript,redeemlen,userdata,len,txids[BASILISK_BOBPAYMENT],0,pubkey33,1,expiration,&values[BASILISK_ALICESPEND])) != 0 )
                                printf("alicespend.(%s)\n",txbytes[BASILISK_ALICESPEND]);
                        }
                    }
                    if ( txbytes[BASILISK_ALICESPEND] != 0 )
                    {
                        txids[BASILISK_ALICESPEND] = basilisk_swap_sendrawtransaction(myinfo,"alicespend",bobcoin,txbytes[BASILISK_ALICESPEND]);
                        if ( bits256_nonz(txids[BASILISK_ALICESPEND]) != 0 ) // tested
                        {
                            sentflags[BASILISK_ALICESPEND] = 1;
                            paymentspent = txids[BASILISK_ALICESPEND];
                        }
                    }
                }
            }
            if ( sentflags[BASILISK_ALICECLAIM] == 0 && sentflags[BASILISK_BOBDEPOSIT] != 0 && bits256_nonz(txids[BASILISK_BOBDEPOSIT]) != 0 && bits256_nonz(depositspent) == 0 )
            {
                if ( time(NULL) > expiration )
                {
                    //if ( txbytes[BASILISK_ALICECLAIM] == 0 )
                    {
                        redeemlen = basilisk_swap_bobredeemscript(1,&secretstart,redeemscript,dlocktime,pubA0,pubB0,pubB1,privAm,zero,secretAm,secretAm256,secretBn,secretBn256);
                        if ( redeemlen > 0 )
                        {
                            len = basilisk_swapuserdata(userdata,zero,1,myprivs[0],redeemscript,redeemlen);
                            if ( (txbytes[BASILISK_ALICECLAIM]= basilisk_swap_bobtxspend("aliceclaim",myinfo,bobcoin,myprivs[0],0,redeemscript,redeemlen,userdata,len,txids[BASILISK_BOBDEPOSIT],0,pubkey33,0,expiration,&values[BASILISK_ALICECLAIM])) != 0 )
                                printf("privBn.(%s) aliceclaim.(%s)\n",bits256_str(str,privBn),txbytes[BASILISK_ALICECLAIM]);
                        }
                    }
                    if ( txbytes[BASILISK_ALICECLAIM] != 0 )
                    {
                        txids[BASILISK_ALICECLAIM] = basilisk_swap_sendrawtransaction(myinfo,"aliceclaim",bobcoin,txbytes[BASILISK_ALICECLAIM]);
                        if ( bits256_nonz(txids[BASILISK_ALICECLAIM]) != 0 ) // tested
                        {
                            sentflags[BASILISK_ALICECLAIM] = 1;
                            depositspent = txids[BASILISK_ALICECLAIM];
                        }
                    }
                } else printf("now %u before expiration %u\n",(uint32_t)time(NULL),expiration);
            }
            if ( sentflags[BASILISK_ALICEPAYMENT] != 0 && bits256_nonz(Apaymentspent) == 0 && sentflags[BASILISK_ALICECLAIM] == 0 )
            {
                //if ( txbytes[BASILISK_ALICERECLAIM] == 0 )
                {
                    privBn = basilisk_swap_privBn_extract(myinfo,&txids[BASILISK_BOBREFUND],bobcoin,txids[BASILISK_BOBDEPOSIT],privBn);
                    if ( bits256_nonz(txids[BASILISK_ALICEPAYMENT]) != 0 && bits256_nonz(privAm) != 0 && bits256_nonz(privBn) != 0 )
                    {
                        if ( (txbytes[BASILISK_ALICERECLAIM]= basilisk_swap_Aspend("alicereclaim",myinfo,alicecoin,privAm,privBn,txids[BASILISK_ALICEPAYMENT],0,pubkey33,expiration,&values[BASILISK_ALICERECLAIM])) != 0 )
                            printf("privBn.(%s) alicereclaim.(%s)\n",bits256_str(str,privBn),txbytes[BASILISK_ALICERECLAIM]);
                    }
                }
                if ( txbytes[BASILISK_ALICERECLAIM] != 0 )
                {
                    txids[BASILISK_ALICERECLAIM] = basilisk_swap_sendrawtransaction(myinfo,"alicereclaim",alicecoin,txbytes[BASILISK_ALICERECLAIM]);
                    if ( bits256_nonz(txids[BASILISK_ALICERECLAIM]) != 0 ) // tested
                    {
                        sentflags[BASILISK_ALICERECLAIM] = 1;
                        Apaymentspent = txids[BASILISK_ALICERECLAIM];
                    }
                }
            }
        }
        else if ( iambob == 1 )
        {
            if ( sentflags[BASILISK_BOBSPEND] == 0 && bits256_nonz(Apaymentspent) == 0 )
            {
                printf("try to bobspend aspend.%s have privAm.%d\n",bits256_str(str,txids[BASILISK_ALICESPEND]),bits256_nonz(privAm));
                if ( bits256_nonz(txids[BASILISK_ALICESPEND]) != 0 || bits256_nonz(privAm) != 0 )
                {
                    //if ( txbytes[BASILISK_BOBSPEND] == 0 )
                    {
                        if ( bits256_nonz(privAm) == 0 )
                        {
                            privAm = basilisk_swap_privbob_extract(myinfo,bobcoin,txids[BASILISK_ALICESPEND],0,1);
                        }
                        if ( bits256_nonz(privAm) != 0 && bits256_nonz(privBn) != 0 )
                        {
                            if ( (txbytes[BASILISK_BOBSPEND]= basilisk_swap_Aspend("bobspend",myinfo,alicecoin,privAm,privBn,txids[BASILISK_ALICEPAYMENT],0,pubkey33,expiration,&values[BASILISK_BOBSPEND])) != 0 )
                                printf("bobspend.(%s)\n",txbytes[BASILISK_BOBSPEND]);
                        }
                    }
                    if ( txbytes[BASILISK_BOBSPEND] != 0 )
                    {
                        txids[BASILISK_BOBSPEND] = basilisk_swap_sendrawtransaction(myinfo,"bobspend",alicecoin,txbytes[BASILISK_BOBSPEND]);
                        if ( bits256_nonz(txids[BASILISK_BOBSPEND]) != 0 ) // tested
                        {
                            sentflags[BASILISK_BOBSPEND] = 1;
                            Apaymentspent = txids[BASILISK_BOBSPEND];
                        }
                    }
                }
            }
            if ( sentflags[BASILISK_BOBRECLAIM] == 0 && sentflags[BASILISK_BOBPAYMENT] != 0 && bits256_nonz(txids[BASILISK_BOBPAYMENT]) != 0 && time(NULL) > expiration && bits256_nonz(paymentspent) == 0 )
            {
                //if ( txbytes[BASILISK_BOBRECLAIM] == 0 )
                {
                    // bobreclaim
                    redeemlen = basilisk_swap_bobredeemscript(0,&secretstart,redeemscript,plocktime,pubA0,pubB0,pubB1,zero,privBn,secretAm,secretAm256,secretBn,secretBn256);
                    if ( redeemlen > 0 )
                    {
                        len = basilisk_swapuserdata(userdata,zero,1,myprivs[1],redeemscript,redeemlen);
                        if ( (txbytes[BASILISK_BOBRECLAIM]= basilisk_swap_bobtxspend("bobrefund",myinfo,bobcoin,myprivs[1],0,redeemscript,redeemlen,userdata,len,txids[BASILISK_BOBPAYMENT],0,pubkey33,0,expiration,&values[BASILISK_BOBRECLAIM])) != 0 )
                        {
                            int32_t z;
                            for (z=0; z<20; z++)
                                printf("%02x",secretAm[z]);
                            printf(" secretAm, myprivs[1].(%s) bobreclaim.(%s)\n",bits256_str(str,myprivs[1]),txbytes[BASILISK_BOBRECLAIM]);
                        }
                    }
                }
                if ( txbytes[BASILISK_BOBRECLAIM] != 0 )
                {
                    txids[BASILISK_BOBRECLAIM] = basilisk_swap_sendrawtransaction(myinfo,"bobreclaim",bobcoin,txbytes[BASILISK_BOBRECLAIM]);
                    if ( bits256_nonz(txids[BASILISK_BOBRECLAIM]) != 0 ) // tested
                    {
                        sentflags[BASILISK_BOBRECLAIM] = 1;
                        paymentspent = txids[BASILISK_BOBRECLAIM];
                    }
                }
            }
            if ( sentflags[BASILISK_BOBREFUND] == 0 && sentflags[BASILISK_BOBDEPOSIT] != 0 && bits256_nonz(txids[BASILISK_BOBDEPOSIT]) != 0 && bits256_nonz(depositspent) == 0 )
            {
                if ( bits256_nonz(paymentspent) != 0 || time(NULL) > expiration )
                {
                    printf("do the refund!\n");
                    //if ( txbytes[BASILISK_BOBREFUND] == 0 )
                    {
                        revcalc_rmd160_sha256(secretBn,privBn);
                        vcalc_sha256(0,secretBn256,privBn.bytes,sizeof(privBn));
                        redeemlen = basilisk_swap_bobredeemscript(1,&secretstart,redeemscript,dlocktime,pubA0,pubB0,pubB1,privAm,privBn,secretAm,secretAm256,secretBn,secretBn256);
                        len = basilisk_swapuserdata(userdata,privBn,0,myprivs[0],redeemscript,redeemlen);
                        if ( (txbytes[BASILISK_BOBREFUND]= basilisk_swap_bobtxspend("bobrefund",myinfo,bobcoin,myprivs[0],0,redeemscript,redeemlen,userdata,len,txids[BASILISK_BOBDEPOSIT],0,pubkey33,1,expiration,&values[BASILISK_BOBREFUND])) != 0 )
                            printf("pubB1.(%s) bobrefund.(%s)\n",bits256_str(str,pubB1),txbytes[BASILISK_BOBREFUND]);
                    }
                    if ( txbytes[BASILISK_BOBREFUND] != 0 )
                    {
                        txids[BASILISK_BOBREFUND] = basilisk_swap_sendrawtransaction(myinfo,"bobrefund",bobcoin,txbytes[BASILISK_BOBREFUND]);
                        if ( bits256_nonz(txids[BASILISK_BOBREFUND]) != 0 ) // tested
                        {
                            sentflags[BASILISK_BOBREFUND] = 1;
                            depositspent = txids[BASILISK_BOBREFUND];
                        }
                    }
                } else printf("time %u vs expiration %u\n",(uint32_t)time(NULL),expiration);
            }
        }
    }
    //printf("finish.%d iambob.%d REFUND %d %d %d %d\n",finishedflag,iambob,sentflags[BASILISK_BOBREFUND] == 0,sentflags[BASILISK_BOBDEPOSIT] != 0,bits256_nonz(txids[BASILISK_BOBDEPOSIT]) != 0,bits256_nonz(depositspent) == 0);
    if ( sentflags[BASILISK_ALICESPEND] != 0 || sentflags[BASILISK_BOBRECLAIM] != 0 )
        sentflags[BASILISK_BOBPAYMENT] = 1;
    if ( sentflags[BASILISK_ALICERECLAIM] != 0 || sentflags[BASILISK_BOBSPEND] != 0 )
        sentflags[BASILISK_ALICEPAYMENT] = 1;
    if ( sentflags[BASILISK_ALICECLAIM] != 0 || sentflags[BASILISK_BOBREFUND] != 0 )
        sentflags[BASILISK_BOBDEPOSIT] = 1;
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        if ( bits256_nonz(txids[i]) != 0 && values[i] == 0 )
            values[i] = basilisk_txvalue(myinfo,basilisk_isbobcoin(iambob,i) ? bobcoin : alicecoin,txids[i],0);
    if ( origfinishedflag == 0 )
    {
        printf("iambob.%d Apaymentspent.(%s) alice.%d bob.%d %s %.8f\n",iambob,bits256_str(str,Apaymentspent),sentflags[BASILISK_ALICERECLAIM],sentflags[BASILISK_BOBSPEND],alicecoin,dstr(values[BASILISK_ALICEPAYMENT]));
        printf("paymentspent.(%s) alice.%d bob.%d %s %.8f\n",bits256_str(str,paymentspent),sentflags[BASILISK_ALICESPEND],sentflags[BASILISK_BOBRECLAIM],bobcoin,dstr(values[BASILISK_BOBPAYMENT]));
        printf("depositspent.(%s) alice.%d bob.%d %s %.8f\n",bits256_str(str,depositspent),sentflags[BASILISK_ALICECLAIM],sentflags[BASILISK_BOBREFUND],bobcoin,dstr(values[BASILISK_BOBDEPOSIT]));
    }
    values[BASILISK_OTHERFEE] = 0;
    if ( iambob == 0 )
    {
        if ( strcmp(alicecoin,"BTC") == 0 )
        {
            BTCtotals[BASILISK_ALICEPAYMENT] -= values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_ALICEPAYMENT];
            BTCtotals[BASILISK_ALICERECLAIM] += values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_ALICERECLAIM];
            BTCtotals[BASILISK_MYFEE] -= values[BASILISK_MYFEE] * sentflags[BASILISK_MYFEE];
        }
        else if ( strcmp(alicecoin,"KMD") == 0 )
        {
            KMDtotals[BASILISK_ALICEPAYMENT] -= values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_ALICEPAYMENT];
            KMDtotals[BASILISK_ALICERECLAIM] += values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_ALICERECLAIM];
            KMDtotals[BASILISK_MYFEE] -= values[BASILISK_MYFEE] * sentflags[BASILISK_MYFEE];
        }
        if ( strcmp(bobcoin,"KMD") == 0 )
        {
            KMDtotals[BASILISK_ALICESPEND] += values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_ALICESPEND];
            KMDtotals[BASILISK_ALICECLAIM] += values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_ALICECLAIM];
        }
        else if ( strcmp(bobcoin,"BTC") == 0 )
        {
            BTCtotals[BASILISK_ALICESPEND] += values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_ALICESPEND];
            BTCtotals[BASILISK_ALICECLAIM] += values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_ALICECLAIM];
        }
    }
    else
    {
        if ( strcmp(bobcoin,"BTC") == 0 )
        {
            BTCtotals[BASILISK_BOBPAYMENT] -= values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_BOBPAYMENT];
            BTCtotals[BASILISK_BOBDEPOSIT] -= values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_BOBDEPOSIT];
            BTCtotals[BASILISK_BOBREFUND] += values[BASILISK_BOBREFUND] * sentflags[BASILISK_BOBREFUND];
            BTCtotals[BASILISK_BOBRECLAIM] += values[BASILISK_BOBRECLAIM] * sentflags[BASILISK_BOBRECLAIM];
            BTCtotals[BASILISK_MYFEE] -= values[BASILISK_MYFEE] * sentflags[BASILISK_MYFEE];
        }
        else if ( strcmp(bobcoin,"KMD") == 0 )
        {
            KMDtotals[BASILISK_BOBPAYMENT] -= values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_BOBPAYMENT];
            KMDtotals[BASILISK_BOBDEPOSIT] -= values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_BOBDEPOSIT];
            KMDtotals[BASILISK_BOBREFUND] += values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_BOBREFUND];
            KMDtotals[BASILISK_BOBRECLAIM] += values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_BOBRECLAIM];
            KMDtotals[BASILISK_MYFEE] -= values[BASILISK_MYFEE] * sentflags[BASILISK_MYFEE];
        }
        if ( strcmp(alicecoin,"KMD") == 0 )
        {
            KMDtotals[BASILISK_BOBSPEND] += values[BASILISK_BOBSPEND] * sentflags[BASILISK_BOBSPEND];
        }
        else if ( strcmp(alicecoin,"BTC") == 0 )
        {
            BTCtotals[BASILISK_BOBSPEND] += values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_BOBSPEND];
        }
    }
    finishedflag = basilisk_swap_isfinished(iambob,txids,sentflags,paymentspent,Apaymentspent,depositspent);
    jaddnum(item,"requestid",requestid);
    jaddnum(item,"quoteid",quoteid);
    jadd(item,"txs",array);
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
    {
        if ( sentflags[i] != 0 )
            jaddistr(array,txnames[i]);
        if ( txbytes[i] != 0 )
            free(txbytes[i]);
    }
    jadd(item,"sentflags",array);
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        jaddinum(array,dstr(values[i]));
    jadd(item,"values",array);
    jaddstr(item,"result","success");
    if ( finishedflag != 0 )
        jaddstr(item,"status","finished");
    else jaddstr(item,"status","pending");
    bits256_str(str,paymentspent), jaddbits256(item,"paymentspent",paymentspent);
    bits256_str(str,Apaymentspent), jaddbits256(item,"Apaymentspent",Apaymentspent);
    bits256_str(str,depositspent), jaddbits256(item,"depositspent",depositspent);
    if ( origfinishedflag == 0 && finishedflag != 0 )
    {
        //printf("SWAP %u-%u finished!\n",requestid,quoteid);
        sprintf(fname,"%s/SWAPS/%u-%u.finished",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            char *itemstr;
            itemstr = jprint(item,0);
            fprintf(fp,"%s\n",itemstr);
            free(itemstr);
            fclose(fp);
        }
    }
    return(item);
}

char *basilisk_swaplist(struct supernet_info *myinfo)
{
    char fname[512],*status; FILE *fp; cJSON *item,*retjson,*array,*totalsobj; uint32_t quoteid,requestid; int64_t KMDtotals[16],BTCtotals[16],Btotal,Ktotal; int32_t i;
    memset(KMDtotals,0,sizeof(KMDtotals));
    memset(BTCtotals,0,sizeof(BTCtotals));
    //,statebits; int32_t optionduration; struct basilisk_request R; bits256 privkey;
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        struct basilisk_swap *swap; int32_t flag = 0;
        while ( fread(&requestid,1,sizeof(requestid),fp) == sizeof(requestid) && fread(&quoteid,1,sizeof(quoteid),fp) == sizeof(quoteid) )
        {
            flag = 0;
            for (i=0; i<myinfo->numswaps; i++)
                if ( (swap= myinfo->swaps[i]) != 0 && swap->I.req.requestid == requestid && swap->I.req.quoteid == quoteid )
                {
                    jaddi(array,basilisk_swapjson(myinfo,swap));
                    flag = 1;
                    break;
                }
            if ( flag == 0 )
            {
                if ( (item= basilisk_remember(myinfo,KMDtotals,BTCtotals,requestid,quoteid)) != 0 )
                {
                    jaddi(array,item);
                    if ( 1 && (status= jstr(item,"status")) != 0 && strcmp(status,"pending") == 0 )
                        break;
                }
            }
        }
        fclose(fp);
    }
    jaddstr(retjson,"result","success");
    jadd(retjson,"swaps",array);
    if ( cJSON_GetArraySize(array) > 0 )
    {
        totalsobj = cJSON_CreateObject();
        for (Btotal=i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
            if ( BTCtotals[i] != 0 )
                jaddnum(totalsobj,txnames[i],dstr(BTCtotals[i])), Btotal += BTCtotals[i];
        jadd(retjson,"BTCtotals",totalsobj);
        totalsobj = cJSON_CreateObject();
        for (Ktotal=i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
            if ( KMDtotals[i] != 0 )
                jaddnum(totalsobj,txnames[i],dstr(KMDtotals[i])), Ktotal += KMDtotals[i];
        jadd(retjson,"KMDtotals",totalsobj);
        jaddnum(retjson,"KMDtotal",dstr(Ktotal));
        jaddnum(retjson,"BTCtotal",dstr(Btotal));
        if ( Ktotal > 0 && Btotal < 0 )
            jaddnum(retjson,"avebuy",(double)-Btotal/Ktotal);
        else if ( Ktotal < 0 && Btotal > 0 )
            jaddnum(retjson,"avesell",(double)-Btotal/Ktotal);
    }
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(myinfo->linfos)/sizeof(*myinfo->linfos); i++)
    {
        if ( myinfo->linfos[i].base[0] != 0 && myinfo->linfos[i].rel[0] != 0 )
            jaddi(array,linfo_json(&myinfo->linfos[i]));
    }
    jadd(retjson,"quotes",array);
    return(jprint(retjson,1));
}

