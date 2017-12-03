
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
//  LP_utxos.c
//  marketmaker
//

int32_t LP_privkey_init(int32_t mypubsock,struct iguana_info *coin,bits256 myprivkey,bits256 mypub)
{
    int32_t enable_utxos = 0;
    char *script,destaddr[64]; cJSON *array,*item; bits256 txid,deposittxid,zero; int32_t used,i,flag=0,height,n,cmpflag,iambob,vout,depositvout; uint64_t *values=0,satoshis,txfee,biggerval,value,total = 0; int64_t targetval; //struct LP_utxoinfo *utxo;
    if ( coin == 0 || (IAMLP == 0 && coin->inactive != 0) )
    {
        //printf("coin not active\n");
        return(0);
    }
    if ( coin->privkeydepth > 0 )
        return(0);
    coin->privkeydepth++;
    LP_address(coin,coin->smartaddr);
    //if ( coin->inactive == 0 )
    //    LP_listunspent_issue(coin->symbol,coin->smartaddr,0);
    memset(zero.bytes,0,sizeof(zero));
    array = LP_listunspent(coin->symbol,coin->smartaddr,zero,zero);
    if ( array != 0 )
    {
        txfee = LP_txfeecalc(coin,0,0);
        if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            coin->numutxos = n;
            //printf("LP_privkey_init %s %d\n",coin->symbol,n);
            for (iambob=0; iambob<=1; iambob++)
            {
                if ( iambob == 0 )
                    values = calloc(n,sizeof(*values));
                else memset(values,0,n * sizeof(*values));
                used = 0;
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    value = LP_listunspent_parseitem(coin,&txid,&vout,&height,item);
                    satoshis = LP_txvalue(destaddr,coin->symbol,txid,vout);
                    if ( satoshis != 0 && satoshis != value )
                        printf("%s %s  privkey_init value  %.8f vs %.8f (%s) %.8f %.8f\n",coin->symbol,coin->smartaddr,dstr(satoshis),dstr(value),jprint(item,0),jdouble(item,"amount"),jdouble(item,"interest"));
                    if ( coin->electrum != 0 || LP_inventory_prevent(iambob,coin->symbol,txid,vout) == 0 )//&& height > 0 )
                    {
                        values[i] = satoshis;
                        //flag += LP_address_utxoadd(coin,destaddr,txid,vout,satoshis,height,-1);
                    } else used++;
                }
                //printf("array.%d\n",n);
                while ( used < n-1 )
                {
                    //for (i=0; i<n; i++)
                    //   printf("%.8f ",dstr(values[i]));
                    //printf("used.%d of n.%d\n",used,n);
                    if ( (i= LP_maxvalue(values,n)) >= 0 )
                    {
                        item = jitem(array,i);
                        if ( coin->electrum == 0 )
                        {
                            deposittxid = jbits256(item,"txid");
                            depositvout = juint(item,"vout");
                            script = jstr(item,"scriptPubKey");
                        }
                        else
                        {
                            deposittxid = jbits256(item,"tx_hash");
                            depositvout = juint(item,"tx_pos");
                            script = coin->smartaddr;
                        }
                        biggerval = values[i];
                        values[i] = 0, used++;
                        if ( iambob == 0 )
                            targetval = (biggerval / 776) + txfee;
                        else targetval = (biggerval / 9) * 8 + 2*txfee;
                        if ( targetval < txfee*2 )
                            targetval = txfee*2;
                        //printf("iambob.%d i.%d deposit %.8f min %.8f target %.8f\n",iambob,i,dstr(biggerval),dstr((1+LP_MINSIZE_TXFEEMULT)*txfee),dstr(targetval));
                        if ( biggerval < (1+LP_MINSIZE_TXFEEMULT)*txfee )
                            continue;
                        i = -1;
                        if ( iambob != 0 )
                        {
                            if ( (i= LP_nearestvalue(iambob,values,n,targetval)) < 0 )
                                targetval /= 4;
                            if ( targetval < txfee*(1+LP_MINSIZE_TXFEEMULT) )
                                continue;
                        }
                        if ( i >= 0 || (i= LP_nearestvalue(iambob,values,n,targetval)) >= 0 )
                        {
                            //printf("iambob.%d i.%d %.8f target %.8f\n",iambob,i,dstr(biggerval),dstr(targetval));
                            item = jitem(array,i);
                            cmpflag = 0;
                            if ( coin->electrum == 0 )
                            {
                                txid = jbits256(item,"txid");
                                vout = juint(item,"vout");
                                if ( jstr(item,"scriptPubKey") != 0 && strcmp(script,jstr(item,"scriptPubKey")) == 0 )
                                    cmpflag = 1;
                            }
                            else
                            {
                                txid = jbits256(item,"tx_hash");
                                vout = juint(item,"tx_pos");
                                cmpflag = 1;
                            }
                            if ( cmpflag != 0 )
                            {
                                value = values[i];
                                values[i] = 0, used++;
                                /*portable_mutex_lock(&LP_UTXOmutex);
                                if ( iambob != 0 )
                                {
                                    if ( (utxo= LP_utxoadd(1,coin->symbol,txid,vout,value,deposittxid,depositvout,biggerval,coin->smartaddr,mypub,LP_gui,G.LP_sessionid,value)) != 0 )
                                    {
                                    }
                                }
                                else
                                {
                                    //printf("call utxoadd\n");
                                    if ( (utxo= LP_utxoadd(0,coin->symbol,deposittxid,depositvout,biggerval,txid,vout,value,coin->smartaddr,mypub,LP_gui,G.LP_sessionid,biggerval)) != 0 )
                                    {
                                    }
                                }
                                portable_mutex_unlock(&LP_UTXOmutex);*/
                                total += value;
                            } // else printf("scriptmismatch.(%s) vs %s\n",script,jprint(item,0));
                        } //else printf("nothing near i.%d\n",i);
                    } else break;
                }
                if ( enable_utxos == 0 )
                    break;
            }
        }
        free_json(array);
        if ( 0 && flag != 0 )
            LP_postutxos(coin->symbol,coin->smartaddr);
    }
    if ( values != 0 )
        free(values);
    if ( coin->privkeydepth > 0 )
        coin->privkeydepth--;
    //printf("privkey.%s %.8f\n",symbol,dstr(total));
    return(flag);
}

char *LP_secretaddresses(void *ctx,char *prefix,char *passphrase,int32_t n,uint8_t taddr,uint8_t pubtype)
{
    int32_t i; uint8_t tmptype,pubkey33[33],rmd160[20]; char output[777*45],str[65],str2[65],buf[8192],wifstr[128],coinaddr[64]; bits256 checkprivkey,privkey,pubkey; cJSON *retjson;
    retjson = cJSON_CreateObject();
    if ( prefix == 0 || prefix[0] == 0 )
        prefix = "secretaddress";
    if ( passphrase == 0 || passphrase[0] == 0 )
        passphrase = "password";
    if ( n <= 0 )
        n = 16;
    else if ( n > 777 )
        n = 777;
    conv_NXTpassword(privkey.bytes,pubkey.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
    bitcoin_priv2pub(ctx,pubkey33,coinaddr,privkey,taddr,pubtype);
    printf("generator (%s) secrets.[%d] <%s> t.%u p.%u\n",coinaddr,n,passphrase,taddr,pubtype);
    sprintf(output,"\"addresses\":[");
    for (i=0; i<n; i++)
    {
        sprintf(buf,"%s %s %03d",prefix,passphrase,i);
        conv_NXTpassword(privkey.bytes,pubkey.bytes,(uint8_t *)buf,(int32_t)strlen(buf));
        bitcoin_priv2pub(ctx,pubkey33,coinaddr,privkey,taddr,pubtype);
        bitcoin_priv2wif(0,wifstr,privkey,188);
        bitcoin_wif2priv(0,&tmptype,&checkprivkey,wifstr);
        bitcoin_addr2rmd160(taddr,&tmptype,rmd160,coinaddr);
        if ( bits256_cmp(checkprivkey,privkey) != 0 )
        {
            printf("WIF.(%s) error -> %s vs %s?\n",wifstr,bits256_str(str,privkey),bits256_str(str2,checkprivkey));
            free_json(retjson);
            return(clonestr("{\"error\":\"couldnt validate wifstr\"}"));
        }
        else if ( tmptype != pubtype )
        {
            printf("checktype.%d != pubtype.%d\n",tmptype,pubtype);
            free_json(retjson);
            return(clonestr("{\"error\":\"couldnt validate pubtype\"}"));
        }
        jaddstr(retjson,coinaddr,wifstr);
        sprintf(output+strlen(output),"\\\"%s\\\"%c ",coinaddr,i<n-1?',':' ');
        printf("./komodo-cli jumblr_secret %s\n",coinaddr);
    }
    printf("%s]\n",output);
    return(jprint(retjson,1));
}

bits256 LP_privkeycalc(void *ctx,uint8_t *pubkey33,bits256 *pubkeyp,struct iguana_info *coin,char *passphrase,char *wifstr)
{
    //static uint32_t counter;
    bits256 privkey,userpub,zero,userpass,checkkey; char tmpstr[128]; cJSON *retjson; uint8_t tmptype; int32_t notarized;
    if ( passphrase != 0 && passphrase[0] != 0 )
    {
        calc_NXTaddr(G.LP_NXTaddr,userpub.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
        conv_NXTpassword(privkey.bytes,pubkeyp->bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
        //vcalc_sha256(0,checkkey.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
        //printf("SHA256.(%s) ",bits256_str(pstr,checkkey));
        //printf("privkey.(%s)\n",bits256_str(pstr,privkey));
    }
    else
    {
        bitcoin_wif2priv(coin->wiftaddr,&tmptype,&privkey,wifstr);
        if ( 0 )
        {
            char str[65],str2[65];
            checkkey = iguana_wif2privkey(wifstr);
            if ( bits256_cmp(checkkey,privkey) != 0 )
                printf("WIF.(%s) -> %s or %s?\n",wifstr,bits256_str(str,privkey),bits256_str(str2,checkkey));
        }
    }
    privkey.bytes[0] &= 248, privkey.bytes[31] &= 127, privkey.bytes[31] |= 64;
    bitcoin_priv2pub(ctx,coin->pubkey33,coin->smartaddr,privkey,coin->taddr,coin->pubtype);
    if ( coin->counter == 0 )
    {
        coin->counter++;
        memcpy(G.LP_pubsecp,coin->pubkey33,33);
        bitcoin_priv2wif(coin->wiftaddr,tmpstr,privkey,coin->wiftype);
        bitcoin_addr2rmd160(coin->taddr,&tmptype,G.LP_myrmd160,coin->smartaddr);
        LP_privkeyadd(privkey,G.LP_myrmd160);
        G.LP_privkey = privkey;
        if ( 0 && (coin->pubtype != 60 || strcmp(coin->symbol,"KMD") == 0) )
            printf("%s (%s) %d wif.(%s) (%s)\n",coin->symbol,coin->smartaddr,coin->pubtype,tmpstr,passphrase);
        if ( G.counter++ == 0 )
        {
            bitcoin_priv2wif(coin->wiftaddr,G.USERPASS_WIFSTR,privkey,188);
            bitcoin_wif2priv(coin->wiftaddr,&tmptype,&checkkey,G.USERPASS_WIFSTR);
            if ( bits256_cmp(checkkey,privkey) != 0 )
            {
                char str[65],str2[65];
                printf("FATAL ERROR converting USERPASS_WIFSTR %s -> %s != %s\n",G.USERPASS_WIFSTR,bits256_str(str,checkkey),bits256_str(str2,privkey));
                exit(-1);
            }
            conv_NXTpassword(userpass.bytes,pubkeyp->bytes,(uint8_t *)G.USERPASS_WIFSTR,(int32_t)strlen(G.USERPASS_WIFSTR));
            userpub = curve25519(userpass,curve25519_basepoint9());
            printf("userpass.(%s)\n",bits256_str(G.USERPASS,userpub));
        }
    }
    if ( coin->importedprivkey == 0 && coin->electrum == 0 && coin->userpass[0] != 0 && LP_getheight(&notarized,coin) > 0 )
    {
        memset(zero.bytes,0,sizeof(zero));
        LP_listunspent_issue(coin->symbol,coin->smartaddr,0,zero,zero);
        if ( (retjson= LP_importprivkey(coin->symbol,tmpstr,coin->smartaddr,-1)) != 0 )
        {
            if ( jobj(retjson,"error") != 0 )
            {
                printf("cant importprivkey.%s -> (%s), abort session\n",coin->symbol,jprint(retjson,1));
                exit(-1);
            }
            free_json(retjson);
        }
        coin->importedprivkey = (uint32_t)time(NULL);
    }
    vcalc_sha256(0,checkkey.bytes,privkey.bytes,sizeof(privkey));
    checkkey.bytes[0] &= 248, checkkey.bytes[31] &= 127, checkkey.bytes[31] |= 64;
    G.LP_mypub25519 = *pubkeyp = curve25519(checkkey,curve25519_basepoint9());
    G.LP_mypriv25519 = checkkey;
    LP_pubkeyadd(G.LP_mypub25519);
    return(privkey);
}

void LP_privkey_updates(void *ctx,int32_t pubsock,char *passphrase)
{
    struct iguana_info *coin,*tmp; bits256 pubkey,privkey; uint8_t pubkey33[33]; int32_t initonly;
    initonly = (passphrase != 0);
    memset(privkey.bytes,0,sizeof(privkey));
    memset(pubkey.bytes,0,sizeof(pubkey));
	//printf("Total coins: %d\n", HASH_COUNT(LP_coins));
	//int num_iter = 0;
    HASH_ITER(hh,LP_coins,coin,tmp)
    {
		//printf("LP_privkey_updates [%02d / %02d]\n", num_iter++, HASH_COUNT(LP_coins));
        if ( initonly != 0 )
        {
            coin->counter = 0;
            memset(coin->smartaddr,0,sizeof(coin->smartaddr));
            if ( bits256_nonz(privkey) == 0 || coin->smartaddr[0] == 0 )
                privkey = LP_privkeycalc(ctx,pubkey33,&pubkey,coin,passphrase,"");
        }
        //printf("i.%d of %d\n",i,LP_numcoins);
        else if ( IAMLP == 0 || coin->inactive == 0 )
        {
            //printf("from updates %s\n",coin->symbol);
            if ( 0 && LP_privkey_init(pubsock,coin,G.LP_privkey,G.LP_mypub25519) == 0 && (LP_rand() % 10) == 0 )
            {
                //LP_postutxos(coin->symbol,coin->smartaddr);
            }
        }
    }
}

int32_t LP_passphrase_init(char *passphrase,char *gui)
{
    static void *ctx; int32_t counter; //iambob,; struct LP_utxoinfo *utxo,*tmp;
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    if ( G.LP_pendingswaps != 0 )
        return(-1);
    G.initializing = 1;
    if ( gui == 0 )
        gui = "cli";
    counter = G.USERPASS_COUNTER;
    while ( G.waiting == 0 )
    {
        printf("waiting for G.waiting\n");
        sleep(5);
    }
    /*for (iambob=0; iambob<2; iambob++)
    {
        if ( G.LP_utxoinfos[iambob] != 0 )
        {
            HASH_ITER(hh,G.LP_utxoinfos[iambob],utxo,tmp)
            {
                HASH_DELETE(hh,G.LP_utxoinfos[iambob],utxo);
                //free(utxo);
            }
        }
        if ( G.LP_utxoinfos2[iambob] != 0 )
        {
            G.LP_utxoinfos2[iambob] = 0;
            //HASH_ITER(hh,G.LP_utxoinfos2[iambob],utxo,tmp)
            //{
            //    HASH_DELETE(hh,G.LP_utxoinfos2[iambob],utxo);
            //    free(utxo);
            //}
        }
    }*/
    memset(&G,0,sizeof(G));
    LP_privkey_updates(ctx,LP_mypubsock,passphrase);
    init_hexbytes_noT(G.LP_myrmd160str,G.LP_myrmd160,20);
    G.LP_sessionid = (uint32_t)time(NULL);
    safecopy(G.gui,gui,sizeof(G.gui));
    G.USERPASS_COUNTER = counter;
    G.initializing = 0;
    return(0);
}


