
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
//  LP_rpc.c
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

char *dex_listtransactions(char *symbol,char *coinaddr,int32_t num,int32_t skip)
{
    return(0);
}

bits256 LP_privkey(char *coinaddr)
{
    bits256 privkey;
    return(privkey);
}

bits256 LP_pubkey(bits256 privkey)
{
    bits256 pubkey;
    pubkey = curve25519(privkey,curve25519_basepoint9());
    return(pubkey);
}

void LP_unspentslock(char *symbol,cJSON *vins)
{
    
}

void LP_unspents_mark(char *symbol,cJSON *vins)
{
    
}

uint64_t LP_getestimatedfee(char *symbol)
{
    return(200);
}

uint64_t LP_txfee(char *symbol)
{
    return(10000);
}

char *LP_validateaddress(char *symbol,char *address)
{
    char buf[128],*retstr=0; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"\"%s\"",address);
    retstr = bitcoind_passthru(symbol,coin->serverport,coin->userpass,"validateaddress",buf);
    usleep(10000);
    return(retstr);
}

cJSON *LP_gettxout(char *symbol,bits256 txid,int32_t vout)
{
    char buf[128],str[65],*retstr=0; cJSON *json=0; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"\"%s\", %d",bits256_str(str,txid),vout);
    retstr = bitcoind_passthru(symbol,coin->serverport,coin->userpass,"gettxout",buf);
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
    }
    //printf("dpow_gettxout.(%s)\n",retstr);
    return(json);
}

char *LP_decoderawtransaction(char *symbol,char *rawtx)
{
    char *retstr,*paramstr; cJSON *array; struct iguana_info *coin = LP_coinfind(symbol);
    array = cJSON_CreateArray();
    jaddistr(array,rawtx);
    paramstr = jprint(array,1);
    retstr = bitcoind_passthru(symbol,coin->serverport,coin->userpass,"decoderawtransaction",paramstr);
    //printf("%s decoderawtransaction.(%s) <- (%s)\n",coin->symbol,retstr,paramstr);
    free(paramstr);
    return(retstr);
}

cJSON *LP_gettransaction(char *symbol,bits256 txid)
{
    char buf[128],str[65],*retstr=0; cJSON *json = 0; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"[\"%s\", 1]",bits256_str(str,txid));
    if ( (retstr= bitcoind_passthru(symbol,coin->serverport,coin->userpass,"getrawtransaction",buf)) != 0 )
    {
    }
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
    }
    return(json);
}

cJSON *LP_listunspent(char *symbol,char *coinaddr)
{
    char buf[128],*retstr; cJSON *json = 0; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"0, 99999999, [\"%s\"]",coinaddr);
    if ( (retstr= bitcoind_passthru(symbol,coin->serverport,coin->userpass,"listunspent",buf)) != 0 )
    {
        json = cJSON_Parse(retstr);
        //printf("%s (%s) listunspent.(%s)\n",coin->symbol,buf,retstr);
        free(retstr);
    } else printf("%s null retstr from (%s)n",coin->symbol,buf);
    return(json);
}

cJSON *LP_listtransactions(char *symbol,char *coinaddr,int32_t count,int32_t skip)
{
    char buf[128],*retstr; cJSON *json = 0; struct iguana_info *coin = LP_coinfind(symbol);
    if ( count == 0 )
        count = 100;
    sprintf(buf,"[\"%s\", %d, %d, true]",coinaddr,count,skip);
    if ( (retstr= bitcoind_passthru(symbol,coin->serverport,coin->userpass,"listtransactions",buf)) != 0 )
    {
        //printf("LIST.(%s)\n",retstr);
        json = cJSON_Parse(retstr);
        free(retstr);
        return(json);
    } else printf("%s null retstr from (%s)n",coin->symbol,buf);
    return(0);
}

char *LP_signrawtransaction(char *symbol,char *rawtx,cJSON *vins)
{
    cJSON *array; char *paramstr,*retstr; struct iguana_info *coin = LP_coinfind(symbol);
    array = cJSON_CreateArray();
    jaddistr(array,rawtx);
    jaddi(array,jduplicate(vins));
    paramstr = jprint(array,1);
    //printf("signrawtransaction\n");
    retstr = bitcoind_passthru(symbol,coin->serverport,coin->userpass,"signrawtransaction",paramstr);
    //printf("%s signrawtransaction.(%s) params.(%s)\n",coin->symbol,retstr,paramstr);
    free(paramstr);
    return(retstr);
}

char *LP_sendrawtransaction(char *symbol,char *signedtx)
{
    cJSON *array; char *paramstr,*retstr; struct iguana_info *coin = LP_coinfind(symbol);
    array = cJSON_CreateArray();
    jaddistr(array,signedtx);
    paramstr = jprint(array,1);
    retstr = bitcoind_passthru(symbol,coin->serverport,coin->userpass,"sendrawtransaction",paramstr);
    printf(">>>>>>>>>>> %s dpow_sendrawtransaction.(%s) -> (%s)\n",coin->symbol,paramstr,retstr);
    free(paramstr);
    return(retstr);
}

char *LP_importaddress(char *symbol,char *address)
{
    char buf[1024],*retstr; cJSON *validatejson; int32_t isvalid=0,doneflag = 0; struct iguana_info *coin = LP_coinfind(symbol);
    if ( (retstr= LP_validateaddress(symbol,address)) != 0 )
    {
        if ( (validatejson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (isvalid= is_cJSON_True(jobj(validatejson,"isvalid")) != 0) != 0 )
            {
                if ( is_cJSON_True(jobj(validatejson,"iswatchonly")) != 0 || is_cJSON_True(jobj(validatejson,"ismine")) != 0 )
                    doneflag = 1;
            }
            free_json(validatejson);
        }
        free(retstr);
        retstr = 0;
    }
    if ( isvalid == 0 )
        return(clonestr("{\"isvalid\":false}"));
    if ( doneflag != 0 )
        return(0); // success
    sprintf(buf,"[\"%s\", \"%s\", false]",address,address);
    retstr = bitcoind_passthru(symbol,coin->serverport,coin->userpass,"importaddress",buf);
    printf("%s importaddress.(%s) -> (%s)\n",coin->symbol,address,retstr);
    return(retstr);
}

char *LP_signrawtx(char *symbol,bits256 *signedtxidp,int32_t *completedp,cJSON *vins,char *rawtxbytes,cJSON *privkeys,struct vin_info *V)
{
    return(0);
}

cJSON *LP_swapgettxout(char *symbol,bits256 trigger,int32_t vout)
{
    cJSON *retjson=0; //char *retstr; struct iguana_info *coin;
    /*if ( ((coin= LP_coinfind(symbol)) == 0 || coin->FULLNODE == 0) && iguana_isnotarychain(symbol) >= 0 )
     {
     if ( (retstr= dex_gettxout(0,0,0,trigger,symbol,vout)) != 0 )
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
     retjson = dpow_gettxout(coin,trigger,vout);
     //printf("need to verify passthru has this info\n");
     //printf("dpowgettxout.(%s)\n",jprint(retjson,0));
     }*/
    return(basilisk_nullretjson(retjson));
}

uint64_t LP_txvalue(char *symbol,bits256 txid,int32_t vout)
{
    uint64_t value = 0;
    return(value);
}

cJSON *LP_swapgettx(char *symbol,bits256 txid)
{
    cJSON *retjson=0; //char *retstr; struct iguana_info *coin;
    /*if ( ((coin= LP_coinfind(symbol)) == 0 || coin->FULLNODE == 0) && iguana_isnotarychain(symbol) >= 0 )
     {
     if ( (retstr= dex_gettransaction(0,0,0,txid,symbol)) != 0 )
     {
     retjson = cJSON_Parse(retstr);
     free(retstr);
     }
     //if ( strcmp("BTC",symbol) == 0 )
     //    printf("%s gettx.(%s)\n",symbol,jprint(retjson,0));
     } else retjson = dpow_gettransaction(coin,txid);*/
    return(basilisk_nullretjson(retjson));
}

bits256 basilisk_swap_sendrawtransaction(char *txname,char *symbol,char *txbytes)
{
    char *retstr; bits256 txid; int32_t i,sentflag = 0;
    memset(&txid,0,sizeof(txid));
    for (i=0; i<3; i++)
    {
        if ( (retstr= LP_sendrawtransaction(symbol,txbytes)) != 0 )
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

bits256 LP_broadcast(char *name,char *symbol,uint8_t *data,int32_t datalen)
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
            if ( (retstr= LP_sendrawtransaction(symbol,signedtx)) != 0 )
            {
                if ( is_hexstr(retstr,0) == 64 )
                {
                    decode_hex(txid.bytes,32,retstr);
                    free(retstr);
                    printf("sendrawtransaction.%s %s.(%s)\n",name,symbol,bits256_str(str,txid));
                    break;
                }
                else
                {
                    printf("sendrawtransaction.%s %s error.(%s)\n",name,symbol,retstr);
                    free(retstr);
                }
            } else printf("sendrawtransaction.%s %s got null return\n",name,symbol);
        }
        free(signedtx);
    }
    return(txid);
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

int32_t LP_numconfirms(struct basilisk_swap *swap,struct basilisk_rawtx *rawtx)
{
#ifdef BASILISK_DISABLEWAITTX
    return(100);
#endif
    /*cJSON *argjson,*valuearray=0; char *valstr; int32_t i,n,retval = -1;
     argjson = cJSON_CreateObject();
    jaddbits256(argjson,"txid",rawtx->I.actualtxid);
    jaddnum(argjson,"vout",0);
    jaddstr(argjson,"coin",rawtx->coin->symbol);
    if ( (valstr= basilisk_value(rawtx->coin,0,0,swap->persistent_pubkey,argjson,0)) != 0 )
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
    return(retval);*/
}
