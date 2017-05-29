
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

char *LP_getdatadir()
{
    return("/root");
}

cJSON *basilisk_nullretjson(cJSON *retjson)
{
    char *outstr;
    if ( retjson != 0 )
    {
        outstr = jprint(retjson,0);
        if ( strcmp(outstr,"{}") == 0 || strcmp(outstr,"[]") == 0 )
        {
            free_json(retjson);
            retjson = 0;
        }
        free(outstr);
    }
    return(retjson);
}

char *blocktrail_listtransactions(char *symbol,char *coinaddr,int32_t num,int32_t skip)
{
    return(0);
}

cJSON *bitcoin_json(struct iguana_info *coin,char *method,char *params)
{
    char *retstr; cJSON *retjson = 0;
    if ( coin != 0 )
    {
        retstr = bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,method,params);
        if ( retstr != 0 && retstr[0] != 0 )
        {
            retjson = cJSON_Parse(retstr);
            free(retstr);
        }
        //printf("dpow_gettxout.(%s)\n",retstr);
    }
    return(basilisk_nullretjson(retjson));
}

void LP_unspents_mark(char *symbol,cJSON *vins)
{
    printf("LOCK (%s)\n",jprint(vins,0));
}

cJSON *LP_gettxout(char *symbol,bits256 txid,int32_t vout)
{
    char buf[128],str[65]; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"\"%s\", %d",bits256_str(str,txid),vout);
    return(bitcoin_json(coin,"gettxout",buf));
}

cJSON *LP_gettx(char *symbol,bits256 txid)
{
    char buf[128],str[65]; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"[\"%s\", 1]",bits256_str(str,txid));
    return(bitcoin_json(coin,"getrawtransaction",buf));
}

cJSON *LP_listunspent(char *symbol,char *coinaddr)
{
    char buf[128]; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"0, 99999999, [\"%s\"]",coinaddr);
    return(bitcoin_json(coin,"listunspent",buf));
}

cJSON *LP_listtransactions(char *symbol,char *coinaddr,int32_t count,int32_t skip)
{
    char buf[128]; struct iguana_info *coin = LP_coinfind(symbol);
    if ( count == 0 )
        count = 100;
    sprintf(buf,"[\"%s\", %d, %d, true]",coinaddr,count,skip);
    return(bitcoin_json(coin,"listtransactions",buf));
}

cJSON *LP_validateaddress(char *symbol,char *address)
{
    char buf[512]; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"\"%s\"",address);
    return(bitcoin_json(coin,"validateaddress",buf));
}

int32_t LP_importaddress(char *symbol,char *address)
{
    char buf[1024],*retstr; cJSON *validatejson; int32_t isvalid=0,doneflag = 0; struct iguana_info *coin = LP_coinfind(symbol);
    if ( coin == 0 )
        return(-2);
    if ( (validatejson= LP_validateaddress(symbol,address)) != 0 )
    {
        if ( (isvalid= is_cJSON_True(jobj(validatejson,"isvalid")) != 0) != 0 )
        {
            if ( is_cJSON_True(jobj(validatejson,"iswatchonly")) != 0 || is_cJSON_True(jobj(validatejson,"ismine")) != 0 )
                doneflag = 1;
        }
        free_json(validatejson);
    }
    if ( isvalid == 0 )
        return(-1);
    if ( doneflag != 0 )
        return(0); // success
    sprintf(buf,"[\"%s\", \"%s\", false]",address,address);
    if ( (retstr= bitcoind_passthru(symbol,coin->serverport,coin->userpass,"importaddress",buf)) != 0 )
        free(retstr);
    return(1);
}

uint64_t LP_getestimatedrate(char *symbol)
{
    char buf[512],*retstr; uint64_t rate = 200; struct iguana_info *coin = LP_coinfind(symbol);
    if ( coin != 0 )
    {
        sprintf(buf,"[%d]",3);
        if ( (retstr= bitcoind_passthru(symbol,coin->serverport,coin->userpass,"importaddress",buf)) != 0 )
        {
            rate = atof(retstr);
            printf("estimated rate %s -> %llu\n",retstr,(long long)rate);
            free(retstr);
        }
    }
    return(rate);
}

uint64_t LP_txfee(char *symbol)
{
    uint64_t txfee = 0;
    if ( strcmp(symbol,"BTC") != 0 )
        txfee = 50000;
    return(txfee);
}

char *LP_sendrawtransaction(char *symbol,char *signedtx)
{
    cJSON *array; char *paramstr,*retstr; struct iguana_info *coin = LP_coinfind(symbol);
    if ( coin == 0 )
        return(0);
    array = cJSON_CreateArray();
    jaddistr(array,signedtx);
    paramstr = jprint(array,1);
    retstr = bitcoind_passthru(symbol,coin->serverport,coin->userpass,"sendrawtransaction",paramstr);
    printf(">>>>>>>>>>> %s dpow_sendrawtransaction.(%s) -> (%s)\n",coin->symbol,paramstr,retstr);
    free(paramstr);
    return(retstr);
}

char *LP_signrawtx(char *symbol,bits256 *signedtxidp,int32_t *completedp,cJSON *vins,char *rawtx,cJSON *privkeys,struct vin_info *V)
{
    cJSON *array,*json; int32_t len; uint8_t *data; char *paramstr,*retstr,*hexstr,*signedtx=0; struct iguana_info *coin = LP_coinfind(symbol);
    memset(signedtxidp,0,sizeof(*signedtxidp));
    *completedp = 0;
    if ( coin == 0 )
        return(0);
    array = cJSON_CreateArray();
    jaddistr(array,rawtx);
    jaddi(array,jduplicate(vins));
    jaddi(array,jduplicate(privkeys));
    paramstr = jprint(array,1);
    //printf("signrawtransaction\n");
    if ( (retstr= bitcoind_passthru(symbol,coin->serverport,coin->userpass,"signrawtransaction",paramstr)) != 0 )
    {
printf("%s signrawtransaction.(%s) params.(%s)\n",coin->symbol,retstr,paramstr);
        if ( (json= cJSON_Parse(retstr)) != 0 )
        {
            if ( (hexstr= jstr(json,"hex")) != 0 )
            {
                len = (int32_t)strlen(hexstr);
                signedtx = calloc(1,len+1);
                strcpy(signedtx,hexstr);
                *completedp = jint(json,"completed");
                data = malloc(len >> 1);
                decode_hex(data,len>>1,hexstr);
                *signedtxidp = bits256_doublesha256(0,data,len >> 1);
            }
            free_json(json);
        }
        free(retstr);
    }
    free(paramstr);
    return(signedtx);
}
