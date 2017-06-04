
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
char *issue_LP_getpeers(char *destip,uint16_t destport,char *ipaddr,uint16_t port,double profitmargin,int32_t numpeers,int32_t numutxos)
{
    char url[512],*retstr;
    sprintf(url,"http://%s:%u/api/stats/getpeers?ipaddr=%s&port=%u&profit=%.6f&numpeers=%d&numutxos=%d",destip,destport,ipaddr,port,profitmargin,numpeers,numutxos);
    //printf("send.(%s)\n",url);
    retstr = issue_curl(url);
    //printf("GETPEERS.(%s)\n",retstr);
    return(retstr);
}

char *issue_LP_getutxos(char *destip,uint16_t destport,char *coin,int32_t lastn,char *ipaddr,uint16_t port,double profitmargin,int32_t numpeers,int32_t numutxos)
{
    char url[512];
    sprintf(url,"http://%s:%u/api/stats/getutxos?coin=%s&lastn=%d&ipaddr=%s&port=%u&profit=%.6f&numpeers=%d&numutxos=%d",destip,destport,coin,lastn,ipaddr,port,profitmargin,numpeers,numutxos);
    return(issue_curl(url));
}

char *issue_LP_clientgetutxos(char *destip,uint16_t destport,char *coin,int32_t lastn)
{
    char url[512];
    sprintf(url,"http://%s:%u/api/stats/getutxos?coin=%s&lastn=%d&ipaddr=127.0.0.1&port=0",destip,destport,coin,lastn);
    //printf("getutxos.(%s)\n",url);
    return(issue_curl(url));
}

char *issue_LP_notify(char *destip,uint16_t destport,char *ipaddr,uint16_t port,double profitmargin,int32_t numpeers,int32_t numutxos)
{
    char url[512];
    sprintf(url,"http://%s:%u/api/stats/notify?ipaddr=%s&port=%u&profit=%.6f&numpeers=%d&numutxos=%d",destip,destport,ipaddr,port,profitmargin,numpeers,numutxos);
    return(issue_curl(url));
}

char *issue_LP_notifyutxo(char *destip,uint16_t destport,struct LP_utxoinfo *utxo)
{
    char url[4096],str[65],str2[65];
    sprintf(url,"http://%s:%u/api/stats/notifyutxo?ipaddr=%s&port=%u&profit=%.6f&coin=%s&txid=%s&vout=%d&value=%.8f&txid2=%s&vout2=%d&value2=%.8f&script=%s&address=%s",destip,destport,utxo->ipaddr,utxo->port,utxo->profitmargin,utxo->coin,bits256_str(str,utxo->txid),utxo->vout,dstr(utxo->satoshis),bits256_str(str2,utxo->txid2),utxo->vout2,dstr(utxo->satoshis2),utxo->spendscript,utxo->coinaddr);
    if ( strlen(url) > 1024 )
        printf("WARNING long url.(%s)\n",url);
    return(issue_curl(url));
}

cJSON *bitcoin_json(struct iguana_info *coin,char *method,char *params)
{
    char *retstr; cJSON *retjson = 0;
    if ( coin != 0 )
    {
        //printf("issue.(%s, %s, %s, %s, %s)\n",coin->symbol,coin->serverport,coin->userpass,method,params);
        retstr = bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,method,params);
        if ( retstr != 0 && retstr[0] != 0 )
        {
            //printf("%s: %s.%s -> (%s)\n",coin->symbol,method,params,retstr);
            retjson = cJSON_Parse(retstr);
            free(retstr);
        }
        //printf("dpow_gettxout.(%s)\n",retstr);
    }
    return(retjson);
}

void LP_unspents_mark(char *symbol,cJSON *vins)
{
    printf("LOCK (%s)\n",jprint(vins,0));
}

cJSON *LP_getinfo(char *symbol)
{
    struct iguana_info *coin = LP_coinfind(symbol);
    return(bitcoin_json(coin,"getinfo","[]"));
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

cJSON *LP_importprivkey(char *symbol,char *wifstr,char *label,int32_t flag)
{
    char buf[512]; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"[\"%s\", \"%s\", %s]",wifstr,label,flag < 0 ? "false" : "true");
    return(bitcoin_json(coin,"importprivkey",buf));
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
    {
        printf("importaddress.(%s %s) -> (%s)\n",symbol,address,retstr);
        free(retstr);
    } else printf("importaddress.(%s %s)\n",symbol,address);
    return(1);
}

double LP_getestimatedrate(char *symbol)
{
    char buf[512],*retstr; double rate = 20; struct iguana_info *coin = LP_coinfind(symbol);
    if ( coin != 0 )
    {
        sprintf(buf,"[%d]",3);
        if ( (retstr= bitcoind_passthru(symbol,coin->serverport,coin->userpass,"estimatefee",buf)) != 0 )
        {
            if ( retstr[0] != '-' )
            {
                rate = atof(retstr) / 1024.;
                printf("estimated rate.(%s) %s -> %.8f\n",symbol,retstr,rate);
            }
            free(retstr);
        }
    }
    return(rate);
}

uint64_t LP_txfee(char *symbol)
{
    uint64_t txfee = 0;
    if ( strcmp(symbol,"BTC") != 0 )
        txfee = 10000;
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
    {
        printf("LP_signrawtx cant find coin.(%s)\n",symbol);
        return(0);
    }
    array = cJSON_CreateArray();
    jaddistr(array,rawtx);
    jaddi(array,jduplicate(vins));
    jaddi(array,jduplicate(privkeys));
    paramstr = jprint(array,1);
    //printf("signrawtransaction\n");
    if ( (retstr= bitcoind_passthru(symbol,coin->serverport,coin->userpass,"signrawtransaction",paramstr)) != 0 )
    {
        if ( (json= cJSON_Parse(retstr)) != 0 )
        {
            if ( (hexstr= jstr(json,"hex")) != 0 )
            {
                len = (int32_t)strlen(hexstr);
                signedtx = calloc(1,len+1);
                strcpy(signedtx,hexstr);
                *completedp = is_cJSON_True(jobj(json,"complete"));
                data = malloc(len >> 1);
                decode_hex(data,len>>1,hexstr);
                *signedtxidp = bits256_doublesha256(0,data,len >> 1);
            }
            //else
                printf("%s signrawtransaction.(%s) params.(%s)\n",coin->symbol,retstr,paramstr);
            free_json(json);
        }
        free(retstr);
    }
    free(paramstr);
    return(signedtx);
}
