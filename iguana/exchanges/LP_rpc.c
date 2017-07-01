
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

char *LP_issue_curl(char *debugstr,char *destip,uint16_t port,char *url)
{
    char *retstr = 0; int32_t maxerrs; struct LP_peerinfo *peer = 0;
    peer = LP_peerfind((uint32_t)calc_ipbits(destip),port);
    maxerrs = LP_MAXPEER_ERRORS;
    if ( peer == 0 || (peer->errors < maxerrs || peer->good >= LP_MINPEER_GOOD) )
    {
        if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) == 0 )
        {
            if ( peer != 0 )
            {
                peer->errors++;
                peer->good *= LP_PEERGOOD_ERRORDECAY;
            } else printf("%s error on (%s:%u) without peer\n",debugstr,destip,port);
        }
        else if ( peer != 0 )
            peer->good++;
    }
    return(retstr);
}

char *LP_isitme(char *destip,uint16_t destport)
{
    if ( LP_mypeer != 0 && strcmp(destip,LP_mypeer->ipaddr) == 0 && LP_mypeer->port == destport )
    {
        //printf("no need to notify ourselves\n");
        return(clonestr("{\"result\":\"success\"}"));
    } else return(0);
}

char *issue_LP_getpeers(char *destip,uint16_t destport,char *ipaddr,uint16_t port,double profitmargin,int32_t numpeers,int32_t numutxos)
{
    char url[512];
    sprintf(url,"http://%s:%u/api/stats/getpeers?ipaddr=%s&port=%u&profit=%.6f&numpeers=%d&numutxos=%d",destip,destport,ipaddr,port,profitmargin,numpeers,numutxos);
    return(LP_issue_curl("getpeers",destip,port,url));
}

char *issue_LP_getutxos(char *destip,uint16_t destport,char *coin,int32_t lastn,char *ipaddr,uint16_t port,double profitmargin,int32_t numpeers,int32_t numutxos)
{
    char url[512];
    sprintf(url,"http://%s:%u/api/stats/getutxos?coin=%s&lastn=%d&ipaddr=%s&port=%u&profit=%.6f&numpeers=%d&numutxos=%d",destip,destport,coin,lastn,ipaddr,port,profitmargin,numpeers,numutxos);
    return(LP_issue_curl("getutxos",destip,destport,url));
    //return(issue_curlt(url,LP_HTTP_TIMEOUT));
}

char *issue_LP_clientgetutxos(char *destip,uint16_t destport,char *coin,int32_t lastn)
{
    char url[512];//,*retstr;
    sprintf(url,"http://%s:%u/api/stats/getutxos?coin=%s&lastn=%d&ipaddr=127.0.0.1&port=0",destip,destport,coin,lastn);
    return(LP_issue_curl("clientgetutxos",destip,destport,url));
    //retstr = issue_curlt(url,LP_HTTP_TIMEOUT);
    //printf("%s clientgetutxos.(%s)\n",url,retstr);
    //return(retstr);
}

char *issue_LP_notify(char *destip,uint16_t destport,char *ipaddr,uint16_t port,double profitmargin,int32_t numpeers,int32_t numutxos)
{
    char url[512],*retstr;
    if ( (retstr= LP_isitme(destip,destport)) != 0 )
    {
        free(retstr);
        return(0);
    }
    sprintf(url,"http://%s:%u/api/stats/notify?ipaddr=%s&port=%u&profit=%.6f&numpeers=%d&numutxos=%d",destip,destport,ipaddr,port,profitmargin,numpeers,numutxos);
    return(LP_issue_curl("notify",destip,destport,url));
    //return(issue_curlt(url,LP_HTTP_TIMEOUT));
}

char *issue_LP_notifyutxo(char *destip,uint16_t destport,struct LP_utxoinfo *utxo)
{
    char url[4096],str[65],str2[65],str3[65],*retstr; struct _LP_utxoinfo u; uint64_t val,val2;
    if ( (retstr= LP_isitme(destip,destport)) != 0 )
    {
        free(retstr);
        return(0);
    }
    if ( utxo->iambob == 0 )
    {
        printf("issue_LP_notifyutxo trying to send Alice %s/v%d\n",bits256_str(str,utxo->payment.txid),utxo->payment.vout);
        return(0);
    }
    u = (utxo->iambob != 0) ? utxo->deposit : utxo->fee;
    if ( LP_iseligible(&val,&val2,utxo->iambob,utxo->coin,utxo->payment.txid,utxo->payment.vout,utxo->S.satoshis,u.txid,u.vout,utxo->pubkey) > 0 )
    {
        sprintf(url,"http://%s:%u/api/stats/notified?iambob=%d&pubkey=%s&profit=%.6f&coin=%s&txid=%s&vout=%d&value=%llu&txid2=%s&vout2=%d&value2=%llu&script=%s&address=%s&timestamp=%u&gui=%s",destip,destport,utxo->iambob,bits256_str(str3,utxo->pubkey),utxo->S.profitmargin,utxo->coin,bits256_str(str,utxo->payment.txid),utxo->payment.vout,(long long)utxo->payment.value,bits256_str(str2,utxo->deposit.txid),utxo->deposit.vout,(long long)utxo->deposit.value,utxo->spendscript,utxo->coinaddr,(uint32_t)time(NULL),utxo->gui);
        if ( strlen(url) > 1024 )
            printf("WARNING long url.(%s)\n",url);
        return(LP_issue_curl("notifyutxo",destip,destport,url));
        //return(issue_curlt(url,LP_HTTP_TIMEOUT));
    }
    else
    {
        printf("issue_LP_notifyutxo: ineligible utxo iambob.%d %.8f %.8f\n",utxo->iambob,dstr(val),dstr(val2));
        return(0);
    }
}

char *issue_LP_register(char *destip,uint16_t destport,bits256 pubkey,char *ipaddr,uint16_t pushport)
{
    char url[512],str[65];//*retstr;
    sprintf(url,"http://%s:%u/api/stats/register?client=%s&pushaddr=%s&pushport=%u",destip,destport,bits256_str(str,pubkey),ipaddr,pushport);
    return(LP_issue_curl("register",destip,destport,url));
    //retstr = issue_curlt(url,LP_HTTP_TIMEOUT);
    //printf("getutxo.(%s) -> (%s)\n",url,retstr!=0?retstr:"");
    //return(retstr);
}

char *issue_LP_psock(char *destip,uint16_t destport,int32_t ispaired)
{
    char url[512];
    sprintf(url,"http://%s:%u/api/stats/psock?ispaired=%d",destip,destport,ispaired);
    return(LP_issue_curl("psock",destip,destport,url));
    //retstr = issue_curlt(url,LP_HTTP_TIMEOUT);
    //printf("getutxo.(%s) -> (%s)\n",url,retstr!=0?retstr:"");
    //return(retstr);
}

uint16_t LP_psock_get(char *connectaddr,char *publicaddr,int32_t ispaired)
{
    uint16_t publicport = 0; char *retstr,*addr; cJSON *retjson; struct LP_peerinfo *peer,*tmp;
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        connectaddr[0] = publicaddr[0] = 0;
        if ( peer->errors < LP_MAXPEER_ERRORS && (retstr= issue_LP_psock(peer->ipaddr,peer->port,ispaired)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( (addr= jstr(retjson,"publicaddr")) != 0 )
                    safecopy(publicaddr,addr,128);
                if ( (addr= jstr(retjson,"connectaddr")) != 0 )
                    safecopy(connectaddr,addr,128);
                if ( publicaddr[0] != 0 && connectaddr[0] != 0 )
                    publicport = juint(retjson,"publicport");
                free_json(retjson);
            }
            printf("got.(%s) connect.%s public.%s\n",retstr,connectaddr,publicaddr);
            free(retstr);
        }
        if ( publicport != 0 )
            break;
    }
    return(publicport);
}

char *issue_LP_lookup(char *destip,uint16_t destport,bits256 pubkey)
{
    char url[512],str[65];
    sprintf(url,"http://%s:%u/api/stats/lookup?client=%s",destip,destport,bits256_str(str,pubkey));
    //printf("getutxo.(%s)\n",url);
    return(LP_issue_curl("lookup",destip,destport,url));
    //return(issue_curlt(url,LP_HTTP_TIMEOUT));
}

char *issue_LP_getprices(char *destip,uint16_t destport)
{
    char url[512];
    sprintf(url,"http://%s:%u/api/stats/getprices",destip,destport);
    //printf("getutxo.(%s)\n",url);
    return(LP_issue_curl("getprices",destip,destport,url));
    //return(issue_curlt(url,LP_HTTP_TIMEOUT));
}

cJSON *bitcoin_json(struct iguana_info *coin,char *method,char *params)
{
    char *retstr; cJSON *retjson = 0;
    if ( coin != 0 )
    {
        printf("issue.(%s, %s, %s, %s, %s)\n",coin->symbol,coin->serverport,coin->userpass,method,params);
        retstr = bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,method,params);
        if ( retstr != 0 && retstr[0] != 0 )
        {
            //printf("%s: %s.%s -> (%s)\n",coin->symbol,method,params,retstr);
            retjson = cJSON_Parse(retstr);
            free(retstr);
        }
        //usleep(1000);
        //printf("dpow_gettxout.(%s)\n",retstr);
    } else printf("bitcoin_json cant talk to NULL coin\n");
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

cJSON *LP_getmempool(char *symbol)
{
    struct iguana_info *coin = LP_coinfind(symbol);
    return(bitcoin_json(coin,"getrawmempool","[]"));
}

cJSON *LP_gettxout(char *symbol,bits256 txid,int32_t vout)
{
    char buf[128],str[65]; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"\"%s\", %d, true",bits256_str(str,txid),vout);
    return(bitcoin_json(coin,"gettxout",buf));
}

cJSON *LP_gettx(char *symbol,bits256 txid)
{
    char buf[128],str[65]; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"[\"%s\", 1]",bits256_str(str,txid));
    return(bitcoin_json(coin,"getrawtransaction",buf));
}

cJSON *LP_getblock(char *symbol,bits256 txid)
{
    char buf[128],str[65]; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"[\"%s\"]",bits256_str(str,txid));
    return(bitcoin_json(coin,"getblock",buf));
}

cJSON *LP_getblockhashstr(char *symbol,char *blockhashstr)
{
    char buf[128]; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"[\"%s\"]",blockhashstr);
    return(bitcoin_json(coin,"getblock",buf));
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
        //printf("importaddress.(%s %s) -> (%s)\n",symbol,address,retstr);
        free(retstr);
    } //else printf("importaddress.(%s %s)\n",symbol,address);
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
                coin->estimatedrate = rate = atof(retstr) / 1024.;
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

char *LP_blockhashstr(char *symbol,int32_t height)
{
    cJSON *array; char *paramstr,*retstr; struct iguana_info *coin = LP_coinfind(symbol);
    if ( coin == 0 )
        return(0);
    array = cJSON_CreateArray();
    jaddinum(array,height);
    paramstr = jprint(array,1);
    retstr = bitcoind_passthru(symbol,coin->serverport,coin->userpass,"getblockhash",paramstr);
    free(paramstr);
    return(retstr);
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
    //printf(">>>>>>>>>>> %s dpow_sendrawtransaction.(%s) -> (%s)\n",coin->symbol,paramstr,retstr);
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

cJSON *LP_blockjson(int32_t *heightp,char *symbol,char *blockhashstr,int32_t height)
{
    cJSON *json = 0; int32_t flag = 0;
    if ( blockhashstr == 0 )
        blockhashstr = LP_blockhashstr(symbol,height), flag = 1;
    if ( blockhashstr != 0 )
    {
        if ( (json= LP_getblockhashstr(symbol,blockhashstr)) != 0 )
        {
            if ( *heightp != 0 )
            {
                *heightp = juint(json,"height");
                if ( height >= 0 && *heightp != height )
                {
                    printf("unexpected height %d vs %d\n",*heightp,height);
                    *heightp = -1;
                    free_json(json);
                    json = 0;
                }
            }
        }
        if ( flag != 0 && blockhashstr != 0 )
            free(blockhashstr);
    }
    return(json);
}

