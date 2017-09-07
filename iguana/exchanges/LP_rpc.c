
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

char *issue_LP_getpeers(char *destip,uint16_t destport,char *ipaddr,uint16_t port,int32_t numpeers,int32_t numutxos)
{
    char url[512],*retstr;
    sprintf(url,"http://%s:%u/api/stats/getpeers?ipaddr=%s&port=%u&numpeers=%d&numutxos=%d",destip,destport,ipaddr,port,numpeers,numutxos);
    retstr = LP_issue_curl("getpeers",destip,port,url);
    //printf("%s -> getpeers.(%s)\n",destip,retstr);
    return(retstr);
}

char *issue_LP_numutxos(char *destip,uint16_t destport,char *ipaddr,uint16_t port,int32_t numpeers,int32_t numutxos)
{
    char url[512],*retstr;
    sprintf(url,"http://%s:%u/api/stats/numutxos?ipaddr=%s&port=%u&numpeers=%d&numutxos=%d",destip,destport,ipaddr,port,numpeers,numutxos);
    retstr = LP_issue_curl("numutxos",destip,port,url);
    //printf("%s -> getpeers.(%s)\n",destip,retstr);
    return(retstr);
}

char *issue_LP_getutxos(char *destip,uint16_t destport,char *coin,int32_t lastn,char *ipaddr,uint16_t port,int32_t numpeers,int32_t numutxos)
{
    char url[512];
    sprintf(url,"http://%s:%u/api/stats/getutxos?coin=%s&lastn=%d&ipaddr=%s&port=%u&numpeers=%d&numutxos=%d",destip,destport,coin,lastn,ipaddr,port,numpeers,numutxos);
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

char *issue_LP_notify(char *destip,uint16_t destport,char *ipaddr,uint16_t port,int32_t numpeers,int32_t numutxos,uint32_t sessionid)
{
    char url[512],*retstr;
    if ( (retstr= LP_isitme(destip,destport)) != 0 )
        return(retstr);
    sprintf(url,"http://%s:%u/api/stats/notify?ipaddr=%s&port=%u&numpeers=%d&numutxos=%d&session=%u",destip,destport,ipaddr,port,numpeers,numutxos,sessionid);
    return(LP_issue_curl("notify",destip,destport,url));
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
    static uint32_t stratumid;
    char *retstr,stratumreq[8192]; cJSON *retjson = 0;
    // "getinfo", "getrawmempool", "paxprice", "gettxout", "getrawtransaction", "getblock", "listunspent", "listtransactions", "validateaddress", "importprivkey"
    // bitcoind_passthru callers: "importaddress", "estimatefee", "getblockhash", "sendrawtransaction", "signrawtransaction"
    
    //"server.version", "server.banner", "server.donation_address", "server.peers.subscribe", "--blockchain.numblocks.subscribe", "blockchain.headers.subscribe", "blockchain.address.subscribe", "blockchain.address.get_history", "blockchain.address.get_mempool", "blockchain.address.get_balance", "--blockchain.address.get_proof", "blockchain.address.listunspent", "--blockchain.utxo.get_address", "blockchain.block.get_header", "blockchain.block.get_chunk", "blockchain.transaction.broadcast", "blockchain.transaction.get_merkle", "blockchain.transaction.get", "blockchain.estimatefee"
    
    // 1.1: "blockchain.scripthash.get_balance", "blockchain.scripthash.get_history", "blockchain.scripthash.get_mempool", "blockchain.scripthash.listunspent", "blockchain.scripthash.subscribe", "server.features", "server.add_peer"
    method = "server.version";
    params = "[]";
    sprintf(stratumreq,"{ \"jsonrpc\":\"2.0\", \"id\": %u, \"method\":\"%s\", \"params\": %s }\n",stratumid++,method,params);
    if ( (retstr= issue_curlt("46.4.125.2:50001",LP_HTTP_TIMEOUT*5)) != 0 )
    {
        printf("%s -> %s\n",stratumreq,retstr);
        free(retstr);
    }
    if ( coin != 0 )
    {
        //printf("issue.(%s, %s, %s, %s, %s)\n",coin->symbol,coin->serverport,coin->userpass,method,params);
        if ( coin->inactive == 0 || strcmp(method,"importprivkey") == 0  || strcmp(method,"validateaddress") == 0 )
        {
            retstr = bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,method,params);
            if ( retstr != 0 && retstr[0] != 0 )
            {
                //printf("%s: %s.%s -> (%s)\n",coin->symbol,method,params,retstr);
                retjson = cJSON_Parse(retstr);
                free(retstr);
            }
            //usleep(100);
            //printf("dpow_gettxout.(%s)\n",retstr);
        } else retjson = cJSON_Parse("{\"result\":\"disabled\"}");
    } else printf("bitcoin_json cant talk to NULL coin\n");
    return(retjson);
}

void LP_unspents_mark(char *symbol,cJSON *vins)
{
    printf("LOCK (%s)\n",jprint(vins,0));
}

char *NXTnodes[] = { "62.75.159.113", "91.44.203.238", "82.114.88.225", "78.63.207.76", "188.174.110.224", "91.235.72.49", "213.144.130.91", "209.222.98.250", "216.155.128.10", "178.33.203.157", "162.243.122.251", "69.163.47.173", "193.151.106.129", "78.94.2.74", "192.3.196.10", "173.33.112.87", "104.198.173.28", "35.184.154.126", "174.140.167.239", "23.88.113.131", "198.71.84.173", "178.150.207.53", "23.88.61.53", "192.157.233.106", "192.157.241.212", "23.89.192.88", "23.89.200.27", "192.157.241.139", "23.89.200.63", "23.89.192.98", "163.172.214.102", "176.9.85.5", "80.150.243.88", "80.150.243.92", "80.150.243.98", "109.70.186.198", "146.148.84.237", "104.155.56.82", "104.197.157.140", "37.48.73.249", "146.148.77.226", "84.57.170.200", "107.161.145.131", "80.150.243.97", "80.150.243.93", "80.150.243.100", "80.150.243.95", "80.150.243.91", "80.150.243.99", "80.150.243.96", "93.231.187.177", "212.237.23.85", "35.158.179.254", "46.36.66.41", "185.170.113.79", "163.172.68.112", "78.47.35.210", "77.90.90.75", "94.177.196.134", "212.237.22.215", "94.177.234.11", "167.160.180.199", "54.68.189.9", "94.159.62.14", "195.181.221.89", "185.33.145.94", "195.181.209.245", "195.181.221.38", "195.181.221.162", "185.33.145.12", "185.33.145.176", "178.79.128.235", "94.177.214.120", "94.177.199.41", "94.177.214.200", "94.177.213.201", "212.237.13.162", "195.181.221.236", "195.181.221.185", "185.28.103.187", "185.33.146.244", "217.61.123.71", "195.181.214.45", "195.181.212.99", "195.181.214.46", "195.181.214.215", "195.181.214.68", "217.61.123.118", "195.181.214.79", "217.61.123.14", "217.61.124.100", "195.181.214.111", "85.255.0.176", "81.2.254.116", "217.61.123.184", "195.181.212.231", "94.177.214.110", "195.181.209.164", "104.129.56.238", "85.255.13.64", "167.160.180.206", "217.61.123.226", "167.160.180.208", "93.186.253.127", "212.237.6.208", "94.177.207.190", "217.61.123.119", "85.255.1.245", "217.61.124.157", "37.59.57.141", "167.160.180.58", "104.223.53.14", "217.61.124.69", "195.181.212.103", "85.255.13.141", "104.207.133.204", "71.90.7.107", "107.150.18.108", "23.94.134.161", "80.150.243.13", "80.150.243.11", "185.81.165.52", "80.150.243.8" };


cJSON *LP_assethbla(char *assetid)
{
    char url[1024],*retstr; int32_t n; cJSON *array,*bid=0,*ask=0,*retjson;
    sprintf(url,"http://%s:7876/nxt?=%%2Fnxt&requestType=getBidOrders&asset=%s&firstIndex=0&lastIndex=0",NXTnodes[rand() % (sizeof(NXTnodes)/sizeof(*NXTnodes))],assetid);
    if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
    {
        bid = cJSON_Parse(retstr);
        free(retstr);
    }
    sprintf(url,"http://%s:7876/nxt?=%%2Fnxt&requestType=getAskOrders&asset=%s&firstIndex=0&lastIndex=0",NXTnodes[rand() % (sizeof(NXTnodes)/sizeof(*NXTnodes))],assetid);
    if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
    {
        ask = cJSON_Parse(retstr);
        free(retstr);
    }
    retjson = cJSON_CreateObject();
    if ( bid != 0 && ask != 0 )
    {
        if ( (array= jarray(&n,bid,"bidOrders")) != 0 )
            jadd(retjson,"bid",jduplicate(jitem(array,0)));
        if ( (array= jarray(&n,ask,"askOrders")) != 0 )
            jadd(retjson,"ask",jduplicate(jitem(array,0)));
    }
    if ( bid != 0 )
        free_json(bid);
    if ( ask != 0 )
        free_json(ask);
    return(retjson);
}

int32_t LP_getheight(struct iguana_info *coin)
{
    cJSON *retjson; int32_t height = -1; //struct iguana_info *coin = LP_coinfind(symbol);
    if ( (retjson= bitcoin_json(coin,"getinfo","[]")) != 0 )
    {
        height = jint(retjson,"blocks");
        free_json(retjson);
    }
    return(height);
}

cJSON *LP_getmempool(char *symbol)
{
    struct iguana_info *coin = LP_coinfind(symbol);
    return(bitcoin_json(coin,"getrawmempool","[]"));
}

cJSON *LP_paxprice(char *fiat)
{
    char buf[128],lfiat[65]; struct iguana_info *coin = LP_coinfind("KMD");
    strcpy(lfiat,fiat);
    tolowercase(lfiat);
    sprintf(buf,"[\"%s\", \"kmd\"]",lfiat);
    return(bitcoin_json(coin,"paxprice",buf));
}

cJSON *LP_gettxout(char *symbol,bits256 txid,int32_t vout)
{
    char buf[128],str[65]; struct iguana_info *coin = LP_coinfind(symbol);
    sprintf(buf,"[\"%s\", %d, true]",bits256_str(str,txid),vout);
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

int32_t LP_txheight(uint32_t *timestampp,uint32_t *blocktimep,struct iguana_info *coin,bits256 txid)
{
    bits256 blockhash; cJSON *blockobj,*txobj; int32_t height = 0;
    if ( (txobj= LP_gettx(coin->symbol,txid)) != 0 )
    {
        *timestampp = juint(txobj,"locktime");
        *blocktimep = juint(txobj,"blocktime");
        blockhash = jbits256(txobj,"blockhash");
        if ( bits256_nonz(blockhash) != 0 && (blockobj= LP_getblock(coin->symbol,blockhash)) != 0 )
        {
            height = jint(blockobj,"height");
            //printf("%s LP_txheight.%d\n",coin->symbol,height);
            free_json(blockobj);
        } //else printf("%s LP_txheight error (%s)\n",coin->symbol,jprint(txobj,0));
        free_json(txobj);
    }
    return(height);
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
    sprintf(buf,"[0, 99999999, [\"%s\"]]",coinaddr);
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
    sprintf(buf,"[\"%s\"]",address);
    return(bitcoin_json(coin,"validateaddress",buf));
}

cJSON *LP_importprivkey(char *symbol,char *wifstr,char *label,int32_t flag)
{
    static void *ctx;
    char buf[512],address[64]; cJSON *retjson; struct iguana_info *coin; int32_t doneflag = 0;
    coin = LP_coinfind(symbol);
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    bitcoin_wif2addr(ctx,coin->wiftaddr,coin->taddr,coin->pubtype,address,wifstr);
    if ( (retjson= LP_validateaddress(symbol,address)) != 0 )
    {
        if ( jobj(retjson,"ismine") != 0 && is_cJSON_True(jobj(retjson,"ismine")) != 0 )
        {
            doneflag = 1;
            //printf("%s already ismine\n",address);
        }
        //printf("%s\n",jprint(retjson,0));
        free_json(retjson);
    }
    if ( doneflag == 0 )
    {
        if ( coin->noimportprivkey_flag != 0 )
            sprintf(buf,"[\"%s\"]",wifstr);
        else sprintf(buf,"\"%s\", \"%s\", %s",wifstr,label,flag < 0 ? "false" : "true");
        return(bitcoin_json(coin,"importprivkey",buf));
    } else return(cJSON_Parse("{\"result\":\"success\"}"));
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
    if ( coin != 0 && (strcmp(coin->symbol,"BTC") == 0 || coin->txfee == 0) )
    {
        sprintf(buf,"[%d]",3);
        if ( (retstr= bitcoind_passthru(symbol,coin->serverport,coin->userpass,"estimatefee",buf)) != 0 )
        {
            if ( retstr[0] != '-' )
            {
                rate = atof(retstr) / 1024.;
                //printf("estimated rate.(%s) %s -> %.8f\n",symbol,retstr,rate);
            }
            free(retstr);
        }
    } else return((double)coin->txfee / LP_AVETXSIZE);
    return(SATOSHIDEN * rate);
}

uint64_t LP_txfee(char *symbol)
{
    uint64_t txfee = 0;
    if ( strcmp(symbol,"BTC") != 0 )
        txfee = LP_MIN_TXFEE;
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
                    printf("unexpected height %d vs %d for %s (%s)\n",*heightp,height,blockhashstr,jprint(json,0));
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
