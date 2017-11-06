
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
        //printf("issue.(%s)\n",url);
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

char *issue_LP_getpeers(char *destip,uint16_t destport,char *ipaddr,uint16_t port,int32_t numpeers)
{
    char url[512],*retstr;
    sprintf(url,"http://%s:%u/api/stats/getpeers?ipaddr=%s&port=%u&numpeers=%d",destip,destport,ipaddr,port,numpeers);
    retstr = LP_issue_curl("getpeers",destip,port,url);
    //printf("%s -> getpeers.(%s)\n",destip,retstr);
    return(retstr);
}

char *issue_LP_uitem(char *destip,uint16_t destport,char *symbol,char *coinaddr,bits256 txid,int32_t vout,int32_t height,uint64_t value)
{
    char url[512],*retstr,str[65];
    if ( (retstr= LP_isitme(destip,destport)) != 0 )
        return(retstr);
    sprintf(url,"http://%s:%u/api/stats/uitem?coin=%s&coinaddr=%s&txid=%s&vout=%d&ht=%d&value=%llu",destip,destport,symbol,coinaddr,bits256_str(str,txid),vout,height,(long long)value);
    retstr = LP_issue_curl("uitem",destip,destport,url);
    //printf("uitem.(%s)\n",retstr);
    return(retstr);
}

char *issue_LP_notify(char *destip,uint16_t destport,char *ipaddr,uint16_t port,int32_t numpeers,uint32_t sessionid,char *rmd160str,bits256 pub)
{
    char url[512],*retstr,str[65];
    if ( (retstr= LP_isitme(destip,destport)) != 0 )
        return(retstr);
    sprintf(url,"http://%s:%u/api/stats/notify?ipaddr=%s&port=%u&numpeers=%d&session=%u",destip,destport,ipaddr,port,numpeers,sessionid);
    if ( rmd160str != 0 && bits256_nonz(pub) != 0 )
    {
        sprintf(url+strlen(url),"&rmd160=%s&pub=%s",rmd160str,bits256_str(str,pub));
        //printf("SEND (%s)\n",url);
    }
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

char *issue_LP_listunspent(char *destip,uint16_t destport,char *symbol,char *coinaddr)
{
    char url[512],*retstr;
    sprintf(url,"http://%s:%u/api/stats/listunspent?coin=%s&address=%s",destip,destport,symbol,coinaddr);
    retstr = LP_issue_curl("listunspent",destip,destport,url);
    //printf("listunspent.(%s) -> (%s)\n",url,retstr);
    return(retstr);
}

char *LP_apicall(struct iguana_info *coin,char *method,char *params)
{
    cJSON *retjson; char *retstr;
    if ( coin == 0 )
        return(0);
    if ( coin->electrum != 0 )
    {
        if ( (retjson= electrum_submit(coin->symbol,coin->electrum,&retjson,method,params,ELECTRUM_TIMEOUT)) != 0 )
        {
            retstr = jprint(retjson,1);
            //printf("got.%p (%s)\n",retjson,retstr);
            return(retstr);
        } return(clonestr("{\"error\":\"electrum no response\"}"));
    } else return(bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,method,params));
}

cJSON *bitcoin_json(struct iguana_info *coin,char *method,char *params)
{
    cJSON *retjson = 0; char *retstr;
    // "getinfo", "getrawmempool", "paxprice", "gettxout", "getrawtransaction", "getblock", "listunspent", "listtransactions", "validateaddress", "importprivkey"
    // bitcoind_passthru callers: "importaddress", "estimatefee", "getblockhash", "sendrawtransaction", "signrawtransaction"
    if ( coin != 0 )
    {
        //printf("issue.(%s, %s, %s, %s, %s)\n",coin->symbol,coin->serverport,coin->userpass,method,params);
        if ( coin->electrum != 0 && (strcmp(method,"getblock") == 0 || strcmp(method,"paxprice") == 0 || strcmp(method,"getrawmempool") == 0) )
            return(cJSON_Parse("{\"error\":\"illegal electrum call\"}"));
        if ( coin->inactive == 0 || strcmp(method,"importprivkey") == 0  || strcmp(method,"validateaddress") == 0 )
        {
            if ( coin->electrum == 0 )
            {
                retstr = bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,method,params);
                if ( 0 && strcmp("KMD",coin->symbol) == 0 )
                    printf("%s.(%s %s): %s.%s -> (%s)\n",coin->symbol,coin->serverport,coin->userpass,method,params,retstr);
                if ( retstr != 0 && retstr[0] != 0 )
                {
                    retjson = cJSON_Parse(retstr);
                    free(retstr);
                }
            }
            else
            {
                if ( (retjson= electrum_submit(coin->symbol,coin->electrum,&retjson,method,params,ELECTRUM_TIMEOUT)) != 0 )
                {
                    if ( jobj(retjson,"error") != 0 )
                    {
                        free_json(retjson);
                        retjson = 0;
                    }
                //printf("electrum %s.%s -> (%s)\n",method,params,jprint(retjson,0));
                    /*if ( (resultjson= jobj(retjson,"result")) != 0 )
                    {
                        resultjson = jduplicate(resultjson);
                        free_json(retjson);
                        retjson = resultjson;
                    }*/
                }
            }
        } else retjson = cJSON_Parse("{\"result\":\"disabled\"}");
    } else printf("bitcoin_json cant talk to NULL coin\n");
    return(retjson);
}

void LP_unspents_mark(char *symbol,cJSON *vins)
{
    printf("LOCK (%s)\n",jprint(vins,0));
}

char *NXTnodes[] = { "62.75.159.113", "91.44.203.238", "82.114.88.225", "78.63.207.76", "188.174.110.224", "91.235.72.49", "213.144.130.91", "209.222.98.250", "216.155.128.10", "178.33.203.157", "162.243.122.251", "69.163.47.173", "193.151.106.129", "78.94.2.74", "192.3.196.10", "173.33.112.87", "104.198.173.28", "35.184.154.126", "174.140.167.239", "23.88.113.131", "198.71.84.173", "178.150.207.53", "23.88.61.53", "192.157.233.106", "192.157.241.212", "23.89.192.88", "23.89.200.27", "192.157.241.139", "23.89.200.63", "23.89.192.98", "163.172.214.102", "176.9.85.5", "80.150.243.88", "80.150.243.92", "80.150.243.98", "109.70.186.198", "146.148.84.237", "104.155.56.82", "104.197.157.140", "37.48.73.249", "146.148.77.226", "84.57.170.200", "107.161.145.131", "80.150.243.97", "80.150.243.93", "80.150.243.100", "80.150.243.95", "80.150.243.91", "80.150.243.99", "80.150.243.96", "93.231.187.177", "212.237.23.85", "35.158.179.254", "46.36.66.41", "185.170.113.79", "163.172.68.112", "78.47.35.210", "77.90.90.75", "94.177.196.134", "212.237.22.215", "94.177.234.11", "167.160.180.199", "54.68.189.9", "94.159.62.14", "195.181.221.89", "185.33.145.94", "195.181.209.245", "195.181.221.38", "195.181.221.162", "185.33.145.12", "185.33.145.176", "178.79.128.235", "94.177.214.120", "94.177.199.41", "94.177.214.200", "94.177.213.201", "212.237.13.162", "195.181.221.236", "195.181.221.185", "185.28.103.187", "185.33.146.244", "217.61.123.71", "195.181.214.45", "195.181.212.99", "195.181.214.46", "195.181.214.215", "195.181.214.68", "217.61.123.118", "195.181.214.79", "217.61.123.14", "217.61.124.100", "195.181.214.111", "85.255.0.176", "81.2.254.116", "217.61.123.184", "195.181.212.231", "94.177.214.110", "195.181.209.164", "104.129.56.238", "85.255.13.64", "167.160.180.206", "217.61.123.226", "167.160.180.208", "93.186.253.127", "212.237.6.208", "94.177.207.190", "217.61.123.119", "85.255.1.245", "217.61.124.157", "37.59.57.141", "167.160.180.58", "104.223.53.14", "217.61.124.69", "195.181.212.103", "85.255.13.141", "104.207.133.204", "71.90.7.107", "107.150.18.108", "23.94.134.161", "80.150.243.13", "80.150.243.11", "185.81.165.52", "80.150.243.8" };

static char *assetids[][4] =
{
    { "13502152099823770958", "SUPERNETx2", "10000", "10000" },
    { "12071612744977229797", "SUPERNET", "10000", "10000" },
    { "12071612744977229797", "UNITY", "10000", "10000" },
    { "15344649963748848799", "DEX", "1", "100000000" },
    { "6883271355794806507", "PANGEA", "10000", "10000" },
    { "17911762572811467637", "JUMBLR", "10000", "10000" },
    { "17083334802666450484", "BET", "10000", "10000" },
    { "13476425053110940554", "CRYPTO", "1000", "100000" },
    { "6932037131189568014", "HODL", "1", "100000000" },
    { "3006420581923704757", "SHARK", "10000", "10000" },
    { "17571711292785902558", "BOTS", "1", "100000000" },
    { "10524562908394749924", "MGW", "1", "100000000" },
};

void LP_sendtoaddress_line(char *validaddress,char *assetname,uint64_t satoshis,uint64_t txnum)
{
    char line[1024],lowerstr[64];
    if ( strcmp(assetname,"SUPERNETx2") == 0 )
    {
        sprintf(line,"fiat/supernet sendtoaddress %s %.8f # txnum.%llu",validaddress,dstr(satoshis),(long long)txnum);
        printf("%s\n",line);
        sprintf(line,"fiat/revs sendtoaddress %s %.8f # txnum.%llu",validaddress,dstr(satoshis),(long long)txnum);
    }
    else
    {
        strcpy(lowerstr,assetname);
        tolowercase(lowerstr);
        sprintf(line,"fiat/%s sendtoaddress %s %.8f # txnum.%llu",lowerstr,validaddress,dstr(satoshis),(long long)txnum);
    }
    printf("%s\n",line);
}

uint64_t LP_assetid_mult(int32_t *assetindp,char *name,uint64_t assetid)
{
    int32_t i; uint64_t mult = 0;
    name[0] = 0;
    *assetindp = -1;
    for (i=0; i<sizeof(assetids)/sizeof(*assetids); i++)
    {
        if ( assetid == calc_nxt64bits(assetids[i][0]) )
        {
            *assetindp = i;
            mult = atoi(assetids[i][3]);
            strcpy(name,assetids[i][1]);
            break;
        }
    }
    return(mult);
}

cJSON *LP_NXT_message(char *method,uint64_t txnum,char *passphrase)
{
    char url[1024],*retstr; cJSON *retjson = 0;
    sprintf(url,"http://127.0.0.1:7876/nxt?requestType=%s&transaction=%llu&secretPhrase=%s",method,(long long)txnum,passphrase);
    //printf("issue.(%s)\n",url);
    if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            
        }
        free(retstr);
    }
    return(retjson);
}

cJSON *LP_NXT_decrypt(uint64_t txnum,char *account,char *data,char *nonce,char *passphrase)
{
    char url[1024],*retstr; cJSON *retjson = 0;
    if ( account != 0 && data != 0 && nonce != 0 && passphrase != 0 )
    {
        sprintf(url,"http://127.0.0.1:7876/nxt?requestType=readMessage&transaction=%llu&secretPhrase=%s",(long long)txnum,passphrase);
        if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                
            }
            free(retstr);
        }
    }
    return(retjson);
}

cJSON *LP_NXT_redeems()
{
    char url[1024],*retstr,*recv,*method,*msgstr,assetname[16]; uint64_t totals[20],mult,txnum,assetid,qty; int32_t i,ind,numtx,past_marker=0; cJSON *item,*attach,*decjson,*array,*msgjson,*encjson,*retjson=0;
    uint64_t txnum_marker = calc_nxt64bits("0");
    uint64_t txnum_marker2 = calc_nxt64bits("7256847492742571143");
char *passphrase = "";
char *account = "NXT-MRBN-8DFH-PFMK-A4DBM";
    memset(totals,0,sizeof(totals));
    sprintf(url,"http://127.0.0.1:7876/nxt?requestType=getBlockchainTransactions&account=%s",account);
    //printf("calling (%s)\n",url);
    if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (array= jarray(&numtx,retjson,"transactions")) != 0 )
            {
                for (i=0; i<numtx; i++)
                {
                    msgjson = encjson = decjson = 0;
                    txnum = assetid = qty = 0;
                    item = jitem(array,i);
                    msgstr = jstr(item,"message");
                    txnum = j64bits(item,"transaction");
                    if ( txnum == txnum_marker )
                        past_marker = 1;
                    //printf("%d: %s\n",i,jprint(item,0));
                    if ( (recv= jstr(item,"recipientRS")) != 0 && strcmp(recv,"NXT-MRBN-8DFH-PFMK-A4DBM") == 0 )
                    {
                        if ( (attach= jobj(item,"attachment")) != 0 && jint(attach,"version.AssetTransfer") == 1 )
                        {
                            assetid = j64bits(attach,"asset");
                            qty = j64bits(attach,"quantityQNT");
                            //printf("txnum.%llu (%s)\n",(long long)txnum,jprint(attach,0));
                            if ( (msgstr == 0 || msgstr[0] == 0) && jint(attach,"version.PrunablePlainMessage") == 1 )
                            {
                                method = "getPrunableMessage";
                                if ( (msgjson= LP_NXT_message(method,txnum,"test")) != 0 )
                                {
                                    msgstr = jstr(msgjson,"message");
                                    //printf("%d method.(%s) (%s)\n",i,method,msgstr);
                                }
                            }
                            if ( msgstr == 0 || msgstr[0] == 0 )
                                msgstr = jstr(attach,"message");
                            if ( msgstr == 0 || msgstr[0] == 0 )
                            {
                                
                                if ( (encjson= jobj(attach,"encryptedMessage")) != 0 )
                                {
                                    msgstr = "encryptedMessage";//jstr(encjson,"data");
                                    if ( (decjson= LP_NXT_decrypt(txnum,account,jstr(encjson,"data"),jstr(encjson,"nonce"),passphrase)) != 0 )
                                    {
                                        //printf("%s\n",jprint(decjson,0));
                                        if ( jstr(decjson,"decryptedMessage") != 0 )
                                            msgstr = jstr(decjson,"decryptedMessage");
                                    }
                                }
                            }
                        }
                        mult = LP_assetid_mult(&ind,assetname,assetid);
                        if ( ind >= 0 )
                            totals[ind] += qty * mult;
                        if ( msgstr != 0 && assetname[0] != 0 && qty != 0 )
                        {
                            char validaddress[64]; int32_t z,n;
                            n = (int32_t)strlen(msgstr);
                            for (z=0; z<n; z++)
                            {
                                if ( msgstr[z] == 'R' )
                                    break;
                            }
                            memset(validaddress,0,sizeof(validaddress));
                            if ( n-z >= 34 )
                                strncpy(validaddress,&msgstr[z],34);
                            if ( strlen(validaddress) == 34 || strlen(validaddress) == 33 )
                            {
                                //printf("%-4d: (%34s) <- %13.5f %10s tx.%llu past_marker.%d\n",i,validaddress,dstr(qty * mult),assetname,(long long)txnum,past_marker);
                                if ( past_marker == 0 )
                                {
                                    LP_sendtoaddress_line(validaddress,assetname,(qty * mult),txnum);
                                }
                            } else printf("%-4d: (%34s) <- %13.5f %10s tx.%llu\n",i,msgstr!=0?msgstr:jprint(item,0),dstr(qty * mult),assetname,(long long)txnum);
                        }
                        if ( msgjson != 0 )
                            free_json(msgjson);
                        if ( decjson != 0 )
                            free_json(decjson);
                    }
                    if ( txnum == txnum_marker2 )
                        break;
                }
            }
            //free_json(retjson);
        }
        free(retstr);
    }
    printf("\nTotal redeemed\n");
    for (i=0; i<sizeof(totals)/sizeof(*totals); i++)
    {
        if ( totals[i] != 0 )
            printf("%-10s %13.5f\n",assetids[i][1],dstr(totals[i]));
    }
    return(retjson);
}

cJSON *LP_assethbla(char *assetid)
{
    char url[1024],*retstr; int32_t n; cJSON *array,*bid=0,*ask=0,*retjson;
    sprintf(url,"http://%s:7876/nxt?requestType=getBidOrders&asset=%s&firstIndex=0&lastIndex=0",NXTnodes[rand() % (sizeof(NXTnodes)/sizeof(*NXTnodes))],assetid);
    if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
    {
        bid = cJSON_Parse(retstr);
        free(retstr);
    }
    sprintf(url,"http://%s:7876/nxt?requestType=getAskOrders&asset=%s&firstIndex=0&lastIndex=0",NXTnodes[rand() % (sizeof(NXTnodes)/sizeof(*NXTnodes))],assetid);
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
    cJSON *retjson; char *retstr,*method = "getinfo"; int32_t height;
    if ( coin == 0 )
        return(-1);
    height = coin->height;
    if ( coin->electrum == 0 && time(NULL) > coin->heighttime+60 )
    {
        if ( strcmp(coin->symbol,"BTC") == 0 )
            method = "getblockchaininfo";
        retstr = bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,method,"[]");
        if ( retstr != 0 && retstr[0] != 0 )
        {
            retjson = cJSON_Parse(retstr);
            coin->height = height = jint(retjson,"blocks");
            free_json(retjson);
            if ( coin->height > 0 )
                coin->heighttime = (uint32_t)time(NULL);
            free(retstr);
        }
    }
    return(height);
}

uint64_t LP_RTsmartbalance(struct iguana_info *coin)
{
    cJSON *array,*item; char buf[512],*retstr; int32_t i,n; uint64_t valuesum,value;
    valuesum = 0;
    sprintf(buf,"[0, 99999999, [\"%s\"]]",coin->smartaddr);
    retstr = bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,"listunspent",buf);
    if ( retstr != 0 && retstr[0] != 0 )
    {
        array = cJSON_Parse(retstr);
        if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                value = LP_value_extract(item,1);
                valuesum += value;
            }
        }
        free_json(array);
    }
    return(valuesum);
}

cJSON *LP_getmempool(char *symbol,char *coinaddr)
{
    cJSON *array; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 || (coin->electrum != 0 && coinaddr == 0) )
        return(cJSON_Parse("{\"error\":\"no native coin\"}"));
    if ( coin->electrum == 0 )
        return(bitcoin_json(coin,"getrawmempool","[]"));
    else return(electrum_address_getmempool(symbol,coin->electrum,&array,coinaddr));
}

cJSON *LP_paxprice(char *fiat)
{
    char buf[128],lfiat[65]; struct iguana_info *coin = LP_coinfind("KMD");
    strcpy(lfiat,fiat);
    tolowercase(lfiat);
    sprintf(buf,"[\"%s\", \"kmd\"]",lfiat);
    return(bitcoin_json(coin,"paxprice",buf));
}

cJSON *LP_gettx(char *symbol,bits256 txid)
{
    struct iguana_info *coin; char buf[512],str[65]; cJSON *retjson;
    //printf("LP_gettx %s %s\n",symbol,bits256_str(str,txid));
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    if ( bits256_nonz(txid) == 0 )
        return(cJSON_Parse("{\"error\":\"null txid\"}"));
    if ( coin->electrum == 0 )
    {
        sprintf(buf,"[\"%s\", 1]",bits256_str(str,txid));
        retjson = bitcoin_json(coin,"getrawtransaction",buf);
        return(retjson);
    }
    else
    {
        if ( (retjson= electrum_transaction(symbol,coin->electrum,&retjson,txid)) != 0 )
            return(retjson);
        else printf("failed blockchain.transaction.get %s %s\n",coin->symbol,bits256_str(str,txid));
        return(cJSON_Parse("{\"error\":\"no transaction bytes\"}"));
    }
}

uint32_t LP_locktime(char *symbol,bits256 txid)
{
    cJSON *txobj; uint32_t locktime = 0;
    if ( (txobj= LP_gettx(symbol,txid)) != 0 )
    {
        locktime = juint(txobj,"locktime");
        free_json(txobj);
    }
    return(locktime);
}

cJSON *LP_gettxout_json(bits256 txid,int32_t vout,int32_t height,char *coinaddr,uint64_t value)
{
    cJSON *retjson,*addresses,*sobj;
    retjson = cJSON_CreateObject();
    jaddnum(retjson,"value",dstr(value));
    jaddnum(retjson,"height",height);
    jaddbits256(retjson,"txid",txid);
    jaddnum(retjson,"vout",vout);
    addresses = cJSON_CreateArray();
    jaddistr(addresses,coinaddr);
    sobj = cJSON_CreateObject();
    jaddnum(sobj,"reqSigs",1);
    jaddstr(sobj,"type","pubkey");
    jadd(sobj,"addresses",addresses);
    jadd(retjson,"scriptPubKey",sobj);
    //printf("GETTXOUT.(%s)\n",jprint(retjson,0));
    return(retjson);
}

cJSON *LP_gettxout(char *symbol,char *coinaddr,bits256 txid,int32_t vout)
{
    char buf[128],str[65]; cJSON *item,*array,*vouts,*txobj,*retjson=0; int32_t i,v,n; bits256 t; struct iguana_info *coin; struct LP_transaction *tx; struct LP_address_utxo *up;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    if ( (coin= LP_coinfind(symbol)) == 0 )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    if ( bits256_nonz(txid) == 0 )
        return(cJSON_Parse("{\"error\":\"null txid\"}"));
    if ( coin->electrum == 0 )
    {
        sprintf(buf,"[\"%s\", %d, true]",bits256_str(str,txid),vout);
        return(bitcoin_json(coin,"gettxout",buf));
    }
    else
    {
        if ( (tx= LP_transactionfind(coin,txid)) != 0 && vout < tx->numvouts )
        {
            if ( tx->outpoints[vout].spendheight > 0 )
                return(0);
            //return(LP_gettxout_json(txid,vout,tx->height,tx->outpoints[vout].coinaddr,tx->outpoints[vout].value));
        }
        if ( coinaddr[0] == 0 )
        {
            if ( (txobj= electrum_transaction(symbol,coin->electrum,&txobj,txid)) != 0 )
            {
                if ( (vouts= jarray(&n,txobj,"vout")) != 0 && n > 0 )
                    LP_destaddr(coinaddr,jitem(vouts,vout));
                free_json(txobj);
            }
        }
        if ( coinaddr[0] != 0 )
        {
            if ( (up= LP_address_utxofind(coin,coinaddr,txid,vout)) != 0 )
            {
                if ( up->spendheight > 0 )
                    return(0);
                //return(LP_gettxout_json(txid,vout,up->U.height,coinaddr,up->U.value));
            }
            if ( (array= electrum_address_listunspent(coin->symbol,0,&array,coinaddr,1)) != 0 )
            {
                //printf("array.(%s)\n",jprint(array,0));
                if ( array != 0 && (n= cJSON_GetArraySize(array)) > 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        item = jitem(array,i);
                        t = jbits256(item,"tx_hash");
                        v = jint(item,"tx_pos");
                        if ( v == vout && bits256_cmp(t,txid) == 0 )
                        {
                            retjson = LP_gettxout_json(txid,vout,jint(item,"height"),coinaddr,j64bits(item,"value"));
                            break;
                        }
                    }
                }
                free_json(array);
                if ( retjson != 0 )
                    return(retjson);
            }
        }
        printf("couldnt find %s/v%d\n",bits256_str(str,txid),vout);
        return(cJSON_Parse("{\"error\":\"couldnt get tx\"}"));
    }
}

/*cJSON *LP_listtransactions(char *symbol,char *coinaddr,int32_t count,int32_t skip)
{
    char buf[128]; struct iguana_info *coin = LP_coinfind(symbol);
    if ( coin == 0 )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    if ( count == 0 )
        count = 100;
    sprintf(buf,"[\"%s\", %d, %d, true]",coinaddr,count,skip);
    return(bitcoin_json(coin,"listtransactions",buf));
}*/

cJSON *LP_validateaddress(char *symbol,char *address)
{
    char buf[512],coinaddr[64],checkaddr[64],script[128]; int32_t i; uint8_t rmd160[20],addrtype; cJSON *retjson; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    if ( coin != 0 && coin->electrum != 0 )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"address",address);
        bitcoin_addr2rmd160(coin->taddr,&addrtype,rmd160,address);
        bitcoin_address(checkaddr,coin->taddr,addrtype,rmd160,20);
        jadd(retjson,"isvalid",strcmp(address,checkaddr)==0? cJSON_CreateTrue() : cJSON_CreateFalse());
        if ( addrtype == coin->pubtype )
        {
            strcpy(script,"76a914");
            for (i=0; i<20; i++)
                sprintf(&script[i*2+6],"%02x",rmd160[i]);
            script[i*2+6] = 0;
            strcat(script,"88ac");
            jaddstr(retjson,"scriptPubKey",script);
        }
        bitcoin_address(coinaddr,coin->taddr,coin->pubtype,G.LP_myrmd160,20);
        jadd(retjson,"ismine",strcmp(address,coin->smartaddr) == 0 ? cJSON_CreateTrue() : cJSON_CreateFalse());
        jadd(retjson,"iswatchonly",cJSON_CreateFalse());
        jadd(retjson,"isscript",addrtype == coin->p2shtype ? cJSON_CreateTrue() : cJSON_CreateFalse());
        return(retjson);
    }
    else
    {
        sprintf(buf,"[\"%s\"]",address);
        return(bitcoin_json(coin,"validateaddress",buf));
    }
}

int32_t LP_address_ismine(char *symbol,char *address)
{
    int32_t doneflag = 0; cJSON *retjson;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
    if ( (retjson= LP_validateaddress(symbol,address)) != 0 )
    {
        if ( jobj(retjson,"ismine") != 0 && is_cJSON_True(jobj(retjson,"ismine")) != 0 )
        {
            doneflag = 1;
            //printf("%s ismine (%s)\n",address,jprint(retjson,0));
        }
        //printf("%s\n",jprint(retjson,0));
        free_json(retjson);
    }
    return(doneflag);
}

int32_t LP_address_isvalid(char *symbol,char *address)
{
    int32_t isvalid = 0; cJSON *retjson;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
    if ( (retjson= LP_validateaddress(symbol,address)) != 0 )
    {
        if ( jobj(retjson,"isvalid") != 0 && is_cJSON_True(jobj(retjson,"isvalid")) != 0 )
        {
            isvalid = 1;
            //printf("%s ismine (%s)\n",address,jprint(retjson,0));
        }
        //printf("%s\n",jprint(retjson,0));
        free_json(retjson);
    }
    return(isvalid);
}

cJSON *LP_listunspent(char *symbol,char *coinaddr)
{
    char buf[128]; cJSON *retjson; int32_t numconfs; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    //printf("LP_listunspent.(%s %s)\n",symbol,coinaddr);
    if ( coin == 0 || (IAMLP == 0 && coin->inactive != 0) )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    if ( coin->electrum == 0 )
    {
        if ( LP_address_ismine(symbol,coinaddr) > 0 )
        {
            if ( strcmp(symbol,"BTC") == 0 )
                numconfs = 0;
            else numconfs = 1;
            sprintf(buf,"[%d, 99999999, [\"%s\"]]",numconfs,coinaddr);
            return(bitcoin_json(coin,"listunspent",buf));
        } else return(LP_address_utxos(coin,coinaddr,0));
    } else return(electrum_address_listunspent(symbol,coin->electrum,&retjson,coinaddr,1));
}

int32_t LP_listunspent_issue(char *symbol,char *coinaddr,int32_t fullflag)
{
    struct iguana_info *coin; int32_t n = 0; cJSON *retjson=0; char *retstr=0,destip[64]; uint16_t destport;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
    if ( (coin= LP_coinfind(symbol)) != 0 )
    {
        if ( coin->electrum != 0 )
        {
            if ( (retjson= electrum_address_listunspent(symbol,coin->electrum,&retjson,coinaddr,1)) != 0 )
            {
                n = cJSON_GetArraySize(retjson);
                //printf("LP_listunspent_issue.%s %s.%d %s\n",symbol,coinaddr,n,jprint(retjson,0));
            }
        }
        else
        {
            if ( strcmp(coin->smartaddr,coinaddr) == 0 )
            {
                retjson = LP_listunspent(symbol,coinaddr);
                coin->numutxos = cJSON_GetArraySize(retjson);
                //printf("SELF_LISTUNSPENT.(%s %s)\n",symbol,coinaddr);
            }
            else if ( IAMLP == 0 )
            {
                //printf("LP_listunspent_query.(%s %s)\n",symbol,coinaddr);
                LP_listunspent_query(coin->symbol,coin->smartaddr);
                if ( fullflag != 0 )
                {
                    if ( (destport= LP_randpeer(destip)) > 0 )
                    {
                        retstr = issue_LP_listunspent(destip,destport,symbol,coinaddr);
                        //printf("issue %s %s %s -> (%s)\n",coin->symbol,coinaddr,destip,retstr);
                        retjson = cJSON_Parse(retstr);
                    } else printf("LP_listunspent_issue couldnt get a random peer?\n");
                }
            }
            if ( retjson != 0 )
            {
                n = cJSON_GetArraySize(retjson);
                if ( electrum_process_array(coin,0,coinaddr,retjson,1) != 0 )
                {
                    //LP_postutxos(symbol,coinaddr); // might be good to not saturate
                }
            }
        }
        //printf("issue listunspent %s (%s)\n",coinaddr,jprint(retjson,0));
        if ( retjson != 0 )
            free_json(retjson);
        if ( retstr != 0 )
            free(retstr);
    }
    return(n);
}

cJSON *LP_importprivkey(char *symbol,char *wifstr,char *label,int32_t flag)
{
    static void *ctx;
    char buf[512],address[64]; cJSON *retjson; struct iguana_info *coin; int32_t doneflag = 0;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    if ( coin->electrum != 0 )
        return(cJSON_Parse("{\"result\":\"electrum should have local wallet\"}"));
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
    char buf[1024],*retstr; cJSON *validatejson; int32_t isvalid=0,doneflag = 0; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(-2);
    coin = LP_coinfind(symbol);
    if ( coin == 0 )
        return(-2);
    if ( coin->electrum != 0 )
    {
        /*if ( (retjson= electrum_address_subscribe(symbol,coin->electrum,&retjson,address)) != 0 )
        {
            printf("importaddress.(%s) -> %s\n",address,jprint(retjson,0));
            free_json(retjson);
        }*/
        return(0);
    }
    else
    {
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
}

double _LP_getestimatedrate(struct iguana_info *coin)
{
    char buf[512],*retstr=0; int32_t numblocks; cJSON *errjson,*retjson; double rate = 0.00000020;
    if ( coin->rate < 0. || time(NULL) > coin->ratetime+30 )
    {
        numblocks = strcmp(coin->symbol,"BTC") == 0 ? 6 : 2;
        if ( coin->electrum == 0 )
        {
            sprintf(buf,"[%d]",numblocks);
            retstr = LP_apicall(coin,"estimatefee",buf);
        }
        else
        {
            if ( (retjson= electrum_estimatefee(coin->symbol,coin->electrum,&retjson,numblocks)) != 0 )
                retstr = jprint(retjson,1);
        }
        if ( retstr != 0 )
        {
            if ( retstr[0] == '{' && (errjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( jobj(errjson,"error") != 0 )
                    rate = 0.;
                free_json(errjson);
            }
            else if ( retstr[0] != '-' )
            {
                rate = atof(retstr) / 1024.;
                if ( rate < 0.00000020 )
                    rate = 0.00000020;
                rate *= 1.1;
                if ( coin->electrum != 0 )
                    rate *= 1.667;
                if ( fabs(rate - coin->rate) > SMALLVAL )
                    printf("t%u estimated rate.(%s) (%s) -> %.8f %.8f\n",coin->ratetime,coin->symbol,retstr,rate,coin->rate);
                coin->rate = rate;
                coin->ratetime = (uint32_t)time(NULL);
            }
            free(retstr);
        } else rate = coin->rate;
    } else rate = coin->rate;
    return(rate);
}

double LP_getestimatedrate(struct iguana_info *coin)
{
    double rate = 0.00000020;
    if ( coin == 0 )
        return(rate);
    if ( (rate= _LP_getestimatedrate(coin)) <= 0. )
        rate = dstr(coin->txfee) / LP_AVETXSIZE;
    return(rate);
}

char *LP_sendrawtransaction(char *symbol,char *signedtx)
{
    cJSON *array,*errobj; char *paramstr,*tmpstr,*retstr=0; int32_t n,alreadyflag = 0; cJSON *retjson; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 || signedtx == 0 || signedtx[0] == 0 )
    {
        printf("LP_sendrawtransaction null symbol %p or signedtx.%p\n",symbol,signedtx);
        return(0);
    }
    coin = LP_coinfind(symbol);
    if ( coin == 0 )
    {
        printf("LP_sendrawtransaction null coin\n");
        return(0);
    }
    if ( coin->electrum == 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,signedtx);
        paramstr = jprint(array,1);
        retstr = bitcoind_passthru(symbol,coin->serverport,coin->userpass,"sendrawtransaction",paramstr);
        //printf(">>>>>>>>>>> %s dpow_sendrawtransaction.(%s) -> (%s)\n",coin->symbol,paramstr,retstr);
        free(paramstr);
    }
    else
    {
        if ( (retjson= electrum_sendrawtransaction(symbol,coin->electrum,&retjson,signedtx)) != 0 )
        {
            retstr = jprint(retjson,1);
            //electrum sendrawtx (the transaction was rejected by network rules.\n\ntransaction already in block chain)
            if ( strstr(retstr,"already in block") != 0 )
                alreadyflag = 1;
            //printf("electrum sendrawtx.(%s) -> %s already.%d\n",signedtx,retstr,alreadyflag);
            if ( alreadyflag != 0 )
            {
                errobj = cJSON_CreateObject();
                jaddstr(errobj,"error","rejected");
                jaddnum(errobj,"code",-27);
                retstr = jprint(errobj,1);
            }
            else
            {
                n = (int32_t)strlen(retstr);
                if ( retstr[0] == '"' && retstr[n-1] == '"' )
                {
                    retstr[n-1] = 0;
                    tmpstr = clonestr(retstr+1);
                    free(retstr);
                    retstr = tmpstr;
                }
            }
        }
    }
    return(retstr);
}

char *LP_signrawtx(char *symbol,bits256 *signedtxidp,int32_t *completedp,cJSON *vins,char *rawtx,cJSON *privkeys,struct vin_info *V)
{
    cJSON *array,*json,*retjson; int32_t len; uint8_t *data; char str[65],*paramstr,*retstr,*hexstr,*signedtx=0; struct iguana_msgtx msgtx; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
    coin = LP_coinfind(symbol);
    memset(signedtxidp,0,sizeof(*signedtxidp));
    *completedp = 0;
    if ( coin == 0 )
    {
        printf("LP_signrawtx cant find coin.(%s)\n",symbol);
        return(0);
    }
    //int32_t iguana_signrawtransaction(void *ctx,char *symbol,uint8_t wiftaddr,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,struct iguana_msgtx *msgtx,char **signedtxp,bits256 *signedtxidp,struct vin_info *V,int32_t numinputs,char *rawtx,cJSON *vins,cJSON *privkeysjson)
    memset(&msgtx,0,sizeof(msgtx));
    signedtx = 0;
    memset(signedtxidp,0,sizeof(*signedtxidp));
    //printf("locktime.%u sequenceid.%x rawtx.(%s) vins.(%s)\n",locktime,sequenceid,rawtxbytes,jprint(vins,0));
    if ( (*completedp= iguana_signrawtransaction(coin->ctx,symbol,coin->wiftaddr,coin->taddr,coin->pubtype,coin->p2shtype,coin->isPoS,1000000,&msgtx,&signedtx,signedtxidp,V,16,rawtx,vins,privkeys,coin->zcash)) < 0 )
        //if ( (signedtx= LP_signrawtx(symbol,signedtxidp,&completed,vins,rawtxbytes,privkeys,V)) == 0 )
        printf("couldnt sign transaction.%s %s\n",rawtx,bits256_str(str,*signedtxidp));
    else if ( *completedp == 0 )
    {
        printf("incomplete signing %s (%s)\n",rawtx,jprint(vins,0));
        if ( signedtx != 0 )
            free(signedtx), signedtx = 0;
    } else printf("basilisk_swap_bobtxspend %s -> %s\n",rawtx,bits256_str(str,*signedtxidp));
    if ( signedtx == 0 )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"error","couldnt sign tx");
        jaddstr(retjson,"coin",coin->symbol);
        jaddstr(retjson,"rawtx",rawtx);
        jadd(retjson,"vins",vins);
        jadd(retjson,"privkeys",privkeys);
        return(jprint(retjson,1));
    }
    return(signedtx);
    
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
                len >>= 1;
                data = malloc(len);
                decode_hex(data,len,hexstr);
                *signedtxidp = bits256_doublesha256(0,data,len);
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

cJSON *LP_getblock(char *symbol,bits256 txid)
{
    char buf[128],str[65]; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 || coin->electrum != 0 )
        return(cJSON_Parse("{\"error\":\"no native coin\"}"));
    sprintf(buf,"[\"%s\"]",bits256_str(str,txid));
    return(bitcoin_json(coin,"getblock",buf));
}

// not in electrum path
uint64_t LP_txfee(char *symbol)
{
    uint64_t txfee = 0;
    if ( symbol == 0 || symbol[0] == 0 )
        return(LP_MIN_TXFEE);
    if ( strcmp(symbol,"BTC") != 0 )
        txfee = LP_MIN_TXFEE;
    return(txfee);
}

bits256 LP_getbestblockhash(struct iguana_info *coin)
{
    char *retstr; bits256 blockhash;
    memset(blockhash.bytes,0,sizeof(blockhash));
    if ( coin->electrum == 0 )
    {
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,"getbestblockhash","")) != 0 )
        {
            if ( is_hexstr(retstr,0) == sizeof(blockhash)*2 )
                decode_hex(blockhash.bytes,sizeof(blockhash),retstr);
            free(retstr);
        }
    }
    return(blockhash);
}

char *LP_blockhashstr(char *symbol,int32_t height)
{
    cJSON *array; char *paramstr,*retstr; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
    coin = LP_coinfind(symbol);
    if ( coin == 0 || coin->electrum != 0 )
        return(0);
    array = cJSON_CreateArray();
    jaddinum(array,height);
    paramstr = jprint(array,1);
    retstr = bitcoind_passthru(symbol,coin->serverport,coin->userpass,"getblockhash",paramstr);
    free(paramstr);
    return(retstr);
}

cJSON *LP_getblockhashstr(char *symbol,char *blockhashstr)
{
    char buf[128]; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 || coin->electrum != 0 )
        return(cJSON_Parse("{\"error\":\"no native coin daemon\"}"));
    sprintf(buf,"[\"%s\"]",blockhashstr);
    return(bitcoin_json(coin,"getblock",buf));
}

cJSON *LP_blockjson(int32_t *heightp,char *symbol,char *blockhashstr,int32_t height)
{
    cJSON *json = 0; int32_t flag = 0; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 || coin->electrum != 0 )
    {
        printf("unexpected electrum path for %s\n",symbol);
        return(0);
    }
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

const char *Notaries_elected[][2] =
{
    { "0_jl777_testA", "03b7621b44118017a16043f19b30cc8a4cfe068ac4e42417bae16ba460c80f3828" },
    { "0_jl777_testB", "02ebfc784a4ba768aad88d44d1045d240d47b26e248cafaf1c5169a42d7a61d344" },
    { "0_kolo_testA", "0287aa4b73988ba26cf6565d815786caf0d2c4af704d7883d163ee89cd9977edec" },
    { "artik_AR", "029acf1dcd9f5ff9c455f8bb717d4ae0c703e089d16cf8424619c491dff5994c90" },
    { "artik_EU", "03f54b2c24f82632e3cdebe4568ba0acf487a80f8a89779173cdb78f74514847ce" },
    { "artik_NA", "0224e31f93eff0cc30eaf0b2389fbc591085c0e122c4d11862c1729d090106c842" },
    { "artik_SH", "02bdd8840a34486f38305f311c0e2ae73e84046f6e9c3dd3571e32e58339d20937" },
    { "badass_EU", "0209d48554768dd8dada988b98aca23405057ac4b5b46838a9378b95c3e79b9b9e" },
    { "badass_NA", "02afa1a9f948e1634a29dc718d218e9d150c531cfa852843a1643a02184a63c1a7" },
    { "badass_SH", "026b49dd3923b78a592c1b475f208e23698d3f085c4c3b4906a59faf659fd9530b" },
    { "crackers_EU", "03bc819982d3c6feb801ec3b720425b017d9b6ee9a40746b84422cbbf929dc73c3" }, // 10
    { "crackers_NA", "03205049103113d48c7c7af811b4c8f194dafc43a50d5313e61a22900fc1805b45" },
    { "crackers_SH", "02be28310e6312d1dd44651fd96f6a44ccc269a321f907502aae81d246fabdb03e" },
    { "durerus_EU", "02bcbd287670bdca2c31e5d50130adb5dea1b53198f18abeec7211825f47485d57" },
    { "etszombi_AR", "031c79168d15edabf17d9ec99531ea9baa20039d0cdc14d9525863b83341b210e9" },
    { "etszombi_EU", "0281b1ad28d238a2b217e0af123ce020b79e91b9b10ad65a7917216eda6fe64bf7" },
    { "etszombi_SH", "025d7a193c0757f7437fad3431f027e7b5ed6c925b77daba52a8755d24bf682dde" },
    { "farl4web_EU", "0300ecf9121cccf14cf9423e2adb5d98ce0c4e251721fa345dec2e03abeffbab3f" },
    { "farl4web_SH", "0396bb5ed3c57aa1221d7775ae0ff751e4c7dc9be220d0917fa8bbdf670586c030" },
    { "fullmoon_AR", "0254b1d64840ce9ff6bec9dd10e33beb92af5f7cee628f999cb6bc0fea833347cc" },
    { "fullmoon_NA", "031fb362323b06e165231c887836a8faadb96eda88a79ca434e28b3520b47d235b" }, // 20
    { "fullmoon_SH", "030e12b42ec33a80e12e570b6c8274ce664565b5c3da106859e96a7208b93afd0d" },
    { "grewal_NA", "03adc0834c203d172bce814df7c7a5e13dc603105e6b0adabc942d0421aefd2132" },
    { "grewal_SH", "03212a73f5d38a675ee3cdc6e82542a96c38c3d1c79d25a1ed2e42fcf6a8be4e68" },
    { "indenodes_AR", "02ec0fa5a40f47fd4a38ea5c89e375ad0b6ddf4807c99733c9c3dc15fb978ee147" },
    { "indenodes_EU", "0221387ff95c44cb52b86552e3ec118a3c311ca65b75bf807c6c07eaeb1be8303c" },
    { "indenodes_NA", "02698c6f1c9e43b66e82dbb163e8df0e5a2f62f3a7a882ca387d82f86e0b3fa988" },
    { "indenodes_SH", "0334e6e1ec8285c4b85bd6dae67e17d67d1f20e7328efad17ce6fd24ae97cdd65e" },
    { "jeezy_EU", "023cb3e593fb85c5659688528e9a4f1c4c7f19206edc7e517d20f794ba686fd6d6" },
    { "jsgalt_NA", "027b3fb6fede798cd17c30dbfb7baf9332b3f8b1c7c513f443070874c410232446" },
    { "karasugoi_NA", "02a348b03b9c1a8eac1b56f85c402b041c9bce918833f2ea16d13452309052a982" }, // 30
    { "kashifali_EU", "033777c52a0190f261c6f66bd0e2bb299d30f012dcb8bfff384103211edb8bb207" },
    { "kolo_AR", "03016d19344c45341e023b72f9fb6e6152fdcfe105f3b4f50b82a4790ff54e9dc6" },
    { "kolo_SH", "02aa24064500756d9b0959b44d5325f2391d8e95c6127e109184937152c384e185" },
    { "metaphilibert_AR", "02adad675fae12b25fdd0f57250b0caf7f795c43f346153a31fe3e72e7db1d6ac6" },
    { "movecrypto_AR", "022783d94518e4dc77cbdf1a97915b29f427d7bc15ea867900a76665d3112be6f3" },
    { "movecrypto_EU", "021ab53bc6cf2c46b8a5456759f9d608966eff87384c2b52c0ac4cc8dd51e9cc42" },
    { "movecrypto_NA", "02efb12f4d78f44b0542d1c60146738e4d5506d27ec98a469142c5c84b29de0a80" },
    { "movecrypto_SH", "031f9739a3ebd6037a967ce1582cde66e79ea9a0551c54731c59c6b80f635bc859" },
    { "muros_AR", "022d77402fd7179335da39479c829be73428b0ef33fb360a4de6890f37c2aa005e" },
    { "noashh_AR", "029d93ef78197dc93892d2a30e5a54865f41e0ca3ab7eb8e3dcbc59c8756b6e355" }, // 40
    { "noashh_EU", "02061c6278b91fd4ac5cab4401100ffa3b2d5a277e8f71db23401cc071b3665546" },
    { "noashh_NA", "033c073366152b6b01535e15dd966a3a8039169584d06e27d92a69889b720d44e1" },
    { "nxtswe_EU", "032fb104e5eaa704a38a52c126af8f67e870d70f82977e5b2f093d5c1c21ae5899" },
    { "polycryptoblog_NA", "02708dcda7c45fb54b78469673c2587bfdd126e381654819c4c23df0e00b679622" },
    { "pondsea_AR", "032e1c213787312099158f2d74a89e8240a991d162d4ce8017d8504d1d7004f735" },
    { "pondsea_EU", "0225aa6f6f19e543180b31153d9e6d55d41bc7ec2ba191fd29f19a2f973544e29d" },
    { "pondsea_NA", "031bcfdbb62268e2ff8dfffeb9ddff7fe95fca46778c77eebff9c3829dfa1bb411" },
    { "pondsea_SH", "02209073bc0943451498de57f802650311b1f12aa6deffcd893da198a544c04f36" },
    { "popcornbag_AR", "02761f106fb34fbfc5ddcc0c0aa831ed98e462a908550b280a1f7bd32c060c6fa3" },
    { "popcornbag_NA", "03c6085c7fdfff70988fda9b197371f1caf8397f1729a844790e421ee07b3a93e8" }, // 50
    { "ptytrader_NA", "0328c61467148b207400b23875234f8a825cce65b9c4c9b664f47410b8b8e3c222" },
    { "ptytrader_SH", "0250c93c492d8d5a6b565b90c22bee07c2d8701d6118c6267e99a4efd3c7748fa4" },
    { "rnr_AR", "029bdb08f931c0e98c2c4ba4ef45c8e33a34168cb2e6bf953cef335c359d77bfcd" },
    { "rnr_EU", "03f5c08dadffa0ffcafb8dd7ffc38c22887bd02702a6c9ac3440deddcf2837692b" },
    { "rnr_NA", "02e17c5f8c3c80f584ed343b8dcfa6d710dfef0889ec1e7728ce45ce559347c58c" },
    { "rnr_SH", "037536fb9bdfed10251f71543fb42679e7c52308bcd12146b2568b9a818d8b8377" },
    { "titomane_AR", "03cda6ca5c2d02db201488a54a548dbfc10533bdc275d5ea11928e8d6ab33c2185" },
    { "titomane_EU", "02e41feded94f0cc59f55f82f3c2c005d41da024e9a805b41105207ef89aa4bfbd" },
    { "titomane_SH", "035f49d7a308dd9a209e894321f010d21b7793461b0c89d6d9231a3fe5f68d9960" },
    { "vanbreuk_EU", "024f3cad7601d2399c131fd070e797d9cd8533868685ddbe515daa53c2e26004c3" }, // 60
    { "xrobesx_NA", "03f0cc6d142d14a40937f12dbd99dbd9021328f45759e26f1877f2a838876709e1" },
    { "xxspot1_XX", "02ef445a392fcaf3ad4176a5da7f43580e8056594e003eba6559a713711a27f955" },
    { "xxspot2_XX", "03d85b221ea72ebcd25373e7961f4983d12add66a92f899deaf07bab1d8b6f5573" }
};

int32_t LP_txhasnotarization(struct iguana_info *coin,bits256 txid)
{
    cJSON *txobj,*vins,*vin,*vouts,*vout,*spentobj,*sobj; char *hexstr; uint8_t script[35]; bits256 spenttxid; uint64_t notarymask; int32_t i,j,numnotaries,len,spentvout,numvins,numvouts,hasnotarization = 0;
    if ( (txobj= LP_gettx(coin->symbol,txid)) != 0 )
    {
        if ( (vins= jarray(&numvins,txobj,"vin")) != 0 )
        {
            if ( numvins >= DPOW_MIN_ASSETCHAIN_SIGS )
            {
                notarymask = numnotaries = 0;
                for (i=0; i<numvins; i++)
                {
                    vin = jitem(vins,i);
                    spenttxid = jbits256(vin,"txid");
                    spentvout = jint(vin,"vout");
                    if ( (spentobj= LP_gettx(coin->symbol,spenttxid)) != 0 )
                    {
                        if ( (vouts= jarray(&numvouts,spentobj,"vout")) != 0 )
                        {
                            if ( spentvout < numvouts )
                            {
                                vout = jitem(vouts,spentvout);
                                if ( (sobj= jobj(vout,"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 && (len= is_hexstr(hexstr,0)) == sizeof(script)*2 )
                                {
                                    len >>= 1;
                                    decode_hex(script,len,hexstr);
                                    if ( script[0] == 33 && script[34] == 0xac )
                                    {
                                        for (j=0; j<sizeof(Notaries_elected)/sizeof(*Notaries_elected); j++)
                                        {
                                            if ( strncmp(Notaries_elected[j][1],hexstr+2,66) == 0 )
                                            {
                                                if ( ((1LL << j) & notarymask) == 0 )
                                                {
                                                    //printf("n%d ",j);
                                                    numnotaries++;
                                                    notarymask |= (1LL << j);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        free_json(spentobj);
                    }
                }
                if ( numnotaries > 0 )
                {
                    if ( numnotaries >= DPOW_MIN_ASSETCHAIN_SIGS )
                        hasnotarization = 1;
                    //printf("numnotaries.%d %s hasnotarization.%d\n",numnotaries,coin->symbol,hasnotarization);
                }
            }
        }
        free_json(txobj);
    }
    return(hasnotarization);
}

int32_t LP_hasnotarization(struct iguana_info *coin,cJSON *blockjson)
{
    int32_t i,n,hasnotarization = 0; bits256 txid; cJSON *txarray;
    if ( (txarray= jarray(&n,blockjson,"tx")) != 0 )
    {
        for (i=0; i<n; i++)
        {
            txid = jbits256i(txarray,i);
            hasnotarization += LP_txhasnotarization(coin,txid);
        }
    }
    return(hasnotarization);
}

int32_t LP_notarization_latest(int32_t *bestheightp,struct iguana_info *coin)
{
    cJSON *blockjson; bits256 blockhash; int32_t height=-1,hasnotarization;
    *bestheightp = -1;
    memset(blockhash.bytes,0,sizeof(blockhash));
    while ( 1 )
    {
        if ( bits256_nonz(blockhash) == 0 )
            blockhash = LP_getbestblockhash(coin);
        if ( bits256_nonz(blockhash) != 0 )
        {
            if ( (blockjson= LP_getblock(coin->symbol,blockhash)) != 0 )
            {
                if ( *bestheightp < 0 )
                    *bestheightp = jint(blockjson,"height");
                if ( (hasnotarization= LP_hasnotarization(coin,blockjson)) > 0 )
                {
                    height = jint(blockjson,"height");
                    //char str[65]; printf("%s height.%d\n",bits256_str(str,blockhash),height);
                }
                else
                {
                    blockhash = jbits256(blockjson,"previousblockhash");
                    if ( bits256_nonz(blockhash) == 0 )
                    {
                        printf("null prev.(%s)\n",jprint(blockjson,0));
                        free_json(blockjson);
                        break;
                    }
                }
                free_json(blockjson);
                if ( height > 0 )
                    break;
            }
        } else break;
    }
    return(height);
}
