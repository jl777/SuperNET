
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
//  LP_commands.c
//  marketmaker
//

char *LP_numutxos()
{
    cJSON *retjson = cJSON_CreateObject();
    if ( LP_mypeer != 0 )
    {
        jaddstr(retjson,"ipaddr",LP_mypeer->ipaddr);
        jaddnum(retjson,"port",LP_mypeer->port);
        //jaddnum(retjson,"numutxos",LP_mypeer->numutxos);
        jaddnum(retjson,"numpeers",LP_mypeer->numpeers);
        jaddnum(retjson,"session",G.LP_sessionid);
    } else jaddstr(retjson,"error","client node");
    return(jprint(retjson,1));
}

char *stats_JSON(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,char *remoteaddr,uint16_t port) // from rpc port
{
    char *method,*ipaddr,*userpass,*base,*rel,*coin,*retstr = 0; uint16_t argport=0,pushport,subport; int32_t changed,otherpeers,flag = 0; struct LP_peerinfo *peer; cJSON *retjson,*reqjson = 0; struct iguana_info *ptr;
//printf("stats_JSON(%s)\n",jprint(argjson,0));
    method = jstr(argjson,"method");
    if ( (ipaddr= jstr(argjson,"ipaddr")) != 0 && (argport= juint(argjson,"port")) != 0 && (method == 0 || strcmp(method,"electrum") != 0) )
    {
        if ( strcmp(ipaddr,"127.0.0.1") != 0 && argport >= 1000 )
        {
            flag = 1;
            if ( (pushport= juint(argjson,"push")) == 0 )
                pushport = argport + 1;
            if ( (subport= juint(argjson,"sub")) == 0 )
                subport = argport + 2;
            if ( (peer= LP_peerfind((uint32_t)calc_ipbits(ipaddr),argport)) != 0 )
            {
                if ( 0 && (otherpeers= jint(argjson,"numpeers")) > peer->numpeers )
                    peer->numpeers = otherpeers;
                /*if ( 0 && (othernumutxos= jint(argjson,"numutxos")) > peer->numutxos )
                {
                    printf("change.(%s) numutxos.%d -> %d mynumutxos.%d\n",peer->ipaddr,peer->numutxos,othernumutxos,LP_mypeer != 0 ? LP_mypeer->numutxos:0);
                    peer->numutxos = othernumutxos;
                }*/
                if ( peer->sessionid == 0 )
                    peer->sessionid = juint(argjson,"session");
                //printf("peer.(%s) found (%d %d) (%d %d) (%s)\n",peer->ipaddr,peer->numpeers,peer->numutxos,otherpeers,othernumutxos,jprint(argjson,0));
            } else LP_addpeer(LP_mypeer,LP_mypubsock,ipaddr,argport,pushport,subport,jint(argjson,"numpeers"),jint(argjson,"numutxos"),juint(argjson,"session"));
        }
    }
    if ( method == 0 )
    {
        if ( flag == 0 || jobj(argjson,"result") != 0 )
            printf("stats_JSON no method: (%s) (%s:%u)\n",jprint(argjson,0),ipaddr,argport);
        return(0);
    }
    /*if ( strcmp(method,"hello") == 0 )
    {
        //printf("got hello from %s:%u\n",ipaddr!=0?ipaddr:"",argport);
        return(0);
    }
    else*/ if ( strcmp(method,"sendmessage") == 0 && jobj(argjson,"userpass") == 0 )
    {
        static char *laststr;
        char *newstr; bits256 pubkey = jbits256(argjson,"pubkey");
        if ( bits256_nonz(pubkey) == 0 || bits256_cmp(pubkey,G.LP_mypub25519) == 0 )
        {
            newstr = jprint(argjson,0);
            if ( laststr == 0 || strcmp(laststr,newstr) != 0 )
            {
                printf("got message.(%s) from %s:%u\n",newstr,ipaddr!=0?ipaddr:"",argport);
                if ( laststr != 0 )
                    free(laststr);
                laststr = newstr;
                LP_gotmessage(argjson);
                retstr = clonestr(laststr);
            }
        } else retstr = clonestr("{\"error\":\"duplicate message\"}");
    }
    //else if ( strcmp(method,"nn_tests") == 0 )
    //    return(clonestr("{\"result\":\"success\"}"));
    else if ( strcmp(method,"help") == 0 )
        return(clonestr("{\"result\":\" \
available localhost RPC commands: * means it needs to be a signed request\n \
pricearray(base, rel, firsttime=0, lasttime=-1, timescale=60) -> [timestamp, avebid, aveask, highbid, lowask]\n\
setprice(base, rel, price)*\n\
autoprice(base, rel, price, margin, type)*\n\
goal(coin=*, val=<autocalc>)*\n\
myprice(base, rel)\n\
enable(coin)*\n\
disable(coin)*\n\
inventory(coin)\n\
bestfit(rel, relvolume)\n\
lastnonce()\n\
buy(base, rel, price, relvolume, timeout=10, duration=3600, nonce)*\n\
sell(base, rel, price, basevolume, timeout=10, duration=3600, nonce)*\n\
withdraw(coin, outputs[])*\n\
sendrawtransaction(coin, signedtx)\n\
swapstatus()*\n\
swapstatus(requestid, quoteid)*\n\
public API:\n \
getcoins()\n\
getcoin(coin)\n\
portfolio()\n\
getpeers()\n\
passphrase(passphrase, gui)\n\
listunspent(coin, address)\n\
setconfirms(coin, numconfirms, maxconfirms=6)*\n\
trust(pubkey, trust)*\n\
balance(coin, address)\n\
orderbook(base, rel, duration=3600)\n\
getprices(base, rel)\n\
sendmessage(base=coin, rel="", pubkey=zero, <argjson method2>)\n\
getmessages(firsti=0, num=100)\n\
deletemessages(firsti=0, num=100)\n\
secretaddresses(prefix='secretaddress', passphrase, num=10, pubtype=60, taddr=0)\n\
electrum(coin, ipaddr, port)*\n\
snapshot(coin, height)\n\
snapshot_balance(coin, height, addresses[])\n\
dividends(coin, height, <args>)\n\
\"}"));
    //sell(base, rel, price, basevolume, timeout=10, duration=3600)\n\

    base = jstr(argjson,"base");
    rel = jstr(argjson,"rel");
    coin = jstr(argjson,"coin");
    if ( G.USERPASS[0] != 0 && strcmp(remoteaddr,"127.0.0.1") == 0 && port != 0 )
    {
        if ( G.USERPASS_COUNTER == 0 )
        {
            G.USERPASS_COUNTER = 1;
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"userpass",G.USERPASS);
            jaddbits256(retjson,"mypubkey",G.LP_mypub25519);
            jadd(retjson,"coins",LP_coinsjson(LP_showwif));
            return(jprint(retjson,1));
        }
        if ( (userpass= jstr(argjson,"userpass")) == 0 || strcmp(userpass,G.USERPASS) != 0 )
            return(clonestr("{\"error\":\"authentication error you need to make sure userpass is set\"}"));
        jdelete(argjson,"userpass");
        if ( strcmp(method,"sendmessage") == 0 )
        {
            if ( jobj(argjson,"method2") == 0 )
            {
                LP_broadcast_message(LP_mypubsock,base!=0?base:jstr(argjson,"coin"),rel,jbits256(argjson,"pubkey"),jprint(argjson,0));
            }
            return(clonestr("{\"result\":\"success\"}"));
        }
        else if ( strcmp(method,"getmessages") == 0 )
        {
            if ( (retjson= LP_getmessages(jint(argjson,"firsti"),jint(argjson,"num"))) != 0 )
                return(jprint(retjson,1));
            else return(clonestr("{\"error\":\"null messages\"}"));
        }
        else if ( strcmp(method,"deletemessages") == 0 )
        {
            LP_deletemessages(jint(argjson,"firsti"),jint(argjson,"num"));
            return(clonestr("{\"result\":\"success\"}"));
        }
        else if ( strcmp(method,"passphrase") == 0 )
        {
            if ( LP_passphrase_init(jstr(argjson,"passphrase"),jstr(argjson,"gui")) < 0 )
                return(clonestr("{\"error\":\"couldnt change passphrase\"}"));
            {
                retjson = cJSON_CreateObject();
                jaddstr(retjson,"result","success");
                jaddstr(retjson,"userpass",G.USERPASS);
                jaddbits256(retjson,"mypubkey",G.LP_mypub25519);
                return(jprint(retjson,1));
            }
        }
        else if ( strcmp(method,"portfolio") == 0 )
        {
            return(LP_portfolio());
        }
        else if ( strcmp(method,"secretaddresses") == 0 )
        {
            uint8_t taddr,pubtype;
            pubtype = (jobj(argjson,"pubtype") == 0) ? 60 : juint(argjson,"pubtype");
            taddr = (jobj(argjson,"taddr") == 0) ? 0 : juint(argjson,"taddr");
            return(LP_secretaddresses(ctx,jstr(argjson,"prefix"),jstr(argjson,"passphrase"),juint(argjson,"num"),taddr,pubtype));
        }
        if ( base != 0 && rel != 0 )
        {
            double price,bid,ask;
            if ( IAMLP == 0 && LP_isdisabled(base,rel) != 0 )
                return(clonestr("{\"error\":\"at least one of coins disabled\"}"));
            price = jdouble(argjson,"price");
            if ( strcmp(method,"setprice") == 0 )
            {
                if ( price > SMALLVAL )
                {
                    //LP_signature_add(argjson,base,rel,(uint64_t)price * SATOSHIDEN);
                    if ( LP_mypriceset(&changed,base,rel,price) < 0 )
                        return(clonestr("{\"error\":\"couldnt set price\"}"));
                    //else if ( LP_mypriceset(&changed,rel,base,1./price) < 0 )
                    //    return(clonestr("{\"error\":\"couldnt set price\"}"));
                    else return(LP_pricepings(ctx,myipaddr,LP_mypubsock,base,rel,price * LP_profitratio));
                } else return(clonestr("{\"error\":\"no price\"}"));
            }
            else if ( strcmp(method,"autoprice") == 0 )
            {
                //LP_signature_add(argjson,base,rel,(uint64_t)price * SATOSHIDEN);
                if ( LP_autoprice(base,rel,price,jdouble(argjson,"margin"),jstr(argjson,"type")) < 0 )
                    return(clonestr("{\"error\":\"couldnt set autoprice\"}"));
                else return(clonestr("{\"result\":\"success\"}"));
            }
            else if ( strcmp(method,"pricearray") == 0 )
            {
                return(jprint(LP_pricearray(base,rel,juint(argjson,"firsttime"),juint(argjson,"lasttime"),jint(argjson,"timescale")),1));
            }
            else if ( strcmp(method,"myprice") == 0 )
            {
                if ( LP_myprice(&bid,&ask,base,rel) > SMALLVAL )
                {
                    retjson = cJSON_CreateObject();
                    jaddstr(retjson,"base",base);
                    jaddstr(retjson,"rel",rel);
                    jaddnum(retjson,"bid",bid);
                    jaddnum(retjson,"ask",ask);
                    return(jprint(retjson,1));
                } else return(clonestr("{\"error\":\"no price set\"}"));
            }
            else if ( strcmp(method,"buy") == 0 )
            {
                //*
                if ( price > SMALLVAL )
                {
                    return(LP_autobuy(ctx,myipaddr,pubsock,base,rel,price,jdouble(argjson,"relvolume"),jint(argjson,"timeout"),jint(argjson,"duration"),jstr(argjson,"gui"),juint(argjson,"nonce")));
                } else return(clonestr("{\"error\":\"no price set\"}"));
            }
            else if ( strcmp(method,"sell") == 0 )
            {
                //*
                if ( price > SMALLVAL )
                {
                    return(LP_autobuy(ctx,myipaddr,pubsock,rel,base,1./price,jdouble(argjson,"basevolume"),jint(argjson,"timeout"),jint(argjson,"duration"),jstr(argjson,"gui"),juint(argjson,"nonce")));
                } else return(clonestr("{\"error\":\"no price set\"}"));
            }
        }
        else if ( rel != 0 && strcmp(method,"bestfit") == 0 )
        {
            double relvolume;
            if ( (relvolume= jdouble(argjson,"relvolume")) > SMALLVAL )
                return(LP_bestfit(rel,relvolume));
            else return(clonestr("{\"error\":\"no relvolume set\"}"));
        }
        else if ( (coin= jstr(argjson,"coin")) != 0 )
        {
            if ( strcmp(method,"enable") == 0 )
            {
                //*
                if ( (ptr= LP_coinsearch(coin)) != 0 )
                {
                    if ( LP_conflicts_find(ptr) == 0 )
                    {
                        ptr->inactive = 0;
                        cJSON *array = cJSON_CreateArray();
                        jaddi(array,LP_coinjson(ptr,0));
                        return(jprint(array,1));
                    } else return(clonestr("{\"error\":\"coin port conflicts with existing coin\"}"));
                } else return(clonestr("{\"error\":\"couldnt find coin\"}"));
            }
            else if ( strcmp(method,"disable") == 0 )
            {
                //*
                if ( (ptr= LP_coinsearch(coin)) != 0 )
                {
                    ptr->inactive = (uint32_t)time(NULL);
                    cJSON *array = cJSON_CreateArray();
                    jaddi(array,LP_coinjson(ptr,0));
                    return(jprint(array,1));
                } else return(clonestr("{\"error\":\"couldnt find coin\"}"));
            }
            else if ( strcmp(method,"electrum") == 0 )
            {
                //*
                if ( (ptr= LP_coinsearch(coin)) != 0 )
                {
                    ptr->inactive = 0;
                    return(jprint(LP_electrumserver(ptr,jstr(argjson,"ipaddr"),juint(argjson,"port")),1));
                } else return(clonestr("{\"error\":\"cant find coind\"}"));
            }
            else if ( strcmp(method,"sendrawtransaction") == 0 )
            {
                return(LP_sendrawtransaction(coin,jstr(argjson,"signedtx")));
            }
            else if ( strcmp(method,"withdraw") == 0 )
            {
                ///*
                if ( (ptr= LP_coinsearch(coin)) != 0 )
                {
                    if ( jobj(argjson,"outputs") == 0 )
                        return(clonestr("{\"error\":\"withdraw needs to have outputs\"}"));
                    else return(LP_withdraw(ptr,argjson));
                }
                return(clonestr("{\"error\":\"cant find coind\"}"));
            }
            else if ( strcmp(method,"setconfirms") == 0 )
            {
                int32_t n;
                //*
                n = jint(argjson,"numconfirms");
                if ( n < 0 )
                    return(clonestr("{\"error\":\"illegal numconfirms\"}"));
                if ( (ptr= LP_coinsearch(coin)) != 0 )
                {
                    ptr->userconfirms = n;
                    if ( (n= jint(argjson,"maxconfirms")) > 0 )
                        ptr->maxconfirms = n;
                    if ( ptr->maxconfirms > 0 && ptr->userconfirms > ptr->maxconfirms )
                        ptr->userconfirms = ptr->maxconfirms;
                    return(clonestr("{\"result\":\"success\"}"));
                } else return(clonestr("{\"error\":\"cant find coind\"}"));
            }
            else if ( strcmp(method,"snapshot") == 0 )
            {
                if ( (ptr= LP_coinsearch(coin)) != 0 )
                    return(jprint(LP_snapshot(ptr,juint(argjson,"height")),1));
                else return(clonestr("{\"error\":\"cant find coind\"}"));
            }
            else if ( strcmp(method,"dividends") == 0 )
            {
                if ( (ptr= LP_coinsearch(coin)) != 0 )
                    return(LP_dividends(ptr,juint(argjson,"height"),argjson));
                else return(clonestr("{\"error\":\"cant find coind\"}"));
            }
            else if ( strcmp(method,"snapshot_balance") == 0 )
            {
                if ( (ptr= LP_coinsearch(coin)) != 0 )
                    return(LP_snapshot_balance(ptr,juint(argjson,"height"),argjson));
                else return(clonestr("{\"error\":\"cant find coind\"}"));
            }
            if ( LP_isdisabled(coin,0) != 0 )
                return(clonestr("{\"error\":\"coin is disabled\"}"));
            if ( strcmp(method,"inventory") == 0 )
            {
                struct iguana_info *ptr;
                if ( (ptr= LP_coinfind(coin)) != 0 )
                {
                    //privkey = LP_privkeycalc(ctx,pubkey33,&pubkey,ptr,"",USERPASS_WIFSTR);
                    //LP_utxopurge(0);
                    if ( bits256_nonz(G.LP_mypriv25519) != 0 )
                        LP_privkey_init(-1,ptr,G.LP_mypriv25519,G.LP_mypub25519);
                    else printf("no LP_mypriv25519\n");
                    retjson = cJSON_CreateObject();
                    jaddstr(retjson,"result","success");
                    jaddstr(retjson,"coin",coin);
                    jaddnum(retjson,"timestamp",time(NULL));
                    jadd(retjson,"alice",LP_inventory(coin));
                    //jadd(retjson,"bob",LP_inventory(coin,1));
                    LP_smartutxos_push(ptr);
                    return(jprint(retjson,1));
                }
            }
            else if ( strcmp(method,"goal") == 0 )
            {
                //*
                return(LP_portfolio_goal(coin,jdouble(argjson,"val")));
            }
            else if ( strcmp(method,"getcoin") == 0 )
                return(LP_getcoin(coin));
        }
        else if ( strcmp(method,"goal") == 0 )
        {
            //*
            return(LP_portfolio_goal("*",100.));
        }
        else if ( strcmp(method,"swapstatus") == 0 )
        {
            uint32_t requestid,quoteid;
            //*
            if ( (requestid= juint(argjson,"requestid")) != 0 && (quoteid= juint(argjson,"quoteid")) != 0 )
                return(basilisk_swapentry(requestid,quoteid));
            else return(basilisk_swaplist(0,0));
        }
        else if ( strcmp(method,"lastnonce") == 0 )
        {
            cJSON *retjson = cJSON_CreateObject();
            jaddstr(retjson,"result","success");
            jaddnum(retjson,"lastnonce",LP_lastnonce);
            return(jprint(retjson,1));
        }
        else if ( strcmp(method,"myprices") == 0 )
            return(LP_myprices());
        else if ( strcmp(method,"trust") == 0 )
        {
            //*
            return(LP_pubkey_trustset(jbits256(argjson,"pubkey"),jint(argjson,"trust")));
        }
        else if ( strcmp(method,"trusted") == 0 )
            return(LP_pubkey_trusted());
    }
    if ( IAMLP == 0 )
    {
        if ( (reqjson= LP_dereference(argjson,"broadcast")) != 0 )
        {
            if ( jobj(reqjson,"method2") != 0 )
            {
                jdelete(reqjson,"method");
                method = jstr(reqjson,"method2");
                jaddstr(reqjson,"method",method);
            }
            argjson = reqjson;
        }
    }
    if ( strcmp(method,"postprice") == 0 )
        retstr = LP_postedprice(argjson);
    else if ( strcmp(method,"postutxos") == 0 )
        retstr = LP_postedutxos(argjson);
    else if ( strcmp(method,"getprices") == 0 )
        return(LP_prices());
    else if ( strcmp(method,"uitem") == 0 )
    {
        bits256 txid; int32_t vout,height; uint64_t value; char *coinaddr;
        txid = jbits256(argjson,"txid");
        vout = jint(argjson,"vout");
        height = jint(argjson,"ht");
        value = j64bits(argjson,"value");
        coinaddr = jstr(argjson,"coinaddr");
        if ( coin != 0 && coinaddr != 0 )
        {
            //char str[65]; printf("uitem %s %s %s/v%d %.8f ht.%d\n",coin,coinaddr,bits256_str(str,txid),vout,dstr(value),height);
            LP_address_utxoadd(LP_coinfind(coin),coinaddr,txid,vout,value,height,-1);
        }
        return(clonestr("{\"result\":\"success\"}"));
    }
    else if ( strcmp(method,"orderbook") == 0 )
        return(LP_orderbook(base,rel,jint(argjson,"duration")));
    else if ( strcmp(method,"listunspent") == 0 )
    {
        if ( (ptr= LP_coinsearch(jstr(argjson,"coin"))) != 0 )
        {
            char *coinaddr;
            if ( (coinaddr= jstr(argjson,"address")) != 0 )
            {
                if ( coinaddr[0] != 0 )
                {
                    LP_listunspent_issue(coin,coinaddr,1);
                    if ( strcmp(coinaddr,ptr->smartaddr) == 0 && bits256_nonz(G.LP_mypriv25519) != 0 )
                    {
                        LP_privkey_init(-1,ptr,G.LP_mypriv25519,G.LP_mypub25519);
                        //LP_smartutxos_push(ptr);
                    }
                    else
                    {
                        
                    }
                }
                return(jprint(LP_address_utxos(ptr,coinaddr,1),1));
            } else return(clonestr("{\"error\":\"no address specified\"}"));
        } else return(clonestr("{\"error\":\"cant find coind\"}"));
    }
    else if ( strcmp(method,"balance") == 0 )
    {
        if ( (ptr= LP_coinsearch(jstr(argjson,"coin"))) != 0 )
            return(jprint(LP_address_balance(ptr,jstr(argjson,"address"),1),1));
        else return(clonestr("{\"error\":\"cant find coind\"}"));
    }
    else if ( strcmp(method,"checktxid") == 0 )
        retstr = LP_spentcheck(argjson);
    else if ( strcmp(method,"addr_unspents") == 0 )
    {
        //printf("GOT ADDR_UNSPENTS\n");
        if ( (ptr= LP_coinsearch(jstr(argjson,"coin"))) != 0 )
        {
            char *coinaddr; //cJSON *array,*item,*req; int32_t i,n,vout,height; bits256 zero,txid; uint64_t value;
            if ( (coinaddr= jstr(argjson,"address")) != 0 )
            {
                if ( coinaddr[0] != 0 )
                {
                    if ( strcmp(coinaddr,ptr->smartaddr) == 0 && bits256_nonz(G.LP_mypriv25519) != 0 )
                    {
                        //printf("%s %s is my address being asked for!\n",ptr->symbol,coinaddr);
                        ptr->addr_listunspent_requested = (uint32_t)time(NULL);
                    }
                }
            }
        }
        retstr = clonestr("{\"result\":\"success\"}");
    }
    //else if ( IAMLP == 0 && LP_isdisabled(base,rel) != 0 )
    //    return(clonestr("{\"result\":\"at least one of coins disabled\"}"));
    //else if ( IAMLP == 0 && LP_isdisabled(jstr(argjson,"coin"),0) != 0 )
    //    retstr = clonestr("{\"result\":\"coin is disabled\"}");
    else if ( strcmp(method,"getcoins") == 0 )
        return(jprint(LP_coinsjson(0),1));
    else if ( strcmp(method,"encrypted") == 0 )
        retstr = clonestr("{\"result\":\"success\"}");
    else if ( strcmp(method,"getpeers") == 0 )
        return(LP_peers());
    else
    {
        if ( base != 0 && rel != 0 && strcmp(method,"pricearray") == 0 )
        {
            uint32_t firsttime;
            if ( (firsttime= juint(argjson,"firsttime")) < time(NULL)-30*24*3600 )
                firsttime = (uint32_t)(time(NULL)-30*24*3600);
            return(jprint(LP_pricearray(base,rel,firsttime,juint(argjson,"lasttime"),jint(argjson,"timescale")),1));
        }
        else if ( strcmp(method,"notify") == 0 )
        {
            char *rmd160str,*secpstr; bits256 pub; struct LP_pubkeyinfo *pubp;
            pub = jbits256(argjson,"pub");
            if ( bits256_nonz(pub) != 0 && (rmd160str= jstr(argjson,"rmd160")) != 0 && strlen(rmd160str) == 40 )
            {
                if ( (pubp= LP_pubkeyadd(pub)) != 0 )
                {
                    decode_hex(pubp->rmd160,20,rmd160str);
                    if ( (secpstr= jstr(argjson,"pubsecp")) != 0 )
                    {
                        decode_hex(pubp->pubsecp,sizeof(pubp->pubsecp),secpstr);
                        //printf("got pubkey.(%s)\n",secpstr);
                    }
                }
                //printf("NOTIFIED pub %s rmd160 %s\n",bits256_str(str,pub),rmd160str);
            }
            retstr = clonestr("{\"result\":\"success\",\"notify\":\"received\"}");
        }
        if ( IAMLP != 0 )
        {
            if ( strcmp(method,"broadcast") == 0 )
            {
                bits256 zero; char *cipherstr; int32_t cipherlen; uint8_t cipher[LP_ENCRYPTED_MAXSIZE];
                if ( (reqjson= LP_dereference(argjson,"broadcast")) != 0 )
                {
                    Broadcaststr = jprint(reqjson,0);
                    if ( (cipherstr= jstr(reqjson,"cipher")) != 0 )
                    {
                        cipherlen = (int32_t)strlen(cipherstr) >> 1;
                        if ( cipherlen <= sizeof(cipher) )
                        {
                            decode_hex(cipher,cipherlen,cipherstr);
                            LP_queuesend(calc_crc32(0,&cipher[2],cipherlen-2),LP_mypubsock,base,rel,cipher,cipherlen);
                        } else retstr = clonestr("{\"error\":\"cipher too big\"}");
                    }
                    else
                    {
                        memset(zero.bytes,0,sizeof(zero));
                        //printf("broadcast.(%s)\n",msg);
                        LP_reserved_msg(base!=0?base:jstr(argjson,"coin"),rel,zero,jprint(reqjson,0));
                    }
                    retstr = clonestr("{\"result\":\"success\"}");
                } else retstr = clonestr("{\"error\":\"couldnt dereference sendmessage\"}");
            }
            else if ( strcmp(method,"psock") == 0 )
            {
                if ( myipaddr == 0 || myipaddr[0] == 0 || strcmp(myipaddr,"127.0.0.1") == 0 )
                {
                    if ( LP_mypeer != 0 )
                        myipaddr = LP_mypeer->ipaddr;
                    else printf("LP_psock dont have actual ipaddr?\n");
                }
                if ( jint(argjson,"ispaired") != 0 )
                    return(LP_psock(myipaddr,jint(argjson,"ispaired")));
                else return(clonestr("{\"error\":\"you are running an obsolete version, update\"}"));
            }
        }
        else
        {
            if ( strcmp(method,"psock") == 0 )
            {
                //printf("nonLP got (%s)\n",jprint(argjson,0));
                retstr = clonestr("{\"result\":\"success\"}");
            }
        }
    }
    if ( retstr == 0 )
        printf("ERROR.(%s)\n",jprint(argjson,0));
    if ( reqjson != 0 )
        free_json(reqjson);
    if ( retstr != 0 )
    {
        free(retstr);
        return(0);
    }
    return(0);
}
