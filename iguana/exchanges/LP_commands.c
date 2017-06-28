
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


char *stats_JSON(void *ctx,char *myipaddr,int32_t pubsock,double profitmargin,cJSON *argjson,char *remoteaddr,uint16_t port) // from rpc port
{
    char *method,*ipaddr,*userpass,*base,*rel,*coin,*retstr = 0; uint16_t argport=0,pushport,subport; int32_t otherpeers,othernumutxos,flag = 0; struct LP_peerinfo *peer; cJSON *retjson; struct iguana_info *ptr;
    if ( (ipaddr= jstr(argjson,"ipaddr")) != 0 && (argport= juint(argjson,"port")) != 0 )
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
                if ( 0 && (othernumutxos= jint(argjson,"numutxos")) > peer->numutxos )
                {
                    printf("change.(%s) numutxos.%d -> %d mynumutxos.%d\n",peer->ipaddr,peer->numutxos,othernumutxos,LP_mypeer != 0 ? LP_mypeer->numutxos:0);
                    peer->numutxos = othernumutxos;
                }
                //printf("peer.(%s) found (%d %d) (%d %d) (%s)\n",peer->ipaddr,peer->numpeers,peer->numutxos,otherpeers,othernumutxos,jprint(argjson,0));
            } else LP_addpeer(LP_mypeer,LP_mypubsock,ipaddr,argport,pushport,subport,jdouble(argjson,"profit"),jint(argjson,"numpeers"),jint(argjson,"numutxos"));
        }
    }
    if ( (method= jstr(argjson,"method")) == 0 )
    {
        if ( flag == 0 || jobj(argjson,"result") != 0 )
            printf("stats_JSON no method: (%s) (%s:%u)\n",jprint(argjson,0),ipaddr,argport);
        return(0);
    }
    if ( strcmp(method,"hello") == 0 )
    {
        //printf("got hello from %s:%u\n",ipaddr!=0?ipaddr:"",argport);
        return(0);
    }
    else if ( strcmp(method,"nn_tests") == 0 )
        return(clonestr("{\"result\":\"success\"}"));
    else if ( strcmp(method,"help") == 0 )
        return(clonestr("{\"result\":\" \
available localhost RPC commands:\n \
setprice(base, rel, price)\n\
myprice(base, rel)\n\
enable(coin)\n\
disable(coin)\n\
inventory(coin)\n\
autotrade(base, rel, price, volume, timeout)\n\
swapstatus()\n\
swapstatus(requestid, quoteid)\n\
public API:\n \
getcoins()\n\
getpeers()\n\
getutxos()\n\
getutxos(coin, lastn)\n\
orderbook(base, rel)\n\
getprices(base, rel)\n\
trust(pubkey, trust)\n\
register(pubkey,pushaddr)\n\
registerall(numnodes)\n\
lookup(pubkey)\n\
forward(pubkey,method2,<argjson>)\n\
forward(pubkey,method2=publish,<argjson>)\n\
forwardhex(pubkey,hex)\n\
\"}"));
    base = jstr(argjson,"base");
    rel = jstr(argjson,"rel");
    if ( USERPASS[0] != 0 && strcmp(remoteaddr,"127.0.0.1") == 0 && port != 0 )
    {
        if ( USERPASS_COUNTER == 0 )
        {
            USERPASS_COUNTER = 1;
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"userpass",USERPASS);
            jaddbits256(retjson,"mypubkey",LP_mypubkey);
            jadd(retjson,"coins",LP_coinsjson());
            return(jprint(retjson,1));
        }
        if ( (userpass= jstr(argjson,"userpass")) == 0 || strcmp(userpass,USERPASS) != 0 )
            return(clonestr("{\"error\":\"authentication error\"}"));
        if ( base != 0 && rel != 0 )
        {
            double price;
            if ( LP_isdisabled(base,rel) != 0 )
                return(clonestr("{\"error\":\"at least one of coins disabled\"}"));
            price = jdouble(argjson,"price");
            if ( strcmp(method,"setprice") == 0 )
            {
                if ( price > SMALLVAL )
                {
                    if ( LP_mypriceset(base,rel,price) < 0 )
                        return(clonestr("{\"error\":\"couldnt set price\"}"));
                    else return(LP_pricepings(ctx,myipaddr,LP_mypubsock,profitmargin,base,rel,price * LP_profitratio));
                } else return(clonestr("{\"error\":\"no price\"}"));
            }
            else if ( strcmp(method,"myprice") == 0 )
            {
                double bid,ask;
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
            else if ( strcmp(method,"autotrade") == 0 )
            {
                if ( price > SMALLVAL )
                {
                    printf("price set (%s/%s) <- %.8f\n",rel,base,1./price);
                    LP_mypriceset(rel,base,1./price);
                    return(LP_autotrade(ctx,myipaddr,pubsock,profitmargin,base,rel,price,jdouble(argjson,"volume"),jint(argjson,"timeout")));
                } else return(clonestr("{\"error\":\"no price set\"}"));
            }
        }
        else if ( (coin= jstr(argjson,"coin")) != 0 )
        {
            if ( strcmp(method,"enable") == 0 )
            {
                if ( (ptr= LP_coinsearch(coin)) != 0 )
                    ptr->inactive = 0;
                return(jprint(LP_coinsjson(),1));
            }
            else if ( strcmp(method,"disable") == 0 )
            {
                if ( (ptr= LP_coinsearch(coin)) != 0 )
                    ptr->inactive = (uint32_t)time(NULL);
                return(jprint(LP_coinsjson(),1));
            }
            if ( LP_isdisabled(coin,0) != 0 )
                return(clonestr("{\"error\":\"coin is disabled\"}"));
            if ( strcmp(method,"inventory") == 0 )
            {
                struct iguana_info *ptr; bits256 privkey,pubkey; uint8_t pubkey33[33];
                if ( (ptr= LP_coinfind(coin)) != 0 )
                {
                    privkey = LP_privkeycalc(ctx,pubkey33,&pubkey,ptr,"",USERPASS_WIFSTR);
                    //LP_utxopurge(0);
                    LP_privkey_init(-1,ptr,privkey,pubkey,pubkey33);
                    retjson = cJSON_CreateObject();
                    jaddstr(retjson,"result","success");
                    jadd(retjson,"alice",LP_inventory(coin,0));
                    jadd(retjson,"bob",LP_inventory(coin,1));
                    return(jprint(retjson,1));
                }
            }
        }
        else if ( strcmp(method,"swapstatus") == 0 )
        {
            uint32_t requestid,quoteid;
            if ( (requestid= juint(argjson,"requestid")) != 0 && (quoteid= juint(argjson,"quoteid")) != 0 )
                return(basilisk_swapentry(requestid,quoteid));
            else return(basilisk_swaplist());
        }
        else if ( strcmp(method,"myprices") == 0 )
            return(LP_myprices());
        else if ( strcmp(method,"trust") == 0 )
            return(LP_pubkey_trustset(jbits256(argjson,"pubkey"),jint(argjson,"trust")));
    }
    if ( LP_isdisabled(base,rel) != 0 )
        retstr = clonestr("{\"error\":\"at least one of coins disabled\"}");
    else if ( LP_isdisabled(jstr(argjson,"coin"),0) != 0 )
        retstr = clonestr("{\"error\":\"coin is disabled\"}");
    else if ( strcmp(method,"reserved") == 0 )
        retstr = LP_quotereceived(argjson);
    else if ( strcmp(method,"connected") == 0 )
        retstr = LP_connectedalice(argjson);
    else if ( strcmp(method,"checktxid") == 0 )
        retstr = LP_spentcheck(argjson);
    else if ( strcmp(method,"getcoins") == 0 )
        return(jprint(LP_coinsjson(),1));
    else if ( strcmp(method,"postprice") == 0 )
        retstr = LP_postedprice(argjson);
    else if ( strcmp(method,"broadcast") == 0 )
        retstr = LP_broadcasted(argjson);
    else if ( strcmp(method,"getprices") == 0 )
        return(LP_prices());
    else if ( strcmp(method,"orderbook") == 0 )
       return(LP_orderbook(base,rel));
    else if ( strcmp(method,"registerall") == 0 )
        return(LP_registerall(jint(argjson,"numnodes")));
    else if ( strcmp(method,"forward") == 0 )
    {
        cJSON *reqjson;
        if ( (reqjson= LP_dereference(argjson,"forward")) != 0 )
        {
            //printf("FORWARDED.(%s)\n",jprint(argjson,0));
            if ( LP_forward(ctx,myipaddr,pubsock,profitmargin,jbits256(argjson,"pubkey"),jprint(reqjson,1),1) > 0 )
                retstr = clonestr("{\"result\":\"success\"}");
            else retstr = clonestr("{\"error\":\"error forwarding\"}");
        } else retstr = clonestr("{\"error\":\"cant recurse forwards\"}");

    }
    else if ( strcmp(method,"keepalive") == 0 )
    {
        printf("got keepalive lag.%d switch.%u\n",(int32_t)time(NULL) - LP_deadman_switch,LP_deadman_switch);
        LP_deadman_switch = (uint32_t)time(NULL);
        return(clonestr("{\"result\":\"success\"}"));
    }
    else if ( strcmp(method,"getpeers") == 0 )
        return(LP_peers());
    else if ( strcmp(method,"getutxos") == 0 )
        return(LP_utxos(1,LP_mypeer,jstr(argjson,"coin"),jint(argjson,"lastn")));
    else if ( strcmp(method,"notified") == 0 )
    {
        if ( LP_utxoaddjson(1,LP_mypubsock,argjson) != 0 )
            return(clonestr("{\"result\":\"success\",\"notifyutxo\":\"received\"}"));
        else return(clonestr("{\"error\":\"couldnt add utxo\"}"));
    }
    else if ( IAMLP != 0 )
    {
        if ( strcmp(method,"register") == 0 )
        {
            retstr = LP_register(jbits256(argjson,"client"),jstr(argjson,"pushaddr"),juint(argjson,"pushport"));
            //printf("got (%s) from register\n",retstr!=0?retstr:"");
            return(retstr);
        }
        else if ( strcmp(method,"lookup") == 0 )
            return(LP_lookup(jbits256(argjson,"client")));
        else if ( strcmp(method,"forwardhex") == 0 )
            retstr = LP_forwardhex(ctx,pubsock,jbits256(argjson,"pubkey"),jstr(argjson,"hex"));
        else if ( strcmp(method,"psock") == 0 )
        {
            if ( myipaddr == 0 || myipaddr[0] == 0 || strcmp(myipaddr,"127.0.0.1") == 0 )
            {
                if ( LP_mypeer != 0 )
                    myipaddr = LP_mypeer->ipaddr;
                else printf("LP_psock dont have actual ipaddr?\n");
            }
            return(LP_psock(myipaddr,jint(argjson,"ispaired")));
        }
        else if ( strcmp(method,"notify") == 0 )
            retstr = clonestr("{\"result\":\"success\",\"notify\":\"received\"}");
    }
    if ( retstr != 0 )
    {
        free(retstr);
        return(0);
    }
    printf("ERROR.(%s)\n",jprint(argjson,0));
    return(0);
}
