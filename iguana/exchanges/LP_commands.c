
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

double LP_query(char *method,struct LP_quoteinfo *qp,char *base,char *rel,bits256 mypub)
{
    cJSON *reqjson; int32_t i,flag = 0; double price = 0.; struct LP_utxoinfo *utxo;
    qp->desthash = mypub;
    strcpy(qp->srccoin,base);
    strcpy(qp->destcoin,rel);
    if ( strcmp(method,"request") == 0 )
    {
        qp->quotetime = (uint32_t)time(NULL);
        if ( (utxo= LP_utxofind(0,qp->desttxid,qp->destvout)) != 0 && LP_ismine(utxo) > 0 && LP_isavailable(utxo) > 0 )
            LP_unavailableset(utxo,qp->srchash);
        else
        {
            printf("couldnt find my txid to make request\n");
            return(0.);
        }
    }
    reqjson = LP_quotejson(qp);
    if ( bits256_nonz(qp->desthash) != 0 )
        flag = 1;
    jaddstr(reqjson,"method",method);
    if ( strcmp(method,"price") != 0 )
        printf("QUERY.(%s)\n",jprint(reqjson,0));
    LP_forward(qp->srchash,jprint(reqjson,1),1);
    for (i=0; i<30; i++)
    {
        if ( (price= LP_pricecache(qp,base,rel,qp->txid,qp->vout)) != 0. )
        {
            if ( flag == 0 || bits256_nonz(qp->desthash) != 0 )
            {
                //printf("break out of loop.%d price %.8f\n",i,price);
                break;
            }
        }
        usleep(100000);
    }
    return(price);
}

int32_t LP_connectstart(int32_t pubsock,struct LP_utxoinfo *utxo,cJSON *argjson,char *myipaddr,char *base,char *rel,double profitmargin)
{
    char *retstr,pairstr[512]; cJSON *retjson; double price; bits256 privkey; int32_t pair=-1,retval = -1,DEXselector = 0; uint64_t destvalue; struct LP_quoteinfo Q; struct basilisk_swap *swap;
    if ( (price= LP_price(base,rel)) != 0. )
    {
        price *= (1. + profitmargin);
        if ( LP_quoteinfoinit(&Q,utxo,rel,price) < 0 )
            return(-1);
        if ( LP_quoteparse(&Q,argjson) < 0 )
            return(-2);
        //printf("connect with.(%s)\n",jprint(argjson,0));
        Q.destsatoshis = Q.satoshis * price;
        privkey = LP_privkey(utxo->coinaddr);
        if ( bits256_nonz(utxo->S.mypub) == 0 )
            utxo->S.mypub = LP_pubkey(privkey);
        if ( LP_iseligible(1,Q.srccoin,Q.txid,Q.vout,Q.satoshis,Q.txid2,Q.vout2) == 0 )
        {
            printf("not eligible\n");
            return(-1);
        }
        if ( bits256_nonz(privkey) != 0 && Q.quotetime >= Q.timestamp-3 && Q.quotetime < utxo->T.swappending && bits256_cmp(utxo->S.mypub,Q.srchash) == 0 && (destvalue= LP_txvalue(rel,Q.desttxid,Q.destvout)) >= price*Q.satoshis+Q.desttxfee && destvalue >= Q.destsatoshis+Q.desttxfee )
        {
            nanomsg_tcpname(pairstr,myipaddr,10000+(rand() % 10000));
            if ( (pair= nn_socket(AF_SP,NN_PAIR)) < 0 )
                printf("error creating utxo->pair\n");
            else if ( nn_bind(pair,pairstr) >= 0 )
            {
                LP_requestinit(&Q.R,Q.srchash,Q.desthash,base,Q.satoshis,rel,Q.destsatoshis,Q.timestamp,Q.quotetime,DEXselector);
                swap = LP_swapinit(1,0,privkey,&Q.R,&Q);
                swap->N.pair = pair;
                utxo->S.swap = swap;
                swap->utxo = utxo;
                if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_bobloop,(void *)swap) == 0 )
                {
                    retjson = LP_quotejson(&Q);
                    jaddstr(retjson,"method","connected");
                    jaddstr(retjson,"pair",pairstr);
                    jaddnum(retjson,"requestid",Q.R.requestid);
                    jaddnum(retjson,"quoteid",Q.R.quoteid);
                    retstr = jprint(retjson,1);
                    if ( pubsock >= 0 )
                        LP_send(pubsock,retstr,1);
                    else LP_forward(utxo->S.otherpubkey,retstr,1);
                    retval = 0;
                } else printf("error launching swaploop\n");
            } else printf("printf error nn_connect to %s\n",pairstr);
        }
        else
        {
            printf("dest %.8f < required %.8f (%d %d %d %d %d %d) %.8f %.8f\n",dstr(Q.satoshis),dstr(price*(utxo->S.satoshis-Q.txfee)),bits256_nonz(privkey) != 0 ,Q.timestamp == utxo->T.swappending-LP_RESERVETIME ,Q.quotetime >= Q.timestamp ,Q.quotetime < utxo->T.swappending ,bits256_cmp(utxo->S.mypub,Q.srchash) == 0 ,   LP_txvalue(rel,Q.desttxid,Q.destvout) >= price*Q.satoshis+Q.desttxfee,dstr(LP_txvalue(rel,Q.desttxid,Q.destvout)),dstr(price*Q.satoshis+Q.desttxfee));
        }
    } else printf("no price for %s/%s\n",base,rel);
    if ( retval < 0 )
    {
        if ( pair >= 0 )
            nn_close(pair);
        LP_availableset(utxo);
    }
    return(retval);
}

char *LP_connected(cJSON *argjson) // alice
{
    cJSON *retjson; bits256 spendtxid; int32_t spendvini,selector,pairsock = -1; char *pairstr; int32_t DEXselector = 0; struct LP_utxoinfo *utxo; struct LP_quoteinfo Q; struct basilisk_swap *swap;
    LP_quoteparse(&Q,argjson);
    if ( IAMLP == 0 && bits256_cmp(Q.desthash,LP_mypubkey) == 0 && (utxo= LP_utxofind(0,Q.desttxid,Q.destvout)) != 0 && LP_ismine(utxo) > 0 && LP_isavailable(utxo) > 0 )
    {
        if ( (selector= LP_mempool_vinscan(&spendtxid,&spendvini,Q.srccoin,Q.txid,Q.vout,Q.txid2,Q.vout2)) >= 0 )
        {
            char str[65]; printf("LP_connected src selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
            return(clonestr("{\"error\",\"src txid in mempool\"}"));
        }
        if ( (selector= LP_mempool_vinscan(&spendtxid,&spendvini,Q.srccoin,Q.txid,Q.vout,Q.txid2,Q.vout2)) >= 0 )
        {
            char str[65]; printf("LP_connected src selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
            return(clonestr("{\"error\",\"dest txid in mempool\"}"));
        }
        retjson = cJSON_CreateObject();
        if ( (pairstr= jstr(argjson,"pair")) == 0 || (pairsock= nn_socket(AF_SP,NN_PAIR)) < 0 )
            jaddstr(retjson,"error","couldnt create pairsock");
        else if ( nn_connect(pairsock,pairstr) >= 0 )
        {
            LP_unavailableset(utxo,Q.srchash);
            Q.privkey = LP_privkey(Q.destaddr);
            LP_requestinit(&Q.R,Q.srchash,Q.desthash,Q.srccoin,Q.satoshis,Q.destcoin,Q.destsatoshis,Q.timestamp,Q.quotetime,DEXselector);
            swap = LP_swapinit(0,0,Q.privkey,&Q.R,&Q);
            swap->N.pair = pairsock;
            utxo->S.swap = swap;
            swap->utxo = utxo;
            printf("alice pairstr.(%s)\n",pairstr);
            if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_aliceloop,(void *)swap) == 0 )
            {
                jaddstr(retjson,"result","success");
                jadd(retjson,"trade",LP_quotejson(&Q));
                jaddnum(retjson,"requestid",Q.R.requestid);
                jaddnum(retjson,"quoteid",Q.R.quoteid);
            } else jaddstr(retjson,"error","couldnt aliceloop");
        }
        return(jprint(retjson,1));
    } else return(clonestr("{\"result\",\"update stats\"}"));
}

int32_t LP_tradecommand(char *myipaddr,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen,double profitmargin)
{
    char *method,*base,*rel,*retstr; cJSON *retjson; double price; bits256 txid,spendtxid; struct LP_utxoinfo *utxo; int32_t selector,spendvini,retval = -1; struct LP_quoteinfo Q;
    if ( (method= jstr(argjson,"method")) != 0 )
    {
        txid = jbits256(argjson,"txid");
        if ( (utxo= LP_utxofind(1,txid,jint(argjson,"vout"))) != 0 && LP_ismine(utxo) > 0 && (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 && strcmp(base,utxo->coin) == 0 )
        {
            printf("LP_tradecommand.(%s)\n",jprint(argjson,0));
            if ( (selector= LP_mempool_vinscan(&spendtxid,&spendvini,utxo->coin,utxo->payment.txid,utxo->payment.vout,utxo->deposit.txid,utxo->deposit.vout)) >= 0 )
            {
                char str[65]; printf("LP_tradecommand selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
                utxo->T.spentflag = (uint32_t)time(NULL);
                return(0);
            }
            if ( utxo->S.swap == 0 && time(NULL) > utxo->T.swappending )
                utxo->T.swappending = 0;
            if ( strcmp(method,"price") == 0 || strcmp(method,"request") == 0 ) // bob
            {
                retval = 1;
                if ( LP_isavailable(utxo) > 0 )
                {
                    if ( (price= LP_price(base,rel)) != 0. )
                    {
                        price *= (1. + profitmargin);
                        if ( LP_quoteinfoinit(&Q,utxo,rel,price) < 0 )
                            return(-1);
                        if ( LP_iseligible(1,Q.srccoin,Q.txid,Q.vout,Q.satoshis,Q.txid2,Q.vout2) == 0 )
                        {
                            printf("not eligible\n");
                            return(-1);
                        }
                        if ( strcmp(method,"price") == 0 )
                            Q.timestamp = (uint32_t)time(NULL);
                        retjson = LP_quotejson(&Q);
                        utxo->S.otherpubkey = jbits256(argjson,"desthash");
                        if ( strcmp(method,"request") == 0 )
                        {
                            retval |= 2;
                            LP_unavailableset(utxo,jbits256(argjson,"desthash"));
                            jaddnum(retjson,"quotetime",juint(argjson,"quotetime"));
                            jaddnum(retjson,"pending",utxo->T.swappending);
                            jaddbits256(retjson,"desthash",utxo->S.otherpubkey);
                            jaddstr(retjson,"method","reserved");
                        }
                        else jaddstr(retjson,"method","quote");
                        retstr = jprint(retjson,1);
                        if ( pubsock >= 0 )
                            LP_send(pubsock,retstr,1);
                        else LP_forward(utxo->S.otherpubkey,retstr,1);
                        utxo->T.published = (uint32_t)time(NULL);
                    } else printf("null price\n");
                } else printf("swappending.%u swap.%p\n",utxo->T.swappending,utxo->S.swap);
            }
            else if ( strcmp(method,"connect") == 0 ) // bob
            {
                retval = 4;
                if ( (selector= LP_mempool_vinscan(&spendtxid,&spendvini,jstr(argjson,"destcoin"),jbits256(argjson,"desttxid"),jint(argjson,"destvout"),jbits256(argjson,"feetxid"),jint(argjson,"feevout"))) >= 0 )
                {
                    char str[65]; printf("LP_tradecommand fee selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
                    return(0);
                }
                if ( utxo->T.swappending != 0 && utxo->S.swap == 0 )
                    LP_connectstart(pubsock,utxo,argjson,myipaddr,base,rel,profitmargin);
                else printf("swap %p when connect came in (%s)\n",utxo->S.swap,jprint(argjson,0));
            }
        }
    }
    return(retval);
}

char *stats_JSON(cJSON *argjson,char *remoteaddr,uint16_t port) // from rpc port
{
    char *method,*ipaddr,*userpass,*base,*rel,*coin,*retstr = 0; uint16_t argport,pushport,subport; int32_t otherpeers,othernumutxos; struct LP_utxoinfo *utxo,*tmp; struct LP_peerinfo *peer; cJSON *retjson; struct iguana_info *ptr;
    if ( (method= jstr(argjson,"method")) == 0 )
        return(clonestr("{\"error\":\"need method in request\"}"));
    else if ( strcmp(method,"help") == 0 )
        return(clonestr("{\"result\":\" \
available localhost RPC commands:\n \
setprice(base, rel, price)\n\
myprice(base, rel)\n\
enable(coin)\n\
disable(coin)\n\
inventory(coin)\n\
candidates(txid, vout)\n\
autotrade(txid, vout, maxprice)\n\
swapstatus()\n\
swapstatus(requestid, quoteid)\n\
public API:\n \
getcoins()\n\
getpeers()\n\
getutxos()\n\
getutxos(coin, lastn)\n\
orderbook(base, rel)\n\
getprice(base, rel)\n\
register(pubkey,pushaddr)\n\
lookup(pubkey)\n\
forward(pubkey,hexstr)\n\
\"}"));
    //printf("CMD.(%s)\n",jprint(argjson,0));
    if ( USERPASS[0] != 0 && strcmp(remoteaddr,"127.0.0.1") == 0 && port != 0 )
    {
        if ( USERPASS_COUNTER == 0 )
        {
            USERPASS_COUNTER = 1;
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"userpass",USERPASS);
            jadd(retjson,"coins",LP_coinsjson());
            return(jprint(retjson,1));
        }
        if ( (userpass= jstr(argjson,"userpass")) == 0 || strcmp(userpass,USERPASS) != 0 )
            return(clonestr("{\"error\":\"authentication error\"}"));
        if ( (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 )
        {
            //char str[65];
            if ( LP_isdisabled(base,rel) != 0 )
                return(clonestr("{\"error\":\"at least one of coins disabled\"}"));
            if ( strcmp(method,"setprice") == 0 )
            {
                if ( LP_mypriceset(base,rel,jdouble(argjson,"price")) < 0 )
                    return(clonestr("{\"error\":\"couldnt set price\"}"));
                else
                {
                    if ( IAMLP != 0 )
                    {
                        HASH_ITER(hh,LP_utxoinfos[1],utxo,tmp)
                        {
                            if ( LP_ismine(utxo) > 0 && strcmp(utxo->coin,base) == 0 )//|| strcmp(utxo->coin,rel) == 0) )
                                LP_priceping(LP_mypubsock,utxo,rel,LP_profitratio - 1.);
                            //else printf("notmine.(%s %s)\n",utxo->coin,bits256_str(str,utxo->txid));
                        }
                    }
                    return(clonestr("{\"result\":\"success\"}"));
                }
            }
            else if ( strcmp(method,"myprice") == 0 )
            {
                double bid,ask;
                if ( LP_myprice(&bid,&ask,base,rel) != 0. )
                {
                    retjson = cJSON_CreateObject();
                    jaddstr(retjson,"base",base);
                    jaddstr(retjson,"rel",rel);
                    jaddnum(retjson,"bid",bid);
                    jaddnum(retjson,"ask",ask);
                    return(jprint(retjson,1));
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
                    privkey = LP_privkeycalc(pubkey33,&pubkey,ptr,"",USERPASS_WIFSTR);
                    //LP_utxopurge(0);
                    LP_privkey_init(-1,ptr,privkey,pubkey,pubkey33);
                    retjson = cJSON_CreateObject();
                    jaddstr(retjson,"result","success");
                    jadd(retjson,"alice",LP_inventory(coin,0));
                    jadd(retjson,"bob",LP_inventory(coin,1));
                    return(jprint(retjson,1));
                }
            }
            else if ( (strcmp(method,"candidates") == 0 || strcmp(method,"autotrade") == 0) )
            {
                bits256 txid; int32_t vout; struct LP_utxoinfo *utxo;
                txid = jbits256(argjson,"txid");
                if ( bits256_nonz(txid) == 0 )
                    return(clonestr("{\"error\":\"invalid or missing txid\"}"));
                if ( jobj(argjson,"vout") == 0 )
                    return(clonestr("{\"error\":\"missing vout\"}"));
                vout = jint(argjson,"vout");
                if ( (utxo= LP_utxofind(0,txid,vout)) == 0 )
                    return(clonestr("{\"error\":\"txid/vout not found\"}"));
                if ( strcmp(method,"candidates") == 0 )
                    return(jprint(LP_tradecandidates(coin),1));
                else return(jprint(LP_autotrade(utxo,coin,jdouble(argjson,"maxprice")),1));
            }
        }
        else if ( strcmp(method,"swapstatus") == 0 )
        {
            uint32_t requestid,quoteid;
            if ( (requestid= juint(argjson,"requestid")) != 0 && (quoteid= juint(argjson,"quoteid")) != 0 )
                return(basilisk_swapentry(requestid,quoteid));
            else return(basilisk_swaplist());
        }
    }
    if ( LP_isdisabled(jstr(argjson,"base"),jstr(argjson,"base")) != 0 )
        return(clonestr("{\"error\":\"at least one of coins disabled\"}"));
    if ( LP_isdisabled(jstr(argjson,"coin"),0) != 0 )
        return(clonestr("{\"error\":\"coin is disabled\"}"));
    if ( (ipaddr= jstr(argjson,"ipaddr")) != 0 && (argport= juint(argjson,"port")) != 0 )
    {
        if ( strcmp(ipaddr,"127.0.0.1") != 0 && port >= 1000 )
        {
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
    if ( strcmp(method,"quote") == 0 || strcmp(method,"reserved") == 0 )
        retstr = LP_quotereceived(argjson);
    else if ( strcmp(method,"connected") == 0 )
        retstr = LP_connected(argjson);
    else if ( strcmp(method,"checktxid") == 0 )
        retstr = LP_spentcheck(argjson);
    else if ( strcmp(method,"getcoins") == 0 )
        retstr = jprint(LP_coinsjson(),1);
    else if ( strcmp(method,"getprice") == 0 )
        retstr = LP_pricestr(jstr(argjson,"base"),jstr(argjson,"rel"));
    else if ( strcmp(method,"orderbook") == 0 )
        retstr = LP_orderbook(jstr(argjson,"base"),jstr(argjson,"rel"));
    else if ( strcmp(method,"forward") == 0 )
    {
        cJSON *reqjson = jduplicate(argjson);
        printf("FORWARDED.(%s)\n",jprint(argjson,0));
        jdelete(reqjson,"method");
        if ( jstr(reqjson,"method2") != 0 && strncmp("forward",jstr(reqjson,"method2"),strlen("forward")) != 0 )
        {
            jaddstr(reqjson,"method",jstr(argjson,"method2"));
            if ( LP_forward(jbits256(argjson,"pubkey"),jprint(reqjson,1),1) > 0 )
                retstr = clonestr("{\"result\":\"success\"}");
            else retstr = clonestr("{\"error\":\"error forwarding\"}");
        } else retstr = clonestr("{\"error\":\"cant recurse forwards\"}");
    }
    else if ( strcmp(method,"getpeers") == 0 )
        retstr = LP_peers();
    else if ( IAMLP != 0 )
    {
        if ( strcmp(method,"getutxos") == 0 )
        {
            retstr = LP_utxos(1,LP_mypeer,jstr(argjson,"coin"),jint(argjson,"lastn"));
            //printf("RETURN. %d utxos\n",cJSON_GetArraySize(cJSON_Parse(retstr)));
        }
        else if ( strcmp(method,"register") == 0 )
            retstr = LP_register(jbits256(argjson,"pubkey"),jstr(argjson,"pushaddr"));
        else if ( strcmp(method,"lookup") == 0 )
            retstr = LP_lookup(jbits256(argjson,"pubkey"));
        else if ( strcmp(method,"forwardhex") == 0 )
            retstr = LP_forwardhex(jbits256(argjson,"pubkey"),jstr(argjson,"hexstr"));
        else if ( strcmp(method,"notify") == 0 )
            retstr = clonestr("{\"result\":\"success\",\"notify\":\"received\"}");
        else if ( strcmp(method,"notified") == 0 )
        {
            if ( juint(argjson,"timestamp") > time(NULL)-60 )
            {
                printf("utxonotify.(%s)\n",jprint(argjson,0));
                LP_addutxo(1,LP_mypubsock,jstr(argjson,"coin"),jbits256(argjson,"txid"),jint(argjson,"vout"),j64bits(argjson,"valuesats"),jbits256(argjson,"txid2"),jint(argjson,"vout2"),j64bits(argjson,"valuesats2"),jstr(argjson,"script"),jstr(argjson,"address"),jbits256(argjson,"pubkey"),jdouble(argjson,"profit"));
            }
            retstr = clonestr("{\"result\":\"success\",\"notifyutxo\":\"received\"}");
        }
    }
    if ( retstr != 0 )
        return(retstr);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"error","unrecognized command");
    printf("ERROR.(%s)\n",jprint(argjson,0));
    return(clonestr(jprint(retjson,1)));
}
