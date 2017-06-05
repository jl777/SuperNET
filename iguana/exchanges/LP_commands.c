
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

double LP_query(char *method,struct LP_quoteinfo *qp,char *ipaddr,uint16_t port,char *base,char *rel,bits256 mypub)
{
    cJSON *reqjson; struct LP_peerinfo *peer; int32_t i,flag = 0,pushsock = -1; double price = 0.;
    if ( ipaddr != 0 && port >= 1000 )
    {
        if ( (peer= LP_peerfind((uint32_t)calc_ipbits(ipaddr),port)) == 0 )
            peer = LP_addpeer(1,0,-1,ipaddr,port,port+1,port+2,0,0,0);
        if ( peer != 0 )
        {
            if ( (pushsock= peer->pushsock) >= 0 )
            {
                qp->desthash = mypub;
                strcpy(qp->srccoin,base);
                strcpy(qp->destcoin,rel);
                if ( strcmp(method,"request") == 0 )
                    qp->quotetime = (uint32_t)time(NULL);
                reqjson = LP_quotejson(qp);
                if ( bits256_nonz(qp->desthash) != 0 )
                    flag = 1;
                jaddstr(reqjson,"method",method);
                LP_send(pushsock,jprint(reqjson,1),1);
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
            } else printf("no pushsock for peer.%s:%u\n",ipaddr,port);
        } else printf("cant find/create peer.%s:%u\n",ipaddr,port);
    }
    return(price);
}

int32_t LP_command(struct LP_peerinfo *mypeer,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen,double profitmargin)
{
    char *method,*base,*rel,*retstr,pairstr[512]; cJSON *retjson; double price; bits256 privkey,txid; struct LP_utxoinfo *utxo; int32_t retval = -1,DEXselector = 0; uint64_t destvalue; struct basilisk_request R; struct LP_quoteinfo Q;
    if ( IAMCLIENT == 0 && (method= jstr(argjson,"method")) != 0 )
    {
        txid = jbits256(argjson,"txid");
        if ( (utxo= LP_utxofind(txid,jint(argjson,"vout"))) != 0 && strcmp(utxo->ipaddr,mypeer->ipaddr) == 0 && utxo->port == mypeer->port && (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 && strcmp(base,utxo->coin) == 0 )
        {
            //printf("LP_command.(%s)\n",jprint(argjson,0));
            if ( time(NULL) > utxo->swappending )
                utxo->swappending = 0;
            if ( strcmp(method,"price") == 0 || strcmp(method,"request") == 0 )
            {
                retval = 1;
                if ( utxo->swappending == 0 )
                {
                    if ( strcmp(method,"request") == 0 && utxo->pair >= 0 )
                        nn_close(utxo->pair), utxo->pair = -1;
                    if ( (price= LP_price(base,rel)) != 0. )
                    {
                        price *= (1. + profitmargin);
                        if ( LP_quoteinfoinit(&Q,utxo,rel,price) < 0 )
                            return(-1);
                        if ( strcmp(method,"price") == 0 )
                            Q.timestamp = (uint32_t)time(NULL);
                        retjson = LP_quotejson(&Q);
                        if ( strcmp(method,"request") == 0 )
                        {
                            retval |= 2;
                            utxo->swappending = (uint32_t)(time(NULL) + LP_RESERVETIME);
                            utxo->otherpubkey = jbits256(argjson,"desthash");
                            jaddnum(retjson,"quotetime",juint(argjson,"quotetime"));
                            jaddnum(retjson,"pending",utxo->swappending);
                            jaddbits256(retjson,"desthash",utxo->otherpubkey);
                            jaddstr(retjson,"method","reserved");
                        }
                        else jaddstr(retjson,"method","quote");
                        retstr = jprint(retjson,1);
                        LP_send(pubsock,retstr,1);
                        utxo->published = (uint32_t)time(NULL);
                    } else printf("null price\n");
                } else printf("swappending.%u pair.%d\n",utxo->swappending,utxo->pair);
            }
            else if ( strcmp(method,"connect") == 0 )
            {
                retval = 4;
                if ( utxo->pair < 0 )
                {
                    if ( (price= LP_price(base,rel)) != 0. )
                    {
                        price *= (1. + profitmargin);
                        if ( LP_quoteinfoinit(&Q,utxo,rel,price) < 0 )
                            return(-1);
                        if ( LP_quoteparse(&Q,argjson) < 0 )
                            return(-2);
                        //printf("connect with.(%s)\n",jprint(argjson,0));
                        privkey = LP_privkey(utxo->coinaddr);
                        if ( bits256_nonz(utxo->mypub) == 0 )
                            utxo->mypub = LP_pubkey(privkey);
                        if ( bits256_nonz(privkey) != 0 && Q.quotetime >= Q.timestamp-3 && Q.quotetime < utxo->swappending && bits256_cmp(utxo->mypub,Q.srchash) == 0 && (destvalue= LP_txvalue(rel,Q.desttxid,Q.destvout)) >= price*Q.satoshis+Q.desttxfee && destvalue >= Q.destsatoshis+Q.desttxfee )
                        {
                            nanomsg_tcpname(pairstr,mypeer->ipaddr,10000+(rand() % 10000));
                            if ( (utxo->pair= nn_socket(AF_SP,NN_PAIR)) < 0 )
                                printf("error creating utxo->pair\n");
                            else if ( nn_bind(utxo->pair,pairstr) >= 0 )
                            {
                                //char str[65]; printf("destsatoshis %.8f %s t%u\n",dstr(Q.destsatoshis),bits256_str(str,Q.desthash),Q.quotetime);
                                LP_requestinit(&R,Q.srchash,Q.desthash,base,Q.satoshis,rel,Q.destsatoshis,Q.timestamp,Q.quotetime,DEXselector);
                                if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_bobloop,(void *)utxo) == 0 )
                                {
                                    retjson = LP_quotejson(&Q);
                                    jaddstr(retjson,"method","connected");
                                    jaddstr(retjson,"pair",pairstr);
                                    jaddnum(retjson,"requestid",R.requestid);
                                    jaddnum(retjson,"quoteid",R.quoteid);
                                    retstr = jprint(retjson,1);
                                    LP_send(pubsock,retstr,1);
                                    utxo->swap = LP_swapinit(1,0,privkey,&R,&Q);
                                }
                                else
                                {
                                    printf("error launching swaploop\n");
                                    free(utxo->swap);
                                    utxo->swap = 0;
                                    nn_close(utxo->pair);
                                    utxo->pair = -1;
                                }
                            }
                            else
                            {
                                printf("printf error nn_connect to %s\n",pairstr);
                                nn_close(utxo->pair);
                                utxo->pair = -1;
                            }
                        } else printf("dest %.8f < required %.8f (%d %d %d %d %d %d) %.8f %.8f\n",dstr(Q.satoshis),dstr(price*(utxo->satoshis-Q.txfee)),bits256_nonz(privkey) != 0 ,Q.timestamp == utxo->swappending-LP_RESERVETIME ,Q.quotetime >= Q.timestamp ,Q.quotetime < utxo->swappending ,bits256_cmp(utxo->mypub,Q.srchash) == 0 ,   LP_txvalue(rel,Q.desttxid,Q.destvout) >= price*Q.satoshis+Q.desttxfee,dstr(LP_txvalue(rel,Q.desttxid,Q.destvout)),dstr(price*Q.satoshis+Q.desttxfee));
                    } else printf("no price for %s/%s\n",base,rel);
                } else printf("utxo->pair.%d when connect came in (%s)\n",utxo->pair,jprint(argjson,0));
            }
        }
    }
    return(retval);
}

char *LP_connected(cJSON *argjson)
{
    cJSON *retjson; int32_t pairsock = -1; char *pairstr; struct LP_quoteinfo *qp; int32_t DEXselector = 0;
    retjson = cJSON_CreateObject();
    if ( IAMCLIENT == 0 )
        jaddstr(retjson,"result","update stats");
    else
    {
        if ( (pairstr= jstr(argjson,"pair")) == 0 || (pairsock= nn_socket(AF_SP,NN_PAIR)) < 0 )
            jaddstr(retjson,"error","couldnt create pairsock");
        else if ( nn_connect(pairsock,pairstr) >= 0 )
        {
            qp = calloc(1,sizeof(*qp));
            LP_quoteparse(qp,argjson);
            qp->pair = pairsock;
            qp->privkey = LP_privkey(qp->destaddr);
            LP_requestinit(&qp->R,qp->srchash,qp->desthash,qp->srccoin,qp->satoshis,qp->destcoin,qp->destsatoshis,qp->timestamp,qp->quotetime,DEXselector);
            printf("alice pairstr.(%s)\n",pairstr);
            if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_aliceloop,(void *)qp) == 0 )
            {
                jaddstr(retjson,"result","success");
                jadd(retjson,"trade",LP_quotejson(qp));
            } else jaddstr(retjson,"error","couldnt aliceloop");
        }
    }
    return(jprint(retjson,1));
}

// addcoin api

char *stats_JSON(cJSON *argjson,char *remoteaddr,uint16_t port) // from rpc port
{
    char *method,*ipaddr,*userpass,*base,*rel,*coin,*retstr = 0; uint16_t argport,pushport,subport; int32_t amclient,otherpeers,othernumutxos; struct LP_peerinfo *peer; cJSON *retjson;
    if ( (method= jstr(argjson,"method")) == 0 )
        return(clonestr("{\"error\":\"need method in request\"}"));
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
            if ( strcmp(method,"setprice") == 0 )
            {
                if ( LP_mypriceset(base,rel,jdouble(argjson,"price")) < 0 )
                    return(clonestr("{\"error\":\"couldnt set price\"}"));
                else return(clonestr("{\"result\":\"success\"}"));
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
            if ( strcmp(method,"inventory") == 0 )
            {
                LP_privkey_init(0,-1,coin,0,USERPASS_WIFSTR,1);
                return(LP_inventory(coin));
            }
            else if ( IAMCLIENT != 0 && (strcmp(method,"candidates") == 0 || strcmp(method,"autotrade") == 0) )
            {
                bits256 txid; int32_t vout; struct LP_utxoinfo *utxo;
                txid = jbits256(argjson,"txid");
                if ( bits256_nonz(txid) == 0 )
                    return(clonestr("{\"error\":\"invalid or missing txid\"}"));
                if ( jobj(argjson,"vout") == 0 )
                    return(clonestr("{\"error\":\"missing vout\"}"));
                vout = jint(argjson,"vout");
                if ( (utxo= LP_utxofind(txid,vout)) == 0 )
                    return(clonestr("{\"error\":\"txid/vout not found\"}"));
                if ( strcmp(method,"candidates") == 0 )
                    return(jprint(LP_tradecandidates(utxo,coin),1));
                else return(jprint(LP_autotrade(utxo,coin,jdouble(argjson,"maxprice")),1));
            }
       }
    }
    amclient = (LP_mypeer == 0);
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
            } else LP_addpeer(amclient,LP_mypeer,LP_mypubsock,ipaddr,argport,pushport,subport,jdouble(argjson,"profit"),jint(argjson,"numpeers"),jint(argjson,"numutxos"));
        }
    }
    //printf("CMD.(%s)\n",jprint(argjson,0));
    if ( strcmp(method,"quote") == 0 || strcmp(method,"reserved") == 0 )
        retstr = LP_quotereceived(argjson);
    else if ( strcmp(method,"connected") == 0 )
        retstr = LP_connected(argjson);
    else if ( strcmp(method,"getprice") == 0 )
        retstr = LP_pricestr(jstr(argjson,"base"),jstr(argjson,"rel"));
    else if ( strcmp(method,"orderbook") == 0 )
        retstr = LP_orderbook(jstr(argjson,"base"),jstr(argjson,"rel"));
    else if ( strcmp(method,"getpeers") == 0 )
        retstr = LP_peers();
    else if ( IAMCLIENT == 0 && strcmp(method,"getutxos") == 0 && (coin= jstr(argjson,"coin")) != 0 )
    {
        retstr = LP_utxos(LP_mypeer,coin,jint(argjson,"lastn"));
        printf("RETURN.(%s)\n",retstr);
    }
    else if ( IAMCLIENT == 0 && strcmp(method,"notify") == 0 )
        retstr = clonestr("{\"result\":\"success\",\"notify\":\"received\"}");
    else if ( IAMCLIENT == 0 && strcmp(method,"notified") == 0 )
    {
        if ( juint(argjson,"timestamp") > time(NULL)-60 )
        {
            printf("utxonotify.(%s)\n",jprint(argjson,0));
            LP_addutxo(amclient,LP_mypeer,LP_mypubsock,jstr(argjson,"coin"),jbits256(argjson,"txid"),jint(argjson,"vout"),j64bits(argjson,"valuesats"),jbits256(argjson,"txid2"),jint(argjson,"vout2"),j64bits(argjson,"valuesats2"),jstr(argjson,"script"),jstr(argjson,"address"),jstr(argjson,"ipaddr"),juint(argjson,"port"),jdouble(argjson,"profit"));
        }
        retstr = clonestr("{\"result\":\"success\",\"notifyutxo\":\"received\"}");
    }
    if ( retstr != 0 )
        return(retstr);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"error","unrecognized command");
    printf("ERROR.(%s)\n",jprint(argjson,0));
    return(clonestr(jprint(retjson,1)));
}
