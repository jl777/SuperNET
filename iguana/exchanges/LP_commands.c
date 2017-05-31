
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

struct basilisk_request *LP_requestinit(struct basilisk_request *rp,bits256 srchash,bits256 desthash,char *src,uint64_t srcsatoshis,char *dest,uint64_t destsatoshis,uint32_t timestamp,uint32_t quotetime,int32_t DEXselector)
{
    memset(rp,0,sizeof(*rp));
    rp->srchash = srchash;
    rp->desthash = desthash;
    rp->srcamount = srcsatoshis;
    rp->destamount = destsatoshis;
    rp->timestamp = timestamp;
    rp->quotetime = quotetime;
    rp->DEXselector = DEXselector;
    safecopy(rp->src,src,sizeof(rp->src));
    safecopy(rp->dest,dest,sizeof(rp->dest));
    rp->quoteid = basilisk_quoteid(rp);
    rp->requestid = basilisk_requestid(rp);
    return(rp);
}

double LP_pricequery(bits256 *otherpubp,uint32_t *reservedp,uint64_t *txfeep,uint64_t *destsatoshisp,uint64_t *desttxfeep,char *ipaddr,uint16_t port,char *base,char *rel,bits256 txid,int32_t vout,bits256 mypub)
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
                reqjson = cJSON_CreateObject();
                jaddbits256(reqjson,"txid",txid);
                jaddnum(reqjson,"vout",vout);
                jaddstr(reqjson,"base",base);
                jaddstr(reqjson,"rel",rel);
                if ( bits256_nonz(mypub) == 0 )
                    jaddstr(reqjson,"method","price");
                else
                {
                    flag = 1;
                    jaddstr(reqjson,"method","request");
                    jaddbits256(reqjson,"mypub",mypub);
                }
                LP_send(pushsock,jprint(reqjson,1),1);
                for (i=0; i<10; i++)
                {
                    if ( (price= LP_pricecache(otherpubp,reservedp,txfeep,destsatoshisp,desttxfeep,base,rel,txid,vout)) != 0. )
                    {
                        if ( flag == 0 || bits256_nonz(*otherpubp) != 0 )
                            break;
                    }
                    usleep(250000);
                }
            } else printf("no pushsock for peer.%s:%u\n",ipaddr,port);
        } else printf("cant find/create peer.%s:%u\n",ipaddr,port);
    }
    return(price);
}

/*
 //5.9.253.196:7779 [{"ipaddr":"5.9.253.196","port":7779,"profit":0.01064000,"coin":"KMD","address":"RFQn4gNG555woQWQV1wPseR47spCduiJP5","script":"76a914434009423522682bd7cc1b18a614c3096d19683188ac","txid":"f5d5e2eb4ef85c78f95076d0d2d99af9e1b85968e57b3c7bdb282bd005f7c341","vout":1,"value":100,"deposit":"07902a65d11f0f577a0346432bcd2b6b53de5554c314209d1964693962524d69","dvout":1,"dvalue":120}]
 
 LP_send(peer->pushsock,jprint(reqjson,0),1);
 jdelete(reqjson,"method");
 jaddstr(reqjson,"method","request");
 LP_send(peer->pushsock,jprint(reqjson,0),1);
 jdelete(reqjson,"method");
 jaddstr(reqjson,"method","connect");
 LP_send(peer->pushsock,jprint(reqjson,0),1);
 
 //SENT.({"base":"KMD","rel":"BTC","timestamp":1496076137,"price":0.00021791,"txid":"f5d5e2eb4ef85c78f95076d0d2d99af9e1b85968e57b3c7bdb282bd005f7c341","srchash":"2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74","txfee":"100000","satoshis":"9999900000","destsatoshis":"2179101","result":"reserved","pending":1496076197}
*/
int32_t LP_sizematch(uint64_t mysatoshis,uint64_t othersatoshis)
{
    if ( mysatoshis >= othersatoshis )
        return(0);
    else return(-1);
}

cJSON *LP_tradecandidates(struct LP_utxoinfo *myutxo,char *base)
{
    struct LP_peerinfo *peer,*tmp; char *utxostr,coinstr[16]; cJSON *array,*icopy,*retarray=0,*item; int32_t i,n; double price; bits256 otherpub; uint32_t reserved; int64_t estimatedbase; uint64_t txfee,destsatoshis,desttxfee;
    if ( (price= LP_price(base,myutxo->coin)) == .0 )
        return(0);
    estimatedbase = myutxo->satoshis / price;
    if ( estimatedbase <= 0 )
        return(0);
    //printf("%s -> %s price %.8f mysatoshis %llu estimated base %llu\n",base,myutxo->coin,price,(long long)myutxo->satoshis,(long long)estimatedbase);
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        if ( (utxostr= issue_LP_clientgetutxos(peer->ipaddr,peer->port,base,100)) != 0 )
        {
            //printf("%s:%u %s\n",peer->ipaddr,peer->port,utxostr);
            if ( (array= cJSON_Parse(utxostr)) != 0 )
            {
                if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
                {
                    retarray = cJSON_CreateArray();
                    for (i=0; i<n; i++)
                    {
                        item = jitem(array,i);
                        safecopy(coinstr,jstr(item,"base"),sizeof(coinstr));
                        if ( strcmp(coinstr,base) == 0 && LP_sizematch(estimatedbase,j64bits(item,"satoshis")) == 0 )
                        {
                            icopy = 0;
                            if ( (price= LP_pricecache(&otherpub,&reserved,&txfee,&destsatoshis,&desttxfee,base,myutxo->coin,jbits256(item,"txid"),jint(item,"vout"))) != 0. )
                            {
                                if ( LP_sizematch(myutxo->satoshis,destsatoshis) == 0 )
                                    icopy = jduplicate(item);
                            } else icopy = jduplicate(item);
                            if ( icopy != 0 )
                            {
                                if ( price != 0. )
                                    jaddnum(icopy,"price",price);
                                jaddi(retarray,icopy);
                            }
                        }
                    }
                }
                free_json(array);
            }
            free(utxostr);
        }
        if ( retarray != 0 )
            break;
    }
    return(retarray);
}

cJSON *LP_bestprice(struct LP_utxoinfo *utxo,char *base)
{
    static bits256 zero;
    int32_t i,n,besti; cJSON *array,*item,*bestitem=0; double bestmetric,metric,bestprice=0.,price,prices[100]; bits256 otherpubs[100]; uint32_t reserved[100]; uint64_t txfees[100],destsatoshis[100],desttxfees[100];
    bestprice = 0.;
    if ( (array= LP_tradecandidates(utxo,base)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            memset(prices,0,sizeof(prices));
            memset(reserved,0,sizeof(reserved));
            memset(otherpubs,0,sizeof(otherpubs));
            memset(txfees,0,sizeof(txfees));
            memset(destsatoshis,0,sizeof(destsatoshis));
            memset(desttxfees,0,sizeof(desttxfees));
            //BTC 0.02500000 -> ([{"ipaddr":"5.9.253.196","port":7779,"profit":0.01035000,"base":"KMD","coin":"KMD","address":"RFQn4gNG555woQWQV1wPseR47spCduiJP5","script":"76a914434009423522682bd7cc1b18a614c3096d19683188ac","txid":"f5d5e2eb4ef85c78f95076d0d2d99af9e1b85968e57b3c7bdb282bd005f7c341","vout":1,"value":100,"deposit":"07902a65d11f0f577a0346432bcd2b6b53de5554c314209d1964693962524d69","dvout":1,"dvalue":120}])
            for (i=0; i<n && i<sizeof(prices)/sizeof(*prices); i++)
            {
                item = jitem(array,i);
                if ( (price= jdouble(item,"price")) == 0. )
                {
                    price = LP_pricequery(&otherpubs[i],&reserved[i],&txfees[i],&destsatoshis[i],&desttxfees[i],jstr(item,"ipaddr"),jint(item,"port"),base,utxo->coin,jbits256(item,"txid"),jint(item,"vout"),zero);
                    if ( destsatoshis[i] != 0 && (double)j64bits(item,"value")/destsatoshis[i] > price )
                        price = (double)j64bits(item,"satoshis")/destsatoshis[i];
                }
                if ( (prices[i]= price) != 0. && (bestprice == 0. || price < bestprice) )
                    bestprice = price;
                printf("i.%d price %.8f bestprice %.8f: (%s)\n",i,price,bestprice,jprint(item,0));
            }
            if ( bestprice != 0. )
            {
                bestmetric = 0.;
                besti = -1;
                for (i=0; i<n && i<sizeof(prices)/sizeof(*prices); i++)
                {
                    if ( (price= prices[i]) != 0. && destsatoshis[i] != 0 )
                    {
                        metric = price / bestprice;
                        if ( metric > 0.9 )
                        {
                            metric = destsatoshis[i] / metric * metric * metric;
                            if ( metric > bestmetric )
                            {
                                besti = i;
                                bestmetric = metric;
                            }
                        }
                    }
                }
                if ( besti >= 0 )
                {
                    bestitem = jduplicate(jitem(array,besti));
                    i = besti;
                    item = bestitem;
                    price = LP_pricequery(&otherpubs[i],&reserved[i],&txfees[i],&destsatoshis[i],&desttxfees[i],jstr(item,"ipaddr"),jint(item,"port"),base,utxo->coin,jbits256(item,"txid"),jint(item,"vout"),myutxo->pubkey);
                    if ( jobj(bestitem,"price") != 0 )
                        jdelete(bestitem,"price");
                    jaddnum(bestitem,"reserved",reserved[besti]);
                    jaddnum(bestitem,"price",prices[besti]);
                    jadd64bits(bestitem,"txfee",txfees[besti]);
                    jadd64bits(bestitem,"desttxfee",desttxfees[besti]);
                    jadd64bits(bestitem,"destsatoshis",destsatoshis[besti]);
                    jaddbits256(bestitem,"otherpub",otherpubs[besti]);
                }
            }
            free_json(array);
        }
    }
    return(bestitem);
}

char *LP_quote(uint32_t reserved,char *base,char *rel,bits256 txid,int32_t vout,double price,uint64_t satoshis,uint64_t txfee,uint64_t destsatoshis,uint64_t desttxfee,bits256 otherpub)
{
    struct LP_cacheinfo *ptr;
    if ( (ptr= LP_cacheadd(base,rel,txid,vout,price,satoshis)) != 0 )
    {
        //SENT.({"base":"KMD","rel":"BTC","address":"RFQn4gNG555woQWQV1wPseR47spCduiJP5","timestamp":1496216835,"price":0.00021141,"txid":"f5d5e2eb4ef85c78f95076d0d2d99af9e1b85968e57b3c7bdb282bd005f7c341","srchash":"0bcabd875bfa724e26de5f35035ca3767c50b30960e23cbfcbd478cac9147412","txfee":"100000","desttxfee":"10000","value":"10000000000","satoshis":"9999900000","destsatoshis":"2124104","method":"quote"})
        ptr->reserved = reserved;
        ptr->txfee = txfee;
        ptr->destsatoshis = destsatoshis;
        ptr->desttxfee = desttxfee;
        ptr->otherpub = otherpub;
        return(clonestr("{\"result\":\"updated\"}"));
    }
    else return(clonestr("{\"error\":\"nullptr\"}"));
}

void LP_command(struct LP_peerinfo *mypeer,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen,double profitmargin)
{
    char *method,*base,*rel,*retstr,pairstr[512]; cJSON *retjson; double price; bits256 srchash,desthash,pubkey,privkey,txid,desttxid; struct LP_utxoinfo *utxo; uint32_t timestamp,quotetime; int32_t destvout,DEXselector = 0; uint64_t txfee,satoshis,desttxfee,destsatoshis,value; struct basilisk_request R;
    //LP_command.({"txid":"f5d5e2eb4ef85c78f95076d0d2d99af9e1b85968e57b3c7bdb282bd005f7c341","vout":1,"base":"KMD","rel":"BTC","method":"price"})
    if ( (method= jstr(argjson,"method")) != 0 )
    {
        txid = jbits256(argjson,"txid");
        if ( (utxo= LP_utxofind(txid,jint(argjson,"vout"))) != 0 && strcmp(utxo->ipaddr,mypeer->ipaddr) == 0 && utxo->port == mypeer->port && (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 && strcmp(base,utxo->coin) == 0 )
        {
            printf("LP_command.(%s)\n",jprint(argjson,0));
            if ( time(NULL) > utxo->swappending )
                utxo->swappending = 0;
            if ( strcmp(method,"price") == 0 || strcmp(method,"request") == 0 )
            {
                if ( utxo->swappending == 0 && utxo->pair < 0 )
                {
                    if ( utxo->pair >= 0 )
                        nn_close(utxo->pair), utxo->pair = -1;
                    if ( (price= LP_price(base,rel)) != 0. )
                    {
                        price *= (1. + profitmargin);
                        retjson = cJSON_CreateObject();
                        jaddstr(retjson,"base",base);
                        jaddstr(retjson,"rel",rel);
                        jaddstr(retjson,"address",utxo->coinaddr);
                        jaddnum(retjson,"timestamp",time(NULL));
                        jaddnum(retjson,"price",price);
                        jaddbits256(retjson,"txid",txid);
                        jaddnum(retjson,"vout",utxo->vout);
                        pubkey = LP_pubkey(LP_privkey(utxo->coinaddr));
                        jaddbits256(retjson,"srchash",pubkey);
                        if ( (txfee= LP_getestimatedrate(base)*LP_AVETXSIZE) < 10000 )
                            txfee = 10000;
                        jadd64bits(retjson,"txfee",txfee);
                        if ( (desttxfee= LP_getestimatedrate(rel) * LP_AVETXSIZE) < 10000 )
                            desttxfee = 10000;
                        jadd64bits(retjson,"desttxfee",desttxfee);
                        jadd64bits(retjson,"value",utxo->satoshis);
                        jadd64bits(retjson,"satoshis",utxo->satoshis - txfee);
                        jadd64bits(retjson,"destsatoshis",price * (utxo->satoshis-txfee) + desttxfee);
                        if ( strcmp(method,"request") == 0 )
                        {
                            utxo->swappending = (uint32_t)(time(NULL) + LP_RESERVETIME);
                            utxo->otherpubkey = jbits256(argjson,"pubkey");
                            jaddbits256(retjson,"otherpubkey",utxo->otherpubkey);
                            jaddstr(retjson,"method","reserved");
                            jaddnum(retjson,"pending",utxo->swappending);
                        } else jaddstr(retjson,"method","quote");
                        retstr = jprint(retjson,1);
                        LP_send(pubsock,retstr,1);
                    } else printf("null price\n");
                } else printf("swappending.%u pair.%d\n",utxo->swappending,utxo->pair);
            }
            else if ( strcmp(method,"connect") == 0 )
            {
                if ( utxo->pair < 0 )
                {
                    if ( (price= LP_price(base,rel)) != 0. )
                    {
                        price *= (1. + profitmargin);
                        txfee = j64bits(argjson,"txfee");
                        desttxfee = j64bits(argjson,"desttxfee");
                        satoshis = j64bits(argjson,"satoshis");
                        desttxid = jbits256(argjson,"desttxid");
                        destvout = jint(argjson,"destvout");
                        timestamp = juint(argjson,"timestamp");
                        privkey = LP_privkey(utxo->coinaddr);
                        pubkey = LP_pubkey(privkey);
                        srchash = jbits256(argjson,"srchash");
                        value = j64bits(argjson,"destsatoshis");
                        quotetime = juint(argjson,"quotetime");
                        //if ( timestamp == utxo->swappending-LP_RESERVETIME && quotetime >= timestamp && quotetime < utxo->swappending && bits256_cmp(pubkey,srchash) == 0 && (destsatoshis= LP_txvalue(rel,desttxid,destvout)) > price*(utxo->satoshis-txfee)+desttxfee && value <= destsatoshis-desttxfee )
                        {
                            destsatoshis = value;
                            nanomsg_tcpname(pairstr,mypeer->ipaddr,10000+(rand() % 10000));
                            if ( (utxo->pair= nn_socket(AF_SP,NN_PAIR)) < 0 )
                                printf("error creating utxo->pair\n");
                            else if ( nn_connect(utxo->pair,pairstr) >= 0 )
                            {
                                desthash = jbits256(argjson,"desthash");
                                LP_requestinit(&R,srchash,desthash,base,satoshis,rel,destsatoshis,timestamp,quotetime,DEXselector);
                                if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_bobloop,(void *)utxo) == 0 )
                                {
                                    retjson = cJSON_CreateObject();
                                    jaddstr(retjson,"result","connected");
                                    jaddstr(retjson,"pair",pairstr);
                                    jaddnum(retjson,"requestid",R.requestid);
                                    jaddnum(retjson,"quoteid",R.quoteid);
                                    retstr = jprint(retjson,1);
                                    LP_send(pubsock,retstr,1);
                                    utxo->swap = LP_swapinit(1,0,privkey,&R);
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
                        } //else printf("dest %.8f < required %.8f\n",dstr(value),dstr(price*(utxo->satoshis-txfee)));
                    } else printf("no price for %s/%s\n",base,rel);
                } else printf("utxo->pair.%d when connect came in (%s)\n",utxo->pair,jprint(argjson,0));
            }
        }
    }
}

char *stats_JSON(cJSON *argjson,char *remoteaddr,uint16_t port) // from rpc port
{
    char *method,*ipaddr,*coin,*retstr = 0; uint16_t argport,pushport,subport; int32_t amclient,otherpeers,othernumutxos; struct LP_peerinfo *peer; cJSON *retjson;
    if ( (method= jstr(argjson,"method")) == 0 )
        return(clonestr("{\"error\":\"need method in request\"}"));
    else
    {
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
                    if ( (otherpeers= jint(argjson,"numpeers")) > peer->numpeers )
                        peer->numpeers = otherpeers;
                    if ( (othernumutxos= jint(argjson,"numutxos")) > peer->numutxos )
                    {
                        printf("change.(%s) numutxos.%d -> %d mynumutxos.%d\n",peer->ipaddr,peer->numutxos,othernumutxos,LP_mypeer != 0 ? LP_mypeer->numutxos:0);
                        peer->numutxos = othernumutxos;
                    }
                    //printf("peer.(%s) found (%d %d) (%d %d) (%s)\n",peer->ipaddr,peer->numpeers,peer->numutxos,otherpeers,othernumutxos,jprint(argjson,0));
                } else LP_addpeer(amclient,LP_mypeer,LP_mypubsock,ipaddr,argport,pushport,subport,jdouble(argjson,"profit"),jint(argjson,"numpeers"),jint(argjson,"numutxos"));
            } 
        }
        if ( strcmp(method,"quote") == 0 || strcmp(method,"reserved") == 0 )
            retstr = LP_quote(juint(argjson,"pending"),jstr(argjson,"base"),jstr(argjson,"rel"),jbits256(argjson,"txid"),jint(argjson,"vout"),jdouble(argjson,"price"),j64bits(argjson,"satoshis"),j64bits(argjson,"txfee"),j64bits(argjson,"destsatoshis"),j64bits(argjson,"desttxfee"),jbits256(argjson,"otherpubkey"));
        else if ( IAMCLIENT == 0 && strcmp(method,"getpeers") == 0 )
            retstr = LP_peers();
        else if ( IAMCLIENT == 0 && strcmp(method,"getutxos") == 0 && (coin= jstr(argjson,"coin")) != 0 )
            retstr = LP_utxos(LP_mypeer,coin,jint(argjson,"lastn"));
        else if ( IAMCLIENT == 0 && strcmp(method,"notify") == 0 )
            retstr = clonestr("{\"result\":\"success\",\"notify\":\"received\"}");
        else if ( IAMCLIENT == 0 && strcmp(method,"notifyutxo") == 0 )
        {
            printf("utxonotify.(%s)\n",jprint(argjson,0));
            LP_addutxo(amclient,LP_mypeer,LP_mypubsock,jstr(argjson,"coin"),jbits256(argjson,"txid"),jint(argjson,"vout"),SATOSHIDEN * jdouble(argjson,"value"),jbits256(argjson,"deposit"),jint(argjson,"dvout"),SATOSHIDEN * jdouble(argjson,"dvalue"),jstr(argjson,"script"),jstr(argjson,"address"),jstr(argjson,"ipaddr"),juint(argjson,"port"),jdouble(argjson,"profit"));
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
