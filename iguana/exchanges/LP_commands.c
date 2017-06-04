
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
    struct basilisk_request R;
    memset(rp,0,sizeof(*rp));
    rp->srchash = srchash;
    rp->srcamount = srcsatoshis;
    rp->timestamp = timestamp;
    rp->DEXselector = DEXselector;
    safecopy(rp->src,src,sizeof(rp->src));
    safecopy(rp->dest,dest,sizeof(rp->dest));
    R = *rp;
    rp->requestid = basilisk_requestid(rp);
    rp->quotetime = quotetime;
    rp->desthash = desthash;
    rp->destamount = destsatoshis;
    rp->quoteid = basilisk_quoteid(rp);
    return(rp);
}

cJSON *LP_quotejson(struct LP_quoteinfo *qp)
{
    double price; cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"base",qp->srccoin);
    jaddstr(retjson,"rel",qp->destcoin);
    if ( qp->coinaddr[0] != 0 )
        jaddstr(retjson,"address",qp->coinaddr);
    if ( qp->timestamp != 0 )
        jaddnum(retjson,"timestamp",qp->timestamp);
    if ( bits256_nonz(qp->txid) != 0 )
    {
        jaddbits256(retjson,"txid",qp->txid);
        jaddnum(retjson,"vout",qp->vout);
    }
    if ( bits256_nonz(qp->srchash) != 0 )
        jaddbits256(retjson,"srchash",qp->srchash);
    if ( qp->txfee != 0 )
        jadd64bits(retjson,"txfee",qp->txfee);
    if ( qp->quotetime != 0 )
        jaddnum(retjson,"quotetime",qp->quotetime);
    if ( qp->satoshis != 0 )
    {
        jadd64bits(retjson,"satoshis",qp->satoshis);
        price = (double)(qp->destsatoshis+qp->desttxfee) / qp->satoshis;
        jaddnum(retjson,"price",price);
    }
    if ( bits256_nonz(qp->desthash) != 0 )
        jaddbits256(retjson,"desthash",qp->desthash);
    if ( bits256_nonz(qp->txid2) != 0 )
    {
        jaddbits256(retjson,"txid2",qp->txid2);
        jaddnum(retjson,"vout2",qp->vout2);
        if ( qp->satoshis2 != 0 )
            jadd64bits(retjson,"satoshis2",qp->satoshis2);
    }
    if ( bits256_nonz(qp->desttxid) != 0 )
    {
        if ( qp->destaddr[0] != 0 )
            jaddstr(retjson,"destaddr",qp->destaddr);
        jaddbits256(retjson,"desttxid",qp->desttxid);
        jaddnum(retjson,"destvout",qp->destvout);
    }
    if ( bits256_nonz(qp->feetxid) != 0 )
    {
        jaddbits256(retjson,"feetxid",qp->feetxid);
        jaddnum(retjson,"feevout",qp->feevout);
    }
    if ( qp->destsatoshis != 0 )
        jadd64bits(retjson,"destsatoshis",qp->destsatoshis);
    if ( qp->desttxfee != 0 )
        jadd64bits(retjson,"desttxfee",qp->desttxfee);
    if ( qp->change != 0 )
        jaddnum(retjson,"change",dstr(qp->change));
    return(retjson);
}

int32_t LP_quoteparse(struct LP_quoteinfo *qp,cJSON *argjson)
{
    safecopy(qp->srccoin,jstr(argjson,"base"),sizeof(qp->srccoin));
    safecopy(qp->coinaddr,jstr(argjson,"address"),sizeof(qp->coinaddr));
    safecopy(qp->destcoin,jstr(argjson,"rel"),sizeof(qp->destcoin));
    safecopy(qp->destaddr,jstr(argjson,"destaddr"),sizeof(qp->destaddr));
    qp->timestamp = juint(argjson,"timestamp");
    qp->quotetime = juint(argjson,"quotetime");
    qp->txid = jbits256(argjson,"txid");
    qp->txid2 = jbits256(argjson,"txid2");
    qp->vout = jint(argjson,"vout");
    qp->vout2 = jint(argjson,"vout2");
    qp->feevout = jint(argjson,"feevout");
    qp->srchash = jbits256(argjson,"srchash");
    qp->desttxid = jbits256(argjson,"desttxid");
    qp->feetxid = jbits256(argjson,"feetxid");
    qp->destvout = jint(argjson,"destvout");
    qp->desthash = jbits256(argjson,"desthash");
    if ( (qp->satoshis= j64bits(argjson,"satoshis")) == 0 )
        qp->satoshis = SATOSHIDEN * jdouble(argjson,"value");
    if ( (qp->satoshis2= j64bits(argjson,"satoshis2")) == 0 )
        qp->satoshis = SATOSHIDEN * jdouble(argjson,"value2");
    qp->destsatoshis = j64bits(argjson,"destsatoshis");
    qp->change = SATOSHIDEN * jdouble(argjson,"change");
    qp->txfee = j64bits(argjson,"txfee");
    qp->desttxfee = j64bits(argjson,"desttxfee");
    return(0);
}

int32_t LP_quoteinfoinit(struct LP_quoteinfo *qp,struct LP_utxoinfo *utxo,char *destcoin,double price)
{
    memset(qp,0,sizeof(*qp));
    qp->timestamp = (uint32_t)time(NULL);
    safecopy(qp->destcoin,destcoin,sizeof(qp->destcoin));
    if ( (qp->txfee= LP_getestimatedrate(utxo->coin)*LP_AVETXSIZE) < 10000 )
        qp->txfee = 10000;
    if ( qp->txfee >= utxo->satoshis || qp->txfee >= utxo->satoshis2 )
        return(-1);
    qp->txid = utxo->txid;
    qp->vout = utxo->vout;
    qp->txid2 = utxo->txid2;
    qp->vout2 = utxo->vout2;
    qp->satoshis2 = utxo->satoshis2 - qp->txfee;
    qp->satoshis = utxo->satoshis - qp->txfee;
    qp->destsatoshis = qp->satoshis * price;
    if ( (qp->desttxfee= LP_getestimatedrate(qp->destcoin) * LP_AVETXSIZE) < 10000 )
        qp->desttxfee = 10000;
    if ( qp->desttxfee >= qp->destsatoshis )
        return(-2);
    qp->destsatoshis -= qp->desttxfee;
    safecopy(qp->srccoin,utxo->coin,sizeof(qp->srccoin));
    safecopy(qp->coinaddr,utxo->coinaddr,sizeof(qp->coinaddr));
    qp->srchash = LP_pubkey(LP_privkey(utxo->coinaddr));
    return(0);
}

int32_t LP_quoteinfoset(struct LP_quoteinfo *qp,uint32_t timestamp,uint32_t quotetime,uint64_t value,uint64_t txfee,uint64_t destsatoshis,uint64_t desttxfee,bits256 desttxid,int32_t destvout,bits256 desthash,char *destaddr)
{
    if ( txfee != qp->txfee )
    {
        if ( txfee >= value )
            return(-1);
        qp->txfee = txfee;
        qp->satoshis = value - txfee;
    }
    qp->timestamp = timestamp;
    qp->quotetime = quotetime;
    qp->destsatoshis = destsatoshis;
    qp->desttxfee = desttxfee;
    qp->desttxid = desttxid;
    qp->destvout = destvout;
    qp->desthash = desthash;
    safecopy(qp->destaddr,destaddr,sizeof(qp->destaddr));
    return(0);
}

char *LP_quotereceived(cJSON *argjson)
{
    struct LP_cacheinfo *ptr; double price; struct LP_quoteinfo Q;
    LP_quoteparse(&Q,argjson);
    price = (double)(Q.destsatoshis + Q.desttxfee) / (Q.satoshis + Q.txfee);
    if ( (ptr= LP_cacheadd(Q.srccoin,Q.destcoin,Q.txid,Q.vout,price,&Q)) != 0 )
    {
        ptr->Q = Q;
        return(clonestr("{\"result\":\"updated\"}"));
    } else return(clonestr("{\"error\":\"nullptr\"}"));
}

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

int32_t LP_sizematch(uint64_t mysatoshis,uint64_t othersatoshis)
{
    if ( mysatoshis >= othersatoshis )
        return(0);
    else return(-1);
}

cJSON *LP_tradecandidates(struct LP_utxoinfo *myutxo,char *base)
{
    struct LP_peerinfo *peer,*tmp; struct LP_quoteinfo Q; char *utxostr,coinstr[16]; cJSON *array,*icopy,*retarray=0,*item; int32_t i,n; double price; int64_t estimatedbase;
    if ( (price= LP_price(base,myutxo->coin)) == .0 )
    {
        printf("no LP_price (%s -> %s)\n",base,myutxo->coin);
        return(0);
    }
    estimatedbase = myutxo->satoshis / price;
    printf("%s -> %s price %.8f mysatoshis %llu estimated base %llu\n",base,myutxo->coin,price,(long long)myutxo->satoshis,(long long)estimatedbase);
    if ( estimatedbase <= 0 )
        return(0);
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
                        //printf("%s\n",jprint(item,0));
                        safecopy(coinstr,jstr(item,"base"),sizeof(coinstr));
                        if ( strcmp(coinstr,base) == 0 && LP_sizematch(estimatedbase,j64bits(item,"satoshis")) == 0 )
                        {
                            icopy = 0;
                            if ( (price= LP_pricecache(&Q,base,myutxo->coin,jbits256(item,"txid"),jint(item,"vout"))) != 0. )
                            {
                                if ( LP_sizematch(myutxo->satoshis,Q.destsatoshis) == 0 )
                                    icopy = jduplicate(item);
                            } else icopy = jduplicate(item);
                            if ( icopy != 0 )
                            {
                                if ( price != 0. )
                                    jaddnum(icopy,"price",price);
                                jaddi(retarray,icopy);
                            }
                        } else printf("skip %s estimated %.8f vs %.8f\n",coinstr,dstr(estimatedbase),dstr(j64bits(item,"satoshis")));
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

cJSON *LP_autotrade(struct LP_utxoinfo *myutxo,char *base,double maxprice)
{
    static bits256 zero;
    int32_t i,n,besti,DEXselector=0; cJSON *array,*item,*bestitem=0; struct basilisk_request R; double bestmetric,metric,bestprice=0.,price,prices[100]; struct LP_quoteinfo Q[sizeof(prices)/sizeof(*prices)];
    bestprice = 0.;
    if ( maxprice == 0. )
        maxprice = LP_price(base,myutxo->coin) / 0.975;
    if ( (array= LP_tradecandidates(myutxo,base)) != 0 )
    {
        printf("candidates.(%s)\n",jprint(array,0));
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            memset(prices,0,sizeof(prices));
            memset(Q,0,sizeof(Q));
            for (i=0; i<n && i<sizeof(prices)/sizeof(*prices); i++)
            {
                item = jitem(array,i);
                LP_quoteparse(&Q[i],item);
                if ( (price= jdouble(item,"price")) == 0. )
                {
                    price = LP_query("price",&Q[i],jstr(item,"ipaddr"),jint(item,"port"),base,myutxo->coin,zero);
                    if ( Q[i].destsatoshis != 0 && (double)j64bits(item,"satoshis")/Q[i].destsatoshis > price )
                    {
                        printf("adjustprice %.8f -> %.8f\n",price,(double)j64bits(item,"satoshis")/Q[i].destsatoshis);
                        price = (double)j64bits(item,"satoshis")/Q[i].destsatoshis;
                    }
                }
                if ( (prices[i]= price) != 0. && (bestprice == 0. || price < bestprice) )
                    bestprice = price;
                char str[65]; printf("i.%d of %d: (%s) -> txid.%s price %.8f best %.8f dest %.8f\n",i,n,jprint(item,0),bits256_str(str,Q[i].txid),price,bestprice,dstr(Q[i].destsatoshis));
            }
            if ( bestprice != 0. )
            {
                bestmetric = 0.;
                besti = -1;
                for (i=0; i<n && i<sizeof(prices)/sizeof(*prices); i++)
                {
                    if ( (price= prices[i]) != 0. && Q[i].destsatoshis != 0 )
                    {
                        metric = price / bestprice;
                        printf("%f ",metric);
                        if ( metric > 0.9 )
                        {
                            metric = Q[i].destsatoshis / metric * metric * metric;
                            printf("%f, ",metric);
                            if ( metric > bestmetric )
                            {
                                besti = i;
                                bestmetric = metric;
                            }
                        }
                    } else printf("(%f %f) ",price,dstr(Q[i].destsatoshis));
                }
                printf("metrics, best %f\n",bestmetric);
                if ( besti >= 0 )//&& bits256_cmp(myutxo->mypub,otherpubs[besti]) == 0 )
                {
                    i = besti;
                    bestprice = prices[i];
                    item = jitem(array,i);
                    bestitem = LP_quotejson(&Q[i]);
                    printf("bestprice %f vs maxprice %f\n",bestprice,maxprice);
                    if ( maxprice == 0. || bestprice <= maxprice )
                    {
                        Q[i].desttxid = myutxo->txid;
                        Q[i].destvout = myutxo->vout;
                        Q[i].feetxid = myutxo->txid2;
                        Q[i].feevout = myutxo->vout2;
                        strcpy(Q[i].destaddr,myutxo->coinaddr);
                        price = LP_query("request",&Q[i],jstr(item,"ipaddr"),jint(item,"port"),base,myutxo->coin,myutxo->mypub);
                        if ( jobj(bestitem,"price") != 0 )
                            jdelete(bestitem,"price");
                        jaddnum(bestitem,"price",prices[i]);
                        if ( price <= maxprice )
                        {
                            Q[i].desttxid = myutxo->txid;
                            Q[i].destvout = myutxo->vout;
                            Q[i].feetxid = myutxo->txid2;
                            Q[i].feevout = myutxo->vout2;
                            strcpy(Q[i].destaddr,myutxo->coinaddr);
                            price = LP_query("connect",&Q[i],jstr(item,"ipaddr"),jint(item,"port"),base,myutxo->coin,myutxo->mypub);
                            LP_requestinit(&R,Q[i].srchash,Q[i].desthash,base,Q[i].satoshis,Q[i].destcoin,Q[i].destsatoshis,Q[i].timestamp,Q[i].quotetime,DEXselector);
                            jaddstr(bestitem,"status","connected");
                            jaddnum(bestitem,"requestid",R.requestid);
                            jaddnum(bestitem,"quoteid",R.quoteid);
                            printf("Alice r.%u q.%u\n",R.requestid,R.quoteid);
                        } else jaddstr(bestitem,"status","too expensive");
                    }
                }
            }
            free_json(array);
        }
    }
    if ( bestitem == 0 )
        return(cJSON_Parse("{\"error\":\"no match found\"}"));
    return(bestitem);
}

int32_t LP_priceping(int32_t pubsock,struct LP_utxoinfo *utxo,char *rel,double profitmargin)
{
    double price; uint32_t now; cJSON *retjson; struct LP_quoteinfo Q; char *retstr;
    if ( (now= (uint32_t)time(NULL)) > utxo->swappending )
        utxo->swappending = 0;
    if ( now > utxo->published+60 && utxo->swappending == 0 && utxo->pair < 0 && utxo->swap == 0 && (price= LP_price(utxo->coin,rel)) != 0. )
    {
        price *= (1. + profitmargin);
        if ( LP_quoteinfoinit(&Q,utxo,rel,price) < 0 )
            return(-1);
        Q.timestamp = (uint32_t)time(NULL);
        retjson = LP_quotejson(&Q);
        jaddstr(retjson,"method","quote");
        retstr = jprint(retjson,1);
        LP_send(pubsock,retstr,1);
        utxo->published = now;
        return(0);
    }
    return(-1);
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
                            Q.change = destvalue - (Q.destsatoshis+Q.desttxfee);
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
            jaddstr(retjson,"BTC",BTCADDR);
            jaddstr(retjson,"KMD",KMDADDR);
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
        retstr = LP_utxos(LP_mypeer,coin,jint(argjson,"lastn"));
    else if ( IAMCLIENT == 0 && strcmp(method,"notify") == 0 )
        retstr = clonestr("{\"result\":\"success\",\"notify\":\"received\"}");
    else if ( IAMCLIENT == 0 && strcmp(method,"notifyutxo") == 0 )
    {
        printf("utxonotify.(%s)\n",jprint(argjson,0));
        LP_addutxo(amclient,LP_mypeer,LP_mypubsock,jstr(argjson,"coin"),jbits256(argjson,"txid"),jint(argjson,"vout"),SATOSHIDEN * jdouble(argjson,"value"),jbits256(argjson,"txid2"),jint(argjson,"vout2"),SATOSHIDEN * jdouble(argjson,"value2"),jstr(argjson,"script"),jstr(argjson,"address"),jstr(argjson,"ipaddr"),juint(argjson,"port"),jdouble(argjson,"profit"));
        retstr = clonestr("{\"result\":\"success\",\"notifyutxo\":\"received\"}");
    }
    if ( retstr != 0 )
        return(retstr);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"error","unrecognized command");
    printf("ERROR.(%s)\n",jprint(argjson,0));
    return(clonestr(jprint(retjson,1)));
}
