
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
//  LP_quotes.c
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
        jadd64bits(retjson,"satoshis",qp->satoshis);
    if ( bits256_nonz(qp->desthash) != 0 )
        jaddbits256(retjson,"desthash",qp->desthash);
    if ( bits256_nonz(qp->txid2) != 0 )
    {
        jaddbits256(retjson,"txid2",qp->txid2);
        jaddnum(retjson,"vout2",qp->vout2);
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
    if ( qp->desttxfee != 0 )
        jadd64bits(retjson,"desttxfee",qp->desttxfee);
    if ( qp->destsatoshis != 0 )
    {
        jadd64bits(retjson,"destsatoshis",qp->destsatoshis);
        if ( qp->satoshis != 0 )
        {
            price = (double)(qp->destsatoshis + qp->desttxfee) / qp->satoshis;
            jaddnum(retjson,"price",price);
        }
    }
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
    qp->satoshis = j64bits(argjson,"satoshis");
    qp->destsatoshis = j64bits(argjson,"destsatoshis");
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
    if ( utxo->iambob == 0 || qp->txfee >= utxo->S.satoshis || qp->txfee >= utxo->deposit.value || utxo->deposit.value < LP_DEPOSITSATOSHIS(utxo->S.satoshis) )
        return(-1);
    qp->txid = utxo->payment.txid;
    qp->vout = utxo->payment.vout;
    qp->txid2 = utxo->deposit.txid;
    qp->vout2 = utxo->deposit.vout;
    qp->satoshis = utxo->S.satoshis - qp->txfee;
    qp->destsatoshis = qp->satoshis * price;
    if ( (qp->desttxfee= LP_getestimatedrate(qp->destcoin) * LP_AVETXSIZE) < 10000 )
        qp->desttxfee = 10000;
    if ( qp->desttxfee >= qp->destsatoshis )
        return(-2);
    qp->destsatoshis -= qp->desttxfee;
    safecopy(qp->srccoin,utxo->coin,sizeof(qp->srccoin));
    safecopy(qp->coinaddr,utxo->coinaddr,sizeof(qp->coinaddr));
    qp->srchash = utxo->pubkey;
    return(0);
}

int32_t LP_quotedestinfo(struct LP_quoteinfo *qp,uint32_t quotetime,uint64_t destsatoshis,bits256 desttxid,int32_t destvout,bits256 feetxid,int32_t feevout,bits256 desthash,char *destaddr)
{
    qp->quotetime = quotetime;
    qp->destsatoshis = destsatoshis;
    qp->desttxid = desttxid;
    qp->destvout = destvout;
    qp->desthash = desthash;
    qp->feetxid = feetxid;
    qp->feevout = feevout;
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
        char str[65]; printf("received.(%s) quote %.8f\n",bits256_str(str,Q.txid),price);
        return(clonestr("{\"result\":\"updated\"}"));
    } else return(clonestr("{\"error\":\"nullptr\"}"));
}

char *LP_pricepings(int32_t pubsock,char *base,char *rel,double price)
{
    bits256 zero; cJSON *reqjson = cJSON_CreateObject();
    jaddbits256(reqjson,"pubkey",LP_mypubkey);
    jaddstr(reqjson,"base",base);
    jaddstr(reqjson,"rel",rel);
    jaddnum(reqjson,"price",price);
    if ( pubsock >= 0 )
    {
        jaddstr(reqjson,"method","postprice");
        printf("pricepings.(%s)\n",jprint(reqjson,0));
        LP_send(pubsock,jprint(reqjson,1),1);
    }
    else
    {
        jaddstr(reqjson,"method","forward");
        jaddstr(reqjson,"method2","postprice");
        memset(zero.bytes,0,sizeof(zero));
        LP_forward(zero,jprint(reqjson,1),1);
    }
    return(clonestr("{\"result\":\"success\"}"));
}

char *LP_postedprice(cJSON *argjson)
{
    bits256 pubkey; double price; char *base,*rel;
    //printf("PRICE POSTED.(%s)\n",jprint(argjson,0));
    if ( (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 && (price= jdouble(argjson,"price")) > SMALLVAL )
    {
        pubkey = jbits256(argjson,"pubkey");
        if ( bits256_nonz(pubkey) != 0 )
        {
            LP_pricefeedupdate(pubkey,base,rel,price);
            return(clonestr("{\"result\":\"success\"}"));
        }
    }
    return(clonestr("{\"error\":\"missing fields in posted price\"}"));
}

int32_t LP_sizematch(uint64_t mysatoshis,uint64_t othersatoshis)
{
    if ( mysatoshis >= othersatoshis )
        return(0);
    else return(-1);
}

int32_t LP_arrayfind(cJSON *array,bits256 txid,int32_t vout)
{
    int32_t i,n = cJSON_GetArraySize(array); cJSON *item;
    for (i=0; i<n; i++)
    {
        item = jitem(array,i);
        if ( vout == jint(item,"vout") && bits256_cmp(txid,jbits256(item,"txid")) == 0 )
            return(i);
    }
    return(-1);
}

double LP_query(char *method,struct LP_quoteinfo *qp)
{
    cJSON *reqjson; int32_t i,flag = 0; double price = 0.; struct LP_utxoinfo *utxo;
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
    printf("QUERY.(%s)\n",jprint(reqjson,0));
    LP_forward(qp->srchash,jprint(reqjson,1),1);
    for (i=0; i<30; i++)
    {
        if ( (price= LP_pricecache(qp,qp->srccoin,qp->destcoin,qp->txid,qp->vout)) > SMALLVAL )
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
    char *retstr,pairstr[512],destaddr[64]; cJSON *retjson; double price; bits256 privkey; int32_t pair=-1,retval = -1,DEXselector = 0; uint64_t destvalue; struct LP_quoteinfo Q; struct basilisk_swap *swap;
    if ( (price= LP_price(base,rel)) > SMALLVAL )
    {
        price *= (1. + profitmargin);
        if ( LP_quoteinfoinit(&Q,utxo,rel,price) < 0 )
            return(-1);
        if ( LP_quoteparse(&Q,argjson) < 0 )
            return(-2);
        printf("connect with.(%s)\n",jprint(argjson,0));
        Q.destsatoshis = Q.satoshis * price;
        privkey = LP_privkey(utxo->coinaddr);
        if ( bits256_nonz(utxo->S.mypub) == 0 )
            utxo->S.mypub = LP_pubkey(privkey);
        if ( LP_iseligible(1,Q.srccoin,Q.txid,Q.vout,Q.satoshis,Q.txid2,Q.vout2) == 0 )
        {
            printf("not eligible\n");
            return(-1);
        }
        if ( utxo->payment.value > (Q.satoshis << 1) )
        {
            printf("utxo payment %.8f is less than half covered by Q %.8f\n",dstr(utxo->payment.value),dstr(Q.satoshis));
            return(-1);
        }
        if ( bits256_nonz(privkey) != 0 && Q.quotetime >= Q.timestamp-3 && Q.quotetime < utxo->T.swappending && bits256_cmp(utxo->S.mypub,Q.srchash) == 0 && (destvalue= LP_txvalue(destaddr,rel,Q.desttxid,Q.destvout)) >= price*Q.satoshis+Q.desttxfee && destvalue >= Q.destsatoshis+Q.desttxfee )
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
            printf("dest %.8f < required %.8f (%d %d %d %d %d %d) %.8f %.8f\n",dstr(Q.satoshis),dstr(price*(utxo->S.satoshis-Q.txfee)),bits256_nonz(privkey) != 0 ,Q.timestamp == utxo->T.swappending-LP_RESERVETIME ,Q.quotetime >= Q.timestamp ,Q.quotetime < utxo->T.swappending ,bits256_cmp(utxo->S.mypub,Q.srchash) == 0 ,   LP_txvalue(destaddr,rel,Q.desttxid,Q.destvout) >= price*Q.satoshis+Q.desttxfee,dstr(LP_txvalue(destaddr,rel,Q.desttxid,Q.destvout)),dstr(price*Q.satoshis+Q.desttxfee));
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
    char *method,*base,*rel,*retstr; cJSON *retjson; double price,bid,ask; bits256 txid,spendtxid; struct LP_utxoinfo *utxo; int32_t selector,spendvini,retval = -1; struct LP_quoteinfo Q;
    if ( (method= jstr(argjson,"method")) != 0 && (strcmp(method,"request") == 0 ||strcmp(method,"connect") == 0) )
    {
        retval = 1;
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
            if ( strcmp(method,"request") == 0 ) // bob
            {
                retval = 1;
                if ( LP_isavailable(utxo) > 0 )
                {
                    if ( (price= LP_myprice(&bid,&ask,base,rel)) > SMALLVAL )
                    {
                        price *= (1. + profitmargin);
                        if ( LP_quoteinfoinit(&Q,utxo,rel,price) < 0 )
                            return(-1);
                        if ( LP_iseligible(1,Q.srccoin,Q.txid,Q.vout,Q.satoshis,Q.txid2,Q.vout2) == 0 )
                        {
                            printf("not eligible\n");
                            return(-1);
                        }
                        Q.timestamp = (uint32_t)time(NULL);
                        retjson = LP_quotejson(&Q);
                        utxo->S.otherpubkey = jbits256(argjson,"desthash");
                        retval |= 2;
                        LP_unavailableset(utxo,jbits256(argjson,"desthash"));
                        jaddnum(retjson,"quotetime",juint(argjson,"quotetime"));
                        jaddnum(retjson,"pending",utxo->T.swappending);
                        jaddbits256(retjson,"desthash",utxo->S.otherpubkey);
                        jaddstr(retjson,"method","reserved");
                        retstr = jprint(retjson,1);
                        if ( pubsock >= 0 )
                            LP_send(pubsock,retstr,1);
                        else LP_forward(utxo->S.otherpubkey,retstr,1);
                        utxo->T.lasttime = (uint32_t)time(NULL);
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

char *LP_autotrade(char *base,char *rel,double maxprice,double volume)
{
    uint64_t destsatoshis,asatoshis; bits256 txid,pubkey; char *obookstr; cJSON *orderbook,*asks,*item,*bestitem=0; struct LP_utxoinfo *autxo,*butxo,*bestutxo = 0; int32_t i,vout,numasks,DEXselector=0; double ordermatchprice,bestmetric,metric,bestprice=0.,vol,price; struct LP_quoteinfo Q;
    if ( maxprice <= 0. || volume <= 0. || LP_priceinfofind(base) == 0 || LP_priceinfofind(rel) == 0 )
        return(clonestr("{\"error\":\"invalid parameter\"}"));
    destsatoshis = SATOSHIDEN * volume;
    if ( (autxo= LP_utxo_bestfit(rel,destsatoshis)) == 0 )
        return(clonestr("{\"error\":\"cant find utxo that is big enough\"}"));
    bestmetric = ordermatchprice = 0.;
    if ( (obookstr= LP_orderbook(base,rel)) != 0 )
    {
        if ( (orderbook= cJSON_Parse(obookstr)) != 0 )
        {
            if ( (asks= jarray(&numasks,orderbook,"asks")) != 0 )
            {
                for (i=0; i<numasks; i++)
                {
                    item = jitem(asks,i);
                    if ( (price= jdouble(item,"price")) > SMALLVAL && price <= maxprice )
                    {
                        pubkey = jbits256(item,"pubkey");
                        if ( bits256_cmp(pubkey,LP_mypubkey) != 0 )
                        {
                            if ( bestprice == 0. ) // assumes price ordered asks
                                bestprice = price;
                            txid = jbits256(item,"txid");
                            vout = jint(item,"vout");
                            vol = jdouble(item,"volume");
                            if ( (butxo= LP_utxofind(1,txid,vout)) != 0 && vol*SATOSHIDEN == butxo->payment.value && LP_isavailable(butxo) > 0 && LP_ismine(butxo) == 0 )
                            {
                                asatoshis = butxo->payment.value * price;
                                if ( asatoshis <= destsatoshis && destsatoshis > (asatoshis >> 1) )
                                {
                                    metric = price / bestprice;
                                    printf("%f %f %f %f ",price,metric,dstr(asatoshis),metric * metric * metric);
                                    if ( metric < 1.1 )
                                    {
                                        metric = dstr(asatoshis) * metric * metric * metric;
                                        printf("(%f) <- metric\n",metric);
                                        if ( bestmetric == 0. || metric < bestmetric )
                                        {
                                            bestutxo = butxo;
                                            ordermatchprice = price;
                                            bestmetric = metric;
                                        }
                                    }
                                }
                            } else printf("cant find butxo.%p or value mismatch %.8f != %.8f\n",butxo,vol,butxo!=0?dstr(butxo->payment.value):0);
                        }
                    } else break;
                }
            }
            free_json(orderbook);
        }
        free(obookstr);
    }
    if ( bestutxo == 0 || ordermatchprice == 0. )
        return(clonestr("{\"error\":\"cant find ordermatch utxo\"}"));
    asatoshis = bestutxo->payment.value * ordermatchprice;
    if ( LP_quoteinfoinit(&Q,bestutxo,rel,ordermatchprice) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote\"}"));
    if ( LP_quotedestinfo(&Q,Q.timestamp+1,asatoshis,autxo->payment.txid,autxo->payment.vout,autxo->fee.txid,autxo->fee.vout,LP_mypubkey,autxo->coinaddr) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote info\"}"));
    price = LP_query("request",&Q);
    if ( price <= maxprice )
    {
        bestitem = LP_quotejson(&Q);
        price = LP_query("connect",&Q);
        LP_requestinit(&Q.R,Q.srchash,Q.desthash,base,Q.satoshis,Q.destcoin,Q.destsatoshis,Q.timestamp,Q.quotetime,DEXselector);
        jaddstr(bestitem,"status","connected");
        jaddnum(bestitem,"maxprice",maxprice);
        jaddnum(bestitem,"requestid",Q.R.requestid);
        jaddnum(bestitem,"quoteid",Q.R.quoteid);
        printf("Alice r.%u q.%u\n",Q.R.requestid,Q.R.quoteid);
    } else jaddstr(bestitem,"status","too expensive");
    return(jprint(bestitem,0));
}




