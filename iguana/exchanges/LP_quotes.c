
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
        //jadd64bits(retjson,"feesatoshis",qp->feesatoshis);
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
    //qp->feesatoshis = j64bits(argjson,"feesatoshis");
    qp->satoshis = j64bits(argjson,"satoshis");
    qp->satoshis2 = j64bits(argjson,"satoshis2");
    qp->value = j64bits(argjson,"value");
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
    if ( qp->txfee >= utxo->value || qp->txfee >= utxo->value2 || utxo->value2 < utxo->satoshis+(utxo->satoshis>>3) )
        return(-1);
    qp->txid = utxo->txid;
    qp->vout = utxo->vout;
    qp->txid2 = utxo->txid2;
    qp->vout2 = utxo->vout2;
    qp->satoshis = utxo->satoshis;
    qp->satoshis2 = utxo->satoshis + (utxo->satoshis >> 3);
    qp->destsatoshis = qp->satoshis * price;
    //qp->feesatoshis = qp->destsatoshis / INSTANTDEX_INSURANCEDIV;
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
    //qp->feesatoshis = qp->destsatoshis / INSTANTDEX_INSURANCEDIV;
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

cJSON *LP_tradecandidates(struct LP_utxoinfo *myutxo,char *base)
{
    struct LP_peerinfo *peer,*tmp; struct LP_quoteinfo Q; char *utxostr,coinstr[16]; cJSON *array,*retarray=0,*item; int32_t i,n; double price;
    if ( (price= LP_price(base,myutxo->coin)) == .0 )
    {
        printf("no LP_price (%s -> %s)\n",base,myutxo->coin);
        return(0);
    }
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
                        LP_quoteparse(&Q,item);
                        safecopy(coinstr,jstr(item,"base"),sizeof(coinstr));
                        if ( strcmp(coinstr,base) == 0 )
                            if ( LP_arrayfind(retarray,Q.txid,Q.vout) < 0 )
                                jaddi(retarray,jduplicate(item));
                    }
                }
                free_json(array);
            }
            free(utxostr);
        }
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
        printf("candidates.(%s)\nn.%d",jprint(array,0),cJSON_GetArraySize(array));
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
                    Q[i].destsatoshis = price * Q[i].satoshis;
                }
                if ( (prices[i]= price) != 0. && (bestprice == 0. || price < bestprice) )
                    bestprice = price;
                //char str[65]; printf("i.%d of %d: (%s) -> txid.%s price %.8f best %.8f dest %.8f\n",i,n,jprint(item,0),bits256_str(str,Q[i].txid),price,bestprice,dstr(Q[i].destsatoshis));
            }
            if ( bestprice != 0. )
            {
                bestmetric = 0.;
                besti = -1;
                for (i=0; i<n && i<sizeof(prices)/sizeof(*prices); i++)
                {
                    if ( (price= prices[i]) != 0. && myutxo->satoshis > Q[i].destsatoshis )
                    {
                        metric = price / bestprice;
                        printf("%f %f %f %f ",price,metric,dstr(Q[i].destsatoshis),metric * metric * metric);
                        if ( metric < 1.1 )
                        {
                            metric = dstr(Q[i].destsatoshis) * metric * metric * metric;
                            printf("%f\n",metric);
                            if ( bestmetric == 0. || metric < bestmetric )
                            {
                                besti = i;
                                bestmetric = metric;
                            }
                        }
                    } else printf("(%f %f) ",dstr(myutxo->satoshis),dstr(Q[i].destsatoshis));
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
    double price,bid,ask; uint32_t now; cJSON *retjson; struct LP_quoteinfo Q; char *retstr;
    if ( (now= (uint32_t)time(NULL)) > utxo->swappending )
        utxo->swappending = 0;
    if ( now > utxo->published+60 && utxo->swappending == 0 && utxo->pair < 0 && utxo->swap == 0 && (price= LP_myprice(&bid,&ask,utxo->coin,rel)) != 0. )
    {
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




