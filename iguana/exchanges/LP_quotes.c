
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
        //char str[65]; printf("received.(%s) quote %.8f\n",bits256_str(str,Q.txid),price);
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

cJSON *LP_tradecandidates(char *base)
{
    struct LP_peerinfo *peer,*tmp; struct LP_quoteinfo Q; char *utxostr,coinstr[16]; cJSON *array,*retarray=0,*item; int32_t i,n,totaladded,added;
    /*if ( (price= LP_price(base,myutxo->coin)) == .0 )
    {
        printf("no LP_price (%s -> %s)\n",base,myutxo->coin);
        return(0);
    }*/
    totaladded = 0;
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        printf("%s:%u %s\n",peer->ipaddr,peer->port,base);
        n = added = 0;
        if ( (utxostr= issue_LP_clientgetutxos(peer->ipaddr,peer->port,base,100)) != 0 )
        {
            printf("%s:%u %s %s\n",peer->ipaddr,peer->port,base,utxostr);
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
                        {
                            if ( LP_iseligible(1,Q.srccoin,Q.txid,Q.vout,Q.satoshis,Q.txid2,Q.vout2) != 0 )
                            {
                                if ( LP_arrayfind(retarray,Q.txid,Q.vout) < 0 )
                                {
                                    jaddi(retarray,jduplicate(item));
                                    added++;
                                    totaladded++;
                                }
                            } else printf("ineligible.(%s)\n",jprint(item,0));
                        }
                    }
                 }
                free_json(array);
            }
            free(utxostr);
        }
        if ( n == totaladded && added == 0 )
        {
            printf("n.%d totaladded.%d vs added.%d\n",n,totaladded,added);
            break;
        }
    }
    return(retarray);
}

void LP_quotesinit(char *base,char *rel)
{
    cJSON *array,*item; struct LP_quoteinfo Q; bits256 zero; int32_t i,n,iter;
    memset(&zero,0,sizeof(zero));
    for (iter=0; iter<2; iter++)
    if ( (array= LP_tradecandidates(iter == 0 ? base : rel)) != 0 )
    {
        //printf("candidates.(%s)\nn.%d\n",jprint(array,0),cJSON_GetArraySize(array));
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            memset(&Q,0,sizeof(Q));
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                LP_quoteparse(&Q,item);
                if ( iter == 0 )
                    LP_query("price",&Q,base,rel,zero);
                else LP_query("price",&Q,rel,base,zero);
            }
        }
        free_json(array);
    }
}

cJSON *LP_autotrade(struct LP_utxoinfo *myutxo,char *base,double maxprice)
{
    static bits256 zero;
    int32_t i,n,besti,DEXselector=0; cJSON *array,*item,*bestitem=0; struct basilisk_request R; double bestmetric,metric,bestprice=0.,price,prices[100]; struct LP_quoteinfo Q[sizeof(prices)/sizeof(*prices)];
    bestprice = 0.;
    if ( maxprice == 0. )
        maxprice = LP_price(base,myutxo->coin) / 0.975;
    if ( (array= LP_tradecandidates(base)) != 0 )
    {
        printf("candidates.(%s)\nn.%d\n",jprint(array,0),cJSON_GetArraySize(array));
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
                    price = LP_query("price",&Q[i],base,myutxo->coin,zero);
                    Q[i].destsatoshis = price * Q[i].satoshis;
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
                    if ( (price= prices[i]) != 0. && myutxo->S.satoshis >= Q[i].destsatoshis+Q[i].desttxfee )
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
                    } else printf("(%f %f) ",dstr(myutxo->S.satoshis),dstr(Q[i].destsatoshis));
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
                        Q[i].desttxid = myutxo->payment.txid;
                        Q[i].destvout = myutxo->payment.vout;
                        Q[i].feetxid = myutxo->fee.txid;
                        Q[i].feevout = myutxo->fee.vout;
                        strcpy(Q[i].destaddr,myutxo->coinaddr);
                        price = LP_query("request",&Q[i],base,myutxo->coin,myutxo->S.mypub);
                        if ( jobj(bestitem,"price") != 0 )
                            jdelete(bestitem,"price");
                        jaddnum(bestitem,"price",prices[i]);
                        if ( price <= maxprice )
                        {
                            Q[i].desttxid = myutxo->payment.txid;
                            Q[i].destvout = myutxo->payment.vout;
                            Q[i].feetxid = myutxo->fee.txid;
                            Q[i].feevout = myutxo->fee.vout;
                            strcpy(Q[i].destaddr,myutxo->coinaddr);
                            price = LP_query("connect",&Q[i],base,myutxo->coin,myutxo->S.mypub);
                            LP_requestinit(&R,Q[i].srchash,Q[i].desthash,base,Q[i].satoshis,Q[i].destcoin,Q[i].destsatoshis,Q[i].timestamp,Q[i].quotetime,DEXselector);
                            jaddstr(bestitem,"status","connected");
                            jaddnum(bestitem,"requestid",R.requestid);
                            jaddnum(bestitem,"quoteid",R.quoteid);
                            printf("Alice r.%u q.%u\n",R.requestid,R.quoteid);
                        }
                        else
                        {
                            jaddstr(bestitem,"status","too expensive");
                            jaddnum(bestitem,"price",price);
                            jaddnum(bestitem,"maxprice",maxprice);
                            jaddnum(bestitem,"bestprice",bestprice);
                        }
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




