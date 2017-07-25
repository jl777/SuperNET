
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
//  LP_ordermatch.c
//  marketmaker
//

uint64_t LP_txfeecalc(char *symbol,uint64_t txfee)
{
    struct iguana_info *coin;
    if ( strcmp(symbol,"BTC") == 0 )
    {
        if ( txfee == 0 && (txfee= LP_getestimatedrate(symbol) * LP_AVETXSIZE) < LP_MIN_TXFEE )
            txfee = LP_MIN_TXFEE;
    }
    else if ( (coin= LP_coinfind(symbol)) != 0 )
        txfee = coin->txfee;
    if ( txfee < LP_MIN_TXFEE )
        txfee = LP_MIN_TXFEE;
    return(txfee);
}

void LP_txfees(uint64_t *txfeep,uint64_t *desttxfeep,char *base,char *rel)
{
    *txfeep = LP_txfeecalc(base,0);
    *desttxfeep = LP_txfeecalc(rel,0);
}

double LP_qprice_calc(int64_t *destsatoshisp,int64_t *satoshisp,double price,uint64_t b_satoshis,uint64_t txfee,uint64_t a_value,uint64_t maxdestsatoshis,uint64_t desttxfee)
{
    uint64_t destsatoshis,satoshis;
    a_value -= (desttxfee + 1);
    destsatoshis = ((b_satoshis - txfee) * price);
    if ( destsatoshis > a_value )
        destsatoshis = a_value;
    if ( maxdestsatoshis != 0 && destsatoshis > maxdestsatoshis-desttxfee-1 )
        destsatoshis = maxdestsatoshis-desttxfee-1;
    satoshis = (destsatoshis / price + 0.49) - txfee;
    *destsatoshisp = destsatoshis;
    *satoshisp = satoshis;
    if ( satoshis > 0 )
        return((double)destsatoshis / satoshis);
    else return(0.);
}

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
    printf("r.%u %u, q.%u %u: %s %.8f -> %s %.8f\n",rp->timestamp,rp->requestid,rp->quotetime,rp->quoteid,rp->src,dstr(rp->srcamount),rp->dest,dstr(rp->destamount));
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
            price = (double)qp->destsatoshis / qp->satoshis;
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

int32_t LP_quoteinfoinit(struct LP_quoteinfo *qp,struct LP_utxoinfo *utxo,char *destcoin,double price,uint64_t satoshis,uint64_t destsatoshis)
{
    memset(qp,0,sizeof(*qp));
    if ( qp->timestamp == 0 )
        qp->timestamp = (uint32_t)time(NULL);
    safecopy(qp->destcoin,destcoin,sizeof(qp->destcoin));
    LP_txfees(&qp->txfee,&qp->desttxfee,utxo->coin,qp->destcoin);
    qp->satoshis = satoshis;//(destsatoshis / price) + 0.49;
    qp->destsatoshis = destsatoshis;
    if ( utxo->iambob == 0 || qp->txfee >= qp->satoshis || qp->txfee >= utxo->deposit.value || utxo->deposit.value < LP_DEPOSITSATOSHIS(qp->satoshis) )
    {
        printf("quoteinit error.(%d %d %d %d) %.8f vs %.8f\n",utxo->iambob == 0,qp->txfee >= qp->satoshis,qp->txfee >= utxo->deposit.value,utxo->deposit.value < LP_DEPOSITSATOSHIS(qp->satoshis),dstr(utxo->deposit.value),dstr(LP_DEPOSITSATOSHIS(qp->satoshis)));
        return(-1);
    }
    qp->txid = utxo->payment.txid;
    qp->vout = utxo->payment.vout;
    qp->txid2 = utxo->deposit.txid;
    qp->vout2 = utxo->deposit.vout;
    if ( qp->desttxfee >= qp->destsatoshis )
    {
        printf("quoteinit desttxfee %.8f < %.8f destsatoshis\n",dstr(qp->desttxfee),dstr(qp->destsatoshis));
        return(-2);
    }
    safecopy(qp->srccoin,utxo->coin,sizeof(qp->srccoin));
    safecopy(qp->coinaddr,utxo->coinaddr,sizeof(qp->coinaddr));
    qp->srchash = utxo->pubkey;
    return(0);
}

int32_t LP_quotedestinfo(struct LP_quoteinfo *qp,bits256 desttxid,int32_t destvout,bits256 feetxid,int32_t feevout,bits256 desthash,char *destaddr)
{
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
    price = (double)Q.destsatoshis / Q.satoshis;
    if ( (ptr= LP_cacheadd(Q.srccoin,Q.destcoin,Q.txid,Q.vout,price,&Q)) != 0 )
    {
        ptr->Q = Q;
        printf(">>>>>>>>>> received quote %s/%s %.8f\n",Q.srccoin,Q.destcoin,price);
        return(clonestr("{\"result\":\"updated\"}"));
    } else return(clonestr("{\"error\":\"nullptr\"}"));
}

char *LP_pricepings(void *ctx,char *myipaddr,int32_t pubsock,char *base,char *rel,double price)
{
    bits256 zero; char *msg; cJSON *reqjson = cJSON_CreateObject();
    memset(zero.bytes,0,sizeof(zero));
    jaddbits256(reqjson,"pubkey",LP_mypub25519);
    jaddstr(reqjson,"base",base);
    jaddstr(reqjson,"rel",rel);
    jaddnum(reqjson,"price",price);
    jaddstr(reqjson,"method","postprice");
    msg = jprint(reqjson,1);
    LP_broadcast_message(pubsock,base,rel,zero,msg);
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

int32_t LP_quote_checkmempool(struct LP_quoteinfo *qp)
{
    int32_t selector,spendvini; bits256 spendtxid;
    if ( (selector= LP_mempool_vinscan(&spendtxid,&spendvini,qp->srccoin,qp->txid,qp->vout,qp->txid2,qp->vout2)) >= 0 )
    {
        char str[65]; printf("LP_tradecommand selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
        return(-1);
    }
    if ( (selector= LP_mempool_vinscan(&spendtxid,&spendvini,qp->destcoin,qp->desttxid,qp->destvout,qp->feetxid,qp->feevout)) >= 0 )
    {
        char str[65]; printf("LP_tradecommand dest selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
        return(-1);
    }
    return(0);
}

double LP_quote_validate(struct LP_utxoinfo **autxop,struct LP_utxoinfo **butxop,struct LP_quoteinfo *qp,int32_t iambob)
{
    double qprice; uint64_t txfee,desttxfee,srcvalue,srcvalue2,destvalue,destvalue2;
    *autxop = *butxop = 0;
    if ( LP_iseligible(&srcvalue,&srcvalue2,1,qp->srccoin,qp->txid,qp->vout,qp->satoshis,qp->txid2,qp->vout2) == 0 )
    {
        printf("bob not eligible\n");
        return(-2);
    }
    if ( LP_iseligible(&destvalue,&destvalue2,0,qp->destcoin,qp->desttxid,qp->destvout,qp->destsatoshis,qp->feetxid,qp->feevout) == 0 )
    {
        char str[65]; printf("alice not eligible (%.8f %.8f) %s/v%d\n",dstr(destvalue),dstr(destvalue2),bits256_str(str,qp->feetxid),qp->feevout);
        return(-3);
    }
    if ( LP_quote_checkmempool(qp) < 0 )
        return(-4);
    if ( (*butxop= LP_utxofind(1,qp->txid,qp->vout)) == 0 )
        return(-5);
    if ( bits256_cmp((*butxop)->deposit.txid,qp->txid2) != 0 || (*butxop)->deposit.vout != qp->vout2 )
        return(-6);
    if ( strcmp((*butxop)->coinaddr,qp->coinaddr) != 0 )
        return(-7);
    if ( iambob == 0 )
    {
        if ( (*autxop= LP_utxofind(0,qp->desttxid,qp->destvout)) == 0 )
            return(-8);
        if ( bits256_cmp((*autxop)->fee.txid,qp->feetxid) != 0 || (*autxop)->fee.vout != qp->feevout )
            return(-9);
        if ( strcmp((*autxop)->coinaddr,qp->destaddr) != 0 )
            return(-10);
    }
    if ( destvalue < qp->desttxfee+qp->destsatoshis || srcvalue < qp->txfee+qp->satoshis )
    {
        printf("destvalue %.8f srcvalue %.8f, destsatoshis %.8f or satoshis %.8f is too small txfees %.8f %.8f?\n",dstr(destvalue),dstr(srcvalue),dstr(qp->destsatoshis),dstr(qp->satoshis),dstr(qp->desttxfee),dstr(qp->txfee));
        return(-11);
    }
    qprice = ((double)qp->destsatoshis / qp->satoshis);
    if ( qp->satoshis < (srcvalue / LP_MINVOL) || srcvalue < qp->txfee*LP_MINSIZE_TXFEEMULT )
    {
        printf("utxo payment %.8f is less than %f covered by Q %.8f or <10x txfee %.8f\n",dstr(srcvalue),1./LP_MINVOL,dstr(qp->satoshis),dstr(qp->txfee));
        return(-12);
    }
    if ( qp->destsatoshis < (destvalue / LP_MINCLIENTVOL) || destvalue < qp->desttxfee*LP_MINSIZE_TXFEEMULT )
    {
        printf("destsatoshis %.8f is less than %f of value %.8f or < 10x txfee %.8f\n",dstr(qp->destsatoshis),1./LP_MINCLIENTVOL,dstr(destvalue),dstr(qp->desttxfee));
        return(-13);
    }
    LP_txfees(&txfee,&desttxfee,qp->srccoin,qp->destcoin);
    printf("qprice %.8f <- %.8f/%.8f txfees.(%.8f %.8f) vs (%.8f %.8f)\n",qprice,dstr(qp->destsatoshis),dstr(qp->satoshis),dstr(qp->txfee),dstr(qp->desttxfee),dstr(txfee),dstr(desttxfee));
    if ( qp->txfee < LP_REQUIRED_TXFEE*txfee || qp->desttxfee < LP_REQUIRED_TXFEE*desttxfee )
        return(-14);
    return(qprice);
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

double LP_query(void *ctx,char *myipaddr,int32_t mypubsock,char *method,struct LP_quoteinfo *qp)
{
    cJSON *reqjson; char *msg; int32_t i,flag = 0; double price = 0.; struct LP_utxoinfo *utxo;
    if ( strcmp(method,"request") == 0 )
    {
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
    jaddbits256(reqjson,"pubkey",qp->srchash);
    jaddstr(reqjson,"method",method);
    msg = jprint(reqjson,1);
    printf("QUERY.(%s)\n",msg);
    LP_broadcast_message(LP_mypubsock,qp->srccoin,qp->destcoin,qp->srchash,msg);
    for (i=0; i<30; i++)
    {
        if ( (price= LP_pricecache(qp,qp->srccoin,qp->destcoin,qp->txid,qp->vout)) > SMALLVAL )
        {
            if ( flag == 0 || bits256_nonz(qp->desthash) != 0 )
            {
                printf("break out of loop.%d price %.8f %s/%s\n",i,price,qp->srccoin,qp->destcoin);
                break;
            }
        }
        usleep(100000);
    }
    return(price);
}

int32_t LP_nanobind(void *ctx,char *pairstr)
{
    int32_t i,r,pairsock = -1; uint16_t mypullport; char bindaddr[128];
    if ( LP_canbind != 0 )
    {
        if ( (pairsock= nn_socket(AF_SP,NN_PAIR)) < 0 )
            printf("error creating utxo->pair\n");
        else
        {
            for (i=0; i<10; i++)
            {
                r = (10000 + (rand() % 50000)) & 0xffff;
                if ( LP_fixed_pairport != 0 )
                    r = LP_fixed_pairport;
                nanomsg_transportname(0,pairstr,LP_myipaddr,r);
                nanomsg_transportname(1,bindaddr,LP_myipaddr,r);
                if ( nn_bind(pairsock,bindaddr) >= 0 )
                {
                    //timeout = 1;
                    //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                    //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                    printf("nanobind %s to %d\n",pairstr,pairsock);
                    return(pairsock);
                } else printf("error binding to %s for %s\n",bindaddr,pairstr);
                if ( LP_fixed_pairport != 0 )
                    break;
            }
        }
    } else pairsock = LP_initpublicaddr(ctx,&mypullport,pairstr,"127.0.0.1",0,1);
    return(pairsock);
}

int32_t LP_connectstartbob(void *ctx,int32_t pubsock,struct LP_utxoinfo *utxo,cJSON *argjson,char *base,char *rel,double price,struct LP_quoteinfo *qp)
{
    char pairstr[512],*msg; cJSON *retjson; bits256 privkey; int32_t pair=-1,retval = -1,DEXselector = 0; struct basilisk_swap *swap; struct iguana_info *coin;
    printf("LP_connectstartbob.(%s) with.(%s) %s\n",LP_myipaddr,jprint(argjson,0),LP_myipaddr);
    qp->quotetime = (uint32_t)time(NULL);
    if ( (coin= LP_coinfind(utxo->coin)) == 0 )
    {
        printf("cant find coin.%s\n",utxo->coin);
        return(-1);
    }
    privkey = LP_privkey(utxo->coinaddr,coin->taddr);
    if ( bits256_nonz(privkey) != 0 && qp->quotetime >= qp->timestamp-3 && qp->quotetime <= utxo->T.swappending && bits256_cmp(LP_mypub25519,qp->srchash) == 0 )
    {
        if ( (pair= LP_nanobind(ctx,pairstr)) >= 0 )
        {
            LP_requestinit(&qp->R,qp->srchash,qp->desthash,base,qp->satoshis-qp->txfee,rel,qp->destsatoshis-qp->desttxfee,qp->timestamp,qp->quotetime,DEXselector);
            swap = LP_swapinit(1,0,privkey,&qp->R,qp);
            swap->N.pair = pair;
            utxo->S.swap = swap;
            swap->utxo = utxo;
            if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_bobloop,(void *)swap) == 0 )
            {
                retjson = LP_quotejson(qp);
                jaddstr(retjson,"method","connected");
                jaddstr(retjson,"pair",pairstr);
                jaddnum(retjson,"requestid",qp->R.requestid);
                jaddnum(retjson,"quoteid",qp->R.quoteid);
                char str[65]; printf("BOB pubsock.%d binds to %d (%s)\n",pubsock,pair,bits256_str(str,utxo->S.otherpubkey));
                msg = jprint(retjson,1);
                LP_broadcast_message(pubsock,base,rel,utxo->S.otherpubkey,msg);
                retval = 0;
            } else printf("error launching swaploop\n");
        } else printf("couldnt bind to any port %s\n",pairstr);
    }
    else
    {
        printf("dest %.8f vs required %.8f (%d %d %d %d %d)\n",dstr(qp->destsatoshis),dstr(price*(utxo->S.satoshis-qp->txfee)),bits256_nonz(privkey) != 0 ,qp->timestamp == utxo->T.swappending-LP_RESERVETIME,qp->quotetime >= qp->timestamp-3,qp->quotetime < utxo->T.swappending,bits256_cmp(LP_mypub25519,qp->srchash) == 0);
    }
    if ( retval < 0 )
    {
        if ( pair >= 0 )
            nn_close(pair);
        LP_availableset(utxo);
    } else LP_unavailableset(utxo,utxo->S.otherpubkey);
    return(retval);
}

char *LP_connectedalice(cJSON *argjson) // alice
{
    cJSON *retjson; double bid,ask,price,qprice; int32_t pairsock = -1; char *pairstr; int32_t DEXselector = 0; struct LP_utxoinfo *autxo,*butxo; struct LP_quoteinfo Q; struct basilisk_swap *swap; struct iguana_info *coin;
    if ( LP_quoteparse(&Q,argjson) < 0 )
        clonestr("{\"error\":\"cant parse quote\"}");
    if ( bits256_cmp(Q.desthash,LP_mypub25519) != 0 )
        return(clonestr("{\"result\",\"update stats\"}"));
    printf("CONNECTED.(%s)\n",jprint(argjson,0));
    if ( (qprice= LP_quote_validate(&autxo,&butxo,&Q,0)) <= SMALLVAL )
    {
        LP_availableset(autxo);
        LP_pendingswaps--;
        printf("quote validate error %.0f\n",qprice);
        return(clonestr("{\"error\":\"quote validation error\"}"));
    }
    if ( LP_myprice(&bid,&ask,Q.srccoin,Q.destcoin) <= SMALLVAL || bid <= SMALLVAL )
    {
        printf("this node has no price for %s/%s (%.8f %.8f)\n",Q.destcoin,Q.srccoin,bid,ask);
        LP_availableset(autxo);
        LP_pendingswaps--;
        return(clonestr("{\"error\":\"no price set\"}"));
    }
    printf("%s/%s bid %.8f ask %.8f\n",Q.srccoin,Q.destcoin,bid,ask);
    //if ( (price= ask) == 0. )
        price = bid;
    /*if ( SATOSHIDEN*qprice > (SATOSHIDEN * price) * 1.001 + 10 )
    {
        printf("qprice %.8f too big vs %.8f\n",qprice,price);
        LP_availableset(autxo);
        LP_pendingswaps--;
        return(clonestr("{\"error\":\"quote price too expensive\"}"));
    }*/
    if ( (coin= LP_coinfind(Q.destcoin)) == 0 )
    {
        LP_pendingswaps--;
        return(clonestr("{\"error\":\"cant get alicecoin\"}"));
    }
    Q.privkey = LP_privkey(Q.destaddr,coin->taddr);
    if ( bits256_nonz(Q.privkey) != 0 && Q.quotetime >= Q.timestamp-3 )
    {
        retjson = cJSON_CreateObject();
        if ( (pairstr= jstr(argjson,"pair")) == 0 || (pairsock= nn_socket(AF_SP,NN_PAIR)) < 0 )
            jaddstr(retjson,"error","couldnt create pairsock");
        else if ( nn_connect(pairsock,pairstr) >= 0 )
        {
            //timeout = 1;
            //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
            //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
            LP_requestinit(&Q.R,Q.srchash,Q.desthash,Q.srccoin,Q.satoshis-Q.txfee,Q.destcoin,Q.destsatoshis-Q.desttxfee,Q.timestamp,Q.quotetime,DEXselector);
            swap = LP_swapinit(0,0,Q.privkey,&Q.R,&Q);
            swap->N.pair = pairsock;
            autxo->S.swap = swap;
            swap->utxo = autxo;
            printf("alice pairstr.(%s) pairsock.%d\n",pairstr,pairsock);
            if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_aliceloop,(void *)swap) == 0 )
            {
                jaddstr(retjson,"result","success");
                jadd(retjson,"trade",LP_quotejson(&Q));
                jaddnum(retjson,"requestid",Q.R.requestid);
                jaddnum(retjson,"quoteid",Q.R.quoteid);
            } else jaddstr(retjson,"error","couldnt aliceloop");
        } else printf("connect error %s\n",nn_strerror(nn_errno()));
        printf("connected result.(%s)\n",jprint(retjson,0));
        if ( jobj(retjson,"error") != 0 )
            LP_availableset(autxo);
        else LP_pendingswaps++;
        return(jprint(retjson,1));
    }
    else
    {
        LP_availableset(autxo);
        printf("no privkey found\n");
        return(clonestr("{\"error\",\"no privkey\"}"));
    }
}

int32_t LP_tradecommand(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen)
{
    char *method,*msg; cJSON *retjson; double qprice,price,bid,ask; struct LP_utxoinfo *autxo,*butxo; int32_t retval = -1; struct LP_quoteinfo Q;
    if ( (method= jstr(argjson,"method")) != 0 && (strcmp(method,"request") == 0 ||strcmp(method,"connect") == 0) )
    {
        printf("TRADECOMMAND.(%s)\n",jprint(argjson,0));
        retval = 1;
        if ( LP_quoteparse(&Q,argjson) == 0 && bits256_cmp(LP_mypub25519,Q.srchash) == 0 )
        {
            if ( (price= LP_myprice(&bid,&ask,Q.srccoin,Q.destcoin)) <= SMALLVAL || ask <= SMALLVAL )
            {
                printf("this node has no price for %s/%s\n",Q.srccoin,Q.destcoin);
                return(-3);
            }
            price = ask;
            if ( (qprice= LP_quote_validate(&autxo,&butxo,&Q,1)) <= SMALLVAL )
            {
                printf("quote validate error %.0f\n",qprice);
                return(-4);
            }
            if ( qprice < (price - 0.00000001) * 0.9999 )
            {
                printf("(%.8f %.8f) quote price %.8f too low vs %.8f for %s/%s\n",bid,ask,qprice,price,Q.srccoin,Q.destcoin);
                return(-5);
            }
            if ( butxo->S.swap == 0 && time(NULL) > butxo->T.swappending )
                butxo->T.swappending = 0;
            if ( strcmp(method,"request") == 0 ) // bob needs apayment + fee tx's
            {
                if ( LP_isavailable(butxo) > 0 )
                {
                    butxo->T.swappending = Q.timestamp + LP_RESERVETIME;
                    retjson = LP_quotejson(&Q);
                    butxo->S.otherpubkey = jbits256(argjson,"desthash");
                    LP_unavailableset(butxo,butxo->S.otherpubkey);
                    jaddnum(retjson,"quotetime",juint(argjson,"quotetime"));
                    jaddnum(retjson,"pending",butxo->T.swappending);
                    jaddbits256(retjson,"desthash",butxo->S.otherpubkey);
                    jaddbits256(retjson,"pubkey",butxo->S.otherpubkey);
                    jaddstr(retjson,"method","reserved");
                    msg = jprint(retjson,1);
                    printf("set swappending.%u accept qprice %.8f, min %.8f\n(%s)",butxo->T.swappending,qprice,price,msg);
                    LP_broadcast_message(pubsock,Q.srccoin,Q.destcoin,butxo->S.otherpubkey,msg);
                    butxo->T.lasttime = (uint32_t)time(NULL);
                } else printf("warning swappending.%u swap.%p\n",butxo->T.swappending,butxo->S.swap);
            }
            else if ( strcmp(method,"connect") == 0 ) // bob
            {
                retval = 4;
                if ( butxo->T.swappending != 0 && butxo->S.swap == 0 )
                    LP_connectstartbob(ctx,pubsock,butxo,argjson,Q.srccoin,Q.destcoin,qprice,&Q);
                else printf("pend.%u swap %p when connect came in (%s)\n",butxo->T.swappending,butxo->S.swap,jprint(argjson,0));
            }
        }
    }
    return(retval);
}

struct LP_utxoinfo *LP_bestutxo(double *ordermatchpricep,int64_t *bestsatoshisp,int64_t *bestdestsatoshisp,struct LP_utxoinfo *autxo,char *base,double maxprice,int32_t duration,uint64_t txfee,uint64_t desttxfee,uint64_t maxdestsatoshis)
{
    int64_t satoshis,destsatoshis; uint64_t val,val2; bits256 txid,pubkey; char *obookstr; cJSON *orderbook,*asks,*item; struct LP_utxoinfo *butxo,*bestutxo = 0; int32_t i,n,j,vout,numasks; double bestmetric=0.,metric,vol,price,qprice,bestprice = 0.; struct LP_pubkeyinfo *pubp;
    *ordermatchpricep = 0.;
    *bestsatoshisp = *bestdestsatoshisp = 0;
    if ( duration <= 0 )
        duration = LP_ORDERBOOK_DURATION;
    if ( maxprice <= 0. || LP_priceinfofind(base) == 0 )
        return(0);
    LP_txfees(&txfee,&desttxfee,base,autxo->coin);
    if ( (obookstr= LP_orderbook(base,autxo->coin,duration)) != 0 )
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
                        price *= 1.0001;
                        if ( price > maxprice )
                            price = maxprice;
                        pubkey = jbits256(item,"pubkey");
                        if ( bits256_cmp(pubkey,LP_mypub25519) != 0 && (pubp= LP_pubkeyadd(pubkey)) != 0 && pubp->numerrors < LP_MAXPUBKEY_ERRORS )
                        {
                            if ( bestprice == 0. ) // assumes price ordered asks
                                bestprice = price;
                            //printf("item.[%d] %s\n",i,jprint(item,0));
                            txid = jbits256(item,"txid");
                            vout = jint(item,"vout");
                            vol = jdouble(item,"volume");
                            metric = price / bestprice;
                            if ( (butxo= LP_utxofind(1,txid,vout)) != 0 && (long long)(vol*SATOSHIDEN) == butxo->S.satoshis && LP_isavailable(butxo) > 0 && LP_ismine(butxo) == 0 )//&& butxo->T.bestflag == 0 )
                            {
                                if ( LP_iseligible(&val,&val2,butxo->iambob,butxo->coin,butxo->payment.txid,butxo->payment.vout,butxo->S.satoshis,butxo->deposit.txid,butxo->deposit.vout) > 0 )
                                {
                                    destsatoshis = ((butxo->S.satoshis - txfee) * price);
                                    satoshis = (destsatoshis / price + 0.49) - txfee;
                                    if ( satoshis <= 0 )
                                        continue;
                                    qprice = (double)destsatoshis / satoshis;
                                    n = (int32_t)((double)destsatoshis / desttxfee);
                                    if ( n < 10 )
                                        n = 10;
                                    else n = 3;
                                    for (j=0; j<n; j++)
                                    {
                                        if ( (qprice= LP_qprice_calc(&destsatoshis,&satoshis,(price*(100.+j))/100.,butxo->S.satoshis,txfee,autxo->payment.value,maxdestsatoshis,desttxfee)) > price+SMALLVAL )
                                            break;
                                    }
                                    //printf("j.%d/%d qprice %.8f vs price %.8f best.(%.8f %.8f)\n",j,n,qprice,price,dstr(satoshis),dstr(destsatoshis));
                                    if ( metric < 1.2 && destsatoshis > desttxfee && destsatoshis-desttxfee > (autxo->payment.value / LP_MINCLIENTVOL) && satoshis-txfee > (butxo->S.satoshis / LP_MINVOL) && satoshis <= butxo->payment.value-txfee )
                                    {
                                        printf("value %.8f price %.8f/%.8f best %.8f destsatoshis %.8f * metric %.8f -> (%f)\n",dstr(autxo->payment.value),price,bestprice,bestmetric,dstr(destsatoshis),metric,dstr(destsatoshis) * metric * metric * metric);
                                        metric = dstr(destsatoshis) * metric * metric * metric;
                                        if ( bestmetric == 0. || metric < bestmetric )
                                        {
                                            bestutxo = butxo;
                                            *ordermatchpricep = price;
                                            *bestdestsatoshisp = destsatoshis;
                                            *bestsatoshisp = satoshis;
                                            bestmetric = metric;
                                            printf("set best!\n");
                                        }
                                    } else printf("skip.(%d %d %d %d %d) metric %f destsatoshis %.8f value %.8f destvalue %.8f txfees %.8f %.8f sats %.8f\n",metric < 1.2,destsatoshis > desttxfee,destsatoshis-desttxfee > (autxo->payment.value / LP_MINCLIENTVOL),satoshis-txfee > (butxo->S.satoshis / LP_MINVOL),satoshis < butxo->payment.value-txfee,metric,dstr(destsatoshis),dstr(butxo->S.satoshis),dstr(autxo->payment.value),dstr(txfee),dstr(desttxfee),dstr(satoshis));
                                }
                                else
                                {
                                    printf("ineligible.(%.8f %.8f)\n",price,dstr(butxo->S.satoshis));
                                    if ( butxo->T.spentflag == 0 )
                                        butxo->T.spentflag = (uint32_t)time(NULL);
                                }
                            }
                            else
                            {
                                if ( butxo != 0 )
                                    printf("%llu %llu %d %d %d: ",(long long)(vol*SATOSHIDEN),(long long)butxo->S.satoshis,vol*SATOSHIDEN == butxo->S.satoshis,LP_isavailable(butxo) > 0,LP_ismine(butxo) == 0);
                                printf("cant find butxo.%p or value mismatch %.8f != %.8f or bestflag.%d\n",butxo,vol,butxo!=0?dstr(butxo->S.satoshis):0,butxo->T.bestflag);
                            }
                        } else printf("self trading or blacklisted peer\n");
                    }
                    else
                    {
                        printf("maxprice %.8f vs %.8f\n",maxprice,price);
                        break;
                    }
                }
            }
            free_json(orderbook);
        }
        free(obookstr);
    }
    if ( bestutxo == 0 || *ordermatchpricep == 0. || *bestdestsatoshisp == 0 )
        return(0);
    int32_t changed;
    LP_mypriceset(&changed,autxo->coin,base,1. / *ordermatchpricep);
    return(bestutxo);
}

char *LP_bestfit(char *rel,double relvolume)
{
    struct LP_utxoinfo *autxo;
    if ( relvolume <= 0. || LP_priceinfofind(rel) == 0 )
        return(clonestr("{\"error\":\"invalid parameter\"}"));
    if ( (autxo= LP_utxo_bestfit(rel,SATOSHIDEN * relvolume)) == 0 )
        return(clonestr("{\"error\":\"cant find utxo that is big enough\"}"));
    return(jprint(LP_utxojson(autxo),1));
}

char *LP_ordermatch(char *base,int64_t txfee,double maxprice,double maxvolume,char *rel,bits256 txid,int32_t vout,bits256 feetxid,int32_t feevout,int64_t desttxfee,int32_t duration)
{
    struct LP_quoteinfo Q; int64_t bestsatoshis=0,bestdestsatoshis = 0; double ordermatchprice = 0.; struct LP_utxoinfo *autxo,*bestutxo;
    txfee = LP_txfeecalc(base,txfee);
    desttxfee = LP_txfeecalc(rel,desttxfee);
    if ( (autxo= LP_utxopairfind(0,txid,vout,feetxid,feevout)) == 0 )
        return(clonestr("{\"error\":\"cant find alice utxopair\"}"));
    if ( (bestutxo= LP_bestutxo(&ordermatchprice,&bestsatoshis,&bestdestsatoshis,autxo,base,maxprice,duration,txfee,desttxfee,SATOSHIDEN*maxvolume)) == 0 || ordermatchprice == 0. || bestdestsatoshis == 0 )
        return(clonestr("{\"error\":\"cant find ordermatch utxo\"}"));
    if ( LP_quoteinfoinit(&Q,bestutxo,rel,ordermatchprice,bestsatoshis,bestdestsatoshis) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote\"}"));
    if ( LP_quotedestinfo(&Q,autxo->payment.txid,autxo->payment.vout,autxo->fee.txid,autxo->fee.vout,LP_mypub25519,autxo->coinaddr) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote info\"}"));
    return(jprint(LP_quotejson(&Q),1));
}

char *LP_trade(void *ctx,char *myipaddr,int32_t mypubsock,struct LP_quoteinfo *qp,double maxprice,int32_t timeout,int32_t duration)
{
    struct LP_utxoinfo *bobutxo,*aliceutxo; cJSON *bestitem=0; int32_t DEXselector=0; uint32_t expiration; double price; struct LP_pubkeyinfo *pubp;
    if ( (aliceutxo= LP_utxopairfind(0,qp->desttxid,qp->destvout,qp->feetxid,qp->feevout)) == 0 )
    {
        char str[65],str2[65]; printf("dest.(%s)/v%d fee.(%s)/v%d\n",bits256_str(str,qp->desttxid),qp->destvout,bits256_str(str2,qp->feetxid),qp->feevout);
        return(clonestr("{\"error\":\"cant find alice utxopair\"}"));
    }
    if ( (bobutxo= LP_utxopairfind(1,qp->txid,qp->vout,qp->txid2,qp->vout2)) == 0 )
        return(clonestr("{\"error\":\"cant find bob utxopair\"}"));
    bobutxo->T.bestflag = (uint32_t)time(NULL);
    //if ( (retstr= LP_registerall(0)) != 0 )
    //    free(retstr);
    price = LP_query(ctx,myipaddr,mypubsock,"request",qp);
    bestitem = LP_quotejson(qp);
    if ( LP_pricevalid(price) > 0 )
    {
        if ( price <= maxprice )
        {
            price = LP_query(ctx,myipaddr,mypubsock,"connect",qp);
            LP_requestinit(&qp->R,qp->srchash,qp->desthash,bobutxo->coin,qp->satoshis-qp->txfee,qp->destcoin,qp->destsatoshis-qp->desttxfee,qp->timestamp,qp->quotetime,DEXselector);
            expiration = (uint32_t)time(NULL) + timeout;
            while ( time(NULL) < expiration )
            {
                if ( aliceutxo->S.swap != 0 )
                    break;
                sleep(1);
            }
            if ( aliceutxo->S.swap == 0 )
            {
                if ( (pubp= LP_pubkeyadd(bobutxo->pubkey)) != 0 )
                    pubp->numerrors++;
                jaddstr(bestitem,"status","couldnt establish connection");
            } else jaddstr(bestitem,"status","connected");
            jaddnum(bestitem,"quotedprice",price);
            jaddnum(bestitem,"maxprice",maxprice);
            jaddnum(bestitem,"requestid",qp->R.requestid);
            jaddnum(bestitem,"quoteid",qp->R.quoteid);
            printf("Alice r.%u qp->%u\n",qp->R.requestid,qp->R.quoteid);
        }
        else
        {
            jaddnum(bestitem,"quotedprice",price);
            jaddnum(bestitem,"maxprice",maxprice);
            jaddstr(bestitem,"status","too expensive");
        }
    }
    else
    {
        jaddnum(bestitem,"maxprice",maxprice);
        jaddstr(bestitem,"status","no response to request");
    }
    if ( aliceutxo->S.swap == 0 )
        LP_availableset(aliceutxo);
    return(jprint(bestitem,0));
}

char *LP_autotrade(void *ctx,char *myipaddr,int32_t mypubsock,char *base,char *rel,double maxprice,double relvolume,int32_t timeout,int32_t duration)
{
    uint64_t desttxfee,txfee; int64_t bestsatoshis=0,bestdestsatoshis=0; struct LP_utxoinfo *autxo,*butxo,*bestutxo = 0; double qprice,ordermatchprice=0.; struct LP_quoteinfo Q;
    if ( duration <= 0 )
        duration = LP_ORDERBOOK_DURATION;
    if ( timeout <= 0 )
        timeout = LP_AUTOTRADE_TIMEOUT;
    if ( maxprice <= 0. || relvolume <= 0. || LP_priceinfofind(base) == 0 || LP_priceinfofind(rel) == 0 )
        return(clonestr("{\"error\":\"invalid parameter\"}"));
    if ( (autxo= LP_utxo_bestfit(rel,SATOSHIDEN * relvolume)) == 0 )
        return(clonestr("{\"error\":\"cant find utxo that is big enough\"}"));
    LP_txfees(&txfee,&desttxfee,base,rel);
    if ( (bestutxo= LP_bestutxo(&ordermatchprice,&bestsatoshis,&bestdestsatoshis,autxo,base,maxprice,duration,txfee,desttxfee,SATOSHIDEN*relvolume)) == 0 || ordermatchprice == 0. || bestdestsatoshis == 0 )
    {
        printf("bestutxo.%p ordermatchprice %.8f bestdestsatoshis %.8f\n",bestutxo,ordermatchprice,dstr(bestdestsatoshis));
        return(clonestr("{\"error\":\"cant find ordermatch utxo\"}"));
    }
    if ( LP_quoteinfoinit(&Q,bestutxo,rel,ordermatchprice,bestsatoshis,bestdestsatoshis) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote\"}"));
    if ( LP_quotedestinfo(&Q,autxo->payment.txid,autxo->payment.vout,autxo->fee.txid,autxo->fee.vout,LP_mypub25519,autxo->coinaddr) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote info\"}"));
    if ( (qprice= LP_quote_validate(&autxo,&butxo,&Q,0)) <= SMALLVAL )
    {
        printf("quote validate error %.0f\n",qprice);
        return(clonestr("{\"error\":\"quote validation error\"}"));
    }
    printf("do quote.(%s)\n",jprint(LP_quotejson(&Q),1));
    return(LP_trade(ctx,myipaddr,mypubsock,&Q,maxprice,timeout,duration));
}




