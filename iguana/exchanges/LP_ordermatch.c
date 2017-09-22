
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

uint64_t LP_txfeecalc(struct iguana_info *coin,uint64_t txfee)
{
    if ( coin != 0 )
    {
        if ( strcmp(coin->symbol,"BTC") == 0 )
        {
            if ( txfee == 0 && (txfee= LP_getestimatedrate(coin) * LP_AVETXSIZE) < LP_MIN_TXFEE )
                txfee = LP_MIN_TXFEE;
        }
        else txfee = coin->txfee;
        if ( txfee < LP_MIN_TXFEE )
            txfee = LP_MIN_TXFEE;
    }
    return(txfee);
}

void LP_txfees(uint64_t *txfeep,uint64_t *desttxfeep,char *base,char *rel)
{
    *txfeep = LP_txfeecalc(LP_coinfind(base),0);
    *desttxfeep = LP_txfeecalc(LP_coinfind(rel),0);
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
    /*if ( qp->txfee >= qp->satoshis || qp->txfee >= utxo->deposit.value || utxo->deposit.value < LP_DEPOSITSATOSHIS(qp->satoshis) ) //utxo->iambob == 0 ||
    {
        printf("quoteinit error.(%d %d %d %d) %.8f vs %.8f\n",utxo->iambob == 0,qp->txfee >= qp->satoshis,qp->txfee >= utxo->deposit.value,utxo->deposit.value < LP_DEPOSITSATOSHIS(qp->satoshis),dstr(utxo->deposit.value),dstr(LP_DEPOSITSATOSHIS(qp->satoshis)));
        return(-1);
    }*/
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
    jaddbits256(reqjson,"pubkey",G.LP_mypub25519);
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

int32_t LP_quote_checkmempool(struct LP_quoteinfo *qp,struct LP_utxoinfo *autxo,struct LP_utxoinfo *butxo)
{
    int32_t selector,spendvini; bits256 spendtxid;
    if ( butxo != 0 && (selector= LP_mempool_vinscan(&spendtxid,&spendvini,qp->srccoin,qp->coinaddr,qp->txid,qp->vout,qp->txid2,qp->vout2)) >= 0 )
    {
        char str[65]; printf("LP_tradecommand selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
        return(-1);
    }
    if ( autxo != 0 && (selector= LP_mempool_vinscan(&spendtxid,&spendvini,qp->destcoin,qp->destaddr,qp->desttxid,qp->destvout,qp->feetxid,qp->feevout)) >= 0 )
    {
        char str[65]; printf("LP_tradecommand dest selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
        return(-1);
    }
    return(0);
}

double LP_quote_validate(struct LP_utxoinfo *autxo,struct LP_utxoinfo *butxo,struct LP_quoteinfo *qp,int32_t iambob)
{
    double qprice=0.; uint64_t txfee,desttxfee,srcvalue=0,srcvalue2=0,destvalue=0,destvalue2=0;
    if ( butxo != 0 )
    {
        if (LP_iseligible(&srcvalue,&srcvalue2,1,qp->srccoin,qp->txid,qp->vout,qp->satoshis,qp->txid2,qp->vout2) == 0 )
        {
            printf("bob not eligible\n");
            return(-2);
        }
        if ( bits256_cmp(butxo->deposit.txid,qp->txid2) != 0 || butxo->deposit.vout != qp->vout2 )
            return(-6);
        if ( strcmp(butxo->coinaddr,qp->coinaddr) != 0 )
            return(-7);
    }
    if ( autxo != 0 && LP_iseligible(&destvalue,&destvalue2,0,qp->destcoin,qp->desttxid,qp->destvout,qp->destsatoshis,qp->feetxid,qp->feevout) == 0 )
    {
        char str[65]; printf("alice not eligible (%.8f %.8f) %s/v%d\n",dstr(destvalue),dstr(destvalue2),bits256_str(str,qp->feetxid),qp->feevout);
        return(-3);
    }
    if ( LP_quote_checkmempool(qp,autxo,butxo) < 0 )
        return(-4);
    //if ( iambob != 0 && (*butxop= LP_utxofind(1,qp->txid,qp->vout)) == 0 )
    //    return(-5);
    if ( iambob == 0 && autxo != 0 )
    {
        //if ( (*autxop= LP_utxofind(0,qp->desttxid,qp->destvout)) == 0 )
        //    return(-8);
        if ( bits256_cmp(autxo->fee.txid,qp->feetxid) != 0 || autxo->fee.vout != qp->feevout )
            return(-9);
        if ( strcmp(autxo->coinaddr,qp->destaddr) != 0 )
            return(-10);
    }
    if ( autxo != 0 && destvalue < qp->desttxfee+qp->destsatoshis )
    {
        printf("destvalue %.8f  destsatoshis %.8f is too small txfee %.8f?\n",dstr(destvalue),dstr(qp->destsatoshis),dstr(qp->desttxfee));
        return(-11);
    }
    if ( butxo != 0 && srcvalue < qp->txfee+qp->satoshis )
    {
        printf("srcvalue %.8f satoshis %.8f is too small txfee %.8f?\n",dstr(srcvalue),dstr(qp->satoshis),dstr(qp->txfee));
        return(-33);
    }
    if ( qp->satoshis != 0 )
        qprice = ((double)qp->destsatoshis / qp->satoshis);
    LP_txfees(&txfee,&desttxfee,qp->srccoin,qp->destcoin);
    printf("qprice %.8f <- %.8f/%.8f txfees.(%.8f %.8f) vs (%.8f %.8f)\n",qprice,dstr(qp->destsatoshis),dstr(qp->satoshis),dstr(qp->txfee),dstr(qp->desttxfee),dstr(txfee),dstr(desttxfee));
    if ( qp->txfee < LP_REQUIRED_TXFEE*txfee || qp->desttxfee < LP_REQUIRED_TXFEE*desttxfee )
        return(-14);
    if ( butxo != 0 )
    {
        if ( qp->satoshis < (srcvalue / LP_MINVOL) || srcvalue < qp->txfee*LP_MINSIZE_TXFEEMULT )
        {
            printf("utxo payment %.8f is less than %f covered by Q %.8f or <10x txfee %.8f\n",dstr(srcvalue),1./LP_MINVOL,dstr(qp->satoshis),dstr(qp->txfee));
            return(-12);
        }
    }
    if ( autxo != 0 )
    {
        if ( qp->destsatoshis < (destvalue / LP_MINCLIENTVOL) || destvalue < qp->desttxfee*LP_MINSIZE_TXFEEMULT )
        {
            printf("destsatoshis %.8f is less than %f of value %.8f or < 10x txfee %.8f\n",dstr(qp->destsatoshis),1./LP_MINCLIENTVOL,dstr(destvalue),dstr(qp->desttxfee));
            return(-13);
        }
    }
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
    cJSON *reqjson; bits256 zero; char *msg; int32_t i,flag = 0; double price = 0.; struct LP_utxoinfo *utxo;
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
    memset(&zero,0,sizeof(zero));
    if ( 0 && strcmp(method,"connect") == 0 )
    {
        sleep(3);
        LP_broadcast_message(LP_mypubsock,qp->srccoin,qp->destcoin,zero,msg);
    }
    else
    {
        memset(&zero,0,sizeof(zero));
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
            usleep(1000000);
        }
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

struct LP_utxoinfo BUTXOS[100];

int32_t LP_butxo_findeither(bits256 txid,int32_t vout)
{
    struct LP_utxoinfo *utxo; int32_t i,retval = 0;
    portable_mutex_lock(&LP_butxomutex);
    for (i=0; i<sizeof(BUTXOS)/sizeof(*BUTXOS); i++)
    {
        utxo = &BUTXOS[i];
        if ( (vout == utxo->payment.vout && bits256_cmp(txid,utxo->payment.txid)) == 0 || (vout == utxo->deposit.vout && bits256_cmp(txid,utxo->deposit.txid) == 0) )
        {
            retval = 1;
            break;
        }
    }
    portable_mutex_unlock(&LP_butxomutex);
    return(retval);
}

int32_t LP_nearest_utxovalue(struct LP_address_utxo **utxos,int32_t n,uint64_t targetval)
{
    int32_t i,mini = -1; int64_t dist; uint64_t mindist = (1LL << 60);
    for (i=0; i<n; i++)
    {
        if ( utxos[i] != 0 )
        {
            dist = (utxos[i]->U.value - targetval);
            if ( dist >= 0 && dist < mindist )
            {
                printf("(%.8f %.8f %.8f).%d ",dstr(utxos[i]->U.value),dstr(dist),dstr(mindist),mini);
                mini = i;
                mindist = dist;
            }
        }
    }
    return(mini);
}

struct LP_utxoinfo *LP_address_utxopair(struct LP_utxoinfo *utxo,struct LP_address_utxo **utxos,int32_t max,struct iguana_info *coin,char *coinaddr,uint64_t txfee,double volume,double price,int32_t avoidflag,uint64_t desttxfee)
{
    struct LP_address *ap; uint64_t targetval; int32_t m,mini; struct LP_address_utxo *up,*up2;
    if ( coin != 0 && (ap= LP_addressfind(coin,coinaddr)) != 0 )
    {
        if ( (m= LP_address_utxo_ptrs(utxos,max,ap,avoidflag)) > 1 )
        {
            targetval = SATOSHIDEN * ((volume + dstr(desttxfee)) / price) + 2*txfee;
            {
                int32_t i;
                for (i=0; i<m; i++)
                    printf("%.8f ",dstr(utxos[i]->U.value));
                printf("targetval %.8f vol %.8f price %.8f txfee %.8f\n",dstr(targetval),volume,price,dstr(txfee));
            }
            if ( (mini= LP_nearest_utxovalue(utxos,m,targetval)) >= 0 )
            {
                up = utxos[mini];
                utxos[mini] = 0;
                targetval = (up->U.value / 8) * 9 + 2*txfee;
                if ( (mini= LP_nearest_utxovalue(utxos,m,targetval)) >= 0 )
                {
                    if ( up != 0 && (up2= utxos[mini]) != 0 )
                    {
                        safecopy(utxo->coin,coin->symbol,sizeof(utxo->coin));
                        safecopy(utxo->coinaddr,coinaddr,sizeof(utxo->coinaddr));
                        utxo->payment.txid = up->U.txid;
                        utxo->payment.vout = up->U.vout;
                        utxo->payment.value = up->U.value;
                        utxo->iambob = 1;
                        utxo->deposit.txid = up2->U.txid;
                        utxo->deposit.vout = up2->U.vout;
                        utxo->deposit.value = up2->U.value;
                        utxo->S.satoshis = SATOSHIDEN * (volume / price);
                        return(utxo);
                    }
                }
            }
        }
    }
    return(0);
}

struct LP_utxoinfo *_LP_butxo_find(struct LP_utxoinfo *butxo)
{
    int32_t i; struct LP_utxoinfo *utxo=0; uint32_t now = (uint32_t)time(NULL);
    //portable_mutex_lock(&LP_butxomutex);
    printf("_LP_butxo_find\n");
    for (i=0; i<sizeof(BUTXOS)/sizeof(*BUTXOS); i++)
    {
        utxo = &BUTXOS[i];
        if ( butxo->payment.vout == utxo->payment.vout && butxo->deposit.vout == utxo->deposit.vout && bits256_nonz(butxo->payment.txid) != 0 && bits256_nonz(butxo->deposit.txid) != 0 && bits256_cmp(butxo->payment.txid,utxo->payment.txid) == 0 && bits256_cmp(butxo->deposit.txid,utxo->deposit.txid) == 0 )
            break;
        if ( utxo->S.swap == 0 && now > utxo->T.swappending )
            memset(utxo,0,sizeof(*utxo));
        utxo = 0;
    }
    //portable_mutex_unlock(&LP_butxomutex);
    printf("_LP_butxo_find %p\n",utxo);
    return(utxo);
}

struct LP_utxoinfo *LP_butxo_add(struct LP_utxoinfo *butxo)
{
    static struct LP_utxoinfo zeroes;
    int32_t i; struct LP_utxoinfo *utxo=0;
    printf("LP_butxo_add\n");
    portable_mutex_lock(&LP_butxomutex);
    if ( (utxo= _LP_butxo_find(butxo)) == 0 )
    {
        for (i=0; i<sizeof(BUTXOS)/sizeof(*BUTXOS); i++)
        {
            utxo = &BUTXOS[i];
            if ( memcmp(&zeroes,utxo,sizeof(*utxo)) == 0 )
            {
                *utxo = *butxo;
                break;
            }
            utxo = 0;
        }
    }
    portable_mutex_unlock(&LP_butxomutex);
    printf("LP_butxo_add %p\n",utxo);
    return(utxo);
}

void LP_butxo_swapfields_copy(struct LP_utxoinfo *destutxo,struct LP_utxoinfo *srcutxo)
{
    printf("LP_butxo_swapfields_copy %u <- %u\n",destutxo->T.swappending,srcutxo->T.swappending);
    destutxo->S = srcutxo->S;
    destutxo->T = srcutxo->T;
}

void LP_butxo_swapfields(struct LP_utxoinfo *butxo)
{
    struct LP_utxoinfo *getutxo=0;
    printf("swapfields\n");
    portable_mutex_lock(&LP_butxomutex);
    if ( (getutxo= _LP_butxo_find(butxo)) != 0 )
        LP_butxo_swapfields_copy(butxo,getutxo);
    portable_mutex_unlock(&LP_butxomutex);
}

void LP_butxo_swapfields_set(struct LP_utxoinfo *butxo)
{
    struct LP_utxoinfo *setutxo;
    printf("swapfields set\n");
    if ( (setutxo= LP_butxo_add(butxo)) != 0 )
    {
        LP_butxo_swapfields_copy(setutxo,butxo);
        printf("LP_butxo_swapfields_copy set\n");
    }
}

void LP_abutxo_set(struct LP_utxoinfo *autxo,struct LP_utxoinfo *butxo,struct LP_quoteinfo *qp)
{
    if ( butxo != 0 )
    {
        memset(butxo,0,sizeof(*butxo));
        butxo->pubkey = qp->srchash;
        safecopy(butxo->coin,qp->srccoin,sizeof(butxo->coin));
        safecopy(butxo->coinaddr,qp->coinaddr,sizeof(butxo->coinaddr));
        butxo->payment.txid = qp->txid;
        butxo->payment.vout = qp->vout;
        //butxo->payment.value = qp->value;
        butxo->iambob = 1;
        butxo->deposit.txid = qp->txid2;
        butxo->deposit.vout = qp->vout2;
        //butxo->deposit.value = up2->U.value;
        butxo->S.satoshis = qp->satoshis;
    }
    if ( autxo != 0 )
    {
        memset(autxo,0,sizeof(*autxo));
        autxo->pubkey = qp->desthash;
        safecopy(autxo->coin,qp->destcoin,sizeof(autxo->coin));
        safecopy(autxo->coinaddr,qp->destaddr,sizeof(autxo->coinaddr));
        autxo->payment.txid = qp->desttxid;
        autxo->payment.vout = qp->destvout;
        //autxo->payment.value = qp->value;
        autxo->iambob = 0;
        autxo->fee.txid = qp->feetxid;
        autxo->fee.vout = qp->feevout;
        //autxo->deposit.value = up2->U.value;
        autxo->S.satoshis = qp->destsatoshis;
    }
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
    if ( bits256_nonz(privkey) != 0 && bits256_cmp(G.LP_mypub25519,qp->srchash) == 0 ) //qp->quotetime >= qp->timestamp-3 && qp->quotetime <= utxo->T.swappending &&
    {
        if ( (pair= LP_nanobind(ctx,pairstr)) >= 0 )
        {
            LP_requestinit(&qp->R,qp->srchash,qp->desthash,base,qp->satoshis-qp->txfee,rel,qp->destsatoshis-qp->desttxfee,qp->timestamp,qp->quotetime,DEXselector);
            printf("call swapinit\n");
            swap = LP_swapinit(1,0,privkey,&qp->R,qp);
            printf("swapinit.%p\n",swap);
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
        printf("dest %.8f vs required %.8f (%d %d %d %d %d)\n",dstr(qp->destsatoshis),dstr(price*(utxo->S.satoshis-qp->txfee)),bits256_nonz(privkey) != 0 ,qp->timestamp == utxo->T.swappending-LP_RESERVETIME,qp->quotetime >= qp->timestamp-3,qp->quotetime < utxo->T.swappending,bits256_cmp(G.LP_mypub25519,qp->srchash) == 0);
    }
    if ( retval < 0 )
    {
        if ( pair >= 0 )
            nn_close(pair);
        LP_availableset(utxo);
    } else LP_unavailableset(utxo,utxo->S.otherpubkey);
    LP_butxo_swapfields(utxo);
    return(retval);
}

char *LP_connectedalice(cJSON *argjson) // alice
{
    cJSON *retjson; double bid,ask,price,qprice; int32_t pairsock = -1; char *pairstr; int32_t DEXselector = 0; struct LP_utxoinfo A,B,*autxo,*butxo; struct LP_quoteinfo Q; struct basilisk_swap *swap; struct iguana_info *coin;
    if ( LP_quoteparse(&Q,argjson) < 0 )
        clonestr("{\"error\":\"cant parse quote\"}");
    if ( bits256_cmp(Q.desthash,G.LP_mypub25519) != 0 )
        return(clonestr("{\"result\",\"update stats\"}"));
    printf("CONNECTED.(%s)\n",jprint(argjson,0));
    autxo = &A;
    butxo = &B;
    LP_abutxo_set(autxo,butxo,&Q);
    if ( (qprice= LP_quote_validate(autxo,butxo,&Q,0)) <= SMALLVAL )
    {
        LP_availableset(autxo);
        G.LP_pendingswaps--;
        printf("quote validate error %.0f\n",qprice);
        return(clonestr("{\"error\":\"quote validation error\"}"));
    }
    if ( LP_myprice(&bid,&ask,Q.srccoin,Q.destcoin) <= SMALLVAL || bid <= SMALLVAL )
    {
        printf("this node has no price for %s/%s (%.8f %.8f)\n",Q.destcoin,Q.srccoin,bid,ask);
        LP_availableset(autxo);
        G.LP_pendingswaps--;
        return(clonestr("{\"error\":\"no price set\"}"));
    }
    // SPV validate bobs
    printf("%s/%s bid %.8f ask %.8f\n",Q.srccoin,Q.destcoin,bid,ask);
    price = bid;
    if ( (coin= LP_coinfind(Q.destcoin)) == 0 )
    {
        G.LP_pendingswaps--;
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
        else G.LP_pendingswaps++;
        return(jprint(retjson,1));
    }
    else
    {
        LP_availableset(autxo);
        printf("no privkey found\n");
        return(clonestr("{\"error\",\"no privkey\"}"));
    }
}

int32_t LP_listunspent_both(char *symbol,char *coinaddr)
{
    int32_t i,v,height,n=0; uint64_t value; bits256 txid; char buf[512]; cJSON *array,*item; struct iguana_info *coin = LP_coinfind(symbol);
    if ( coin != 0 && coin->inactive == 0 )
    {
        if ( coin->electrum != 0 || LP_address_ismine(symbol,coinaddr) <= 0 )
        {
            //printf("issue path electrum.%p\n",coin->electrum);
            //if ( coin->electrum != 0 && (array= electrum_address_gethistory(symbol,coin->electrum,&array,coinaddr)) != 0 )
            //    free_json(array);
            n = LP_listunspent_issue(symbol,coinaddr);
        }
        else
        {
            //printf("my coin electrum.%p\n",coin->electrum);
            sprintf(buf,"[1, 99999999, [\"%s\"]]",coinaddr);
            if ( (array= bitcoin_json(coin,"listunspent",buf)) != 0 )
            {
                if ( (n= cJSON_GetArraySize(array)) > 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        item = jitem(array,i);
                        txid = jbits256(item,"txid");
                        v = jint(item,"vout");
                        value = LP_value_extract(item,0);
                        height = LP_txheight(coin,txid);
                        //char str[65]; printf("LP_listunspent_both: %s/v%d ht.%d %.8f\n",bits256_str(str,txid),v,height,dstr(value));
                        LP_address_utxoadd(coin,coinaddr,txid,v,value,height,-1);
                    }
                }
            }
        }
    } //else printf("%s coin.%p inactive.%d\n",symbol,coin,coin!=0?coin->inactive:-1);
    return(n);
}

int32_t LP_tradecommand(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen)
{
    char *method,*msg; cJSON *retjson; double qprice,price,bid,ask; struct LP_utxoinfo A,B,*autxo,*butxo; struct iguana_info *coin; struct LP_address_utxo *utxos[1000]; struct LP_quoteinfo Q; int32_t retval = -1,max=(int32_t)(sizeof(utxos)/sizeof(*utxos));
    if ( (method= jstr(argjson,"method")) != 0 && (strcmp(method,"request") == 0 ||strcmp(method,"connect") == 0) )
    {
        printf("LP_tradecommand: check received %s\n",method);
        retval = 1;
        if ( LP_quoteparse(&Q,argjson) == 0 && bits256_cmp(G.LP_mypub25519,Q.srchash) == 0 && bits256_cmp(G.LP_mypub25519,Q.desthash) != 0 )
        {
            if ( (coin= LP_coinfind(Q.srccoin)) == 0 || (price= LP_myprice(&bid,&ask,Q.srccoin,Q.destcoin)) <= SMALLVAL || ask <= SMALLVAL )
            {
                printf("this node has no price for %s/%s\n",Q.srccoin,Q.destcoin);
                return(-3);
            }
            price = ask;
            autxo = &A;
            butxo = &B;
            LP_abutxo_set(autxo,butxo,&Q);
            LP_butxo_swapfields(butxo);
            if ( strcmp(method,"request") == 0 )
            {
                if ( (qprice= LP_quote_validate(autxo,butxo,&Q,1)) <= SMALLVAL )
                {
                    LP_listunspent_both(Q.srccoin,Q.coinaddr);
                    butxo = LP_address_utxopair(butxo,utxos,max,LP_coinfind(Q.srccoin),Q.coinaddr,Q.txfee,dstr(Q.destsatoshis),price,1,Q.desttxfee);
                    Q.txid = butxo->payment.txid;
                    Q.vout = butxo->payment.vout;
                    Q.txid2 = butxo->deposit.txid;
                    Q.vout2 = butxo->deposit.vout;
                    LP_abutxo_set(0,butxo,&Q);
                    LP_butxo_swapfields(butxo);
                }
            }
            if ( butxo == 0 || bits256_nonz(butxo->payment.txid) == 0 || bits256_nonz(butxo->deposit.txid) == 0 || butxo->payment.vout < 0 || butxo->deposit.vout < 0 )
            {
                char str[65]; printf("couldnt find bob utxos for autxo %s/v%d %.8f\n",bits256_str(str,autxo->payment.txid),autxo->payment.vout,dstr(autxo->S.satoshis));
                return(1);
            }
            printf("TRADECOMMAND.(%s)\n",jprint(argjson,0));
            if ( (qprice= LP_quote_validate(autxo,butxo,&Q,1)) <= SMALLVAL )
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
                    butxo->T.lasttime = (uint32_t)time(NULL);
                    printf("set swappending.%u accept qprice %.8f, min %.8f\n(%s)\n",butxo->T.swappending,qprice,price,msg);
                    {
                        bits256 zero;
                        memset(&zero,0,sizeof(zero));
                        LP_broadcast_message(pubsock,Q.srccoin,Q.destcoin,zero,msg);//butxo->S.otherpubkey,msg);
                        LP_butxo_swapfields_set(butxo);
                        printf("return after RESERVED\n");
                        return(2);
                    }
                } else printf("warning swappending.%u swap.%p\n",butxo->T.swappending,butxo->S.swap);
            }
            else if ( strcmp(method,"connect") == 0 ) // bob
            {
                retval = 4;
                if ( butxo->S.swap == 0 && butxo->T.swappending != 0 )
                {
                    // validate SPV alice
                    LP_connectstartbob(ctx,pubsock,butxo,argjson,Q.srccoin,Q.destcoin,qprice,&Q);
                    LP_butxo_swapfields_set(butxo);
                    return(3);
                }
                else printf("pend.%u swap %p when connect came in (%s)\n",butxo->T.swappending,butxo->S.swap,jprint(argjson,0));
            }
            LP_butxo_swapfields_set(butxo);
        }
    }
    return(retval);
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

char *LP_trade(void *ctx,char *myipaddr,int32_t mypubsock,struct LP_quoteinfo *qp,double maxprice,int32_t timeout,int32_t duration)
{
    struct LP_utxoinfo *aliceutxo; cJSON *bestitem=0; int32_t DEXselector=0; uint32_t expiration; double price; struct LP_pubkeyinfo *pubp;
    if ( (aliceutxo= LP_utxopairfind(0,qp->desttxid,qp->destvout,qp->feetxid,qp->feevout)) == 0 )
    {
        char str[65],str2[65]; printf("dest.(%s)/v%d fee.(%s)/v%d\n",bits256_str(str,qp->desttxid),qp->destvout,bits256_str(str2,qp->feetxid),qp->feevout);
        return(clonestr("{\"error\":\"cant find alice utxopair\"}"));
    }
    price = LP_query(ctx,myipaddr,mypubsock,"request",qp);
    bestitem = LP_quotejson(qp);
    if ( LP_pricevalid(price) > 0 )
    {
        if ( price <= maxprice )
        {
            price = LP_query(ctx,myipaddr,mypubsock,"connect",qp);
            LP_requestinit(&qp->R,qp->srchash,qp->desthash,qp->srccoin,qp->satoshis-qp->txfee,qp->destcoin,qp->destsatoshis-qp->desttxfee,qp->timestamp,qp->quotetime,DEXselector);
            expiration = (uint32_t)time(NULL) + timeout;
            while ( time(NULL) < expiration )
            {
                if ( aliceutxo->S.swap != 0 )
                    break;
                sleep(3);
                //price = LP_query(ctx,myipaddr,mypubsock,"connect",qp);
                //LP_requestinit(&qp->R,qp->srchash,qp->desthash,qp->srccoin,qp->satoshis-qp->txfee,qp->destcoin,qp->destsatoshis-qp->desttxfee,qp->timestamp,qp->quotetime,DEXselector);
            }
            if ( aliceutxo->S.swap == 0 )
            {
                if ( (pubp= LP_pubkeyadd(qp->srchash)) != 0 )
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

struct LP_utxoinfo *LP_buyutxo(struct LP_utxoinfo *space,double *ordermatchpricep,int64_t *bestsatoshisp,int64_t *bestdestsatoshisp,struct LP_utxoinfo *autxo,char *base,double maxprice,int32_t duration,uint64_t txfee,uint64_t desttxfee,double relvolume,char *gui)
{
    bits256 pubkey; char *obookstr,coinaddr[64],str[65]; cJSON *orderbook,*asks,*item; int32_t i,n,numasks,max = 10000; struct LP_address_utxo **utxos; double price; struct LP_pubkeyinfo *pubp; struct iguana_info *basecoin; struct LP_utxoinfo *bestutxo = 0;
    *ordermatchpricep = 0.;
    *bestsatoshisp = *bestdestsatoshisp = 0;
    basecoin = LP_coinfind(base);
    if ( duration <= 0 )
        duration = LP_ORDERBOOK_DURATION;
    if ( maxprice <= 0. || LP_priceinfofind(base) == 0 || basecoin == 0 )
        return(0);
    utxos = calloc(max,sizeof(*utxos));
    LP_txfees(&txfee,&desttxfee,base,autxo->coin);
    printf("LP_buyutxo %s/%s %.8f %.8f\n",base,autxo->coin,dstr(txfee),dstr(desttxfee));
    if ( (obookstr= LP_orderbook(base,autxo->coin,duration)) != 0 )
    {
        if ( (orderbook= cJSON_Parse(obookstr)) != 0 )
        {
            if ( (asks= jarray(&numasks,orderbook,"asks")) != 0 )
            {
                for (i=0; i<numasks; i++)
                {
                    item = jitem(asks,i);
                    price = jdouble(item,"price");
                    if ( LP_pricevalid(price) > 0 && price <= maxprice )
                    {
                        pubkey = jbits256(item,"pubkey");
                        printf("%s pubcmp %d\n",jprint(item,0),bits256_cmp(pubkey,G.LP_mypub25519));
                        if ( bits256_cmp(pubkey,G.LP_mypub25519) != 0 && (pubp= LP_pubkeyadd(pubkey)) != 0 )
                        {
                            bitcoin_address(coinaddr,basecoin->taddr,basecoin->pubtype,pubp->rmd160,sizeof(pubp->rmd160));
                            n = LP_listunspent_both(base,coinaddr);
                            if ( n > 1 )
                            {
                                if ( (bestutxo= LP_address_utxopair(space,utxos,max,basecoin,coinaddr,txfee,dstr(autxo->S.satoshis),price,0,desttxfee)) != 0 )
                                {
                                    bestutxo->pubkey = pubp->pubkey;
                                    safecopy(bestutxo->gui,gui,sizeof(bestutxo->gui));
                                    //autxo->S.satoshis = bestutxo->S.satoshis * price - desttxfee;
                                    *bestsatoshisp = bestutxo->S.satoshis;
                                    *ordermatchpricep = price;
                                    *bestdestsatoshisp = autxo->S.satoshis;
                                    printf("ordermatch %.8f %.8f %.8f txfees (%.8f %.8f)\n",price,dstr(*bestsatoshisp),dstr(*bestdestsatoshisp),dstr(txfee),dstr(desttxfee));
                                    break;
                                }
                            } else printf("no unspents %s %s %s\n",base,coinaddr,bits256_str(str,pubkey));
                        } else printf("self trading or blacklisted peer\n");
                    }
                    else
                    {
                        if ( i == 0 )
                            printf("too expensive maxprice %.8f vs %.8f\n",maxprice,price);
                        break;
                    }
                }
            }
            free_json(orderbook);
        }
        free(obookstr);
    }
    free(utxos);
    if ( *ordermatchpricep == 0. || *bestdestsatoshisp == 0 )
        return(0);
    int32_t changed;
    LP_mypriceset(&changed,autxo->coin,base,1. / *ordermatchpricep);
    return(bestutxo);
}

char *LP_autobuy(void *ctx,char *myipaddr,int32_t mypubsock,char *base,char *rel,double maxprice,double relvolume,int32_t timeout,int32_t duration,char *gui)
{
    uint64_t desttxfee,txfee; int64_t bestsatoshis=0,bestdestsatoshis=0; struct LP_utxoinfo *autxo,_best,*bestutxo = 0; double qprice,ordermatchprice=0.; struct LP_quoteinfo Q;
    printf("LP_autobuy %s/%s price %.8f vol %.8f\n",base,rel,maxprice,relvolume);
    if ( duration <= 0 )
        duration = LP_ORDERBOOK_DURATION;
    if ( timeout <= 0 )
        timeout = LP_AUTOTRADE_TIMEOUT;
    if ( maxprice <= 0. || relvolume <= 0. || LP_priceinfofind(base) == 0 || LP_priceinfofind(rel) == 0 )
        return(clonestr("{\"error\":\"invalid parameter\"}"));
    LP_txfees(&txfee,&desttxfee,base,rel);
    if ( (autxo= LP_utxo_bestfit(rel,SATOSHIDEN * relvolume + desttxfee)) == 0 )
        return(clonestr("{\"error\":\"cant find utxo that is big enough\"}"));
    memset(&_best,0,sizeof(_best));
    if ( (bestutxo= LP_buyutxo(&_best,&ordermatchprice,&bestsatoshis,&bestdestsatoshis,autxo,base,maxprice,duration,txfee,desttxfee,relvolume,gui)) == 0 || ordermatchprice == 0. || bestdestsatoshis == 0 )
    {
        printf("bestutxo.%p ordermatchprice %.8f bestdestsatoshis %.8f\n",bestutxo,ordermatchprice,dstr(bestdestsatoshis));
        return(clonestr("{\"error\":\"cant find ordermatch utxo\"}"));
    }
    if ( LP_quoteinfoinit(&Q,bestutxo,rel,ordermatchprice,bestsatoshis,bestdestsatoshis) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote\"}"));
    if ( LP_quotedestinfo(&Q,autxo->payment.txid,autxo->payment.vout,autxo->fee.txid,autxo->fee.vout,G.LP_mypub25519,autxo->coinaddr) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote info\"}"));
    if ( (qprice= LP_quote_validate(autxo,0,&Q,0)) <= SMALLVAL )
    {
        printf("quote validate error %.0f\n",qprice);
        return(clonestr("{\"error\":\"quote validation error\"}"));
    }
    //printf("do quote.(%s)\n",jprint(LP_quotejson(&Q),1));
    return(LP_trade(ctx,myipaddr,mypubsock,&Q,maxprice,timeout,duration));
}


