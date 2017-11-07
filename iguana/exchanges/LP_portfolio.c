
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
//  LP_portfolio.c
//  marketmaker
//

char LP_portfolio_base[16],LP_portfolio_rel[16];
double LP_portfolio_relvolume;

cJSON *LP_portfolio_entry(struct iguana_info *coin)
{
    cJSON *item = cJSON_CreateObject();
    jaddstr(item,"coin",coin->symbol);
    jaddstr(item,"address",coin->smartaddr);
    jaddnum(item,"amount",dstr(coin->maxamount));
    jaddnum(item,"price",coin->price_kmd);
    jaddnum(item,"kmd_equiv",dstr(coin->kmd_equiv));
    jaddnum(item,"perc",coin->perc);
    jaddnum(item,"goal",coin->goal);
    jaddnum(item,"goalperc",coin->goalperc);
    jaddnum(item,"relvolume",coin->relvolume);
    jaddnum(item,"force",coin->force);
    jaddnum(item,"balanceA",dstr(coin->balanceA));
    jaddnum(item,"valuesumA",dstr(coin->valuesumA));
    if ( coin->valuesumA != 0 )
        jaddnum(item,"aliceutil",100. * (double)coin->balanceA/coin->valuesumA);
    jaddnum(item,"balanceB",dstr(coin->balanceB));
    jaddnum(item,"valuesumB",dstr(coin->valuesumB));
    jaddnum(item,"balance",dstr(coin->maxamount));
    if ( coin->valuesumB != 0 )
        jaddnum(item,"bobutil",100. * (double)coin->balanceB/coin->valuesumB);
    return(item);
}

uint64_t LP_balance(uint64_t *valuep,int32_t iambob,char *symbol,char *coinaddr)
{
    cJSON *array,*item; int32_t i,n; uint64_t valuesum,satoshisum,value;
    valuesum = satoshisum = 0;
    if ( (array= LP_listunspent(symbol,coinaddr)) != 0 )
    {
        if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                value = LP_value_extract(item,1);
                valuesum += value;
            }
        }
        free_json(array);
    }
    if ( (array= LP_inventory(symbol)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 && is_cJSON_Array(array) != 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                //valuesum += j64bits(item,"value") + j64bits(item,"value2");
                satoshisum += j64bits(item,"satoshis");
            }
        }
        free_json(array);
    }
    *valuep = valuesum;
    return(satoshisum);
}

char *LP_portfolio()
{
    double maxval = 0.,minval = 0.,goalsum = 0.; uint64_t kmdsum = 0; int32_t iter; cJSON *retjson,*array; struct iguana_info *coin,*tmp,*sellcoin = 0,*buycoin = 0;
    array = cJSON_CreateArray();
    retjson = cJSON_CreateObject();
    for (iter=0; iter<2; iter++)
    {
        HASH_ITER(hh,LP_coins,coin,tmp)
        {
            if ( coin->inactive != 0 )//|| (coin->electrum != 0 && coin->obooktime == 0) )
                continue;
            if ( iter == 0 )
            {
                //printf("from portfolio\n");
                LP_privkey_init(-1,coin,G.LP_privkey,G.LP_mypub25519);
                coin->balanceA = LP_balance(&coin->valuesumA,0,coin->symbol,coin->smartaddr);
                coin->balanceB = LP_balance(&coin->valuesumB,1,coin->symbol,coin->smartaddr);
                if ( strcmp(coin->symbol,"KMD") != 0 )
                    coin->price_kmd = LP_price(coin->symbol,"KMD");
                else coin->price_kmd = 1.;
                coin->maxamount = coin->valuesumA;
                if ( coin->valuesumB > coin->maxamount )
                    coin->maxamount = coin->valuesumB;
                coin->kmd_equiv = coin->maxamount * coin->price_kmd;
                kmdsum += coin->kmd_equiv;
                goalsum += coin->goal;
            }
            else
            {
                coin->relvolume = 0.;
                if ( kmdsum > SMALLVAL )
                    coin->perc = 100. * coin->kmd_equiv / kmdsum;
                if ( goalsum > SMALLVAL && coin->goal > SMALLVAL )
                {
                    coin->goalperc = 100. * coin->goal / goalsum;
                    if ( (coin->force= (coin->goalperc - coin->perc)) < 0. )
                    {
                        coin->force *= -coin->force;
                        if ( coin->price_kmd > SMALLVAL )
                            coin->relvolume = (dstr(coin->maxamount) * (coin->perc - coin->goalperc)) / 100.;
                    } else coin->force *= coin->force;
                    if ( coin->force > maxval )
                    {
                        maxval = coin->force;
                        buycoin = coin;
                    }
                    if ( coin->force < minval )
                    {
                        minval = coin->force;
                        sellcoin = coin;
                    }
                } else coin->goalperc = coin->force = 0.;
                jaddi(array,LP_portfolio_entry(coin));
            }
        }
    }
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"kmd_equiv",dstr(kmdsum));
    if ( buycoin != 0 )
    {
        jaddstr(retjson,"buycoin",buycoin->symbol);
        jaddnum(retjson,"buyforce",maxval);
    }
    if ( sellcoin != 0 )
    {
        jaddstr(retjson,"sellcoin",sellcoin->symbol);
        jaddnum(retjson,"sellforce",minval);
    }
    if ( LP_portfolio_relvolume > SMALLVAL )
    {
        jaddstr(retjson,"base",LP_portfolio_base);
        jaddstr(retjson,"rel",LP_portfolio_rel);
        jaddnum(retjson,"relvolume",LP_portfolio_relvolume);
    }
    jadd(retjson,"portfolio",array);
    return(jprint(retjson,1));
}

char *LP_portfolio_goal(char *symbol,double goal)
{
    struct iguana_info *coin,*tmp; int32_t iter,n = 0; double kmdbtc = 50.;
    if ( strcmp(symbol,"*") == 0 )
    {
        for (iter=0; iter<2; iter++)
        {
            HASH_ITER(hh,LP_coins,coin,tmp)
            {
                if ( coin->inactive != 0 )
                    continue;
                if ( iter == 0 )
                    coin->goal = 0;
                if ( coin->inactive == 0 && strcmp(coin->symbol,"KMD") != 0 && strcmp(coin->symbol,"BTC") != 0 )
                {
                    if ( iter == 0 )
                        n++;
                    else coin->goal = (100. - kmdbtc) / n;
                }
            }
            if ( n == 0 )
                break;
        }
        if ( (coin= LP_coinfind("KMD")) != 0 && coin->inactive == 0 )
            coin->goal = kmdbtc * 0.5;
        if ( (coin= LP_coinfind("BTC")) != 0 && coin->inactive == 0 )
            coin->goal = kmdbtc * 0.5;
        if ( coin->goal != 0 )
            coin->obooktime = (uint32_t)time(NULL);
        return(LP_portfolio());
    }
    else if ( (coin= LP_coinfind(symbol)) != 0 && coin->inactive == 0 )
    {
        coin->goal = goal;
        printf("set %s goal %f\n",coin->symbol,goal);
        if ( coin->goal != 0 )
            coin->obooktime = (uint32_t)time(NULL);
        return(LP_portfolio());
    } else return(clonestr("{\"error\":\"cant set goal for inactive coin\"}"));
}

int32_t LP_autoprices,num_LP_autorefs;

struct LP_autoprice_ref
{
    char refbase[16],refrel[16],base[16],rel[16];
} LP_autorefs[100];

/*int32_t LP_autofill(char *base,char *rel,double maxprice,double totalrelvolume)
{
    struct LP_priceinfo *basepp,*relpp;
    if ( (basepp= LP_priceinfofind(base)) != 0 && (relpp= LP_priceinfofind(rel)) != 0 )
    {
        basepp->maxprices[relpp->ind] = maxprice;
        basepp->relvols[relpp->ind] = totalrelvolume;
        LP_autofills++;
        return(0);
    }
    return(-1);
}*/

int32_t LP_autoprice(char *base,char *rel,cJSON *argjson)
{
    //curl --url "http://127.0.0.1:7783" --data "{\"userpass\":\"$userpass\",\"method\":\"autoprice\",\"base\":\"MNZ\",\"rel\":\"KMD\",\"offset\":0.1,\"refbase\":\"KMD\",\refrel\":\"BTC\",\"factor\":15000,\"margin\":0.01}"
    struct LP_priceinfo *basepp,*relpp; int32_t i; char *refbase,*refrel; double minprice,margin,offset,factor,fixedprice;
    //printf("autoprice.(%s %s) %s\n",base,rel,jprint(argjson,0));
    if ( (basepp= LP_priceinfofind(base)) != 0 && (relpp= LP_priceinfofind(rel)) != 0 )
    {
        if ( jobj(argjson,"minprice") != 0 )
            minprice = jdouble(argjson,"minprice");
        else minprice = 0.;
        margin = jdouble(argjson,"margin");
        offset = jdouble(argjson,"offset");
        factor = jdouble(argjson,"factor");
        fixedprice = jdouble(argjson,"fixed");
        basepp->fixedprices[relpp->ind] = fixedprice;
        basepp->minprices[relpp->ind] = minprice;
        basepp->margins[relpp->ind] = margin;
        basepp->offsets[relpp->ind] = offset;
        basepp->factors[relpp->ind] = factor;
        if ( (refbase= jstr(argjson,"refbase")) != 0 && (refrel= jstr(argjson,"refrel")) != 0 )
        {
            for (i=0; i<num_LP_autorefs; i++)
            {
                if ( strcmp(base,LP_autorefs[i].base) == 0 && strcmp(rel,LP_autorefs[i].rel) == 0 )
                {
                    safecopy(LP_autorefs[i].refbase,refbase,sizeof(LP_autorefs[i].refbase));
                    safecopy(LP_autorefs[i].refrel,refrel,sizeof(LP_autorefs[i].refrel));
                    printf("%d Update ref %s/%s for %s/%s factor %.8f offset %.8f\n",i,refbase,refrel,base,rel,factor,offset);
                    break;
                }
            }
            if ( i == num_LP_autorefs && num_LP_autorefs < sizeof(LP_autorefs)/sizeof(*LP_autorefs) )
            {
                safecopy(LP_autorefs[num_LP_autorefs].refbase,refbase,sizeof(LP_autorefs[num_LP_autorefs].refbase));
                safecopy(LP_autorefs[num_LP_autorefs].refrel,refrel,sizeof(LP_autorefs[num_LP_autorefs].refrel));
                safecopy(LP_autorefs[num_LP_autorefs].base,base,sizeof(LP_autorefs[num_LP_autorefs].base));
                safecopy(LP_autorefs[num_LP_autorefs].rel,rel,sizeof(LP_autorefs[num_LP_autorefs].rel));
                printf("%d Using ref %s/%s for %s/%s factor %.8f, offset %.8f, margin %.8f\n",num_LP_autorefs,refbase,refrel,base,rel,factor,offset,margin);
                num_LP_autorefs++;
            }
        }
        LP_autoprices++;
        return(0);
    }
    return(-1);
}

void LP_autopriceset(void *ctx,int32_t dir,struct LP_priceinfo *basepp,struct LP_priceinfo *relpp,double price,char *refbase,char *refrel)
{
    static uint32_t lasttime;
    double margin,minprice,newprice,oppomargin,fixedprice,factor,offset; double bid,ask; int32_t changed;
    margin = basepp->margins[relpp->ind];
    oppomargin = relpp->margins[basepp->ind];
    if ( (fixedprice= relpp->fixedprices[basepp->ind]) > SMALLVAL )
    {
        LP_mypriceset(&changed,relpp->symbol,basepp->symbol,fixedprice);
        printf("autoprice FIXED %s/%s <- %.8f\n",basepp->symbol,relpp->symbol,fixedprice);
        LP_pricepings(ctx,LP_myipaddr,LP_mypubsock,relpp->symbol,basepp->symbol,fixedprice);
        return;
    }
    if ( margin != 0. || oppomargin != 0. )
    {
        offset = basepp->offsets[relpp->ind];
        factor = basepp->factors[relpp->ind];
        if ( fabs(price) < SMALLVAL && refbase != 0 && refrel != 0 )
        {
            price = LP_myprice(&bid,&ask,refbase,refrel);
            //printf("%s/%s USE ref %s/%s %.8f factor %.8f offset %.8f margin %.8f\n",basepp->symbol,relpp->symbol,refbase,refrel,price,factor,offset,margin);
        }
        if ( LP_pricevalid(price) > 0 )
        {
            if ( factor > SMALLVAL )
            {
                //double tmp = (price * factor) + offset;
                //printf("price %.8f -> %.8f factor %.8f offset %.8f margin %.8f [%.8f %.8f] [%.8f %.8f]\n",price,tmp,factor,offset,margin,(tmp * (1. + margin)),1./(tmp * (1. - margin)),(tmp * (1. - margin)),1./(tmp * (1. + margin)));
                price = (price * factor) + offset;
            }
            if ( margin == 0. )
                margin = oppomargin;
            //printf("min %.8f %s/%s %.8f dir.%d margin %.8f (%.8f %.8f)\n",basepp->minprices[relpp->ind],relpp->symbol,basepp->symbol,price,dir,margin,1. / (price * (1. - margin)),(price * (1. + margin)));
            if ( dir > 0 )
                newprice = (1. / price) * (1. + margin);
            else newprice = (price * (1. + margin));
            if ( (minprice= basepp->minprices[relpp->ind]) == 0. || price >= minprice )
            {
                LP_mypriceset(&changed,relpp->symbol,basepp->symbol,newprice);
                //printf("autoprice changed.%d %s/%s <- %.8f\n",changed,basepp->symbol,relpp->symbol,price);
                if ( changed != 0 || time(NULL) > lasttime+LP_ORDERBOOK_DURATION*.777)
                {
                    lasttime = (uint32_t)time(NULL);
                    LP_pricepings(ctx,LP_myipaddr,LP_mypubsock,relpp->symbol,basepp->symbol,newprice);
                }
            }
        }
    }
}

double LP_pricesparse(void *ctx,int32_t trexflag,char *retstr,struct LP_priceinfo *btcpp)
{
    //{"success":true,"message":"","result":[{"MarketName":"BTC-KMD","High":0.00040840,"Low":0.00034900,"Volume":328042.46061669,"Last":0.00037236,"BaseVolume":123.36439511,"TimeStamp":"2017-07-15T13:50:21.87","Bid":0.00035721,"Ask":0.00037069,"OpenBuyOrders":343,"OpenSellOrders":1690,"PrevDay":0.00040875,"Created":"2017-02-11T23:04:01.853"},
    //{"TradePairId":4762,"Label":"WAVES/BTC","AskPrice":0.00099989,"BidPrice":0.00097350,"Low":0.00095000,"High":0.00108838,"Volume":6501.24403100,"LastPrice":0.00098028,"BuyVolume":1058994.86554882,"SellVolume":2067.87377158,"Change":-7.46,"Open":0.00105926,"Close":0.00098028,"BaseVolume":6.52057452,"BuyBaseVolume":2.33098660,"SellBaseVolume":1167.77655709},
    int32_t i,j,n,iter; double price,kmdbtc,bid,ask,nxtkmd=0.; struct LP_priceinfo *coinpp,*refpp; char symbol[16],*name,*refcoin; cJSON *retjson,*array,*item;
    if ( (retjson= cJSON_Parse(retstr)) != 0 )
    {
        //printf("got.(%s)\n",retstr);
        kmdbtc = 0.;
        refcoin = "BTC";
        refpp = btcpp;
        if ( (array= jarray(&n,retjson,trexflag != 0 ? "result" : "Data")) != 0 )
        {
            for (iter=0; iter<2; iter++)
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (name= jstr(item,trexflag != 0 ? "MarketName" : "Label")) != 0 )
                    {
                        symbol[0] = 0;
                        if ( trexflag != 0 )
                        {
                            if ( strncmp("BTC-",name,4) == 0 )
                            {
                                name += 4;
                                strcpy(symbol,name);
                            }
                        }
                        else
                        {
                            for (j=0; j<sizeof(symbol)-1; j++)
                                if ( (symbol[j]= name[j]) == '/' )
                                    break;
                            symbol[j] = 0;
                            if ( strcmp(name+j+1,"BTC") != 0 )
                                continue;
                        }
                        if ( symbol[0] != 0 )
                        {
                            //printf("%s\n",jprint(item,0));
                            bid = jdouble(item,trexflag != 0 ? "Bid" : "BidPrice");
                            ask = jdouble(item,trexflag != 0 ? "Ask" : "AskPrice");
                            if ( iter == 1 && kmdbtc > SMALLVAL && strcmp(symbol,"NXT") == 0 )
                                nxtkmd = 0.5 * (bid + ask) / kmdbtc;
                            if ( (coinpp= LP_priceinfofind(symbol)) != 0 )
                            {
                                coinpp->high[trexflag] = jdouble(item,"High");
                                coinpp->low[trexflag] = jdouble(item,"Low");
                                //coinpp->volume = jdouble(item,"Volume");
                                //coinpp->btcvolume = jdouble(item,"BaseVolume");
                                coinpp->last[trexflag] = jdouble(item,trexflag != 0 ? "Last" : "LastPrice");
                                coinpp->bid[trexflag] = bid;
                                coinpp->ask[trexflag] = ask;
                                //coinpp->prevday = jdouble(item,"PrevDay");
                                //printf("iter.%d trexflag.%d %s high %.8f, low %.8f, last %.8f hbla.(%.8f %.8f)\n",iter,trexflag,symbol,coinpp->high[trexflag],coinpp->low[trexflag],coinpp->last[trexflag],coinpp->bid[trexflag],coinpp->ask[trexflag]);
                                if ( coinpp->bid[trexflag] > SMALLVAL && coinpp->ask[trexflag] > SMALLVAL )
                                {
                                    price = 0.5 * (coinpp->bid[trexflag] + coinpp->ask[trexflag]);
                                    if ( iter == 0 )
                                    {
                                        if ( strcmp(symbol,"KMD") == 0 )
                                            kmdbtc = price;
                                    }
                                    else
                                    {
                                        if ( strcmp(symbol,"KMD") == 0 )
                                            continue;
                                        //printf("(%s/%s) iter.%d trexflag.%d %s %.8f %.8f\n",refpp->symbol,coinpp->symbol,iter,trexflag,symbol,price,price/kmdbtc);
                                        price /= kmdbtc;
                                    }
                                    if ( trexflag == 0 && coinpp->bid[1] > SMALLVAL && coinpp->ask[1] > SMALLVAL )
                                    {
                                        //printf("have trex: iter.%d trexflag.%d %s %.8f %.8f\n",iter,trexflag,symbol,coinpp->bid[1],coinpp->ask[1]);
                                        continue;
                                    }
                                    LP_autopriceset(ctx,1,coinpp,refpp,price,0,0);
                                    LP_autopriceset(ctx,-1,refpp,coinpp,price,0,0);
                                }
                            }
                        }
                    }
                }
                refcoin = "KMD";
                if ( kmdbtc == 0. || (refpp= LP_priceinfofind("KMD")) == 0 )
                    break;
            }
        }
        free_json(retjson);
    }
    return(nxtkmd);
}

void LP_autoprice_iter(void *ctx,struct LP_priceinfo *btcpp)
{
    char *retstr; cJSON *retjson,*bid,*ask; uint64_t bidsatoshis,asksatoshis; int32_t i; double nxtkmd,price; struct LP_priceinfo *kmdpp,*fiatpp,*nxtpp,*basepp,*relpp;
    if ( (retstr= issue_curlt("https://bittrex.com/api/v1.1/public/getmarketsummaries",LP_HTTP_TIMEOUT*10)) == 0 )
    {
        printf("trex error getting marketsummaries\n");
        sleep(60);
        return;
    }
    nxtkmd = LP_pricesparse(ctx,1,retstr,btcpp);
    free(retstr);
    if ( (retstr= issue_curlt("https://www.cryptopia.co.nz/api/GetMarkets",LP_HTTP_TIMEOUT*10)) == 0 )
    {
        printf("cryptopia error getting marketsummaries\n");
        sleep(60);
        return;
    }
    LP_pricesparse(ctx,0,retstr,btcpp);
    free(retstr);
    if ( (kmdpp= LP_priceinfofind("KMD")) != 0 )
    {
        for (i=0; i<32; i++)
        {
            if ( (fiatpp= LP_priceinfofind(CURRENCIES[i])) != 0 )
            {
                if ( (retjson= LP_paxprice(CURRENCIES[i])) != 0 )
                {
                    //printf("(%s %.8f %.8f) ",CURRENCIES[i],jdouble(retjson,"price"),jdouble(retjson,"invprice"));
                    price = jdouble(retjson,"price");
                    LP_autopriceset(ctx,1,fiatpp,kmdpp,price,0,0);
                    LP_autopriceset(ctx,-1,kmdpp,fiatpp,price,0,0);
                    free_json(retjson);
                }
            }
        }
    }
    if ( nxtkmd > SMALLVAL )
    {
        for (i=0; i<sizeof(assetids)/sizeof(*assetids); i++)
        {
            if ( (nxtpp= LP_priceinfofind(assetids[i][1])) != 0 )
            {
                price = 0.;
                bidsatoshis = asksatoshis = 0;
                if ( (retjson= LP_assethbla(assetids[i][0])) != 0 )
                {
                    if ( (bid= jobj(retjson,"bid")) != 0 && (ask= jobj(retjson,"ask")) != 0 )
                    {
                        bidsatoshis = j64bits(bid,"priceNQT") * atoi(assetids[i][2]);
                        asksatoshis = j64bits(ask,"priceNQT") * atoi(assetids[i][2]);
                        if ( bidsatoshis != 0 && asksatoshis != 0 )
                            price = 0.5 * dstr(bidsatoshis + asksatoshis) * nxtkmd;
                    }
                    LP_autopriceset(ctx,1,nxtpp,kmdpp,price,0,0);
                    LP_autopriceset(ctx,-1,kmdpp,nxtpp,price,0,0);
                    //printf("%s %s -> (%s) nxtkmd %.8f %.8f %.8f\n",assetids[i][1],assetids[i][0],jprint(retjson,0),nxtkmd,0.5*dstr(bidsatoshis + asksatoshis),price);
                    free_json(retjson);
                }
            }
        }
    }
    for (i=0; i<num_LP_autorefs; i++)
    {
        basepp = LP_priceinfofind(LP_autorefs[i].base);
        relpp = LP_priceinfofind(LP_autorefs[i].rel);
        if ( basepp != 0 && relpp != 0 )
        {
            //printf("check ref-autoprice %s/%s\n",LP_autorefs[i].refbase,LP_autorefs[i].refrel);
            LP_autopriceset(ctx,1,basepp,relpp,0.,LP_autorefs[i].refbase,LP_autorefs[i].refrel);
        }
    }
}

int32_t LP_portfolio_trade(void *ctx,uint32_t *requestidp,uint32_t *quoteidp,struct iguana_info *buy,struct iguana_info *sell,double relvolume,int32_t setbaserel,char *gui)
{
    char *retstr2; double bid,ask,maxprice; bits256 zero; uint32_t requestid,quoteid,iter,i; cJSON *retjson2;
    requestid = quoteid = 0;
    LP_myprice(&bid,&ask,buy->symbol,sell->symbol);
    maxprice = ask;
    if ( setbaserel != 0 )
    {
        strcpy(LP_portfolio_base,"");
        strcpy(LP_portfolio_rel,"");
        LP_portfolio_relvolume = 0.;
    }
    printf("pending.%d base buy.%s, rel sell.%s relvolume %f maxprice %.8f (%.8f %.8f)\n",G.LP_pendingswaps,buy->symbol,sell->symbol,sell->relvolume,maxprice,bid,ask);
    if ( LP_pricevalid(maxprice) > 0 )
    {
        relvolume = sell->relvolume;
        for (iter=0; iter<2; iter++)
        {
            if ( relvolume < dstr(LP_MIN_TXFEE) )
                break;
            if ( LP_utxo_bestfit(sell->symbol,SATOSHIDEN * relvolume) != 0 )
            {
                memset(zero.bytes,0,sizeof(zero));
                if ( (retstr2= LP_autobuy(ctx,"127.0.0.1",-1,buy->symbol,sell->symbol,maxprice,relvolume,60,24*3600,gui,LP_lastnonce+1,zero,1)) != 0 )
                {
                    if ( (retjson2= cJSON_Parse(retstr2)) != 0 )
                    {
                        if ( (requestid= juint(retjson2,"requestid")) != 0 && (quoteid= juint(retjson2,"quoteid")) != 0 )
                        {
                            
                        }
                        free_json(retjson2);
                    }
                    printf("%s relvolume %.8f LP_autotrade.(%s)\n",sell->symbol,relvolume,retstr2);
                    free(retstr2);
                }
                if ( requestid != 0 && quoteid != 0 )
                    break;
            } else printf("cant find alice %.8f %s\n",relvolume,sell->symbol);
            if ( iter == 0 )
            {
                for (i=0; i<100; i++)
                {
                    relvolume *= .99;
                    if ( LP_utxo_bestfit(sell->symbol,SATOSHIDEN * relvolume) != 0 )
                    {
                        printf("i.%d relvolume %.8f from %.8f\n",i,relvolume,sell->relvolume);
                        break;
                    }
                }
            }
        }
    }
    else if ( setbaserel != 0 )
    {
        strcpy(LP_portfolio_base,buy->symbol);
        strcpy(LP_portfolio_rel,sell->symbol);
        LP_portfolio_relvolume = sell->relvolume;
    }
    *requestidp = requestid;
    *quoteidp = quoteid;
    if ( requestid != 0 && quoteid != 0 )
        return(0);
    else return(-1);
}

struct LP_portfoliotrade { double metric; char buycoin[16],sellcoin[16]; };

int32_t LP_portfolio_order(struct LP_portfoliotrade *trades,int32_t max,cJSON *array)
{
    int32_t i,j,m,n = 0; cJSON *item; struct LP_portfoliotrade coins[256];
    memset(coins,0,sizeof(coins));
    if ( (m= cJSON_GetArraySize(array)) > 0 )
    {
        for (i=j=0; i<m && i<sizeof(coins)/sizeof(*coins); i++)
        {
            item = jitem(array,i);
            safecopy(coins[j].buycoin,jstr(item,"coin"),sizeof(coins[j].buycoin));
            coins[j].metric = jdouble(item,"force");
            if ( fabs(coins[j].metric) > SMALLVAL && coins[j].buycoin[0] != 0 )
                j++;
        }
        if ( (m= j) > 1 )
        {
            for (i=n=0; i<m-1; i++)
                for (j=i+1; j<m; j++)
                    if ( coins[i].metric*coins[j].metric < 0. )
                    {
                        if ( coins[i].metric > 0. )
                        {
                            trades[n].metric = (coins[i].metric - coins[j].metric);
                            strcpy(trades[n].buycoin,coins[i].buycoin);
                            strcpy(trades[n].sellcoin,coins[j].buycoin);
                            printf("buy %s %f, sell %s %f -> %f\n",trades[n].buycoin,coins[i].metric,trades[n].sellcoin,coins[j].metric,trades[n].metric);
                        }
                        else
                        {
                            trades[n].metric = (coins[j].metric - coins[i].metric);
                            strcpy(trades[n].buycoin,coins[j].buycoin);
                            strcpy(trades[n].sellcoin,coins[i].buycoin);
                            printf("buy %s %f, sell %s %f -> %f\n",trades[n].buycoin,coins[j].metric,trades[n].sellcoin,coins[i].metric,trades[n].metric);
                        }
                        n++;
                        if ( n >= max )
                            break;
                    }
            revsortds((void *)trades,n,sizeof(*trades));
            for (i=0; i<n; i++)
                printf("%d: buy %s, sell %s -> %f\n",i,trades[i].buycoin,trades[i].sellcoin,trades[i].metric);
        }
    }
    return(n);
}

void prices_loop(void *ctx)
{
    char *retstr; cJSON *retjson,*array; char *buycoin,*sellcoin; struct iguana_info *buy,*sell; uint32_t requestid,quoteid; int32_t i,n,m; struct LP_portfoliotrade trades[256]; struct LP_priceinfo *btcpp;
    strcpy(prices_loop_stats.name,"prices_loop");
    prices_loop_stats.threshold = 91000.;
    while ( 1 )
    {
        LP_millistats_update(&prices_loop_stats);
        LP_tradebots_timeslice(ctx);
        if ( (btcpp= LP_priceinfofind("BTC")) == 0 )
        {
            printf("prices_loop BTC not in LP_priceinfofind\n");
            sleep(60);
            continue;
        }
        if ( LP_autoprices != 0 )
            LP_autoprice_iter(ctx,btcpp);
        if ( (retstr= LP_portfolio()) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( (buycoin= jstr(retjson,"buycoin")) != 0 && (buy= LP_coinfind(buycoin)) != 0 && (sellcoin= jstr(retjson,"sellcoin")) != 0 && (sell= LP_coinfind(sellcoin)) != 0 && buy->inactive == 0 && sell->inactive == 0 )
                {
                    if ( LP_portfolio_trade(ctx,&requestid,&quoteid,buy,sell,sell->relvolume,1,"portfolio") < 0 )
                    {
                        array = jarray(&m,retjson,"portfolio");
                        if ( array != 0 && (n= LP_portfolio_order(trades,(int32_t)(sizeof(trades)/sizeof(*trades)),array)) > 0 )
                        {
                            for (i=0; i<n; i++)
                            {
                                if ( strcmp(trades[i].buycoin,buycoin) != 0 || strcmp(trades[i].sellcoin,sellcoin) != 0 )
                                {
                                    buy = LP_coinfind(trades[i].buycoin);
                                    sell = LP_coinfind(trades[i].sellcoin);
                                    if ( buy != 0 && sell != 0 && LP_portfolio_trade(ctx,&requestid,&quoteid,buy,sell,sell->relvolume,0,"portfolio") == 0 )
                                        break;
                                }
                            }
                        }
                    }
                }
                free_json(retjson);
            }
            free(retstr);
        }
        sleep(60);
    }
}


