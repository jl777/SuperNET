/******************************************************************************
 * Copyright © 2014-2016 The SuperNET Developers.                             *
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


#ifndef xcode_exchangeparse_h
#define xcode_exchangeparse_h


char *Supported_exchanges[] = { INSTANTDEX_NAME, INSTANTDEX_NXTAEUNCONF, INSTANTDEX_NXTAENAME, INSTANTDEX_BASKETNAME, "basketNXT", "basketUSD", "basketBTC", "basketCNY", INSTANTDEX_ACTIVENAME, "wallet", "jumblr", "pangea", "peggy", // peggy MUST be last of special exchanges
    "bitfinex", "btc38", "bitstamp", "btce", "poloniex", "bittrex", "huobi", "coinbase", "okcoin", "lakebtc", "quadriga",
    //"bityes", "kraken", "gatecoin", "quoine", "jubi", "hitbtc"  // no trading for these exchanges yet
}; // "bter" <- orderbook is backwards and all entries are needed, later to support, "exmo" flakey apiservers

void init_exchanges()
{
    int32_t i;
    for (FIRST_EXTERNAL=0; FIRST_EXTERNAL<sizeof(Supported_exchanges)/sizeof(*Supported_exchanges); FIRST_EXTERNAL++)
    {
        find_exchange(0,Supported_exchanges[FIRST_EXTERNAL]);
        if ( strcmp(Supported_exchanges[FIRST_EXTERNAL],"peggy") == 0 )
        {
            FIRST_EXTERNAL++;
            break;
        }
    }
    for (i=FIRST_EXTERNAL; i<sizeof(Supported_exchanges)/sizeof(*Supported_exchanges); i++)
        find_exchange(0,Supported_exchanges[i]);
    prices777_initpair(-1,0,0,0,0.,0,0,0,0);
    void prices777_basketsloop(void *ptr);
    iguana_launch(iguana_coinadd("BTCD"),"basketloop",(void *)prices777_basketsloop,0,IGUANA_EXCHANGETHREAD);
    //prices777_makebasket("{\"name\":\"NXT/BTC\",\"base\":\"NXT\",\"rel\":\"BTC\",\"basket\":[{\"exchange\":\"bittrex\"},{\"exchange\":\"poloniex\"},{\"exchange\":\"btc38\"}]}",0);
}

void init_InstantDEX()
{
    int32_t a,b;
    //init_pingpong_queue(&Pending_offersQ,"pending_offers",0,0,0);
    //Pending_offersQ.offset = 0;
    init_exchanges();
    find_exchange(&a,INSTANTDEX_NXTAENAME), find_exchange(&b,INSTANTDEX_NAME);
    if ( a != INSTANTDEX_NXTAEID || b != INSTANTDEX_EXCHANGEID )
        printf("invalid exchangeid %d, %d\n",a,b);
    find_exchange(&a,INSTANTDEX_NXTAENAME), find_exchange(&b,INSTANTDEX_NAME);
    if ( a != INSTANTDEX_NXTAEID || b != INSTANTDEX_EXCHANGEID )
        printf("invalid exchangeid %d, %d\n",a,b);
    printf("NXT-> %llu BTC -> %llu\n",(long long)stringbits("NXT"),(long long)stringbits("BTC"));
    //INSTANTDEX.readyflag = 1;
}

int32_t supported_exchange(char *exchangestr)
{
    int32_t i;
    for (i=0; i<sizeof(Supported_exchanges)/sizeof(*Supported_exchanges); i++)
        if ( strcmp(exchangestr,Supported_exchanges[i]) == 0 )
            return(i);
    return(-1);
}

cJSON *exchanges_json()
{
    struct exchange_info *exchange; int32_t exchangeid,n = 0; char api[4]; cJSON *item,*array = cJSON_CreateArray();
    for (exchangeid=0; exchangeid<MAX_EXCHANGES; exchangeid++)
    {
        item = cJSON_CreateObject();
        exchange = &Exchanges[exchangeid];
        if ( exchange->name[0] == 0 )
            break;
        cJSON_AddItemToObject(item,"name",cJSON_CreateString(exchange->name));
        memset(api,0,sizeof(api));
        n = 0;
        if ( exchange->issue.trade != 0 )
        {
            //printf("%s.(%s/%s/%s).%p\n",exchange->name,exchange->apikey,exchange->apisecret,exchange->userid,exchange);
            if ( exchange->apikey[0] != 0 )
                api[n++] = 'K';
            if ( exchange->apisecret[0] != 0 )
                api[n++] = 'S';
            if ( exchange->userid[0] != 0 )
                api[n++] = 'U';
            api[n] = 0;
            cJSON_AddItemToObject(item,"trade",cJSON_CreateString(api));
        }
        cJSON_AddItemToArray(array,item);
    }
    return(array);
}

int32_t is_exchange_nxt64bits(uint64_t nxt64bits)
{
    int32_t exchangeid;
    struct exchange_info *exchange = 0;
    for (exchangeid=0; exchangeid<MAX_EXCHANGES; exchangeid++)
    {
        exchange = &Exchanges[exchangeid];
        // printf("(%s).(%llu vs %llu) ",exchange->name,(long long)exchange->nxt64bits,(long long)nxt64bits);
        if ( exchange->name[0] == 0 )
            return(0);
        if ( exchange->nxt64bits == nxt64bits )
            return(1);
    }
    printf("no exchangebits match\n");
    return(0);
}

struct exchange_info *get_exchange(int32_t exchangeid) { return(&Exchanges[exchangeid]); }
char *exchange_str(int32_t exchangeid) { return(Exchanges[exchangeid].name); }

struct exchange_info *exchange_find(char *exchangestr)
{
    int32_t exchangeid;
    struct exchange_info *exchange = 0;
    for (exchangeid=0; exchangeid<MAX_EXCHANGES; exchangeid++)
    {
        exchange = &Exchanges[exchangeid];
        if ( strcmp(exchangestr,exchange->name) == 0 )
            return(exchange);
    }
    return(0);
}

struct exchange_info *find_exchange(int32_t *exchangeidp,char *exchangestr)
{
    int32_t exchangeid; struct exchange_info *exchange = 0;
    if ( supported_exchange(exchangestr) < 0 )
    {
        if ( exchangeidp != 0 )
            *exchangeidp = -1;
        return(0);
    }
    for (exchangeid=0; exchangeid<MAX_EXCHANGES; exchangeid++)
    {
        exchange = &Exchanges[exchangeid];
        //printf("(%s v %s) ",exchangestr,exchange->name);
        if ( exchange->name[0] == 0 )
        {
            portable_mutex_init(&exchange->mutex);
            strcpy(exchange->name,exchangestr);
            exchange->exchangeid = exchangeid;
            exchange->nxt64bits = stringbits(exchangestr);
            printf("CREATE EXCHANGE.(%s) id.%d %llu\n",exchangestr,exchangeid,(long long)exchange->nxt64bits);
            //if ( exchangestr[0] == 0 )
            //    getchar();
            break;
        }
        if ( strcmp(exchangestr,exchange->name) == 0 )
            break;
    }
    if ( exchange != 0 && exchangeidp != 0 )
        *exchangeidp = exchange->exchangeid;
    return(exchange);
}

int32_t baserel_polarity(char *pairs[][2],int32_t n,char *_base,char *_rel)
{
    int32_t i; char base[16],rel[16];
    strcpy(base,_base), tolowercase(base);
    strcpy(rel,_rel), tolowercase(rel);
    for (i=0; i<n; i++)
    {
        if ( strcmp(pairs[i][0],base) == 0 && strcmp(pairs[i][1],rel) == 0 )
            return(1);
        else if ( strcmp(pairs[i][0],rel) == 0 && strcmp(pairs[i][1],base) == 0 )
            return(-1);
    }
    printf("cant find.(%s/%s) [%s/%s].%d\n",base,rel,pairs[0][0],pairs[0][1],n);
    return(0);
}

double prices777_standard(char *exchangestr,char *url,struct prices777 *prices,char *price,char *volume,int32_t maxdepth,char *field)
{
    char *jsonstr; cJSON *json; double hbla = 0.;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //if ( strcmp(exchangestr,"btc38") == 0 )
            printf("(%s) -> (%s)\n",url,jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            hbla = prices777_json_orderbook(exchangestr,prices,maxdepth,json,field,"bids","asks",price,volume);
            free_json(json);
        }
        free(jsonstr);
    }
    return(hbla);
}

int32_t InstantDEX_supports(char *base,char *rel) { return(1); }

int32_t NXT_supports(char *base,char *rel)
{
    if ( strcmp(rel,"NXT") == 0 )
        return(1);
    else if ( strcmp(base,"NXT") == 0 )
        return(-1);
    else return(0);
}

#ifdef notnow
char *bittrex_parsebalance(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    int32_t i,n; char *str,*itemstr = 0; cJSON *item,*array,*obj; double total,pending;
    *balancep = 0.;
    if ( exchange->balancejson != 0 && (array= jarray(&n,exchange->balancejson,"result")) != 0 )
    {
        for (i=0; i<n; i++)
        {
            if ( (item= jitem(array,i)) != 0 )
            {
                if ( (str= jstr(item,"Currency")) != 0 && strcmp(coinstr,str) == 0 )
                {
                    itemstr = jprint(item,0);
                    *balancep = jdouble(item,"Available");
                    total = jdouble(item,"Balance");
                    pending = jdouble(item,"Pending");
                    if ( (obj= cJSON_Parse(itemstr)) != 0 )
                    {
                        jaddnum(obj,"balance",*balancep);
                        jaddnum(obj,"total",total);
                        jaddnum(obj,"pending",pending);
                        if ( (str= jstr(obj,"CryptoAddress")) != 0 )
                            jaddstr(obj,"deposit_address",str);
                        free(itemstr);
                        itemstr = jprint(obj,1);
                    }
                    break;
                }
            }
        }
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

int32_t bittrex_supports(char *base,char *rel)
{
    if ( strlen(base) > 5 || strlen(rel) > 5 || strcmp(rel,"CNY") == 0 || strcmp(base,"CNY") == 0 || strcmp(rel,"USD") == 0 || strcmp(base,"USD") == 0 )
        return(0);
    if ( strcmp(rel,"BTC") == 0 )
        return(1);
    else if ( strcmp(base,"BTC") == 0 )
        return(-1);
    else return(0);
}

double prices777_bittrex(struct prices777 *prices,int32_t maxdepth) // "BTC-BTCD"
{
    cJSON *json,*obj; char *jsonstr,market[128]; double hbla = 0.;
    if ( prices->url[0] == 0 )
    {
        sprintf(market,"%s-%s",prices->rel,prices->base);
        sprintf(prices->url,"https://bittrex.com/api/v1.1/public/getorderbook?market=%s&type=both&depth=%d",market,maxdepth);
    }
    jsonstr = issue_curl(prices->url);
    if ( jsonstr != 0 )
    {
        if ( (json = cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (obj= cJSON_GetObjectItem(json,"success")) != 0 && is_cJSON_True(obj) != 0 )
                hbla = prices777_json_orderbook("bittrex",prices,maxdepth,json,"result","buy","sell","Rate","Quantity");
            free_json(json);
        }
        free(jsonstr);
    }
    return(hbla);
}

/*int32_t bter_supports(char *base,char *rel)
{
    return(0);
    if ( strcmp(rel,"BTC") == 0 || strcmp(rel,"CNY") == 0 )
        return(1);
    else if ( strcmp(base,"BTC") == 0 || strcmp(base,"CNY") == 0 )
        return(-1);
    else return(0);
    char *bterassets[][8] = { { "UNITY", "12071612744977229797" },  { "ATOMIC", "11694807213441909013" },  { "DICE", "18184274154437352348" },  { "MRKT", "134138275353332190" },  { "MGW", "10524562908394749924" } };
     uint64_t unityid = calc_nxt64bits("12071612744977229797");
     n = add_exchange_assetids(assetids,n,BTC_ASSETID,baseid,relid,exchangeid,bterassets,(int32_t)(sizeof(bterassets)/sizeof(*bterassets)));
     if ( baseid == unityid || relid == unityid )
     {
     n = add_exchange_assetid(assetids,n,unityid,BTC_ASSETID,exchangeid);
     n = add_exchange_assetid(assetids,n,unityid,NXT_ASSETID,exchangeid);
     n = add_exchange_assetid(assetids,n,unityid,CNY_ASSETID,exchangeid);
     }
     return(n);
}

double prices777_bter(struct prices777 *prices,int32_t maxdepth)
{
    cJSON *json,*obj; char resultstr[MAX_JSON_FIELD],*jsonstr; double hbla = 0.;
    if ( prices->url[0] == 0 )
        sprintf(prices->url,"http://data.bter.com/api/1/depth/%s_%s",prices->base,prices->rel);
    jsonstr = issue_curl(prices->url);
    //printf("(%s) -> (%s)\n",ep->url,jsonstr);
    //{"result":"true","asks":[["0.00008035",100],["0.00008030",2030],["0.00008024",100],["0.00008018",643.41783554],["0.00008012",100]
    if ( jsonstr != 0 )
    {
        //printf("BTER.(%s)\n",jsonstr);
        if ( (json = cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (obj= cJSON_GetObjectItem(json,"result")) != 0 )
            {
                copy_cJSON(resultstr,obj);
                if ( strcmp(resultstr,"true") == 0 )
                {
                    maxdepth = MAX_DEPTH;//1000; // since bter ask is wrong order, need to scan entire list
                    hbla = prices777_json_orderbook("bter",prices,maxdepth,json,0,"bids","asks",0,0);
                }
            }
            free_json(json);
        }
        free(jsonstr);
    }
    return(hbla);
}*/

char *poloniex_parsebalance(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    char *itemstr = 0; cJSON *item,*obj; double onorders,btcvalue;
    *balancep = 0.;
    if ( exchange->balancejson != 0 && (item= jobj(exchange->balancejson,coinstr)) != 0 )
    {
        itemstr = jprint(item,0);
        *balancep = jdouble(item,"available");
        onorders = jdouble(item,"onOrders");
        btcvalue = jdouble(item,"btcValue");
        if ( (obj= cJSON_Parse(itemstr)) != 0 )
        {
            free(itemstr);
            jaddstr(obj,"base",coinstr);
            jaddnum(obj,"balance",*balancep);
            jaddnum(obj,"onOrders",onorders);
            jaddnum(obj,"btcvalue",btcvalue);
            itemstr = jprint(obj,1);
        }
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

int32_t poloniex_supports(char *base,char *rel)
{
    if ( strlen(base) > 5 || strlen(rel) > 5 || strcmp(rel,"CNY") == 0 || strcmp(base,"CNY") == 0 || strcmp(rel,"USD") == 0 || strcmp(base,"USD") == 0 )
        return(0);
    if ( strcmp(rel,"BTC") == 0 )
        return(1);
    else if ( strcmp(base,"BTC") == 0 )
        return(-1);
    else return(0);
    //char *poloassets[][8] = { { "UNITY", "12071612744977229797" },  { "JLH", "6932037131189568014" },  { "XUSD", "12982485703607823902" },  { "LQD", "4630752101777892988" },  { "NXTI", "14273984620270850703" }, { "CNMT", "7474435909229872610", "6220108297598959542" } };
    //return(add_exchange_assetids(assetids,n,BTC_ASSETID,baseid,relid,exchangeid,poloassets,(int32_t)(sizeof(poloassets)/sizeof(*poloassets))));
}

double prices777_poloniex(struct prices777 *prices,int32_t maxdepth)
{
    char market[128];
    if ( prices->url[0] == 0 )
    {
        sprintf(market,"%s_%s",prices->rel,prices->base);
        sprintf(prices->url,"https://poloniex.com/public?command=returnOrderBook&currencyPair=%s&depth=%d",market,maxdepth);
    }
    return(prices777_standard("poloniex",prices->url,prices,0,0,maxdepth,0));
}

int32_t kraken_supports(char *_base,char *_rel)
{
    char *supports[] = { "BTC", "ETH", "LTC", "NMC", "STR", "DOGE", "XVN", "XRP", "USD", "CAD", "JPY", "GBP", "KRW" };
    int32_t i,j; char base[64],rel[64];
    strcpy(base,_base), strcpy(rel,_rel);
    touppercase(base), touppercase(rel);
    if ( strlen(base) > 5 || strlen(rel) > 5 )
        return(0);
    for (i=0; i<sizeof(supports)/sizeof(*supports); i++)
        if ( strcmp(base,supports[i]) == 0 )
        {
            for (j=0; j<sizeof(supports)/sizeof(*supports); j++)
                if ( strcmp(rel,supports[j]) == 0 )
                    return(1);
            break;
        }
    return(0);
}

double prices777_kraken(struct prices777 *prices,int32_t maxdepth)
{
    char market[128],field[64],base[64],rel[64],*jsonstr; cJSON *json; double hbla = 0.;
    strcpy(base,prices->base), strcpy(rel,prices->rel);
    touppercase(base), touppercase(rel);
    if ( strcmp(base,"BTC") == 0 )
        strcpy(base,"XBT");
    if ( strcmp(rel,"BTC") == 0 )
        strcpy(rel,"XBT");
    if ( strcmp(base,"DOGE") == 0 )
        strcpy(base,"XDG");
    if ( strcmp(rel,"DOGE") == 0 )
        strcpy(rel,"XDG");
    sprintf(field,"X%sZ%s",base,rel);
    if ( prices->url[0] == 0 )
    {
        sprintf(market,"%s%s",base,rel);
        sprintf(prices->url,"https://api.kraken.com/0/public/Depth?pair=%s&count=%d",market,maxdepth);
    }
    if ( (jsonstr= issue_curl(prices->url)) != 0 )
    {
//{"error":[],"result":{"XXBTZUSD":{"asks":[["230.31677","1.438",1440886427],["230.31678","7.229",1440886068],["230.77732","0.012",1440876801],["230.77833","9.642",1440885707],["231.24081","9.719",1440884428]],"bids":[["228.04086","3.052",1440886443],["228.04085","0.590",1440886446],["228.04076","9.550",1440886434],["227.58559","10.214",1440800610],["227.56018","5.000",1440881811]]}}}
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            //printf("got.(%s)\n",jsonstr);
            hbla = prices777_json_orderbook("kraken",prices,maxdepth,jobj(json,"result"),field,"bids","asks",0,0);
            free_json(json);
        }
        free(jsonstr);
    }
    return(hbla);
}

char *bitfinex_parsebalance(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    //[[{"type":"deposit","currency":"btc","amount":"0.0","available":"0.0"},{"type":"deposit","currency":"usd","amount":"0.0","available":"0.0"},{"type":"exchange","currency":"btc","amount":"0.01065851","available":"0.01065851"},{"type":"exchange","currency":"usd","amount":"23386.37278962","available":"0.00378962"},{"type":"trading","currency":"btc","amount":"0.0","available":"0.0"},{"type":"trading","currency":"usd","amount":"0.0","available":"0.0"}]]
    int32_t i,n,ind; char field[64],*str,*typestr,*itemstr = 0; cJSON *item,*obj,*array; double amounts[3],avail[3],val0,val1;
    *balancep = 0.;
    strcpy(field,coinstr), tolowercase(field);
    memset(amounts,0,sizeof(amounts));
    memset(avail,0,sizeof(avail));
    if ( exchange->balancejson != 0 && is_cJSON_Array(exchange->balancejson) != 0 && (n= cJSON_GetArraySize(exchange->balancejson)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            if ( (item= jitem(exchange->balancejson,i)) != 0 )
            {
                if ( (str= jstr(item,"currency")) != 0 && strcmp(field,str) == 0 )
                {
                    val0 = jdouble(item,"amount");
                    val1 = jdouble(item,"available");
                    if ( (typestr= jstr(item,"type")) != 0 )
                    {
                        if ( strcmp(typestr,"deposit") == 0 )
                            ind = 0;
                        else if ( strcmp(typestr,"exchange") == 0 )
                            ind = 1;
                        else if ( strcmp(typestr,"trading") == 0 )
                            ind = 2;
                        else ind = -1;
                        if ( ind >= 0 )
                        {
                            amounts[ind] = val0;
                            avail[ind] = val1;
                        }
                    }
                }
            }
        }
        if ( (obj= cJSON_CreateObject()) != 0 )
        {
            touppercase(field);
            *balancep = avail[0] + avail[1] + avail[2];
            jaddstr(obj,"base",field);
            jaddnum(obj,"balance",*balancep);
            jaddnum(obj,"total",amounts[0]+amounts[1]+amounts[2]);
            array = cJSON_CreateArray(), jaddinum(array,avail[0]), jaddinum(array,amounts[0]), jadd(obj,"deposit",array);
            array = cJSON_CreateArray(), jaddinum(array,avail[1]), jaddinum(array,amounts[1]), jadd(obj,"exchange",array);
            array = cJSON_CreateArray(), jaddinum(array,avail[2]), jaddinum(array,amounts[2]), jadd(obj,"trading",array);
            itemstr = jprint(obj,1);
        }
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

int32_t bitfinex_supports(char *base,char *rel)
{
    char *baserels[][2] = { {"btc","usd"}, {"ltc","usd"}, {"ltc","btc"} };
    return(baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel));
}

double prices777_bitfinex(struct prices777 *prices,int32_t maxdepth)
{
    if ( prices->url[0] == 0 )
        sprintf(prices->url,"https://api.bitfinex.com/v1/book/%s%s",prices->base,prices->rel);
    return(prices777_standard("bitfinex",prices->url,prices,"price","amount",maxdepth,0));
}

char *btce_parsebalance(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    //btce.({"success":1,"return":{"funds":{"usd":73.02571846,"btc":0,"ltc":0,"nmc":0,"rur":0,"eur":0,"nvc":0.0000322,"trc":0,"ppc":0.00000002,"ftc":0,"xpm":2.28605349,"cnh":0,"gbp":0},"rights":{"info":1,"trade":1,"withdraw":0},"transaction_count":0,"open_orders":3,"server_time":1441918649}})
    char field[128],*itemstr = 0; cJSON *obj,*item;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    if ( exchange->balancejson != 0 && (obj= jobj(exchange->balancejson,"return")) != 0 && (item= jobj(obj,"funds")) != 0 )
    {
        *balancep = jdouble(item,field);
        obj = cJSON_CreateObject();
        touppercase(field);
        jaddstr(obj,"base",field);
        jaddnum(obj,"balance",*balancep);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

int32_t btce_supports(char *base,char *rel)
{
    char *baserels[][2] = { {"btc","usd"}, {"btc","rur"}, {"btc","eur"}, {"ltc","btc"}, {"ltc","usd"}, {"ltc","rur"}, {"ltc","eur"}, {"nmc","btc"}, {"nmc","usd"}, {"nvc","btc"}, {"nvc","usd"}, {"eur","usd"}, {"eur","rur"}, {"ppc","btc"}, {"ppc","usd"} };
    return(baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel));
}

double prices777_btce(struct prices777 *prices,int32_t maxdepth)
{
    char field[64];
    sprintf(field,"%s_%s",prices->lbase,prices->lrel);
    if ( prices->url[0] == 0 )
        sprintf(prices->url,"https://btc-e.com/api/3/depth/%s",field);
    return(prices777_standard("btce",prices->url,prices,0,0,maxdepth,field));
}

char *bitstamp_parsebalance(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    char field[128],*itemstr = 0; cJSON *obj,*item;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    if ( exchange->balancejson != 0 && (obj= jobj(exchange->balancejson,"return")) != 0 && (item= jobj(obj,"funds")) != 0 )
    {
        *balancep = jdouble(item,field);
        obj = cJSON_CreateObject();
        touppercase(field);
        jaddstr(obj,"base",field);
        jaddnum(obj,"balance",*balancep);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

int32_t bitstamp_supports(char *base,char *rel)
{
    if ( strcmp(base,"BTC") == 0 && strcmp(rel,"USD") == 0 )
        return(1);
    else if ( strcmp(rel,"BTC") == 0 && strcmp(base,"USD") == 0 )
        return(-1);
    else return(0);
}

double prices777_bitstamp(struct prices777 *prices,int32_t maxdepth)
{
    if ( prices->url[0] == 0 )
        sprintf(prices->url,"https://www.bitstamp.net/api/order_book/");
    return(prices777_standard("bitstamp",prices->url,prices,0,0,maxdepth,0));
}

char *okcoin_parsebalance(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    //okcoin.({"info":{"funds":{"asset":{"net":"0","total":"0"},"free":{"btc":"0","ltc":"0","usd":"0"},"freezed":{"btc":"0","ltc":"0","usd":"0"}}},"result":true})
    char field[128],*itemstr = 0; cJSON *obj,*item,*avail,*locked; double lockval = 0;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    if ( exchange->balancejson != 0 && (obj= jobj(exchange->balancejson,"info")) != 0 && (item= jobj(obj,"funds")) != 0 )
    {
        if ( (avail= jobj(item,"free")) != 0 )
            *balancep = jdouble(avail,field);
        if ( (locked= jobj(item,"freezed")) != 0 )
            lockval = jdouble(locked,field);
        obj = cJSON_CreateObject();
        touppercase(field);
        jaddstr(obj,"base",field);
        jaddnum(obj,"balance",*balancep);
        jaddnum(obj,"locked",lockval);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

int32_t okcoin_supports(char *base,char *rel)
{
    char *baserels[][2] = { {"btc","usd"}, {"ltc","usd"} };
    return(baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel));
}

double prices777_okcoin(struct prices777 *prices,int32_t maxdepth)
{
    if ( prices->url[0] == 0 )
        sprintf(prices->url,"https://www.okcoin.com/api/v1/depth.do?symbol=%s_%s",prices->lbase,prices->lrel);
    if ( strcmp(prices->rel,"USD") != 0 && strcmp(prices->rel,"BTC") != 0 )
    {
        fprintf(stderr,">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> FATAL ERROR OKCOIN.(%s) only supports USD\n",prices->url);
        printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> FATAL ERROR OKCOIN.(%s) only supports USD\n",prices->url);
        exit(-1);
        return(0);
    }
    return(prices777_standard("okcoin",prices->url,prices,0,0,maxdepth,0));
}

char *huobi_parsebalance(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    char field[128],*itemstr = 0; cJSON *obj,*item;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    if ( exchange->balancejson != 0 && (obj= jobj(exchange->balancejson,"return")) != 0 && (item= jobj(obj,"funds")) != 0 )
    {
        *balancep = jdouble(item,field);
        obj = cJSON_CreateObject();
        touppercase(field);
        jaddstr(obj,"base",field);
        jaddnum(obj,"balance",*balancep);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

int32_t huobi_supports(char *base,char *rel)
{
    char *baserels[][2] = { {"btc","cny"}, {"ltc","cny"} };
    return(baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel));
}

double prices777_huobi(struct prices777 *prices,int32_t maxdepth)
{
    if ( prices->url[0] == 0 )
        sprintf(prices->url,"http://api.huobi.com/staticmarket/depth_%s_json.js ",prices->lbase);
    return(prices777_standard("huobi",prices->url,prices,0,0,maxdepth,0));
}

int32_t bityes_supports(char *base,char *rel)
{
    char *baserels[][2] = { {"btc","usd"}, {"ltc","usd"} };
    return(baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel));
}

double prices777_bityes(struct prices777 *prices,int32_t maxdepth)
{
    //if ( prices->url[0] == 0 )
    sprintf(prices->url,"https://market.bityes.com/%s_%s/depth.js?time=%ld",prices->lrel,prices->lbase,(long)time(NULL));
    return(prices777_standard("bityes",prices->url,prices,0,0,maxdepth,0));
}

char *coinbase_parsebalance(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    char field[128],*itemstr = 0; cJSON *obj,*item;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    if ( exchange->balancejson != 0 && (obj= jobj(exchange->balancejson,"return")) != 0 && (item= jobj(obj,"funds")) != 0 )
    {
        *balancep = jdouble(item,field);
        obj = cJSON_CreateObject();
        touppercase(field);
        jaddstr(obj,"base",field);
        jaddnum(obj,"balance",*balancep);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

int32_t coinbase_supports(char *base,char *rel)
{
    if ( strcmp(base,"BTC") == 0 && strcmp(rel,"USD") == 0 )
        return(1);
    else if ( strcmp(rel,"BTC") == 0 && strcmp(base,"USD") == 0 )
        return(-1);
    else return(0);
}

double prices777_coinbase(struct prices777 *prices,int32_t maxdepth)
{
    if ( prices->url[0] == 0 )
        sprintf(prices->url,"https://api.exchange.coinbase.com/products/%s-%s/book?level=2",prices->base,prices->rel);
    return(prices777_standard("coinbase",prices->url,prices,0,0,maxdepth,0));
}

char *lakebtc_parsebalance(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    char field[128],*str,*itemstr = 0; cJSON *obj=0,*item=0,*prof=0; double locked = 0;
    *balancep = 0.;
    strcpy(field,coinstr);
    touppercase(field);
    if ( exchange->balancejson != 0 && (obj= jobj(exchange->balancejson,"balance")) != 0 && (item= jobj(exchange->balancejson,"locked")) != 0 && (prof= jobj(exchange->balancejson,"profile")) != 0 )
    {
        *balancep = jdouble(obj,field);
        locked = jdouble(item,field);
        obj = cJSON_CreateObject();
        jaddstr(obj,"base",field);
        jaddnum(obj,"balance",*balancep);
        jaddnum(obj,"locked",locked);
        if ( (str= jstr(prof,"btc_deposit_addres")) != 0 )
            jaddstr(obj,"deposit_address",str);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

int32_t lakebtc_supports(char *base,char *rel)
{
    char *baserels[][2] = { {"btc","usd"}, {"btc","cny"} };
    return(baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel));
}

double prices777_lakebtc(struct prices777 *prices,int32_t maxdepth)
{
    if ( prices->url[0] == 0 )
    {
        if ( strcmp(prices->rel,"USD") == 0 )
            sprintf(prices->url,"https://www.LakeBTC.com/api_v1/bcorderbook");
        else if ( strcmp(prices->rel,"CNY") == 0 )
            sprintf(prices->url,"https://www.LakeBTC.com/api_v1/bcorderbook_cny");
        else printf("illegal lakebtc pair.(%s/%s)\n",prices->base,prices->rel);
    }
    return(prices777_standard("lakebtc",prices->url,prices,0,0,maxdepth,0));
}

#ifdef exmo_supported
int32_t exmo_supports(char *base,char *rel)
{
    if ( strcmp(base,"BTC") == 0 && (strcmp(rel,"USD") == 0 || strcmp(rel,"EUR") == 0 || strcmp(rel,"RUR") == 0) )
        return(1);
    else if ( strcmp(rel,"BTC") == 0 && (strcmp(base,"USD") == 0 || strcmp(base,"EUR") == 0 || strcmp(base,"RUR") == 0) )
        return(-1);
    else return(0);
}

double prices777_exmo(struct prices777 *prices,int32_t maxdepth)
{
    if ( prices->url[0] == 0 )
        sprintf(prices->url,"https://api.exmo.com/api_v2/orders_book?pair=%s_%s",prices->base,prices->rel);
    return(prices777_standard("exmo",prices->url,prices,0,0,maxdepth,0));
}
#endif

// "gatecoin", "quoine", "jubi", "hitbtc"

char *btc38_parsebalance(struct exchange_info *exchange,double *balancep,char *coinstr)
{
    char field[128],*str,*itemstr = 0; cJSON *obj; double lockbalance,imma;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    strcat(field,"_balance");
    if ( exchange->balancejson != 0 && (str= jstr(exchange->balancejson,field)) != 0 )
    {
        *balancep = jdouble(exchange->balancejson,field);
        strcpy(field,coinstr), tolowercase(field), strcat(field,"_balance_lock");
        lockbalance = jdouble(exchange->balancejson,field);
        strcpy(field,coinstr), tolowercase(field), strcat(field,"_balance_imma");
        imma = jdouble(exchange->balancejson,field);
        obj = cJSON_CreateObject();
        jaddnum(obj,"balance",*balancep);
        jaddnum(obj,"locked_balance",lockbalance);
        jaddnum(obj,"imma_balance",imma);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

int32_t btc38_supports(char *_base,char *_rel)
{
    char *cnypairs[] = { "BTC", "LTC", "DOGE", "XRP", "BTS", "STR", "NXT", "BLK", "YBC", "BILS", "BOST", "PPC", "APC", "ZCC", "XPM", "DGC", "MEC", "WDC", "QRK", "BEC", "ANC", "UNC", "RIC", "SRC", "TAG" };
    char *btcpairs[] = { "TMC", "LTC", "DOGE", "XRP", "BTS", "STR", "NXT", "BLK", "XEM", "VPN", "BILS", "BOST", "WDC", "ANC", "XCN", "VOOT", "SYS", "NRS", "NAS", "SYNC", "MED", "EAC" };
    int32_t i; char base[64],rel[64];
    strcpy(base,_base), strcpy(rel,_rel);
    touppercase(base), touppercase(rel);
    if ( strlen(base) > 5 || strlen(rel) > 5 )
        return(0);
    if ( strcmp(base,"BTC") == 0 && strcmp(rel,"CNY") == 0 )
        return(1);
    else if ( strcmp(base,"CNY") == 0 && strcmp(rel,"BTC") == 0 )
        return(-1);
    else if ( strcmp(base,"BTC") == 0 )
    {
        for (i=0; i<sizeof(btcpairs)/sizeof(*btcpairs); i++)
            if ( strcmp(btcpairs[i],rel) == 0 )
                return(-1);
    }
    else if ( strcmp(rel,"BTC") == 0 )
    {
        for (i=0; i<sizeof(btcpairs)/sizeof(*btcpairs); i++)
            if ( strcmp(btcpairs[i],base) == 0 )
                return(1);
    }
    else if ( strcmp(base,"CNY") == 0 )
    {
        for (i=0; i<sizeof(cnypairs)/sizeof(*cnypairs); i++)
            if ( strcmp(cnypairs[i],rel) == 0 )
                return(-1);
    }
    else if ( strcmp(rel,"CNY") == 0 )
    {
        for (i=0; i<sizeof(cnypairs)/sizeof(*cnypairs); i++)
            if ( strcmp(cnypairs[i],base) == 0 )
                return(1);
    }
    printf("BTC38 doesnt support (%s/%s)\n",base,rel);
    return(0);
}

double prices777_btc38(struct prices777 *prices,int32_t maxdepth)
{
    if ( prices->url[0] == 0 )
    {
        if ( strcmp(prices->lbase,"cny") == 0 && strcmp(prices->lrel,"btc") == 0 )
            sprintf(prices->url,"http://api.btc38.com/v1/depth.php?c=%s&mk_type=%s","btc","cny");
        else sprintf(prices->url,"http://api.btc38.com/v1/depth.php?c=%s&mk_type=%s",prices->lbase,prices->lrel);
    }
    return(prices777_standard("btc38",prices->url,prices,0,0,maxdepth,0));
}

char *quadriga_parsebalance(struct exchange_info *exchange,double *balancep,char *coinstr)
{
//[{"btc_available":"0.00000000","btc_reserved":"0.00000000","btc_balance":"0.00000000","cad_available":"0.00","cad_reserved":"0.00","cad_balance":"0.00","usd_available":"0.00","usd_reserved":"0.00","usd_balance":"0.00","xau_available":"0.000000","xau_reserved":"0.000000","xau_balance":"0.000000","fee":"0.5000"}]
    char field[128],*str,*itemstr = 0; cJSON *obj; double reserv,total;
    *balancep = 0.;
    strcpy(field,coinstr);
    tolowercase(field);
    strcat(field,"_available");
    if ( exchange->balancejson != 0 && (str= jstr(exchange->balancejson,field)) != 0 )
    {
        *balancep = jdouble(exchange->balancejson,field);
        strcpy(field,coinstr), tolowercase(field), strcat(field,"_reserved");
        reserv = jdouble(exchange->balancejson,field);
        strcpy(field,coinstr), tolowercase(field), strcat(field,"_balance");
        total = jdouble(exchange->balancejson,field);
        obj = cJSON_CreateObject();
        jaddnum(obj,"balance",*balancep);
        jaddnum(obj,"locked_balance",reserv);
        jaddnum(obj,"total",total);
        itemstr = jprint(obj,1);
    }
    if ( itemstr == 0 )
        return(clonestr("{\"error\":\"cant find coin balance\"}"));
    return(itemstr);
}

int32_t quadriga_supports(char *base,char *rel)
{
    char *baserels[][2] = { {"btc","usd"}, {"btc","cad"} };
    return(baserel_polarity(baserels,(int32_t)(sizeof(baserels)/sizeof(*baserels)),base,rel));
}

double prices777_quadriga(struct prices777 *prices,int32_t maxdepth)
{
    if ( prices->url[0] == 0 )
        sprintf(prices->url,"https://api.quadrigacx.com/v2/order_book?book=%s_%s",prices->lbase,prices->lrel);
    return(prices777_standard("quadriga",prices->url,prices,0,0,maxdepth,0));
}


/*void prices777_kraken(struct prices777 *prices,int32_t maxdepth)
 {
 if ( prices->url[0] == 0 )
 sprintf(prices->url,"https://api.kraken.com/0/public/Depth"); // need POST
 prices777_standard("kraken",prices->url,prices,0,0,maxdepth);
 }*/

/*void prices777_itbit(struct prices777 *prices,int32_t maxdepth)
 {
 if ( prices->url[0] == 0 )
 sprintf(prices->url,"https://www.itbit.com/%s%s",prices->base,prices->rel);
 prices777_standard("itbit",prices->url,prices,0,0,maxdepth);
 }*/
#endif

uint64_t prices777_truefx(uint64_t *millistamps,double *bids,double *asks,double *opens,double *highs,double *lows,char *username,char *password,uint64_t idnum)
{
    char *truefxfmt = "http://webrates.truefx.com/rates/connect.html?f=csv&id=jl777:truefxtest:poll:1437671654417&c=EUR/USD,USD/JPY,GBP/USD,EUR/GBP,USD/CHF,AUD/NZD,CAD/CHF,CHF/JPY,EUR/AUD,EUR/CAD,EUR/JPY,EUR/CHF,USD/CAD,AUD/USD,GBP/JPY,AUD/CAD,AUD/CHF,AUD/JPY,EUR/NOK,EUR/NZD,GBP/CAD,GBP/CHF,NZD/JPY,NZD/USD,USD/NOK,USD/SEK";
    
    // EUR/USD,1437569931314,1.09,034,1.09,038,1.08922,1.09673,1.09384 USD/JPY,1437569932078,123.,778,123.,781,123.569,123.903,123.860 GBP/USD,1437569929008,1.56,332,1.56,337,1.55458,1.56482,1.55538 EUR/GBP,1437569931291,0.69,742,0.69,750,0.69710,0.70383,0.70338 USD/CHF,1437569932237,0.96,142,0.96,153,0.95608,0.96234,0.95748 EUR/JPY,1437569932237,134.,960,134.,972,134.842,135.640,135.476 EUR/CHF,1437569930233,1.04,827,1.04,839,1.04698,1.04945,1.04843 USD/CAD,1437569929721,1.30,231,1.30,241,1.29367,1.30340,1.29466 AUD/USD,1437569931700,0.73,884,0.73,890,0.73721,0.74395,0.74200 GBP/JPY,1437569931924,193.,500,193.,520,192.298,193.670,192.649
    char url[1024],userpass[1024],buf[128],base[64],rel[64],*str; cJSON *array; int32_t jpyflag,i,c,n = 0; double pre,pre2,bid,ask,open,high,low; long millistamp;
    //printf("truefx.(%s)(%s).%llu\n",username,password,(long long)idnum);
    url[0] = 0;
    if ( username[0] != 0 && password[0] != 0 )
    {
        if ( idnum == 0 )
        {
            sprintf(userpass,"http://webrates.truefx.com/rates/connect.html?f=csv&s=y&u=%s&p=%s&q=poll",username,password);
            if ( (str= issue_curl(userpass)) != 0 )
            {
                _stripwhite(str,0);
                printf("(%s) -> (%s)\n",userpass,str);
                sprintf(userpass,"%s:%s:poll:",username,password);
                idnum = calc_nxt64bits(str + strlen(userpass));
                free(str);
                printf("idnum.%llu\n",(long long)idnum);
            }
        }
        if ( idnum != 0 )
            sprintf(url,truefxfmt,username,password,(long long)idnum);
    }
    if ( url[0] == 0 )
        sprintf(url,"http://webrates.truefx.com/rates/connect.html?f=csv&s=y");
    if ( (str= issue_curl(url)) != 0 )
    {
        //printf("(%s) -> (%s)\n",url,str);
        while ( str[n + 0] != 0 && str[n] != '\n' && str[n] != '\r' )
        {
            for (i=jpyflag=0; str[n + i]!=' '&&str[n + i]!='\n'&&str[n + i]!='\r'&&str[n + i]!=0; i++)
            {
                if ( i > 0 && str[n+i] == ',' && str[n+i-1] == '.' )
                    str[n+i-1] = ' ', jpyflag = 1;
                else if ( i > 0 && str[n+i-1] == ',' && str[n+i] == '0' && str[n+i+1+2] == ',' )
                {
                    str[n+i] = ' ';
                    if ( str[n+i+1] == '0' )
                        str[n+i+1] = ' ', i++;
                }
            }
            memcpy(base,str+n,3), base[3] = 0;
            memcpy(rel,str+n+4,3), rel[3] = 0;
            str[n + i] = 0;
            //printf("str.(%s) (%s/%s) %d n.%d i.%d\n",str+n,base,rel,str[n],n,i);
            sprintf(buf,"[%s]",str+n+7+1);
            n += i + 1;
            if ( (array= cJSON_Parse(buf)) != 0 )
            {
                if ( is_cJSON_Array(array) != 0 )
                {
                    millistamp = (uint64_t)get_API_float(jitem(array,0));
                    pre = get_API_float(jitem(array,1));
                    bid = get_API_float(jitem(array,2));
                    pre2 = get_API_float(jitem(array,3));
                    ask = get_API_float(jitem(array,4));
                    open = get_API_float(jitem(array,5));
                    high = get_API_float(jitem(array,6));
                    low = get_API_float(jitem(array,7));
                    if ( jpyflag != 0 )
                        bid = pre + (bid / 1000.), ask = pre2 + (ask / 1000.);
                    else bid = pre + (bid / 100000.), ask = pre2 + (ask / 100000.);
                    if ( (c= prices777_contractnum(base,rel)) >= 0 )
                    {
                        char name[64];
                        strcpy(name,base), strcat(name,rel);
                        if ( BUNDLE.truefx[c] == 0 )
                            BUNDLE.truefx[c] = prices777_initpair(0,"truefx",base,rel,0,name,stringbits(base),stringbits(rel),0);
                        millistamps[c] = millistamp,opens[c] = open, highs[c] = high, lows[c] = low, bids[c] = bid, asks[c] = ask;
                        if ( Debuglevel > 2 )
                        {
                            if ( jpyflag != 0 )
                                printf("%s%s.%-2d %llu: %.3f %.3f %.3f | %.3f %.3f\n",base,rel,c,(long long)millistamp,open,high,low,bid,ask);
                            else printf("%s%s.%-2d %llu: %.5f %.5f %.5f | %.5f %.5f\n",base,rel,c,(long long)millistamp,open,high,low,bid,ask);
                        }
                    } else printf("unknown basepair.(%s) (%s)\n",base,rel);
                }
                free_json(array);
            } else printf("cant parse.(%s)\n",buf);
        }
        free(str);
    }
    return(idnum);
}


double prices777_fxcm(double lhlogmatrix[8][8],double logmatrix[8][8],double bids[64],double asks[64],double highs[64],double lows[64])
{
    char name[64],*xmlstr,*str; cJSON *json,*obj; int32_t i,j,c,flag,k,n = 0; double bid,ask,high,low; struct destbuf numstr;
    memset(bids,0,sizeof(*bids) * NUM_CONTRACTS), memset(asks,0,sizeof(*asks) * NUM_CONTRACTS);
    if ( (xmlstr= issue_curl("http://rates.fxcm.com/RatesXML")) != 0 )
    {
        _stripwhite(xmlstr,0);
        //printf("(%s)\n",xmlstr);
        i = 0;
        if ( strncmp("<?xml",xmlstr,5) == 0 )
            for (; xmlstr[i]!='>'&&xmlstr[i]!=0; i++)
                ;
        if ( xmlstr[i] == '>' )
            i++;
        for (j=0; xmlstr[i]!=0; i++)
        {
            if ( strncmp("<Rates>",&xmlstr[i],strlen("<Rates>")) == 0 )
                xmlstr[j++] = '[', i += strlen("<Rates>")-1;
            else if ( strncmp("<RateSymbol=",&xmlstr[i],strlen("<RateSymbol=")) == 0 )
            {
                if ( j > 1 )
                    xmlstr[j++] = ',';
                memcpy(&xmlstr[j],"{\"Symbol\":",strlen("{\"Symbol\":")), i += strlen("<RateSymbol=")-1, j += strlen("{\"Symbol\":");
            }
            else
            {
                char *strpairs[][2] = { { "<Bid>", "\"Bid\":" }, { "<Ask>", "\"Ask\":" }, { "<High>", "\"High\":" }, { "<Low>", "\"Low\":" }, { "<Direction>", "\"Direction\":" }, { "<Last>", "\"Last\":\"" } };
                for (k=0; k<sizeof(strpairs)/sizeof(*strpairs); k++)
                    if ( strncmp(strpairs[k][0],&xmlstr[i],strlen(strpairs[k][0])) == 0 )
                    {
                        memcpy(&xmlstr[j],strpairs[k][1],strlen(strpairs[k][1]));
                        i += strlen(strpairs[k][0])-1;
                        j += strlen(strpairs[k][1]);
                        break;
                    }
                if ( k == sizeof(strpairs)/sizeof(*strpairs) )
                {
                    char *ends[] = { "</Bid>", "</Ask>", "</High>", "</Low>", "</Direction>", "</Last>", "</Rate>", "</Rates>", ">" };
                    for (k=0; k<sizeof(ends)/sizeof(*ends); k++)
                        if ( strncmp(ends[k],&xmlstr[i],strlen(ends[k])) == 0 )
                        {
                            i += strlen(ends[k])-1;
                            if ( strcmp("</Rate>",ends[k]) == 0 )
                                xmlstr[j++] = '}';
                            else if ( strcmp("</Rates>",ends[k]) == 0 )
                                xmlstr[j++] = ']';
                            else if ( strcmp("</Last>",ends[k]) == 0 )
                                xmlstr[j++] = '\"';
                            else xmlstr[j++] = ',';
                            break;
                        }
                    if ( k == sizeof(ends)/sizeof(*ends) )
                        xmlstr[j++] = xmlstr[i];
                }
            }
        }
        xmlstr[j] = 0;
        if ( (json= cJSON_Parse(xmlstr)) != 0 )
        {
            /*<Rate Symbol="USDJPY">
             <Bid>123.763</Bid>
             <Ask>123.786</Ask>
             <High>123.956</High>
             <Low>123.562</Low>
             <Direction>-1</Direction>
             <Last>08:49:15</Last>*/
            //printf("Parsed stupid XML! (%s)\n",xmlstr);
            if ( is_cJSON_Array(json) != 0 && (n= cJSON_GetArraySize(json)) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    obj = jitem(json,i);
                    flag = 0;
                    c = -1;
                    if ( (str= jstr(obj,"Symbol")) != 0 && strlen(str) < 15 )
                    {
                        strcpy(name,str);
                        if ( strcmp(name,"USDCNH") == 0 )
                            strcpy(name,"USDCNY");
                        copy_cJSON(&numstr,jobj(obj,"Bid")), bid = atof(numstr.buf);
                        copy_cJSON(&numstr,jobj(obj,"Ask")), ask = atof(numstr.buf);
                        copy_cJSON(&numstr,jobj(obj,"High")), high = atof(numstr.buf);
                        copy_cJSON(&numstr,jobj(obj,"Low")), low = atof(numstr.buf);
                        if ( (c= prices777_contractnum(name,0)) >= 0 )
                        {
                            bids[c] = bid, asks[c] = ask, highs[c] = high, lows[c] = low;
                            //printf("c.%d (%s) %f %f\n",c,name,bid,ask);
                            flag = 1;
                            if ( BUNDLE.fxcm[c] == 0 )
                            {
                                //printf("max.%ld FXCM: not initialized.(%s) %d\n",sizeof(CONTRACTS)/sizeof(*CONTRACTS),name,c);
                                BUNDLE.fxcm[c] = prices777_initpair(0,"fxcm",name,0,0,name,peggy_basebits(name),peggy_relbits(name),0);
                            }
                        } else printf("cant find.%s\n",name);//, getchar();
                    }
                    if ( flag == 0 )
                        printf("FXCM: Error finding.(%s) c.%d (%s)\n",name,c,cJSON_Print(obj));
                }
            }
            free_json(json);
        } else printf("couldnt parse.(%s)\n",xmlstr);
        free(xmlstr);
    }
    calc_primary_currencies(lhlogmatrix,lows,highs);
    return(calc_primary_currencies(logmatrix,bids,asks));
}

double prices777_instaforex(double logmatrix[8][8],uint32_t timestamps[NUM_COMBINED+1],double bids[128],double asks[128])
{
    //{"NZDUSD":{"symbol":"NZDUSD","lasttime":1437580206,"digits":4,"change":"-0.0001","bid":"0.6590","ask":"0.6593"},
    char *jsonstr,*str; cJSON *json,*item; int32_t i,c; struct destbuf numstr;
    memset(timestamps,0,sizeof(*timestamps) * (NUM_COMBINED + 1)), memset(bids,0,sizeof(*bids) * (NUM_COMBINED + 1)), memset(asks,0,sizeof(*asks) * (NUM_COMBINED + 1));
    if ( (jsonstr= issue_curl("https://quotes.instaforex.com/get_quotes.php?q=NZDUSD,NZDCHF,NZDCAD,NZDJPY,GBPNZD,EURNZD,AUDNZD,CADJPY,CADCHF,USDCAD,EURCAD,GBPCAD,AUDCAD,USDCHF,CHFJPY,EURCHF,GBPCHF,AUDCHF,EURUSD,EURAUD,EURJPY,EURGBP,GBPUSD,GBPJPY,GBPAUD,USDJPY,AUDJPY,AUDUSD,XAUUSD&m=json")) != 0 )
    {
        // printf("(%s)\n",jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            for (i=0; i<=NUM_CONTRACTS; i++)
            {
                if ( i < NUM_CONTRACTS )
                    str = CONTRACTS[i], c = i;
                else str = "XAUUSD", c = prices777_contractnum(str,0);
                if ( (item= jobj(json,str)) != 0 )
                {
                    timestamps[c] = juint(item,"lasttime");
                    copy_cJSON(&numstr,jobj(item,"bid")), bids[c] = atof(numstr.buf);
                    copy_cJSON(&numstr,jobj(item,"ask")), asks[c] = atof(numstr.buf);
                    //if ( c < NUM_CONTRACTS && Contract_rel[c] == JPY )
                    //    bids[i] /= 100., asks[i] /= 100.;
                    if ( Debuglevel > 2 )
                        printf("%s.(%.6f %.6f) ",str,bids[c],asks[c]);
                    if ( BUNDLE.instaforex[c] == 0 )
                        BUNDLE.instaforex[c] = prices777_initpair(0,"instaforex",str,0,0,str,peggy_basebits(str),peggy_relbits(str),0);
                }
            }
            free_json(json);
        }
        free(jsonstr);
    }
    return(calc_primary_currencies(logmatrix,bids,asks));
}

int32_t prices777_ecbparse(char *date,double *prices,char *url,int32_t basenum)
{
    char *jsonstr,*relstr,*basestr; int32_t count=0,i,relnum; cJSON *json,*ratesobj,*item; struct destbuf tmp;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        if ( Debuglevel > 2 )
            printf("(%s)\n",jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            copy_cJSON(&tmp,jobj(json,"date")), safecopy(date,tmp.buf,64);
            if ( (basestr= jstr(json,"base")) != 0 && strcmp(basestr,CURRENCIES[basenum]) == 0 && (ratesobj= jobj(json,"rates")) != 0 && (item= ratesobj->child) != 0 )
            {
                while ( item != 0 )
                {
                    if ( (relstr= get_cJSON_fieldname(item)) != 0 && (relnum= prices777_basenum(relstr)) >= 0 )
                    {
                        i = basenum*MAX_CURRENCIES + relnum;
                        prices[i] = item->valuedouble;
                        //if ( basenum == JPYNUM )
                        //    prices[i] *= 100.;
                        // else if ( relnum == JPYNUM )
                        //     prices[i] /= 100.;
                        count++;
                        if ( Debuglevel > 2 )
                            printf("(%02d:%02d %f) ",basenum,relnum,prices[i]);
                    } else printf("cant find.(%s)\n",relstr);//, getchar();
                    item = item->next;
                }
            }
            free_json(json);
        }
        free(jsonstr);
    }
    return(count);
}

int32_t prices777_ecb(char *date,double *prices,int32_t year,int32_t month,int32_t day)
{
    // http://api.fixer.io/latest?base=CNH
    // http://api.fixer.io/2000-01-03?base=USD
    // "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD"
    char baseurl[512],tmpdate[64],url[512],checkdate[16]; int32_t basenum,count,i,iter,nonz;
    checkdate[0] = 0;
    if ( year == 0 )
        strcpy(baseurl,"http://api.fixer.io/latest?base=");
    else
    {
        sprintf(checkdate,"%d-%02d-%02d",year,month,day);
        sprintf(baseurl,"http://api.fixer.io/%s?base=",checkdate);
    }
    count = 0;
    for (iter=0; iter<2; iter++)
    {
        for (basenum=0; basenum<sizeof(CURRENCIES)/sizeof(*CURRENCIES); basenum++)
        {
            if ( strcmp(CURRENCIES[basenum],"XAU") == 0 )
                break;
            if ( iter == 0 )
            {
                sprintf(url,"%s%s",baseurl,CURRENCIES[basenum]);
                count += prices777_ecbparse(basenum == 0 ? date : tmpdate,prices,url,basenum);
                if ( (basenum != 0 && strcmp(tmpdate,date) != 0) || (checkdate[0] != 0 && strcmp(checkdate,date) != 0) )
                {
                    printf("date mismatch (%s) != (%s) or checkdate.(%s)\n",tmpdate,date,checkdate);
                    return(-1);
                }
            }
            else
            {
                for (nonz=i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
                {
                    if ( strcmp(CURRENCIES[i],"XAU") == 0 )
                        break;
                    if ( prices[MAX_CURRENCIES*basenum + i] != 0. )
                        nonz++;
                    if ( Debuglevel > 2 )
                        printf("%8.5f ",prices[MAX_CURRENCIES*basenum + i]);
                }
                if ( Debuglevel > 2 )
                    printf("%s.%d %d\n",CURRENCIES[basenum],basenum,nonz);
            }
        }
    }
    return(count);
}

#endif

