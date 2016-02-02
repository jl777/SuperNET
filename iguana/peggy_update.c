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

#include "peggy.h"
#include "exchanges777.h"

short Baserel_contractnum[NUM_CURRENCIES+1][NUM_CURRENCIES+1] =
{
	{ 28, 18, 25, 22, 27,  9, 13,  0, 36 },
	{ 18, 29, 20, 21, 19, 10, 15,  5, 37 },
	{ 25, 20, 30, 23, 26,  7, 14,  3, -1 },
	{ 22, 21, 23, 31, 24, 11, 16,  4, 38 },
	{ 27, 19, 26, 24, 32, 12, 17,  6, 39 },
	{  9, 10,  7, 11, 12, 33,  8,  2, -1 },
	{ 13, 15, 14, 16, 17,  8, 34,  1, 40 },
	{  0,  5,  3,  4,  6,  2,  1, 35, -1 },
	{ 36, 37, -1, 38, 39, -1, 40, -1, 74 },
};

short Currency_contractdirs[NUM_CURRENCIES+1][NUM_CURRENCIES] =
{
	{ -1,  1,  1, -1, -1,  1, -1,  1 },
	{  1,  1,  1,  1,  1,  1,  1,  1 },
	{ -1, -1, -1, -1, -1, -1, -1,  1 },
	{  1,  1,  1, -1,  1,  1,  1,  1 },
	{  1,  1,  1, -1, -1,  1,  1,  1 },
	{ -1,  1,  1, -1, -1, -1, -1,  1 },
	{ -1, -1, -1,  1, -1, -1, -1,  1 },
	{  1,  1,  1,  1, -1, -1, -1,  1 },
	{  1,  1,  1,  1,  1,  1,  1,  1 },
};

static char *Yahoo_metals[] = { YAHOO_METALS };

char CURRENCIES[][8] = { "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK", // end of currencies
    "XAU", "XAG", "XPT", "XPD", // metals, gold must be first
    "BTCD", "BTC", "NXT", "LTC", "ETH", "DOGE", "BTS", "MAID", "XCP",  "XMR" // cryptos
};

char CONTRACTS[][16] = {  "NZDUSD", "NZDCHF", "NZDCAD", "NZDJPY", "GBPNZD", "EURNZD", "AUDNZD", "CADJPY", "CADCHF", "USDCAD", "EURCAD", "GBPCAD", "AUDCAD", "USDCHF", "CHFJPY", "EURCHF", "GBPCHF", "AUDCHF", "EURUSD", "EURAUD", "EURJPY", "EURGBP", "GBPUSD", "GBPJPY", "GBPAUD", "USDJPY", "AUDJPY", "AUDUSD", "USDCNY", "USDHKD", "USDMXN", "USDZAR", "USDTRY", "EURTRY", "TRYJPY", "USDSGD", "EURNOK", "USDNOK","USDSEK","USDDKK","EURSEK","EURDKK","NOKJPY","SEKJPY","USDPLN","EURPLN","USDILS", // no more currencies
    "XAUUSD", "XAGUSD", "XPTUSD", "XPDUSD", "COPPER", "NGAS", "UKOIL", "USOIL", // commodities
    // cryptos
    "NAS100", "SPX500", "US30", "BUND", "EUSTX50", "UK100", "JPN225", "GER30", "SUI30", "AUS200", "HKG33", "FRA40", "ESP35", "ITA40", "USDOLLAR", // indices
    "SuperNET" // assets
};

int32_t PAX_ispair(char *base,char *rel,char *contract)
{
    int32_t i,j;
    base[0] = rel[0] = 0;
    for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
    {
        if ( strncmp(CURRENCIES[i],contract,strlen(CURRENCIES[i])) == 0 )
        {
            for (j=0; j<sizeof(CURRENCIES)/sizeof(*CURRENCIES); j++)
                if ( strcmp(CURRENCIES[j],contract+strlen(CURRENCIES[i])) == 0 )
                {
                    strcpy(base,CURRENCIES[i]);
                    strcpy(rel,CURRENCIES[j]);
                    /*USDCNY 6.209700 -> 0.655564
                     USDCNY 6.204146 -> 0.652686
                     USDHKD 7.753400 -> 0.749321
                     USDHKD 7.746396 -> 0.746445
                     USDZAR 12.694000 -> 1.101688
                     USDZAR 12.682408 -> 1.098811
                     USDTRY 2.779700 -> 0.341327
                     EURTRY 3.048500 -> 0.386351
                     TRYJPY 44.724000 -> 0.690171
                     TRYJPY 44.679966 -> 0.687290
                     USDSGD 1.375200 -> 0.239415*/
                    //if ( strcmp(contract,"USDCNY") == 0 || strcmp(contract,"TRYJPY") == 0 || strcmp(contract,"USDZAR") == 0 )
                    //    printf("i.%d j.%d base.%s rel.%s\n",i,j,base,rel);
                    return((i<<8) | j);
                }
            break;
        }
    }
    return(-1);
}

int32_t PAX_basenum(char *base)
{
    int32_t i,j;
    if ( 1 )
    {
        for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
            for (j=0; j<sizeof(CURRENCIES)/sizeof(*CURRENCIES); j++)
                if ( i != j && strcmp(CURRENCIES[i],CURRENCIES[j]) == 0 )
                    printf("duplicate.(%s)\n",CURRENCIES[i]);//, getchar();
    }
    for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
        if ( strcmp(CURRENCIES[i],base) == 0 )
            return(i);
    return(-1);
}

int32_t PAX_contractnum(char *base,char *rel)
{
    int32_t i,j,c; char contractstr[16],*contract = 0;
    if ( 0 )
    {
        for (i=0; i<sizeof(CONTRACTS)/sizeof(*CONTRACTS); i++)
            for (j=0; j<sizeof(CONTRACTS)/sizeof(*CONTRACTS); j++)
                if ( i != j && strcmp(CONTRACTS[i],CONTRACTS[j]) == 0 )
                    printf("duplicate.(%s)\n",CONTRACTS[i]);//, getchar();
    }
    if ( base != 0 && base[0] != 0 && rel != 0 && rel[0] != 0 )
    {
        for (i=0; i<NUM_CURRENCIES; i++)
            if ( strcmp(base,CURRENCIES[i]) == 0 )
            {
                for (j=0; j<NUM_CURRENCIES; j++)
                    if ( strcmp(rel,CURRENCIES[j]) == 0 )
                        return(Baserel_contractnum[i][j]);
                break;
            }
        sprintf(contractstr,"%s%s",base,rel);
        contract = contractstr;
    } else contract = base;
    if ( contract != 0 && contract[0] != 0 )
    {
        for (c=0; c<sizeof(CONTRACTS)/sizeof(*CONTRACTS); c++)
            if ( strcmp(CONTRACTS[c],contract) == 0 )
                return(c);
    }
    return(-1);
}

cJSON *url_json(char *url)
{
    char *jsonstr; cJSON *json = 0;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //printf("(%s) -> (%s)\n",url,jsonstr);
        json = cJSON_Parse(jsonstr);
        free(jsonstr);
    }
    return(json);
}

cJSON *url_json2(char *url)
{
    char *jsonstr; cJSON *json = 0;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //printf("(%s) -> (%s)\n",url,jsonstr);
        json = cJSON_Parse(jsonstr);
        free(jsonstr);
    }
    return(json);
}

double PAX_yahoo(char *metal)
{
    // http://finance.yahoo.com/webservice/v1/symbols/allcurrencies/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XAU=X/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XAG=X/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XPT=X/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XPD=X/quote?format=json
    char url[1024],*jsonstr; cJSON *json,*obj,*robj,*item,*field; double price = 0.;
    sprintf(url,"http://finance.yahoo.com/webservice/v1/symbols/%s=X/quote?format=json",metal);
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //printf("(%s)\n",jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (obj= jobj(json,"list")) != 0 && (robj= jobj(obj,"resources")) != 0 && (item= jitem(robj,0)) != 0 )
            {
                if ( (robj= jobj(item,"resource")) != 0 && (field= jobj(robj,"fields")) != 0 && (price= jdouble(field,"price")) != 0 )
                    price = 1. / price;
            }
            free_json(json);
        }
        free(jsonstr);
    }
    if ( Debuglevel > 2 )
        printf("(%s %f) ",metal,price);
    return(price);
}

void PAX_btcprices(struct peggy_info *PEGS,int32_t enddatenum,int32_t numdates)
{
    int32_t i,n,year,month,day,seconds,datenum; char url[1024],date[64],*dstr,*str;
    uint32_t timestamp,utc32[MAX_SPLINES]; struct tai t;
    cJSON *coindesk,*quandl,*btcdhist,*bpi,*array,*item;
    double btcddaily[MAX_SPLINES],cdaily[MAX_SPLINES],qdaily[MAX_SPLINES],ask,high,low,bid,close,vol,quotevol,open,price = 0.;
    coindesk = url_json("http://api.coindesk.com/v1/bpi/historical/close.json");
    sprintf(url,"https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=%ld&end=9999999999&period=86400",(long)(time(NULL)-numdates*3600*24));
    if ( (bpi= jobj(coindesk,"bpi")) != 0 )
    {
        datenum = enddatenum;
        memset(utc32,0,sizeof(utc32));
        memset(cdaily,0,sizeof(cdaily));
        if ( datenum == 0 )
        {
            datenum = OS_conv_unixtime(&t,&seconds,(uint32_t)time(NULL));
            printf("got datenum.%d %d %d %d\n",datenum,seconds/3600,(seconds/60)%24,seconds%60);
        }
        for (i=0; i<numdates; i++)
        {
            expand_datenum(date,datenum);
            if ( (price= jdouble(bpi,date)) != 0 )
            {
                utc32[numdates - 1 - i] = OS_conv_datenum(datenum,12,0,0);
                cdaily[numdates - 1 - i] = price * .001;
                //printf("(%s %u %f) ",date,utc32[numdates - 1 - i],price);
            }
            datenum = ecb_decrdate(&year,&month,&day,date,datenum);
        }
        PAX_genspline(&PEGS->splines[MAX_CURRENCIES],MAX_CURRENCIES,"coindesk",utc32,cdaily,numdates,cdaily);
        
    } else printf("no bpi\n");
    quandl = url_json("https://www.quandl.com/api/v1/datasets/BAVERAGE/USD.json?rows=64");
    if ( (str= jstr(quandl,"updated_at")) != 0 && (datenum= conv_date(&seconds,str)) > 0 && (array= jarray(&n,quandl,"data")) != 0 )
    {
        printf("datenum.%d data.%d %d\n",datenum,n,cJSON_GetArraySize(array));
        memset(utc32,0,sizeof(utc32)), memset(qdaily,0,sizeof(qdaily));
        for (i=0; i<n&&i<MAX_SPLINES; i++)
        {
            // ["Date","24h Average","Ask","Bid","Last","Total Volume"]
            // ["2015-07-25",289.27,288.84,288.68,288.87,44978.61]
            item = jitem(array,i);
            if ( Debuglevel > 2 )
                printf("(%s) ",cJSON_Print(item));
            if ( (dstr= jstr(jitem(item,0),0)) != 0 && (datenum= conv_date(&seconds,dstr)) > 0 )
            {
                price = jdouble(jitem(item,1),0), ask = jdouble(jitem(item,2),0), bid = jdouble(jitem(item,3),0);
                close = jdouble(jitem(item,4),0), vol = jdouble(jitem(item,5),0);
                if ( Debuglevel > 2 )
                    fprintf(stderr,"%d.[%d %f %f %f %f %f].%d ",i,datenum,price,ask,bid,close,vol,n);
                utc32[numdates - 1 - i] = OS_conv_datenum(datenum,12,0,0), qdaily[numdates - 1 - i] = price * .001;
            }
        }
        PAX_genspline(&PEGS->splines[MAX_CURRENCIES+1],MAX_CURRENCIES+1,"quandl",utc32,qdaily,n<MAX_SPLINES?n:MAX_SPLINES,qdaily);
    }
    btcdhist = url_json(url);
    //{"date":1406160000,"high":0.01,"low":0.00125,"open":0.01,"close":0.001375,"volume":1.50179994,"quoteVolume":903.58818412,"weightedAverage":0.00166204},
    if ( (array= jarray(&n,btcdhist,0)) != 0 )
    {
        memset(utc32,0,sizeof(utc32)), memset(btcddaily,0,sizeof(btcddaily));
        //printf("GOT.(%s)\n",cJSON_Print(array));
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            timestamp = juint(item,"date"), high = jdouble(item,"high"), low = jdouble(item,"low"), open = jdouble(item,"open");
            close = jdouble(item,"close"), vol = jdouble(item,"volume"), quotevol = jdouble(item,"quoteVolume"), price = jdouble(item,"weightedAverage");
            //printf("[%u %f %f %f %f %f %f %f]",timestamp,high,low,open,close,vol,quotevol,price);
            if ( Debuglevel > 2 )
                printf("[%u %d %f]",timestamp,OS_conv_unixtime(&t,&seconds,timestamp),price);
            utc32[i] = timestamp - 12*3600, btcddaily[i] = price * 100.;
        }
        if ( Debuglevel > 2 )
            printf("poloniex.%d\n",n);
        PAX_genspline(&PEGS->splines[MAX_CURRENCIES+2],MAX_CURRENCIES+2,"btcdhist",utc32,btcddaily,n<MAX_SPLINES?n:MAX_SPLINES,btcddaily);
    }
    // https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=1405699200&end=9999999999&period=86400
}

int32_t PAX_ecbparse(char *date,double *prices,char *url,int32_t basenum)
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
                    if ( (relstr= get_cJSON_fieldname(item)) != 0 && (relnum= PAX_basenum(relstr)) >= 0 )
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

int32_t PAX_ecbprices(char *date,double *prices,int32_t year,int32_t month,int32_t day)
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
                count += PAX_ecbparse(basenum == 0 ? date : tmpdate,prices,url,basenum);
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

int32_t ecb_matrix(double matrix[32][32],char *date)
{
    FILE *fp=0; int32_t n=0,datenum,year=0,seconds,month=0,day=0,loaded = 0; char fname[64],_date[64];
    if ( date == 0 )
        date = _date, memset(_date,0,sizeof(_date));
    sprintf(fname,"DB/ECB/%s",date), OS_compatible_path(fname);
    if ( date[0] != 0 && (fp= fopen(fname,"rb")) != 0 )
    {
        if ( fread(matrix,1,sizeof(matrix[0][0])*32*32,fp) == sizeof(matrix[0][0])*32*32 )
            loaded = 1;
        else printf("fread error\n");
        fclose(fp);
    } else printf("ecb_matrix.(%s) load error fp.%p\n",fname,fp);
    if ( loaded == 0 )
    {
        datenum = conv_date(&seconds,date);
        year = datenum / 10000, month = (datenum / 100) % 100, day = (datenum % 100);
        if ( (n= PAX_ecbprices(date,&matrix[0][0],year,month,day)) > 0 )
        {
            sprintf(fname,"DB/ECB/%s",date), OS_compatible_path(fname);
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                if ( fwrite(matrix,1,sizeof(matrix[0][0])*32*32,fp) == sizeof(matrix[0][0])*32*32 )
                    loaded = 1;
                fclose(fp);
            }
        } else printf("peggy_matrix error loading %d.%d.%d\n",year,month,day);
    }
    if ( loaded == 0 && n == 0 )
    {
        printf("peggy_matrix couldnt process loaded.%d n.%d\n",loaded,n);
        return(-1);
    }
    //"2000-01-03"
    if ( (datenum= conv_date(&seconds,date)) < 0 )
        return(-1);
    printf("loaded.(%s) nonz.%d (%d %d %d) datenum.%d\n",date,n,year,month,day,datenum);
    return(datenum);
}

void PAX_update(struct peggy_info *PEGS,double *btcusdp,double *btcdbtcp)
{
    int32_t i,n,seconds,datenum; uint32_t timestamp; char url[1024],*dstr,*str;
    double btcddaily=0.,btcusd=0.,ask,high,low,bid,close,vol,quotevol,open,price = 0.;
    //cJSON *btcdtrades,*btcdtrades2,*,*bitcoincharts,;
    cJSON *quandl,*btcdhist,*array,*item,*bitcoinave,*blockchaininfo,*coindesk=0;
    //btcdtrades = url_json("https://poloniex.com/public?command=returnTradeHistory&currencyPair=BTC_BTCD");
    //btcdtrades2 = url_json("https://bittrex.com/api/v1.1/public/getmarkethistory?market=BTC-BTCD&count=50");
    bitcoinave = url_json("https://api.bitcoinaverage.com/ticker/USD/");
    //bitcoincharts = url_json("http://api.bitcoincharts.com/v1/weighted_prices.json");
    blockchaininfo = url_json("https://blockchain.info/ticker");
    coindesk = url_json("http://api.coindesk.com/v1/bpi/historical/close.json");
    sprintf(url,"https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=%ld&end=9999999999&period=86400",(long)(time(NULL)-2*3600*24));
    quandl = url_json("https://www.quandl.com/api/v1/datasets/BAVERAGE/USD.json?rows=1");
    if ( quandl != 0 && (str= jstr(quandl,"updated_at")) != 0 && (datenum= conv_date(&seconds,str)) > 0 && (array= jarray(&n,quandl,"data")) != 0 )
    {
        //printf("datenum.%d data.%d %d\n",datenum,n,cJSON_GetArraySize(array));
        for (i=0; i<1; i++)
        {
            // ["Date","24h Average","Ask","Bid","Last","Total Volume"]
            // ["2015-07-25",289.27,288.84,288.68,288.87,44978.61]
            item = jitem(array,i);
            if ( (dstr= jstr(jitem(item,0),0)) != 0 && (datenum= conv_date(&seconds,dstr)) > 0 )
            {
                btcusd = price = jdouble(jitem(item,1),0), ask = jdouble(jitem(item,2),0), bid = jdouble(jitem(item,3),0);
                close = jdouble(jitem(item,4),0), vol = jdouble(jitem(item,5),0);
                //fprintf(stderr,"%d.[%d %f %f %f %f %f].%d ",i,datenum,price,ask,bid,close,vol,n);
            }
        }
    }
    {
        double avebid,aveask,bidvol,askvol; struct exchange_quote sortbuf[512];
        struct supernet_info *myinfo = SuperNET_MYINFO(0); cJSON *argjson = cJSON_Parse("{}");
        aveask = instantdex_aveprice(myinfo,sortbuf,(int32_t)(sizeof(sortbuf)/sizeof(*sortbuf)),&askvol,"BTCD","BTC",1,argjson);
        avebid = instantdex_aveprice(myinfo,sortbuf,(int32_t)(sizeof(sortbuf)/sizeof(*sortbuf)),&bidvol,"BTCD","BTC",-1,argjson);
        if ( avebid > SMALLVAL && aveask > SMALLVAL )
        {
            price = (avebid*bidvol + aveask*askvol) / (bidvol + askvol);
            *btcdbtcp = price;
            printf("set BTCD price %f\n",price);
            PEGS->btcdbtc = price;
        }
        else
        {
            btcdhist = url_json(url);
            //{"date":1406160000,"high":0.01,"low":0.00125,"open":0.01,"close":0.001375,"volume":1.50179994,"quoteVolume":903.58818412,"weightedAverage":0.00166204},
            if ( btcdhist != 0 && (array= jarray(&n,btcdhist,0)) != 0 )
            {
                //printf("GOT.(%s)\n",cJSON_Print(array));
                for (i=0; i<1; i++)
                {
                    item = jitem(array,i);
                    timestamp = juint(item,"date"), high = jdouble(item,"high"), low = jdouble(item,"low"), open = jdouble(item,"open");
                    close = jdouble(item,"close"), vol = jdouble(item,"volume"), quotevol = jdouble(item,"quoteVolume"), price = jdouble(item,"weightedAverage");
                    //printf("[%u %f %f %f %f %f %f %f]",timestamp,high,low,open,close,vol,quotevol,price);
                    //printf("[%u %d %f]",timestamp,OS_conv_unixtime(&seconds,timestamp),price);
                    btcddaily = price;
                    if ( btcddaily != 0 )
                        PEGS->btcdbtc = *btcdbtcp = btcddaily;
                }
                //printf("poloniex.%d\n",n);
            }
            if ( btcdhist != 0 )
                free_json(btcdhist);
        }
    }
    if ( bitcoinave != 0 )
    {
        if ( (price= jdouble(bitcoinave,"24h_avg")) > SMALLVAL )
        {
            //printf("bitcoinave %f %f\n",btcusd,price);
            dxblend(&btcusd,price,0.5);
        }
        free_json(bitcoinave);
    }
    if ( quandl != 0 )
        free_json(quandl);
    if ( coindesk != 0 )
        free_json(coindesk);
    if ( blockchaininfo != 0 )
    {
        if ( (item= jobj(blockchaininfo,"USD")) != 0 && item != 0 && (price= jdouble(item,"15m")) > SMALLVAL )
        {
            //printf("blockchaininfo %f %f\n",btcusd,price);
            dxblend(&btcusd,price,0.5);
        }
        free_json(blockchaininfo);
    }
    if ( btcusd != 0 )
        PEGS->btcusd = *btcusdp = btcusd;
}

double blend_price(double *volp,double wtA,cJSON *jsonA,double wtB,cJSON *jsonB)
{
    //A.{"ticker":{"base":"BTS","target":"CNY","price":"0.02958291","volume":"3128008.39295500","change":"0.00019513","markets":[{"market":"BTC38","price":"0.02960000","volume":3051650.682955},{"market":"Bter","price":"0.02890000","volume":76357.71}]},"timestamp":1438490881,"success":true,"error":""}
    // B.{"id":"bts\/cny","price":"0.02940000","price_before_24h":"0.02990000","volume_first":"3048457.6857147217","volume_second":"90629.45859575272","volume_btc":"52.74","best_market":"btc38","latest_trade":"2015-08-02 03:57:38","coin1":"BitShares","coin2":"CNY","markets":[{"market":"btc38","price":"0.02940000","volume":"3048457.6857147217","volume_btc":"52.738317962865"},{"market":"bter","price":"0.04350000","volume":"0","volume_btc":"0"}]}
    double priceA,priceB,priceB24,price,volA,volB; cJSON *obj;
    priceA = priceB = priceB24= price = volA = volB = 0.;
    if ( jsonA != 0 && (obj= jobj(jsonA,"ticker")) != 0 )
    {
        priceA = jdouble(obj,"price");
        volA = jdouble(obj,"volume");
    }
    if ( jsonB != 0 )
    {
        priceB = jdouble(jsonB,"price");
        priceB24 = jdouble(jsonB,"price_before_24h");
        volB = jdouble(jsonB,"volume_first");
    }
    //printf("priceA %f volA %f, priceB %f %f volB %f\n",priceA,volA,priceB,priceB24,volB);
    if ( priceB > SMALLVAL && priceB24 > SMALLVAL )
        priceB = (priceB * .1) + (priceB24 * .9);
    else if ( priceB < SMALLVAL )
        priceB = priceB24;
    if ( priceA*volA < SMALLVAL )
        price = priceB;
    else if ( priceB*volB < SMALLVAL )
        price = priceA;
    else price = (wtA * priceA) + (wtB * priceB);
    *volp = (volA + volB);
    return(price);
}

void _crypto_update(struct peggy_info *PEGS,double cryptovols[2][8][2],struct PAX_data *dp,int32_t selector,int32_t peggyflag)
{
    char *cryptonatorA = "https://www.cryptonator.com/api/full/%s-%s"; //unity-btc
    char *cryptocoinchartsB = "http://api.cryptocoincharts.info/tradingPair/%s_%s"; //bts_btc
    char *cryptostrs[9] = { "btc", "nxt", "unity", "eth", "ltc", "xmr", "bts", "xcp", "etc" };
    int32_t iter,i,j; double btcusd,btcdbtc,cnyusd,prices[8][2],volumes[8][2];
    char base[16],rel[16],url[512],*str; cJSON *jsonA,*jsonB;
    if ( peggyflag != 0 )
    {
        cnyusd = PEGS->cnyusd;
        btcusd = PEGS->btcusd;
        btcdbtc = PEGS->btcdbtc;
        //printf("update with btcusd %f btcd %f cnyusd %f cnybtc %f\n",btcusd,btcdbtc,cnyusd,cnyusd/btcusd);
        if ( btcusd < SMALLVAL || btcdbtc < SMALLVAL )
        {
            PAX_update(PEGS,&btcusd,&btcdbtc);
            printf("PAX_update with btcusd %f btcd %f\n",btcusd,btcdbtc);
        }
        memset(prices,0,sizeof(prices));
        memset(volumes,0,sizeof(volumes));
        for (j=0; j<sizeof(cryptostrs)/sizeof(*cryptostrs); j++)
        {
            str = cryptostrs[j];
            if ( strcmp(str,"etc") == 0 )
            {
                if ( prices[3][0] > SMALLVAL )
                    break;
                i = 3;
            } else i = j;
            for (iter=0; iter<1; iter++)
            {
                if ( i == 0 && iter == 0 )
                    strcpy(base,"btcd"), strcpy(rel,"btc");
                else strcpy(base,str), strcpy(rel,iter==0?"btc":"cny");
                //if ( selector == 0 )
                {
                    sprintf(url,cryptonatorA,base,rel);
                    jsonA = url_json(url);
                }
                //else
                {
                    sprintf(url,cryptocoinchartsB,base,rel);
                    jsonB = url_json(url);
                }
                prices[i][iter] = blend_price(&volumes[i][iter],0.4,jsonA,0.6,jsonB);
                if ( iter == 1 )
                {
                    if ( btcusd > SMALLVAL )
                    {
                        prices[i][iter] *= cnyusd / btcusd;
                        volumes[i][iter] *= cnyusd / btcusd;
                    } else prices[i][iter] = volumes[i][iter] = 0.;
                }
                cryptovols[0][i][iter] = _pairaved(cryptovols[0][i][iter],prices[i][iter]);
                cryptovols[1][i][iter] = _pairaved(cryptovols[1][i][iter],volumes[i][iter]);
                if ( Debuglevel > 2 )
                    printf("(%f %f).%d:%d ",cryptovols[0][i][iter],cryptovols[1][i][iter],i,iter);
                //if ( cnyusd < SMALLVAL || btcusd < SMALLVAL )
                //    break;
            }
        }
    }
}

void PAX_RTupdate(struct peggy_info *PEGS,double cryptovols[2][8][2],double RTmetals[4],double *RTprices,struct PAX_data *dp)
{
    char *cryptostrs[8] = { "btc", "nxt", "unity", "eth", "ltc", "xmr", "bts", "xcp" };
    int32_t iter,i,c,baserel,basenum,relnum; double cnyusd,btcusd,btcdbtc,bid,ask,price,vol,prices[8][2],volumes[8][2];
    char base[16],rel[16];
    PAX_update(PEGS,&btcusd,&btcdbtc);
    memset(prices,0,sizeof(prices));
    memset(volumes,0,sizeof(volumes));
    for (i=0; i<sizeof(cryptostrs)/sizeof(*cryptostrs); i++)
        for (iter=0; iter<2; iter++)
            prices[i][iter] = cryptovols[0][i][iter], volumes[i][iter] = cryptovols[1][i][iter];
    if ( prices[0][0] > SMALLVAL )
        dxblend(&btcdbtc,prices[0][0],.9);
    dxblend(&dp->btcdbtc,btcdbtc,.995);
    if ( PEGS->btcdbtc < SMALLVAL )
        PEGS->btcdbtc = dp->btcdbtc;
    if ( (cnyusd= PEGS->cnyusd) > SMALLVAL )
    {
        if ( prices[0][1] > SMALLVAL )
        {
            //printf("cnyusd %f, btccny %f -> btcusd %f %f\n",cnyusd,prices[0][1],prices[0][1]*cnyusd,btcusd);
            btcusd = prices[0][1] * cnyusd;
            if ( dp->btcusd < SMALLVAL )
                dp->btcusd = btcusd;
            else dxblend(&dp->btcusd,btcusd,.995);
            if ( PEGS->btcusd < SMALLVAL )
                PEGS->btcusd = dp->btcusd;
            if ( PEGS->data.btcusd < SMALLVAL )
                PEGS->data.btcusd = dp->btcusd;
            printf("cnyusd %f, btccny %f -> btcusd %f %f -> %f %f %f\n",cnyusd,prices[0][1],prices[0][1]*cnyusd,btcusd,dp->btcusd,PEGS->btcusd,PEGS->data.btcusd);
        }
    }
    for (i=1; i<sizeof(cryptostrs)/sizeof(*cryptostrs); i++)
    {
        if ( (vol= volumes[i][0]+volumes[i][1]) > SMALLVAL )
        {
            price = ((prices[i][0] * volumes[i][0]) + (prices[i][1] * volumes[i][1])) / vol;
            if ( Debuglevel > 2 )
                printf("%s %f v%f + %f v%f -> %f %f\n",cryptostrs[i],prices[i][0],volumes[i][0],prices[i][1],volumes[i][1],price,dp->cryptos[i]);
            dxblend(&dp->cryptos[i],price,.995);
        }
    }
    btcusd = PEGS->btcusd;
    btcdbtc = PEGS->btcdbtc;
    if ( Debuglevel > 2 )
        printf("    update with btcusd %f btcd %f\n",btcusd,btcdbtc);
    if ( btcusd < SMALLVAL || btcdbtc < SMALLVAL )
    {
        PAX_update(PEGS,&btcusd,&btcdbtc);
        if ( Debuglevel > 2 )
            printf("     price777_update with btcusd %f btcd %f\n",btcusd,btcdbtc);
    } else PEGS->btcusd = btcusd, PEGS->btcdbtc = btcdbtc;
    for (c=0; c<sizeof(CONTRACTS)/sizeof(*CONTRACTS); c++)
    {
        for (iter=0; iter<3; iter++)
        {
            switch ( iter )
            {
                case 0: bid = dp->tbids[c], ask = dp->tasks[c]; break;
                case 1: bid = dp->fbids[c], ask = dp->fasks[c]; break;
                case 2: bid = dp->ibids[c], ask = dp->iasks[c]; break;
            }
            if ( (price= _pairaved(bid,ask)) > SMALLVAL )
            {
                if ( Debuglevel > 2 )
                    printf("%.6f ",price);
                dxblend(&RTprices[c],price,.995);
                if ( 0 && (baserel= PAX_ispair(base,rel,CONTRACTS[c])) >= 0 )
                {
                    basenum = (baserel >> 8) & 0xff, relnum = baserel & 0xff;
                    if ( basenum < 32 && relnum < 32 )
                    {
                        //printf("%s.%d %f <- %f\n",CONTRACTS[c],c,RTmatrix[basenum][relnum],RTprices[c]);
                        //dxblend(&RTmatrix[basenum][relnum],RTprices[c],.999);
                    }
                }
                if ( strcmp(CONTRACTS[c],"XAUUSD") == 0 )
                    dxblend(&RTmetals[0],price,.995);
            }
        }
    }
    for (i=0; i<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); i++)
        if ( PEGS->data.metals[i] != 0 )
            dxblend(&RTmetals[i],PEGS->data.metals[i],.995);
}

void PAX_bidask(struct exchange_info *exchange,uint32_t *timestamps,double *bids,double *asks,int32_t baseid,int32_t relid)
{
    int32_t contractnum; struct exchange_quote bidasks[2];
    contractnum = Baserel_contractnum[baseid][relid];
    (*exchange->issue.price)(exchange,CURRENCIES[baseid],CURRENCIES[relid],bidasks,1,0.,0,0);
    bids[contractnum] = bidasks[0].price;
    asks[contractnum] = bidasks[1].price;
    timestamps[contractnum] = bidasks[0].timestamp;
    printf("(%d %.6f) ",contractnum,_pairaved(bids[contractnum],asks[contractnum]));
}

struct exchange_info *PAX_bidasks(char *exchangestr,uint32_t *timestamps,double *bids,double *asks)
{
    int32_t baseid,relid; struct exchange_info *exchange;
    if ( (exchange= exchanges777_find(exchangestr)) != 0 )
    {
        for (baseid=0; baseid<8; baseid++)
        {
            for (relid=0; relid<8; relid++)
            {
                if ( Currency_contractdirs[baseid][relid] > 0 )
                    PAX_bidask(exchange,timestamps,bids,asks,baseid,relid);
            }
        }
    } else printf("cant find (%s) exchange\n",exchangestr);
    printf("%s\n",exchangestr);
    return(exchange);
}

int32_t PAX_idle(struct peggy_info *PEGS,int32_t peggyflag,int32_t idlegap)
{
    static double lastupdate,lastdayupdate; static int32_t didinit; static portable_mutex_t mutex;
    struct exchange_info *exchange; struct exchange_quote bidasks[2]; double btcdbtc,btcusd;
    int32_t i,datenum,contractnum; struct PAX_data *dp = &PEGS->tmp;
    *dp = PEGS->data;
    if ( didinit == 0 )
    {
        portable_mutex_init(&mutex);
        //prices777_init(BUNDLE.jsonstr,peggyflag);
        didinit = 1;
        if ( peggyflag != 0 )
        {
            //int32_t opreturns_init(uint32_t blocknum,uint32_t blocktimestamp,char *path);
            //opreturns_init(0,(uint32_t)time(NULL),"peggy");
        }
    }
    if ( peggyflag != 0 && OS_milliseconds() > lastupdate + (1000*idlegap) )
    {
        lastupdate = OS_milliseconds();
        if ( OS_milliseconds() > lastdayupdate + 60000*60 )
        {
            lastdayupdate = OS_milliseconds();
            if ( (datenum= ecb_matrix(dp->ecbmatrix,dp->edate)) > 0 )
            {
                dp->ecbdatenum = datenum;
                dp->ecbyear = dp->ecbdatenum / 10000,  dp->ecbmonth = (dp->ecbdatenum / 100) % 100,  dp->ecbday = (dp->ecbdatenum % 100);
                expand_datenum(dp->edate,datenum);
                memcpy(dp->RTmatrix,dp->ecbmatrix,sizeof(dp->RTmatrix));
            }
        }
        for (i=0; i<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); i++)
            dp->metals[i] = PAX_yahoo(Yahoo_metals[i]);
        PAX_bidasks("truefx",dp->ttimestamps,dp->tbids,dp->tasks);
        PAX_bidasks("fxcm",dp->ftimestamps,dp->fbids,dp->fasks);
        if ( (exchange= PAX_bidasks("instaforex",dp->itimestamps,dp->ibids,dp->iasks)) != 0 )
        {
            if ( (contractnum= PAX_contractnum("XAU","USD")) >= 0 )
            {
                (*exchange->issue.price)(exchange,"XAU","USD",bidasks,1,0.,0,0);
                dp->ibids[contractnum] = bidasks[0].price;
                dp->iasks[contractnum] = bidasks[1].price;
                dp->itimestamps[contractnum] = bidasks[0].timestamp;
            }
        }
        PAX_update(PEGS,&btcusd,&btcdbtc);
        if ( btcusd > SMALLVAL )
            dxblend(&dp->btcusd,btcusd,0.99);
        if ( btcdbtc > SMALLVAL )
            dxblend(&dp->btcdbtc,btcdbtc,0.99);
        if ( dp->btcusd == 0 )
            dp->btcusd = dp->btcusd;
        if ( dp->btcdbtc == 0 )
            dp->btcdbtc = dp->btcdbtc;
        if ( dp->ecbmatrix[USD][USD] > SMALLVAL && dp->ecbmatrix[CNY][CNY] > SMALLVAL )
            PEGS->cnyusd = (dp->ecbmatrix[CNY][CNY] / dp->ecbmatrix[USD][USD]);
        portable_mutex_lock(&mutex);
        PEGS->data = *dp;
        portable_mutex_unlock(&mutex);
        //kv777_write(PEGS->kv,"data",5,&PEGS->data,sizeof(BUNDLE.data));
        PAX_RTupdate(PEGS,PEGS->cryptovols,dp->RTmetals,dp->RTprices,dp);
        //printf("update finished\n");
        void peggy();
        peggy();
        didinit = 1;
    }
    return(0);
}
