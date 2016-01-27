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

#define _issue_curl(curl_handle,label,url) bitcoind_RPC(curl_handle,label,url,0,0,0)

#define INSTANTDEX_MINVOL 75
#define INSTANTDEX_MINVOLPERC ((double)INSTANTDEX_MINVOL / 100.)
#define INSTANTDEX_PRICESLIPPAGE 0.001
#define FINISH_HEIGHT 7

#define INSTANTDEX_TRIGGERDEADLINE 120
#define JUMPTRADE_SECONDS 100
#define INSTANTDEX_ACCT "4383817337783094122"
#define INSTANTDEX_FEE ((long)(2.5 * SATOSHIDEN))

#include "../iguana777.h"
#include "InstantDEX_quote.h"

#define INSTANTDEX_LOCALAPI "allorderbooks", "orderbook", "lottostats", "LSUM", "makebasket", "disable", "enable", "peggyrates", "tradesequence", "placebid", "placeask", "orderstatus", "openorders", "cancelorder", "tradehistory", "balance", "allexchanges",


typedef char *(*json_handler)(int32_t localaccess,int32_t valid,char *sender,cJSON **objs,int32_t numobjs,char *origargstr);

queue_t InstantDEXQ,TelepathyQ,Pending_offersQ;
cJSON *InstantDEX_lottostats();

//#include "NXT_tx.h"
#include "trades.h"
#include "quotes.h"
#include "subatomic.h"

#include "orderbooks.h"
#include "exchangeparse.h"
#include "exchange_trades.h"
#include "exchanges/poloniex.c"
#include "exchanges/bittrex.c"
#include "exchanges/btce.c"
#include "exchanges/bitfinex.c"
#include "exchanges/btc38.c"
#include "exchanges/huobi.c"
#include "exchanges/lakebtc.c"
#include "exchanges/quadriga.c"
#include "exchanges/okcoin.c"
#include "exchanges/coinbase.c"
#include "exchanges/bitstamp.c"

// {"plugin":"InstantDEX","method":"orderbook","baseid":"8688289798928624137","rel":"USD","exchange":"active","allfields":1}

// {"plugin":"InstantDEX","method":"orderbook","baseid":"17554243582654188572","rel":"12071612744977229797","exchange":"active","allfields":1}
// {"plugin":"InstantDEX","method":"orderbook","baseid":"6918149200730574743","rel":"XMR","exchange":"active","allfields":1}

void idle()
{
    char *jsonstr,*str; cJSON *json; int32_t n = 0; uint32_t nonce;
    /*printf("INSTANTDEX.readyflag.%d\n",INSTANTDEX.readyflag);
    while ( INSTANTDEX.readyflag == 0 )
        sleep(1);
    printf("INSTANTDEX.readyflag.%d\n",INSTANTDEX.readyflag);*/
    while ( 1 )
    {
        if ( n == 0 )
            sleep(1);
        n = 0;
        if ( (jsonstr= queue_dequeue(&InstantDEXQ,1)) != 0 )
        {
            printf("Dequeued InstantDEX.(%s)\n",jsonstr);
            if ( (json= cJSON_Parse(jsonstr)) != 0 )
            {
                //fprintf(stderr,"dequeued\n");
                if ( (str= busdata_sync(&nonce,jsonstr,"allnodes",0)) != 0 )
                {
                    //fprintf(stderr,"busdata.(%s)\n",str);
                    free(str);
                }
                free_json(json);
                n++;
            } else printf("error parsing (%s) from InstantDEXQ\n",jsonstr);
            free_queueitem(jsonstr);
        }
    }
}

uint32_t _get_NXTheight(uint32_t *firsttimep)
{
    static uint32_t last,lastheight,lastNXTtime;
    cJSON *json; uint32_t height = 0; char cmd[256],*jsonstr;
    if ( time(NULL) > last+10 )
    {
        sprintf(cmd,"requestType=getState");
        if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
        {
            //printf("(%s) -> (%s)\n",cmd,jsonstr);
            if ( (json= cJSON_Parse(jsonstr)) != 0 )
            {
                if ( firsttimep != 0 )
                    lastNXTtime = *firsttimep = (uint32_t)get_cJSON_int(json,"time");
                height = (int32_t)get_cJSON_int(json,"numberOfBlocks");
                if ( height > 0 )
                    height--;
                lastheight = height;
                free_json(json);
            }
            free(jsonstr);
        }
        last = (uint32_t)time(NULL);
    }
    else
    {
        height = lastheight;
        if ( firsttimep != 0 )
            *firsttimep = lastNXTtime;
    }
    return(height);
}

void idle2()
{
    static double lastmilli;
    uint32_t NXTblock;
    //while ( INSTANTDEX.readyflag == 0 )
    //    sleep(1);
    while ( 1 )
    {
        if ( milliseconds() < (lastmilli + 5000) )
            sleep(1);
        NXTblock = _get_NXTheight(0);
        if ( 1 && NXTblock != prices777_NXTBLOCK )
        {
            prices777_NXTBLOCK = NXTblock;
            InstantDEX_update(IGUANA_NXTADDR,IGUANA_NXTACCTSECRET);//,SUPERNET.);
            //fprintf(stderr,"done idle NXT\n");
        }
        lastmilli = milliseconds();
    }
}

cJSON *InstantDEX_lottostats()
{
    char cmdstr[1024],NXTaddr[64],buf[1024],*jsonstr; struct destbuf receiverstr;
    cJSON *json,*array,*txobj; int32_t i,n,totaltickets = 0; uint64_t amount,senderbits; uint32_t timestamp = 0;
    if ( timestamp == 0 )
        timestamp = 38785003;
    sprintf(cmdstr,"requestType=getBlockchainTransactions&account=%s&timestamp=%u&type=0&subtype=0",INSTANTDEX_ACCT,timestamp);
    //printf("cmd.(%s)\n",cmdstr);
    if ( (jsonstr= issue_NXTPOST(cmdstr)) != 0 )
    {
        // printf("jsonstr.(%s)\n",jsonstr);
        // mm string.({"requestProcessingTime":33,"transactions":[{"fullHash":"2a2aab3b84dadf092cf4cedcd58a8b5a436968e836338e361c45651bce0ef97e","confirmations":203,"signatureHash":"52a4a43d9055fe4861b3d13fbd03a42fecb8c9ad4ac06a54da7806a8acd9c5d1","transaction":"711527527619439146","amountNQT":"1100000000","transactionIndex":2,"ecBlockHeight":360943,"block":"6797727125503999830","recipientRS":"NXT-74VC-NKPE-RYCA-5LMPT","type":0,"feeNQT":"100000000","recipient":"4383817337783094122","version":1,"sender":"423766016895692955","timestamp":38929220,"ecBlockId":"10121077683890606382","height":360949,"subtype":0,"senderPublicKey":"4e5bbad625df3d536fa90b1e6a28c3f5a56e1fcbe34132391c8d3fd7f671cb19","deadline":1440,"blockTimestamp":38929430,"senderRS":"NXT-8E6V-YBWH-5VMR-26ESD","signature":"4318f36d9cf68ef0a8f58303beb0ed836b670914065a868053da5fe8b096bc0c268e682c0274e1614fc26f81be4564ca517d922deccf169eafa249a88de58036"}]})
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (array= cJSON_GetObjectItem(json,"transactions")) != 0 && is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    txobj = cJSON_GetArrayItem(array,i);
                    copy_cJSON(&receiverstr,cJSON_GetObjectItem(txobj,"recipient"));
                    if ( strcmp(receiverstr.buf,INSTANTDEX_ACCT) == 0 )
                    {
                        if ( (senderbits = get_API_nxt64bits(cJSON_GetObjectItem(txobj,"sender"))) != 0 )
                        {
                            expand_nxt64bits(NXTaddr,senderbits);
                            amount = get_API_nxt64bits(cJSON_GetObjectItem(txobj,"amountNQT"));
                            if ( amount == INSTANTDEX_FEE )
                                totaltickets++;
                            else if ( amount >= 2*INSTANTDEX_FEE )
                                totaltickets += 2;
                        }
                    }
                }
            }
            free_json(json);
        }
        free(jsonstr);
    }
    sprintf(buf,"{\"result\":\"lottostats\",\"totaltickets\":\"%d\"}",totaltickets);
    return(cJSON_Parse(buf));
}

void set_best_amounts(int64_t *baseamountp,int64_t *relamountp,double price,double volume)
{
    double checkprice,checkvol,distA,distB,metric,bestmetric = (1. / SMALLVAL);
    uint64_t baseamount,relamount,bestbaseamount = 0,bestrelamount = 0;
    int32_t i,j;
    baseamount = volume * SATOSHIDEN;
    relamount = ((price * volume) * SATOSHIDEN);
    //*baseamountp = baseamount, *relamountp = relamount;
    //return;
    for (i=-1; i<=1; i++)
        for (j=-1; j<=1; j++)
        {
            checkprice = prices777_price_volume(&checkvol,baseamount+i,relamount+j);
            distA = (checkprice - price);
            distA *= distA;
            distB = (checkvol - volume);
            distB *= distB;
            metric = sqrt(distA + distB);
            if ( metric < bestmetric )
            {
                bestmetric = metric;
                bestbaseamount = baseamount + i;
                bestrelamount = relamount + j;
                //printf("i.%d j.%d metric. %f\n",i,j,metric);
            }
        }
    *baseamountp = bestbaseamount;
    *relamountp = bestrelamount;
}

int32_t bidask_parse(int32_t localaccess,struct destbuf *exchangestr,struct destbuf *name,struct destbuf *base,struct destbuf *rel,struct destbuf *gui,struct InstantDEX_quote *iQ,cJSON *json)
{
    uint64_t basemult,relmult,baseamount,relamount; double price,volume; int32_t exchangeid,keysize,flag; char key[1024],buf[64],*methodstr;
    memset(iQ,0,sizeof(*iQ));
    iQ->s.baseid = j64bits(json,"baseid"); iQ->s.relid = j64bits(json,"relid");
    iQ->s.baseamount = j64bits(json,"baseamount"), iQ->s.relamount = j64bits(json,"relamount");
    iQ->s.vol = jdouble(json,"volume"); iQ->s.price = jdouble(json,"price");
    copy_cJSON(exchangestr,jobj(json,"exchange"));
    if ( exchangestr->buf[0] == 0 || find_exchange(&exchangeid,exchangestr->buf) == 0 )
        exchangeid = -1;
    iQ->exchangeid = exchangeid;
    copy_cJSON(base,jobj(json,"base"));
    copy_cJSON(rel,jobj(json,"rel"));
    copy_cJSON(name,jobj(json,"name"));
    methodstr = jstr(json,"method");
    if ( methodstr != 0 && (strcmp(methodstr,"placeask") == 0 || strcmp(methodstr,"ask") == 0) )
        iQ->s.isask = 1;
    if ( iQ->s.vol < 0. )
    {
        iQ->s.vol = -iQ->s.vol;
        iQ->s.isask ^= 1;
    }
    if ( methodstr != 0 && strcmp(exchangestr->buf,"wallet") == 0 && (iQ->s.baseid == NXT_ASSETID || strcmp(base->buf,"NXT") == 0) )
    {
        flag = 1;
        if ( strcmp(methodstr,"placeask") == 0 )
            methodstr = "placebid";
        else if ( strcmp(methodstr,"placebid") == 0 )
            methodstr = "placeask";
        else if ( strcmp(methodstr,"ask") == 0 )
            methodstr = "bid";
        else if ( strcmp(methodstr,"bid") == 0 )
            methodstr = "ask";
        else flag = 0;
        if ( flag != 0 )
        {
            iQ->s.baseid = iQ->s.relid, iQ->s.relid = NXT_ASSETID;
            strcpy(base->buf,rel->buf), strcpy(rel->buf,"NXT");
            baseamount = iQ->s.baseamount;
            iQ->s.baseamount = iQ->s.relamount, iQ->s.relamount = baseamount;
            name->buf[0] = 0;
            if ( iQ->s.vol > SMALLVAL && iQ->s.price > SMALLVAL )
            {
                iQ->s.vol *= iQ->s.price;
                iQ->s.price = 1. / iQ->s.price;
            }
            iQ->s.isask ^= 1;
            printf("INVERT\n");
        }
    }
    if ( (iQ->s.timestamp= juint(json,"timestamp")) == 0 )
        iQ->s.timestamp = (uint32_t)time(NULL);
    copy_cJSON(gui,jobj(json,"gui")), strncpy(iQ->gui,gui->buf,sizeof(iQ->gui)-1);
    iQ->s.automatch = juint(json,"automatch");
    iQ->s.minperc = juint(json,"minperc");
    if ( (iQ->s.duration= juint(json,"duration")) == 0 || iQ->s.duration > ORDERBOOK_EXPIRATION )
        iQ->s.duration = ORDERBOOK_EXPIRATION;
    InstantDEX_name(key,&keysize,exchangestr->buf,name->buf,base->buf,&iQ->s.baseid,rel->buf,&iQ->s.relid);
    //printf(">>>>>>>>>>>> BASE.(%s) REL.(%s)\n",base->buf,rel->buf);
    iQ->s.basebits = stringbits(base->buf);
    iQ->s.relbits = stringbits(rel->buf);
    safecopy(iQ->base,base->buf,sizeof(iQ->base));
    safecopy(iQ->rel,rel->buf,sizeof(iQ->rel));
    iQ->s.offerNXT = j64bits(json,"offerNXT");
    iQ->s.quoteid = j64bits(json,"quoteid");
    if ( strcmp(exchangestr->buf,"jumblr") == 0 || strcmp(exchangestr->buf,"pangea") == 0 )
    {
        if ( strcmp(exchangestr->buf,"pangea") == 0 )
        {
            if ( juint(json,"rakemillis") != 0 )
                iQ->s.minperc = juint(json,"rakemillis");
            if ( j64bits(json,"bigblind") != 0 )
            {
                iQ->s.baseamount = j64bits(json,"bigblind");
                iQ->s.vol = ((double)iQ->s.baseamount / SATOSHIDEN);
            }
            if ( j64bits(json,"ante") != 0 )
                iQ->s.relamount = j64bits(json,"ante");
            iQ->s.minbuyin = juint(json,"minbuyin");
            iQ->s.maxbuyin = juint(json,"maxbuyin");
            /*if ( (iQ->s.maxrake= j64bits(json,"maxrake")) != 0 )
            {
                if ( strcmp(base->buf,"BTC") == 0 && iQ->s.maxrake < SATOSHIDEN/10 )
                    iQ->s.maxrake = SATOSHIDEN/10;
                else if ( iQ->s.maxrake < 10*SATOSHIDEN )
                    iQ->s.maxrake = 10*SATOSHIDEN;
            }*/
        }
        if ( iQ->s.price == 0. )
            iQ->s.price = 1.;
        if ( iQ->s.vol == 0. )
            iQ->s.vol = 1.;
        if ( iQ->s.baseamount == 0 )
            iQ->s.baseamount = iQ->s.vol * SATOSHIDEN;
        if ( localaccess != 0 && strcmp(exchangestr->buf,"jumblr") == 0 )
        {
#ifdef later
            struct coin777 *coin; int32_t maxamount;
            if ( (coin= coin777_find(base->buf,0)) != 0 )
            {
                if ( coin->jvin == 0 && coin->jvinaddr[0] == 0 )
                {
                    coin->jvin = -1;
                    printf("initial state for jumblr.%s detected\n",coin->name);
                    sleep(5);
                }
                if ( coin->jvin < 0 )
                {
                    printf("no %s unspents available for jumblr/pangea jvin.%d %.8f\n",coin->name,coin->jvin,dstr(coin->junspent));
                    return(-1);
                }
                maxamount = coin->junspent - coin->mgw.txfee*2 - (coin->junspent>>10);
                if ( iQ->s.baseamount > maxamount )
                    iQ->s.baseamount = maxamount;
                else if ( iQ->s.baseamount < coin->mgw.txfee )
                {
                    printf("jumblr/pangea amount %.8f less than txfee %.8f\n",dstr(iQ->s.baseamount),dstr(coin->mgw.txfee));
                    return(-1);
                }
            }
            else
            {
                printf("%s not initialized for jumblr\n",base->buf);
                return(-1);
            }
#endif
        }
    }
    else
    {
        if ( iQ->s.baseamount == 0 || iQ->s.relamount == 0 )
        {
            if ( iQ->s.price <= SMALLVAL || iQ->s.vol <= SMALLVAL )
                return(-1);
            set_best_amounts(&iQ->s.baseamount,&iQ->s.relamount,iQ->s.price,iQ->s.vol);
        }
    }
    if ( iQ->s.quoteid == 0 )
        iQ->s.quoteid = calc_quoteid(iQ);
    else if ( iQ->s.quoteid != calc_quoteid(iQ) )
    {
        printf("bidask_parse quoteid.%llu != calc.%llu\n",(long long)iQ->s.quoteid,(long long)calc_quoteid(iQ));
        return(-1);
    }
    if ( iQ->s.price > SMALLVAL && iQ->s.vol > SMALLVAL && iQ->s.baseid != 0 && iQ->s.relid != 0 )
    {
        buf[0] = 0, _set_assetname(&basemult,buf,0,iQ->s.baseid);
        printf("baseid.%llu -> %s mult.%llu\n",(long long)iQ->s.baseid,buf,(long long)basemult);
        buf[0] = 0, _set_assetname(&relmult,buf,0,iQ->s.relid);
        printf("relid.%llu -> %s mult.%llu\n",(long long)iQ->s.relid,buf,(long long)relmult);
        //basemult = get_assetmult(iQ->baseid), relmult = get_assetmult(iQ->relid);
        baseamount = (iQ->s.baseamount + basemult/2) / basemult, baseamount *= basemult;
        relamount = (iQ->s.relamount + relmult/2) / relmult, relamount *= relmult;
        if ( iQ->s.price != 0. && iQ->s.vol != 0 )
        {
            price = prices777_price_volume(&volume,baseamount,relamount);
            if ( fabs(iQ->s.price - price)/price > 0.001 )
            {
                printf("cant create accurate price ref.(%f %f) -> (%f %f)\n",iQ->s.price,iQ->s.vol,price,volume);
                return(-1);
            }
        }
    }
    return(0);
}

char *InstantDEX(char *jsonstr,char *remoteaddr,int32_t localaccess)
{
    char *prices777_allorderbooks();
    char *InstantDEX_tradehistory(cJSON *json,int32_t firsti,int32_t endi);
    char *InstantDEX_cancelorder(cJSON *json,char *activenxt,char *secret,uint64_t sequenceid,uint64_t quoteid);
    struct destbuf exchangestr,method,gui,name,base,rel; double balance;
    char *retstr = 0,key[512],retbuf[1024],*activenxt,*secret,*coinstr; struct InstantDEX_quote iQ; struct exchange_info *exchange;
    cJSON *json; uint64_t assetbits,sequenceid; uint32_t maxdepth; int32_t invert=0,keysize,allfields; struct prices777 *prices = 0;
    //printf("INSTANTDEX.(%s)\n",jsonstr);
    //if ( INSTANTDEX.readyflag == 0 )
    //    return(0);
    if ( jsonstr != 0 && (json= cJSON_Parse(jsonstr)) != 0 )
    {
        // test: asset/asset, asset/external, external/external, autofill and automatch
        // peggy integration
        if ( bidask_parse(localaccess,&exchangestr,&name,&base,&rel,&gui,&iQ,json) < 0 && (strcmp(exchangestr.buf,"jumblr") == 0 || strcmp(exchangestr.buf,"pangea") == 0) )
        {
            //return(clonestr("{\"error\":\"invalid parameters\"}"));
        }
        if ( iQ.s.offerNXT == 0 )
            iQ.s.offerNXT = IGUANA_MY64BITS;
printf("isask.%d base.(%s) rel.(%s)\n",iQ.s.isask,base.buf,rel.buf);
        copy_cJSON(&method,jobj(json,"method"));
        if ( (sequenceid= j64bits(json,"orderid")) == 0 )
            sequenceid = j64bits(json,"sequenceid");
        allfields = juint(json,"allfields");
        if ( (maxdepth= juint(json,"maxdepth")) <= 0 )
            maxdepth = MAX_DEPTH;
        if ( exchangestr.buf[0] == 0 )
        {
            if ( iQ.s.baseid != 0 && iQ.s.relid != 0 )
                strcpy(exchangestr.buf,"nxtae");
            else strcpy(exchangestr.buf,"basket");
        }
        assetbits = InstantDEX_name(key,&keysize,exchangestr.buf,name.buf,base.buf,&iQ.s.baseid,rel.buf,&iQ.s.relid);
        //printf("2nd isask.%d base.(%s) rel.(%s)\n",iQ.s.isask,base.buf,rel.buf);
        exchange = exchange_find(exchangestr.buf);
        secret = jstr(json,"secret"), activenxt = jstr(json,"activenxt");
        if ( secret == 0 )
        {
            secret = IGUANA_NXTACCTSECRET;
            activenxt = IGUANA_NXTADDR;
        }
        if ( strcmp(method.buf,"exit") == 0 )
        {
            printf("getchar and then exit\n");
            getchar();
            exit(0);
        }
        if ( strcmp(method.buf,"orderstatus") == 0 )
            retstr = InstantDEX_orderstatus(json,sequenceid,iQ.s.quoteid);
        else if ( strcmp(method.buf,"cancelorder") == 0 )
            retstr = InstantDEX_cancelorder(json,jstr(json,"activenxt"),jstr(json,"secret"),sequenceid,iQ.s.quoteid);
        else if ( strcmp(method.buf,"openorders") == 0 )
            retstr = InstantDEX_openorders(json,IGUANA_NXTADDR,juint(json,"allorders"));
        else if ( strcmp(method.buf,"tradehistory") == 0 )
            retstr = InstantDEX_tradehistory(json,juint(json,"firsti"),juint(json,"endi"));
        else if ( strcmp(method.buf,"withdraw") == 0 )
            retstr = InstantDEX_withdraw(json);
        else if ( strcmp(method.buf,"balance") == 0 )
        {
            if ( exchange != 0 && exchange->issue.trade != 0 )
            {
                if ( exchange->issue.balances != 0 )
                {
                    if ( exchange->balancejson != 0 )
                        free_json(exchange->balancejson), exchange->balancejson = 0;
                    exchange->lastbalancetime = (uint32_t)time(NULL);
                    if ( (exchange->balancejson= (*exchange->issue.balances)(&exchange->cHandle,exchange)) != 0 )
                    {
                        if ( (coinstr= jstr(json,"base")) != 0 )
                            retstr = (*exchange->issue.parsebalance)(exchange,&balance,coinstr);
                        else retstr = jprint(exchange->balancejson,0);
                    } else retstr = clonestr("{\"error\":\"balances null return\"}");
                } else retstr = clonestr("{\"error\":\"no balances function\"}");
            } else retstr = clonestr("{\"error\":\"cant find exchange trade or balances function\"}");
            printf("%s ptr.%p trade.%p\n",exchangestr.buf,exchange,exchange!=0?exchange->issue.trade:0);
        }
        else if ( strcmp(method.buf,"allorderbooks") == 0 )
            retstr = prices777_allorderbooks();
        else if ( strcmp(method.buf,"allexchanges") == 0 )
            retstr = jprint(exchanges_json(),1);
        else if ( strcmp(method.buf,"lottostats") == 0 )
            retstr = jprint(InstantDEX_lottostats(),1);
       /* else if ( strcmp(method.buf,"tradesequence") == 0 )
        {
            //printf("call tradesequence.(%s)\n",jsonstr);
            int32_t dotrade,numtrades; struct prices777_order trades[256]; struct pending_trade *pend;
            dotrade = juint(json,"dotrade");
            retstr = InstantDEX_tradesequence(0,0,0,&numtrades,trades,(int32_t)(sizeof(trades)/sizeof(*trades)),dotrade,activenxt,secret,json);
            if ( dotrade != 0 )
            {
                pend = calloc(1,sizeof(*pend));
                pend->dir = iQ.s.isask == 0 ? 1 : -1, pend->price = iQ.s.price, pend->volume = iQ.s.vol, pend->orderid = iQ.s.quoteid;
                pend->tradesjson = json;
                pend->type = 'S';
                pend->timestamp = (uint32_t)time(NULL);
                //InstantDEX_history(0,pend,0);
                queue_enqueue("PendingQ",&Pending_offersQ.pingpong[0],&pend->DL,0);
            }
        }*/
        else if ( strcmp(method.buf,"makebasket") == 0 )
        {
            if ( (prices= prices777_makebasket(0,json,1,"basket",0,0)) != 0 )
                retstr = clonestr("{\"result\":\"basket made\"}");
            else retstr = clonestr("{\"error\":\"couldnt make basket\"}");
        }
        else if ( strcmp(method.buf,"peggyrates") == 0 )
        {
            //if ( SUPERNET.peggy != 0 )
            //    retstr = peggyrates(juint(json,"timestamp"),jstr(json,"name"));
            //else retstr = clonestr("{\"error\":\"peggy disabled\"}");
        }
        else if ( strcmp(method.buf,"LSUM") == 0 )
        {
            sprintf(retbuf,"{\"result\":\"%s\",\"amount\":%d}",(rand() & 1) ? "BUY" : "SELL",(rand() % 100) * 100000);
            retstr = clonestr(retbuf);
        }
        else if ( strcmp(method.buf,"placebid") == 0 || strcmp(method.buf,"placeask") == 0 )
            return(InstantDEX_placebidask(0,sequenceid,exchangestr.buf,name.buf,base.buf,rel.buf,&iQ,jstr(json,"extra"),secret,activenxt,json));
        else if ( strcmp(exchangestr.buf,"active") == 0 && strcmp(method.buf,"orderbook") == 0 )
            retstr = prices777_activebooks(name.buf,base.buf,rel.buf,iQ.s.baseid,iQ.s.relid,maxdepth,allfields,strcmp(exchangestr.buf,"active") == 0 || juint(json,"tradeable"));
        else if ( (prices= prices777_find(&invert,iQ.s.baseid,iQ.s.relid,exchangestr.buf)) == 0 )
        {
            if ( (prices= prices777_poll(exchangestr.buf,name.buf,base.buf,iQ.s.baseid,rel.buf,iQ.s.relid)) != 0 )
            {
                if ( prices777_equiv(prices->baseid) == prices777_equiv(iQ.s.baseid) && prices777_equiv(prices->relid) == prices777_equiv(iQ.s.relid) )
                    invert = 0;
                else if ( prices777_equiv(prices->baseid) == prices777_equiv(iQ.s.relid) && prices777_equiv(prices->relid) == prices777_equiv(iQ.s.baseid) )
                    invert = 1;
                else invert = 0, printf("baserel not matching (%s %s) %llu %llu vs (%s %s) %llu %llu\n",prices->base,prices->rel,(long long)prices->baseid,(long long)prices->relid,base.buf,rel.buf,(long long)iQ.s.baseid,(long long)iQ.s.relid);
            }
        }
        if ( retstr == 0 && prices != 0 )
        {
            if ( strcmp(method.buf,"disablequotes") == 0 )
            {
                if ( prices != 0 )
                {
                    if ( strcmp(prices->exchange,"unconf") == 0 )
                        return(clonestr("{\"error\":\"cannot disable unconf\"}"));
                    prices->disabled = 1;
                    return(clonestr("{\"result\":\"success\"}"));
                }
                else return(clonestr("{\"error\":\"no prices to disable\"}"));
            }
            else if ( strcmp(method.buf,"enablequotes") == 0 )
            {
                if ( prices != 0 )
                {
                    prices->disabled = 0;
                    return(clonestr("{\"result\":\"success\"}"));
                }
                else return(clonestr("{\"error\":\"no prices to enable\"}"));
            }
            else if ( strcmp(method.buf,"orderbook") == 0 )
            {
                if ( maxdepth < MAX_DEPTH )
                    return(prices777_orderbook_jsonstr(invert,IGUANA_MY64BITS,prices,&prices->O,maxdepth,allfields));
                else if ( (retstr= prices->orderbook_jsonstrs[invert][allfields]) == 0 )
                {
                    retstr = prices777_orderbook_jsonstr(invert,IGUANA_MY64BITS,prices,&prices->O,MAX_DEPTH,allfields);
                    portable_mutex_lock(&prices->mutex);
                    if ( prices->orderbook_jsonstrs[invert][allfields] != 0 )
                        free(prices->orderbook_jsonstrs[invert][allfields]);
                    prices->orderbook_jsonstrs[invert][allfields] = retstr;
                    portable_mutex_unlock(&prices->mutex);
                    if ( retstr == 0 )
                        retstr = clonestr("{}");
                }
                if ( retstr != 0 )
                    retstr = clonestr(retstr);
            }
            //else if ( strcmp(method.buf,"tradebot") == 0 )
            //    retstr = InstantDEX_tradebot(prices,json,&iQ,invert);
        }
        //if ( Debuglevel > 2 )
            printf("(%s) %p exchange.(%s) base.(%s) %llu rel.(%s) %llu | name.(%s) %llu\n",retstr!=0?retstr:"",prices,exchangestr.buf,base.buf,(long long)iQ.s.baseid,rel.buf,(long long)iQ.s.relid,name.buf,(long long)assetbits);
    }
    return(retstr);
}

char *bidask_func(int32_t localaccess,int32_t valid,char *sender,cJSON *json,char *origargstr)
{
    struct destbuf gui,exchangestr,name,base,rel,offerNXT; struct InstantDEX_quote iQ;
    copy_cJSON(&offerNXT,jobj(json,"offerNXT"));
//printf("got (%s)\n",origargstr);
    if ( strcmp(IGUANA_NXTADDR,offerNXT.buf) != 0 )
    {
        if ( bidask_parse(localaccess,&exchangestr,&name,&base,&rel,&gui,&iQ,json) == 0 )
            return(InstantDEX_placebidask(sender,j64bits(json,"orderid"),exchangestr.buf,name.buf,base.buf,rel.buf,&iQ,jstr(json,"extra"),jstr(json,"secret"),jstr(json,"activenxt"),json));
        else printf("error with incoming bidask\n");
    } else fprintf(stderr,"got my bidask from network (%s)\n",origargstr);
    return(clonestr("{\"result\":\"got loopback bidask\"}"));
}

