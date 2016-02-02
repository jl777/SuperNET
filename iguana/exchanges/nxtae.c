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

#define NXT_ASSETID ('N' + ((uint64_t)'X'<<8) + ((uint64_t)'T'<<16))    // 5527630
#define DEFAULT_NXT_DEADLINE 720
#define issue_NXTPOST(cmdstr) bitcoind_RPC(0,"curl",myinfo->NXTAPIURL,0,0,cmdstr)
#define NXT_MSTYPE 5
#define NXT_ASSETTYPE 2
#define NXT_GENESISTIME 1385294400

cJSON *_issue_NXTjson(struct supernet_info *myinfo,char *extra)
{
    char cmd[4096],*jsonstr; cJSON *json = 0;
    //sprintf(cmd,"requestType=getAsset&asset=%s",assetidstr);
    sprintf(cmd,"requestType=%s",extra);
    //printf("_cmd.(%s)\n",cmd);
    if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
    {
        json = cJSON_Parse(jsonstr);
        free(jsonstr);
    }
    return(json);
}

char *_issue_getAsset(struct supernet_info *myinfo,char *assetidstr)
{
    char cmd[4096],*jsonstr;
    //sprintf(cmd,"requestType=getAsset&asset=%s",assetidstr);
    sprintf(cmd,"requestType=getAsset&asset=%s",assetidstr);
    //printf("_cmd.(%s)\n",cmd);
    jsonstr = issue_NXTPOST(cmd);
    //printf("(%s) -> (%s)\n",cmd,jsonstr);
    return(jsonstr);
}

char *_issue_getCurrency(struct supernet_info *myinfo,char *assetidstr)
{
    char cmd[4096];
    //sprintf(cmd,"requestType=getAsset&asset=%s",assetidstr);
    sprintf(cmd,"requestType=getCurrency&currency=%s",assetidstr);
    //printf("_cmd.(%s)\n",cmd);
    return(issue_NXTPOST(cmd));
}

char *_get_AEquotestr(struct supernet_info *myinfo,char *str,uint64_t orderid)
{
    char cmd[256];
    sprintf(cmd,"requestType=get%sOrder&order=%llu",str,(long long)orderid);
    return(issue_NXTPOST(cmd));
}

uint64_t _get_AEquote(struct supernet_info *myinfo,char *str,uint64_t orderid)
{
    char *jsonstr; cJSON *json; uint64_t nxt64bits = 0;
    if ( (jsonstr= _get_AEquotestr(myinfo,str,orderid)) != 0 )
    {
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            nxt64bits = j64bits(json,"account");
            free_json(json);
        }
        free(jsonstr);
    }
    return(nxt64bits);
}

char *_get_MSoffers(struct supernet_info *myinfo,char *str)
{
    char cmd[512];
    sprintf(cmd,"requestType=get%sOffers&account=%s",str,myinfo->myaddr.NXTADDR);
    return(issue_NXTPOST(cmd));
}

uint32_t get_blockutime(struct supernet_info *myinfo,uint32_t blocknum)
{
    cJSON *json; uint32_t timestamp = 0; char cmd[4096],*jsonstr;
    sprintf(cmd,"requestType=getBlock&height=%u",blocknum);
    if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
    {
        //printf("(%s) -> (%s)\n",cmd,jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (timestamp= juint(json,"timestamp")) != 0 )
                timestamp += NXT_GENESISTIME;
            free_json(json);
        }
        free(jsonstr);
    }
    return(timestamp);
}

char *MGWassets[][3] =
{
    { "12659653638116877017", "BTC", "8" },
    { "17554243582654188572", "BTC", "8" }, // assetid, name, decimals
    { "4551058913252105307", "BTC", "8" },
    { "6918149200730574743", "BTCD", "4" },
    { "11060861818140490423", "BTCD", "4" },
    { "16344939950195952527", "DOGE", "4" },
    { "2303962892272487643", "DOGE", "4" },
    { "6775076774325697454", "OPAL", "8" },
    { "7734432159113182240", "VPN", "4" },
    { "9037144112883608562", "VRC", "8" },
    { "2881764795164526882", "LTC", "4" },
};

uint64_t is_MGWcoin(char *name)
{
    int32_t i;
    for (i=0; i<(int32_t)(sizeof(MGWassets)/sizeof(*MGWassets)); i++)
        if ( strcmp(MGWassets[i][1],name) == 0 )
            return(calc_nxt64bits(MGWassets[i][0]));
    return(0);
}

char *is_MGWasset(uint64_t assetid)
{
    int32_t i; char assetidstr[64];
    expand_nxt64bits(assetidstr,assetid);
    for (i=0; i<(int32_t)(sizeof(MGWassets)/sizeof(*MGWassets)); i++)
        if ( strcmp(MGWassets[i][0],assetidstr) == 0 )
            return(MGWassets[i][1]);
    return(0);
}

uint64_t NXT_assetid(char *name)
{
    uint64_t assetid;
    if ( (assetid= is_MGWcoin(name)) != 0 )
        return(assetid);
    else return(calc_nxt64bits(name));
}

double NXT_price_volume(double *volumep,uint64_t baseamount,uint64_t relamount)
{
    *volumep = (((double)baseamount + 0.000000009999999) / SATOSHIDEN);
    if ( baseamount > 0. )
        return((double)relamount / (double)baseamount);
    else return(0.);
}

int32_t is_native_crypto(char *name)
{
    int32_t i,n;
    if ( (n= (int32_t)strlen(name)) > 0 && n < 6 )
    {
        for (i=0; i<n; i++)
        {
            if ( (name[i] >= '0' && name[i] <= '9') || (name[i] >= 'A' && name[i] <= 'Z') )                continue;
            printf("(%s) is not native crypto\n",name);
            return(0);
        }
        printf("(%s) is native crypto\n",name);
        return(1);
    }
    return(0);
}

int32_t get_assettype(struct supernet_info *myinfo,int32_t *numdecimalsp,char *assetidstr)
{
    cJSON *json; char name[64],*jsonstr; uint64_t assetid; int32_t ap_type = -1; //struct assethash *ap,A;
    *numdecimalsp = -1;
    name[0] = 0;
    if ( is_native_crypto(assetidstr) > 0 )
    {
        //printf("found native crypto.(%s) name.(%s)\n",assetidstr,name);
        ap_type = 0;
        *numdecimalsp = 8;
        return(0);
    }
    if ( (assetid= calc_nxt64bits(assetidstr)) == NXT_ASSETID )
    {
        //printf("found NXT_ASSETID.(%s)\n",assetidstr);
        ap_type = 0;
        *numdecimalsp = 8;
        return(0);
    }
    /*if ( (ap= find_asset(assetid)) != 0 )
     {
     *numdecimalsp = ap->decimals;
     return(ap->type);
     }*/
    memset(name,0,sizeof(name));
    if ( (jsonstr= _issue_getAsset(myinfo,assetidstr)) != 0 )
    {
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( get_cJSON_int(json,"errorCode") == 0 )
            {
                //printf("assetstr.(%s)\n",jsonstr);
                if ( extract_cJSON_str(name,16,json,"name") <= 0 )
                    *numdecimalsp = -1;
                else *numdecimalsp = (int32_t)get_cJSON_int(json,"decimals");
                ap_type = NXT_ASSETTYPE;
            } //else printf("errorcode.%lld (%s)\n",(long long)get_cJSON_int(json,"errorCode"),jsonstr);
            free_json(json);
        } else printf("cant parse.(%s)\n",jsonstr);
        free(jsonstr);
    } else printf("couldnt getAsset.(%s)\n",assetidstr);
    if ( ap_type < 0 )
    {
        if ( (jsonstr= _issue_getCurrency(myinfo,assetidstr)) != 0 )
        {
            if ( (json= cJSON_Parse(jsonstr)) != 0 )
            {
                if ( get_cJSON_int(json,"errorCode") == 0 )
                {
                    if ( extract_cJSON_str(name,16,json,"name") <= 0 )
                        *numdecimalsp = -1;
                    else *numdecimalsp = (int32_t)get_cJSON_int(json,"decimals");
                    ap_type = NXT_MSTYPE;
                }
                free_json(json);
            }
            free(jsonstr);
        }
    }
    /*memset(&A,0,sizeof(A));
     A.assetid = assetid;
     A.minvol = A.mult = calc_decimals_mult(*numdecimalsp);
     A.decimals = *numdecimalsp;
     A.type = ap_type;
     strcpy(A.name,name);
     create_asset(assetid,&A);*/
    return(ap_type);
}

uint64_t calc_decimals_mult(int32_t decimals)
{
    int32_t i; uint64_t mult = 1;
    for (i=7-decimals; i>=0; i--)
        mult *= 10;
    return(mult);
}

uint64_t assetmult(struct supernet_info *myinfo,int32_t *is_MSp,char *assetidstr)
{
    int32_t ap_type,decimals; uint64_t mult = 0;
    ap_type = get_assettype(myinfo,&decimals,assetidstr);
    if ( decimals >= 0 && decimals <= 8 )
        mult = calc_decimals_mult(decimals);
    *is_MSp = (ap_type == NXT_MSTYPE);
    return(mult);
}

int32_t assetdecimals(struct supernet_info *myinfo,char *assetidstr)
{
    int32_t ap_type,decimals = 0;
    ap_type = get_assettype(myinfo,&decimals,assetidstr);
    if ( ap_type == 0 )
        return(8);
    return(decimals);
}

uint64_t min_asset_amount(struct supernet_info *myinfo,uint64_t assetid)
{
    char assetidstr[64]; int32_t tmp;
    if ( assetid == NXT_ASSETID )
        return(1);
    expand_nxt64bits(assetidstr,assetid);
    return(assetmult(myinfo,&tmp,assetidstr));
}

int32_t get_assetdecimals(struct supernet_info *myinfo,uint64_t assetid)
{
    char assetidstr[64];
    if ( assetid == NXT_ASSETID )
        return(8);
    expand_nxt64bits(assetidstr,assetid);
    return(assetdecimals(myinfo,assetidstr));
}

uint64_t get_assetmult(struct supernet_info *myinfo,int32_t *is_MSp,uint64_t assetid)
{
    char assetidstr[64];
    expand_nxt64bits(assetidstr,assetid);
    return(assetmult(myinfo,is_MSp,assetidstr));
}

double get_minvolume(struct supernet_info *myinfo,uint64_t assetid)
{
    int32_t tmp;
    return(dstr(get_assetmult(myinfo,&tmp,assetid)));
}

int64_t get_asset_quantity(struct supernet_info *myinfo,int64_t *unconfirmedp,char *NXTaddr,char *assetidstr)
{
    char cmd[2*MAX_JSON_FIELD],*jsonstr; struct destbuf assetid; int32_t i,n,iter; cJSON *array,*item,*obj,*json; int64_t quantity,qty = 0;
    uint64_t assetidbits = calc_nxt64bits(assetidstr);
    quantity = *unconfirmedp = 0;
    if ( assetidbits == NXT_ASSETID )
    {
        sprintf(cmd,"requestType=getBalance&account=%s",NXTaddr);
        if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
        {
            //printf("(%s) -> (%s)\n",cmd,jsonstr);
            if ( (json= cJSON_Parse(jsonstr)) != 0 )
            {
                qty = get_API_nxt64bits(cJSON_GetObjectItem(json,"balanceNQT"));
                *unconfirmedp = get_API_nxt64bits(cJSON_GetObjectItem(json,"unconfirmedBalanceNQT"));
                printf("(%s)\n",jsonstr);
                free_json(json);
            }
            free(jsonstr);
        }
        return(qty);
    }
    sprintf(cmd,"requestType=getAccount&account=%s",NXTaddr);
    if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
    {
        //printf("(%s) -> (%s)\n",cmd,jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            for (iter=0; iter<2; iter++)
            {
                qty = 0;
                array = cJSON_GetObjectItem(json,iter==0?"assetBalances":"unconfirmedAssetBalances");
                if ( is_cJSON_Array(array) != 0 )
                {
                    n = cJSON_GetArraySize(array);
                    for (i=0; i<n; i++)
                    {
                        item = cJSON_GetArrayItem(array,i);
                        if ( (obj = cJSON_GetObjectItem(item,"asset")) == 0 )
                            printf("check for mscoin\n"), getchar();
                        copy_cJSON(&assetid,obj);
                        //printf("i.%d of %d: %s(%s)\n",i,n,assetid,cJSON_Print(item));
                        if ( strcmp(assetid.buf,assetidstr) == 0 )
                        {
                            qty = get_cJSON_int(item,iter==0?"balanceQNT":"unconfirmedBalanceQNT");
                            break;
                        }
                    }
                }
                if ( iter == 0 )
                    quantity = qty;
                else *unconfirmedp = qty;
            }
            free_json(json);
        }
        free(jsonstr);
    }
    return(quantity);
}

uint64_t calc_asset_qty(struct supernet_info *myinfo,int32_t *is_MSp,uint64_t *availp,uint64_t *priceNQTp,int32_t checkflag,uint64_t assetid,double price,double vol)
{
    char assetidstr[64];
    uint64_t ap_mult,priceNQT,quantityQNT = 0;
    int64_t unconfirmed,balance;
    *priceNQTp = *availp = 0;
    if ( assetid != NXT_ASSETID )
    {
        expand_nxt64bits(assetidstr,assetid);
        if ( (ap_mult= get_assetmult(myinfo,is_MSp,assetid)) != 0 )
        {
            //price = (double)get_satoshi_obj(srcitem,"priceNQT") / ap_mult;
            //vol = (double)get_satoshi_obj(srcitem,"quantityQNT") * ((double)ap_mult / SATOSHIDEN);
            priceNQT = (price * ap_mult + (ap_mult/2)/SATOSHIDEN);
            quantityQNT = (vol * SATOSHIDEN) / ap_mult;
            balance = get_asset_quantity(myinfo,&unconfirmed,myinfo->myaddr.NXTADDR,assetidstr);
            //printf("%s balance %.8f unconfirmed %.8f vs price %llu qty %llu for asset.%s | price_vol.(%f * %f) * (%lld / %llu)\n",NXTaddr,dstr(balance),dstr(unconfirmed),(long long)priceNQT,(long long)quantityQNT,assetidstr,price,vol,(long long)SATOSHIDEN,(long long)ap_mult);
            //getchar();
            if ( checkflag != 0 && (balance < quantityQNT || unconfirmed < quantityQNT) )
            {
                printf("balance %.8f < qty %.8f || unconfirmed %.8f < qty %llu\n",dstr(balance),dstr(quantityQNT),dstr(unconfirmed),(long long)quantityQNT);
                return(0);
            }
            *priceNQTp = priceNQT;
            *availp = unconfirmed;
        } else printf("%llu null apmult\n",(long long)assetid);
    }
    else
    {
        *is_MSp = 0;
        *priceNQTp = price * SATOSHIDEN;
        quantityQNT = vol;
    }
    return(quantityQNT);
}

int32_t NXT_assetpolarity(struct supernet_info *myinfo,char *name)
{
    int32_t ap_type,decimals;
    if ( (ap_type= get_assettype(myinfo,&decimals,name)) == NXT_ASSETTYPE || ap_type == NXT_MSTYPE )
        return(1);
    else return(0);
}

#define EXCHANGE_NAME "nxtae"
#define UPDATE nxtae ## _price
#define SUPPORTS nxtae ## _supports
#define SIGNPOST nxtae ## _signpost
#define TRADE nxtae ## _trade
#define ORDERSTATUS nxtae ## _orderstatus
#define CANCELORDER nxtae ## _cancelorder
#define OPENORDERS nxtae ## _openorders
#define TRADEHISTORY nxtae ## _tradehistory
#define BALANCES nxtae ## _balances
#define PARSEBALANCE nxtae ## _parsebalance
#define WITHDRAW nxtae ## _withdraw
#define CHECKBALANCE nxtae ## _checkbalance
#define ALLPAIRS nxtae ## _allpairs
#define FUNCS nxtae ## _funcs
#define BASERELS nxtae ## _baserels

static char *BASERELS[][2] = { {"btc","nxt"}, {"btcd","nxt"}, {"ltc","nxt"}, {"vrc","nxt"}, {"doge","nxt"}, {"opal","nxt"} };

char *ALLPAIRS(struct exchange_info *exchange,cJSON *argjson)
{
    return(jprint(exchanges777_allpairs(BASERELS,(int32_t)(sizeof(BASERELS)/sizeof(*BASERELS))),1));
}

int32_t SUPPORTS(struct exchange_info *exchange,char *base,char *rel,cJSON *argjson)
{
    int32_t polarity; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    if ( (polarity= baserel_polarity(BASERELS,(int32_t)(sizeof(BASERELS)/sizeof(*BASERELS)),base,rel)) == 0 )
    {
        if ( strcmp(rel,"NXT") == 0 || strcmp(rel,"nxt") == 0 || calc_nxt64bits(rel) == NXT_ASSETID )
            return(NXT_assetpolarity(myinfo,base));
        else if ( strcmp(base,"NXT") == 0 || strcmp(base,"nxt") == 0 || calc_nxt64bits(base) == NXT_ASSETID )
            return(-NXT_assetpolarity(myinfo,rel));
    }
    return(polarity);
}

cJSON *inner_json(double price,double vol,uint32_t timestamp,uint64_t quoteid,uint64_t nxt64bits,uint64_t qty,uint64_t pqt,uint64_t baseamount,uint64_t relamount)
{
    cJSON *inner = cJSON_CreateArray();
    jaddnum(inner,"price",price);
    jaddnum(inner,"volume",vol);
    jadd64bits(inner,"quoteid",quoteid);
    jadd64bits(inner,"offerNXT",nxt64bits);
    jaddnum(inner,"timestamp",timestamp);
    jadd64bits(inner,"quantityQNT",qty);
    jadd64bits(inner,"priceNQT",pqt);
    jadd64bits(inner,"baseamount",baseamount);
    jadd64bits(inner,"relamount",relamount);
    return(inner);
}

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *bidasks,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert)
{
    int32_t flip,i,n,is_MS; uint64_t baseamount,relamount,qty,pqt,ap_mult,baseid;
    char url[1024],*str,*cmd,*field; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    uint32_t timestamp; cJSON *json,*bids,*asks,*srcobj,*item,*array; double price,vol,hbla = 0.;
    if ( NXT_ASSETID != stringbits("NXT") || (strcmp(rel,"nxt") != 0 && strcmp(rel,"NXT") != 0 && strcmp(rel,"5527630") != 0) )
    {
        printf("NXT_ASSETID.%llu != %llu stringbits rel.%s\n",(long long)NXT_ASSETID,(long long)stringbits("NXT"),rel);//, getchar();
        return(0);
    }
    baseid = NXT_assetid(base);
    ap_mult = get_assetmult(myinfo,&is_MS,baseid);
    bids = cJSON_CreateArray(), asks = cJSON_CreateArray();
    for (flip=0; flip<2; flip++)
    {
        /*{
         "offer": "16959774565785265980",
         "expirationHeight": 1000000,
         "accountRS": "NXT-QFAF-GR4F-RBSR-AXW2G",
         "limit": "9000000",
         "currency": "5775213290661997199",
         "supply": "0",
         "account": "9728792749189838093",
         "height": 348856,
         "rateNQT": "650"
         }*/
        if ( is_MS == 0 )
        {
            if ( flip == 0 )
                cmd = "getBidOrders", field = "bidOrders", array = bids;
            else cmd = "getAskOrders", field = "askOrders", array = asks;
            sprintf(url,"requestType=%s&asset=%llu&limit=%d",cmd,(long long)baseid,maxdepth);
        }
        else
        {
            if ( flip == 0 )
                cmd = "getBuyOffers", field = "offers", array = bids;
            else cmd = "getSellOffers", field = "offers", array = asks;
            sprintf(url,"requestType=%s&currency=%llu&limit=%d",cmd,(long long)baseid,maxdepth);
        }
        if ( (str= issue_NXTPOST(url)) != 0 )
        {
            //printf("{%s}\n",str);
            if ( (json= cJSON_Parse(str)) != 0 )
            {
                if ( (srcobj= jarray(&n,json,field)) != 0 )
                {
                    for (i=0; i<n && i<maxdepth; i++)
                    {
                        /*
                         "quantityQNT": "79",
                         "priceNQT": "13499000000",
                         "transactionHeight": 480173,
                         "accountRS": "NXT-FJQN-8QL2-BMY3-64VLK",
                         "transactionIndex": 1,
                         "asset": "15344649963748848799",
                         "type": "ask",
                         "account": "5245394173527769812",
                         "order": "17926122097022414596",
                         "height": 480173
                         */
                        item = cJSON_GetArrayItem(srcobj,i);
                        if ( is_MS == 0 )
                            qty = j64bits(item,"quantityQNT"), pqt = j64bits(item,"priceNQT");
                        else qty = j64bits(item,"limit"), pqt = j64bits(item,"rateNQT");
                        baseamount = (qty * ap_mult), relamount = (qty * pqt);
                        price = NXT_price_volume(&vol,baseamount,relamount);
                        //printf("(%llu %llu) %f %f mult.%llu qty.%llu pqt.%llu baseamount.%lld relamount.%lld\n",(long long)prices->baseid,(long long)prices->relid,price,vol,(long long)prices->ap_mult,(long long)qty,(long long)pqt,(long long)baseamount,(long long)relamount);
                        timestamp = get_blockutime(myinfo,juint(item,"height"));
                        item = inner_json(price,vol,timestamp,j64bits(item,is_MS == 0 ? "order" : "offer"),j64bits(item,"account"),qty,pqt,baseamount,relamount);
                        cJSON_AddItemToArray(array,item);
                    }
                }
                free_json(json);
            }
            free(str);
        } else printf("cant get.(%s)\n",url);
    }
    json = cJSON_CreateObject();
    cJSON_AddItemToObject(json,"bids",bids);
    cJSON_AddItemToObject(json,"asks",asks);
   // if ( Debuglevel > 2 )
        printf("invert.%d NXTAE.(%s)\n",invert,jprint(json,0));
    hbla = exchanges777_json_orderbook(exchange,commission,base,rel,bidasks,maxdepth,json,0,"bids","asks",0,0,invert);
    free_json(json);
    return(hbla);
}

uint64_t submit_triggered_nxtae(struct supernet_info *myinfo,int32_t dotrade,char **retjsonstrp,int32_t is_MS,char *bidask,uint64_t assetid,uint64_t qty,uint64_t NXTprice,char *triggerhash,char *comment,uint64_t otherNXT,uint32_t triggerheight)
{
    int32_t deadline = 1 + 20; uint64_t txid = 0; struct destbuf errstr; char cmd[4096],secret[8192],*jsonstr; cJSON *json;
    if ( retjsonstrp != 0 )
        *retjsonstrp = 0;
    if ( triggerheight != 0 )
        deadline = DEFAULT_NXT_DEADLINE;
    escape_code(secret,myinfo->secret);
    if ( dotrade == 0 )
        strcpy(secret,"<secret>");
    sprintf(cmd,"requestType=%s&secretPhrase=%s&feeNQT=%u&deadline=%d",bidask,secret,0,deadline);
    sprintf(cmd+strlen(cmd),"&%s=%llu&%s=%llu",is_MS!=0?"units":"quantityQNT",(long long)qty,is_MS!=0?"currency":"asset",(long long)assetid);
    if ( NXTprice != 0 )
    {
        if ( is_MS != 0 )
            sprintf(cmd+strlen(cmd),"&rateNQT=%llu",(long long)NXTprice);
        else sprintf(cmd+strlen(cmd),"&priceNQT=%llu",(long long)NXTprice);
    }
    if ( otherNXT != 0 )
        sprintf(cmd+strlen(cmd),"&recipient=%llu",(long long)otherNXT);
    if ( triggerhash != 0 && triggerhash[0] != 0 )
    {
        if ( triggerheight == 0 )
            sprintf(cmd+strlen(cmd),"&referencedTransactionFullHash=%s",triggerhash);
        else sprintf(cmd+strlen(cmd),"&referencedTransactionFullHash=%s&phased=true&phasingFinishHeight=%u&phasingVotingModel=4&phasingQuorum=1&phasingLinkedFullHash=%s",triggerhash,triggerheight,triggerhash);
    }
    if ( comment != 0 && comment[0] != 0 )
        sprintf(cmd+strlen(cmd),"&message=%s",comment);
    if ( dotrade == 0 )
    {
        if ( retjsonstrp != 0 )
        {
            json = cJSON_CreateObject();
            jaddstr(json,"submit",cmd);
            *retjsonstrp = jprint(json,1);
        }
        return(0);
    }
    if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
    {
        _stripwhite(jsonstr,' ');
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            copy_cJSON(&errstr,cJSON_GetObjectItem(json,"error"));
            if ( errstr.buf[0] == 0 )
                copy_cJSON(&errstr,cJSON_GetObjectItem(json,"errorDescription"));
            if ( errstr.buf[0] != 0 )
            {
                printf("submit_triggered_bidask.(%s) -> (%s)\n",cmd,jsonstr);
                if ( retjsonstrp != 0 )
                    *retjsonstrp = clonestr(errstr.buf);
            }
            else txid = get_API_nxt64bits(cJSON_GetObjectItem(json,"transaction"));
        }
        free(jsonstr);
    }
    return(txid);
}

char *fill_nxtae(struct supernet_info *myinfo,int32_t dotrade,uint64_t *txidp,int32_t dir,double price,double volume,uint64_t baseid,uint64_t relid)
{
    uint64_t txid,assetid,avail,qty,priceNQT,ap_mult; int32_t is_MS; char retbuf[512],*errstr,*cmdstr;
    if ( baseid == NXT_ASSETID )
        dir = -dir, assetid = relid;
    else if ( relid == NXT_ASSETID )
        assetid = baseid;
    else return(clonestr("{\"error\":\"NXT AE order without NXT\"}"));
    if ( (ap_mult= get_assetmult(myinfo,&is_MS,assetid)) == 0 )
        return(clonestr("{\"error\":\"assetid not found\"}"));
    qty = calc_asset_qty(myinfo,&is_MS,&avail,&priceNQT,0,assetid,price,volume);
    if ( is_MS == 0 )
        cmdstr = dir > 0 ? "placeBidOrder" : "placeAskOrder";
    else cmdstr = dir > 0 ? "currencyBuy" : "currencySell";
    txid = submit_triggered_nxtae(myinfo,dotrade,&errstr,is_MS,cmdstr,assetid,qty,priceNQT,0,0,0,0);
    if ( errstr != 0 )
        sprintf(retbuf,"{\"error\":\"%s\"}",errstr), free(errstr);
    else sprintf(retbuf,"{\"result\":\"success\",\"txid\":\"%llu\"}",(long long)txid);
    if ( txidp != 0 )
        *txidp = txid;
    return(clonestr(retbuf));
}

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    uint64_t baseid,relid; char *retstr; uint64_t txid = 0; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    if ( (baseid= NXT_assetid(base)) != 0 && (relid= NXT_assetid(rel)) != 0 )
    {
        retstr = fill_nxtae(myinfo,dotrade,&txid,dir,price,volume,baseid,relid);
        if ( retstrp != 0 )
            *retstrp = retstr;
        else free(retstr);
    }
    return(txid);
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    cJSON *item; char extra[256]; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    if ( strcmp(coinstr,"NXT") == 0 )
    {
        if ( (item= _issue_NXTjson(myinfo,"getAccount")) != 0 )
        {
            jadd(item,"NXT",item);
            jaddstr(item,"result","success");
            *balancep = dstr(j64bits(item,"balanceNQT"));
            return(jprint(item,1));
        }
    }
    else if ( NXT_assetpolarity(myinfo,coinstr) != 0 )
    {
        sprintf(extra,"getAccountAssets&asset=%s",coinstr);
        if ( (item= _issue_NXTjson(myinfo,extra)) != 0 )
        {
            if ( jstr(item,"assetid") != 0 )
            {
                jaddstr(item,"result","success");
                return(jprint(item,1));
            }
            free_json(item);
        }
    }
    else
    {
        sprintf(extra,"getAccountCurrencies&currency=%s",coinstr);
        if ( (item= _issue_NXTjson(myinfo,extra)) != 0 )
        {
            if ( jstr(item,"currency") != 0 )
            {
                jaddstr(item,"result","success");
                return(jprint(item,1));
            }
            free_json(item);
        }
    }
    return(clonestr("{\"error\":\"cant get coin balance\"}"));
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    cJSON *item,*retjson = cJSON_CreateObject(); struct supernet_info *myinfo = SuperNET_MYINFO(0);
    if ( (item= _issue_NXTjson(myinfo,"getAccountAssets")) != 0 )
        jadd(retjson,"assets",item);
    if ( (item= _issue_NXTjson(myinfo,"getAccountCurrencies")) != 0 )
        jadd(retjson,"currencies",item);
    if ( (item= _issue_NXTjson(myinfo,"getAccount")) != 0 )
        jadd(retjson,"NXT",item);
    jaddstr(retjson,"result","success");
    return(retjson);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    uint64_t nxt64bits; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    if ( (nxt64bits= _get_AEquote(myinfo,"Bid",quoteid)) == 0 )
        return(_get_AEquotestr(myinfo,"Ask",quoteid));
    else return(_get_AEquotestr(myinfo,"Bid",quoteid));

}

char *CANCELORDER(struct exchange_info *exchange,uint64_t orderid,cJSON *argjson)
{
    uint64_t nxt64bits; char cmd[4096],secret[8192],*str = "Bid",*retstr = 0; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    if ( (nxt64bits= _get_AEquote(myinfo,str,orderid)) == 0 )
        str = "Ask", nxt64bits = _get_AEquote(myinfo,str,orderid);
    if ( nxt64bits == calc_nxt64bits(myinfo->myaddr.NXTADDR) )
    {
        escape_code(secret,myinfo->secret);
        sprintf(cmd,"requestType=cancel%sOrder&secretPhrase=%s&feeNQT=%d&deadline=%d&order=%llu",str,secret,0,DEFAULT_NXT_DEADLINE,(long long)orderid);
        retstr = issue_NXTPOST(cmd);
        //printf("(%s) -> (%s)\n",cmd,retstr);
    }
    else retstr = clonestr("{\"error\":\"cant cancel orderid\"}");
    return(retstr);
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    cJSON *item,*retjson = cJSON_CreateObject(); struct supernet_info *myinfo = SuperNET_MYINFO(0);
    if ( (item= _issue_NXTjson(myinfo,"getBuyOffers")) != 0 )
        jadd(retjson,"buyoffers",item);
    if ( (item= _issue_NXTjson(myinfo,"getSellOffers")) != 0 )
        jadd(retjson,"selloffers",item);
    if ( (item= _issue_NXTjson(myinfo,"getAccountCurrentBidOrders")) != 0 )
        jadd(retjson,"bidorders",item);
    if ( (item= _issue_NXTjson(myinfo,"getAccountCurrentAskOrders")) != 0 )
        jadd(retjson,"sellorders",item);
    jaddstr(retjson,"result","success");
    return(jprint(retjson,1));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"nxtae tradehistory here\"}"));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"MGW withdraw here\"}"));
}

struct exchange_funcs nxtae_funcs = EXCHANGE_FUNCS(nxtae,EXCHANGE_NAME);

#include "exchange_undefs.h"
