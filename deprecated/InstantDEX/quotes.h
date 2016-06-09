/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
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


#ifndef xcode_quotes_h
#define xcode_quotes_h

#ifdef oldway
int32_t make_jumpiQ(uint64_t refbaseid,uint64_t refrelid,int32_t flip,struct InstantDEX_quote *iQ,struct InstantDEX_quote *baseiQ,struct InstantDEX_quote *reliQ,char *gui,int32_t duration)
{
    uint64_t baseamount,relamount,frombase,fromrel,tobase,torel;
    double vol;
    char exchange[64];
    uint32_t timestamp;
    frombase = baseiQ->baseamount, fromrel = baseiQ->relamount;
    tobase = reliQ->baseamount, torel = reliQ->relamount;
    if ( make_jumpquote(refbaseid,refrelid,&baseamount,&relamount,&frombase,&fromrel,&tobase,&torel) == 0. )
        return(0);
    if ( (timestamp= reliQ->timestamp) > baseiQ->timestamp )
        timestamp = baseiQ->timestamp;
    iQ_exchangestr(exchange,iQ);
    create_InstantDEX_quote(iQ,timestamp,0,calc_quoteid(baseiQ) ^ calc_quoteid(reliQ),0.,0.,refbaseid,baseamount,refrelid,relamount,exchange,0,gui,baseiQ,reliQ,duration);
    if ( Debuglevel > 2 )
        printf("jump%s: %f (%llu/%llu) %llu %llu (%f %f) %llu %llu\n",flip==0?"BID":"ASK",calc_price_volume(&vol,iQ->baseamount,iQ->relamount),(long long)baseamount,(long long)relamount,(long long)frombase,(long long)fromrel,calc_price_volume(&vol,frombase,fromrel),calc_price_volume(&vol,tobase,torel),(long long)tobase,(long long)torel);
    iQ->isask = flip;
    iQ->minperc = baseiQ->minperc;
    if ( reliQ->minperc > iQ->minperc )
        iQ->minperc = reliQ->minperc;
    return(1);
}
#else

struct InstantDEX_quote *AllQuotes;

void clear_InstantDEX_quoteflags(struct InstantDEX_quote *iQ)
{
    //duration:14,wallet:1,a:1,isask:1,expired:1,closed:1,swap:1,responded:1,matched:1,feepaid:1,automatch:1,pending:1,minperc:7;
    iQ->s.a = iQ->s.expired = iQ->s.swap = iQ->s.feepaid = 0;
    iQ->s.closed = iQ->s.pending = iQ->s.responded = iQ->s.matched = 0;
}
void cancel_InstantDEX_quote(struct InstantDEX_quote *iQ) { iQ->s.closed = 1; }

int32_t InstantDEX_uncalcsize() { struct InstantDEX_quote iQ; return(sizeof(iQ.hh) + sizeof(iQ.s.quoteid) + sizeof(iQ.s.price) + sizeof(iQ.s.vol)); }

int32_t iQcmp(struct InstantDEX_quote *iQA,struct InstantDEX_quote *iQB)
{
    if ( iQA->s.isask == iQB->s.isask && iQA->s.baseid == iQB->s.baseid && iQA->s.relid == iQB->s.relid && iQA->s.baseamount == iQB->s.baseamount && iQA->s.relamount == iQB->s.relamount )
        return(0);
    else if ( iQA->s.isask != iQB->s.isask && iQA->s.baseid == iQB->s.relid && iQA->s.relid == iQB->s.baseid && iQA->s.baseamount == iQB->s.relamount && iQA->s.relamount == iQB->s.baseamount )
        return(0);
    return(-1);
}

uint64_t calc_txid(unsigned char *buf,int32_t len)
{
    bits256 hash;
    vcalc_sha256(0,hash.bytes,buf,len);
    return(hash.txid);
}

uint64_t calc_quoteid(struct InstantDEX_quote *iQ)
{
    struct InstantDEX_quote Q;
    if ( iQ == 0 )
        return(0);
    if ( iQ->s.duration == 0 || iQ->s.duration > ORDERBOOK_EXPIRATION )
        iQ->s.duration = ORDERBOOK_EXPIRATION;
    if ( iQ->s.quoteid == 0 )
    {
        Q = *iQ;
        clear_InstantDEX_quoteflags(&Q);
        if ( Q.s.isask != 0 )
        {
            Q.s.baseid = iQ->s.relid, Q.s.baseamount = iQ->s.relamount;
            Q.s.relid = iQ->s.baseid, Q.s.relamount = iQ->s.baseamount;
            Q.s.isask = Q.s.minperc = 0;
        }
        return(calc_txid((uint8_t *)((long)&Q + InstantDEX_uncalcsize()),sizeof(Q) - InstantDEX_uncalcsize()));
    } return(iQ->s.quoteid);
}

struct InstantDEX_quote *find_iQ(uint64_t quoteid)
{
    struct InstantDEX_quote *iQ;
    HASH_FIND(hh,AllQuotes,&quoteid,sizeof(quoteid),iQ);
    return(iQ);
}

struct InstantDEX_quote *delete_iQ(uint64_t quoteid)
{
    struct InstantDEX_quote *iQ;
    if ( (iQ= find_iQ(quoteid)) != 0 )
    {
        HASH_DELETE(hh,AllQuotes,iQ);
    }
    return(iQ);
}

struct InstantDEX_quote *findquoteid(uint64_t quoteid,int32_t evenclosed)
{
    struct InstantDEX_quote *iQ;
    if ( (iQ= find_iQ(quoteid)) != 0 )
    {
        if ( evenclosed != 0 || iQ->s.closed == 0 )
        {
            if ( calc_quoteid(iQ) == quoteid )
                return(iQ);
            else printf("calc_quoteid %llu vs %llu\n",(long long)calc_quoteid(iQ),(long long)quoteid);
        } //else printf("quoteid.%llu closed.%d\n",(long long)quoteid,iQ->closed);
    } else printf("couldnt find %llu\n",(long long)quoteid);
    return(0);
}

int32_t cancelquote(char *NXTaddr,uint64_t quoteid)
{
    struct InstantDEX_quote *iQ;
    if ( (iQ= findquoteid(quoteid,0)) != 0 && iQ->s.offerNXT == calc_nxt64bits(NXTaddr) && iQ->exchangeid == INSTANTDEX_EXCHANGEID )
    {
        cancel_InstantDEX_quote(iQ);
        return(1);
    }
    return(0);
}

struct InstantDEX_quote *create_iQ(struct InstantDEX_quote *iQ,char *walletstr)
{
    struct InstantDEX_quote *newiQ,*tmp; struct prices777 *prices; int32_t inverted; long len = 0;
    if ( walletstr != 0 && (len= strlen(walletstr)) > 0 )
        iQ->s.wallet = 1, len++;
    calc_quoteid(iQ);
    printf("createiQ %llu/%llu %f %f quoteid.%llu offerNXT.%llu wallet.%d (%s)\n",(long long)iQ->s.baseid,(long long)iQ->s.relid,iQ->s.price,iQ->s.vol,(long long)iQ->s.quoteid,(long long)iQ->s.offerNXT,iQ->s.wallet,walletstr!=0?walletstr:"");
    if ( (newiQ= find_iQ(iQ->s.quoteid)) != 0 )
        return(newiQ);
    newiQ = calloc(1,sizeof(*newiQ) + len);
    *newiQ = *iQ;
    if ( len != 0 )
        memcpy(newiQ->walletstr,walletstr,len);
    HASH_ADD(hh,AllQuotes,s.quoteid,sizeof(newiQ->s.quoteid),newiQ);
    if ( (prices= prices777_find(&inverted,iQ->s.baseid,iQ->s.relid,INSTANTDEX_NAME)) != 0 )
        prices->dirty++;
    {
        struct InstantDEX_quote *checkiQ;
        if ( (checkiQ= find_iQ(iQ->s.quoteid)) == 0 || iQcmp(iQ,checkiQ) != 0 )//memcmp((uint8_t *)((long)checkiQ + sizeof(checkiQ->hh) + sizeof(checkiQ->quoteid)),(uint8_t *)((long)iQ + sizeof(iQ->hh) + sizeof(iQ->quoteid)),sizeof(*iQ) - sizeof(iQ->hh) - sizeof(iQ->quoteid)) != 0 )
        {
            int32_t i;
            for (i=(sizeof(iQ->hh) - sizeof(iQ->s.quoteid)); i<sizeof(*iQ) - sizeof(iQ->hh) - sizeof(iQ->s.quoteid); i++)
                printf("%02x ",((uint8_t *)iQ)[i]);
            printf("iQ\n");
            for (i=(sizeof(checkiQ->hh) + sizeof(checkiQ->s.quoteid)); i<sizeof(*checkiQ) - sizeof(checkiQ->hh) - sizeof(checkiQ->s.quoteid); i++)
                printf("%02x ",((uint8_t *)checkiQ)[i]);
            printf("checkiQ\n");
            printf("error finding iQ after adding %llu vs %llu\n",(long long)checkiQ->s.quoteid,(long long)iQ->s.quoteid);
        }
    }
    HASH_ITER(hh,AllQuotes,iQ,tmp)
    {
        if ( iQ->s.expired != 0 )
        {
            printf("quoteid.%llu expired, purging\n",(long long)iQ->s.expired);
            delete_iQ(iQ->s.quoteid);
        }
    }
    return(newiQ);
}

#ifdef later
cJSON *pangea_walletitem(cJSON *walletitem,struct coin777 *coin,int32_t rakemillis,int64_t bigblind,int64_t ante,int32_t minbuyin,int32_t maxbuyin)
{
    char *addr; struct destbuf pubkey;
    if ( walletitem == 0 )
        walletitem = cJSON_CreateObject();
    //printf("call get_acct_coinaddr.%s (%s) (%s)\n",coin->name,coin->serverport,coin->userpass);
    if ( coin->pangeapubkey[0] == 0 || coin->pangeacoinaddr[0] == 0 )
    {
        if ( strcmp("NXT",coin->name) == 0 )
        {
        }
        else if ( (addr= get_acct_coinaddr(coin->pangeacoinaddr,coin->name,coin->serverport,coin->userpass,"pangea")) != 0 )
        {
            //printf("get_pubkey\n");
            get_pubkey(&pubkey,coin->name,coin->serverport,coin->userpass,coin->pangeacoinaddr);
            strcpy(coin->pangeapubkey,pubkey.buf);
        }
    }
    jaddstr(walletitem,"pubkey",coin->pangeapubkey);
    jaddstr(walletitem,"coinaddr",coin->pangeacoinaddr);
    jaddnum(walletitem,"rakemillis",rakemillis);
    jaddnum(walletitem,"minbuyin",minbuyin);
    jaddnum(walletitem,"maxbuyin",maxbuyin);
    jadd64bits(walletitem,"bigblind",bigblind);
    jadd64bits(walletitem,"ante",ante);
    return(walletitem);
}

cJSON *set_walletstr(cJSON *walletitem,char *walletstr,struct InstantDEX_quote *iQ)
{
    char pubkeystr[128],pkhash[128],base[64],rel[64],fieldA[64],fieldB[64],fieldpkhash[64],*pubA,*pubB,*pkhashstr,*str,*exchangestr;
    struct coin777 *coin; int32_t flip = 0;
    if ( walletstr != 0 && walletitem == 0 )
       walletitem = cJSON_Parse(walletstr);
    if ( walletitem == 0 )
       walletitem = cJSON_CreateObject();
    unstringbits(base,iQ->s.basebits), unstringbits(rel,iQ->s.relbits);
    flip = (iQ->s.offerNXT != IGUANA_MY64BITS);
    if ( strcmp(base,"NXT") != 0 )
        coin = coin777_find(base,1);
    else if ( strcmp(rel,"NXT") != 0 )
        coin = coin777_find(rel,1), flip ^= 1;
    else coin = 0;
    if ( coin != 0 )
    {
        if ( (exchangestr= exchange_str(iQ->exchangeid)) != 0 && strcmp(exchangestr,"pangea") == 0 )
            pangea_walletitem(walletitem,coin,iQ->s.minperc,iQ->s.baseamount,iQ->s.relamount,iQ->s.minbuyin,iQ->s.maxbuyin);
        else
        {
            //printf("START.(%s)\n",jprint(walletitem,0));
            if ( (iQ->s.isask ^ flip) == 0 )
            {
                sprintf(fieldA,"%spubA",coin->name);
                if ( (pubA= jstr(walletitem,fieldA)) != 0 )
                    cJSON_DeleteItemFromObject(walletitem,fieldA);
                jaddstr(walletitem,fieldA,coin->atomicsendpubkey);
                //printf("replaceA\n");
            }
            else
            {
                sprintf(fieldB,"%spubB",coin->name);
                if ( (pubB= jstr(walletitem,fieldB)) != 0 )
                    cJSON_DeleteItemFromObject(walletitem,fieldB);
                jaddstr(walletitem,fieldB,coin->atomicrecvpubkey);
                sprintf(fieldpkhash,"%spkhash",coin->name);
                if ( (pkhashstr= jstr(walletitem,fieldpkhash)) != 0 )
                    cJSON_DeleteItemFromObject(walletitem,fieldpkhash);
                subatomic_pubkeyhash(pubkeystr,pkhash,coin,iQ->s.quoteid);
                jaddstr(walletitem,fieldpkhash,pkhash);
                //printf("replaceB\n");
            }
        }
        str = jprint(walletitem,0);
        strcpy(walletstr,str);
        free(str);
        return(walletitem);
    }
    return(0);
}
#endif

char *InstantDEX_str(char *walletstr,char *buf,int32_t extraflag,struct InstantDEX_quote *iQ)
{
    cJSON *json; char _buf[4096],base[64],rel[64],*str;
    unstringbits(base,iQ->s.basebits), unstringbits(rel,iQ->s.relbits);
    if ( buf == 0 )
        buf = _buf;
    sprintf(buf,"{\"quoteid\":\"%llu\",\"base\":\"%s\",\"baseid\":\"%llu\",\"baseamount\":\"%llu\",\"rel\":\"%s\",\"relid\":\"%llu\",\"relamount\":\"%llu\",\"price\":%.8f,\"volume\":%.8f,\"offerNXT\":\"%llu\",\"timestamp\":\"%u\",\"isask\":\"%u\",\"exchange\":\"%s\",\"gui\":\"%s\"}",(long long)iQ->s.quoteid,base,(long long)iQ->s.baseid,(long long)iQ->s.baseamount,rel,(long long)iQ->s.relid,(long long)iQ->s.relamount,iQ->s.price,iQ->s.vol,(long long)iQ->s.offerNXT,iQ->s.timestamp,iQ->s.isask,exchange_str(iQ->exchangeid),iQ->gui);
    if ( extraflag != 0 )
    {
        sprintf(buf + strlen(buf) - 1,",\"plugin\":\"relay\",\"destplugin\":\"InstantDEX\",\"method\":\"busdata\",\"submethod\":\"%s\"}",(iQ->s.isask != 0) ? "ask" : "bid");
    }
    //printf("InstantDEX_str.(%s)\n",buf);
    if ( (json= cJSON_Parse(buf)) != 0 )
    {
#ifdef later
        char _buf[4096],_walletstr[256],base[64],rel[64],*exchange,*str; cJSON *walletitem,*json; struct coin777 *coin;
        if ( walletstr == 0 )
        {
            walletstr = _walletstr;
            walletstr[0] = 0;
        }
        if ( (exchange= exchange_str(iQ->exchangeid)) != 0 )
        {
            coin = coin777_find(base,0);
            if ( strcmp(exchange,"wallet") == 0 )
                walletitem = set_walletstr(0,walletstr,iQ);
            else if ( strcmp(exchange,"pangea") == 0 && walletstr[0] == 0 && coin != 0 )
                walletitem = pangea_walletitem(0,coin,iQ->s.minperc,iQ->s.baseamount,iQ->s.relamount,iQ->s.minbuyin,iQ->s.maxbuyin);
            else walletitem = 0;
            if ( walletitem != 0 )
            {
                jadd(json,"wallet",walletitem);
                strcpy(walletstr,jprint(walletitem,0));
            }
//printf("exchange.(%s) iswallet.%d (%s) base.(%s) coin.%p (%s)\n",exchange,iQ->s.wallet,walletstr,base,coin,jprint(json,0));
        } else printf("InstantDEX_str cant find exchangeid.%d\n",iQ->exchangeid);
#endif
       str = jprint(json,1);
        strcpy(buf,str);
        //printf("str.(%s) %p\n",buf,buf);
        free(str);
    } else printf("InstantDEX_str cant parse.(%s)\n",buf);
    if ( buf == _buf )
        return(clonestr(buf));
    else return(buf);
}

uint64_t _get_AEquote(char *str,uint64_t orderid)
{
    cJSON *json;
    uint64_t nxt64bits = 0;
    char cmd[256],*jsonstr;
    sprintf(cmd,"requestType=get%sOrder&order=%llu",str,(long long)orderid);
    if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
    {
        //printf("(%s) -> (%s)\n",cmd,jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            nxt64bits = get_API_nxt64bits(cJSON_GetObjectItem(json,"account"));
            free_json(json);
        }
        free(jsonstr);
    }
    return(nxt64bits);
}

char *cancel_NXTorderid(char *NXTaddr,char *nxtsecret,uint64_t orderid)
{
    uint64_t nxt64bits; char cmd[1025],secret[8192],*str = "Bid",*retstr = 0;
    if ( (nxt64bits= _get_AEquote(str,orderid)) == 0 )
        str = "Ask", nxt64bits = _get_AEquote(str,orderid);
    if ( nxt64bits == calc_nxt64bits(NXTaddr) )
    {
        escape_code(secret,nxtsecret);
        sprintf(cmd,"requestType=cancel%sOrder&secretPhrase=%s&feeNQT=%lld&deadline=%d&order=%llu",str,secret,(long long)MIN_NQTFEE,DEFAULT_NXT_DEADLINE,(long long)orderid);
        retstr = issue_NXTPOST(cmd);
        //printf("(%s) -> (%s)\n",cmd,retstr);
    }
    return(retstr);
}

char *InstantDEX_cancelorder(cJSON *argjson,char *activenxt,char *secret,uint64_t orderid,uint64_t quoteid)
{
    struct InstantDEX_quote *iQ; cJSON *json,*array,*item; char numstr[64],*retstr,*exchangestr;
    uint64_t quoteids[256]; int32_t i,exchangeid,n=0;  struct exchange_info *exchange;
    if ( (exchangestr= jstr(argjson,"exchange")) != 0 && (exchange= find_exchange(&exchangeid,exchangestr)) != 0 )
    {
        if ( exchange->issue.cancelorder != 0 )
        {
            if ( (retstr= (*exchange->issue.cancelorder)(&exchange->cHandle,exchange,argjson,quoteid)) == 0 )
                retstr = clonestr("{\"result\":\"nothing returned from exchange\"}");
            return(retstr);
        }
        else return(clonestr("{\"error\":\"no cancelorder function\"}"));
    }
    memset(quoteids,0,sizeof(quoteids));
    json = cJSON_CreateObject(), array = cJSON_CreateArray();
    if ( quoteid != 0 )
        quoteids[n++] = quoteid;
    //n += InstantDEX_quoteids(quoteids+n,orderid);
    for (i=0; i<n; i++)
    {
        quoteid = quoteids[i];
        if ( (retstr= cancel_NXTorderid(activenxt,secret,quoteid)) != 0 )
        {
            if ( (iQ= findquoteid(quoteid,0)) != 0 && iQ->s.offerNXT == calc_nxt64bits(activenxt) )
                cancel_InstantDEX_quote(iQ);
            if ( (item= cJSON_Parse(retstr)) != 0 )
                jaddi(array,item);
            free(retstr);
        }
        cancelquote(activenxt,quoteid);
    }
    if ( orderid != 0 )
    {
        if ( cancelquote(activenxt,orderid) != 0 )
            sprintf(numstr,"%llu",(long long)orderid), jaddstr(json,"ordercanceled",numstr);
    }
    return(jprint(json,1));
}

char *InstantDEX_orderstatus(cJSON *argjson,uint64_t orderid,uint64_t quoteid)
{
    struct InstantDEX_quote *iQ = 0; char *exchangestr,*str; struct exchange_info *exchange; int32_t exchangeid;
    if ( (exchangestr= jstr(argjson,"exchange")) != 0 && (exchange= find_exchange(&exchangeid,exchangestr)) != 0 )
    {
        if ( exchange->issue.orderstatus != 0 )
        {
            if ( (str= (*exchange->issue.orderstatus)(&exchange->cHandle,exchange,argjson,quoteid)) == 0 )
                str = clonestr("{\"result\":\"nothing returned from exchange\"}");
            return(str);
        }
        else return(clonestr("{\"error\":\"no orderstatus function\"}"));
    }
    if ( (iQ= find_iQ(orderid)) != 0 || (iQ= find_iQ(quoteid)) != 0 )
        return(InstantDEX_str(0,0,0,iQ));
    return(clonestr("{\"error\":\"couldnt find orderid\"}"));
}

char *InstantDEX_openorders(cJSON *argjson,char *NXTaddr,int32_t allorders)
{
    struct InstantDEX_quote *iQ,*tmp; char buf[4096],*exchangestr,*jsonstr,*str; uint32_t now,duration;
    cJSON *json,*array,*item; uint64_t nxt64bits; struct exchange_info *exchange; int32_t exchangeid;
    if ( (exchangestr= jstr(argjson,"exchange")) != 0 && (exchange= find_exchange(&exchangeid,exchangestr)) != 0 )
    {
        if ( exchange->issue.openorders != 0 )
        {
            if ( (str= (*exchange->issue.openorders)(&exchange->cHandle,exchange,argjson)) == 0 )
                str = clonestr("{\"result\":\"nothing returned from exchange\"}");
            return(str);
        }
        else return(clonestr("{\"error\":\"no orderstatus function\"}"));
    }
    nxt64bits = calc_nxt64bits(NXTaddr);
    now = (uint32_t)time(NULL);
    json = cJSON_CreateObject(), array = cJSON_CreateArray();
    HASH_ITER(hh,AllQuotes,iQ,tmp)
    {
        if ( (duration= iQ->s.duration) == 0 )
            duration = ORDERBOOK_EXPIRATION;
        if ( iQ->s.timestamp > (now + duration) )
            iQ->s.expired = iQ->s.closed = 1;
        if ( iQ->s.offerNXT == nxt64bits && (allorders != 0 || iQ->s.closed == 0) )
        {
            if ( (jsonstr= InstantDEX_str(0,buf,0,iQ)) != 0 && (item= cJSON_Parse(jsonstr)) != 0 )
                jaddi(array,item);
        }
    }
    jadd(json,"openorders",array);
    return(jprint(json,1));
}

cJSON *InstantDEX_specialorders(uint64_t *quoteidp,uint64_t nxt64bits,char *base,char *special,uint64_t baseamount,int32_t addrtype)
{
    struct InstantDEX_quote *iQ,*tmp; int32_t exchangeid; uint32_t i,n,now,duration,ismine = 0;
    uint64_t basebits; cJSON *item=0,*array = 0; char *coinaddr=0,*pubkey,checkaddr[128];
    now = (uint32_t)time(NULL);
    basebits = stringbits(base);
    if ( special == 0 || find_exchange(&exchangeid,special) == 0 )
        exchangeid = 0;
    n = 0;
    *quoteidp = 0;
    HASH_ITER(hh,AllQuotes,iQ,tmp)
    {
        //printf("iter Q.%llu b.%llu\n",(long long)iQ->s.quoteid,(long long)iQ->s.basebits);
        if ( (duration= iQ->s.duration) == 0 )
            duration = ORDERBOOK_EXPIRATION;
        if ( iQ->s.timestamp > (now + duration) )
        {
            iQ->s.expired = iQ->s.closed = 1;
            printf("expire order %llu\n",(long long)iQ->s.quoteid);
            continue;
        }
        if ( iQ->s.basebits == basebits && (exchangeid == 0 || iQ->exchangeid == exchangeid) )
        {
            //printf("matched basebits\n");
            if ( strcmp(special,"pangea") == 0 )
            {
                checkaddr[0] = 0;
                if ( iQ->s.wallet != 0 && (item= cJSON_Parse(iQ->walletstr)) != 0 && (coinaddr= jstr(item,"coinaddr")) != 0 && coinaddr[0] != 0 && (pubkey= jstr(item,"pubkey")) != 0 && pubkey[0] != 0 )
                    btc_coinaddr(coinaddr,addrtype,pubkey);
                if ( item != 0 )
                    free_json(item);
                if ( coinaddr == 0 || strcmp(coinaddr,checkaddr) != 0 )
                {
                    printf("mismatched pangea coinaddr (%s) vs (%s) or baseamount %.8f vs %.8f\n",coinaddr,checkaddr,dstr(baseamount),dstr(iQ->s.baseamount));
                    continue;
                }
            }
            if ( n > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( iQ->s.offerNXT == j64bits(jitem(array,i),0) )
                        break;
                }
                //printf("found duplicate\n");
            } else i = 0;
            if ( i == n )
            {
                if ( iQ->s.offerNXT == nxt64bits )
                {
                    ismine = 1;
                    if ( *quoteidp == 0 )
                        *quoteidp = iQ->s.quoteid;
                }
                if ( array == 0 )
                    array = cJSON_CreateArray();
                jaddi64bits(array,iQ->s.offerNXT);
                //printf("add %llu\n",(long long)iQ->s.offerNXT);
            }
        } //else printf("quote.%llu basebits.%llu\n",(long long)iQ->s.quoteid,(long long)iQ->s.basebits);
    }
    if ( ismine == 0 )
        free_json(array), array = 0;
    //printf("ismine.%d n.%d array.%d\n",ismine,n,array==0?0:cJSON_GetArraySize(array));
    return(array);
}

int _decreasing_quotes(const void *a,const void *b)
{
#define order_a ((struct InstantDEX_quote *)a)
#define order_b ((struct InstantDEX_quote *)b)
 	if ( order_b->s.price > order_a->s.price )
		return(1);
	else if ( order_b->s.price < order_a->s.price )
		return(-1);
	return(0);
#undef order_a
#undef order_b
}

int _increasing_quotes(const void *a,const void *b)
{
#define order_a ((struct InstantDEX_quote *)a)
#define order_b ((struct InstantDEX_quote *)b)
 	if ( order_b->s.price > order_a->s.price )
		return(-1);
	else if ( order_b->s.price < order_a->s.price )
		return(1);
	return(0);
#undef order_a
#undef order_b
}

cJSON *prices777_orderjson(struct InstantDEX_quote *iQ)
{
    cJSON *item = cJSON_CreateArray();
    jaddinum(item,iQ->s.price);
    jaddinum(item,iQ->s.vol);
    jaddi64bits(item,iQ->s.quoteid);
    return(item);
}

cJSON *InstantDEX_orderbook(struct prices777 *prices)
{
    struct InstantDEX_quote *ptr,iQ,*tmp,*askvals=0,*bidvals=0; cJSON *json,*bids,*asks; uint32_t now,duration;
    int32_t i,isask,iter,n,m,numbids,numasks,invert;
    json = cJSON_CreateObject(), bids = cJSON_CreateArray(), asks = cJSON_CreateArray();
    now = (uint32_t)time(NULL);
    for (iter=numbids=numasks=n=m=0; iter<2; iter++)
    {
        HASH_ITER(hh,AllQuotes,ptr,tmp)
        {
            iQ = *ptr;
            if ( (duration= iQ.s.duration) == 0 )
                duration = ORDERBOOK_EXPIRATION;
            if ( iQ.s.timestamp > (now + duration) )
            {
                iQ.s.expired = iQ.s.closed = 1;
                continue;
            }
            if ( Debuglevel > 2 )
                printf("iterate quote.%llu\n",(long long)iQ.s.quoteid);
            if ( prices777_equiv(ptr->s.baseid) == prices777_equiv(prices->baseid) && prices777_equiv(ptr->s.relid) == prices777_equiv(prices->relid) )
                invert = 0;
            else if ( prices777_equiv(ptr->s.relid) == prices777_equiv(prices->baseid) && prices777_equiv(ptr->s.baseid) == prices777_equiv(prices->relid) )
                invert = 1;
            else continue;
            if ( ptr->s.pending != 0 )
                continue;
            isask = iQ.s.isask;
            if ( invert != 0 )
                isask ^= 1;
            if ( invert != 0 )
            {
                if ( iQ.s.price > SMALLVAL )
                    iQ.s.vol *= iQ.s.price, iQ.s.price = 1. / iQ.s.price;
                else iQ.s.price = prices777_price_volume(&iQ.s.vol,iQ.s.relamount,iQ.s.baseamount);
            }
            else if ( iQ.s.price <= SMALLVAL )
                iQ.s.price = prices777_price_volume(&iQ.s.vol,iQ.s.baseamount,iQ.s.relamount);
            if ( iter == 0 )
            {
                if ( isask != 0 )
                    numasks++;
                else numbids++;
            }
            else
            {
                if ( isask == 0 && n < numbids )
                    bidvals[n++] = iQ;
                else if ( isask != 0 && m < numasks )
                    askvals[m++] = iQ;
            }
        }
        if ( iter == 0 )
        {
            if ( numbids > 0 )
                bidvals = calloc(numbids,sizeof(*bidvals));
            if ( numasks > 0 )
                askvals = calloc(numasks,sizeof(*askvals));
        }
    }
    if ( numbids > 0 )
    {
        if ( n > 0 )
        {
            qsort(bidvals,n,sizeof(*bidvals),_decreasing_quotes);
            for (i=0; i<n; i++)
                jaddi(bids,prices777_orderjson(&bidvals[i]));
        }
        free(bidvals);
    }
    if ( numasks > 0 )
    {
        if ( m > 0 )
        {
            qsort(askvals,m,sizeof(*askvals),_increasing_quotes);
            for (i=0; i<m; i++)
                jaddi(asks,prices777_orderjson(&askvals[i]));
        }
        free(askvals);
    }
    jadd(json,"bids",bids), jadd(json,"asks",asks);
    return(json);
}

double ordermetric(double price,double vol,int32_t dir,double refprice,double refvol)
{
    double metric = 0.;
    if ( vol > (refvol * INSTANTDEX_MINVOLPERC) )//&& refvol > (vol * iQ->s.minperc * .01) )
    {
        if ( vol < refvol )
            metric = (vol / refvol);
        else metric = 1.;
        if ( dir > 0 && price < (refprice * (1. + INSTANTDEX_PRICESLIPPAGE) + SMALLVAL) )
            metric *= (1. + (refprice - price)/refprice);
        else if ( dir < 0 && price > (refprice * (1. - INSTANTDEX_PRICESLIPPAGE) - SMALLVAL) )
            metric *= (1. + (price - refprice)/refprice);
        else metric = 0.;
        if ( metric != 0. )
        {
            printf("price %.8f vol %.8f | %.8f > %.8f? %.8f > %.8f?\n",price,vol,vol,(refvol * INSTANTDEX_MINVOLPERC),refvol,(vol * INSTANTDEX_MINVOLPERC));
            printf("price %f against %f or %f\n",price,(refprice * (1. + INSTANTDEX_PRICESLIPPAGE) + SMALLVAL),(refprice * (1. - INSTANTDEX_PRICESLIPPAGE) - SMALLVAL));
            printf("metric %f\n",metric);
        }
    }
    return(metric);
}

char *autofill(char *remoteaddr,struct InstantDEX_quote *refiQ,char *NXTaddr,char *NXTACCTSECRET)
{
    double price,volume,revprice,revvol,metric,bestmetric = 0.; int32_t dir,inverted; uint64_t nxt64bits; char *retstr=0;
    struct InstantDEX_quote *iQ,*tmp,*bestiQ; struct prices777 *prices; uint32_t duration,now = (uint32_t)time(NULL);
return(0);
    nxt64bits = calc_nxt64bits(NXTaddr);
    memset(&bestiQ,0,sizeof(bestiQ));
    dir = (refiQ->s.isask != 0) ? -1 : 1;
    HASH_ITER(hh,AllQuotes,iQ,tmp)
    {
        if ( (duration= refiQ->s.duration) == 0 )
            duration = ORDERBOOK_EXPIRATION;
        if ( iQ->s.timestamp > (now + duration) )
            iQ->s.expired = iQ->s.closed = 1;
        if ( iQ->s.offerNXT == nxt64bits && iQ->s.closed == 0 && iQ->s.pending == 0 )
        {
            if ( iQ->s.baseid == refiQ->s.baseid && iQ->s.relid == refiQ->s.relid && iQ->s.isask != refiQ->s.isask && (metric= ordermetric(iQ->s.price,iQ->s.vol,dir,refiQ->s.price,refiQ->s.vol)) > bestmetric )
            {
                bestmetric = metric;
                bestiQ = iQ;
            }
            else if ( iQ->s.baseid == refiQ->s.relid && iQ->s.relid == refiQ->s.baseid && iQ->s.isask == refiQ->s.isask && iQ->s.price > SMALLVAL )
            {
                revvol = (iQ->s.price * iQ->s.vol), revprice = (1. / iQ->s.price);
                if ( (metric= ordermetric(revprice,revvol,dir,refiQ->s.price,refiQ->s.vol)) > bestmetric )
                {
                    bestmetric = metric;
                    bestiQ = iQ;
                }
            }
        }
    }
    if ( bestmetric > 0. )
    {
        if ( (prices= prices777_find(&inverted,bestiQ->s.baseid,bestiQ->s.relid,exchange_str(bestiQ->exchangeid))) != 0 )
        {
            printf("isask.%d %f %f -> bestmetric %f inverted.%d autofill dir.%d price %f vol %f\n",bestiQ->s.isask,bestiQ->s.price,bestiQ->s.vol,bestmetric,inverted,dir,refiQ->s.price,refiQ->s.vol);
            if ( bestiQ->s.isask != 0 )
                dir = -1;
            else dir = 1;
            if ( inverted != 0 )
            {
                dir *= -1;
                volume = (bestiQ->s.price * bestiQ->s.vol);
                price = 1. / bestiQ->s.price;
                printf("price inverted (%f %f) -> (%f %f)\n",bestiQ->s.price,bestiQ->s.vol,price,volume);
            } else price = bestiQ->s.price, volume = bestiQ->s.vol;
            retstr = prices777_trade(0,0,0,0,1,0,NXTaddr,NXTACCTSECRET,prices,dir,price,volume,bestiQ,0,bestiQ->s.quoteid,0);
        }
    }
    return(retstr);
}

char *automatch(struct prices777 *prices,int32_t dir,double refprice,double refvol,char *NXTaddr,char *NXTACCTSECRET)
{
    int32_t i,n=0; struct prices777_order order,bestorder; char *retstr = 0; double metric,bestmetric = 0.;
return(0);
    memset(&bestorder,0,sizeof(bestorder));
    if ( dir > 0 )
        n = prices->O.numasks;
    else if ( dir < 0 )
        n = prices->O.numbids;
    if ( n > 0 )
    {
        for (i=0; i<n; i++)
        {
            order = (dir > 0) ? prices->O.book[MAX_GROUPS][i].ask : prices->O.book[MAX_GROUPS][i].bid;
            if ( (metric= ordermetric(order.s.price,order.s.vol,dir,refprice,refvol)) > bestmetric )
            {
                bestmetric = metric;
                bestorder = order;
            }
        }
    }
    //printf("n.%d\n",n);
    if ( bestorder.source != 0 )
        retstr = prices777_trade(0,0,0,0,1,0,NXTaddr,NXTACCTSECRET,bestorder.source,bestorder.s.isask!=0?-1:1,bestorder.s.price,bestorder.s.vol,0,&bestorder,bestorder.s.quoteid,0);
    return(retstr);
}

int offer_checkitem(struct pending_trade *pend,cJSON *item)
{
    uint64_t quoteid; struct InstantDEX_quote *iQ;
    if ( (quoteid= j64bits(item,"quoteid")) != 0 && (iQ= find_iQ(quoteid)) != 0 && iQ->s.closed != 0 )
        return(0);
    return(-1);
}

void trades_update()
{
#ifdef later
    int32_t iter; struct pending_trade *pend;
    for (iter=0; iter<2; iter++)
    {
        while ( (pend= queue_dequeue(&Pending_offersQ.pingpong[iter],0)) != 0 )
        {
            if ( time(NULL) > pend->expiration )
            {
                printf("now.%ld vs timestamp.%u vs expiration %u | ",(long)time(NULL),pend->timestamp,pend->expiration);
                printf("offer_statemachine %llu/%llu %d %f %f\n",(long long)pend->orderid,(long long)pend->quoteid,pend->dir,pend->price,pend->volume);
                //InstantDEX_history(1,pend,retstr);
                if ( pend->bot == 0 )
                    free_pending(pend);
                else pend->finishtime = (uint32_t)time(NULL);
            }
            else
            {
                printf("InstantDEX_update requeue %llu/%llu %d %f %f\n",(long long)pend->orderid,(long long)pend->quoteid,pend->dir,pend->price,pend->volume);
                queue_enqueue("requeue",&Pending_offersQ.pingpong[iter ^ 1],&pend->DL,0);
            }
        }
    }
#endif
}

void InstantDEX_update(char *NXTaddr,char *NXTACCTSECRET)
{
    int32_t dir; double price,volume; uint32_t now; char *retstr = 0;
    int32_t inverted; struct InstantDEX_quote *iQ,*tmp; struct prices777 *prices; uint64_t nxt64bits = calc_nxt64bits(NXTaddr);
    now = (uint32_t)time(NULL);
    HASH_ITER(hh,AllQuotes,iQ,tmp)
    {
        if ( iQ->s.timestamp > (now + ORDERBOOK_EXPIRATION) )
            iQ->s.expired = iQ->s.closed = 1;
        if ( iQ->s.offerNXT == nxt64bits && iQ->s.closed == 0 && iQ->s.pending == 0 )
        {
            if ( (prices= prices777_find(&inverted,iQ->s.baseid,iQ->s.relid,exchange_str(iQ->exchangeid))) != 0 )
            {
                if ( iQ->s.isask != 0 )
                    dir = -1;
                else dir = 1;
                if ( inverted != 0 )
                {
                    dir *= -1;
                    volume = (iQ->s.price * iQ->s.vol);
                    price = 1. / iQ->s.price;
                    printf("price inverted (%f %f) -> (%f %f)\n",iQ->s.price,iQ->s.vol,price,volume);
                } else price = iQ->s.price, volume = iQ->s.vol;
                if ( (retstr= automatch(prices,dir,price,volume,NXTaddr,NXTACCTSECRET)) != 0 )
                {
                    printf("automatched %s isask.%d %f %f (%s)\n",prices->contract,iQ->s.isask,iQ->s.price,iQ->s.vol,retstr);
                    free(retstr);
                }
            }
        }
    }
    trades_update();
}

int32_t is_specialexchange(char *exchangestr)
{
    if ( strcmp(exchangestr,"InstantDEX") == 0 || strcmp(exchangestr,"jumblr") == 0 || strcmp(exchangestr,"pangea") == 0 || strcmp(exchangestr,"peggy") == 0 || strcmp(exchangestr,"wallet") == 0 || strcmp(exchangestr,"active") == 0 || strncmp(exchangestr,"basket",strlen("basket")) == 0 )
        return(1);
    return(0);
}

char *InstantDEX_placebidask(char *remoteaddr,uint64_t orderid,char *exchangestr,char *name,char *base,char *rel,struct InstantDEX_quote *iQ,char *extra,char *secret,char *activenxt,cJSON *origjson)
{
    struct exchange_info *exchange; cJSON *obj;
    char walletstr[256],*str,*retstr = 0; int32_t inverted,dir; struct prices777 *prices; double price,volume;
    if ( secret == 0 || activenxt == 0 )
    {
        secret = IGUANA_NXTACCTSECRET;
        activenxt = IGUANA_NXTADDR;
    }
//printf("placebidask.(%s)\n",jprint(origjson,0));
    if ( (obj= jobj(origjson,"wallet")) != 0 )
    {
        str = jprint(obj,1);
        safecopy(walletstr,str,sizeof(walletstr));
        free(str), str = 0;
    }
    else walletstr[0] = 0;
    if ( exchangestr != 0 && (exchange= exchange_find(exchangestr)) != 0 )
        iQ->exchangeid = exchange->exchangeid;
    if ( iQ->exchangeid < 0 || (exchangestr= exchange_str(iQ->exchangeid)) == 0 )
    {
        printf("exchangestr.%s id.%d\n",exchangestr,iQ->exchangeid);
        return(clonestr("{\"error\":\"exchange not active, check SuperNET.conf exchanges array\"}\n"));
    }
    //printf("walletstr.(%s)\n",walletstr);
    if ( (prices= prices777_find(&inverted,iQ->s.baseid,iQ->s.relid,exchangestr)) == 0 )
        prices = prices777_poll(exchangestr,name,base,iQ->s.baseid,rel,iQ->s.relid);
    if ( prices != 0 )
    {
        price = iQ->s.price, volume = iQ->s.vol;
        if ( price < SMALLVAL || volume < SMALLVAL )
        {
            printf("price %f volume %f error\n",price,volume);
            return(clonestr("{\"error\":\"prices777_trade invalid price or volume\"}\n"));
        }
        if ( iQ->s.isask != 0 )
            dir = -1;
        else dir = 1;
        if ( inverted != 0 )
        {
            dir *= -1;
            volume *= price;
            price = 1. / price;
            printf("price inverted (%f %f) -> (%f %f)\n",iQ->s.price,iQ->s.vol,price,volume);
        }
//printf("dir.%d price %f vol %f isask.%d remoteaddr.%p\n",dir,price,volume,iQ->s.isask,remoteaddr);
        if ( remoteaddr == 0 )
        {
            if ( is_specialexchange(exchangestr) == 0 )
                return(prices777_trade(0,0,0,0,1,0,activenxt,secret,prices,dir,price,volume,iQ,0,iQ->s.quoteid,extra));
            //printf("check automatch\n");
            //if ( strcmp(exchangestr,"wallet") != 0 && strcmp(exchangestr,"jumblr") != 0 && strcmp(exchangestr,"pangea") != 0 && iQ->s.automatch != 0 && (SUPERNET.automatch & 1) != 0 && (retstr= automatch(prices,dir,volume,price,activenxt,secret)) != 0 )
            //    return(retstr);
            if ( strcmp(IGUANA_NXTACCTSECRET,secret) != 0 )
                return(clonestr("{\"error\":\"cant do queued requests with non-default accounts\"}"));
            retstr = InstantDEX_str(walletstr,0,1,iQ);
            //printf("create_iQ.(%llu) quoteid.%llu walletstr.(%s) %p\n",(long long)iQ->s.offerNXT,(long long)iQ->s.quoteid,walletstr,walletstr);
            iQ = create_iQ(iQ,walletstr);
            printf("local got create_iQ.(%llu) quoteid.%llu wallet.(%s) baseamount %llu iswallet.%d\n",(long long)iQ->s.offerNXT,(long long)iQ->s.quoteid,walletstr,(long long)iQ->s.baseamount,iQ->s.wallet);
            prices777_InstantDEX(prices,MAX_DEPTH);
            queue_enqueue("InstantDEX",&InstantDEXQ,queueitem(retstr),0);
        }
        else
        {
            iQ = create_iQ(iQ,walletstr);
            if ( (retstr= autofill(remoteaddr,iQ,activenxt,secret)) == 0 )
            {
                //printf("create_iQ.(%llu) quoteid.%llu\n",(long long)iQ->s.offerNXT,(long long)iQ->s.quoteid);
                if ( strcmp(IGUANA_NXTACCTSECRET,secret) != 0 )
                    return(clonestr("{\"error\":\"cant do queued requests with non-default accounts\"}"));
                prices777_InstantDEX(prices,MAX_DEPTH);
                printf("remote got create_iQ.(%llu) quoteid.%llu wallet.(%s) baseamount %llu\n",(long long)iQ->s.offerNXT,(long long)iQ->s.quoteid,walletstr,(long long)iQ->s.baseamount);
            }
            return(retstr);
        }
    } else printf("cant find prices\n");
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"cant get prices ptr\"}");
    return(retstr);
}


#endif
#endif
