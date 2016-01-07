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

#ifndef xcode_trades_h
#define xcode_trades_h

struct tradehistory { uint64_t assetid,purchased,sold; };

struct tradehistory *_update_tradehistory(struct tradehistory *hist,uint64_t assetid,uint64_t purchased,uint64_t sold)
{
    int32_t i = 0;
    if ( hist == 0 )
        hist = calloc(1,sizeof(*hist));
    if ( hist[i].assetid != 0 )
    {
        for (i=0; hist[i].assetid!=0; i++)
            if ( hist[i].assetid == assetid )
                break;
    }
    if ( hist[i].assetid == 0 )
    {
        hist = realloc(hist,(i+2) * sizeof(*hist));
        memset(&hist[i],0,2 * sizeof(hist[i]));
        hist[i].assetid = assetid;
    }
    if ( hist[i].assetid == assetid )
    {
        hist[i].purchased += purchased;
        hist[i].sold += sold;
        printf("hist[%d] %llu +%llu -%llu -> (%llu %llu)\n",i,(long long)hist[i].assetid,(long long)purchased,(long long)sold,(long long)hist[i].purchased,(long long)hist[i].sold);
    } else printf("_update_tradehistory: impossible case!\n");
    return(hist);
}

struct tradehistory *update_tradehistory(struct tradehistory *hist,uint64_t srcasset,uint64_t srcamount,uint64_t destasset,uint64_t destamount)
{
    hist = _update_tradehistory(hist,srcasset,0,srcamount);
    hist = _update_tradehistory(hist,destasset,destamount,0);
    return(hist);
}

cJSON *_tradehistory_json(struct tradehistory *asset)
{
    cJSON *json = cJSON_CreateObject();
    char numstr[64];
    sprintf(numstr,"%llu",(long long)asset->assetid), cJSON_AddItemToObject(json,"assetid",cJSON_CreateString(numstr));
    sprintf(numstr,"%.8f",dstr(asset->purchased)), cJSON_AddItemToObject(json,"purchased",cJSON_CreateString(numstr));
    sprintf(numstr,"%.8f",dstr(asset->sold)), cJSON_AddItemToObject(json,"sold",cJSON_CreateString(numstr));
    sprintf(numstr,"%.8f",dstr(asset->purchased) - dstr(asset->sold)), cJSON_AddItemToObject(json,"net",cJSON_CreateString(numstr));
    return(json);
}

cJSON *tradehistory_json(struct tradehistory *hist,cJSON *array)
{
    int32_t i; char assetname[64],numstr[64]; cJSON *assets,*netpos,*item,*json = cJSON_CreateObject();
    cJSON_AddItemToObject(json,"rawtrades",array);
    assets = cJSON_CreateArray();
    netpos = cJSON_CreateArray();
    for (i=0; hist[i].assetid!=0; i++)
    {
        cJSON_AddItemToArray(assets,_tradehistory_json(&hist[i]));
        item = cJSON_CreateObject();
        get_assetname(assetname,hist[i].assetid);
        cJSON_AddItemToObject(item,"asset",cJSON_CreateString(assetname));
        sprintf(numstr,"%.8f",dstr(hist[i].purchased) - dstr(hist[i].sold)), cJSON_AddItemToObject(item,"net",cJSON_CreateString(numstr));
        cJSON_AddItemToArray(netpos,item);
    }
    cJSON_AddItemToObject(json,"assets",assets);
    cJSON_AddItemToObject(json,"netpositions",netpos);
    return(json);
}

cJSON *tabulate_trade_history(uint64_t mynxt64bits,cJSON *array)
{
    int32_t i,n;
    cJSON *item;
    long balancing;
    struct tradehistory *hist = 0;
    uint64_t src64bits,srcamount,srcasset,dest64bits,destamount,destasset,jump64bits,jumpamount,jumpasset;
    //{"requestType":"processjumptrade","NXT":"5277534112615305538","assetA":"5527630","amountA":"6700000000","other":"1510821971811852351","assetB":"12982485703607823902","amountB":"100000000","feeA":"250000000","balancing":0,"feeAtxid":"1234468909119892020","triggerhash":"34ea5aaeeeb62111a825a94c366b4ae3d12bb73f9a3413a27d1b480f6029a73c"}
    if ( array != 0 && is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = cJSON_GetArrayItem(array,i);
            src64bits = get_API_nxt64bits(cJSON_GetObjectItem(item,"NXT"));
            srcamount = get_API_nxt64bits(cJSON_GetObjectItem(item,"amountA"));
            srcasset = get_API_nxt64bits(cJSON_GetObjectItem(item,"assetA"));
            dest64bits = get_API_nxt64bits(cJSON_GetObjectItem(item,"other"));
            destamount = get_API_nxt64bits(cJSON_GetObjectItem(item,"amountB"));
            destasset = get_API_nxt64bits(cJSON_GetObjectItem(item,"assetB"));
            jump64bits = get_API_nxt64bits(cJSON_GetObjectItem(item,"jumper"));
            jumpamount = get_API_nxt64bits(cJSON_GetObjectItem(item,"jumpasset"));
            jumpasset = get_API_nxt64bits(cJSON_GetObjectItem(item,"jumpamount"));
            balancing = (long)get_API_nxt64bits(cJSON_GetObjectItem(item,"balancing"));
            if ( src64bits != 0 && srcamount != 0 && srcasset != 0 && dest64bits != 0 && destamount != 0 && destasset != 0 )
            {
                if ( src64bits == mynxt64bits )
                    hist = update_tradehistory(hist,srcasset,srcamount,destasset,destamount);
                else if ( dest64bits == mynxt64bits )
                    hist = update_tradehistory(hist,destasset,destamount,srcasset,srcamount);
                else if ( jump64bits == mynxt64bits )
                    continue;
                else printf("illegal tabulate_trade_entry %llu: (%llu -> %llu) via %llu\n",(long long)mynxt64bits,(long long)src64bits,(long long)dest64bits,(long long)jump64bits);
            } else printf("illegal tabulate_trade_entry %llu: %llu %llu %llu || %llu %llu %llu\n",(long long)mynxt64bits,(long long)src64bits,(long long)srcamount,(long long)srcasset,(long long)dest64bits,(long long)destamount,(long long)destasset);
        }
    }
    if ( hist != 0 )
    {
        array = tradehistory_json(hist,array);
        free(hist);
    }
    return(array);
}

cJSON *get_tradehistory(char *refNXTaddr,uint32_t timestamp)
{
    char cmdstr[1024],NXTaddr[64],*jsonstr; struct destbuf receiverstr,message,newtriggerhash,triggerhash;
    cJSON *json,*array,*txobj,*msgobj,*attachment,*retjson = 0,*histarray = 0; int32_t i,j,n,m,duplicates = 0; uint64_t senderbits;
    if ( timestamp == 0 )
        timestamp = 38785003;
    sprintf(cmdstr,"requestType=getBlockchainTransactions&account=%s&timestamp=%u&withMessage=true",refNXTaddr,timestamp);
    if ( (jsonstr= issue_NXTPOST(cmdstr)) != 0 )
    {
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (array= cJSON_GetObjectItem(json,"transactions")) != 0 && is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    txobj = cJSON_GetArrayItem(array,i);
                    copy_cJSON(&receiverstr,cJSON_GetObjectItem(txobj,"recipient"));
                    if ( (senderbits = get_API_nxt64bits(cJSON_GetObjectItem(txobj,"sender"))) != 0 )
                    {
                        expand_nxt64bits(NXTaddr,senderbits);
                        if ( refNXTaddr != 0 && strcmp(NXTaddr,refNXTaddr) == 0 )
                        {
                            if ( (attachment= cJSON_GetObjectItem(txobj,"attachment")) != 0 && (msgobj= cJSON_GetObjectItem(attachment,"message")) != 0 )
                            {
                                copy_cJSON(&message,msgobj);
                                //printf("(%s) -> ",message);
                                unstringify(message.buf);
                                if ( (msgobj= cJSON_Parse(message.buf)) != 0 )
                                {
                                    //printf("(%s)\n",message);
                                    if ( histarray == 0 )
                                        histarray = cJSON_CreateArray(), j = m = 0;
                                    else
                                    {
                                        copy_cJSON(&newtriggerhash,cJSON_GetObjectItem(msgobj,"triggerhash"));
                                        m = cJSON_GetArraySize(histarray);
                                        for (j=0; j<m; j++)
                                        {
                                            copy_cJSON(&triggerhash,cJSON_GetObjectItem(cJSON_GetArrayItem(histarray,j),"triggerhash"));
                                            if ( strcmp(triggerhash.buf,newtriggerhash.buf) == 0 )
                                            {
                                                duplicates++;
                                                break;
                                            }
                                        }
                                    }
                                    if ( j == m )
                                        cJSON_AddItemToArray(histarray,msgobj);
                                } else printf("parse error on.(%s)\n",message.buf);
                            }
                        }
                    }
                }
            }
            free_json(json);
        }
        free(jsonstr);
    }
    if ( histarray != 0 )
        retjson = tabulate_trade_history(calc_nxt64bits(refNXTaddr),histarray);
    printf("duplicates.%d\n",duplicates);
    return(retjson);
}

void free_pending(struct pending_trade *pend)
{
    struct InstantDEX_quote *iQ;
    if ( (iQ= find_iQ(pend->quoteid)) != 0 )
    {
        iQ->s.closed = 1;
        delete_iQ(pend->quoteid);
    }
    else printf("free_pending: cant find pending tx for %llu\n",(long long)pend->quoteid);
    if ( pend->triggertx != 0 )
        free(pend->triggertx);
    if ( pend->txbytes != 0 )
        free(pend->txbytes);
    if ( pend->tradesjson != 0 )
        free_json(pend->tradesjson);
    free(pend);
}

/*void oldInstantDEX_history(int32_t action,struct pending_trade *pend,char *str)
{
    uint8_t txbuf[32768]; char *tmpstr; uint16_t n; long len = 0;
    // struct pending_trade { struct queueitem DL; struct prices777_order order; uint64_t triggertxid,txid,quoteid,orderid; struct prices777 *prices; char *triggertx,*txbytes; cJSON *tradesjson; double price,volume; uint32_t timestamp; int32_t dir,type; };
    memcpy(&txbuf[len],&action,sizeof(action)), len += sizeof(action);
    if ( action == 0 )
    {
        memcpy(&txbuf[len],pend,sizeof(*pend)), len += sizeof(*pend);
        if ( pend->triggertx != 0 )
        {
            n = (uint16_t)strlen(pend->triggertx) + 1;
            memcpy(&txbuf[len],&n,sizeof(n)), len += sizeof(n);
            memcpy(&txbuf[len],pend->triggertx,n), len += n;
        }
        if ( pend->txbytes != 0 )
        {
            n = (uint16_t)strlen(pend->txbytes) + 1;
            memcpy(&txbuf[len],&n,sizeof(n)), len += sizeof(n);
            memcpy(&txbuf[len],pend->txbytes,n), len += n;
        }
        if ( pend->tradesjson != 0 )
        {
            tmpstr = jprint(pend->tradesjson,0);
            n = (uint16_t)strlen(tmpstr) + 1;
            memcpy(&txbuf[len],&n,sizeof(n)), len += sizeof(n);
            memcpy(&txbuf[len],tmpstr,n), len += n;
            free(tmpstr);
        }
    }
    else
    {
        memcpy(&txbuf[len],&pend->orderid,sizeof(pend->orderid)), len += sizeof(pend->orderid);
        memcpy(&txbuf[len],&pend->quoteid,sizeof(pend->quoteid)), len += sizeof(pend->quoteid);
    }
    if ( str != 0 )
    {
        n = (uint16_t)strlen(str) + 1;
        memcpy(&txbuf[len],&n,sizeof(n)), len += sizeof(n);
        memcpy(&txbuf[len],str,n), len += n;
    }
    else
    {
        n = 0;
        memcpy(&txbuf[len],&n,sizeof(n)), len += sizeof(n);
    }
    txind777_create(INSTANTDEX.history,INSTANTDEX.numhist,pend->timestamp,txbuf,len);
    txinds777_flush(INSTANTDEX.history,INSTANTDEX.numhist,pend->timestamp);
    INSTANTDEX.numhist++;
}*/

char *InstantDEX_loadhistory(struct pending_trade *pend,int32_t *actionp,uint8_t *txbuf,int32_t size)
{
    char *tmpstr,*str = 0; uint16_t n; long len = 0;
    memcpy(actionp,&txbuf[len],sizeof(*actionp)), len += sizeof(*actionp);
    if ( *actionp == 0 )
    {
        memcpy(pend,&txbuf[len],sizeof(*pend)), len += sizeof(*pend);
        //printf("pendsize.%ld trigger.%p tx.%p json.%p\n",(long)sizeof(*pend),pend->triggertx,pend->txbytes,pend->tradesjson);
        if ( pend->triggertx != 0 )
        {
            memcpy(&n,&txbuf[len],sizeof(n)), len += sizeof(n);
            pend->triggertx = calloc(1,n);
            memcpy(pend->triggertx,&txbuf[len],n), len += n;
        }
        if ( pend->txbytes != 0 )
        {
            memcpy(&n,&txbuf[len],sizeof(n)), len += sizeof(n);
            pend->txbytes = calloc(1,n);
            memcpy(pend->txbytes,&txbuf[len],n), len += n;
        }
        if ( pend->tradesjson != 0 )
        {
            memcpy(&n,&txbuf[len],sizeof(n)), len += sizeof(n);
            tmpstr = calloc(1,n);
            memcpy(tmpstr,&txbuf[len],n), len += n;
            if ( (pend->tradesjson= cJSON_Parse(tmpstr)) == 0 )
                printf("cant parse.(%s)\n",tmpstr);
            free(tmpstr);
        }
    }
    else
    {
        memcpy(&pend->orderid,&txbuf[len],sizeof(pend->orderid)), len += sizeof(pend->orderid);
        memcpy(&pend->quoteid,&txbuf[len],sizeof(pend->quoteid)), len += sizeof(pend->quoteid);
    }
    memcpy(&n,&txbuf[len],sizeof(n)), len += sizeof(n);
    if ( n != 0 )
    {
        str = calloc(1,n);
        memcpy(str,&txbuf[len],n), len += n;
    }
    if ( len != size )
        printf("loadhistory warning: len.%ld != size.%d\n",len,size);
    return(str);
}

struct pending_trade *InstantDEX_historyi(int32_t *actionp,char **strp,int32_t i,uint8_t *txbuf,int32_t maxsize)
{
    struct pending_trade *pend = 0;
/*    void *ptr; int32_t size;
    *strp = 0;
    txinds777_seek(INSTANTDEX.history,i);
    if ( (ptr= txinds777_read(&size,txbuf,INSTANTDEX.history)) == 0 || size <= 0 || size > maxsize )
    {
        printf("InstantDEX_inithistory: error reading entry.%d | ptr.%p size.%d\n",i,ptr,maxsize);
        return(0);
    }
    pend = calloc(1,sizeof(*pend));
    *strp = InstantDEX_loadhistory(pend,actionp,ptr,size);*/
    return(pend);
}

int32_t oldInstantDEX_inithistory(int32_t firsti,int32_t endi)
{
    int32_t i,action; uint8_t txbuf[32768]; char *str; struct pending_trade *pend;
    printf("InstantDEX_inithistory firsti.%d endi.%d\n",firsti,endi);
    for (i=firsti; i<endi; i++)
    {
        if ( (pend= InstantDEX_historyi(&action,&str,i,txbuf,sizeof(txbuf))) != 0 )
        {
            printf("type.%d (%c) action.%d orderid.%llu quoteid.%llu (%s)\n",pend->type,pend->type!=0?pend->type:'0',action,(long long)pend->orderid,(long long)pend->quoteid,str!=0?str:"");
            if ( str != 0 )
                free(str);
            free_pending(pend);
        }
    }
    return(i);
}

cJSON *InstantDEX_tradeitem(struct pending_trade *pend)
{
    // struct pending_trade { struct queueitem DL; struct prices777_order order; uint64_t triggertxid,txid,quoteid,orderid; struct prices777 *prices; char *triggertx,*txbytes; cJSON *tradesjson; double price,volume; uint32_t timestamp; int32_t dir,type; };
    struct InstantDEX_quote *iQ; char str[64]; cJSON *json = cJSON_CreateObject();
    str[0] = (pend->type == 0) ? '0' : pend->type;
    str[1] = 0;
    jaddstr(json,"type",str);
    jaddnum(json,"timestamp",pend->timestamp);
    jadd64bits(json,"orderid",pend->orderid), jadd64bits(json,"quoteid",pend->quoteid);
    if ( (iQ= find_iQ(pend->quoteid)) != 0 )
    {
        if ( iQ->s.baseid != 0 && iQ->s.relid != 0 )
            jadd64bits(json,"baseid",iQ->s.baseid), jadd64bits(json,"relid",iQ->s.relid);
        if ( iQ->s.baseamount != 0 && iQ->s.relamount != 0 )
            jaddnum(json,"baseqty",iQ->s.baseamount), jaddnum(json,"relqty",iQ->s.relamount);
    } else printf("tradeitem cant find quoteid.%llu\n",(long long)pend->quoteid);
    if ( pend->dir != 0 )
        jaddnum(json,"dir",pend->dir);
    if ( pend->price > SMALLVAL && pend->volume > SMALLVAL )
        jaddnum(json,"price",pend->price), jaddnum(json,"volume",pend->volume);
    if ( pend->triggertxid != 0 )
        jadd64bits(json,"triggertxid",pend->triggertxid);
    if ( pend->txid != 0 )
        jadd64bits(json,"txid",pend->txid);
    if ( pend->triggertx != 0 )
        jaddstr(json,"triggertx",pend->triggertx);
    if ( pend->txbytes != 0 )
        jaddstr(json,"txbytes",pend->txbytes);
    return(json);
}

char *InstantDEX_withdraw(cJSON *argjson)
{
    char *exchangestr,*str; struct exchange_info *exchange; int32_t exchangeid;
    if ( (exchangestr= jstr(argjson,"exchange")) != 0 && (exchange= find_exchange(&exchangeid,exchangestr)) != 0 )
    {
        if ( exchange->issue.withdraw != 0 )
        {
            if ( (str= (*exchange->issue.withdraw)(&exchange->cHandle,exchange,argjson)) == 0 )
                str = clonestr("{\"result\":\"nothing returned from exchange\"}");
            return(str);
        }
        else return(clonestr("{\"error\":\"no withdraw function\"}"));
    }
    return(clonestr("{\"error\":\"withdraw is not yet\"}"));
}

char *InstantDEX_tradehistory(cJSON *argjson,int32_t firsti,int32_t endi)
{
    /*
    cJSON *json,*array,*item,*tmp; int32_t exchangeid,i,action; uint8_t txbuf[32768];
    char *str,*exchangestr; struct pending_trade *pend; struct exchange_info *exchange;
    if ( (exchangestr= jstr(argjson,"exchange")) != 0 && (exchange= find_exchange(&exchangeid,exchangestr)) != 0 )
    {
        if ( exchange->issue.tradehistory != 0 )
        {
            if ( (str= (*exchange->issue.tradehistory)(&exchange->cHandle,exchange,argjson)) == 0 )
                str = clonestr("{\"result\":\"nothing returned from exchange\"}");
            return(str);
        }
        else return(clonestr("{\"error\":\"no tradehistory function\"}"));
    }
    json = cJSON_CreateObject();
    array = cJSON_CreateArray();
    if ( endi == 0 )
        endi = INSTANTDEX.numhist-1;
    if ( endi < firsti )
        endi = firsti;
    for (i=firsti; i<=endi; i++)
    {
        if ( (pend= InstantDEX_historyi(&action,&str,i,txbuf,sizeof(txbuf))) != 0 )
        {
            item = cJSON_CreateObject();
            jaddnum(item,"i",i);
            jaddnum(item,"action",action);
            jadd(item,"trade",InstantDEX_tradeitem(pend));
            if ( pend->tradesjson != 0 )
                jadd(item,"trades",cJSON_Duplicate(pend->tradesjson,1));
            if ( str != 0 )
            {
                if ( (tmp= cJSON_Parse(str)) != 0 )
                    jadd(item,"str",tmp);
                free(str);
            }
            free_pending(pend);
            jaddi(array,item);
        }
    }
    jadd(json,"tradehistory",array);
    jaddnum(json,"numentries",INSTANTDEX.numhist);
    return(jprint(json,1));*/
    return(0);
}

int32_t substr128(char *dest,char *src)
{
    char zeroes[129],*match; int32_t i;
    for (i=0; i<128; i++)
        zeroes[i] = '0';
    zeroes[i] = 0;
    strcpy(dest,src);
    if ( (match= strstr(dest,zeroes)) != 0 )
    {
        strcpy(match,"Z");
        for (i=0; match[128+i]!=0; i++)
            match[i+1] = match[128+i];
        match[i+1] = 0;
    }
    //printf("substr128.(%s) -> (%s)\n",src,dest);
    return(0);
}

uint64_t gen_NXTtx(struct NXTtx *tx,uint64_t dest64bits,uint64_t assetidbits,uint64_t qty,uint64_t orderid,uint64_t quoteid,int32_t deadline,char *reftx,char *phaselink,uint32_t finishheight,char *phasesecret)
{
    char secret[8192],cmd[16384],destNXTaddr[64],assetidstr[64],hexstr[64],*retstr; uint8_t msgbuf[17]; cJSON *json; int32_t len; uint64_t phasecost = 0;
    if ( deadline > 1000 )
        deadline = 1000;
    expand_nxt64bits(destNXTaddr,dest64bits);
    memset(tx,0,sizeof(*tx));
    if ( ((phasesecret != 0 && phasesecret[0] != 0) || (phaselink!= 0 && phaselink[0] != 0)) && finishheight <= _get_NXTheight(0) )
    {
        printf("finish height.%u must be in the future.%u\n",finishheight,_get_NXTheight(0));
        return(0);
    }
    if ( phaselink != 0 || phasesecret != 0 )
        phasecost = MIN_NQTFEE;
    cmd[0] = 0;
    if ( assetidbits == NXT_ASSETID )
        sprintf(cmd,"requestType=sendMoney&amountNQT=%lld",(long long)qty);
    else
    {
        expand_nxt64bits(assetidstr,assetidbits);
        if ( is_mscoin(assetidstr) == 0 )
            sprintf(cmd,"requestType=transferAsset&asset=%s&quantityQNT=%lld",assetidstr,(long long)qty);
        else sprintf(cmd,"requestType=transferCurrency&currency=%s&units=%lld",assetidstr,(long long)qty);
    }
    if ( quoteid != 0 )
    {
        len = 0;
        printf("serialize buffer\n");
        //len = txind777_txbuf(msgbuf,len,orderid,sizeof(orderid));
        //len = txind777_txbuf(msgbuf,len,quoteid,sizeof(quoteid));
        init_hexbytes_noT(hexstr,msgbuf,len);
        sprintf(cmd+strlen(cmd),"&messageIsText=true&message=%s",hexstr);
    }
    if ( cmd[0] != 0 )
    {
        escape_code(secret,IGUANA_NXTACCTSECRET);
        sprintf(cmd+strlen(cmd),"&deadline=%u&feeNQT=%lld&secretPhrase=%s&recipient=%s&broadcast=false",deadline,(long long)MIN_NQTFEE+phasecost,secret,destNXTaddr);
        if ( reftx != 0 && reftx[0] != 0 )
            sprintf(cmd+strlen(cmd),"&referencedTransactionFullHash=%s",reftx);
        if ( phaselink != 0 && phaselink[0] != 0 )
            sprintf(cmd+strlen(cmd),"&phased=true&phasingFinishHeight=%u&phasingVotingModel=4&phasingQuorum=1&phasingLinkedFullHash=%s",finishheight,phaselink);
        else if ( phasesecret != 0 && phasesecret[0] != 0 )
            sprintf(cmd+strlen(cmd),"&phased=true&phasingFinishHeight=%u&phasingVotingModel=5&phasingHashedSecretAlgorithm=62&phasingQuorum=1&phasingHashedSecret=%s",finishheight,phasesecret);
//printf("generated cmd.(%s)\n",cmd);
        if ( (retstr= issue_NXTPOST(cmd)) != 0 )
        {
//printf("(%s)\n",retstr);
            if ( (json= cJSON_Parse(retstr)) != 0 )
            {
                if ( extract_cJSON_str(tx->txbytes,MAX_JSON_FIELD,json,"transactionBytes") > 0 &&
                    extract_cJSON_str(tx->utxbytes,MAX_JSON_FIELD,json,"unsignedTransactionBytes") > 0 &&
                    extract_cJSON_str(tx->fullhash,MAX_JSON_FIELD,json,"fullHash") > 0 &&
                    extract_cJSON_str(tx->sighash,MAX_JSON_FIELD,json,"signatureHash") > 0 )
                {
                    tx->txid = j64bits(json,"transaction");
                    substr128(tx->utxbytes2,tx->utxbytes);
                }
                free_json(json);
            }
            free(retstr);
        }
    }
    return(tx->txid);
}

struct NXTtx *fee_triggerhash(char *triggerhash,uint64_t orderid,uint64_t quoteid,int32_t deadline)
{
    static struct NXTtx fee;
    if ( fee.fullhash[0] == 0 )
        gen_NXTtx(&fee,calc_nxt64bits(INSTANTDEX_ACCT),NXT_ASSETID,INSTANTDEX_FEE,orderid,quoteid,deadline,0,0,0,0);
    strcpy(triggerhash,fee.fullhash);
    return(&fee);
}

uint64_t InstantDEX_swapstr(char *sendphased,char *phasesecret,uint64_t *txidp,char *triggertx,char *txbytes,char *swapstr,uint64_t orderid,struct prices777_order *order,char *triggerhash,char *phaselink,int32_t finishheight)
{
    struct NXTtx fee,sendtx; uint64_t otherqty = 0,otherassetbits = 0,assetidbits = 0,qty = 0; int32_t deadline = INSTANTDEX_TRIGGERDEADLINE;
    if ( finishheight != 0 )
    {
        if ( finishheight > FINISH_HEIGHT )
            deadline *= (finishheight / FINISH_HEIGHT);
        finishheight += _get_NXTheight(0);
    }
    swapstr[0] = triggertx[0] = txbytes[0] = 0;
    *txidp = 0;
    gen_NXTtx(&fee,calc_nxt64bits(INSTANTDEX_ACCT),NXT_ASSETID,INSTANTDEX_FEE,orderid,order->s.quoteid,deadline,triggerhash,0,0,0);
    strcpy(triggertx,fee.txbytes);
    if ( order->s.baseamount < 0 )
        assetidbits = order->s.baseid, qty = -order->s.baseamount, otherassetbits = order->s.relid, otherqty = order->s.relamount;
    else if ( order->s.relamount < 0 )
        assetidbits = order->s.relid, qty = -order->s.relamount, otherassetbits = order->s.baseid, otherqty = order->s.baseamount;
    printf("genNXTtx.(%llu/%llu) finish at %u vs %u lag %u deadline %d assetidbits.%llu sendphased.(%s)\n",(long long)orderid,(long long)order->s.quoteid,finishheight,_get_NXTheight(0),finishheight-_get_NXTheight(0),deadline,(long long)assetidbits,sendphased!=0?sendphased:"");
    if ( sendphased != 0 && assetidbits != 0 && qty != 0 )
    {
        if ( triggerhash == 0 || triggerhash[0] == 0 )
            triggerhash = fee.fullhash;
        gen_NXTtx(&sendtx,order->s.offerNXT,assetidbits,qty,orderid,order->s.quoteid,deadline,triggerhash,phaselink,finishheight,phasesecret);
        *txidp = sendtx.txid;
        strcpy(txbytes,sendtx.txbytes);
        sprintf(swapstr,",\"F\":\"%u\",\"T\":\"%s\",\"FH\":\"%s\",\"U\":\"%s\",\"S\":\"%s\",\"a\":\"%llu\",\"q\":\"%llu\"}",finishheight,fee.fullhash,sendtx.fullhash,sendtx.utxbytes2,sendtx.sighash,(long long)otherassetbits,(long long)otherqty);
    }
    else sprintf(swapstr,",\"F\":\"%u\",\"T\":\"%s\",\"a\":\"%llu\",\"q\":\"%llu\"}",finishheight,fee.fullhash,(long long)otherassetbits,(long long)otherqty);
    return(fee.txid);
}

uint64_t prices777_swapbuf(char *sendphased,char *phasesecret,uint64_t *txidp,char *triggertx,char *txbytes,char *swapbuf,char *exchangestr,char *base,char *rel,struct prices777_order *order,uint64_t orderid,int32_t finishoffset,char *triggerhash)
{
    char swapstr[4096],*str; uint64_t txid = 0;
    *txidp = 0;
    if ( strcmp(exchangestr,"wallet") == 0 )
        str = "swap";
    else
    {
        str = order->wt > 0. ? "buy" : (order->wt < 0. ? "sell" : "swap");
        //printf("not wallet!\n"); getchar();
    }
    if ( finishoffset == 0 )
        finishoffset = FINISH_HEIGHT;
    sprintf(swapbuf,"{\"orderid\":\"%llu\",\"quoteid\":\"%llu\",\"offerNXT\":\"%llu\",\"fillNXT\":\"%s\",\"plugin\":\"relay\",\"destplugin\":\"InstantDEX\",\"method\":\"busdata\",\"submethod\":\"%s\",\"exchange\":\"%s\",\"base\":\"%s\",\"rel\":\"%s\",\"baseid\":\"%llu\",\"relid\":\"%llu\",\"baseqty\":\"%lld\",\"relqty\":\"%lld\"}",(long long)orderid,(long long)order->s.quoteid,(long long)order->s.offerNXT,IGUANA_NXTADDR,str,exchangestr,base,rel,(long long)order->s.baseid,(long long)order->s.relid,(long long)order->s.baseamount,(long long)order->s.relamount);
    if ( order->s.price > SMALLVAL )
        sprintf(swapbuf + strlen(swapbuf) - 1,",\"price\":%.8f,\"volume\":%.8f}",order->s.price,order->s.vol);
    txid = InstantDEX_swapstr(sendphased,phasesecret,txidp,triggertx,txbytes,swapstr,orderid,order,triggerhash,0,finishoffset);
    strcpy(swapbuf+strlen(swapbuf)-1,swapstr);
    //printf("swapbuf.(%s)\n",swapbuf);
    return(txid);
}

char *prices777_finishswap(int32_t dotrade,int32_t type,struct pending_trade *pend,char *swapbuf,char *triggertx,char *txbytes)
{
    uint32_t nonce; char *str;
    if ( triggertx[0] != 0 )
        pend->triggertx = clonestr(triggertx);
    if ( txbytes[0] != 0 )
        pend->txbytes = clonestr(txbytes);
    pend->order.s.swap = 1;
    pend->tradesjson = cJSON_Parse(swapbuf);
    pend->type = type;
    printf("quoteid.%llu and pending.%d\n",(long long)pend->order.s.quoteid,pend->order.s.pending);
    if ( dotrade != 0 )
    {
        if ( (str= busdata_sync(&nonce,swapbuf,"allnodes",0)) != 0 )
            free(str);
        pend->queueflag = 1;
        queue_enqueue("PendingQ",&Pending_offersQ,&pend->DL,0);
    }
    //InstantDEX_history(0,pend,swapbuf);
    return(clonestr(swapbuf));
}

/*int32_t subatomic_pubkeyhash(char *pubkeystr,char *pkhash,struct coin777 *coin,uint64_t quoteid)
{
    printf("subatomic pubkeyhash not yet\n");
    char tmpswapaddr[128],swapacct[128]; uint8_t tmpbuf[128]; struct destbuf pubkey;
    sprintf(swapacct,"atomic.%llu",(long long)quoteid);
    pkhash[0] = pubkeystr[0] = 0;
    if ( get_acct_coinaddr(tmpswapaddr,coin->name,coin->serverport,coin->userpass,swapacct) != 0 )
    {
        get_pubkey(&pubkey,coin->name,coin->serverport,coin->userpass,tmpswapaddr);
        strcpy(pubkeystr,pubkey.buf);
        calc_OP_HASH160(pkhash,tmpbuf,pubkey.buf);
        return(0);
    }
    return(-1);
}*/

int32_t complete_swap(struct InstantDEX_quote *iQ,uint64_t orderid,uint64_t quoteid,int32_t err)
{
    /*int32_t errcode=-1,errcode2=-2; char *txstr,*txstr2; int32_t iter; struct pending_trade *pend;
    for (iter=0; iter<2; iter++)
    {
        while ( (pend= queue_dequeue(&Pending_offersQ.pingpong[iter],0)) != 0 )
        {
            if ( pend->quoteid == quoteid )
            {
                if ( err == 0 && issue_broadcastTransaction(&errcode2,&txstr2,pend->txbytes,IGUANA_NXTACCTSECRET) == pend->txid && errcode2 == 0 )
                {
                    if ( err == 0 && (issue_broadcastTransaction(&errcode,&txstr,pend->triggertx,IGUANA_NXTACCTSECRET) != pend->triggertxid || errcode != 0) )
                        err = -13;
                }
                if ( err == 0 && errcode == 0 && errcode2 == 0 )
                {
                    iQ->s.matched = 1;
                    //InstantDEX_history(1,pend,0);
                } //else InstantDEX_history(-1,pend,0);
                printf("errs.(%d %d %d) COMPLETED %llu/%llu %d %f %f with txids %llu %llu\n",err,errcode,errcode2,(long long)pend->orderid,(long long)pend->quoteid,pend->dir,pend->price,pend->volume,(long long)pend->triggertxid,(long long)pend->txid);
                pend->queueflag = 1;
                pend->finishtime = (uint32_t)time(NULL);
                return(1);
            }
            queue_enqueue("requeue",&Pending_offersQ.pingpong[iter ^ 1],&pend->DL,0);
        }
    }*/
    printf("complete swap is notyet\n");
    return(-1);
}

char *prices777_tradewallet(struct pending_trade *pend)
{
    printf("tradewallet is not yet\n");
    return(0);
    /*
    struct coin777 *recvcoin,*sendcoin; cJSON *walletitem,*item;
    char fieldA[64],fieldB[64],triggertx[4096],txbytes[4096],fieldpkhash[64],refredeemscript[2048],scriptPubKey[128],p2shaddr[64];
    char swapbuf[8192],buf[1024],*rpubA=0,*rpubB=0,*rpkhash=0,*spubA=0,*spubB=0,*spkhash=0,*recvstr=0;
    char *sendstr=0,*refundtx,*redeemscript,*str; int32_t finishin,deadline; uint32_t nonce;
    uint64_t sendamount,recvamount,sendasset,recvasset; struct destbuf base,rel;
    if ( pend->item != 0 && (item= jitem(pend->item,0)) != 0 && (walletitem= jobj(item,"wallet")) != 0 )
    {
        finishin = (pend->extra[0] == 0) ? 200 : myatoi(pend->extra,10000);
        if ( finishin < FINISH_HEIGHT )
            finishin = FINISH_HEIGHT;
        copy_cJSON(&base,jobj(item,"base"));
        copy_cJSON(&rel,jobj(item,"rel"));
        if ( (recvamount= j64bits(item,"recvbase")) != 0 && (sendamount= j64bits(item,"sendrel")) != 0 )
            recvstr = base.buf, sendstr = rel.buf, recvasset = pend->order.s.baseid, sendasset = pend->order.s.relid;
        else if ( (recvamount= j64bits(item,"recvrel")) != 0 && (sendamount= j64bits(item,"sendbase")) != 0 )
            recvstr = rel.buf, sendstr = base.buf, recvasset = pend->order.s.relid, sendasset = pend->order.s.baseid;
        else
        {
            return(clonestr("{\"error\":\"need recvbase/sendrel or recvrel/sendbase\"}\n"));
        }
        recvcoin = coin777_find(recvstr,1), sendcoin = coin777_find(sendstr,1);
        // placeask -> recvbase/sendrel, placebid -> sendbase/recvrel, it is relative to the one that placed quote
        if ( strcmp(recvstr,"NXT") != 0 ) // placeask COIN/NXT or placebid NXT/COIN
        {
            if ( recvamount < recvcoin->mgw.txfee )
            {
                printf("recvamount %.8f < txfee %.8f\n",dstr(recvamount),dstr(recvcoin->mgw.txfee));
                return(clonestr("{\"error\":\"amount too small\"}\n"));
            }
            sprintf(fieldA,"%spubA",recvstr), rpubA = jstr(walletitem,fieldA);
            sprintf(fieldB,"%spubB",recvstr), rpubB = jstr(walletitem,fieldB);
            sprintf(fieldpkhash,"%spkhash",recvstr), rpkhash = jstr(walletitem,fieldpkhash);
            if ( rpubA[0] != 0 && rpubB != 0 && rpkhash != 0 ) // Alice for recvcoin -> Bob, Bob sends NXT -> Alice
            {
                if ( recvcoin->funding.signedtransaction[0] == 0 && (refundtx= subatomic_fundingtx(refredeemscript,&recvcoin->funding,recvcoin,rpubA,rpubB,rpkhash,recvamount,finishin)) != 0 )
                {
                    deadline = 3600;
                    gen_NXTtx(&recvcoin->trigger,calc_nxt64bits(INSTANTDEX_ACCT),NXT_ASSETID,INSTANTDEX_FEE,pend->orderid,pend->order.s.quoteid,deadline,0,0,0,0);
                    sprintf(swapbuf,"{\"orderid\":\"%llu\",\"quoteid\":\"%llu\",\"offerNXT\":\"%llu\",\"fillNXT\":\"%s\",\"plugin\":\"relay\",\"destplugin\":\"InstantDEX\",\"method\":\"busdata\",\"submethod\":\"swap\",\"exchange\":\"wallet\",\"recvamount\":\"%lld\",\"rtx\":\"%s\",\"rs\":\"%s\",\"recvcoin\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"trigger\":\"%s\",\"sendasset\":\"%llu\",\"sendqty\":\"%llu\",\"base\":\"%s\",\"rel\":\"%s\"}",(long long)pend->orderid,(long long)pend->order.s.quoteid,(long long)pend->order.s.offerNXT,SUPERNET.NXTADDR,(long long)recvamount,refundtx,refredeemscript,recvstr,fieldA,rpubA,fieldB,rpubB,fieldpkhash,rpkhash,recvcoin->trigger.fullhash,(long long)sendasset,(long long)sendamount,pend->prices->base,pend->prices->rel);
                    recvcoin->refundtx = refundtx;
                    pend->order.s.swap = 1;
                    if ( pend->dotrade != 0 && (str= busdata_sync(&nonce,swapbuf,"allnodes",0)) != 0 )
                    {
                        pend->queueflag = 1;
                        queue_enqueue("PendingQ",&Pending_offersQ.pingpong[0],&pend->DL,0);
                    }
                    return(clonestr(swapbuf));
                } else return(clonestr("{\"error\":\"cant create refundtx, maybe already pending\"}\n"));
            }
            else
            {
                sprintf(buf,"{\"error\":\"sendNXT recvstr.(%s) rpubA.(%s) without %s rpubB.%p or %s rpkhash.%p\"}\n",recvstr,rpubA,fieldB,rpubB,fieldpkhash,rpkhash);
                return(clonestr(buf));
            }
        }
        else if ( strcmp(sendstr,"NXT") != 0 )
        {
            if ( sendamount < sendcoin->mgw.txfee )
            {
                printf("sendamount %.8f < txfee %.8f\n",dstr(sendamount),dstr(sendcoin->mgw.txfee));
                return(clonestr("{\"error\":\"amount too small\"}\n"));
            }
            sprintf(fieldA,"%spubA",sendstr), spubA = jstr(walletitem,fieldA);
            sprintf(fieldB,"%spubB",sendstr), spubB = jstr(walletitem,fieldB);
            sprintf(fieldpkhash,"%spkhash",sendstr), spkhash = jstr(walletitem,fieldpkhash);
            if ( spubA != 0 && spubB != 0 && spkhash[0] != 0 ) // Bob <- sendcoin from Alice, send NXT -> Alice
            {
                if ( (redeemscript= create_atomictx_scripts(sendcoin->p2shtype,scriptPubKey,p2shaddr,spubA,spubB,spkhash)) != 0 )
                {
                    pend->triggertxid = prices777_swapbuf("yes",spkhash,&pend->txid,triggertx,txbytes,swapbuf,"wallet",pend->prices->base,pend->prices->rel,&pend->order,pend->orderid,finishin,0);
                    sprintf(swapbuf+strlen(swapbuf)-1,",\"sendcoin\":\"%s\",\"sendamount\":\"%llu\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"recvasset\":\"%llu\",\"recvqty\":\"%llu\"}",sendstr,(long long)sendamount,fieldA,spubA,fieldB,spubB,fieldpkhash,spkhash,(long long)recvasset,(long long)recvamount);
                    free(redeemscript);
                    pend->order.s.swap = 1;
                    if ( pend->dotrade != 0 && (str= busdata_sync(&nonce,swapbuf,"allnodes",0)) != 0 )
                    {
                        free(str);
                        pend->queueflag = 1;
                        queue_enqueue("PendingQ",&Pending_offersQ.pingpong[0],&pend->DL,0);
                    }
                    return(clonestr(swapbuf));
                }
            }
            else
            {
                sprintf(buf,"{\"error\":\"recvNXT sendstr.(%s) spubA.(%s) without %s spubB.(%s) or %s spkhash.(%s)\"}\n",sendstr,spubA,fieldB,spubB,fieldpkhash,spkhash);
                return(clonestr(buf));
            }
        }
        else if ( rpubA[0] != 0 && rpubB != 0 && rpkhash != 0 && spubA != 0 && spubB != 0 && spkhash[0] != 0 && (strcmp(sendstr,"BTC") == 0 || strcmp(recvstr,"BTC") == 0) )
        {
            if ( recvcoin->funding.signedtransaction[0] == 0 && (refundtx= subatomic_fundingtx(refredeemscript,&recvcoin->funding,recvcoin,rpubA,rpubB,rpkhash,recvamount,finishin)) != 0 )
            {
                if ( (redeemscript= create_atomictx_scripts(sendcoin->p2shtype,scriptPubKey,p2shaddr,spubA,spubB,spkhash)) != 0 )
                {
                    pend->triggertxid = prices777_swapbuf(0,0,&pend->txid,triggertx,txbytes,swapbuf,"wallet",pend->prices->base,pend->prices->rel,&pend->order,pend->orderid,finishin,0);
                    sprintf(swapbuf,"{\"orderid\":\"%llu\",\"quoteid\":\"%llu\",\"offerNXT\":\"%llu\",\"fillNXT\":\"%s\",\"plugin\":\"relay\",\"destplugin\":\"InstantDEX\",\"method\":\"busdata\",\"submethod\":\"swap\",\"exchange\":\"wallet\",\"sendcoin\":\"%s\",\"recvcoin\":\"%s\",\"sendamount\":\"%lld\",\"recvamount\":\"%lld\",\"base\":\"%s\",\"rel\":\"%s\"}",(long long)pend->orderid,(long long)pend->order.s.quoteid,(long long)pend->order.s.offerNXT,SUPERNET.NXTADDR,sendstr,recvstr,(long long)sendamount,(long long)recvamount,pend->prices->base,pend->prices->rel);
                    sprintf(swapbuf+strlen(swapbuf)-1,",\"rtx\":\"%s\",\"rs\":\"%s\",\"rpubA\":\"%s\",\"rpubB\":\"%s\",\"rpkhash\":\"%s\",\"pubA\":\"%s\",\"pubB\":\"%s\",\"pkhash\":\"%s\"}",refundtx,refredeemscript,rpubA,rpubB,rpkhash,spubA,spubB,spkhash);
                    free(redeemscript);
                    free(refundtx);
                    pend->order.s.swap = 1;
                    if ( pend->dotrade != 0 && (str= busdata_sync(&nonce,swapbuf,"allnodes",0)) != 0 )
                    {
                        free(str);
                        pend->queueflag = 1;
                        queue_enqueue("PendingQ",&Pending_offersQ.pingpong[0],&pend->DL,0);
                    }
                    return(clonestr(swapbuf));
                }
                free(refundtx);
            }
            else return(clonestr("{\"error\":\"cant create refundtx, maybe already pending\"}\n"));
        }
        else return(clonestr("{\"error\":\"one of wallets must be NXT or BTC\"}\n"));
        printf("wallet swap finishin.%d trigger.%llu swapbuf.(%s)\n",finishin,(long long)pend->triggertxid,swapbuf);
        return(prices777_finishswap(pend->dotrade,'A',pend,swapbuf,triggertx,txbytes));
    }
    else return(clonestr("{\"error\":\"need to have trades[] json item\"}\n"));*/
}

struct pending_trade *prices777_createpending(int32_t *curlingp,void *bot,void **cHandlep,int32_t dotrade,cJSON *item,char *activenxt,char *secret,struct prices777 *prices,int32_t dir,double price,double volume,struct InstantDEX_quote *iQ,struct prices777_order *order,uint64_t orderid,char *extra)
{
    struct InstantDEX_quote _iQ; struct exchange_info *exchange; struct pending_trade *pend;
    char swapbuf[8192],triggertx[4096],txbytes[4096];
    if ( (exchange= find_exchange(0,prices->exchange)) == 0 && exchange->issue.trade != 0 )
    {
        printf("prices777_trade: need to have supported exchange\n");
        return(0);
    }
    if ( cHandlep == 0 )
        cHandlep = &exchange->cHandle;
    if ( iQ == 0 && order == 0 )
    {
        printf("prices777_trade: need to have either iQ or order\n");
        return(0);
    }
    else if ( iQ == 0 && (iQ= find_iQ(order->s.quoteid)) == 0 )
    {
        iQ = &_iQ;
        memset(&_iQ,0,sizeof(_iQ));
        iQ->s = order->s;
        iQ->exchangeid = prices->exchangeid;
        if ( iQ->s.timestamp == 0 )
            iQ->s.timestamp = (uint32_t)time(NULL);
        iQ = create_iQ(iQ,0);
    } else iQ = create_iQ(iQ,0);
    pend = calloc(1,sizeof(*pend));
    pend->bot = bot;
    safecopy((char *)pend->nxtsecret,secret,sizeof(pend->nxtsecret));
    pend->size = (int32_t)sizeof(*pend);
    pend->my64bits = calc_nxt64bits(activenxt);
    triggertx[0] = txbytes[0] = swapbuf[0] = 0;
    pend->prices = prices, pend->dir = dir, pend->price = price, pend->volume = volume, pend->orderid = orderid;
    iQ->s.pending = 1;
    pend->curlingp = curlingp;
    pend->quoteid = iQ->s.quoteid;
    if ( order != 0 )
        pend->order = *order;
    else pend->order.s = iQ->s;
    pend->timestamp = (uint32_t)time(NULL);
    pend->expiration = pend->timestamp + 60;
    pend->cHandlep = cHandlep;
    pend->dotrade = dotrade;
    pend->item = item;
    pend->exchange = exchange;
    safecopy(pend->extra,extra,sizeof(pend->extra));
    return(pend);
}

char *prices777_issuepending(struct pending_trade *pend)
{
    char swapbuf[8192],triggertx[4096],txbytes[4096],*retstr;
    struct prices777 *prices; struct exchange_info *exchange;
    if ( (prices= pend->prices) == 0 || (exchange= pend->exchange) == 0 )
        retstr = clonestr("{\"error\":\"no prices ptr\"}");
    else if ( strcmp(prices->exchange,"wallet") == 0 )
        retstr = prices777_tradewallet(pend);
    else if ( strcmp(prices->exchange,INSTANTDEX_NAME) == 0 )
    {
        pend->expiration = pend->timestamp + INSTANTDEX_TRIGGERDEADLINE*60;
        pend->triggertxid = prices777_swapbuf("yes",0,&pend->txid,triggertx,txbytes,swapbuf,prices->exchange,prices->base,prices->rel,&pend->order,pend->orderid,myatoi(pend->extra,10000),0);
        retstr = prices777_finishswap(pend->dotrade,'T',pend,swapbuf,triggertx,txbytes);
    }
    else if ( strcmp(prices->exchange,"nxtae") == 0 )
    {
        pend->type = 'N';
        retstr = fill_nxtae(pend->dotrade,&pend->txid,pend->my64bits,(char *)pend->nxtsecret,pend->dir,pend->price,pend->volume,prices->baseid,prices->relid);
        if ( pend->dotrade != 0 )
        {
            pend->queueflag = 1;
            queue_enqueue("PendingQ",&Pending_offersQ,&pend->DL,0);
        }
    }
    else
    {
        if ( exchange->issue.trade != 0 )
        {
            printf(" issue dir.%d %s/%s price %f vol %f -> %s\n",pend->dir,prices->base,prices->rel,pend->price,pend->volume,prices->exchange);
            retstr = pend->extra;
            if ( pend->curlingp != 0 )
                *pend->curlingp = 1;
            if ( (pend->txid= (*exchange->issue.trade)(pend->cHandlep,pend->dotrade,&retstr,exchange,prices->base,prices->rel,pend->dir,pend->price,pend->volume)) != 0 )
            {
                pend->queueflag = 1;
                pend->finishtime = (uint32_t)time(NULL);
            }
            else printf("no txid from trade\n");
            if ( pend->curlingp != 0 )
                *pend->curlingp = 0;
            if ( retstr != 0 )
            {
                if ( pend->dotrade != 0 )
                {
                    pend->queueflag = 1;
                    queue_enqueue("PendingQ",&Pending_offersQ,&pend->DL,0);
                }
                printf("returning.%p (%s)\n",retstr,retstr);
            }
        } else retstr = clonestr("{\"error\":\"no trade function for exchange\"}\n");
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"no response\"}");
    return(retstr);
}

char *prices777_trade(int32_t *curlingp,void *bot,struct pending_trade **pendp,void **cHandlep,int32_t dotrade,cJSON *item,char *activenxt,char *secret,struct prices777 *prices,int32_t dir,double price,double volume,struct InstantDEX_quote *iQ,struct prices777_order *order,uint64_t orderid,char *extra)
{
    struct pending_trade *pend; char *retstr;
    if ( pendp != 0 )
        *pendp = 0;
    if ( (pend= prices777_createpending(curlingp,bot,cHandlep,dotrade,item,activenxt,secret,prices,dir,price,volume,iQ,order,orderid,extra)) != 0 )
    {
        if ( bot == 0 || dotrade == 0 )
            retstr = prices777_issuepending(pend);
        else if ( pend->queueflag != 0 )
            retstr = clonestr("{\"result\":\"pending_trade created\"}");
        else retstr = clonestr("{\"error\":\"pending_trade couldnt be created\"}");
        if ( pend->queueflag == 0 )
            free_pending(pend), pend = 0;
        else if ( pendp != 0 )
            *pendp = pend;
        return(retstr);
    }
    else return(clonestr("{\"error\":\"couldnt createpending\"}"));
}

char *issue_calculateFullHash(char *unsignedtxbytes,char *sighash)
{
    char cmd[4096];
    sprintf(cmd,"requestType=calculateFullHash&unsignedTransactionBytes=%s&signatureHash=%s",unsignedtxbytes,sighash);
    return(issue_NXTPOST(cmd));
}

char *issue_parseTransaction(char *txbytes)
{
    char cmd[4096],*retstr = 0;
    sprintf(cmd,"requestType=parseTransaction&transactionBytes=%s",txbytes);
    retstr = issue_NXTPOST(cmd);
    //printf("issue_parseTransaction.%s %s\n",txbytes,retstr);
    if ( retstr != 0 )
    {
        //printf("(%s) -> (%s)\n",cmd,retstr);
        //retstr = parse_NXTresults(0,"sender","",results_processor,jsonstr,strlen(jsonstr));
        //free(jsonstr);
    } else printf("error getting txbytes.%s\n",txbytes);
    return(retstr);
}

uint64_t issue_broadcastTransaction(int32_t *errcodep,char **retstrp,char *txbytes,char *NXTACCTSECRET)
{
    cJSON *json,*errjson;
    uint64_t txid = 0;
    char cmd[4096],secret[8192],*retstr;
    escape_code(secret,NXTACCTSECRET);
    sprintf(cmd,"requestType=broadcastTransaction&secretPhrase=%s&transactionBytes=%s",secret,txbytes);
    retstr = issue_NXTPOST(cmd);
    *errcodep = -1;
    if ( retstrp != 0 )
        *retstrp = retstr;
    if ( retstr != 0 )
    {
        //printf("(%s) -> (%s)\n",cmd,retstr);
        //printf("broadcast got.(%s)\n",retstr);
        if ( (json= cJSON_Parse(retstr)) != 0 )
        {
            errjson = cJSON_GetObjectItem(json,"errorCode");
            if ( errjson != 0 )
            {
                //printf("ERROR broadcasting.(%s)\n",retstr);
                *errcodep = (int32_t)get_cJSON_int(json,"errorCode");
            }
            else
            {
                if ( (txid = get_satoshi_obj(json,"transaction")) != 0 )
                    *errcodep = 0;
            }
        }
        if ( retstrp == 0 )
            free(retstr);
    }
    return(txid);
}

char *issue_signTransaction(char *txbytes,char *NXTACCTSECRET)
{
    char cmd[4096],secret[8192];
    escape_code(secret,NXTACCTSECRET);
    sprintf(cmd,"requestType=signTransaction&secretPhrase=%s&unsignedTransactionBytes=%s",secret,txbytes);
    return(issue_NXTPOST(cmd));
}

char *issue_approveTransaction(char *fullhash,char *revealed,char *message,char *NXTACCTSECRET)
{
    char cmd[4096],secret[8192];
    escape_code(secret,NXTACCTSECRET);
    sprintf(cmd,"requestType=approveTransaction&secretPhrase=%s&transactionFullHash=%s&revealedSecret=%s&messageIsText=true&feeNQT=%lld&deadline=%d&message=%s",secret,fullhash,revealed,(long long)MIN_NQTFEE,DEFAULT_NXT_DEADLINE,message);
    printf("submit approve.(%s)\n",cmd);
    return(issue_NXTPOST(cmd));
}

uint32_t issue_getTime()
{
    char cmd[4096],*jsonstr; cJSON *json; uint32_t timestamp = 0;
    //sprintf(cmd,"requestType=getAsset&asset=%s",assetidstr);
    sprintf(cmd,"requestType=getTime");
    if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
    {
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
            timestamp = juint(json,"time"), free_json(json);
        free(jsonstr);
    }
    return(timestamp);
}

int32_t swap_verifyNXT(uint32_t *finishp,uint32_t *deadlinep,cJSON *origjson,char *offerNXT,char *exchangestr,uint64_t orderid,uint64_t quoteid,struct InstantDEX_quote *iQ,char *phasedtx)
{
    char UTX[32768],*triggerhash,*utx,*sighash,*jsonstr=0,*parsed,*fullhash,*cmpstr; cJSON *json=0,*txobj,*attachment; int32_t retval = -1;
    uint64_t otherbits,otherqty,recvasset; struct destbuf calchash; int64_t recvqty; uint32_t i,j,timestamp,now,finishheight;
    *finishp = 0;
    if ( (triggerhash= jstr(origjson,"T")) == 0 )
        triggerhash = jstr(origjson,"trigger");
    otherbits = j64bits(origjson,"a");
    otherqty = j64bits(origjson,"q");
    fullhash = jstr(origjson,"FH");
    finishheight = juint(origjson,"F");
    if ( phasedtx == 0 )
    {
        utx = jstr(origjson,"U");
        if ( utx != 0 && strlen(utx) > sizeof(UTX) )
        {
            printf("UTX overflow\n");
            return(-1);
        }
        else if ( utx != 0 )
        {
            for (i=0; utx[i]!=0; i++)
                if ( utx[i] == 'Z' )
                {
                    memcpy(UTX,utx,i);
                    for (j=0; j<128; j++)
                        UTX[i+j] = '0';
                    UTX[i+j] = 0;
                    strcat(UTX,utx+i+1);
                    break;
                }
        }
        sighash = jstr(origjson,"S");
        if ( iQ->s.isask == 0 )
            recvasset = iQ->s.baseid, recvqty = iQ->s.baseamount / get_assetmult(recvasset);
        else recvasset = iQ->s.relid, recvqty = iQ->s.relamount / get_assetmult(recvasset);
        printf("utx.(%s) -> UTX.(%s) sighash.(%s)\n",utx,UTX,sighash);
    }
    else
    {
        recvqty = otherqty;
        recvasset = otherbits;
    }
    if ( phasedtx != 0 || (jsonstr= issue_calculateFullHash(UTX,sighash)) != 0 )
    {
        if ( phasedtx != 0 || (json= cJSON_Parse(jsonstr)) != 0 )
        {
            copy_cJSON(&calchash,jobj(json,"fullHash"));
            if ( phasedtx != 0 || strcmp(calchash.buf,fullhash) == 0 )
            {
                if ( (parsed= issue_parseTransaction(phasedtx != 0 ? phasedtx : UTX)) != 0 )
                {
                    _stripwhite(parsed,' ');
                    //printf("iQ (%llu/%llu) otherbits.%llu qty %llu PARSED OFFER.(%s) triggerhash.(%s) (%s) offer sender.%s\n",(long long)iQ->s.baseid,(long long)iQ->s.relid,(long long)otherbits,(long long)otherqty,parsed,fullhash,calchash,sender);
                    if ( (txobj= cJSON_Parse(parsed)) != 0 )
                    {
                        *deadlinep = juint(txobj,"deadline");
                        timestamp = juint(txobj,"timestamp");
                        now = issue_getTime();
                        if ( (attachment= jobj(txobj,"attachment")) != 0 )
                            *finishp = juint(attachment,"phasingFinishHeight");
                        cmpstr = jstr(txobj,"referencedTransactionFullHash");
                        if ( *deadlinep >= INSTANTDEX_TRIGGERDEADLINE/2 && ((long)now - timestamp) < 60 && (cmpstr == 0 || triggerhash == 0 || (cmpstr != 0 && triggerhash != 0 && strcmp(cmpstr,triggerhash) == 0)) )
                        {
                            // https://nxtforum.org/nrs-releases/nrs-v1-5-15/msg191715/#msg191715
                            printf("GEN RESPONDTX lag.%d deadline.%d (recv.%llu %lld) recv.(%llu %lld) orderid.%llu/%llx quoteid.%llu/%llx\n",now-timestamp,*deadlinep,(long long)recvasset,(long long)recvqty,(long long)recvasset,(long long)recvqty,(long long)orderid,(long long)orderid,(long long)quoteid,(long long)quoteid);
                            if ( InstantDEX_verify(IGUANA_MY64BITS,recvasset,recvqty,txobj,recvasset,recvqty) == 0 )
                                retval = 0;
                            else printf("(%s) didnt validate against quoteid.%llu\n",parsed,(long long)quoteid);
                        } else fprintf(stderr,"swap rejects tx deadline %d >= INSTANTDEX_TRIGGERDEADLINE/2 && (now %d - %d timestamp) %d < 60\n",*deadlinep,now,timestamp,now-timestamp);
                        free_json(txobj);
                    } else fprintf(stderr,"swap cant parse tx.(%s)\n",parsed);
                    free(parsed);
                } else fprintf(stderr,"swap cant parse UTX.(%s)\n",UTX);
            } else fprintf(stderr,"mismatch (%s) != (%s)\n",calchash.buf,fullhash);
            if ( json != 0 )
                free_json(json);
        } else fprintf(stderr,"swap cant parse.(%s)\n",jsonstr);
        if ( jsonstr != 0 )
            free(jsonstr);
    } else fprintf(stderr,"calchash.(%s)\n",jsonstr);
    return(retval);
}

struct pending_trade *pending_swap(char **strp,int32_t type,uint64_t orderid,uint64_t quoteid,char *triggerhash,char *fullhash,char *txstr,char *txstr2)
{
    struct pending_trade *pend; cJSON *retjson;
    pend = calloc(1,sizeof(*pend));
    pend->orderid = orderid, pend->quoteid = quoteid;
    if ( triggerhash != 0 )
        pend->triggertx = clonestr(triggerhash);
    if ( fullhash != 0 )
        pend->txbytes = clonestr(fullhash);
    pend->type = type;
    if ( txstr != 0 && txstr2 != 0 )
    {
        retjson = cJSON_CreateObject();
        jadd(retjson,"fee",cJSON_Parse(txstr));
        jadd(retjson,"responsetx",cJSON_Parse(txstr2));
        *strp = jprint(retjson,0);
        pend->tradesjson = retjson;
    }
    pend->timestamp = (uint32_t)time(NULL);
    return(pend);
}

char *swap_responseNXT(int32_t type,char *offerNXT,uint64_t otherbits,uint64_t otherqty,uint64_t orderid,uint64_t quoteid,int32_t deadline,char *triggerhash,char *phaselink,int32_t finishheight,struct InstantDEX_quote *iQ)
{
    struct NXTtx fee,responsetx; int32_t errcode,errcode2; char *txstr,*txstr2,*str = 0; struct pending_trade *pend;
    gen_NXTtx(&fee,calc_nxt64bits(INSTANTDEX_ACCT),NXT_ASSETID,INSTANTDEX_FEE,orderid,quoteid,deadline,triggerhash,0,0,0);
    gen_NXTtx(&responsetx,calc_nxt64bits(offerNXT),otherbits,otherqty,orderid,quoteid,deadline,triggerhash,phaselink,finishheight,0);
    if ( (fee.txid= issue_broadcastTransaction(&errcode,&txstr,fee.txbytes,IGUANA_NXTACCTSECRET)) != 0 )
    {
        if ( (responsetx.txid= issue_broadcastTransaction(&errcode2,&txstr2,responsetx.txbytes,IGUANA_NXTACCTSECRET)) != 0 )
        {
            if ( (pend= pending_swap(&str,type,orderid,quoteid,triggerhash,phaselink,txstr,txstr2)) != 0 && str != 0 )
            {
                iQ->s.pending = iQ->s.swap = 1;
                //InstantDEX_history(0,pend,str);
                pend->queueflag = 1;
                queue_enqueue("PendingQ",&Pending_offersQ,&pend->DL,0);
                printf("BROADCAST fee.txid %llu and %llu (%s %s)\n",(long long)fee.txid,(long long)responsetx.txid,fee.fullhash,responsetx.fullhash);
            }
        } else printf("error.%d broadcasting responsetx.(%s) %s\n",errcode2,responsetx.txbytes,txstr2);
    } else printf("error.%d broadcasting feetx.(%s) %s\n",errcode,fee.txbytes,txstr);
    if ( str == 0 )
        str = clonestr("{\"error\":\"swap_responseNXT error responding\"}");
    return(str);
}

int32_t extract_pkhash(char *pubkeystr,char *pkhash,char *script)
{
    int32_t len; uint8_t rmd160[20],data[4096],*ptr;
    decode_hex(data,(int32_t)strlen(script)>>1,script);
    len = data[0];
    ptr = &data[len + 1];
    len = *ptr++;
    if ( len == 33 )
    {
        init_hexbytes_noT(pubkeystr,ptr,33);
        calc_OP_HASH160(pkhash,rmd160,pubkeystr);
        printf("pkhash.(%s)\n",pkhash);
        return(0);
    }
    return(-1);
}

char *swap_func(int32_t localaccess,int32_t valid,char *sender,cJSON *origjson,char *origargstr)
{
    /*char script[4096],hexstr[128],*str,*base,*rel,*txstr,*phasedtx,*cointxid,*signedtx,*jsonstr; uint8_t msgbuf[512];
    struct pending_trade *pend; struct prices777_order order; struct InstantDEX_quote *iQ,_iQ; cJSON *json;
    uint32_t deadline,finishheight,nonce,isask; int32_t errcode,myoffer,myfill,len; struct NXTtx sendtx,fee; struct destbuf spendtxid,reftx;
    struct destbuf offerNXT,exchange; uint64_t otherbits,otherqty,quoteid,orderid,recvasset,recvqty,sendasset,sendqty,fillNXT,destbits,value;
    char pubkeystr[128],pkhash[64],swapbuf[4096],refredeemscript[1024],vintxid[128],*triggerhash,*fullhash,*dest,deststr[64];*/
    struct destbuf offerNXT,exchange; uint32_t deadline,finishheight,isask; char *triggerhash,*fullhash; int32_t myoffer,myfill; struct InstantDEX_quote *iQ,_iQ;  struct prices777_order order;
    uint64_t otherbits,otherqty,quoteid,orderid,fillNXT;
    copy_cJSON(&offerNXT,jobj(origjson,"offerNXT"));
    fillNXT = j64bits(origjson,"fillNXT");
    copy_cJSON(&exchange,jobj(origjson,"exchange"));
    finishheight = juint(origjson,"F");
    if ( (triggerhash= jstr(origjson,"T")) == 0 )
        triggerhash = jstr(origjson,"trigger");
    myoffer = strcmp(IGUANA_NXTADDR,offerNXT.buf) == 0;
    myfill = (IGUANA_MY64BITS == fillNXT);
//printf("swap_func got (%s)\n",origargstr);
    if ( myoffer+myfill != 0 )
    {
        orderid = j64bits(origjson,"orderid");
        quoteid = j64bits(origjson,"quoteid");
        if ( (iQ= find_iQ(quoteid)) == 0 )
        {
            fprintf(stderr,"swap_func: cant find quoteid.%llu\n",(long long)quoteid);
            iQ = &_iQ, memset(iQ,0,sizeof(*iQ));
            //return(clonestr("{\"error\":\"cant find quoteid\"}"));
        }
        if ( iQ->s.responded != 0 )
        {
            fprintf(stderr,"already responded quoteid.%llu\n",(long long)iQ->s.quoteid);
            return(0);
        }
        isask = iQ->s.isask;
        memset(&order,0,sizeof(order));
        order.s = iQ->s;
#ifdef notyet
        if ( strcmp("wallet",exchange.buf) == 0 )
        {
            uint64_t sendamount,recvamount; struct coin777 *recvcoin,*sendcoin;
            char refundsig[512],fieldA[64],fieldB[64],fieldpkhash[64];
            char *recvstr,*sendstr,*spendtx,*refundtx,*redeemscript,*rpubA,*rpubB,*rpkhash,*spubA,*spubB,*spkhash;
            recvcoin = sendcoin = 0; sendamount = recvamount = 0;
            if ( (recvstr= jstr(origjson,"recvcoin")) != 0 )
                recvcoin = coin777_find(recvstr,0);
            if ( (sendstr= jstr(origjson,"sendcoin")) != 0 )
                sendcoin = coin777_find(sendstr,0);
            if ( iQ->s.baseid == NXT_ASSETID )
                isask ^= 1;
            //printf("recvstr.%p sendstr.%p\n",recvstr,sendstr);
            if ( recvstr != 0 && sendstr != 0 )
            {
                if ( (sendamount= j64bits(origjson,"sendamount")) != 0 && (recvamount= j64bits(origjson,"recvamount")) != 0 && sendcoin != 0 && recvcoin != 0 && (refundtx= jstr(origjson,"rtx")) != 0 && (redeemscript= jstr(origjson,"rs")) != 0 && (rpubA= jstr(origjson,"rpubA")) != 0  && (rpubB= jstr(origjson,"rpubB")) != 0  && (rpkhash= jstr(origjson,"rpkhash")) != 0 && triggerhash != 0 && (spubA= jstr(origjson,"spubA")) != 0  && (spubB= jstr(origjson,"spubB")) != 0  && (spkhash= jstr(origjson,"spkhash")) != 0 )
                {
                }
            }
            else if ( recvstr != 0 )
            {
                //printf("INCOMINGRECV.(%s)\n",origargstr);
                sprintf(fieldA,"%spubA",recvcoin->name);
                sprintf(fieldB,"%spubB",recvcoin->name);
                sprintf(fieldpkhash,"%spkhash",recvcoin->name);
                if ( (recvamount= j64bits(origjson,"recvamount")) != 0 && recvcoin != 0 && (rpubA= jstr(origjson,fieldA)) != 0 && (rpubB= jstr(origjson,fieldB)) != 0 && (rpkhash= jstr(origjson,fieldpkhash)) != 0 )
                {
                    if ( ((isask != 0 && myoffer != 0) || (isask == 0 && myfill != 0)) && j64bits(origjson,"fill") != IGUANA_MY64BITS && (refundtx= jstr(origjson,"rtx")) != 0 && (redeemscript= jstr(origjson,"rs")) != 0 ) // Bob: sends NXT to Alice, recvs recvcoin
                    {
                        subatomic_pubkeyhash(pubkeystr,pkhash,recvcoin,quoteid);
                        //printf("CALC >>>>>>>>>> (%s) vs (%s)\n",pkhash,rpkhash);
                        if ( (base= jstr(origjson,"base")) != 0 && (rel= jstr(origjson,"rel")) != 0 && (sendasset= j64bits(origjson,"sendasset")) != 0 && (sendqty= j64bits(origjson,"sendqty")) != 0 )
                        {
                            //printf("inside (%s/%s) sendasset.%llu sendqty.%llu rpkhash.(%s)\n",base,rel,(long long)sendasset,(long long)sendqty,rpkhash);
                            if ( (spendtx= subatomic_spendtx(&spendtxid,vintxid,refundsig,recvcoin,rpubA,rpubB,pubkeystr,recvamount,refundtx,redeemscript)) != 0 )
                            {
                                finishheight = 60; deadline = 3600*4;
                                if ( (pend= pending_swap(&str,'A',orderid,quoteid,0,0,0,0)) != 0 )
                                {
                                    if ( isask == 0 )
                                        destbits = calc_nxt64bits(offerNXT.buf);
                                    else destbits = fillNXT;
                                    gen_NXTtx(&fee,calc_nxt64bits(INSTANTDEX_ACCT),NXT_ASSETID,INSTANTDEX_FEE,orderid,quoteid,deadline,triggerhash,0,0,0);
                                    issue_broadcastTransaction(&errcode,&txstr,fee.txbytes,IGUANA_NXTACCTSECRET);
                                    gen_NXTtx(&sendtx,destbits,sendasset,sendqty,orderid,quoteid,deadline,triggerhash,0,_get_NXTheight(0)+finishheight,rpkhash);
                                    //issue_broadcastTransaction(&errcode,&txstr,sendtx.txbytes,IGUANA_NXTACCTSECRET);
                                    printf(">>>>>>>>>>>> broadcast fee and phased.(%s) trigger.%s\n",sendtx.txbytes,triggerhash);
                                    sprintf(swapbuf,"{\"orderid\":\"%llu\",\"quoteid\":\"%llu\",\"offerNXT\":\"%s\",\"fillNXT\":\"%llu\",\"plugin\":\"relay\",\"destplugin\":\"InstantDEX\",\"method\":\"busdata\",\"submethod\":\"swap\",\"exchange\":\"wallet\",\"recvcoin\":\"%s\",\"recvamount\":\"%lld\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"refundsig\":\"%s\",\"phasedtx\":\"%s\",\"spendtxid\":\"%s\",\"a\":\"%llu\",\"q\":\"%llu\",\"trigger\":\"%s\",\"fill\":\"%llu\"}",(long long)orderid,(long long)quoteid,offerNXT.buf,(long long)fillNXT,recvcoin->name,(long long)recvamount,fieldA,rpubA,fieldB,rpubB,fieldpkhash,rpkhash,refundsig,sendtx.txbytes,spendtxid.buf,(long long)sendasset,(long long)sendqty,triggerhash,(long long)IGUANA_MY64BITS);
                                    if ( (str= busdata_sync(&nonce,swapbuf,"allnodes",0)) != 0 )
                                        free(str);
                                    // poll for vin then broadcast spendtx
                                    printf(">>>>>>>>>>>>>>>>>>>> wait for (%s) then send SPENDTX.(%s)\n",vintxid,spendtx);
                                    if ( (value= wait_for_txid(script,recvcoin,vintxid,0,recvamount,recvcoin->minconfirms,0)) != 0 )
                                    {
                                        signedtx = malloc(strlen(spendtx) + 16);
                                        sprintf(signedtx,"[\"%s\"]",spendtx);
                                        if ( (cointxid= bitcoind_passthru(recvcoin->name,recvcoin->serverport,recvcoin->userpass,"sendrawtransaction",signedtx)) != 0 )
                                        {
                                            printf(">>>>>>>>>>>>> BROADCAST SPENDTX.(%s) (%s)\n",signedtx,cointxid);
                                            free(cointxid);
                                        }
                                        free(signedtx);
                                    }
                                    printf("ATOMIC SWAP.%llu finished\n",(long long)quoteid);
                                    iQ->s.closed = 1;
                                    delete_iQ(quoteid);
                                } else printf("cant get pending_swap pend.%p\n",pend);
                                free(spendtx);
                                return(clonestr(swapbuf));
                            } else printf("error generating spendtx\n");
                        } else printf("mismatched recv (%s vs %s) or (%s)\n",recvcoin->atomicrecvpubkey,rpubB,rpkhash);
                    }
                    else if ( j64bits(origjson,"fill") != IGUANA_MY64BITS && (str= jstr(origjson,"refundsig")) != 0 && str[0] != 0 && (phasedtx= jstr(origjson,"phasedtx")) != 0 && phasedtx[0] != 0 ) // Alice to verify NXTtx and send recvcoin
                    {
                        if ( isask != 0 )
                            dest = offerNXT.buf;
                        else
                        {
                            expand_nxt64bits(deststr,fillNXT);
                            dest = deststr;
                        }
                        if ( swap_verifyNXT(&finishheight,&deadline,origjson,dest,exchange.buf,orderid,quoteid,iQ,phasedtx) == 0 )
                        {
                            if ( recvcoin->refundtx != 0 && (recvcoin->signedrefund= subatomic_validate(recvcoin,rpubA,rpubB,rpkhash,recvcoin->refundtx,str)) != 0 )
                            {
                                free(recvcoin->refundtx), recvcoin->refundtx = 0;
                                issue_broadcastTransaction(&errcode,&txstr,recvcoin->trigger.txbytes,IGUANA_NXTACCTSECRET);
                                issue_broadcastTransaction(&errcode,&txstr,phasedtx,IGUANA_NXTACCTSECRET);
                                printf(">>>>>>>>>>>>>>>>>>>>>>>>>>> ISSUE TRIGGER.(%s) phased.(%s).%d | signedrefund.(%s)\n",recvcoin->trigger.txbytes,txstr!=0?txstr:"phasedsubmit error",errcode,recvcoin->signedrefund);
                                signedtx = malloc(strlen(recvcoin->funding.signedtransaction) + 16);
                                sprintf(signedtx,"[\"%s\"]",recvcoin->funding.signedtransaction);
                                if ( (cointxid= bitcoind_passthru(recvcoin->name,recvcoin->serverport,recvcoin->userpass,"sendrawtransaction",signedtx)) != 0 )
                                {
                                    printf(">>>>>>>>>>>>> FUNDING BROADCAST.(%s) (%s)\n",recvcoin->funding.signedtransaction,cointxid);
                                    free(cointxid);
                                } else printf("error sendrawtransaction.(%s)\n",recvcoin->funding.signedtransaction);
                                free(signedtx);
                                copy_cJSON(&spendtxid,jobj(origjson,"spendtxid"));
                                printf("wait for spendtx.(%s)\n",spendtxid.buf);
                                if ( (value= wait_for_txid(script,recvcoin,spendtxid.buf,0,recvamount-recvcoin->mgw.txfee,0,0)) != 0 )
                                {
                                    iQ->s.responded = 1;
                                    if ( extract_pkhash(pubkeystr,pkhash,script) == 0 )
                                    {
                                        if ( strcmp(pkhash,rpkhash) == 0 )
                                        {
                                            reftx.buf[0] = 0;
                                            if ( (jsonstr= issue_parseTransaction(phasedtx)) != 0 )
                                            {
                                                if ( (json= cJSON_Parse(jsonstr)) != 0 )
                                                {
                                                    copy_cJSON(&reftx,jobj(json,"fullHash"));
                                                    free_json(json);
                                                }
                                                free(jsonstr);
                                            }
                                            len = 0;
                                            len = txind777_txbuf(msgbuf,len,orderid,sizeof(orderid));
                                            len = txind777_txbuf(msgbuf,len,quoteid,sizeof(quoteid));
                                            init_hexbytes_noT(hexstr,msgbuf,len);
                                            if ( (str= issue_approveTransaction(reftx.buf,pubkeystr,hexstr,IGUANA_NXTACCTSECRET)) != 0 )
                                            {
                                                printf("fullhash.(%s) pubkey.(%s) pkhash.(%s) APPROVED.(%s)\n",reftx.buf,pubkeystr,pkhash,str);
                                                free(str);
                                            } else printf("error sending in approval\n");
      
                                        } else printf("script.(%s) -> pkhash.(%s) vs rpkhash.(%s)\n",script,pkhash,rpkhash);
                                    } else printf("unexpected end of script.(%s) (%s)\n",script,str);
                                }
                                printf("FINISHED ATOMIC SWAP of quoteid.%llu\n",(long long)quoteid);
                                iQ->s.closed = 1;
                                memset(&recvcoin->trigger,0,sizeof(recvcoin->trigger));
                                memset(&recvcoin->funding,0,sizeof(recvcoin->funding));
                                free(recvcoin->signedrefund), recvcoin->signedrefund = 0;
                                delete_iQ(quoteid);
                            } else printf("refund tx didnt verify\n");
                        } else printf("NXT tx didnt verify\n");
                    } //else printf("myfill.%d myoffer.%d recv mismatch isask.%d\n",myfill,myoffer,iQ->s.isask);
                    //printf("recv failed\n");
                    return(clonestr("{\"result\":\"recv failed\"}"));
                }
            }
            else if ( sendstr != 0 )  // Alice sendcoin -> Bob, recvs NXT
            {
                //printf("INCOMINGSEND.(%s)\n",origargstr);
                sprintf(fieldA,"%spubA",sendcoin->name);
                sprintf(fieldB,"%spubB",sendcoin->name);
                sprintf(fieldpkhash,"%spkhash",sendcoin->name);
                if ( ((isask == 0 && myoffer != 0) || (isask != 0 && myfill != 0)) && (sendamount= j64bits(origjson,"sendamount")) != 0 && sendcoin != 0 && triggerhash != 0 && (spubA= jstr(origjson,fieldA)) != 0 && (spubB= jstr(origjson,fieldB)) != 0 && (spkhash= jstr(origjson,fieldpkhash)) != 0 )
                {
                    if ( (base= jstr(origjson,"base")) != 0 && (rel= jstr(origjson,"rel")) != 0 && (recvasset= j64bits(origjson,"recvasset")) != 0 && (recvqty= j64bits(origjson,"recvqty")) != 0 )
                    {
                        if ( sendcoin->funding.signedtransaction[0] == 0 && (refundtx= subatomic_fundingtx(refredeemscript,&sendcoin->funding,sendcoin,spubA,spubB,spkhash,sendamount,10)) != 0 )
                        {
                            deadline = 3600;
                            gen_NXTtx(&sendcoin->trigger,calc_nxt64bits(INSTANTDEX_ACCT),NXT_ASSETID,INSTANTDEX_FEE,orderid,quoteid,deadline,0,0,0,0);
                            sprintf(swapbuf,"{\"orderid\":\"%llu\",\"quoteid\":\"%llu\",\"offerNXT\":\"%s\",\"fillNXT\":\"%llu\",\"plugin\":\"relay\",\"destplugin\":\"InstantDEX\",\"method\":\"busdata\",\"submethod\":\"swap\",\"exchange\":\"%s\",\"recvamount\":\"%lld\",\"rtx\":\"%s\",\"rs\":\"%s\",\"recvcoin\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"trigger\":\"%s\",\"sendasset\":\"%llu\",\"sendqty\":\"%llu\",\"base\":\"%s\",\"rel\":\"%s\",\"fill\":\"%llu\"}",(long long)orderid,(long long)quoteid,offerNXT.buf,(long long)fillNXT,exchange.buf,(long long)sendamount,refundtx,refredeemscript,sendstr,fieldA,spubA,fieldB,spubB,fieldpkhash,spkhash,sendcoin->trigger.fullhash,(long long)recvasset,(long long)recvqty,base,rel,(long long)IGUANA_MY64BITS);
                            sendcoin->refundtx = refundtx;
                            if ( (str= busdata_sync(&nonce,swapbuf,"allnodes",0)) != 0 )
                                free(str);
                            return(clonestr(swapbuf));
                            //printf("BUSDATA.(%s)\n",swapbuf);
                        } else return(clonestr("{\"error\":\"cant create refundtx, maybe already pending\"}\n"));
                    } //else printf("mismatched send (%s vs %s) or (%s)\n",sendcoin->atomicrecvpubkey,spubB,spkhash);
                } else printf("myfill.%d myoffer.%d send mismatch isask.%d\n",myfill,myoffer,iQ->s.isask);
            }
            return(clonestr("{\"result\":\"processed wallet swap\"}"));
        }
#endif
        if ( myoffer != 0 && swap_verifyNXT(&finishheight,&deadline,origjson,offerNXT.buf,exchange.buf,orderid,quoteid,iQ,0) == 0 )
        {
            otherbits = j64bits(origjson,"a");
            otherqty = j64bits(origjson,"q");
            fullhash = jstr(origjson,"FH");
            finishheight = juint(origjson,"F");
            return(swap_responseNXT('R',offerNXT.buf,otherbits,otherqty,orderid,quoteid,deadline,triggerhash,fullhash,finishheight,iQ));
        } else printf("myfill.%d myoffer.%d swap mismatch\n",myfill,myoffer);
    }
    return(clonestr("{\"result\":\"processed swap\"}"));
}

int32_t match_unconfirmed(char *sender,char *hexstr,cJSON *txobj,char *txidstr,char *account,uint64_t amount,uint64_t qty,uint64_t assetid,char *recipient)
{
    // ok, the bug here is that on a delayed respondtx, the originator should refuse to release the trigger (and the money tx)
    uint64_t orderid,quoteid,recvasset,sendasset; int64_t recvqty,sendqty; uint32_t bidask,deadline,timestamp,now; struct InstantDEX_quote *iQ;
    decode_hex((void *)&orderid,sizeof(orderid),hexstr);
    decode_hex((void *)&quoteid,sizeof(quoteid),hexstr+16);
    //printf("match_unconfirmed.(%s) orderid.%llu %llx quoteid.%llu %llx\n",hexstr,(long long)orderid,(long long)orderid,(long long)quoteid,(long long)quoteid);
    deadline = juint(txobj,"deadline");
    timestamp = juint(txobj,"timestamp");
    now = issue_getTime();
    //printf("deadline.%u now.%u timestamp.%u lag %ld\n",deadline,now,timestamp,((long)now - timestamp));
    if ( deadline < INSTANTDEX_TRIGGERDEADLINE/2 || ((long)now - timestamp) > 60*2 )
        return(0);
    if ( (iQ= find_iQ(quoteid)) != 0 && iQ->s.closed == 0 && iQ->s.pending != 0 && (iQ->s.responded == 0 || iQ->s.feepaid == 0) )
    {
        if ( Debuglevel > 2 )
            printf("match unconfirmed %llu/%llu %p swap.%d feepaid.%d responded.%d sender.(%s) -> recv.(%s) me.(%s) offer.(%llu)\n",(long long)orderid,(long long)quoteid,iQ,iQ->s.swap,iQ->s.feepaid,iQ->s.responded,sender,recipient,IGUANA_NXTADDR,(long long)iQ->s.offerNXT);
        if ( iQ->s.swap != 0 && (strcmp(recipient,INSTANTDEX_ACCT) == 0 || strcmp(recipient,IGUANA_NXTADDR) == 0) )
        {
            if ( iQ->s.feepaid == 0 )
            {
                if ( verify_NXTtx(txobj,NXT_ASSETID,INSTANTDEX_FEE,calc_nxt64bits(INSTANTDEX_ACCT)) == 0 )
                {
                    iQ->s.feepaid = 1;
                    printf("FEE DETECTED\n");
                } else printf("notfee: dest.%s src.%s amount.%llu qty.%llu assetid.%llu\n",recipient,sender,(long long)amount,(long long)qty,(long long)assetid);
            }
            if ( iQ->s.responded == 0 )
            {
                bidask = iQ->s.isask;
                if ( iQ->s.offerNXT == IGUANA_MY64BITS )
                    bidask ^= 1;
                if ( bidask != 0 )
                {
                    sendasset = iQ->s.relid, sendqty = iQ->s.relamount;
                    recvasset = iQ->s.baseid, recvqty = iQ->s.baseamount;
                }
                else
                {
                    sendasset = iQ->s.baseid, sendqty = iQ->s.baseamount;
                    recvasset = iQ->s.relid, recvqty = iQ->s.relamount;
                }
                sendqty /= get_assetmult(sendasset);
                recvqty /= get_assetmult(recvasset);
                if ( Debuglevel > 2 )
                    printf("sendasset.%llu sendqty.%llu mult.%llu, recvasset.%llu recvqty.%llu mult.%llu\n",(long long)sendasset,(long long)sendqty,(long long)get_assetmult(sendasset),(long long)recvasset,(long long)recvqty,(long long)get_assetmult(recvasset));
                if ( InstantDEX_verify(IGUANA_MY64BITS,sendasset,sendqty,txobj,recvasset,recvqty) == 0 )
                {
                    iQ->s.responded = 1;
                    printf("iQ: %llu/%llu %lld/%lld | recv %llu %lld offerNXT.%llu\n",(long long)iQ->s.baseid,(long long)iQ->s.relid,(long long)iQ->s.baseamount,(long long)iQ->s.relamount,(long long)recvasset,(long long)recvqty,(long long)iQ->s.offerNXT);
                    printf("RESPONSE DETECTED\n");
                }
            }
            if ( iQ->s.responded != 0 && iQ->s.feepaid != 0 )
            {
                printf("both detected offer.%llu my64bits.%llu\n",(long long)iQ->s.offerNXT,(long long)IGUANA_MY64BITS);
                complete_swap(iQ,orderid,quoteid,iQ->s.offerNXT == IGUANA_MY64BITS);
            }
        }
    }
    return(-1);
}

int32_t is_unfunded_order(uint64_t nxt64bits,uint64_t assetid,uint64_t amount)
{
    char assetidstr[64],NXTaddr[64],cmd[1024],*jsonstr;
    int64_t ap_mult,unconfirmed,balance = 0;
    cJSON *json;
    expand_nxt64bits(NXTaddr,nxt64bits);
    if ( assetid == NXT_ASSETID )
    {
        sprintf(cmd,"requestType=getAccount&account=%s",NXTaddr);
        if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
        {
            if ( (json= cJSON_Parse(jsonstr)) != 0 )
            {
                balance = get_API_nxt64bits(cJSON_GetObjectItem(json,"balanceNQT"));
                free_json(json);
            }
            free(jsonstr);
        }
        strcpy(assetidstr,"NXT");
    }
    else
    {
        expand_nxt64bits(assetidstr,assetid);
        if ( (ap_mult= assetmult(assetidstr)) != 0 )
        {
            expand_nxt64bits(NXTaddr,nxt64bits);
            balance = ap_mult * get_asset_quantity(&unconfirmed,NXTaddr,assetidstr);
        }
    }
    if ( balance < amount )
    {
        printf("balance %.8f < amount %.8f for asset.%s\n",dstr(balance),dstr(amount),assetidstr);
        return(1);
    }
    return(0);
}

cJSON *InstantDEX_tradejson(int32_t *curlingp,void *bot,struct pending_trade **pendp,void **cHandlep,cJSON *item,char *activenxt,char *secret,struct prices777_order *order,int32_t dotrade,uint64_t orderid,char *extra)
{
    char swapbuf[8192],buf[8192],triggertx[4096],txbytes[4096],*retstr,*exchange; uint64_t txid,qty,avail,priceNQT;
    struct prices777 *prices; cJSON *json = 0;
    if ( pendp != 0 )
        *pendp = 0;
    if ( (prices= order->source) != 0 )
    {
        exchange = prices->exchange;
        swapbuf[0] = 0;
        if ( dotrade == 0 )
        {
            if ( strcmp(exchange,INSTANTDEX_NAME) != 0 && strcmp(exchange,"wallet") != 0 )
            {
                sprintf(buf,"{\"orderid\":\"%llu\",\"trade\":\"%s\",\"exchange\":\"%s\",\"base\":\"%s\",\"rel\":\"%s\",\"baseid\":\"%llu\",\"relid\":\"%llu\",\"price\":%.8f,\"volume\":%.8f,\"extra\":\"%s\"}",(long long)orderid,order->wt > 0. ? "buy" : "sell",exchange,prices->base,prices->rel,(long long)prices->baseid,(long long)prices->relid,order->s.price,order->s.vol,extra!=0?extra:"");
                if ( strcmp(exchange,"nxtae") == 0 )
                {
                    qty = calc_asset_qty(&avail,&priceNQT,activenxt,0,prices->baseid,order->s.price,order->s.vol);
                    sprintf(buf+strlen(buf)-1,",\"priceNQT\":\"%llu\",\"quantityQNT\":\"%llu\",\"avail\":\"%llu\"}",(long long)priceNQT,(long long)qty,(long long)avail);
                    if ( qty == 0 )
                        sprintf(buf+strlen(buf)-1,",\"error\":\"insufficient balance\"}");
                }
                return(cJSON_Parse(buf));
            }
            else
            {
                //{"inverted":0,"contract":"MMNXT/Jay","baseid":"979292558519844732","relid":"8688289798928624137","bids":[{"plugin":"Inst
                //    antDEX","method":"tradesequence","dotrade":1,"price":2,"volume":2,"trades":[]}],"asks":[],"numbids":1,"numasks":0,"lastb
                //    id":2,"lastask":0,"NXT":"11471677413693100042","timestamp":1440587058,"maxdepth":25}
                prices777_swapbuf("yes",0,&txid,triggertx,txbytes,swapbuf,prices->exchange,prices->base,prices->rel,order,orderid,extra==0?0:myatoi(extra,10000),0);
                return(cJSON_Parse(swapbuf));
            }
        }
        retstr = prices777_trade(curlingp,bot,pendp,cHandlep,dotrade,item,activenxt,secret,prices,order->wt,order->s.price,order->s.vol,0,order,orderid,extra);
        if ( retstr != 0 )
        {
            json = cJSON_Parse(retstr);
            free(retstr);
        }
    }
    return(json);
}

char *InstantDEX_dotrades(int32_t curlings[],void *bot,void *cHandles[],char *activenxt,char *secret,cJSON *json,struct prices777_order *trades,int32_t numtrades,int32_t dotrade,char *extra)
{
    struct destbuf exchangestr,gui,name,base,rel; struct InstantDEX_quote iQ; cJSON *retjson,*retarray; int32_t i;
    bidask_parse(1,&exchangestr,&name,&base,&rel,&gui,&iQ,json);
    retjson = cJSON_CreateObject(), retarray = cJSON_CreateArray();
    for (i=0; i<numtrades; i++)
    {
        //printf("GOT%d.(%s)\n",i,jprint(json,0));
        if ( trades[i].retitem != 0 )
            free_json(trades[i].retitem );
        trades[i].retitem = InstantDEX_tradejson(curlings!=0?&curlings[i]:0,bot,&trades[i].pend,cHandles!=0?cHandles[i]:0,jobj(json,"trades"),activenxt,secret,&trades[i],dotrade,iQ.s.quoteid,extra);
        jaddi(retarray,trades[i].retitem);
    }
    jadd(retjson,"traderesults",retarray);
    return(jprint(retjson,0));
}

char *InstantDEX_tradesequence(int32_t curlings[],void *bot,void *cHandles[],int32_t *nump,struct prices777_order *trades,int32_t maxtrades,int32_t dotrade,char *activenxt,char *secret,cJSON *json)
{
    //"trades":[[{"basket":"bid","rootwt":-1,"groupwt":1,"wt":-1,"price":40000,"volume":0.00015000,"group":0,"trade":"buy","exchange":"nxtae","asset":"17554243582654188572","base":"BTC","rel":"NXT","orderid":"3545444239044461477","orderprice":40000,"ordervolume":0.00015000}], [{"basket":"bid","rootwt":-1,"groupwt":1,"wt":1,"price":0.00376903,"volume":1297.41480000,"group":10,"trade":"sell","exchange":"coinbase","name":"BTC/USD","base":"BTC","rel":"USD","orderid":"1","orderprice":265.32000000,"ordervolume":4.89000000}]]}
    cJSON *array,*item; int32_t i,n,dir; char *tradestr,*exchangestr; struct prices777_order *order;
    uint64_t orderid,assetid,currency,baseid,relid,quoteid; int64_t sendbase,recvbase,sendrel,recvrel; struct destbuf base,rel,name;
    double orderprice,ordervolume; struct prices777 *prices; uint32_t timestamp;
    if ( (array= jarray(&n,json,"trades")) != 0 )
    {
        if ( n > maxtrades )
            return(clonestr("{\"error\":\"exceeded max trades possible in a tradesequence\"}"));
        if ( n == 1 && is_cJSON_Array(jitem(array,0)) != 0 )
        {
            //printf("NESTED ARRAY DETECTED\n");
            array = jitem(array,0);
            n = cJSON_GetArraySize(array);
        }
        *nump = n;
        timestamp = (uint32_t)time(NULL);
        for (i=0; i<n; i++)
        {
            order = &trades[i];
            memset(order,0,sizeof(*order));
            item = jitem(array,i);
            tradestr = jstr(item,"trade"), exchangestr = jstr(item,"exchange");
            copy_cJSON(&base,jobj(item,"base")), copy_cJSON(&rel,jobj(item,"rel")), copy_cJSON(&name,jobj(item,"name"));
            orderid = j64bits(item,"orderid"), quoteid = j64bits(item,"quoteid");
            if ( orderid == 0 )
                orderid = quoteid;
            if ( quoteid == 0 )
                quoteid = orderid;
            order->id = orderid, order->s.quoteid = quoteid;
            assetid = j64bits(item,"asset"), currency = j64bits(item,"currency");
            baseid = j64bits(item,"baseid"), relid = j64bits(item,"relid");
            sendbase = j64bits(item,"sendbase"), recvbase = j64bits(item,"recvbase");
            sendrel = j64bits(item,"sendrel"), recvrel = j64bits(item,"recvrel");
            order->s.baseamount = (recvbase - sendbase);
            order->s.relamount = (recvrel - sendrel);
            orderprice = jdouble(item,"orderprice"), ordervolume = jdouble(item,"ordervolume");
            order->s.timestamp = juint(item,"timestamp");
            order->s.duration = juint(item,"duration");
            order->s.minperc = juint(item,"minperc");
            order->s.baseid = baseid;
            order->s.relid = relid;
            //printf("ITEM.(%s)\n",jprint(item,0));
            if ( tradestr != 0 )
            {
                if ( strcmp(tradestr,"buy") == 0 )
                    dir = 1;
                else if ( strcmp(tradestr,"sell") == 0 )
                    dir = -1;
                else if ( strcmp(tradestr,"swap") == 0 )
                    dir = 0;
                else return(clonestr("{\"error\":\"invalid trade direction\"}"));
                if ( (prices= prices777_initpair(1,exchangestr,base.buf,rel.buf,0.,name.buf,baseid,relid,0)) != 0 )
                {
                    order->source = prices;
                    order->s.offerNXT = j64bits(item,"offerNXT");
                    order->wt = dir, order->s.price = orderprice, order->s.vol = ordervolume;
                    printf("item[%d] dir.%d (price %.8f vol %.4f) %s/%s baseid.%llu relid.%llu sendbase.%llu recvbase.%llu sendrel.%llu recvrel.%llu | baseqty.%lld relqty.%lld\n",i,dir,order->s.price,order->s.vol,prices->base,prices->rel,(long long)order->s.baseid,(long long)order->s.relid,(long long)sendbase,(long long)recvbase,(long long)sendrel,(long long)recvrel,(long long)order->s.baseamount,(long long)order->s.relamount);
                } else return(clonestr("{\"error\":\"invalid exchange or contract pair\"}"));
            }
            else
            {
                printf("item.(%s)\n",jprint(item,0));
                return(clonestr("{\"error\":\"no trade specified\"}"));
            }
        }
        return(InstantDEX_dotrades(curlings,bot,cHandles,activenxt,secret,json,trades,n,dotrade,jstr(json,"extra")));
    }
    printf("error parsing.(%s)\n",jprint(json,0));
    return(clonestr("{\"error\":\"couldnt process trades\"}"));
}

#endif
