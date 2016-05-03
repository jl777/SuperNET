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
#ifdef notyet

#define BUNDLED
#define PLUGINSTR "teleport"
#define PLUGNAME(NAME) teleport ## NAME
#define STRUCTNAME struct PLUGNAME(_info) 
#define STRINGIFY(NAME) #NAME
#define PLUGIN_EXTRASIZE sizeof(STRUCTNAME)

#define DEFINES_ONLY
#include "../coins/coins777.c"
#include "../agents/plugin777.c"
#include "../utils/bits777.c"
#undef DEFINES_ONLY

#define NXTPRIVACY_COINADDR "RELiMDcxPeAT85acmeAEEX3M2omZRax4ft"

STRUCTNAME TELEPORT;
struct invoice_info { uint8_t hash[32]; };
struct telepod { char txid[256],privkey[256],podaddr[256],script[512]; uint64_t value; int32_t vout,numconfirms; };

int32_t telepathic_remotejson(cJSON *json)
{
    return(0);
}

int32_t telepathic_remotestr(char *pmstr)
{
    return(0);
}

int32_t telepathic_remotebinary(char *hexstr,void *data,int32_t datalen)
{
    char *signedtx,*cointxid; struct coin777 *coin = coin777_find("BTCD",0);
    if ( SUPERNET.iamrelay != 0 && coin != 0 )
    {
        signedtx = malloc(datalen*2 + 16);
        sprintf(signedtx,"[\"%s\"]",hexstr);
        if ( (cointxid= bitcoind_passthru("BTCD",coin->serverport,coin->userpass,"sendrawtransaction",signedtx)) != 0 )
        {
            printf(">>>>>>>>>>>>> BROADCAST.(%s) (%s)\n",signedtx,cointxid);
            free(cointxid);
        }
        free(signedtx);
    }
    return(0);
}

int32_t teleport_idle(struct plugin_info *plugin)
{
    int32_t pmlen; char *pmstr,*decoded; cJSON *decodedjson; uint64_t r;
    if ( TELEPORT.availablemilli == 0 )
    {
        randombytes((void *)&r,sizeof(r));
        TELEPORT.availablemilli = (uint64_t)(milliseconds() + SUPERNET.telepathicdelay + (r % SUPERNET.telepathicdelay));
    }
    if ( milliseconds() > TELEPORT.availablemilli && (pmstr= queue_dequeue(&TelepathyQ,1)) != 0 )
    {
        if ( is_hexstr(pmstr) != 0 )
        {
            pmlen = (int32_t)strlen(pmstr);
            decoded = malloc((pmlen >> 1) + 1);
            decode_hex((void *)decoded,pmlen,pmstr);
            decoded[pmlen] = 0;
            if ( (decodedjson= cJSON_Parse(decoded)) != 0 )
            {
                telepathic_remotejson(decodedjson);
                free_json(decodedjson);
            } else telepathic_remotebinary(pmstr,decoded,pmlen);
            free(decoded);
        } else telepathic_remotestr(pmstr);
        TELEPORT.availablemilli = 0;
        free_queueitem(pmstr);
        return(1);
    }
    return(0);
}

uint64_t parse_unspent_json(struct telepod *pod,struct coin777 *coin,cJSON *json)
{
    char args[MAX_JSON_FIELD+2],*privkey = 0; uint64_t amount = 0; struct destbuf tmp;
    copy_cJSON(&tmp,cJSON_GetObjectItem(json,"txid")), safecopy(pod->txid,tmp.buf,sizeof(pod->txid));
    copy_cJSON(&tmp,cJSON_GetObjectItem(json,"address")), safecopy(pod->podaddr,tmp.buf,sizeof(pod->podaddr));;
    copy_cJSON(&tmp,cJSON_GetObjectItem(json,"scriptPubKey")), safecopy(pod->script,tmp.buf,sizeof(pod->script));;
    amount = (uint64_t)(SATOSHIDEN * jdouble(json,"amount"));
    pod->vout = juint(json,"vout");
    pod->numconfirms = juint(json,"confirmations");
    if ( pod->txid[0] != 0 && pod->podaddr[0] != 0 && pod->script[0] != 0 && amount != 0 && pod->vout >= 0 )
    {
        sprintf(args,"[\"%s\"]",pod->podaddr);
        privkey = bitcoind_RPC(0,coin->name,coin->serverport,coin->userpass,"dumpprivkey",args);
        if ( privkey != 0 )
        {
            strcpy(pod->privkey,privkey);
            free(privkey);
        }
        else amount = 0, fprintf(stderr,"error podaddr.(%s) cant find privkey\n",pod->podaddr);
    } else printf("illegal unspent output: (%s) (%s) (%s) %.8f %d\n",pod->txid,pod->podaddr,pod->script,dstr(amount),pod->vout);
    return(amount);
}

char *teleport_OP_RETURN(int32_t opreturn,char *rawtx,char *opreturnhexstr,int32_t oldtx_format)
{
    char scriptstr[1024],*retstr = 0; long len; struct cointx_info *cointx; struct rawvout *vout;
    if ( (cointx= _decode_rawtransaction(rawtx,oldtx_format)) != 0 )
    {
        vout = &cointx->outputs[opreturn];
        safecopy(vout->script,scriptstr,sizeof(vout->script));
        len = (strlen(rawtx) + strlen(opreturnhexstr)) * 2;
        retstr = calloc(1,len + 1);
        safecopy(cointx->outputs[opreturn].script,opreturnhexstr,sizeof(cointx->outputs[opreturn].script));
        if ( Debuglevel > 1 )
            disp_cointx(cointx);
        printf("teleport_OP_RETURN: vout.%d %p (%s) (%s)\n",opreturn,vout,vout->script,cointx->outputs[opreturn].script);
        if ( _emit_cointx(retstr,len,cointx,oldtx_format) < 0 )
            free(retstr), retstr = 0;
        free(cointx);
    } else printf("error teleport_OP_RETURN\n");
    return(retstr);
}

char *teleport_sign_rawbytes(int32_t *completedp,char *signedbytes,long max,char *coinstr,char *serverport,char *userpass,char *rawbytes)
{
    char *hexstr,*retstr = 0; cJSON *json,*compobj;
    *completedp = 0;
    if ( (retstr= bitcoind_passthru(coinstr,serverport,userpass,"signrawtransaction",rawbytes)) != 0 )
    {
        if ( (json= cJSON_Parse(retstr)) != 0 )
        {
            if ( (compobj= cJSON_GetObjectItem(json,"complete")) != 0 )
                *completedp = ((compobj->type&0xff) == cJSON_True);
            if ( (hexstr= cJSON_str(cJSON_GetObjectItem(json,"hex"))) != 0 )
            {
                if ( strlen(hexstr) > max )
                    printf("sign_rawbytes: strlen(hexstr) %d > %ld destize (%s)\n",(int32_t)strlen(hexstr),max,retstr), free(retstr), retstr = 0;
                else strcpy(signedbytes,hexstr);
            } else printf("no hex.(%s)\n",retstr);
            free_json(json);
        } else printf("json parse error.(%s)\n",retstr);
    } else printf("error signing rawtx\n");
    return(retstr);
}

char *teleport_calctransaction(struct coin777 *coin,cJSON *vinsobj,cJSON *voutsobj,cJSON *privkeys,int32_t opreturnvout,char *opreturnhexstr)
{
    char *paramstr,*txbytes,*txbytes2,*signedtx; int32_t completed; cJSON *array = cJSON_CreateArray();
    cJSON_AddItemToArray(array,cJSON_Duplicate(vinsobj,1));
    cJSON_AddItemToArray(array,cJSON_Duplicate(voutsobj,1));
    paramstr = cJSON_Print(array), free_json(array), _stripwhite(paramstr,' ');
    txbytes = bitcoind_passthru(coin->name,coin->serverport,coin->userpass,"createrawtransaction",paramstr);
    free(paramstr);
    if ( txbytes == 0 )
        return(0);
    printf("got txbytes.(%s) opreturn.%d\n",txbytes,opreturnvout);
    if ( opreturnvout >= 0 && opreturnhexstr != 0 && opreturnhexstr[0] != 0 )
    {
        if ( (txbytes2= teleport_OP_RETURN(opreturnvout,txbytes,opreturnhexstr,coin->mgw.oldtx_format)) == 0 )
        {
            fprintf(stderr,"error replacing with OP_RETURN.%s txout.%d (%s)\n",coin->name,opreturnvout,txbytes);
            free(txbytes);
            return(0);
        }
        free(txbytes);
        txbytes = txbytes2, txbytes2 = 0;
        printf("teleport opreturn txbytes.(%s)\n",txbytes);
    }
    array = cJSON_CreateArray();
    cJSON_AddItemToArray(array,cJSON_CreateString(txbytes));
    cJSON_AddItemToArray(array,vinsobj);
    cJSON_AddItemToArray(array,privkeys);
    paramstr = cJSON_Print(array), free_json(array);
    signedtx = calloc(1,strlen(paramstr)*4 + 4096);
    if ( (signedtx= teleport_sign_rawbytes(&completed,signedtx,strlen(signedtx),coin->name,coin->serverport,coin->userpass,paramstr)) != 0 )
    {
        if ( completed == 0 )
        {
            printf("error signing completed.%d (%s)\n",completed,signedtx);
            free(signedtx), signedtx = 0;
        }
    } else fprintf(stderr,"error _sign_localtx.(%s)\n",txbytes);
    free(paramstr);
    return(signedtx);
}

char *teleport_paymentstr(struct coin777 *coin,char *funding,char *paymentaddr,uint64_t payment,char *opreturnhexstr)
{
    int32_t i,n; uint64_t value,change = 0,sum = 0; cJSON *array,*item,*input,*vins,*vouts,*privkeys;
    char *retstr,*changeaddr=0,params[512],buf[1024]; struct telepod pod; struct destbuf acct;
    if ( coin != 0 && payment != 0 && paymentaddr != 0 && paymentaddr[0] != 0 )
    {
        vins = cJSON_CreateObject(), vouts = cJSON_CreateObject(), privkeys = cJSON_CreateObject();
        sprintf(params,"%d, 99999999",coin->minconfirms);
        retstr = bitcoind_passthru(coin->name,coin->serverport,coin->userpass,"listunspent",params);
        if ( retstr != 0 && retstr[0] != 0 && (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = cJSON_GetArrayItem(array,i);
                    copy_cJSON(&acct,cJSON_GetObjectItem(item,"account"));
                    if ( funding == 0 || strcmp(acct.buf,funding) == 0 )
                    {
                        if ( (value= parse_unspent_json(&pod,coin,item)) != 0 )
                        {
                            sum += value;
                            input = cJSON_CreateObject();
                            cJSON_AddItemToObject(input,"txid",cJSON_CreateString(pod.txid));
                            cJSON_AddItemToObject(input,"vout",cJSON_CreateNumber(pod.vout));
                            cJSON_AddItemToArray(vins,input);
                            cJSON_AddItemToArray(privkeys,cJSON_CreateString(pod.privkey));
                            if ( sum >= payment )
                            {
                                if ( sum > payment )
                                {
                                    change = (sum - payment);
                                    sprintf(buf,"[\"%s\"]",funding);
                                    if ( (changeaddr= bitcoind_RPC(0,coin->name,coin->serverport,coin->userpass,"getnewaddress",buf)) == 0 )
                                        payment += change;
                                }
                                cJSON_AddItemToObject(vouts,paymentaddr,cJSON_CreateNumber(dstr(payment)));
                                if ( changeaddr != 0 )
                                    cJSON_AddItemToObject(vouts,changeaddr,cJSON_CreateNumber(dstr(change)));
                                free_json(array), free(retstr);
                                return(teleport_calctransaction(coin,vins,vouts,privkeys,0,opreturnhexstr));
                            }
                        } else fprintf(stderr,"parse_unspent null\n");
                    }
                }
            } free_json(array);
        } free(retstr);
    }
    printf("teleport_paymentstr: cant find enough unspents from (%s)\n",funding!=0?funding:"all accounts");
    return(0);
}

void telepathic_PM(char *destNXT,char *PM)
{
    uint32_t nonce; char *retstr,*jsonstr; cJSON *json = cJSON_CreateObject();
    //./BitcoinDarkd SuperNET '{"plugin":"relay","method":"PM","broadcast":"allnodes","PM":"testms4gff2","destNXT":"NXT-9Q52-L9PY-8C2A-339MB"}'
    cJSON_AddItemToObject(json,"agent",cJSON_CreateString("relay"));
    cJSON_AddItemToObject(json,"method",cJSON_CreateString("PM"));
    cJSON_AddItemToObject(json,"broadcast",cJSON_CreateString("allnodes"));
    cJSON_AddItemToObject(json,"destNXT",cJSON_CreateString(destNXT));
    cJSON_AddItemToObject(json,"PM",cJSON_CreateString(PM));
    jsonstr = cJSON_Print(json), _stripwhite(jsonstr,' '), free_json(json);
    if ( (retstr= busdata_sync(&nonce,jsonstr,"allnodes",destNXT)) != 0 )
        free(retstr);
    free(jsonstr);
}

char *teleport_calctxbytes(char *funding,uint64_t nxt64bits,uint16_t minlockdays,uint16_t maxlockdays,char *invoices,char *peggy,int32_t numunits,char *paymentaddr)
{
    int32_t peggy_calc_opreturn(uint64_t namebits,char *opreturnhexstr,uint64_t nxt64bits,uint16_t minlockdays,uint16_t maxlockdays,char *invoices,int32_t command,int32_t numunits,char *paymentaddr);
    struct coin777 *coin;
    if ( strcmp(peggy,"BTCD") == 0 && (coin= coin777_find(peggy,1)) != 0 )
    {
        if ( funding == 0 )
            funding = "telepods";
        else if ( strcmp(funding,"any") == 0 )
            funding = 0;
        //if ( peggy_calc_opreturn(stringbits(peggy),opreturnhexstr,nxt64bits,minlockdays,maxlockdays,invoices,PEGGY_LOCK,numunits,paymentaddr) == 0 )
        //    return(teleport_paymentstr(coin,funding,paymentaddr,(uint64_t)numunits * SATOSHIDEN,opreturnhexstr));
        //else
        return(clonestr("{\"error\":\"peggy_calc_opreturn errpr\"}"));
    } else return(clonestr("{\"error\":\"only BTCD for now\"}"));
}

void *invoice_iterator(struct kv777 *kv,void *_ptr,void *key,int32_t keysize,void *value,int32_t valuesize)
{
    char numstr[64]; struct invoice_info *invoice = key; cJSON *item,*array = _ptr;
    if ( keysize == sizeof(*invoice) )
    {
        item = cJSON_CreateObject();
        init_hexbytes_noT(numstr,invoice->hash,sizeof(invoice->hash));
        cJSON_AddItemToObject(item,"invoicebits",cJSON_CreateString(numstr));
        cJSON_AddItemToObject(item,"status",cJSON_CreateNumber(*(int32_t *)value));
        cJSON_AddItemToArray(array,item);
        return(0);
    }
    printf("unexpected services entry size.%d/%d vs %d? abort serviceprovider_iterator\n",keysize,valuesize,(int32_t)sizeof(*invoice));
    return(KV777_ABORTITERATOR);
}

cJSON *teleport_invoices(uint8_t *invoicebits)
{
    cJSON *array,*json = cJSON_CreateObject();
    if ( SUPERNET.invoices != 0 )
    {
        array = cJSON_CreateArray();
        kv777_iterate(SUPERNET.invoices,array,0,invoice_iterator);
        cJSON_AddItemToObject(json,"invoices",array);
        return(json);
    }
    return(json);
}

cJSON *teleport_calcinvoicebits(int32_t *nump,uint8_t invoicebits[][32],uint8_t claimbits[][32],cJSON **claimsp,int16_t lockdays,int32_t numunits)
{
    /*int32_t peggy_numinvoices(int32_t numunits);
    int32_t incr,n = 0; cJSON *claims,*invoices; char invoicestr[65],claimstr[65];
    claims = cJSON_CreateArray(), invoices = cJSON_CreateArray();
    for (incr=10000; incr>0; incr/=10)
    {
        while ( numunits >= incr )
        {
            bits777_invoicehash(lockdays,invoicebits[n],claimbits[n]);
            init_hexbytes_noT(claimstr,claimbits[n],32);
            init_hexbytes_noT(invoicestr,invoicebits[n],32);
            cJSON_AddItemToArray(claims,cJSON_CreateString(claimstr));
            cJSON_AddItemToArray(invoices,cJSON_CreateString(invoicestr));
            numunits -= incr, n++;
        }
    }
    *claimsp = claims, *nump = n;
    if ( n != peggy_numinvoices(numunits) )
    {
        printf("teleport_calcinvoicebits: unexpected mismatch.%d != %d\n",n,peggy_numinvoices(numunits));
        free_json(invoices), free_json(claims);
        return(0);
    }
    return(invoices);*/
    return(0);
}

char *teleport_invoicestatus(char *invoicestr)
{
    char *jsonstr; uint8_t invoicebits[1024]; int32_t len; cJSON *json = cJSON_CreateObject();
    cJSON_AddItemToObject(json,"invoicebits",cJSON_CreateString(invoicestr));
    len = (int32_t)strlen(invoicestr) >> 1, decode_hex(invoicebits,len,invoicestr);
    cJSON_AddItemToObject(json,"status",teleport_invoices(invoicebits));
    jsonstr = cJSON_Print(json), _stripwhite(jsonstr,' '), free_json(json);
    return(jsonstr);
}

char *teleport_sendinvoice(cJSON *origjson,char *peggy,int32_t lockdays,int32_t numunits,char *validation,char *paymentaddr,char *destNXT,char *delivery)
{
    uint8_t invoicebits[512][32],claimbits[512][32]; char *jsonstr; cJSON *array,*json,*item,*item2;
    uint64_t nxt64bits; int32_t i,valuesize,numinvoices; uint8_t *value;
    if ( delivery == 0 )
        delivery = "PM";
    if ( strcmp(delivery,"broadcast") == 0 )
        destNXT = GENESISACCT, delivery = "PM";
    if ( peggy != 0 && numunits != 0 && validation != 0 && paymentaddr != 0 )
    {
        json = cJSON_CreateObject(), array = cJSON_CreateArray();
        cJSON_AddItemToArray(array,origjson);
        if ( (item= teleport_calcinvoicebits(&numinvoices,invoicebits,claimbits,&item2,lockdays,numunits)) != 0 )
            cJSON_AddItemToObject(json,"invoices",item), cJSON_AddItemToObject(json,"claims",item2);
        else cJSON_AddItemToObject(json,"error",cJSON_CreateString("cant create invoices"));
        cJSON_AddItemToArray(array,json);
        jsonstr = cJSON_Print(array), _stripwhite(jsonstr,' '), free_json(array);
        if ( item != 0 )
        {
            if ( strcmp(delivery,"PM") == 0 )
            {
                if ( destNXT != 0 && (nxt64bits= conv_acctstr(destNXT)) != 0 )
                {
                    telepathic_PM(destNXT,jsonstr);
                    if ( SUPERNET.invoices != 0 )
                    {
                        valuesize = (int32_t)strlen(jsonstr) + 1;
                        value = calloc(1,valuesize + sizeof(int32_t));
                        memcpy(&value[sizeof(int32_t)],jsonstr,valuesize);
                        for (i=0; i<numinvoices; i++)
                        {
                            if ( kv777_write(SUPERNET.invoices,invoicebits[i],32,value,valuesize + sizeof(int32_t)) == 0 )
                            {
                                free(jsonstr);
                                return(clonestr("{\"error\":\"kv777_write error\"}"));
                            }
                        }
                    }
                }
                else printf("teleport_sendinvoice: warning need destNXT address to send PM\n");
            }
        }
        return(jsonstr);
    }
    else return(clonestr("{\"error\":\"invalid invoice parameter\"}"));
}

char *teleport_sendmoney(char *funding,char *lockNXT,uint16_t minlockdays,uint16_t maxlockdays,char *invoices,char *peggy,int32_t numunits,char *paymentaddr,char *destNXT,char *delivery)
{
    char *txbytes,*jsonstr = 0; uint64_t nxt64bits = 0; cJSON *json = cJSON_CreateObject();
    if ( lockNXT != 0 && lockNXT[0] != 0 )
        nxt64bits = conv_acctstr(lockNXT);
    if ( delivery == 0 )
        delivery = "PM";
    if ( strcmp(delivery,"broadcast") == 0 )
        destNXT = GENESISACCT, delivery = "PM";
    if ( numunits > 0 && (txbytes= teleport_calctxbytes(funding,nxt64bits,minlockdays,maxlockdays,invoices,peggy,numunits,paymentaddr)) != 0 )
    {
        jsonstr = cJSON_Print(json), _stripwhite(jsonstr,' '), free_json(json);
        if ( strcmp(delivery,"PM") == 0 )
        {
            if ( destNXT != 0 && conv_acctstr(destNXT) != 0 )
                telepathic_PM(destNXT,txbytes);
            else printf("teleport_sendinvoice: warning need destNXT address to send PM\n");
        }
        free(txbytes);
    } else jsonstr = clonestr("{\"error\":\"illegal teleport sendmoney parameter\"}");
    return(jsonstr);
}

#define TELEPORT_METHODS "sendinvoice", "sendmoney"
char *PLUGNAME(_methods)[] = { TELEPORT_METHODS };
char *PLUGNAME(_pubmethods)[] = { TELEPORT_METHODS };
char *PLUGNAME(_authmethods)[] = { TELEPORT_METHODS };

uint64_t PLUGNAME(_register)(struct plugin_info *plugin,STRUCTNAME *data,cJSON *argjson)
{
    uint64_t disableflags = 0;
    return(disableflags);
}

int32_t PLUGNAME(_process_json)(char *forwarder,char *sender,int32_t valid,struct plugin_info *plugin,uint64_t tag,char *retbuf,int32_t maxlen,char *jsonstr,cJSON *json,int32_t initflag,char *tokenstr)
{
    char *resultstr,*methodstr,*retstr = 0;
    retbuf[0] = 0;
    //printf("<<<<<<<<<<<< INSIDE PLUGIN! process %s (%s)\n",plugin->name,jsonstr);
    if ( initflag > 0 )
    {
        // configure settings
        TELEPORT.readyflag = 1;
        plugin->allowremote = 1;
        strcpy(retbuf,"{\"result\":\"teleport initialized\"}");
    }
    else
    {
        if ( plugin_result(retbuf,json,tag) > 0 )
            return((int32_t)strlen(retbuf));
        resultstr = cJSON_str(cJSON_GetObjectItem(json,"result"));
        methodstr = cJSON_str(cJSON_GetObjectItem(json,"method"));
        if ( methodstr == 0 || methodstr[0] == 0 )
        {
            printf("(%s) has not method\n",jsonstr);
            return(0);
        }
        printf("TELEPORT.(%s)\n",methodstr);
        if ( resultstr != 0 && strcmp(resultstr,"registered") == 0 )
        {
            plugin->registered = 1;
            strcpy(retbuf,"{\"result\":\"activated\"}");
        }
        else if ( strcmp(methodstr,"sendinvoice") == 0 )
        {
            retstr = teleport_sendinvoice(json,cJSON_str(cJSON_GetObjectItem(json,"peggy")),get_API_int(cJSON_GetObjectItem(json,"lockdays"),DEFAULT_PEGGYDAYS),juint(json,"numunits"),cJSON_str(cJSON_GetObjectItem(json,"validation")),cJSON_str(cJSON_GetObjectItem(json,"paymentaddr")),cJSON_str(cJSON_GetObjectItem(json,"destNXT")),cJSON_str(cJSON_GetObjectItem(json,"delivery")));
        }
        else if ( strcmp(methodstr,"invoicestatus") == 0 )
        {
            retstr = teleport_invoicestatus(cJSON_str(cJSON_GetObjectItem(json,"invoicebits")));
        }
        else if ( strcmp(methodstr,"sendmoney") == 0 )
        {
            retstr = teleport_sendmoney(cJSON_str(cJSON_GetObjectItem(json,"funding")),cJSON_str(cJSON_GetObjectItem(json,"lockNXT")),get_API_int(cJSON_GetObjectItem(json,"minlockdays"),7),get_API_int(cJSON_GetObjectItem(json,"maxlockdays"),255),cJSON_str(cJSON_GetObjectItem(json,"invoicebits")),cJSON_str(cJSON_GetObjectItem(json,"peggy")),juint(json,"numunits"),cJSON_str(cJSON_GetObjectItem(json,"paymentaddr")),cJSON_str(cJSON_GetObjectItem(json,"destNXT")),cJSON_str(cJSON_GetObjectItem(json,"delivery")));
        }
    }
    return(plugin_copyretstr(retbuf,maxlen,retstr));
}

int32_t PLUGNAME(_shutdown)(struct plugin_info *plugin,int32_t retcode)
{
    if ( retcode == 0 )  // this means parent process died, otherwise _process_json returned negative value
    {
    }
    return(retcode);
}

#endif

