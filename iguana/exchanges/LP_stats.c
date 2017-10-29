
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
//  LP_stats.c
//  marketmaker
//

#define LP_STATSLOG_FNAME "stats.log"

struct LP_swapstats
{
    UT_hash_handle hh;
    struct LP_quoteinfo Q;
    bits256 bobdeposit,alicepayment,bobpayment,paymentspent,Apaymentspent,depositspent;
    double qprice;
    uint64_t aliceid;
    uint32_t ind,methodind,finished,expired;
    char alicegui[32],bobgui[32];
} *LP_swapstats;
int32_t LP_statslog_parsequote(char *method,cJSON *lineobj);

char *LP_stats_methods[] = { "unknown", "request", "reserved", "connect", "connected", "tradestatus" };

static uint32_t LP_requests,LP_reserveds,LP_connects,LP_connecteds,LP_tradestatuses,LP_parse_errors,LP_unknowns,LP_duplicates,LP_aliceids;

void LP_tradecommand_log(cJSON *argjson)
{
    static FILE *logfp; char *jsonstr;
    if ( logfp == 0 )
    {
        if ( (logfp= fopen(LP_STATSLOG_FNAME,"rb+")) != 0 )
            fseek(logfp,0,SEEK_END);
        else logfp = fopen(LP_STATSLOG_FNAME,"wb");
    }
    if ( logfp != 0 )
    {
        jsonstr = jprint(argjson,0);
        fprintf(logfp,"%s\n",jsonstr);
        free(jsonstr);
        fflush(logfp);
    }
}

void LP_statslog_parseline(cJSON *lineobj)
{
    char *method; cJSON *obj;
    if ( (method= jstr(lineobj,"method")) != 0 )
    {
        if ( strcmp(method,"request") == 0 )
            LP_requests++;
        else if ( strcmp(method,"reserved") == 0 )
            LP_reserveds++;
        else if ( strcmp(method,"connect") == 0 )
        {
            if ( (obj= jobj(lineobj,"trade")) == 0 )
                obj = lineobj;
            LP_statslog_parsequote(method,obj);
            LP_connects++;
        }
        else if ( strcmp(method,"connected") == 0 )
        {
            LP_statslog_parsequote(method,lineobj);
            LP_connecteds++;
        }
        else if ( strcmp(method,"tradestatus") == 0 )
        {
            LP_statslog_parsequote(method,lineobj);
            LP_tradestatuses++;
        }
        else
        {
            LP_unknowns++;
            printf("parseline unknown method.(%s) (%s)\n",method,jprint(lineobj,0));
        }
    } else printf("parseline no method.(%s)\n",jprint(lineobj,0));
}

int32_t LP_statslog_parse()
{
    static long lastpos; FILE *fp; char line[8192]; cJSON *lineobj; int32_t n = 0;
    if ( (fp= fopen(LP_STATSLOG_FNAME,"rb")) != 0 )
    {
        if ( lastpos > 0 )
        {
            fseek(fp,0,SEEK_END);
            if ( ftell(fp) > lastpos )
                fseek(fp,lastpos,SEEK_SET);
            else
            {
                fclose(fp);
                return(0);
            }
        }
        while ( fgets(line,sizeof(line),fp) > 0 )
        {
            lastpos = ftell(fp);
            if ( (lineobj= cJSON_Parse(line)) != 0 )
            {
                n++;
                LP_statslog_parseline(lineobj);
                //printf("%s\n",jprint(lineobj,0));
                free_json(lineobj);
            }
        }
        fclose(fp);
    }
    return(n);
}

struct LP_swapstats *LP_swapstats_find(uint64_t aliceid)
{
    struct LP_swapstats *sp;
    HASH_FIND(hh,LP_swapstats,&aliceid,sizeof(aliceid),sp);
    return(sp);
}

struct LP_swapstats *LP_swapstats_add(uint64_t aliceid)
{
    struct LP_swapstats *sp;
    if ( (sp= LP_swapstats_find(aliceid)) == 0 )
    {
        sp = calloc(1,sizeof(*sp));
        sp->aliceid = aliceid;
        HASH_ADD(hh,LP_swapstats,aliceid,sizeof(aliceid),sp);
    }
    return(LP_swapstats_find(aliceid));
}

uint64_t LP_aliceid_calc(bits256 desttxid,int32_t destvout,bits256 feetxid,int32_t feevout)
{
    return((((uint64_t)desttxid.uints[0] << 48) | ((uint64_t)destvout << 32) | ((uint64_t)feetxid.uints[0] << 16) | (uint32_t)feevout));
}

void LP_swapstats_line(int32_t *numtrades,uint64_t *basevols,uint64_t *relvols,char *line,struct LP_swapstats *sp)
{
    char tstr[64]; int32_t baseind,relind;
    if ( (baseind= LP_priceinfoind(sp->Q.srccoin)) >= 0 )
        basevols[baseind] += sp->Q.satoshis, numtrades[baseind]++;
    if ( (relind= LP_priceinfoind(sp->Q.destcoin)) >= 0 )
        relvols[relind] += sp->Q.destsatoshis, numtrades[relind]++;
    sprintf(line,"%s (%s).(%s) %-4d %9s %22llu: (%.8f %5s) -> (%.8f %5s) %.8f finished.%u expired.%u",utc_str(tstr,sp->Q.timestamp),sp->alicegui,sp->bobgui,sp->ind,LP_stats_methods[sp->methodind],(long long)sp->aliceid,dstr(sp->Q.satoshis),sp->Q.srccoin,dstr(sp->Q.destsatoshis),sp->Q.destcoin,sp->qprice,sp->finished,sp->expired);
}

bits256 LP_swapstats_txid(cJSON *argjson,char *name,bits256 oldtxid)
{
    bits256 txid,deadtxid;
    decode_hex(deadtxid.bytes,32,"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    txid = jbits256(argjson,name);
    if ( bits256_nonz(txid) != 0 )
    {
        if ( bits256_cmp(deadtxid,txid) == 0 )
        {
            if ( bits256_nonz(oldtxid) == 0 )
                return(deadtxid);
            else return(oldtxid);
        } else return(txid);
    } else return(oldtxid);
}

int32_t LP_swapstats_update(struct LP_swapstats *sp,struct LP_quoteinfo *qp,cJSON *lineobj)
{
    char *statusstr,*base,*rel,gui[64]; uint32_t requestid,quoteid; uint64_t satoshis,destsatoshis;
    safecopy(gui,sp->Q.gui,sizeof(gui));
    if ( strcmp(LP_stats_methods[sp->methodind],"tradestatus") == 0 )
    {
        base = jstr(lineobj,"bob");
        rel = jstr(lineobj,"alice");
        requestid = juint(lineobj,"requestid");
        quoteid = juint(lineobj,"quoteid");
        satoshis = jdouble(lineobj,"srcamount") * SATOSHIDEN;
        destsatoshis = jdouble(lineobj,"destamount") * SATOSHIDEN;
        if ( base != 0 && strcmp(base,sp->Q.srccoin) == 0 && rel != 0 && strcmp(rel,sp->Q.destcoin) == 0 && requestid == sp->Q.R.requestid && quoteid == sp->Q.R.quoteid && ((satoshis+2*sp->Q.txfee)|1) == (sp->Q.satoshis|1) && ((destsatoshis+2*sp->Q.desttxfee)|1) == (sp->Q.destsatoshis|1) )
        {
            sp->bobdeposit = LP_swapstats_txid(lineobj,"bobdeposit",sp->bobdeposit);
            sp->alicepayment = LP_swapstats_txid(lineobj,"alicepayment",sp->alicepayment);
            sp->bobpayment = LP_swapstats_txid(lineobj,"bobpayment",sp->bobpayment);
            sp->paymentspent = LP_swapstats_txid(lineobj,"paymentspent",sp->paymentspent);
            sp->Apaymentspent = LP_swapstats_txid(lineobj,"Apaymentspent",sp->Apaymentspent);
            sp->depositspent = LP_swapstats_txid(lineobj,"depositspent",sp->depositspent);
            if ( (statusstr= jstr(lineobj,"status")) != 0 && strcmp(statusstr,"finished") == 0 )
            {
                if ( (sp->finished= juint(lineobj,"timestamp")) == 0 )
                    sp->finished = (uint32_t)time(NULL);
            }
            if ( sp->finished == 0 && time(NULL) > sp->Q.timestamp+INSTANTDEX_LOCKTIME*2 )
                sp->expired = (uint32_t)time(NULL);
            return(0);
        }
        else
        {
            if ( requestid == sp->Q.R.requestid && quoteid == sp->Q.R.quoteid )
                printf("mismatched tradestatus aliceid.%016llx b%s/%s r%s/%s r%u/%u q%u/%u %.8f/%.8f -> %.8f/%.8f\n",(long long)sp->aliceid,base,sp->Q.srccoin,rel,sp->Q.destcoin,requestid,sp->Q.R.requestid,quoteid,sp->Q.R.quoteid,dstr(satoshis+2*sp->Q.txfee),dstr(sp->Q.satoshis),dstr(destsatoshis+2*sp->Q.desttxfee),dstr(sp->Q.destsatoshis));
            return(-1);
        }
        
    } else sp->Q = *qp;
    if ( sp->Q.gui[0] == 0 || strcmp(sp->Q.gui,"nogui") == 0 )
        strcpy(sp->Q.gui,gui);
    return(0);
}

int32_t LP_statslog_parsequote(char *method,cJSON *lineobj)
{
    static uint32_t unexpected;
    struct LP_swapstats *sp,*tmp; double qprice; uint32_t requestid,quoteid,timestamp; int32_t i,flag,numtrades[LP_MAXPRICEINFOS],methodind,destvout,feevout,duplicate=0; char *gui,*base,*rel; uint64_t aliceid,txfee,satoshis,destsatoshis; bits256 desttxid,feetxid; struct LP_quoteinfo Q; uint64_t basevols[LP_MAXPRICEINFOS],relvols[LP_MAXPRICEINFOS];
    memset(numtrades,0,sizeof(numtrades));
    memset(basevols,0,sizeof(basevols));
    memset(relvols,0,sizeof(relvols));
    memset(&Q,0,sizeof(Q));
    for (i=methodind=0; i<sizeof(LP_stats_methods)/sizeof(*LP_stats_methods); i++)
        if ( strcmp(LP_stats_methods[i],method) == 0 )
        {
            methodind = i;
            break;
        }
    if ( strcmp(method,"tradestatus") == 0 )
    {
        flag = 0;
        aliceid = j64bits(lineobj,"aliceid");
        requestid = juint(lineobj,"requestid");
        quoteid = juint(lineobj,"quoteid");
        if ( (sp= LP_swapstats_find(aliceid)) != 0 )
        {
            sp->methodind = methodind;
            if ( LP_swapstats_update(sp,&Q,lineobj) == 0 )
                flag = 1;
        }
        if ( flag == 0 )
        {
            HASH_ITER(hh,LP_swapstats,sp,tmp)
            {
                if ( sp->Q.R.requestid == requestid && sp->Q.R.quoteid == quoteid )
                {
                    sp->methodind = methodind;
                    if ( LP_swapstats_update(sp,&Q,lineobj) == 0 )
                        flag = 1;
                    else printf("error after delayed match\n");
                    break;
                }
            }
        }
        if ( flag == 0 )
            printf("unexpected.%d tradestatus.(%s)\n",unexpected++,jprint(lineobj,0));
        return(0);
    }
    if ( LP_quoteparse(&Q,lineobj) < 0 )
    {
        printf("quoteparse_error.(%s)\n",jprint(lineobj,0));
        LP_parse_errors++;
        return(-1);
    }
    else
    {
        gui = jstr(lineobj,"gui");
        if ( gui == 0 || gui[0] == 0 )
            gui = "nogui";
        base = jstr(lineobj,"base");
        rel = jstr(lineobj,"rel");
        satoshis = j64bits(lineobj,"satoshis");
        if ( base == 0 || rel == 0 || satoshis == 0 )
        {
            printf("quoteparse_error.(%s)\n",jprint(lineobj,0));
            LP_parse_errors++;
            return(-1);
        }
        txfee = j64bits(lineobj,"txfee");
        timestamp = juint(lineobj,"timestamp");
        destsatoshis = j64bits(lineobj,"destsatoshis");
        desttxid = jbits256(lineobj,"desttxid");
        destvout = jint(lineobj,"destvout");
        feetxid = jbits256(lineobj,"feetxid");
        feevout = jint(lineobj,"feevout");
        qprice = ((double)destsatoshis / (satoshis - txfee));
        //printf("%s/v%d %s/v%d\n",bits256_str(str,desttxid),destvout,bits256_str(str2,feetxid),feevout);
        aliceid =  LP_aliceid_calc(desttxid,destvout,feetxid,feevout);
        if ( (sp= LP_swapstats_find(aliceid)) != 0 )
        {
            if ( methodind > sp->methodind )
            {
                sp->methodind = methodind;
                LP_swapstats_update(sp,&Q,lineobj);
            }
            duplicate = 1;
            LP_duplicates++;
        }
        else
        {
            if ( (sp= LP_swapstats_add(aliceid)) != 0 )
            {
                sp->Q = Q;
                sp->qprice = qprice;
                sp->methodind = methodind;
                sp->ind = LP_aliceids++;
                strcpy(sp->bobgui,"nogui");
                strcpy(sp->alicegui,"nogui");
                //LP_swapstats_line(numtrades,basevols,relvols,line,sp);
                //printf("%s\n",line);
            } else printf("unexpected LP_swapstats_add failure\n");
        }
        if ( sp != 0 )
        {
            if ( strcmp(gui,"nogui") != 0 )
            {
                if ( jint(lineobj,"iambob") != 0 )
                    strcpy(sp->bobgui,gui);
                else strcpy(sp->alicegui,gui);
            }
        }
    }
    return(duplicate == 0);
}

char *LP_statslog_disp(int32_t n,uint32_t starttime,uint32_t endtime,char *refgui,bits256 refpubkey)
{
    cJSON *retjson,*array,*item; struct LP_swapstats *sp,*tmp; int32_t i,dispflag,numtrades[LP_MAXPRICEINFOS]; char line[1024]; uint64_t basevols[LP_MAXPRICEINFOS],relvols[LP_MAXPRICEINFOS];
    if ( starttime > endtime )
        starttime = endtime;
    memset(basevols,0,sizeof(basevols));
    memset(relvols,0,sizeof(relvols));
    memset(numtrades,0,sizeof(numtrades));
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"newlines",n);
    array = cJSON_CreateArray();
    HASH_ITER(hh,LP_swapstats,sp,tmp)
    {
        if ( sp->finished == 0 && time(NULL) > sp->Q.timestamp+INSTANTDEX_LOCKTIME*2 )
            sp->expired = (uint32_t)time(NULL);
        dispflag = 0;
        if ( starttime == 0 && endtime == 0 )
            dispflag = 1;
        else if ( starttime > time(NULL) && endtime == starttime && sp->finished == 0 && sp->expired == 0 )
            dispflag = 1;
        else if ( sp->Q.timestamp >= starttime && sp->Q.timestamp <= endtime )
            dispflag = 1;
        if ( dispflag != 0 )
        {
            dispflag = 0;
            if ( refgui == 0 || refgui[0] == 0 || strcmp(refgui,sp->bobgui) == 0 || strcmp(refgui,sp->alicegui) == 0 )
            {
                if ( bits256_nonz(refpubkey) == 0 || bits256_cmp(refpubkey,sp->Q.srchash) == 0 || bits256_cmp(refpubkey,sp->Q.desthash) == 0 )
                    dispflag = 1;
            }
        }
        if ( dispflag != 0 )
        {
            LP_swapstats_line(numtrades,basevols,relvols,line,sp);
            item = cJSON_CreateObject();
            jadd64bits(item,"aliceid",sp->aliceid);
            jaddbits256(item,"src",sp->Q.srchash);
            jaddstr(item,"base",sp->Q.srccoin);
            jaddnum(item,"basevol",dstr(sp->Q.satoshis));
            jaddbits256(item,"dest",sp->Q.desthash);
            jaddstr(item,"rel",sp->Q.destcoin);
            jaddnum(item,"relvol",dstr(sp->Q.destsatoshis));
            jaddnum(item,"price",sp->qprice);
            jaddnum(item,"requestid",sp->Q.R.requestid);
            jaddnum(item,"quoteid",sp->Q.R.quoteid);
            jaddstr(item,"line",line);
            jaddi(array,item);
        }
    }
    jadd(retjson,"swaps",array);
    array = cJSON_CreateArray();
    for (i=0; i<LP_MAXPRICEINFOS; i++)
    {
        if ( basevols[i] != 0 || relvols[i] != 0 )
        {
            item = cJSON_CreateObject();
            jaddstr(item,"coin",LP_priceinfostr(i));
            jaddnum(item,"srcvol",dstr(basevols[i]));
            jaddnum(item,"destvol",dstr(relvols[i]));
            jaddnum(item,"numtrades",numtrades[i]);
            jaddnum(item,"total",dstr(basevols[i] + relvols[i]));
            jaddi(array,item);
        }
    }
    jadd(retjson,"volumes",array);
    jaddnum(retjson,"request",LP_requests);
    jaddnum(retjson,"reserved",LP_reserveds);
    jaddnum(retjson,"connect",LP_connects);
    jaddnum(retjson,"connected",LP_connecteds);
    jaddnum(retjson,"duplicates",LP_duplicates);
    jaddnum(retjson,"parse_errors",LP_parse_errors);
    jaddnum(retjson,"uniques",LP_aliceids);
    jaddnum(retjson,"tradestatus",LP_tradestatuses);
    jaddnum(retjson,"unknown",LP_unknowns);
    return(jprint(retjson,1));
}


