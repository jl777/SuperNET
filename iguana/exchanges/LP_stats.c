
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

char *LP_stats_methods[] = { "unknown", "request", "reserved", "connect", "connected", "tradestatus" };

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

static uint32_t LP_requests,LP_reserveds,LP_connects,LP_connecteds,LP_tradestatuses,LP_parse_errors,LP_unknowns,LP_duplicates,LP_aliceids;

struct LP_swapstats
{
    UT_hash_handle hh;
    struct LP_quoteinfo Q;
    double qprice;
    uint64_t aliceid;
    uint32_t ind,methodind;
} *LP_swapstats;

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

void LP_swapstats_line(char *line,struct LP_swapstats *sp)
{
    char tstr[64];
    sprintf(line,"%s %8s %-4d %9s swap.%016llx: (%.8f %5s) -> (%.8f %5s) qprice %.8f",utc_str(tstr,sp->Q.timestamp),sp->Q.gui,sp->ind,LP_stats_methods[sp->methodind],(long long)sp->aliceid,dstr(sp->Q.satoshis),sp->Q.srccoin,dstr(sp->Q.destsatoshis),sp->Q.destcoin,sp->qprice);
}

void LP_swapstats_update(struct LP_swapstats *sp,struct LP_quoteinfo *qp,cJSON *lineobj)
{
    
}

int32_t LP_statslog_parsequote(char *method,cJSON *lineobj)
{
    struct LP_swapstats *sp; double qprice; uint32_t timestamp; int32_t i,methodind,destvout,feevout,duplicate=0; char *gui,*base,*rel,line[1024]; uint64_t aliceid,txfee,satoshis,destsatoshis; bits256 desttxid,feetxid; struct LP_quoteinfo Q;
    memset(&Q,0,sizeof(Q));
    if ( LP_quoteparse(&Q,lineobj) < 0 )
    {
        printf("quoteparse_error.(%s)\n",jprint(lineobj,0));
        LP_parse_errors++;
        return(-1);
    }
    else
    {
        for (i=methodind=0; i<sizeof(LP_stats_methods)/sizeof(*LP_stats_methods); i++)
            if ( strcmp(LP_stats_methods[i],method) == 0 )
            {
                methodind = i;
                break;
            }
        base = jstr(lineobj,"base");
        rel = jstr(lineobj,"rel");
        gui = jstr(lineobj,"gui");
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
            if ( methodind > sp->methodind || strcmp(method,"tradestatus") == 0 )
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
                LP_swapstats_line(line,sp);
                printf("%s\n",line);
            } else printf("unexpected LP_swapstats_add failure\n");
        }
    }
    return(duplicate == 0);
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
            LP_tradestatuses++;
        else
        {
            LP_unknowns++;
            printf("parseline unknown method.(%s) (%s)\n",method,jprint(lineobj,0));
        }
   } else printf("parseline no method.(%s)\n",jprint(lineobj,0));
}

char *LP_statslog_disp(int32_t n)
{
    cJSON *retjson,*array; struct LP_swapstats *sp,*tmp; char line[1024];
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"newlines",n);
    jaddnum(retjson,"request",LP_requests);
    jaddnum(retjson,"reserved",LP_reserveds);
    jaddnum(retjson,"connect",LP_connects);
    jaddnum(retjson,"connected",LP_connecteds);
    jaddnum(retjson,"duplicates",LP_duplicates);
    jaddnum(retjson,"parse_errors",LP_parse_errors);
    jaddnum(retjson,"uniques",LP_aliceids);
    jaddnum(retjson,"tradestatus",LP_tradestatuses);
    jaddnum(retjson,"unknown",LP_unknowns);
    array = cJSON_CreateArray();
    HASH_ITER(hh,LP_swapstats,sp,tmp)
    {
        LP_swapstats_line(line,sp);
        jaddistr(array,line);
    }
    jadd(retjson,"swaps",array);
    return(jprint(retjson,1));
}

char *LP_statslog_parse()
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
                return(clonestr("{\"result\":\"success\",\"newlines\":0}"));
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
    return(LP_statslog_disp(n));
}


