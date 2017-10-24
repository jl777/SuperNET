
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

uint32_t LP_requests,LP_reserveds,LP_connects,LP_connecteds,LP_tradestatuses,LP_parse_errors,LP_unknowns,LP_duplicates;
uint64_t Ridqids[128];

void LP_statslog_parseline(cJSON *lineobj)
{
    char *method; int32_t i,duplicate; struct LP_quoteinfo Q; uint64_t ridqid;
    if ( (method= jstr(lineobj,"method")) != 0 )
    {
        if ( strcmp(method,"request") == 0 )
            LP_requests++;
        else if ( strcmp(method,"reserved") == 0 )
            LP_reserveds++;
        else if ( strcmp(method,"connect") == 0 )
            LP_connects++;
        else if ( strcmp(method,"connected") == 0 )
        {
            memset(&Q,0,sizeof(Q));
            if ( LP_quoteparse(&Q,lineobj) < 0 )
            {
                printf("quoteparse_error.(%s)\n",jprint(lineobj,0));
                LP_parse_errors++;
            }
            else
            {
                ridqid = (((uint64_t)Q.R.requestid << 32) | Q.R.quoteid);
                for (i=duplicate=0; i<sizeof(Ridqids)/sizeof(*Ridqids); i++)
                {
                    if ( Ridqids[i] == ridqid )
                    {
                        duplicate = 1;
                        LP_duplicates++;
                        break;
                    }
                }
                if ( duplicate == 0 )
                {
                    Ridqids[LP_connecteds % (sizeof(Ridqids)/sizeof(*Ridqids))] = ridqid;
                    printf("connected requestid.%u quoteid.%u -> %d\n",Q.R.requestid,Q.R.quoteid,(int32_t)(LP_connecteds % (sizeof(Ridqids)/sizeof(*Ridqids))));
                }
            }
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
    cJSON *retjson;
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"newlines",n);
    jaddnum(retjson,"request",LP_requests);
    jaddnum(retjson,"reserved",LP_reserveds);
    jaddnum(retjson,"connect",LP_connects);
    jaddnum(retjson,"connected",LP_connecteds);
    jaddnum(retjson,"duplicates",LP_duplicates);
    jaddnum(retjson,"parse_errors",LP_parse_errors);
    jaddnum(retjson,"uniques",LP_connecteds-LP_duplicates);
    jaddnum(retjson,"tradestatus",LP_tradestatuses);
    jaddnum(retjson,"unknown",LP_unknowns);
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


