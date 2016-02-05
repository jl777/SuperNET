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

#define EXCHANGE_NAME "fxcm"
#define UPDATE fxcm ## _price
#define SUPPORTS fxcm ## _supports
#define SIGNPOST fxcm ## _signpost
#define TRADE fxcm ## _trade
#define ORDERSTATUS fxcm ## _orderstatus
#define CANCELORDER fxcm ## _cancelorder
#define OPENORDERS fxcm ## _openorders
#define TRADEHISTORY fxcm ## _tradehistory
#define BALANCES fxcm ## _balances
#define PARSEBALANCE fxcm ## _parsebalance
#define WITHDRAW fxcm ## _withdraw
#define CHECKBALANCE fxcm ## _checkbalance
#define ALLPAIRS fxcm ## _allpairs
#define FUNCS fxcm ## _funcs
#define BASERELS fxcm ## _baserels

static char **FXCM_contracts; static int num_FXCM;

char *fxcm_xmlstr()
{
    char *xmlstr; int32_t i,j,k;
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
    }
    return(xmlstr);
}

int32_t fxcm_setcontracts()
{
    int32_t i,n,flag,num = 0; cJSON *json,*obj; char name[32],*str,*xmlstr = fxcm_xmlstr();
    if ( xmlstr != 0 )
    {
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
                if ( FXCM_contracts != 0 )
                {
                    for (i=0; i<num_FXCM; i++)
                    {
                        if ( FXCM_contracts[i] == 0 )
                            break;
                        free(FXCM_contracts[i]);
                    }
                    free(FXCM_contracts);
                }
                FXCM_contracts = calloc(n+1,sizeof(*FXCM_contracts));
                for (i=0; i<n; i++)
                {
                    obj = jitem(json,i);
                    flag = 0;
                    if ( (str= jstr(obj,"Symbol")) != 0 && strlen(str) < 15 )
                    {
                        strcpy(name,str);
                        touppercase(name);
                        if ( strcmp(name,"USDCNH") == 0 )
                            strcpy(name,"USDCNY");
                        FXCM_contracts[num++] = clonestr(name);
                    }
                }
            }
        }
        free(xmlstr);
    }
    return(num);
}

int32_t fxcm_ensure()
{
    if ( num_FXCM == 0 || FXCM_contracts == 0 )
        num_FXCM = fxcm_setcontracts();
    if ( FXCM_contracts == 0 )
        return(-1);
    else return(0);
}

char *ALLPAIRS(struct exchange_info *exchange,cJSON *argjson)
{
    int32_t i,c,n; char base[32],rel[32]; cJSON *json,*item,*array = cJSON_CreateArray();
    if ( fxcm_ensure() == 0 )
    {
        for (i=0; i<num_FXCM; i++)
        {
            if ( strcmp("COPPER",FXCM_contracts[i]) != 0 && (n= (int32_t)strlen(FXCM_contracts[i])) == 6 && ((c= FXCM_contracts[i][n-1]) < '0' || c > '9') )
            {
                strcpy(base,FXCM_contracts[i]);
                strcpy(rel,FXCM_contracts[i] + 3);
                base[3] = rel[3] = 0;
                touppercase(base), touppercase(rel);
            }
            else if ( strcmp(FXCM_contracts[i],"USDOLLAR") == 0 || strcmp(FXCM_contracts[i],"BUND") == 0 || ((c= FXCM_contracts[i][n-1]) >= '0' && c <= '9') )
            {
                strcpy(base,FXCM_contracts[i]), touppercase(base);
                rel[0] = 0;
            }
            else
            {
                strcpy(base,FXCM_contracts[i]), touppercase(base);
                strcpy(rel,"USD");
            }
            item = cJSON_CreateArray();
            jaddistr(item,base);
            jaddistr(item,rel);
            jaddi(array,item);
        }
        json = cJSON_CreateObject();
        jadd(json,"result",array);
        return(jprint(json,1));
    } else return(clonestr("{\"error\":\"cant find FXCM contracts\"}"));
}

int32_t SUPPORTS(struct exchange_info *exchange,char *_base,char *_rel,cJSON *argjson)
{
    int32_t i; char contract[32],revcontract[32],base[32],rel[32];
    if ( fxcm_ensure() == 0 && num_FXCM > 0 && FXCM_contracts != 0 )
    {
        strcpy(base,_base), strcpy(rel,_rel);
        touppercase(base), touppercase(rel);
        sprintf(contract,"%s%s",base,rel), touppercase(contract);
        sprintf(revcontract,"%s%s",rel,base), touppercase(revcontract);
        for (i=0; i<num_FXCM; i++)
        {
            if ( strcmp(contract,FXCM_contracts[i]) == 0 )
                return(1);
            else if ( strcmp(revcontract,FXCM_contracts[i]) == 0 )
                return(-1);
        }
    }
    return(0);
}

void prices777_fxcm(double bids[64],double asks[64],double highs[64],double lows[64])
{
    char name[64],*str,*xmlstr; cJSON *json,*obj; int32_t i,c,flag,n = 0; double bid,ask,high,low; struct destbuf numstr;
    memset(bids,0,sizeof(*bids) * 64), memset(asks,0,sizeof(*asks) * 64);
    memset(highs,0,sizeof(*highs) * 64), memset(lows,0,sizeof(*lows) * 64);
    if ( fxcm_ensure() < 0 )
        return;
    if ( (xmlstr= fxcm_xmlstr()) != 0 )
    {
        if ( (json= cJSON_Parse(xmlstr)) != 0 )
        {
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
                        if ( (c= strsearch(FXCM_contracts,num_FXCM,name)) >= 0 )
                        {
                            bids[c] = bid, asks[c] = ask, highs[c] = high, lows[c] = low;
                            //printf("c.%d (%s) %f %f\n",c,name,bid,ask);
                            flag = 1;
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
}

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *bidasks,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert)
{
    double bid,ask,bids[64],asks[64],highs[64],lows[64]; int32_t numbids,numasks,c; char name[32];
    if ( fxcm_ensure() == 0 )
    {
        strcpy(name,base), strcat(name,rel), touppercase(name);
        if ( (c= strsearch(FXCM_contracts,num_FXCM,name)) >= 0 )
        {
            prices777_fxcm(bids,asks,highs,lows);
            numbids = numasks = 0;
            bid = exchange_setquote(bidasks,&numbids,&numasks,0,invert,bids[c],1,commission,0,(uint32_t)time(NULL),0);
            ask = exchange_setquote(bidasks,&numbids,&numasks,1,invert,asks[c],1,commission,0,(uint32_t)time(NULL),0);
            if ( bid > SMALLVAL && ask > SMALLVAL )
                return((bid + ask) * .5);
        }
    }
    return(0);
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *payload,char *path)
{
    if ( retstrp != 0 )
        *retstrp = clonestr("{\"error\":\"fxcm is readonly data source\"}");
    return(cJSON_Parse("{}"));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"fxcm is readonly data source\"}"));
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    return(cJSON_Parse("{\"error\":\"fxcm is readonly data source\"}"));
}

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    return(0);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"fxcm is readonly data source\"}"));
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"fxcm is readonly data source\"}"));
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"fxcm is readonly data source\"}"));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"fxcm is readonly data source\"}"));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"fxcm is readonly data source\"}"));
}

struct exchange_funcs fxcm_funcs = EXCHANGE_FUNCS(fxcm,EXCHANGE_NAME);

#include "exchange_undefs.h"
