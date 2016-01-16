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

#include "iguana777.h"
#include "SuperNET.h"

cJSON *helpjson(cJSON *json,cJSON *array,cJSON *agents,char *agentstr,char *method,cJSON *methodargs)
{
    cJSON *methodobj,*item; int32_t i,n; char url[2048],curl[2048];
    /*if ( *agentstrp == 0 || strcmp(*agentstrp,agentstr) != 0 )
    {
        if ( array != 0 )
            jadd(json,*agentstrp,array);
        *agentstrp = agentstr;
        jaddistr(agents,agentstr);
        printf("add agent.(%s)\n",agentstr);
    }*/
    if ( (n= cJSON_GetArraySize(agents)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(agents,i);
            if ( strcmp(agentstr,jstr(item,0)) == 0 )
                break;
        }
    } else i = 0;
    if ( i == n )
        jaddistr(agents,agentstr);
    if ( array == 0 )
        array = cJSON_CreateArray();
    methodobj = cJSON_CreateObject();
    jaddstr(methodobj,"agent",agentstr);
    jaddstr(methodobj,"method",method);
    sprintf(url,"http://127.0.0.1:7778/api/%s/%s",agentstr,method);
    sprintf(curl,"curl --url \"http://127.0.0.1:7778\" --data \"{\"agent\":\"%s\",\"method\":\"%s\"",agentstr,method);
    if ( methodargs != 0 && (n= cJSON_GetArraySize(methodargs)) > 0 )
    {
        //printf("method.%s n.%d %s\n",method,n,jprint(methodargs,0));
        for (i=0; i<n; i++)
        {
            strcat(url,i==0?"?":"&");
            item = jitem(methodargs,i);
            sprintf(url+strlen(url),"%s={%s}",get_cJSON_fieldname(item),jstr(item,get_cJSON_fieldname(item)));
            sprintf(curl+strlen(curl),",\"%s\":\"{%s}\"",get_cJSON_fieldname(item),jstr(item,get_cJSON_fieldname(item)));
        }
    }
    strcat(curl,"}\"");
    jaddstr(methodobj,"url",url);
    jaddstr(methodobj,"curl",curl);
    jadd(methodobj,"fields",methodargs==0?cJSON_CreateArray():methodargs);
    jaddi(array,methodobj);
    return(array);
}

cJSON *helpitem(char *field,char *type) { cJSON *obj = cJSON_CreateObject(); jaddstr(obj,field,type); return(obj); }
cJSON *helparray(cJSON *array,cJSON *obj0) { jaddi(array,obj0); return(array);}
cJSON *helparray2(cJSON *array,cJSON *obj0,cJSON *obj1) { jaddi(array,obj0); return(helparray(array,obj1)); }
cJSON *helparray3(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2) { jaddi(array,obj0); return(helparray2(array,obj1,obj2)); }
cJSON *helparray4(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2,cJSON *obj3) { jaddi(array,obj0); return(helparray3(array,obj1,obj2,obj3)); }
cJSON *helparray5(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2,cJSON *obj3,cJSON *obj4) { jaddi(array,obj0); return(helparray4(array,obj1,obj2,obj3,obj4)); }
cJSON *helparray6(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2,cJSON *obj3,cJSON *obj4,cJSON *obj5) { jaddi(array,obj0); return(helparray5(array,obj1,obj2,obj3,obj4,obj5)); }

cJSON *SuperNET_helpjson()
{
    cJSON *array=0,*json,*agents;
    json = cJSON_CreateObject();
    agents = cJSON_CreateArray();
#define IGUANA_ARGS json,array,agents
#define IGUANA_HELP0(agent,name) array = helpjson(IGUANA_ARGS,#agent,#name,0)
#define IGUANA_HELP_S(agent,name,str) array = helpjson(IGUANA_ARGS,#agent,#name,helparray(cJSON_CreateArray(),helpitem(#str,"string")))
#define IGUANA_HELP_SS(agent,name,str,str2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string")))
#define IGUANA_HELP_SSS(agent,name,str,str2,str3) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#str3,"string")))
#define IGUANA_HELP_SI(agent,name,str,val) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#val,"int")))
#define IGUANA_HELP_SII(agent,name,str,val,val2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#val,"int"),helpitem(#val2,"int")))
#define IGUANA_HELP_SSI(agent,name,str,str2,val) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#val,"int")))
#define IGUANA_HELP_SA(agent,name,str,obj) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#obj,"array")))
#define IGUANA_HELP_SAA(agent,name,str,obj,obj2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#obj,"array"),helpitem(#obj2,"array")))
#define IGUANA_HELP_SIII(agent,name,str,val,val2,val3) array = helpjson(IGUANA_ARGS,#agent,#name,helparray4(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#val,"int"),helpitem(#val2,"int"),helpitem(#val3,"int")))
    
#define IGUANA_HELP_I(agent,name,val) array = helpjson(IGUANA_ARGS,#agent,#name,helparray(cJSON_CreateArray(),helpitem(#val,"int")))
#define IGUANA_HELP_II(agent,name,val,val2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#val,"int"),helpitem(#val2,"int")))
#define IGUANA_HELP_IA(agent,name,val,obj) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#val,"int"),helpitem(#obj,"array")))
#define IGUANA_HELP_IIA(agent,name,val,val2,obj) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#val,"int"),helpitem(#val2,"int"),helpitem(#obj,"array")))
#define IGUANA_HELP_III(agent,name,val,val2,val3) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#val,"int"),helpitem(#val2,"int"),helpitem(#val3,"int")))
#define IGUANA_HELP_IAS(agent,name,val,obj,str) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#val,"int"),helpitem(#obj,"array"),helpitem(#str,"string")))
    
#define IGUANA_HELP_AA(agent,name,obj,obj2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#obj,"array"),helpitem(#obj2,"array")))
#define IGUANA_HELP_D(agent,name,amount) array = helpjson(IGUANA_ARGS,#agent,#name,helparray(cJSON_CreateArray(),helpitem(#amount,"float")))
    
#define IGUANA_HELP_HI(agent,name,hash,val) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#hash,"hash"),helpitem(#val,"int")))
#define IGUANA_HELP_HII(agent,name,hash,val,val2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#hash,"hash"),helpitem(#val,"int"),helpitem(#val2,"int")))
    
#define IGUANA_HELP_SSDIS(agent,name,str,str2,amount,val,str3) array = helpjson(IGUANA_ARGS,#agent,#name,helparray5(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#amount,"float"),helpitem(#val,"int"),helpitem(#str3,"string")))
#define IGUANA_HELP_SSDISS(agent,name,str,str2,amount,val,str3,str4) array = helpjson(IGUANA_ARGS,#agent,#name,helparray6(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#amount,"float"),helpitem(#val,"int"),helpitem(#str3,"string"),helpitem(#str4,"string")))
#define IGUANA_HELP_SAIS(agent,name,str,obj,val,str2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray4(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#obj,"array"),helpitem(#val,"int"),helpitem(#str2,"string")))
#define IGUANA_HELP_SDSS(agent,name,str,amount,str2,str3) array = helpjson(IGUANA_ARGS,#agent,#name,helparray4(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#amount,"float"),helpitem(#str2,"string"),helpitem(#str3,"string")))
    
    // API functions
#define ZERO_ARGS IGUANA_HELP0
#define INT_ARG IGUANA_HELP_I
#define TWO_INTS IGUANA_HELP_II
#define STRING_ARG IGUANA_HELP_S
#define TWO_STRINGS IGUANA_HELP_SS
#define THREE_STRINGS IGUANA_HELP_SSS
#define STRING_AND_INT IGUANA_HELP_SI
#define STRING_AND_TWOINTS IGUANA_HELP_SII
#define HASH_AND_INT IGUANA_HELP_HI
#define HASH_AND_TWOINTS IGUANA_HELP_HII
#define DOUBLE_ARG IGUANA_HELP_D
#define STRING_AND_ARRAY IGUANA_HELP_SA
#define STRING_AND_TWOARRAYS IGUANA_HELP_SAA
#define TWO_ARRAYS IGUANA_HELP_AA
#define INT_AND_ARRAY IGUANA_HELP_IA
#define INT_ARRAY_STRING IGUANA_HELP_IAS
#define SS_D_I_S IGUANA_HELP_SSDIS
#define SS_D_I_SS IGUANA_HELP_SSDISS
#define S_A_I_S IGUANA_HELP_SAIS
#define S_D_SS IGUANA_HELP_SDSS
#define TWOINTS_AND_ARRAY IGUANA_HELP_IIA
#define STRING_AND_THREEINTS IGUANA_HELP_SIII
#define TWOSTRINGS_AND_INT IGUANA_HELP_SSI
#define THREE_INTS IGUANA_HELP_III
    
#include "../includes/iguana_apideclares.h"
#undef IGUANA_ARGS
    
#include "../includes/iguana_apiundefs.h"
    if ( array != 0 )
        jadd(json,"API",array);
    jadd(json,"agents",agents);
    return(json);
}

int32_t agentform(FILE *fp,char *form,int32_t max,char *agent,cJSON *methoditem)
{
    cJSON *item,*fieldsarray; int32_t j,m,width,size = 0;
    char *methodstr,*typestr,outstr[2048],outstr2[2048],fields[8192],str[2],agent_method[256],*fieldname;
    form[0] = 0;
    if ( (methodstr= jstr(methoditem,"method")) == 0 )
        methodstr = "method";
    if ( agent == 0 )
        agent = "agent";
    outstr[0] = outstr2[0] = 0;
    str[1] = 0;
    fields[0] = 0;
    sprintf(agent_method,"%s %s",agent,methodstr);
    if ( (fieldsarray= jarray(&m,methoditem,"fields")) != 0 )
    {
        for (j=0; j<m; j++)
        {
            item = jitem(fieldsarray,j);
            fieldname = get_cJSON_fieldname(item);
           // printf("item.(%s) %s\n",jprint(item,0),jstr(item,fieldname));
            if ( (typestr= jstr(item,fieldname)) != 0 )
            {
                if ( strcmp(typestr,"string") == 0 )
                    width = 44;
                else if ( strcmp(typestr,"hash") == 0 )
                    width = 65;
                else if ( strcmp(typestr,"int") == 0 )
                    width = 8;
                else if ( strcmp(typestr,"float") == 0 )
                    width = 16;
                else width = 0;
            }
            //sprintf(buf,"<input type=\"text\" name=\"%s\"/>",fieldname);
            // sprintf(buf,"<textarea cols=\"%d\" rows=\"%d\"  name=\"%s\" %s></textarea>",
            sprintf(fields+strlen(fields),"<b>%s</b> %s <textarea name=\"%s\" rows=\"1\" cols=\"%d\" %s></textarea>",j==0?agent_method:"",fieldname,fieldname,width,fieldname);
            if ( j > 0 )
            {
                strcat(outstr,"+");
                strcat(outstr2," ");
            }
            strcat(outstr,fieldname);
            strcat(outstr2,fieldname);
            //printf("fields[%d] (%s)\n",j,fields);
        }
    } else sprintf(fields+strlen(fields),"<b>%s</b> <textarea rows=\"0\" cols=\"0\"></textarea>",agent_method);
    sprintf(&form[size],"<form action=\"http://127.0.0.1:7778/api/%s/%s\" oninput=\"%s\">%s<output for=\"%s\"></output><input type=\"submit\" value=\"%s\"></form>",agent,methodstr,outstr,fields,outstr2,methodstr);
    if ( fp != 0 )
        fprintf(fp,"<form action=\"http://127.0.0.1:7778/api/%s/%s\" oninput=\"%s\">%s<output for=\"%s\"></output><input type=\"submit\" value=\"%s\"></form>",agent,methodstr,outstr,fields,outstr2,methodstr);
    return((int32_t)strlen(form));
}

/*<form action="action_page.asp"
 oninput="x.value=parseInt(a.value)+parseInt(b.value)">
 0
 <input type="range"  id="a" name="a" value="50">
 100 +
 <input type="number" id="b" name="b" value="50">
 =
 <output name="x" for="a b"></output>
 <br><br>
 <input type="submit">
 </form>*/

char *SuperNET_htmlstr(FILE *fp,char *htmlstr,int32_t max,char *agentstr)
{
    int32_t i,n,len,size = 0; cJSON *helpjson,*item,*array; char *str;
    htmlstr[0] = 0;
    sprintf(htmlstr,"<!DOCTYPE HTML><html> <head><title>SuperUGLY GUI></title></head> <body> ");
    if ( fp != 0 )
        fprintf(fp,"%s\n",htmlstr);
    size = (int32_t)strlen(htmlstr);
    if ( (helpjson= SuperNET_helpjson()) != 0 )
    {
        if ( (array= jarray(&n,helpjson,"API")) != 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                str = jstr(item,"agent");
                if ( agentstr == 0 || agentstr[0] == 0 || (str != 0 && strcmp(str,agentstr) == 0) )
                {
                    len = agentform(fp,&htmlstr[size],max - size,str!=0?str:"agent",item);
                    size += len;
                } //else printf("agentstr.%p (%s) (%s) str.%p \n",agentstr,agentstr,str,str);
            }
        }
        free_json(helpjson);
    }
    strcat(htmlstr,"<br><br/></body></html><br><br/>");
    if ( fp != 0 )
        fprintf(fp,"<br><br/></body></html><br><br/>\n");
    return(htmlstr);
}

cJSON *iguana_peerjson(struct iguana_info *coin,struct iguana_peer *addr)
{
    cJSON *array,*json = cJSON_CreateObject();
    jaddstr(json,"ipaddr",addr->ipaddr);
    jaddnum(json,"protover",addr->protover);
    jaddnum(json,"relay",addr->relayflag);
    jaddnum(json,"height",addr->height);
    jaddnum(json,"rank",addr->rank);
    jaddnum(json,"usock",addr->usock);
    if ( addr->dead != 0 )
        jaddnum(json,"dead",addr->dead);
    jaddnum(json,"ready",addr->ready);
    jaddnum(json,"recvblocks",addr->recvblocks);
    jaddnum(json,"recvtotal",addr->recvtotal);
    jaddnum(json,"lastcontact",addr->lastcontact);
    if ( addr->numpings > 0 )
        jaddnum(json,"aveping",addr->pingsum/addr->numpings);
    array = cJSON_CreateObject();
    jaddnum(array,"version",addr->msgcounts.version);
    jaddnum(array,"verack",addr->msgcounts.verack);
    jaddnum(array,"getaddr",addr->msgcounts.getaddr);
    jaddnum(array,"addr",addr->msgcounts.addr);
    jaddnum(array,"inv",addr->msgcounts.inv);
    jaddnum(array,"getdata",addr->msgcounts.getdata);
    jaddnum(array,"notfound",addr->msgcounts.notfound);
    jaddnum(array,"getblocks",addr->msgcounts.getblocks);
    jaddnum(array,"getheaders",addr->msgcounts.getheaders);
    jaddnum(array,"headers",addr->msgcounts.headers);
    jaddnum(array,"tx",addr->msgcounts.tx);
    jaddnum(array,"block",addr->msgcounts.block);
    jaddnum(array,"mempool",addr->msgcounts.mempool);
    jaddnum(array,"ping",addr->msgcounts.ping);
    jaddnum(array,"pong",addr->msgcounts.pong);
    jaddnum(array,"reject",addr->msgcounts.reject);
    jaddnum(array,"filterload",addr->msgcounts.filterload);
    jaddnum(array,"filteradd",addr->msgcounts.filteradd);
    jaddnum(array,"filterclear",addr->msgcounts.filterclear);
    jaddnum(array,"merkleblock",addr->msgcounts.merkleblock);
    jaddnum(array,"alert",addr->msgcounts.alert);
    jadd(json,"msgcounts",array);
    return(json);
}

cJSON *iguana_peersjson(struct iguana_info *coin,int32_t addronly)
{
    cJSON *retjson,*array; int32_t i; struct iguana_peer *addr;
    if ( coin == 0 )
        return(0);
    array = cJSON_CreateArray();
    for (i=0; i<coin->MAXPEERS; i++)
    {
        addr = &coin->peers.active[i];
        if ( addr->usock >= 0 && addr->ipbits != 0 && addr->ipaddr[0] != 0 )
        {
            if ( addronly != 0 )
                jaddistr(array,addr->ipaddr);
            else jaddi(array,iguana_peerjson(coin,addr));
        }
    }
    if ( addronly == 0 )
    {
        retjson = cJSON_CreateObject();
        jadd(retjson,"peers",array);
        jaddnum(retjson,"maxpeers",coin->MAXPEERS);
        jaddstr(retjson,"coin",coin->symbol);
        return(retjson);
    }
    else return(array);
}

cJSON *SuperNET_peerarray(struct iguana_info *coin,int32_t max,int32_t supernetflag)
{
    int32_t i,r,j,n = 0; struct iguana_peer *addr; cJSON *array = cJSON_CreateArray();
    r = rand();
    for (j=0; j<IGUANA_MAXPEERS; j++)
    {
        i = (r + j) % IGUANA_MAXPEERS;
        addr = &coin->peers.active[i];
        if ( addr->usock >= 0 && supernetflag == (addr->supernet != 0) )
        {
            jaddistr(array,addr->ipaddr);
            if ( ++n >= max )
                break;
        }
    }
    if ( n == 0 )
    {
        free_json(array);
        return(0);
    }
    return(array);
}

int32_t SuperNET_coinpeers(struct iguana_info *coin,cJSON *SNjson,cJSON *rawjson,int32_t max)
{
    cJSON *array,*item;
    if ( (array= SuperNET_peerarray(coin,max,1)) != 0 )
    {
        max -= cJSON_GetArraySize(array);
        item = cJSON_CreateObject();
        jadd(item,"coin",coin->symbol);
        jadd(item,"peers",array);
        jaddi(SNjson,item);
    }
    if ( max > 0 && (array= SuperNET_peerarray(coin,max,0)) != 0 )
    {
        max -= cJSON_GetArraySize(array);
        item = cJSON_CreateObject();
        jadd(item,"coin",coin->symbol);
        jadd(item,"peers",array);
        jaddi(rawjson,item);
    }
    return(max);
}

void SuperNET_remotepeer(struct supernet_info *myinfo,struct iguana_info *coin,char *symbol,char *ipaddr,int32_t supernetflag)
{
    printf("got %s remotepeer.(%s) supernet.%d\n",symbol,ipaddr,supernetflag);
}

void SuperNET_parsepeers(struct supernet_info *myinfo,cJSON *array,int32_t n,int32_t supernetflag)
{
    int32_t i,j,m; cJSON *coinarray,*item; char *symbol,*ipaddr; struct iguana_info *ptr;
    if ( array != 0 && n > 0 )
    {
        for (i=0; i<n; i++)
        {
            if ( (item= jitem(array,i)) != 0 && (symbol= jstr(item,"coin")) != 0 )
            {
                ptr = iguana_coinfind(symbol);
                if ( (coinarray= jarray(&m,item,"peers")) != 0 )
                {
                    for (j=0; j<m; j++)
                    {
                        if ( (ipaddr= jstr(jitem(coinarray,j),0)) != 0 )
                            SuperNET_remotepeer(myinfo,ptr,symbol,ipaddr,supernetflag);
                        else printf("no ipaddr[%d] of %d\n",j,m);
                    }
                }
                printf("parsed.%d %s.peers supernet.%d\n",m,symbol,supernetflag);
            }
        }
    }
}

#include "../includes/iguana_apidefs.h"

TWO_ARRAYS(SuperNET,mypeers,supernet,rawpeers)
{
    SuperNET_parsepeers(myinfo,supernet,cJSON_GetArraySize(supernet),1);
    SuperNET_parsepeers(myinfo,rawpeers,cJSON_GetArraySize(rawpeers),0);
    return(clonestr("{\"result\":\"peers parsed\"}"));
}

STRING_ARG(SuperNET,getpeers,activecoin)
{
    int32_t i,max = 64;
    cJSON *SNjson,*rawjson,*retjson = cJSON_CreateObject();
    SNjson = cJSON_CreateArray();
    rawjson = cJSON_CreateArray();
    if ( coin != 0 )
        max = SuperNET_coinpeers(coin,SNjson,rawjson,max);
    else
    {
        for (i=0; i<IGUANA_MAXCOINS&&max>0; i++)
            if ( Coins[i] != 0 )
                max = SuperNET_coinpeers(Coins[i],SNjson,rawjson,max);
    }
    if ( max != 64 )
    {
        jaddstr(retjson,"agent","SuperNET");
        jaddstr(retjson,"method","mypeers");
        jadd(retjson,"supernet",SNjson);
        jadd(retjson,"rawpeers",rawjson);
    }
    else
    {
        jaddstr(retjson,"error","no peers");
        free_json(SNjson);
        free_json(rawjson);
    }
    return(jprint(retjson,1));
}

STRING_ARG(iguana,peers,activecoin)
{
    if ( coin != 0 )
        return(jprint(iguana_peersjson(coin,0),1));
    else return(clonestr("{\"error\":\"peers needs coin\"}"));
}

STRING_ARG(iguana,getconnectioncount,activecoin)
{
    int32_t i,num = 0; char buf[512];
    if ( coin != 0 )
    {
        for (i=0; i<sizeof(coin->peers.active)/sizeof(*coin->peers.active); i++)
            if ( coin->peers.active[i].usock >= 0 )
                num++;
        sprintf(buf,"{\"result\":\"%d\"}",num);
        return(clonestr(buf));
    } else return(clonestr("{\"error\":\"getconnectioncount needs coin\"}"));
}

STRING_ARG(iguana,addcoin,activecoin)
{
    char *symbol; int32_t retval;
    if ( (symbol= activecoin) == 0 && coin != 0 )
        symbol = coin->symbol;
    if ( symbol != 0 )
    {
        if ( (retval= iguana_launchcoin(symbol,json)) > 0 )
            return(clonestr("{\"result\":\"coin added\"}"));
        else if ( retval == 0 )
            return(clonestr("{\"result\":\"coin already there\"}"));
        else return(clonestr("{\"error\":\"error adding coin\"}"));
    } else return(clonestr("{\"error\":\"addcoin needs newcoin\"}"));
}

STRING_ARG(iguana,startcoin,activecoin)
{
    if ( coin != 0 )
    {
        coin->active = 1;
        return(clonestr("{\"result\":\"coin started\"}"));
    } else return(clonestr("{\"error\":\"startcoin needs coin\"}"));
}

STRING_ARG(iguana,pausecoin,activecoin)
{
    if ( coin != 0 )
    {
        coin->active = 0;
        return(clonestr("{\"result\":\"coin paused\"}"));
    } else return(clonestr("{\"error\":\"pausecoin needs coin\"}"));
}

TWO_STRINGS(iguana,addnode,activecoin,ipaddr)
{
    if ( coin != 0 && ipaddr != 0 )
    {
        iguana_possible_peer(coin,ipaddr);
        return(clonestr("{\"result\":\"addnode submitted\"}"));
    } else return(clonestr("{\"error\":\"addnode needs ipaddr\"}"));
}

TWO_STRINGS(iguana,removenode,activecoin,ipaddr)
{
    int32_t i;
    if ( coin != 0 && ipaddr != 0 )
    {
        for (i=0; i<IGUANA_MAXPEERS; i++)
        {
            if ( strcmp(coin->peers.active[i].ipaddr,ipaddr) == 0 )
            {
                coin->peers.active[i].rank = 0;
                coin->peers.active[i].dead = (uint32_t)time(NULL);
                return(clonestr("{\"result\":\"node marked as dead\"}"));
            }
        }
        return(clonestr("{\"result\":\"node wasnt active\"}"));
    } else return(clonestr("{\"error\":\"removenode needs coin and ipaddr\"}"));
}

TWO_STRINGS(iguana,oneshot,activecoin,ipaddr)
{
    if ( coin != 0 && ipaddr != 0 )
    {
        iguana_possible_peer(coin,ipaddr);
        return(clonestr("{\"result\":\"addnode submitted\"}"));
    } else return(clonestr("{\"error\":\"addnode needs coin and ipaddr\"}"));
}

TWO_STRINGS(iguana,nodestatus,activecoin,ipaddr)
{
    int32_t i; struct iguana_peer *addr;
    if ( coin != 0 && ipaddr != 0 )
    {
        for (i=0; i<coin->MAXPEERS; i++)
        {
            addr = &coin->peers.active[i];
            if ( strcmp(addr->ipaddr,ipaddr) == 0 )
                return(jprint(iguana_peerjson(coin,addr),1));
        }
        return(clonestr("{\"result\":\"nodestatus couldnt find ipaddr\"}"));
    } else return(clonestr("{\"error\":\"nodestatus needs ipaddr\"}"));
}

STRING_AND_INT(iguana,maxpeers,activecoin,max)
{
    cJSON *retjson; int32_t i; struct iguana_peer *addr;
    if ( coin != 0 )
    {
        retjson = cJSON_CreateObject();
        if ( max > IGUANA_MAXPEERS )
            max = IGUANA_MAXPEERS;
        if ( max > coin->MAXPEERS )
        {
            for (i=max; i<coin->MAXPEERS; i++)
                if ( (addr= coin->peers.ranked[i]) != 0 )
                    addr->dead = 1;
        }
        coin->MAXPEERS = max;
        jaddnum(retjson,"maxpeers",coin->MAXPEERS);
        jaddstr(retjson,"coin",coin->symbol);
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"maxpeers needs coin\"}"));
}

char *hmac_dispatch(char *(*hmacfunc)(char *dest,char *key,int32_t key_size,char *message),char *name,char *message,char *password)
{
    char hexstr[1025]; cJSON *json;
    if ( message != 0 && password != 0 )
    {
        (*hmacfunc)(hexstr,password,password==0?0:(int32_t)strlen(password),message);
        json = cJSON_CreateObject();
        jaddstr(json,"result","hmac calculated");
        jaddstr(json,"message",message);
        jaddstr(json,name,hexstr);
        return(jprint(json,1));
    } else return(clonestr("{\"error\":\"hmac needs message and passphrase\"}"));
}

char *hash_dispatch(void (*hashfunc)(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len),char *name,char *message)
{
    char hexstr[1025]; uint8_t databuf[512]; cJSON *json;
    if ( message != 0 )
    {
        (*hashfunc)(hexstr,databuf,(uint8_t *)message,(int32_t)strlen(message));
        json = cJSON_CreateObject();
        jaddstr(json,"result","hash calculated");
        jaddstr(json,"message",message);
        jaddstr(json,name,hexstr);
        return(jprint(json,1));
    } else return(clonestr("{\"error\":\"hash needs message\"}"));
}

STRING_ARG(hash,NXT,passphrase) { return(hash_dispatch(calc_NXTaddr,"NXT",passphrase)); }
STRING_ARG(hash,curve25519,pubkey) { return(hash_dispatch(calc_curve25519_str,"curve25519",pubkey)); }
STRING_ARG(hash,crc32,message) { return(hash_dispatch(calc_crc32str,"crc32",message)); }
STRING_ARG(hash,base64_encode,message) { return(hash_dispatch(calc_base64_encodestr,"base64_encode",message)); }
STRING_ARG(hash,base64_decode,message) { return(hash_dispatch(calc_base64_decodestr,"base64_decode",message)); }
STRING_ARG(hash,rmd160_sha256,message) { return(hash_dispatch(rmd160ofsha256,"rmd160_sha256",message)); }
STRING_ARG(hash,sha256_sha256,message) { return(hash_dispatch(sha256_sha256,"sha256_sha256",message)); }
STRING_ARG(hash,sha224,message) { return(hash_dispatch(calc_sha224,"sha224",message)); }
STRING_ARG(hash,sha256,message) { return(hash_dispatch(vcalc_sha256,"sha256",message)); }
STRING_ARG(hash,sha384,message) { return(hash_dispatch(calc_sha384,"sha384",message)); }
STRING_ARG(hash,sha512,message) { return(hash_dispatch(calc_sha512,"sha512",message)); }
STRING_ARG(hash,rmd128,message) { return(hash_dispatch(calc_rmd128,"rmd128",message)); }
STRING_ARG(hash,rmd160,message) { return(hash_dispatch(calc_rmd160,"rmd160",message)); }
STRING_ARG(hash,rmd256,message) { return(hash_dispatch(calc_rmd256,"rmd256",message)); }
STRING_ARG(hash,rmd320,message) { return(hash_dispatch(calc_rmd320,"rmd320",message)); }
STRING_ARG(hash,sha1,message) { return(hash_dispatch(calc_sha1,"sha1",message)); }
STRING_ARG(hash,md2,message) { return(hash_dispatch(calc_md2str,"md2",message)); }
STRING_ARG(hash,md4,message) { return(hash_dispatch(calc_md4str,"md4",message)); }
STRING_ARG(hash,md5,message) { return(hash_dispatch(calc_md5str,"md5",message)); }
STRING_ARG(hash,tiger,message) { return(hash_dispatch(calc_tiger,"tiger",message)); }
STRING_ARG(hash,whirlpool,message) { return(hash_dispatch(calc_whirlpool,"whirlpool",message)); }
TWO_STRINGS(hmac,sha224,message,passphrase) { return(hmac_dispatch(hmac_sha224_str,"sha224",message,passphrase)); }
TWO_STRINGS(hmac,sha256,message,passphrase) { return(hmac_dispatch(hmac_sha256_str,"sha256",message,passphrase)); }
TWO_STRINGS(hmac,sha384,message,passphrase) { return(hmac_dispatch(hmac_sha384_str,"sha384",message,passphrase)); }
TWO_STRINGS(hmac,sha512,message,passphrase) { return(hmac_dispatch(hmac_sha512_str,"sha512",message,passphrase)); }
TWO_STRINGS(hmac,rmd128,message,passphrase) { return(hmac_dispatch(hmac_rmd128_str,"rmd128",message,passphrase)); }
TWO_STRINGS(hmac,rmd160,message,passphrase) { return(hmac_dispatch(hmac_rmd160_str,"rmd160",message,passphrase)); }
TWO_STRINGS(hmac,rmd256,message,passphrase) { return(hmac_dispatch(hmac_rmd256_str,"rmd256",message,passphrase)); }
TWO_STRINGS(hmac,rmd320,message,passphrase) { return(hmac_dispatch(hmac_rmd320_str,"rmd320",message,passphrase)); }
TWO_STRINGS(hmac,sha1,message,passphrase) { return(hmac_dispatch(hmac_sha1_str,"sha1",message,passphrase)); }
TWO_STRINGS(hmac,md2,message,passphrase) { return(hmac_dispatch(hmac_md2_str,"md2",message,passphrase)); }
TWO_STRINGS(hmac,md4,message,passphrase) { return(hmac_dispatch(hmac_md4_str,"md4",message,passphrase)); }
TWO_STRINGS(hmac,md5,message,passphrase) { return(hmac_dispatch(hmac_md5_str,"md5",message,passphrase)); }
TWO_STRINGS(hmac,tiger,message,passphrase) { return(hmac_dispatch(hmac_tiger_str,"tiger",message,passphrase)); }
TWO_STRINGS(hmac,whirlpool,message,passphrase) { return(hmac_dispatch(hmac_whirlpool_str,"whirlpool",message,passphrase)); }

STRING_ARG(SuperNET,bitcoinrpc,setcoin)
{
    if ( coin != 0 && setcoin != 0 && setcoin[0] != 0 )
    {
        strcpy(myinfo->rpcsymbol,setcoin);
        touppercase(myinfo->rpcsymbol);
        return(clonestr("{\"result\":\"set bitcoin RPC coin\"}"));
    } else return(clonestr("{\"error\":\"bitcoinrpc needs setcoin value\"}"));
}

ZERO_ARGS(SuperNET,help)
{
    cJSON *helpjson,*retjson;
    if ( (helpjson= SuperNET_helpjson()) != 0 )
    {
        retjson = cJSON_CreateObject();
        jadd(retjson,"result",helpjson);
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"cant get helpjson\"}"));
}

TWO_STRINGS(SuperNET,html,agentform,htmlfile)
{
    char *htmlstr; cJSON *retjson; FILE *fp; int32_t max = 4*1024*1024;
    if ( htmlfile == 0 || htmlfile[0] == 0 )
        htmlfile = "uglyform.html";
    fp = fopen(htmlfile,"w");
    htmlstr = malloc(max);
    htmlstr = SuperNET_htmlstr(fp,htmlstr,max,agentform);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",htmlstr);
    free(htmlstr);
    if ( fp != 0 )
        fclose(fp);
    return(jprint(retjson,1));
}
#undef IGUANA_ARGS
#include "../includes/iguana_apiundefs.h"

char *SuperNET_parser(struct supernet_info *myinfo,char *agent,char *method,cJSON *json,char *remoteaddr)
{
    char *coinstr; struct iguana_info *coin = 0;
    if ( (coinstr= jstr(json,"activecoin")) != 0 )
        coin = iguana_coinfind(coinstr);
    if ( coin == 0 && (coinstr= jstr(json,"coin")) != 0 )
        coin = iguana_coinfind(coinstr);
    if ( strcmp(agent,"ramchain") == 0 && coin == 0 )
        return(clonestr("{\"error\":\"ramchain needs coin\"}"));
#define IGUANA_ARGS myinfo,coin,json,remoteaddr
#define IGUANA_DISPATCH0(agent,name) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS))
#define IGUANA_DISPATCH_S(agent,name,str) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str)))
#define IGUANA_DISPATCH_SS(agent,name,str,str2) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2)))
#define IGUANA_DISPATCH_SSS(agent,name,str,str2,str3) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jstr(json,#str3)))
#define IGUANA_DISPATCH_SI(agent,name,str,val) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),juint(json,#val)))
#define IGUANA_DISPATCH_SII(agent,name,str,val,val2) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),juint(json,#val),juint(json,#val2)))
#define IGUANA_DISPATCH_SSI(agent,name,str,str2,val) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),juint(json,#val)))
#define IGUANA_DISPATCH_SA(agent,name,str,array) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jobj(json,#array)))
#define IGUANA_DISPATCH_SAA(agent,name,str,array,array2) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jobj(json,#array),jobj(json,#array2)))
#define IGUANA_DISPATCH_SIII(agent,name,str,val,val2,val3) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),juint(json,#val),juint(json,#val2),juint(json,#val3)))

#define IGUANA_DISPATCH_I(agent,name,val) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,juint(json,#val)))
#define IGUANA_DISPATCH_II(agent,name,val,val2) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,juint(json,#val),juint(json,#val2)))
#define IGUANA_DISPATCH_IIA(agent,name,val,val2,array) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,juint(json,#val),juint(json,#val2),jobj(json,#array)))
#define IGUANA_DISPATCH_III(agent,name,val,val2,val3) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,juint(json,#val),juint(json,#val2),juint(json,#val3)))
#define IGUANA_DISPATCH_IA(agent,name,val,array) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,juint(json,#val),jobj(json,#array)))
#define IGUANA_DISPATCH_IAS(agent,name,val,array,str) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,juint(json,#val),jobj(json,#array),jstr(json,#str)))
    
#define IGUANA_DISPATCH_AA(agent,name,array,array2) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jobj(json,#array),jobj(json,#array2)))
    
#define IGUANA_DISPATCH_D(agent,name,amount) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jdouble(json,#amount)))
    
#define IGUANA_DISPATCH_HI(agent,name,hash,val) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jbits256(json,#hash),juint(json,#val)))
#define IGUANA_DISPATCH_HII(agent,name,hash,val,val2) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jbits256(json,#hash),juint(json,#val),juint(json,#val2)))

#define IGUANA_DISPATCH_SSDIS(agent,name,str,str2,amount,val,str3) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jdouble(json,#amount),juint(json,#val),jstr(json,#str3)))
#define IGUANA_DISPATCH_SSDISS(agent,name,str,str2,amount,val,str3,str4) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jdouble(json,#amount),juint(json,#val),jstr(json,#str3),jstr(json,#str4)))
#define IGUANA_DISPATCH_SAIS(agent,name,str,array,val,str2) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jobj(json,#array),juint(json,#val),jstr(json,#str2)))
#define IGUANA_DISPATCH_SDSS(agent,name,str,amount,str2,str3) else if ( strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jdouble(json,#amount),jstr(json,#str2),jstr(json,#str3)))
    
    // API functions
#define ZERO_ARGS IGUANA_DISPATCH0
#define INT_ARG IGUANA_DISPATCH_I
#define TWO_INTS IGUANA_DISPATCH_II
#define STRING_ARG IGUANA_DISPATCH_S
#define TWO_STRINGS IGUANA_DISPATCH_SS
#define THREE_STRINGS IGUANA_DISPATCH_SSS
#define STRING_AND_INT IGUANA_DISPATCH_SI
#define STRING_AND_TWOINTS IGUANA_DISPATCH_SII
#define HASH_AND_INT IGUANA_DISPATCH_HI
#define HASH_AND_TWOINTS IGUANA_DISPATCH_HII
#define DOUBLE_ARG IGUANA_DISPATCH_D
#define STRING_AND_ARRAY IGUANA_DISPATCH_SA
#define STRING_AND_TWOARRAYS IGUANA_DISPATCH_SAA
#define TWO_ARRAYS IGUANA_DISPATCH_AA
#define INT_AND_ARRAY IGUANA_DISPATCH_IA
#define INT_ARRAY_STRING IGUANA_DISPATCH_IAS
#define SS_D_I_S IGUANA_DISPATCH_SSDIS
#define SS_D_I_SS IGUANA_DISPATCH_SSDISS
#define S_A_I_S IGUANA_DISPATCH_SAIS
#define S_D_SS IGUANA_DISPATCH_SDSS
#define TWOINTS_AND_ARRAY IGUANA_DISPATCH_IIA
#define STRING_AND_THREEINTS IGUANA_DISPATCH_SIII
#define TWOSTRINGS_AND_INT IGUANA_DISPATCH_SSI
#define THREE_INTS IGUANA_DISPATCH_III

#include "../includes/iguana_apideclares.h"
#undef IGUANA_ARGS
    
#include "../includes/iguana_apiundefs.h"
    
    return(clonestr("{\"error\":\"illegal ramchain method or missing coin\"}"));
}


