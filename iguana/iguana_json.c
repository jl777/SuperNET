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

#include "iguana777.h"
//#include "SuperNET.h"

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
    sprintf(curl,"curl --url \"http://127.0.0.1:7778\" --data \"{\\\"agent\\\":\\\"%s\\\",\\\"method\\\":\\\"%s\\\"",agentstr,method);
    if ( methodargs != 0 && (n= cJSON_GetArraySize(methodargs)) > 0 )
    {
        //printf("method.%s n.%d %s\n",method,n,jprint(methodargs,0));
        for (i=0; i<n; i++)
        {
            strcat(url,i==0?"?":"&");
            item = jitem(methodargs,i);
            sprintf(url+strlen(url),"%s={%s}",get_cJSON_fieldname(item),jstr(item,get_cJSON_fieldname(item)));
            sprintf(curl+strlen(curl),",\\\"%s\\\":\\\"{%s}\\\"",get_cJSON_fieldname(item),jstr(item,get_cJSON_fieldname(item)));
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
cJSON *helparray7(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2,cJSON *obj3,cJSON *obj4,cJSON *obj5,cJSON *obj6) { jaddi(array,obj0); return(helparray6(array,obj1,obj2,obj3,obj4,obj5,obj6)); }
cJSON *helparray8(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2,cJSON *obj3,cJSON *obj4,cJSON *obj5,cJSON *obj6,cJSON *obj7) { jaddi(array,obj0); return(helparray7(array,obj1,obj2,obj3,obj4,obj5,obj6,obj7)); }
cJSON *helparray9(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2,cJSON *obj3,cJSON *obj4,cJSON *obj5,cJSON *obj6,cJSON *obj7,cJSON *obj9) { jaddi(array,obj0); return(helparray8(array,obj1,obj2,obj3,obj4,obj5,obj6,obj7,obj9)); }
cJSON *helparray10(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2,cJSON *obj3,cJSON *obj4,cJSON *obj5,cJSON *obj6,cJSON *obj7,cJSON *obj9,cJSON *obj10) { jaddi(array,obj0); return(helparray9(array,obj1,obj2,obj3,obj4,obj5,obj6,obj7,obj9,obj10)); }
cJSON *helparray11(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2,cJSON *obj3,cJSON *obj4,cJSON *obj5,cJSON *obj6,cJSON *obj7,cJSON *obj9,cJSON *obj10,cJSON *obj11) { jaddi(array,obj0); return(helparray10(array,obj1,obj2,obj3,obj4,obj5,obj6,obj7,obj9,obj10,obj11)); }
cJSON *helparray12(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2,cJSON *obj3,cJSON *obj4,cJSON *obj5,cJSON *obj6,cJSON *obj7,cJSON *obj9,cJSON *obj10,cJSON *obj11,cJSON *obj12) { jaddi(array,obj0); return(helparray11(array,obj1,obj2,obj3,obj4,obj5,obj6,obj7,obj9,obj10,obj11,obj12)); }
cJSON *helparray13(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2,cJSON *obj3,cJSON *obj4,cJSON *obj5,cJSON *obj6,cJSON *obj7,cJSON *obj9,cJSON *obj10,cJSON *obj11,cJSON *obj12,cJSON *obj13) { jaddi(array,obj0); return(helparray12(array,obj1,obj2,obj3,obj4,obj5,obj6,obj7,obj9,obj10,obj11,obj12,obj13)); }
cJSON *helparray14(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2,cJSON *obj3,cJSON *obj4,cJSON *obj5,cJSON *obj6,cJSON *obj7,cJSON *obj9,cJSON *obj10,cJSON *obj11,cJSON *obj12,cJSON *obj13,cJSON *obj14) { jaddi(array,obj0); return(helparray13(array,obj1,obj2,obj3,obj4,obj5,obj6,obj7,obj9,obj10,obj11,obj12,obj13,obj14)); }
cJSON *helparray15(cJSON *array,cJSON *obj0,cJSON *obj1,cJSON *obj2,cJSON *obj3,cJSON *obj4,cJSON *obj5,cJSON *obj6,cJSON *obj7,cJSON *obj9,cJSON *obj10,cJSON *obj11,cJSON *obj12,cJSON *obj13,cJSON *obj14,cJSON *obj15) { jaddi(array,obj0); return(helparray14(array,obj1,obj2,obj3,obj4,obj5,obj6,obj7,obj9,obj10,obj11,obj12,obj13,obj14,obj15)); }

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
#define IGUANA_HELP_SDD(agent,name,str,val,val2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#val,"float"),helpitem(#val2,"float")))
#define IGUANA_HELP_SSSS(agent,name,str,str2,str3,str4) array = helpjson(IGUANA_ARGS,#agent,#name,helparray4(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#str3,"string"),helpitem(#str4,"string")))
#define IGUANA_HELP_SSSD(agent,name,str,str2,str3,amount) array = helpjson(IGUANA_ARGS,#agent,#name,helparray4(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#str3,"string"),helpitem(#amount,"float")))
#define IGUANA_HELP_SSSDDD(agent,name,str,str2,str3,amount,val2,val3) array = helpjson(IGUANA_ARGS,#agent,#name,helparray6(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#str3,"string"),helpitem(#amount,"float"),helpitem(#val2,"float"),helpitem(#val3,"float")))
#define IGUANA_HELP_SSSIII(agent,name,str,str2,str3,val,val2,val3) array = helpjson(IGUANA_ARGS,#agent,#name,helparray6(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#str3,"string"),helpitem(#val,"int"),helpitem(#val2,"int"),helpitem(#val3,"int")))

#define IGUANA_HELP_SSH(agent,name,str,str2,hash) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#hash,"hash")))
#define IGUANA_HELP_SSHI(agent,name,str,str2,hash,val) array = helpjson(IGUANA_ARGS,#agent,#name,helparray4(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#hash,"hash"),helpitem(#val,"int")))
#define IGUANA_HELP_SSDD(agent,name,str,str2,val,val2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray4(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#val,"float"),helpitem(#val2,"float")))
#define IGUANA_HELP_SSHII(agent,name,str,str2,hash,val,val2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray5(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#hash,"hash"),helpitem(#val,"int"),helpitem(#val2,"int")))
#define IGUANA_HELP_SSHHII(agent,name,str,str2,hash,hash2,val,val2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray6(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#hash,"hash"),helpitem(#hash2,"hash"),helpitem(#val,"int"),helpitem(#val2,"int")))
#define IGUANA_HELP_SI(agent,name,str,val) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#val,"int")))
#define IGUANA_HELP_SD(agent,name,str,val) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#val,"float")))
#define IGUANA_HELP_SII(agent,name,str,val,val2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#val,"int"),helpitem(#val2,"int")))
#define IGUANA_HELP_SSI(agent,name,str,str2,val) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#val,"int")))
#define IGUANA_HELP_SA(agent,name,str,obj) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#obj,"array")))
#define IGUANA_HELP_SAA(agent,name,str,obj,obj2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#obj,"array"),helpitem(#obj2,"array")))
#define IGUANA_HELP_SIII(agent,name,str,val,val2,val3) array = helpjson(IGUANA_ARGS,#agent,#name,helparray4(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#val,"int"),helpitem(#val2,"int"),helpitem(#val3,"int")))
    
#define IGUANA_HELP_I(agent,name,val) array = helpjson(IGUANA_ARGS,#agent,#name,helparray(cJSON_CreateArray(),helpitem(#val,"int")))
#define IGUANA_HELP_II(agent,name,val,val2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#val,"int"),helpitem(#val2,"int")))
#define IGUANA_HELP_ID(agent,name,val,val2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#val,"int"),helpitem(#val2,"float")))
#define IGUANA_HELP_IA(agent,name,val,obj) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#val,"int"),helpitem(#obj,"array")))
#define IGUANA_HELP_IIA(agent,name,val,val2,obj) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#val,"int"),helpitem(#val2,"int"),helpitem(#obj,"array")))
#define IGUANA_HELP_III(agent,name,val,val2,val3) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#val,"int"),helpitem(#val2,"int"),helpitem(#val3,"int")))
#define IGUANA_HELP_IAS(agent,name,val,obj,str) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#val,"int"),helpitem(#obj,"array"),helpitem(#str,"string")))
    
#define IGUANA_HELP_64A(agent,name,j64,obj) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#j64,"u64bits"),helpitem(#obj,"array")))
#define IGUANA_HELP_AA(agent,name,obj,obj2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#obj,"array"),helpitem(#obj2,"array")))
#define IGUANA_HELP_AOI(agent,name,obj,obj2,val) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#obj,"array"),helpitem(#obj2,"object"),helpitem(#val,"int")))
#define IGUANA_HELP_D(agent,name,amount) array = helpjson(IGUANA_ARGS,#agent,#name,helparray(cJSON_CreateArray(),helpitem(#amount,"float")))
    
#define IGUANA_HELP_H(agent,name,hash) array = helpjson(IGUANA_ARGS,#agent,#name,helparray(cJSON_CreateArray(),helpitem(#hash,"hash")))
#define IGUANA_HELP_HI(agent,name,hash,val) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#hash,"hash"),helpitem(#val,"int")))
#define IGUANA_HELP_HH(agent,name,hash,hash2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#hash,"hash"),helpitem(#hash2,"hash")))
#define IGUANA_HELP_HA(agent,name,hash,obj) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#hash,"hash"),helpitem(#obj,"array")))
#define IGUANA_HELP_HS(agent,name,hash,str) array = helpjson(IGUANA_ARGS,#agent,#name,helparray2(cJSON_CreateArray(),helpitem(#hash,"hash"),helpitem(#str,"str")))
#define IGUANA_HELP_HII(agent,name,hash,val,val2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#hash,"hash"),helpitem(#val,"int"),helpitem(#val2,"int")))
#define IGUANA_HELP_HHS(agent,name,hash,hash2,str) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#hash,"hash"),helpitem(#hash2,"hash"),helpitem(#str,"str")))
#define IGUANA_HELP_HAS(agent,name,hash,obj,str) array = helpjson(IGUANA_ARGS,#agent,#name,helparray3(cJSON_CreateArray(),helpitem(#hash,"hash"),helpitem(#obj,"array"),helpitem(#str,"str")))
    
#define IGUANA_HELP_SSDIS(agent,name,str,str2,amount,val,str3) array = helpjson(IGUANA_ARGS,#agent,#name,helparray5(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#amount,"float"),helpitem(#val,"int"),helpitem(#str3,"string")))
#define IGUANA_HELP_SSDISS(agent,name,str,str2,amount,val,str3,str4) array = helpjson(IGUANA_ARGS,#agent,#name,helparray6(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#str2,"string"),helpitem(#amount,"float"),helpitem(#val,"int"),helpitem(#str3,"string"),helpitem(#str4,"string")))
#define IGUANA_HELP_SAIS(agent,name,str,obj,val,str2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray4(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#obj,"array"),helpitem(#val,"int"),helpitem(#str2,"string")))
#define IGUANA_HELP_SAOS(agent,name,str,obj,obj2,str2) array = helpjson(IGUANA_ARGS,#agent,#name,helparray4(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#obj,"array"),helpitem(#obj2,"object"),helpitem(#str2,"string")))
#define IGUANA_HELP_SDSS(agent,name,str,amount,str2,str3) array = helpjson(IGUANA_ARGS,#agent,#name,helparray4(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#amount,"float"),helpitem(#str2,"string"),helpitem(#str3,"string")))
    
#define IGUANA_HELP_SHI_SDSD_II_SSSSSS(agent,name,str,hash,val,str2,amount,str3,amount2,val2,val3,str4,str5,str6,str7,str8,str9) array = helpjson(IGUANA_ARGS,#agent,#name,helparray15(cJSON_CreateArray(),helpitem(#str,"string"),helpitem(#hash,"hash"),helpitem(#val,"int"),helpitem(#str2,"string"),helpitem(#amount,"float"),helpitem(#str3,"string"),helpitem(#amount2,"float"),helpitem(#val2,"int"),helpitem(#val3,"int"),helpitem(#str4,"string"),helpitem(#str5,"string"),helpitem(#str6,"string"),helpitem(#str7,"string"),helpitem(#str8,"string"),helpitem(#str9,"string")))

    // API functions
#define ZERO_ARGS IGUANA_HELP0
#define INT_ARG IGUANA_HELP_I
#define INT_AND_DOUBLE IGUANA_HELP_ID
#define TWO_INTS IGUANA_HELP_II
#define STRING_ARG IGUANA_HELP_S
#define TWO_STRINGS IGUANA_HELP_SS
#define THREE_STRINGS IGUANA_HELP_SSS
#define FOUR_STRINGS IGUANA_HELP_SSSS
#define STRING_AND_INT IGUANA_HELP_SI
#define STRING_AND_TWOINTS IGUANA_HELP_SII
#define HASH_AND_STRING IGUANA_HELP_HS
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
#define TWOSTRINGS_AND_HASH IGUANA_HELP_SSH
#define TWOSTRINGS_AND_HASH_AND_TWOINTS IGUANA_HELP_SSHII
#define TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS IGUANA_HELP_SSHHII
#define THREE_INTS IGUANA_HELP_III
#define TWOHASHES_AND_STRING IGUANA_HELP_HHS
#define HASH_ARRAY_STRING IGUANA_HELP_HAS
#define U64_AND_ARRAY IGUANA_HELP_64A
#define HASH_ARG IGUANA_HELP_H
#define TWO_HASHES IGUANA_HELP_HH
#define HASH_AND_ARRAY IGUANA_HELP_HA
#define THREE_STRINGS_AND_THREE_INTS IGUANA_HELP_SSSIII
#define THREE_STRINGS_AND_THREE_DOUBLES IGUANA_HELP_SSSDDD
#define THREE_STRINGS_AND_DOUBLE IGUANA_HELP_SSSD
#define STRING_AND_DOUBLE IGUANA_HELP_SD
#define TWO_STRINGS_AND_TWO_DOUBLES IGUANA_HELP_SSDD
#define STRING_AND_TWO_DOUBLES IGUANA_HELP_SDD
#define P2SH_SPENDAPI IGUANA_HELP_SHI_SDSD_II_SSSSSS
#define ARRAY_OBJ_INT IGUANA_HELP_AOI
#define STRING_ARRAY_OBJ_STRING IGUANA_HELP_SAOS

#include "../includes/iguana_apideclares.h"
    
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
                    width = 12;
                else if ( strcmp(typestr,"float") == 0 )
                    width = 24;
                else if ( strcmp(typestr,"u64bits") == 0 )
                    width = 24;
                else if ( strcmp(typestr,"array") == 0 )
                    width = 64;
                else if ( strcmp(typestr,"object") == 0 )
                    width = 64;
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
        fprintf(fp,"%s\n",&form[size]);
    //printf("%s\n",&form[size]);
    return((int32_t)strlen(form));
}

#define HTML_EMIT(str,n)  memcpy(&retbuf[size],str,n), size += (n)
int32_t template_emit(char *retbuf,int32_t maxsize,char *template,char *varname,char *value)
{
    int32_t offset,valuelen,varnamelen,position,size = 0; char *match;
    offset = 0;
    valuelen = (int32_t)strlen(value);
    varnamelen = (int32_t)strlen(varname);
    while ( (match= strstr(varname,&template[offset])) != 0 )
    {
        position = (int32_t)((long)match - (long)&template[offset]);
        printf("found match.(%s) at %d offset.%d\n",varname,position,offset);
        if ( size + (valuelen + position) > maxsize )
            return(-1);
        HTML_EMIT(&template[offset],position), offset += position + varnamelen;
        HTML_EMIT(value,valuelen);
    }
    HTML_EMIT(&template[offset],strlen(&template[offset])+1);
    return(size);
}

#define MAX_TEMPLATESIZE 32768
int32_t templates_emit(char *retbuf,int32_t maxsize,char *template,char *agent,char *method,char *fieldnames,char *fieldnames2)
{
    char buf[MAX_TEMPLATESIZE+4096];
    strcpy(buf,template);
    template_emit(retbuf,maxsize,buf,"$AGENT",agent), strcpy(buf,retbuf);
    template_emit(retbuf,maxsize,buf,"$METHOD",method), strcpy(buf,retbuf);
    template_emit(retbuf,maxsize,buf,"$FIELDNAMES",fieldnames), strcpy(buf,retbuf);
    return(template_emit(retbuf,maxsize,buf,"$FIELDNAMES2",fieldnames2));
}

int32_t pretty_form(FILE *fp,char *formheader,char *formfooter,char *fieldtemplate,char *agent,cJSON *methoditem,cJSON *helpitem,char *suffix)
{
    cJSON *item,*fieldsarray; int32_t j,m,formsize,fieldsize,iter,width,size = 0;
    char *methodstr,*typestr,*fieldname,*helpstr,*curlstr,*urlstr,*itemhelp;
    char outstr[2048],outstr2[2048],str[2],widthstr[16],both[512];
    if ( (methodstr= jstr(methoditem,"method")) == 0 )
        methodstr = "method";
    if ( agent == 0 )
        agent = "agent";
    sprintf(both,"%s-%s",agent,methodstr);
    outstr[0] = outstr2[0] = str[1] = 0;
    formsize = fieldsize = 0;
    if ( (helpstr= jstr(helpitem,"help")) == 0 )
        helpstr = "Some description of this API Call.";
    if ( (urlstr= jstr(methoditem,"url")) == 0 )
        urlstr = "url";
    if ( (curlstr= jstr(methoditem,"curl")) == 0 )
        curlstr = "curl";
    for (iter=0; iter<2; iter++)
    {
        if ( iter == 1 )
        {
            if ( strcmp(suffix,"html") == 0 )
                fprintf(fp,formheader,both,both,both,agent,methodstr,both,both,agent,methodstr,outstr);
            else if ( strcmp(suffix,"md") == 0 )
                fprintf(fp,formheader,methodstr,helpstr,curlstr,urlstr);
        }
        if ( (fieldsarray= jarray(&m,methoditem,"fields")) != 0 )
        {
            for (j=0; j<m; j++)
            {
                item = jitem(fieldsarray,j);
                fieldname = get_cJSON_fieldname(item);
                if ( (itemhelp= jstr(helpitem,fieldname)) == 0 )
                    itemhelp = "no help info";
                // printf("item.(%s) %s\n",jprint(item,0),jstr(item,fieldname));
                if ( iter == 0 )
                {
                    if ( j > 0 )
                    {
                        strcat(outstr,"+");
                        strcat(outstr2," ");
                    }
                    strcat(outstr,fieldname);
                    strcat(outstr2,fieldname);
                }
                else
                {
                    if ( (typestr= jstr(item,fieldname)) != 0 )
                    {
                        if ( strcmp(typestr,"string") == 0 )
                            width = 44;
                        else if ( strcmp(typestr,"hash") == 0 )
                            width = 65;
                        else if ( strcmp(typestr,"int") == 0 )
                            width = 12;
                        else if ( strcmp(typestr,"float") == 0 )
                            width = 24;
                        else if ( strcmp(typestr,"u64bits") == 0 )
                            width = 24;
                        else width = 0;
                    }
                    sprintf(widthstr,"%d",width);
                    if ( strcmp(suffix,"html") == 0 )
                        fprintf(fp,fieldtemplate,fieldname,fieldname,fieldname,widthstr,fieldname);
                    else if ( strcmp(suffix,"md") == 0 )
                        fprintf(fp,fieldtemplate,fieldname,typestr,itemhelp);
                }
            }
        }
        if ( iter == 1 )
        {
            if ( strcmp(suffix,"html") == 0 )
                fprintf(fp,formfooter,outstr2,methodstr,methodstr);
            else if ( strcmp(suffix,"md") == 0 )
                fprintf(fp,formfooter,"");
        }
    }
    return(size);
}

cJSON *update_docjson(cJSON *docjson,char *agent,char *method)
{
    cJSON *item = 0; long allocsize; char *docstr,fname[512],stubstr[4096]; FILE *fp;
    if ( agent != 0 && method != 0 )
    {
        sprintf(stubstr,"{\"agent\":\"%s\",\"method\":\"%s\",\"field0\":\"put in helpful info field0\",\"field1\":\"put in helpful info for field1\",\"help\":\"put helpful info here\",\"teststatus\":[{\"tester\":\"bob\",\"result\":\"put result here\",\"notes\":\"put useful notes here\",\"automated\":\"notyet\",\"sourcefile\":\"%s_%s_test.py\"}]}",agent,method,agent,method);
        sprintf(fname,"%s/%s_%s.json",GLOBAL_HELPDIR,agent,method);
        if ( (docstr= OS_filestr(&allocsize,fname)) != 0 )
        {
            if ( (item= cJSON_Parse(docstr)) == 0 )
                printf("WARNING: cant parse %s\n",fname);
            free(docstr);
        }
        else if ( (fp= fopen(fname,"w")) != 0 )
        {
            if ( (item= cJSON_Parse(stubstr)) == 0 )
                printf("WARNING: cant parse stubstr %s\n",stubstr);
            else
            {
                fprintf(fp,"%s\n",stubstr);
                fclose(fp);
            }
        }
        if ( item == 0 )
            item = cJSON_Parse(stubstr);
        if ( item != 0 )
            jaddi(docjson,item);
    }
    return(item);
}

char *formfname(char *name,char *suffix)
{
    static char retbuf[512];
    sprintf(retbuf,"%s/%s.%s",GLOBAL_HELPDIR,name,suffix);
    return(retbuf);
}

int32_t pretty_forms(char *fname,char *agentstr,char *suffix)
{
    char *str,*header,*footer,*agent,*agenthelp,*prevagent=0,*formheader,*formfooter,*field,*docstr; long allocsize; FILE *fp,*docfp;
    int32_t i,n,len,err=0,size = 0; cJSON *helpjson,*array,*item,*docjson=0,*helpitem;
    header = OS_filestr(&allocsize,formfname("header",suffix)); if ( allocsize > MAX_TEMPLATESIZE ) err++;
    footer = OS_filestr(&allocsize,formfname("footer",suffix)); if ( allocsize > MAX_TEMPLATESIZE ) err++;
    formheader = OS_filestr(&allocsize,formfname("formheader",suffix)); if ( allocsize > MAX_TEMPLATESIZE ) err++;
    formfooter = OS_filestr(&allocsize,formfname("formfooter",suffix)); if ( allocsize > MAX_TEMPLATESIZE ) err++;
    field = OS_filestr(&allocsize,formfname("field",suffix)); if ( allocsize > MAX_TEMPLATESIZE ) err++;
    agent = OS_filestr(&allocsize,formfname("agent",suffix)); if ( allocsize > MAX_TEMPLATESIZE ) err++;
    fp = fopen(fname,"w");
    docjson = cJSON_CreateArray();
    if ( fp != 0 && err == 0 && header != 0 && footer != 0 && formheader != 0 && formfooter != 0 && field != 0 )
    {
        //HTML_EMIT(header,strlen(header));
        fprintf(fp,"%s\n",header);
        if ( (helpjson= SuperNET_helpjson()) != 0 )
        {
            //printf("JSON.(%s)\n",jprint(helpjson,0));
            if ( (array= jarray(&n,helpjson,"API")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (str = jstr(item,"agent")) == 0 )
                        continue;
                    if ( prevagent == 0 || strcmp(str,prevagent) != 0 )
                    {
                        if ( agent != 0 )
                        {
                            char errbuf[512];
                            sprintf(errbuf,"need to create help/%s.md file",str);
                            if ( (agenthelp= OS_filestr(&allocsize,formfname(str,"md"))) != 0 )
                            {
                                fprintf(fp,agent,str,agenthelp);
                                free(agenthelp);
                            }  else fprintf(fp,agent,str,errbuf);
                        }
                        prevagent = str;
                    }
                    helpitem = update_docjson(docjson,str,jstr(item,"method"));
                    if ( agentstr == 0 || agentstr[0] == 0 || (str != 0 && strcmp(str,agentstr) == 0) )
                    {
                        len = pretty_form(fp,formheader,formfooter,field,str!=0?str:"agent",item,helpitem,suffix);
                        size += len;
                        //printf("%s.%s\n",str,jstr(item,"method"));
                    } //else printf("agentstr.%p (%s) (%s) str.%p \n",agentstr,agentstr,str,str);
                }
            }
            free_json(helpjson);
        }
        fprintf(fp,"%s\n",footer);
        fclose(fp);
        //HTML_EMIT(footer,strlen(footer));
    }
    if ( suffix != 0 && docjson != 0 && (docfp= fopen("help.json","w")) != 0 )
    {
        docstr = jprint(docjson,1);
        fprintf(docfp,"%s\n",docstr);
        fclose(docfp);
        free(docstr);
    }
    if ( header != 0 ) free(header);
    if ( footer != 0 ) free(footer);
    if ( formheader != 0 ) free(formheader);
    if ( formfooter != 0 ) free(formfooter);
    if ( field != 0 ) free(field);
    return(size);
}
#undef HTML_EMIT

char *SuperNET_htmlstr(char *fname,char *htmlstr,int32_t maxsize,char *agentstr)
{
    int32_t i,n,len,size = 0; long filesize; cJSON *helpjson,*item,*array; char *str; FILE *fp = 0;
    htmlstr[0] = 0;
    pretty_forms(fname,agentstr,"html");
    //printf("autocreate %s\n","autoAPI.md");
    pretty_forms("autoAPI.md",0,"md");
return(OS_filestr(&filesize,"index7778.html"));
    sprintf(htmlstr,"<!DOCTYPE HTML><html> <head><title>SuperUGLY GUI></title></head> <body> ");
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
                    len = agentform(fp,&htmlstr[size],maxsize - size,str!=0?str:"agent",item);
                    size += len;
                } //else printf("agentstr.%p (%s) (%s) str.%p \n",agentstr,agentstr,str,str);
            }
        }
        //free_json(helpjson);
        return(jprint(helpjson,1));
    }
    strcat(htmlstr,"<br><br/></body></html><br><br/>");
    printf("<br><br/></body></html><br><br/>\n");
    return(htmlstr);
}

cJSON *iguana_peerjson(struct iguana_info *coin,struct iguana_peer *addr)
{
    cJSON *array,*json = cJSON_CreateObject();
    jaddstr(json,"ipaddr",addr->ipaddr);
    if ( addr->supernet != 0 )
        jaddstr(json,"ipaddr",addr->ipaddr);
    jaddstr(json,"supernet","yes");
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
    if ( coin == 0 || coin->peers == 0 )
        return(0);
    array = cJSON_CreateArray();
    for (i=0; i<coin->MAXPEERS; i++)
    {
        addr = &coin->peers->active[i];
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

#include "../includes/iguana_apidefs.h"

STRING_ARG(iguana,peers,activecoin)
{
    if ( coin != 0 )
        return(jprint(iguana_peersjson(coin,0),1));
    else return(clonestr("{\"error\":\"peers needs coin\"}"));
}

STRING_ARG(iguana,getconnectioncount,activecoin)
{
    int32_t i,num = 0; char buf[512];
    if ( coin != 0 && coin->peers != 0 )
    {
        for (i=0; i<sizeof(coin->peers->active)/sizeof(*coin->peers->active); i++)
            if ( coin->peers->active[i].usock >= 0 )
                num++;
        sprintf(buf,"{\"result\":\"%d\"}",num);
        return(clonestr(buf));
    } else return(clonestr("{\"error\":\"getconnectioncount needs coin\"}"));
}

ZERO_ARGS(bitcoinrpc,getdifficulty)
{
    char buf[512];
    if ( coin != 0 )
    {
        sprintf(buf,"{\"result\":\"success\",\"proof-of-work\":\"%.8f\",\"search-interval\": 0}",PoW_from_compact(coin->blocks.hwmchain.RO.bits,coin->chain->unitval));
        return(clonestr(buf));
    } else return(clonestr("{\"error\":\"getdifficulty needs coin\"}"));
}

STRING_ARG(iguana,addcoin,newcoin)
{
    char *symbol; int32_t retval;
    if ( (symbol= newcoin) == 0 && coin != 0 )
        symbol = coin->symbol;
    if ( symbol != 0 )
    {
        printf(">> addcoin.%s\n",symbol);
#ifdef __PNACL__
//        if ( strcmp(symbol,"BTC") == 0 )
//            return(clonestr("{\"result\":\"BTC for chrome app is not yet\"}"));
#endif
        if ( (retval= iguana_launchcoin(myinfo,symbol,json,0)) > 0 )
        {
            if ( myinfo->rpcsymbol[0] == 0 )
                safecopy(myinfo->rpcsymbol,symbol,sizeof(myinfo->rpcsymbol));
            return(clonestr("{\"result\":\"coin added\"}"));
        }
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

STRING_ARG(iguana,stopcoin,activecoin)
{
    if ( activecoin[0] != 0 )
        coin = iguana_coinfind(activecoin);
    if ( coin != 0 )
    {
        coin->active = 0;
        //iguana_coinpurge(coin);
        return(clonestr("{\"result\":\"coin stopped\"}"));
    } else return(clonestr("{\"error\":\"stopcoin needs coin\"}"));
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
    struct iguana_peer *addr; int32_t i,n;
    if ( coin == 0 )
        coin = iguana_coinfind(activecoin);
    printf("coin.%p.[%s] addnode.%s -> %s\n",coin,coin!=0?coin->symbol:"",activecoin,ipaddr);
    if ( coin != 0 && coin->peers != 0 && ipaddr != 0 && is_ipaddr(ipaddr) != 0 )
    {
        //iguana_possible_peer(coin,ipaddr);
        if ( (addr= iguana_peerslot(coin,(uint32_t)calc_ipbits(ipaddr),1)) != 0 )
        {
            addr->supernet = 1;
            if ( addr->usock >= 0 )
            {
                if ( (n= coin->peers->numranked) != 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        if ( addr == coin->peers->ranked[i] )
                            break;
                    }
                    if ( i == n )
                    {
                        if ( i == IGUANA_MAXPEERS )
                            i--;
                        else coin->peers->numranked = n+1;
                        coin->peers->ranked[i] = addr;
                        addr->recvblocks = coin->peers->ranked[0]->recvblocks + 100;
                        addr->recvtotal = coin->peers->ranked[0]->recvtotal*1.1 + 100;
                        printf("set (%s) -> slot.%d numranked.%d\n",ipaddr,i,coin->peers->numranked);
                    } else printf("(%s) is already peer.%d\n",ipaddr,i);
                }
                return(clonestr("{\"result\":\"peer was already connected\"}"));
            }
            if ( addr->pending == 0 )
            {
                addr->pending = (uint32_t)time(NULL);
                iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
                return(clonestr("{\"result\":\"addnode submitted\"}"));
            } else return(clonestr("{\"result\":\"addnode connection was already pending\"}"));
        } else return(clonestr("{\"result\":\"addnode cant find peer slot\"}"));
    }
    else if ( coin == 0 )
        return(clonestr("{\"error\":\"addnode needs active coin, do an addcoin first\"}"));
    else return(clonestr("{\"error\":\"addnode needs ipaddr\"}"));
}

TWO_STRINGS(iguana,persistent,activecoin,ipaddr)
{
    int32_t i;
    if ( coin != 0 && coin->peers != 0 && ipaddr != 0 )
    {
        for (i=0; i<IGUANA_MAXPEERS; i++)
        {
            if ( strcmp(coin->peers->active[i].ipaddr,ipaddr) == 0 )
            {
                coin->peers->active[i].persistent_peer = juint(json,"interval")+3;
                return(clonestr("{\"result\":\"node marked as persistent\"}"));
            }
        }
        return(clonestr("{\"result\":\"node wasnt active\"}"));
    } else return(clonestr("{\"error\":\"persistent needs coin and ipaddr\"}"));
}

TWO_STRINGS(iguana,removenode,activecoin,ipaddr)
{
    int32_t i;
    if ( coin != 0 && coin->peers != 0 && ipaddr != 0 )
    {
        for (i=0; i<IGUANA_MAXPEERS; i++)
        {
            if ( strcmp(coin->peers->active[i].ipaddr,ipaddr) == 0 )
            {
                coin->peers->active[i].rank = 0;
                coin->peers->active[i].dead = (uint32_t)time(NULL);
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
    if ( coin != 0 && coin->peers != 0 && ipaddr != 0 )
    {
        for (i=0; i<coin->MAXPEERS; i++)
        {
            addr = &coin->peers->active[i];
            if ( strcmp(addr->ipaddr,ipaddr) == 0 )
                return(jprint(iguana_peerjson(coin,addr),1));
        }
        return(clonestr("{\"result\":\"nodestatus couldnt find ipaddr\"}"));
    } else return(clonestr("{\"error\":\"nodestatus needs ipaddr\"}"));
}

STRING_AND_INT(iguana,maxpeers,activecoin,max)
{
    cJSON *retjson; int32_t i; struct iguana_peer *addr;
    if ( coin != 0 && coin->peers != 0 )
    {
        retjson = cJSON_CreateObject();
        if ( max > IGUANA_MAXPEERS )
            max = IGUANA_MAXPEERS;
        if ( max > coin->MAXPEERS )
        {
            for (i=max; i<coin->MAXPEERS; i++)
                if ( (addr= coin->peers->ranked[i]) != 0 )
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
    if ( message != 0 && password != 0 && message[0] != 0 && password[0] != 0 )
    {
        memset(hexstr,0,sizeof(hexstr));
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
    char hexstr[65537]; uint8_t databuf[32768]; cJSON *json;
    if ( message != 0 && message[0] != 0 )
    {
        memset(hexstr,0,sizeof(hexstr));
        (*hashfunc)(hexstr,databuf,(uint8_t *)message,(int32_t)strlen(message));
        json = cJSON_CreateObject();
        jaddstr(json,"result","hash calculated");
        jaddstr(json,"message",message);
        jaddstr(json,name,hexstr);
        return(jprint(json,1));
    } else return(clonestr("{\"error\":\"hash needs message\"}"));
}

TWO_HASHES(hash,curve25519_pair,element,scalar)
{
    cJSON *retjson = cJSON_CreateObject();
    jaddbits256(retjson,"result",curve25519(element,scalar));
    return(jprint(retjson,1));
}

STRING_ARG(hash,NXT,passphrase) { return(hash_dispatch(calc_NXTaddr,"NXT",passphrase)); }
STRING_ARG(hash,curve25519,pubkey) { return(hash_dispatch(calc_curve25519_str,"curve25519",pubkey)); }
STRING_ARG(hash,crc32,message) { return(hash_dispatch(calc_crc32str,"crc32",message)); }
STRING_ARG(hash,base64_encode,message) { return(hash_dispatch(calc_base64_encodestr,"base64_encode",message)); }
STRING_ARG(hash,base64_decode,message) { return(hash_dispatch(calc_base64_decodestr,"base64_decode",message)); }
STRING_ARG(hash,rmd160_sha256,message) { return(hash_dispatch(rmd160ofsha256,"rmd160_sha256",message)); }
STRING_ARG(hash,sha256_sha256,message) { return(hash_dispatch(sha256_sha256,"sha256_sha256",message)); }
STRING_ARG(hash,hex,message) { return(hash_dispatch(calc_hexstr,"hex",message)); }
STRING_ARG(hash,unhex,message) { return(hash_dispatch(calc_unhexstr,"unhex",message)); }

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
STRING_ARG(hash,tiger192_3,message) { return(hash_dispatch(calc_tiger,"tiger",message)); }
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
TWO_STRINGS(hmac,tiger192_3,message,passphrase) { return(hmac_dispatch(hmac_tiger_str,"tiger",message,passphrase)); }
TWO_STRINGS(hmac,whirlpool,message,passphrase) { return(hmac_dispatch(hmac_whirlpool_str,"whirlpool",message,passphrase)); }

STRING_ARG(SuperNET,bitcoinrpc,setcoin)
{
    char buf[1024];
    if ( setcoin != 0 && setcoin[0] != 0 )
    {
        strcpy(myinfo->rpcsymbol,setcoin);
        touppercase(myinfo->rpcsymbol);
        printf("bitcoinrpc.%s\n",myinfo->rpcsymbol);
        if ( iguana_launchcoin(myinfo,myinfo->rpcsymbol,json,0) < 0 )
            return(clonestr("{\"error\":\"error creating coin\"}"));
        else
        {
            sprintf(buf,"{\"result\":\"success\",\"setcoin\":\"%s\"}",setcoin);
            return(clonestr(buf));
        }
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
    char *htmlstr; cJSON *retjson; int32_t max = 4*1024*1024;
    if ( htmlfile == 0 || htmlfile[0] == 0 )
        htmlfile = "forms.html";
    //if ( (fp= fopen(htmlfile,"w")) == 0 )
    //    printf("error opening htmlfile.(%s)\n",htmlfile);
    htmlstr = malloc(max);
    htmlstr = SuperNET_htmlstr(htmlfile,htmlstr,max,agentform);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",htmlstr);
    free(htmlstr);
    //if ( fp != 0 )
    //    fclose(fp);
    return(jprint(retjson,1));
}
       
#undef IGUANA_ARGS
#include "../includes/iguana_apiundefs.h"

char *SuperNET_parser(struct supernet_info *myinfo,char *agentstr,char *method,cJSON *json,char *remoteaddr)
{
    char *coinstr; struct iguana_info *coin = 0;
    if ( remoteaddr != 0 && (remoteaddr[0] == 0 || strcmp(remoteaddr,"127.0.0.1") == 0) )
        remoteaddr = 0;
    if ( (coinstr= jstr(json,"activecoin")) == 0 && (coinstr= jstr(json,"coin")) == 0 )
        coinstr = myinfo->rpcsymbol;
    if ( coinstr != 0 && coinstr[0] != 0 )
        coin = iguana_coinfind(coinstr);
    if ( strcmp(agentstr,"bitcoinrpc") == 0 && coin == 0 )
        return(clonestr("{\"error\":\"bitcoinrpc needs coin\"}"));
#define IGUANA_ARGS myinfo,coin,json,remoteaddr
#define IGUANA_DISPATCH0(agent,name) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS))
#define IGUANA_DISPATCH_S(agent,name,str) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str)))
#define IGUANA_DISPATCH_SS(agent,name,str,str2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2)))
#define IGUANA_DISPATCH_ID(agent,name,dval,val) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jdouble(json,#dval),jdouble(json,#val)))
#define IGUANA_DISPATCH_SD(agent,name,str,val) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jdouble(json,#val)))
#define IGUANA_DISPATCH_SSS(agent,name,str,str2,str3) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jstr(json,#str3)))
#define IGUANA_DISPATCH_SSSS(agent,name,str,str2,str3,str4) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jstr(json,#str3),jstr(json,#str4)))
#define IGUANA_DISPATCH_SSSD(agent,name,str,str2,str3,amount) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jstr(json,#str3),jdouble(json,#amount)))
#define IGUANA_DISPATCH_SSDD(agent,name,str,str2,val,val2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jdouble(json,#val),jdouble(json,#val2)))
#define IGUANA_DISPATCH_SSSDDD(agent,name,str,str2,str3,val,val2,val3) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jstr(json,#str3),jdouble(json,#val),jdouble(json,#val2),jdouble(json,#val3)))
#define IGUANA_DISPATCH_SSSIII(agent,name,str,str2,str3,val,val2,val3) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jstr(json,#str3),jint(json,#val),jint(json,#val2),jint(json,#val3)))

#define IGUANA_DISPATCH_SSH(agent,name,str,str2,hash) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jbits256(json,#hash)))
#define IGUANA_DISPATCH_SSHI(agent,name,str,str2,hash,val) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jbits256(json,#hash),juint(json,#val)))
#define IGUANA_DISPATCH_SSHII(agent,name,str,str2,hash,val,val2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jbits256(json,#hash),juint(json,#val),juint(json,#val2)))
#define IGUANA_DISPATCH_SSHHII(agent,name,str,str2,hash,hash2,val,val2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jbits256(json,#hash),jbits256(json,#hash2),juint(json,#val),juint(json,#val2)))
#define IGUANA_DISPATCH_SI(agent,name,str,val) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),juint(json,#val)))
#define IGUANA_DISPATCH_SII(agent,name,str,val,val2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),juint(json,#val),juint(json,#val2)))
#define IGUANA_DISPATCH_SSI(agent,name,str,str2,val) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),juint(json,#val)))
#define IGUANA_DISPATCH_SDD(agent,name,str,val,val2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jdouble(json,#val),jdouble(json,#val2)))
#define IGUANA_DISPATCH_SA(agent,name,str,array) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jobj(json,#array)))
#define IGUANA_DISPATCH_SAA(agent,name,str,array,array2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jobj(json,#array),jobj(json,#array2)))
#define IGUANA_DISPATCH_AOI(agent,name,array,object,val) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jobj(json,#array),jobj(json,#object),juint(json,#val)))
#define IGUANA_DISPATCH_SIII(agent,name,str,val,val2,val3) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),juint(json,#val),juint(json,#val2),juint(json,#val3)))

#define IGUANA_DISPATCH_I(agent,name,val) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,juint(json,#val)))
#define IGUANA_DISPATCH_II(agent,name,val,val2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,juint(json,#val),juint(json,#val2)))
#define IGUANA_DISPATCH_IIA(agent,name,val,val2,array) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,juint(json,#val),juint(json,#val2),jobj(json,#array)))
#define IGUANA_DISPATCH_III(agent,name,val,val2,val3) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,juint(json,#val),juint(json,#val2),juint(json,#val3)))
#define IGUANA_DISPATCH_IA(agent,name,val,array) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,juint(json,#val),jobj(json,#array)))
#define IGUANA_DISPATCH_IAS(agent,name,val,array,str) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,juint(json,#val),jobj(json,#array),jstr(json,#str)))
    
#define IGUANA_DISPATCH_64A(agent,name,j64,array) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,j64bits(json,#j64),jobj(json,#array)))
#define IGUANA_DISPATCH_AA(agent,name,array,array2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jobj(json,#array),jobj(json,#array2)))
    
#define IGUANA_DISPATCH_D(agent,name,amount) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jdouble(json,#amount)))
    
#define IGUANA_DISPATCH_H(agent,name,hash) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jbits256(json,#hash)))
#define IGUANA_DISPATCH_HI(agent,name,hash,val) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jbits256(json,#hash),juint(json,#val)))
#define IGUANA_DISPATCH_HH(agent,name,hash,hash2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jbits256(json,#hash),jbits256(json,#hash2)))
#define IGUANA_DISPATCH_HA(agent,name,hash,array) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jbits256(json,#hash),jobj(json,#array)))
#define IGUANA_DISPATCH_HS(agent,name,hash,str) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jbits256(json,#hash),jstr(json,#str)))
#define IGUANA_DISPATCH_HII(agent,name,hash,val,val2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jbits256(json,#hash),juint(json,#val),juint(json,#val2)))
#define IGUANA_DISPATCH_HHS(agent,name,hash,hash2,str) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jbits256(json,#hash),jbits256(json,#hash2),jstr(json,#str)))
#define IGUANA_DISPATCH_HAS(agent,name,hash,array,str) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jbits256(json,#hash),jobj(json,#array),jstr(json,#str)))

#define IGUANA_DISPATCH_SSDIS(agent,name,str,str2,amount,val,str3) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jdouble(json,#amount),juint(json,#val),jstr(json,#str3)))
#define IGUANA_DISPATCH_SSDISS(agent,name,str,str2,amount,val,str3,str4) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jstr(json,#str2),jdouble(json,#amount),juint(json,#val),jstr(json,#str3),jstr(json,#str4)))
#define IGUANA_DISPATCH_SAIS(agent,name,str,array,val,str2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jobj(json,#array),juint(json,#val),jstr(json,#str2)))
#define IGUANA_DISPATCH_SAOS(agent,name,str,array,object,str2) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jobj(json,#array),jobj(json,#object),jstr(json,#str2)))
#define IGUANA_DISPATCH_SDSS(agent,name,str,amount,str2,str3) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jdouble(json,#amount),jstr(json,#str2),jstr(json,#str3)))
    
#define IGUANA_DISPATCH_SHI_SDSD_II_SSSSSS(agent,name,str,hash,val,str2,amount,str3,amount2,val2,val3,str4,str5,str6,str7,str8,str9) else if ( strcmp(#agent,agentstr) == 0 && strcmp(method,#name) == 0 ) return(agent ## _ ## name(IGUANA_ARGS,jstr(json,#str),jbits256(json,#hash),jint(json,#val),jstr(json,#str2),jdouble(json,#amount),jstr(json,#str3),jdouble(json,#amount2),juint(json,#val2),juint(json,#val3),jstr(json,#str4),jstr(json,#str5),jstr(json,#str6),jstr(json,#str7),jstr(json,#str8),jstr(json,#str9)))

    // API functions
#define ZERO_ARGS IGUANA_DISPATCH0
#define INT_ARG IGUANA_DISPATCH_I
#define INT_AND_DOUBLE IGUANA_DISPATCH_ID
#define TWO_INTS IGUANA_DISPATCH_II
#define STRING_ARG IGUANA_DISPATCH_S
#define TWO_STRINGS IGUANA_DISPATCH_SS
#define THREE_STRINGS IGUANA_DISPATCH_SSS
#define FOUR_STRINGS IGUANA_DISPATCH_SSSS
#define STRING_AND_INT IGUANA_DISPATCH_SI
#define STRING_AND_TWOINTS IGUANA_DISPATCH_SII
#define HASH_AND_INT IGUANA_DISPATCH_HI
#define HASH_AND_STRING IGUANA_DISPATCH_HS
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
#define TWOSTRINGS_AND_HASH IGUANA_DISPATCH_SSH
#define TWOSTRINGS_AND_HASH_AND_TWOINTS IGUANA_DISPATCH_SSHII
#define TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS IGUANA_DISPATCH_SSHHII
#define THREE_INTS IGUANA_DISPATCH_III
#define TWOHASHES_AND_STRING IGUANA_DISPATCH_HHS
#define HASH_ARRAY_STRING IGUANA_DISPATCH_HAS
#define U64_AND_ARRAY IGUANA_DISPATCH_64A
#define HASH_ARG IGUANA_DISPATCH_H
#define TWO_HASHES IGUANA_DISPATCH_HH
#define HASH_AND_ARRAY IGUANA_DISPATCH_HA
#define THREE_STRINGS_AND_THREE_INTS IGUANA_DISPATCH_SSSIII
#define THREE_STRINGS_AND_THREE_DOUBLES IGUANA_DISPATCH_SSSDDD
#define THREE_STRINGS_AND_DOUBLE IGUANA_DISPATCH_SSSD
#define STRING_AND_DOUBLE IGUANA_DISPATCH_SD
#define TWO_STRINGS_AND_TWO_DOUBLES IGUANA_DISPATCH_SSDD
#define STRING_AND_TWO_DOUBLES IGUANA_DISPATCH_SDD
#define P2SH_SPENDAPI IGUANA_DISPATCH_SHI_SDSD_II_SSSSSS
#define ARRAY_OBJ_INT IGUANA_DISPATCH_AOI
#define STRING_ARRAY_OBJ_STRING IGUANA_DISPATCH_SAOS

#include "../includes/iguana_apideclares.h"
//#undef IGUANA_ARGS
    
#include "../includes/iguana_apiundefs.h"
    char errstr[512];
    sprintf(errstr,"{\"error\":\"unsupported call\",\"agent\":\"%s\",\"method\":\"%s\"}",agentstr,method);
    return(clonestr(errstr));
}


