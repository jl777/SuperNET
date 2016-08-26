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

#include "SuperNET.h"

#define BUNDLED
#define PLUGINSTR "relay"
#define PLUGNAME(NAME) relay ## NAME
#define STRUCTNAME struct PLUGNAME(_info) 
#define STRINGIFY(NAME) #NAME
#define PLUGIN_EXTRASIZE sizeof(STRUCTNAME)


#define NN_WS -4

char *PLUGNAME(_methods)[] = { "list", "add", "direct", "join", "busdata", "msigaddr", "allservices", "telepathy" }; // list of supported methods

int32_t nn_typelist[] = { NN_REP, NN_REQ, NN_RESPONDENT, NN_SURVEYOR, NN_PUB, NN_SUB, NN_PULL, NN_PUSH, NN_BUS, NN_PAIR };
char *nn_transports[] = { "tcp", "ws", "ipc", "inproc", "tcpmux", "tbd1", "tbd2", "tbd3" };

void calc_nonces(char *destpoint)
{
    char buf[8192],*str; int32_t n = 0; double endmilli = milliseconds() + 60000;
    //printf("calc_nonces.(%s)\n",destpoint);
    memset(SUPERNET.nonces,0,sizeof(SUPERNET.nonces));
    SUPERNET.numnonces = 0;
    while ( milliseconds() < endmilli && n < sizeof(SUPERNET.nonces)/sizeof(*SUPERNET.nonces) )
    {
        sprintf(buf,"{\"plugin\":\"relay\",\"counter\":\"%d\",\"destplugin\":\"relay\",\"method\":\"nonce\",\"broadcast\":\"8\",\"lbendpoint\":\"%s\",\"relaypoint\":\"%s\",\"globalpoint\":\"%s\",\"destpoint\":\"%s\",\"NXT\":\"%s\"}",n,SUPERNET.lbendpoint,SUPERNET.relayendpoint,SUPERNET.globalendpoint,destpoint,SUPERNET.NXTADDR);
        if ( (str= busdata_sync(&SUPERNET.nonces[n],buf,"8",0)) != 0 )
        {
            //fprintf(stderr,"send.(%s)\n",buf);
            free(str);
            n++;
        }
    }
    SUPERNET.numnonces = n;
    SUPERNET.noncing = 0;
    printf("finished noncing for (%s)\n",destpoint);
    free(destpoint);
}

void recv_nonces(void *_ptr)
{
    int32_t i,j,n; cJSON *json,*item,*array,*nonces; char *jsonstr; struct applicant_info A,*ptr = _ptr;
    if ( ptr->startflag != 0 )
    {
        double endmilli = milliseconds() + 60000;
        printf("start receiving nonces\n");
        SUPERNET.numnonces = 0;
        while ( milliseconds() < endmilli )
            msleep(1000);
        printf("finished.%d recv_nonces\n",SUPERNET.numnonces);
        free(ptr);
        if ( (n= SUPERNET.numnonces) > 0 )
        {
            json = cJSON_CreateObject();
            array = cJSON_CreateArray();
            while ( n > 0 )
            {
                A = SUPERNET.responses[0];
                item = cJSON_CreateObject();
                nonces = cJSON_CreateArray();
                SUPERNET.responses[0] = SUPERNET.responses[--n];
                for (i=0; i<=n; i++)
                {
                    if ( strcmp(A.lbendpoint,SUPERNET.responses[i].lbendpoint) == 0 )
                    {
                        cJSON_AddItemToArray(nonces,cJSON_CreateNumber(SUPERNET.responses[i].nonce));
                        memset(&SUPERNET.responses[i],0,sizeof(SUPERNET.responses[i]));
                    }
                }
                for (j=0,i=1; i<n; i++)
                    if ( SUPERNET.responses[i].senderbits != 0 )
                        SUPERNET.responses[j++] = SUPERNET.responses[i];
                n = j;
                cJSON_AddItemToObject(item,"lbendpoint",cJSON_CreateString(A.lbendpoint));
                cJSON_AddItemToObject(item,"relaypoint",cJSON_CreateString(A.relayendpoint));
                cJSON_AddItemToObject(item,"glboalpoint",cJSON_CreateString(A.globalendpoint));
                cJSON_AddItemToObject(item,"nonces",nonces);
                cJSON_AddItemToArray(array,item);
            }
            cJSON_AddItemToObject(json,"peers",array);
            cJSON_AddItemToObject(json,"lbendpoint",cJSON_CreateString(SUPERNET.lbendpoint));
            cJSON_AddItemToObject(json,"relaypoint",cJSON_CreateString(SUPERNET.relayendpoint));
            cJSON_AddItemToObject(json,"glboalpoint",cJSON_CreateString(SUPERNET.globalendpoint));
            jsonstr = cJSON_Print(json), _stripwhite(jsonstr,' ');
            printf("%s\n",jsonstr);
            if ( SUPERNET.peersjson != 0 )
                free_json(SUPERNET.peersjson);
            SUPERNET.peersjson = json;
        }
        SUPERNET.noncing = 0;
        SUPERNET.numnonces = 0;
    }
    else
    {
        SUPERNET.responses = realloc(SUPERNET.responses,(sizeof(*SUPERNET.responses) * (SUPERNET.numnonces + 1)));
        SUPERNET.responses[SUPERNET.numnonces++] = *ptr;
        fprintf(stderr,"%d: got nonce.%u from %llu %s/%s/%s\n",SUPERNET.numnonces,ptr->nonce,(long long)ptr->senderbits,ptr->lbendpoint,ptr->relayendpoint,ptr->globalendpoint);
    }
}

void protocols_register(char *NXTaddr,char *protocol,char *endpoint,int32_t disconnect)
{
    /*uint64_t nxt64bits = conv_acctstr(NXTaddr);
    if ( disconnect == 0 )
        dKV777_write(SUPERNET.relays,SUPERNET.protocols,nxt64bits,protocol,(int32_t)strlen(protocol)+1,endpoint,(int32_t)strlen(endpoint)+1);
    else dKV777_delete(SUPERNET.relays,SUPERNET.protocols,nxt64bits,protocol,(int32_t)strlen(protocol)+1);*/
    printf("need to %s protocol %s with %s\n",disconnect==0?"register":"disconnect",protocol,endpoint);
}

int32_t PLUGNAME(_process_json)(char *forwarder,char *sender,int32_t valid,struct plugin_info *plugin,uint64_t tag,char *retbuf,int32_t maxlen,char *origjsonstr,cJSON *origjson,int32_t initflag,char *tokenstr)
{
    char *resultstr,*retstr = 0,*methodstr,*jsonstr,*destplugin,*submethod; struct destbuf tagstr,endpoint;
    cJSON *retjson,*json,*tokenobj; uint32_t nonce;
    struct applicant_info apply;
    retbuf[0] = 0;
    if ( tokenstr == 0 )
        tokenstr = "";
    if ( is_cJSON_Array(origjson) != 0 && cJSON_GetArraySize(origjson) == 2 )
        json = cJSON_GetArrayItem(origjson,0), jsonstr = cJSON_Print(json), _stripwhite(jsonstr,' ');
    else json = origjson, jsonstr = origjsonstr;
    if ( Debuglevel > 2 )
        printf("<<<<<<<<<<<< INSIDE relays PLUGIN! process %s [(%s).(%s)]\n",plugin->name,jsonstr,tokenstr);
    if ( initflag > 0 )
    {
        // configure settings
        RELAYS.readyflag = 1;
        plugin->allowremote = 1;
        plugin->sleepmillis = 100;
        strcpy(retbuf,"{\"result\":\"initflag > 0\"}");
    }
    else
    {
        if ( plugin_result(retbuf,json,tag) > 0 )
            return((int32_t)strlen(retbuf));
        resultstr = cJSON_str(cJSON_GetObjectItem(json,"result"));
        methodstr = cJSON_str(cJSON_GetObjectItem(json,"method"));
        destplugin = cJSON_str(cJSON_GetObjectItem(json,"destplugin"));
        submethod = cJSON_str(cJSON_GetObjectItem(json,"submethod"));
        if ( methodstr == 0 || methodstr[0] == 0 )
        {
            printf("(%s) has not method\n",jsonstr);
            return(0);
        }
        //fprintf(stderr,"RELAYS methodstr.(%s) (%s)\n",methodstr,jsonstr);
        if ( resultstr != 0 && strcmp(resultstr,"registered") == 0 )
        {
            plugin->registered = 1;
            strcpy(retbuf,"{\"result\":\"activated\"}");
        }
#ifdef INSIDE_MGW
        else if ( strcmp(methodstr,"msigaddr") == 0 )
        {
            char *devMGW_command(char *jsonstr,cJSON *json);
            if ( SUPERNET.gatewayid >= 0 )
                retstr = devMGW_command(jsonstr,json);
        }
#endif
        else
        {
            strcpy(retbuf,"{\"result\":\"relay command under construction\"}");
            if ( strcmp(methodstr,"list") == 0 )
                retstr = relays_jsonstr(jsonstr,json);
            else if ( strcmp(methodstr,"telepathy") == 0 )
            {
                sprintf(retbuf,"%s",jsonstr);
            }
            else if ( strcmp(methodstr,"busdata") == 0 )
            {
                retstr = busdata_sync(&nonce,jsonstr,cJSON_str(cJSON_GetObjectItem(json,"broadcast")),0);
                // {"plugin":"relay","method":"busdata","destplugin":"relay","submethod":"join","broadcast":"join","endpoint":""}
            }
            else if ( strcmp(methodstr,"allservices") == 0 )
            {
                if ( (retjson= serviceprovider_json()) != 0 )
                {
                    retstr = cJSON_Print(retjson), _stripwhite(retstr,' ');
                    free_json(retjson);
                    //printf("got.(%s)\n",retstr);
                } else printf("null serviceprovider_json()\n");
            }
            else if ( strcmp(methodstr,"protocol") == 0 || strcmp(methodstr,"allprotocols") == 0 )
            {
                if ( strcmp(methodstr,"protocol") == 0 && valid > 0 )
                    protocols_register(sender,jstr(json,"protocol"),jstr(json,"endpoint"),jint(json,"disconnect"));
                if ( (retjson= protocols_json(jstr(json,"protocol"))) != 0 )
                {
                    retstr = cJSON_Print(retjson), _stripwhite(retstr,' ');
                    free_json(retjson);
                } else printf("null protocols_json()\n");
            }
            else if ( strcmp(methodstr,"join") == 0 )
            {
                if ( SUPERNET.noncing == 0 )
                {
                    copy_cJSON(&tagstr,cJSON_GetObjectItem(json,"tag"));
                    copy_cJSON(&endpoint,cJSON_GetObjectItem(json,"endpoint"));
                    SUPERNET.noncing = 1;
                    if ( SUPERNET.iamrelay != 0 )
                    {
                        portable_thread_create((void *)calc_nonces,clonestr(endpoint.buf));
                        sprintf(retbuf,"{\"result\":\"noncing\",\"endpoint\":\"%s\"}",endpoint.buf);
                    }
                    //fprintf(stderr,"join or nonce.(%s)\n",retbuf);
                }
            }
            else if ( strcmp(methodstr,"nonce") == 0 )
            {
                struct destbuf endpointbuf,senderbuf,destpoint,relaypoint,globalpoint,noncestr;
                memset(&apply,0,sizeof(apply));
                copy_cJSON(&destpoint,cJSON_GetObjectItem(json,"destpoint"));
                copy_cJSON(&endpointbuf,cJSON_GetObjectItem(json,"lbendpoint"));
                copy_cJSON(&relaypoint,cJSON_GetObjectItem(json,"relaypoint"));
                copy_cJSON(&globalpoint,cJSON_GetObjectItem(json,"globalpoint"));
                copy_cJSON(&senderbuf,cJSON_GetObjectItem(json,"NXT"));
                if ( SUPERNET.noncing != 0 && strcmp(SUPERNET.lbendpoint,destpoint.buf) == 0 )
                {
                    if ( endpointbuf.buf[0] != 0 && tokenstr != 0 && tokenstr[0] != 0 && (tokenobj= cJSON_Parse(tokenstr)) != 0 )
                    {
                        strcpy(apply.lbendpoint,endpointbuf.buf);
                        strcpy(apply.relayendpoint,relaypoint.buf);
                        strcpy(apply.globalendpoint,globalpoint.buf);
                        apply.senderbits = calc_nxt64bits(senderbuf.buf);
                        copy_cJSON(&noncestr,cJSON_GetObjectItem(tokenobj,"nonce"));
                        if ( noncestr.buf[0] != 0 )
                            apply.nonce = (uint32_t)calc_nxt64bits(noncestr.buf);
                        //printf("tokenobj.(%s) -> nonce.%u\n",tokenstr,apply.nonce);
                        free_json(tokenobj);
                        recv_nonces(&apply);
                    }
                }
            }
        }
    }
    return(plugin_copyretstr(retbuf,maxlen,retstr));
}

#endif

