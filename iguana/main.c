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

#define CHROMEAPP_NAME iguana
#define CHROMEAPP_STR "iguana"
#define CHROMEAPP_CONF "iguana.conf"
#define CHROMEAPP_MAIN iguana_main
#define CHROMEAPP_JSON iguana_JSON
#define CHROMEAPP_HANDLER Handler_iguana

#include "../pnacl_main.h"
#include "iguana777.h"
#include "SuperNET.h"

#define SUPERNET_HELPSTR "SuperNET help text here"

// ALL globals must be here!
struct iguana_info *Coins[IGUANA_MAXCOINS];
int32_t USE_JAY,FIRST_EXTERNAL,IGUANA_disableNXT,Debuglevel;
uint32_t prices777_NXTBLOCK,MAX_DEPTH = 100;
char NXTAPIURL[256],IGUANA_NXTADDR[256],IGUANA_NXTACCTSECRET[256];
uint64_t IGUANA_MY64BITS;
queue_t helperQ,jsonQ,finishedQ,bundlesQ;
static int32_t initflag;
#ifdef __linux__
int32_t IGUANA_NUMHELPERS = 8;
#else
int32_t IGUANA_NUMHELPERS = 1;
#endif

char *SuperNET_jsonstr(struct supernet_info *myinfo,char *jsonstr,char *remoteaddr)
{
    cJSON *json; char *agent,*method;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        method = jstr(json,"method");
        if ( (agent= jstr(json,"agent")) != 0 && method != 0 )
            return(SuperNET_parser(myinfo,agent,method,json,remoteaddr));
        else if ( method != 0 && is_bitcoinrpc(method) )
            return(iguana_bitcoinRPC(myinfo,method,json,remoteaddr));
        return(clonestr("{\"error\":\"need both agent and method\"}"));
    }
    return(clonestr("{\"error\":\"couldnt parse SuperNET_JSON\"}"));
}

struct iguana_jsonitem { struct queueitem DL; struct supernet_info *myinfo; uint32_t fallback,expired,allocsize; char **retjsonstrp; char remoteaddr[64]; char jsonstr[]; };

int32_t iguana_jsonQ()
{
    struct iguana_jsonitem *ptr;
    if ( (ptr= queue_dequeue(&finishedQ,0)) != 0 )
    {
        if ( ptr->expired != 0 )
        {
            *ptr->retjsonstrp = clonestr("{\"error\":\"request timeout\"}");
            printf("garbage collection: expired.(%s)\n",ptr->jsonstr);
            myfree(ptr,ptr->allocsize);
        } else queue_enqueue("finishedQ",&finishedQ,&ptr->DL,0);
    }
    if ( (ptr= queue_dequeue(&jsonQ,0)) != 0 )
    {
printf("process.(%s)\n",ptr->jsonstr);
        if ( (*ptr->retjsonstrp= SuperNET_jsonstr(ptr->myinfo,ptr->jsonstr,ptr->remoteaddr)) == 0 )
            *ptr->retjsonstrp = clonestr("{\"error\":\"null return from iguana_jsonstr\"}");
printf("finished.(%s)\n",ptr->jsonstr);
        queue_enqueue("finishedQ",&finishedQ,&ptr->DL,0);
        return(1);
    }
    return(0);
}

char *iguana_blockingjsonstr(struct supernet_info *myinfo,char *jsonstr,uint64_t tag,int32_t maxmillis,char *remoteaddr)
{
    struct iguana_jsonitem *ptr; char *retjsonstr = 0; int32_t len,allocsize; double expiration;
    expiration = OS_milliseconds() + maxmillis;
    //printf("blocking case.(%s)\n",jsonstr);
    len = (int32_t)strlen(jsonstr);
    allocsize = sizeof(*ptr) + len + 1;
    ptr = mycalloc('J',1,allocsize);
    ptr->allocsize = allocsize;
    ptr->myinfo = myinfo;
    ptr->retjsonstrp = &retjsonstr;
    safecopy(ptr->remoteaddr,remoteaddr,sizeof(ptr->remoteaddr));
    memcpy(ptr->jsonstr,jsonstr,len+1);
    queue_enqueue("jsonQ",&jsonQ,&ptr->DL,0);
    while ( OS_milliseconds() < expiration )
    {
        usleep(100);
        if ( retjsonstr != 0 )
        {
            //printf("blocking retjsonstr.(%s)\n",retjsonstr);
            queue_delete(&finishedQ,&ptr->DL,allocsize,1);
            return(retjsonstr);
        }
        usleep(1000);
    }
    //printf("(%s) expired\n",jsonstr);
    ptr->expired = (uint32_t)time(NULL);
    return(clonestr("{\"error\":\"iguana jsonstr expired\"}"));
}

char *SuperNET_JSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr)
{
    cJSON *retjson; uint64_t tag; uint32_t timeout; char *jsonstr; char *retjsonstr,*retstr = 0;
    printf("SuperNET_JSON.(%s) remoteaddr.(%s)\n",jprint(json,0),remoteaddr!=0?remoteaddr:"");
    if ( json != 0 )
    {
        if ( (tag= j64bits(json,"tag")) == 0 )
        {
            OS_randombytes((uint8_t *)&tag,sizeof(tag));
            jadd64bits(json,"tag",tag);
        }
        if ( (timeout= juint(json,"timeout")) == 0 )
            timeout = IGUANA_JSONTIMEOUT;
        jsonstr = jprint(json,0);
        if ( remoteaddr == 0 || jstr(json,"immediate") != 0 )
            retjsonstr = SuperNET_jsonstr(myinfo,jsonstr,remoteaddr);
        else retjsonstr = iguana_blockingjsonstr(myinfo,jsonstr,tag,timeout,remoteaddr);
        if ( retjsonstr != 0 )
        {
            if ( (retjson= cJSON_Parse(retjsonstr)) != 0 )
            {
                jdelete(retjson,"tag");
                jadd64bits(retjson,"tag",tag);
                retstr = jprint(retjson,1);
                //printf("retstr.(%s) retjsonstr.%p retjson.%p\n",retstr,retjsonstr,retjson);
                free(retjsonstr);//,strlen(retjsonstr)+1);
            } else retstr = retjsonstr;
        }
        free(jsonstr);
    } else retstr = clonestr("{\"error\":\"cant parse JSON\"}");
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null return\"}");
    return(retstr);
}

char *iguana_JSON(char *jsonstr)
{
    char *retstr=0; cJSON *json;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        retstr = SuperNET_JSON(0,json,"127.0.0.1");
        free_json(json);
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"cant parse jsonstr from pnacl\"}");
    return(retstr);
}

char *SuperNET_p2p(struct iguana_info *coin,int32_t *delaymillisp,char *ipaddr,uint8_t *data,int32_t datalen)
{
    cJSON *json,*retjson; char *agent,*method,*retstr = 0;
    if ( (json= cJSON_Parse((char *)data)) != 0 )
    {
        printf("GOT >>>>>>>> SUPERNET P2P.(%s) from.%s\n",(char *)data,coin->symbol);
        if ( (agent= jstr(json,"agent")) != 0 && (method= jstr(json,"method")) != 0 )
        {
            jaddstr(json,"fromp2p",coin->symbol);
            if ( (retstr= SuperNET_JSON(0,json,ipaddr)) != 0 )
            {
                printf("retstr.(%s)\n",retstr);
                if ( (retjson= cJSON_Parse(retstr)) != 0 )
                {
                    if ( jobj(retjson,"result") != 0 || jobj(retjson,"error") != 0 || jobj(retjson,"method") == 0 )
                    {
                        printf("it is a result, dont return\n");
                        free(retstr);
                        retstr = 0;
                    }
                    free_json(retjson);
                }
            }
        }
        free_json(json);
    }
    return(retstr);
}

void ramcoder_test(void *data,int64_t datalen)
{
    static double totalin,totalout;
    int32_t complen,bufsize = 1024 * 1024; uint8_t *buf;
    buf = malloc(bufsize);
    complen = ramcoder_compress(buf,bufsize,data,(int32_t)datalen);
    totalin += datalen;
    totalout += (complen >> 3);
    printf("datalen.%d -> numbits.%d %d %.3f\n",(int32_t)datalen,complen,complen>>3,(double)totalin/totalout);
    free(buf);
}

void iguana_main(void *arg)
{
    struct supernet_info MYINFO; char helperstr[64],*helperargs,*coinargs=0,*secret,*jsonstr = arg;
    int32_t i,len,flag; cJSON *json; uint8_t secretbuf[512];
    mycalloc(0,0,0);
    iguana_initQ(&helperQ,"helperQ");
    OS_ensure_directory("confs");
    OS_ensure_directory("DB");
    OS_ensure_directory("tmp");
    memset(&MYINFO,0,sizeof(MYINFO));
    if ( jsonstr != 0 && (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( jobj(json,"numhelpers") != 0 )
            IGUANA_NUMHELPERS = juint(json,"numhelpers");
        if ( (secret= jstr(json,"secret")) != 0 )
        {
            len = (int32_t)strlen(secret);
            if ( is_hexstr(secret,0) != 0 && len == 128 )
            {
                len >>= 1;
                decode_hex(secretbuf,len,secret);
            } else vcalc_sha256(0,secretbuf,(void *)secret,len), len = sizeof(bits256);
            memcpy(MYINFO.privkey.bytes,secretbuf,sizeof(MYINFO.privkey));
        }
        if ( jobj(json,"coins") != 0 )
            coinargs = jsonstr;
    }
    if ( IGUANA_NUMHELPERS == 0 )
        IGUANA_NUMHELPERS = 1;
    for (i=0; i<IGUANA_NUMHELPERS; i++)
    {
        sprintf(helperstr,"{\"name\":\"helper.%d\"}",i);
        helperargs = clonestr(helperstr);
        iguana_launch(iguana_coinadd("BTCD"),"iguana_helper",iguana_helper,helperargs,IGUANA_PERMTHREAD);
    }
    iguana_launch(iguana_coinadd("BTCD"),"rpcloop",iguana_rpcloop,iguana_coinadd("BTCD"),IGUANA_PERMTHREAD);
    if ( coinargs != 0 )
        iguana_launch(iguana_coinadd("BTCD"),"iguana_coins",iguana_coins,coinargs,IGUANA_PERMTHREAD);
    else if ( 1 )
    {
#ifdef __APPLE__
        sleep(1);
        char *str;
        if ( (str= SuperNET_JSON(&MYINFO,cJSON_Parse("{\"agent\":\"iguana\",\"method\":\"addcoin\",\"services\":0,\"maxpeers\":2,\"activecoin\":\"BTCD\",\"active\":1}"),0)) != 0 )
        {
            printf("got.(%s)\n",str);
            free(str);
        }
#endif
    }
    if ( arg != 0 )
        SuperNET_JSON(&MYINFO,cJSON_Parse(arg),0);
//#ifndef MINIGUANA
 //  iguana_launch(iguana_coinadd("BTCD"),"SuperNET_init",SuperNET_init,&MYINFO,IGUANA_PERMTHREAD);
//#endif
 //init_InstantDEX();
    while ( 1 )
    {
        flag = 0;
        iguana_jsonQ();
        if ( flag == 0 )
        {
            struct iguana_helper *ptr;
            if ( (ptr= queue_dequeue(&bundlesQ,0)) != 0 )
            {
                if ( ptr->bp != 0 && ptr->coin != 0 )
                    flag += iguana_bundleiters(ptr->coin,ptr->bp,ptr->timelimit);
                myfree(ptr,ptr->allocsize);
            }
        }
        if ( flag == 0 )
            sleep(1);
    }
}

