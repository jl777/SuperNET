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

#define CHROMEAPP_NAME iguana
#define CHROMEAPP_STR "iguana"
#define CHROMEAPP_CONF "iguana.conf"
#define CHROMEAPP_MAIN iguana_main
#define CHROMEAPP_JSON iguana_JSON
#define CHROMEAPP_HANDLER Handler_iguana

#include "../pnacl_main.h"
#include "iguana777.h"
#include "SuperNET.h"

// ALL globals must be here!
char *Iguana_validcommands[] =
{
    "SuperNET", "SuperNETb",
    "version", "verack", "getaddr", "addr", "inv", "getdata", "notfound", "getblocks", "getheaders", "headers", "tx", "block", "mempool", "ping", "pong",
    "reject", "filterload", "filteradd", "filterclear", "merkleblock", "alert", ""
};
int32_t Showmode,Autofold,PANGEA_MAXTHREADS = 1;

struct category_info *Categories;
struct iguana_info *Coins[IGUANA_MAXCOINS];
int32_t USE_JAY,FIRST_EXTERNAL,IGUANA_disableNXT,Debuglevel;
uint32_t prices777_NXTBLOCK,MAX_DEPTH = 100;
queue_t helperQ,jsonQ,finishedQ,bundlesQ;
struct supernet_info MYINFO;
static int32_t initflag;
cJSON *API_json;
#ifdef __linux__
int32_t IGUANA_NUMHELPERS = 8;
#else
int32_t IGUANA_NUMHELPERS = 1;
#endif
struct iguana_jsonitem { struct queueitem DL; struct supernet_info *myinfo; uint32_t fallback,expired,allocsize; char **retjsonstrp; char remoteaddr[64]; char jsonstr[]; };

uint16_t SuperNET_API2num(char *agent,char *method)
{
    int32_t i,n = 0; cJSON *item;
    if ( agent != 0 && method != 0 && API_json != 0 && (n= cJSON_GetArraySize(API_json)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(API_json,i);
            if ( strcmp(agent,jstr(item,"agent")) == 0 && strcmp(method,jstr(item,"method")) == 0 )
                return((i << 5) | (SUPERNET_APIVERSION & 0x1f));
        }
    }
    return(-1);
}

int32_t SuperNET_num2API(char *agent,char *method,uint16_t num)
{
    int32_t n,apiversion; cJSON *item;
    if ( (apiversion= (num & 0x1f)) != SUPERNET_APIVERSION )
    {
        printf("need to make sure all released api help returns are indexed here!\n");
        return(-1);
    }
    num >>= 5;
    if ( API_json != 0 && (n= cJSON_GetArraySize(API_json)) > 0 && num < n )
    {
        item = jitem(API_json,num);
        strcpy(agent,jstr(item,"agent"));
        strcpy(method,jstr(item,"method"));
        return(num);
    }
    return(-1);
}

int32_t SuperNET_str2hex(uint8_t *hex,char *str)
{
    int32_t len;
    len = (int32_t)strlen(str)+1;
    decode_hex(hex,len,str);
    return(len);
}

void SuperNET_hex2str(char *str,uint8_t *hex,int32_t len)
{
    init_hexbytes_noT(str,hex,len);
}

struct supernet_info *SuperNET_MYINFO(char *passphrase)
{
    if ( passphrase == 0 || passphrase[0] == 0 )
        return(&MYINFO);
    else
    {
        // search saved accounts
    }
    return(&MYINFO);
    return(0);
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

char *SuperNET_jsonstr(struct supernet_info *myinfo,char *jsonstr,char *remoteaddr)
{
    cJSON *json; char *agent,*method;
    //char str[65]; printf("SuperNET_jsonstr %p %s\n",&myinfo->privkey,bits256_str(str,myinfo->privkey));
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        method = jstr(json,"method");
        if ( (agent= jstr(json,"agent")) != 0 && method != 0 )
            return(SuperNET_parser(myinfo,agent,method,json,remoteaddr));
        else if ( method != 0 && is_bitcoinrpc(method,remoteaddr) )
            return(iguana_bitcoinRPC(myinfo,method,json,remoteaddr));
        return(clonestr("{\"error\":\"need both agent and method\"}"));
    }
    return(clonestr("{\"error\":\"couldnt parse SuperNET_JSON\"}"));
}

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
        char str[65]; printf("ptr %p %s\n",&ptr->myinfo->privkey,bits256_str(str,ptr->myinfo->privkey));
        if ( *ptr->retjsonstrp != 0 && (*ptr->retjsonstrp= SuperNET_jsonstr(ptr->myinfo,ptr->jsonstr,ptr->remoteaddr)) == 0 )
            *ptr->retjsonstrp = clonestr("{\"error\":\"null return from iguana_jsonstr\"}");
        //printf("finished.(%s) -> (%s)\n",ptr->jsonstr,*ptr->retjsonstrp!=0?*ptr->retjsonstrp:"null return");
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
            //printf("got blocking retjsonstr.(%s) delete allocsize.%d:%d\n",retjsonstr,allocsize,ptr->allocsize);
            queue_delete(&finishedQ,&ptr->DL,ptr->allocsize,1);
            return(retjsonstr);
        }
        usleep(1000);
    }
    //printf("(%s) expired\n",jsonstr);
    ptr->expired = (uint32_t)time(NULL);
    return(clonestr("{\"error\":\"iguana jsonstr expired\"}"));
}

char *SuperNET_processJSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr)
{
    cJSON *retjson; uint64_t tag; uint32_t timeout; char *jsonstr,*method,*retjsonstr,*retstr = 0;
    //char str[65]; printf("processJSON %p %s\n",&myinfo->privkey,bits256_str(str,myinfo->privkey));
    if ( json != 0 )
    {
        if ( (tag= j64bits(json,"tag")) == 0 )
        {
            OS_randombytes((uint8_t *)&tag,sizeof(tag));
            jadd64bits(json,"tag",tag);
        }
        if ( (timeout= juint(json,"timeout")) == 0 )
            timeout = IGUANA_JSONTIMEOUT;
        if ( (method= jstr(json,"method")) != 0 && strcmp(method,"DHT") == 0 && remoteaddr != 0 )
        {
            SuperNET_hexmsgprocess(myinfo,json,jstr(json,"hexmsg"),remoteaddr);
            return(clonestr("{\"result\":\"processed remote DHT\"}"));
        }
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

void iguana_exit()
{
    int32_t i,j,iter; char *stopstr = SUPERNET_STOPSTR;
    printf("start EXIT\n");
    for (iter=0; iter<3; iter++)
    {
        for (i=0; i<IGUANA_MAXCOINS; i++)
        {
            if ( Coins[i] != 0 )
            {
                for (j=0; j<IGUANA_MAXPEERS; j++)
                {
                    switch ( iter )
                    {
                        case 0:
                            if ( Coins[i]->peers.active[j].usock >= 0 && Coins[i]->peers.active[j].supernet != 0 )
                                iguana_send_supernet(Coins[i],&Coins[i]->peers.active[j],stopstr,0);
                            break;
                        case 1: Coins[i]->peers.active[j].dead = (uint32_t)time(NULL); break;
                        case 2:
                            if ( Coins[i]->peers.active[j].usock >= 0 )
                                closesocket(Coins[i]->peers.active[j].usock);
                            break;
                    }
                }
            }
        }
        sleep(5);
    }
    printf("sockets closed, now EXIT\n");
    exit(0);
}

#include <signal.h>
void sigint_func() { printf("\nSIGINT\n"); iguana_exit(); }
void sigillegal_func() { printf("\nSIGILL\n"); iguana_exit(); }
void sighangup_func() { printf("\nSIGHUP\n"); iguana_exit(); }
void sigkill_func() { printf("\nSIGKILL\n"); iguana_exit(); }
void sigabort_func() { printf("\nSIGABRT\n"); iguana_exit(); }
void sigquit_func() { printf("\nSIGQUIT\n"); iguana_exit(); }
void sigchild_func() { printf("\nSIGCHLD\n"); signal(SIGCHLD,sigchild_func); }
void sigalarm_func() { printf("\nSIGALRM\n"); signal(SIGALRM,sigalarm_func); }
void sigcontinue_func() { printf("\nSIGCONT\n"); signal(SIGCONT,sigcontinue_func); }

void mainloop(struct supernet_info *myinfo)
{
    struct iguana_helper *ptr; int32_t flag;
    while ( 1 )
    {
        flag = 0;
        iguana_jsonQ();
        if ( flag == 0 )
        {
            if ( (ptr= queue_dequeue(&bundlesQ,0)) != 0 )
            {
                if ( ptr->bp != 0 && ptr->coin != 0 )
                    flag += iguana_bundleiters(ptr->coin,ptr->bp,ptr->timelimit);
                myfree(ptr,ptr->allocsize);
            }
            else pangea_queues(SuperNET_MYINFO(0));
        }
        if ( flag == 0 )
        {
            usleep(100000);
        }
    }
}

void iguana_main(void *arg)
{
    int32_t usessl = 0, ismainnet = 1;
    struct supernet_info *myinfo; char *tmpstr,*helperargs,*coinargs,helperstr[512]; int32_t i;
    mycalloc(0,0,0);
    myinfo = SuperNET_MYINFO(0);
    if ( usessl == 0 )
        strcpy(myinfo->NXTAPIURL,"http://127.0.0.1:");
    else strcpy(myinfo->NXTAPIURL,"https://127.0.0.1:");
    if ( ismainnet != 0 )
        strcat(myinfo->NXTAPIURL,"7876/nxt");
    else strcat(myinfo->NXTAPIURL,"6876/nxt");
    signal(SIGINT,sigint_func);
    signal(SIGILL,sigillegal_func);
    signal(SIGHUP,sighangup_func);
    //signal(SIGKILL,sigkill_func);
    signal(SIGABRT,sigabort_func);
    signal(SIGQUIT,sigquit_func);
    signal(SIGCHLD,sigchild_func);
    signal(SIGALRM,sigalarm_func);
    signal(SIGCONT,sigcontinue_func);
   //iguana_chaingenesis(1,1403138561,0x1e0fffff,8359109,bits256_conv("fd1751cc6963d88feca94c0d01da8883852647a37a0a67ce254d62dd8c9d5b2b")); // BTCD
    //iguana_chaingenesis(1,1409839200,0x1e0fffff,64881664,bits256_conv("698a93a1cacd495a7a4fb3864ad8d06ed4421dedbc57f9aaad733ea53b1b5828")); // VPN
    iguana_chaingenesis(1,1317972665,0x1e0ffff0,2084524493,bits256_conv("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9")); // LTC

    iguana_initQ(&helperQ,"helperQ");
    OS_ensure_directory("help");
    OS_ensure_directory("confs");
    OS_ensure_directory("DB"), OS_ensure_directory("DB/ECB");
    OS_ensure_directory("tmp");
    if ( (tmpstr= SuperNET_JSON(myinfo,cJSON_Parse("{\"agent\":\"SuperNET\",\"method\":\"help\"}"),0)) != 0 )
    {
        if ( (API_json= cJSON_Parse(tmpstr)) != 0 && (API_json= jobj(API_json,"result")) != 0 )
            API_json = jobj(API_json,"API");
        free(tmpstr);
    }
    if ( IGUANA_NUMHELPERS == 0 )
        IGUANA_NUMHELPERS = 1;
    for (i=0; i<IGUANA_NUMHELPERS; i++)
    {
        sprintf(helperstr,"{\"name\":\"helper.%d\"}",i);
        helperargs = clonestr(helperstr);
        iguana_launch(iguana_coinadd("BTCD"),"iguana_helper",iguana_helper,helperargs,IGUANA_PERMTHREAD);
    }
    iguana_launch(iguana_coinadd("BTCD"),"rpcloop",iguana_rpcloop,SuperNET_MYINFO(0),IGUANA_PERMTHREAD);
    category_init(&MYINFO);
    if ( (coinargs= SuperNET_keysinit(&MYINFO,arg)) != 0 )
        iguana_launch(iguana_coinadd("BTCD"),"iguana_coins",iguana_coins,coinargs,IGUANA_PERMTHREAD);
    else if ( 1 )
    {
#ifdef __APPLE__
        sleep(1);
        char *str;
        strcpy(MYINFO.rpcsymbol,"BTC");
        iguana_launchcoin(MYINFO.rpcsymbol,cJSON_Parse("{}"));

        if ( 0 && (str= SuperNET_JSON(&MYINFO,cJSON_Parse("{\"wallet\":\"password\",\"agent\":\"iguana\",\"method\":\"addcoin\",\"services\":128,\"maxpeers\":3,\"newcoin\":\"BTC\",\"active\":0}"),0)) != 0 )
        {
            printf("got.(%s)\n",str);
            free(str);
        }
#endif
    }
    if ( arg != 0 )
        SuperNET_JSON(&MYINFO,cJSON_Parse(arg),0);
    mainloop(&MYINFO);
}

