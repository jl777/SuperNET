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

// ALL globals must be here!
char *Iguana_validcommands[] =
{
    "SuperNET", "SuperNETb",
    "version", "verack", "getaddr", "addr", "inv", "getdata", "notfound", "getblocks", "getheaders", "headers", "tx", "block", "mempool", "ping", "pong",
    "reject", "filterload", "filteradd", "filterclear", "merkleblock", "alert", ""
};

struct iguana_info *Coins[IGUANA_MAXCOINS];
int32_t USE_JAY,FIRST_EXTERNAL,IGUANA_disableNXT,Debuglevel;
uint32_t prices777_NXTBLOCK,MAX_DEPTH = 100;
char NXTAPIURL[256],IGUANA_NXTADDR[256],IGUANA_NXTACCTSECRET[256];
uint64_t IGUANA_MY64BITS;
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

struct supernet_info *SuperNET_MYINFO(char *passphrase)
{
    if ( passphrase == 0 || passphrase[0] == 0 )
        return(&MYINFO);
    else
    {
        // search saved accounts
    }
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
        //printf("process.(%s)\n",ptr->jsonstr);
        if ( (*ptr->retjsonstrp= SuperNET_jsonstr(ptr->myinfo,ptr->jsonstr,ptr->remoteaddr)) == 0 )
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
    cJSON *retjson; uint64_t tag; uint32_t timeout; char *jsonstr; char *retjsonstr,*retstr = 0;
    //printf("SuperNET_JSON.(%s) remoteaddr.(%s)\n",jprint(json,0),remoteaddr!=0?remoteaddr:"");
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

void iguana_exit()
{
    int32_t i,j,iter; char *stopstr = "{\"agent\":\"SuperNET\",\"method\":\"stop\"}";
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

void iguana_main(void *arg)
{
    char helperstr[64],*tmpstr,*helperargs,*ipaddr,*coinargs=0,*secret,*jsonstr = arg;
    int32_t i,len,flag,c; cJSON *json; uint8_t secretbuf[512]; int64_t allocsize;
    memset(&MYINFO,0,sizeof(MYINFO));
    if ( (ipaddr= OS_filestr(&allocsize,"ipaddr")) != 0 )
    {
        printf("got ipaddr.(%s)\n",ipaddr);
        len = (int32_t)strlen(ipaddr) - 1;
        while ( len > 8 && ((c= ipaddr[len]) == '\r' || c == '\n' || c == ' ' || c == '\t') )
            ipaddr[len] = 0, len--;
        printf("got ipaddr.(%s) %x\n",ipaddr,is_ipaddr(ipaddr));
        if ( is_ipaddr(ipaddr) != 0 )
        {
            strcpy(MYINFO.ipaddr,ipaddr);
            MYINFO.myaddr.selfipbits = (uint32_t)calc_ipbits(ipaddr);
        }
        free(ipaddr);
    }
    if ( MYINFO.myaddr.selfipbits == 0 )
    {
        strcpy(MYINFO.ipaddr,"127.0.0.1");
        MYINFO.myaddr.selfipbits = (uint32_t)calc_ipbits(MYINFO.ipaddr);
    }
    signal(SIGINT,sigint_func);
    signal(SIGILL,sigillegal_func);
    signal(SIGHUP,sighangup_func);
    //signal(SIGKILL,sigkill_func);
    signal(SIGABRT,sigabort_func);
    signal(SIGQUIT,sigquit_func);
    signal(SIGCHLD,sigchild_func);
    signal(SIGALRM,sigalarm_func);
    signal(SIGCONT,sigcontinue_func);
    mycalloc(0,0,0);
    iguana_initQ(&helperQ,"helperQ");
    OS_ensure_directory("confs");
    OS_ensure_directory("DB");
    OS_ensure_directory("tmp");
    if ( (tmpstr= SuperNET_JSON(&MYINFO,cJSON_Parse("{\"agent\":\"SuperNET\",\"method\":\"help\"}"),0)) != 0 )
    {
        if ( (API_json= cJSON_Parse(tmpstr)) != 0 && (API_json= jobj(API_json,"result")) != 0 )
            API_json = jobj(API_json,"API");
        free(tmpstr);
    }
    OS_randombytes(MYINFO.privkey.bytes,sizeof(MYINFO.privkey));
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
    MYINFO.myaddr.pubkey = curve25519(MYINFO.privkey,curve25519_basepoint9());
    char str[65],str2[65]; printf("PRIV.%s PUB.%s\n",bits256_str(str,MYINFO.privkey),bits256_str(str2,MYINFO.myaddr.pubkey));
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
        if ( (str= SuperNET_JSON(&MYINFO,cJSON_Parse("{\"agent\":\"iguana\",\"method\":\"addcoin\",\"services\":128,\"maxpeers\":12,\"activecoin\":\"BTCD\",\"active\":1}"),0)) != 0 )
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

