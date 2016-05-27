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
#define CHROMEAPP_CONF "iguana.config"
#define CHROMEAPP_MAIN iguana_main
#define CHROMEAPP_JSON iguana_JSON
#define CHROMEAPP_HANDLER Handler_iguana

#include "../pnacl_main.h"
#include "iguana777.h"
#include "SuperNET.h"
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_schnorr.h"
#include "secp256k1/include/secp256k1_rangeproof.h"

/*#undef fopen
#undef fclose
int32_t Fopen_count,Fclose_count;

FILE *myfopen(char *fname,char *mode)
{
    FILE *fp;
    if ( (fp= fopen(fname,mode)) != 0 )
    {
        Fopen_count++;
        if ( Fopen_count > 2*Fclose_count )
            printf("Fopens.%d vs Fcloses.%d [%d]\n",Fopen_count,Fclose_count,Fopen_count-Fclose_count);
        return(fp);
    }
    return(0);
}

int32_t myfclose(FILE *fp)
{
    Fclose_count++;
    return(fclose(fp));
}*/

// ALL globals must be here!
char *Iguana_validcommands[] =
{
    "SuperNET", "SuperNETb", "inv2", "getdata2", "InstantDEX", "pangea", "quote", "ConnectTo",
    "version", "verack", "getaddr", "addr", "inv", "getdata", "notfound", "getblocks", "getheaders", "headers", "tx", "block", "mempool", "ping", "pong",
    "reject", "filterload", "filteradd", "filterclear", "merkleblock", "alert", ""
};
int32_t Showmode,Autofold,PANGEA_MAXTHREADS = 1;

struct category_info *Categories;
struct iguana_info *Coins[IGUANA_MAXCOINS];
char Userhome[512];
int32_t USE_JAY,FIRST_EXTERNAL,IGUANA_disableNXT,Debuglevel,IGUANA_BIGENDIAN;
uint32_t prices777_NXTBLOCK,MAX_DEPTH = 100;
queue_t helperQ,jsonQ,finishedQ,bundlesQ,emitQ;
struct supernet_info MYINFO,**MYINFOS;
int32_t MAIN_initflag;
int32_t HDRnet,netBLOCKS;
cJSON *API_json;

#ifdef __PNACL__
char GLOBAL_TMPDIR[512] = "/DB/tmp";
char GLOBAL_DBDIR[512] = "/DB";
char GLOBAL_HELPDIR[512] = "/DB/help";
char GLOBAL_VALIDATEDIR[512] = "/DB/purgeable";
char GLOBAL_CONFSDIR[512] = "/DB/confs";
int32_t IGUANA_NUMHELPERS = 1;
#else
char GLOBAL_TMPDIR[512] = "tmp";
char GLOBAL_HELPDIR[512] = "help";
char GLOBAL_DBDIR[512] = "DB";
char GLOBAL_VALIDATEDIR[512] = "DB/purgeable";
char GLOBAL_CONFSDIR[512] = "confs";
#ifdef __linux
int32_t IGUANA_NUMHELPERS = 8;
#else
int32_t IGUANA_NUMHELPERS = 4;
#endif
#endif

struct iguana_jsonitem { struct queueitem DL; struct supernet_info *myinfo; uint32_t fallback,expired,allocsize; char *retjsonstr; char remoteaddr[64]; uint16_t port; char jsonstr[]; };

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
    if ( MYINFO.ctx == 0 )
    {
        MYINFO.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        secp256k1_pedersen_context_initialize(MYINFO.ctx);
        secp256k1_rangeproof_context_initialize(MYINFO.ctx);
        OS_randombytes(MYINFO.privkey.bytes,sizeof(MYINFO.privkey));
        MYINFO.myaddr.pubkey = curve25519(MYINFO.privkey,curve25519_basepoint9());
        printf("SuperNET_MYINFO: generate session keypair\n");
    }
    if ( passphrase == 0 || passphrase[0] == 0 )
        return(&MYINFO);
    else
    {
        // search saved accounts
    }
    return(&MYINFO);
    return(0);
}

struct supernet_info *SuperNET_MYINFOfind(int32_t *nump,bits256 pubkey)
{
    int32_t i;
    *nump = 0;
    if ( MYINFOS != 0 )
    {
        for (i=0; MYINFOS[i]!=0; i++)
        {
            *nump = i;
            if ( bits256_cmp(pubkey,MYINFOS[i]->myaddr.persistent) == 0 )
                return(MYINFOS[i]);
        }
        *nump = i;
    }
    return(0);
}

int32_t SuperNET_MYINFOS(struct supernet_info **myinfos,int32_t max)
{
    int32_t i = 0;
    if ( MYINFOS != 0 )
    {
        for (i=0; i<max; i++)
            if ( (myinfos[i]= MYINFOS[i]) == 0 )
                break;
    }
    return(i);
}

void SuperNET_MYINFOadd(struct supernet_info *myinfo)
{
    int32_t num;
    if ( SuperNET_MYINFOfind(&num,myinfo->myaddr.persistent) == 0 )
    {
        MYINFOS = realloc(MYINFOS,(num + 2) * sizeof(*MYINFOS));
        char str[65]; printf("MYNFOadd[%d] <- %s\n",num,bits256_str(str,myinfo->myaddr.persistent));
        MYINFOS[num] = calloc(1,sizeof(*myinfo));
        *MYINFOS[num] = *myinfo;
        MYINFOS[++num] = 0;
    }
}

char *iguana_JSON(char *jsonstr,uint16_t port)
{
    char *retstr=0; cJSON *json;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        retstr = SuperNET_JSON(0,json,"127.0.0.1",port);
        free_json(json);
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null return from iguana_JSON\"}");
    return(retstr);
}

char *SuperNET_jsonstr(struct supernet_info *myinfo,char *jsonstr,char *remoteaddr,uint16_t port)
{
    cJSON *json; char *agent,*method,*retstr = 0;
    //char str[65]; printf("SuperNET_jsonstr %p %s\n",&myinfo->privkey,bits256_str(str,myinfo->privkey));
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        method = jstr(json,"method");
        if ( (agent= jstr(json,"agent")) != 0 && method != 0 && jobj(json,"params") == 0 )
            retstr = SuperNET_parser(myinfo,agent,method,json,remoteaddr);
        else if ( method != 0 && is_bitcoinrpc(myinfo,method,remoteaddr) >= 0 )
            retstr = iguana_bitcoinRPC(myinfo,method,json,remoteaddr,port);
        else retstr = clonestr("{\"error\":\"need both agent and method\"}");
        free_json(json);
    } else retstr = clonestr("{\"error\":\"couldnt parse SuperNET_JSON\"}");
    //printf("SuperNET_jsonstr ret.(%s)\n",retstr);
    return(retstr);
}

int32_t iguana_jsonQ()
{
    struct iguana_jsonitem *ptr; char *str;
    if ( (ptr= queue_dequeue(&finishedQ,0)) != 0 )
    {
        if ( ptr->expired != 0 )
        {
            if ( (str= ptr->retjsonstr) != 0 )
            {
                ptr->retjsonstr = 0;
                free(str);
            }
            printf("garbage collection: expired.(%s)\n",ptr->jsonstr);
            myfree(ptr,ptr->allocsize);
        } else queue_enqueue("finishedQ",&finishedQ,&ptr->DL,0);
    }
    if ( (ptr= queue_dequeue(&jsonQ,0)) != 0 )
    {
        if ( (ptr->retjsonstr= SuperNET_jsonstr(ptr->myinfo,ptr->jsonstr,ptr->remoteaddr,ptr->port)) == 0 )
            ptr->retjsonstr = clonestr("{\"error\":\"null return from iguana_jsonstr\"}");
        //printf("finished.(%s) -> (%s) %.0f\n",ptr->jsonstr,*ptr->retjsonstrp!=0?*ptr->retjsonstrp:"null return",OS_milliseconds());
        queue_enqueue("finishedQ",&finishedQ,&ptr->DL,0);
        return(1);
    }
    return(0);
}

char *iguana_blockingjsonstr(struct supernet_info *myinfo,char *jsonstr,uint64_t tag,int32_t maxmillis,char *remoteaddr,uint16_t port)
{
    struct iguana_jsonitem *ptr; int32_t len,allocsize; double expiration;
    expiration = OS_milliseconds() + maxmillis;
    //printf("blocking case.(%s) %.0f maxmillis.%d\n",jsonstr,OS_milliseconds(),maxmillis);
    len = (int32_t)strlen(jsonstr);
    allocsize = sizeof(*ptr) + len + 1;
    ptr = mycalloc('J',1,allocsize);
    ptr->allocsize = allocsize;
    ptr->myinfo = myinfo;
    ptr->port = port;
    ptr->retjsonstr = 0;
    safecopy(ptr->remoteaddr,remoteaddr,sizeof(ptr->remoteaddr));
    memcpy(ptr->jsonstr,jsonstr,len+1);
    queue_enqueue("jsonQ",&jsonQ,&ptr->DL,0);
    while ( OS_milliseconds() < expiration )
    {
        usleep(100);
        if ( ptr->retjsonstr != 0 )
        {
            //printf("got blocking retjsonstr.(%s) delete allocsize.%d:%d\n",retjsonstr,allocsize,ptr->allocsize);
            queue_delete(&finishedQ,&ptr->DL,ptr->allocsize,1);
            return(ptr->retjsonstr);
        }
        usleep(1000);
    }
    //printf("(%s) expired\n",jsonstr);
    ptr->expired = (uint32_t)time(NULL);
    return(clonestr("{\"error\":\"iguana jsonstr expired\"}"));
}

char *SuperNET_processJSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr,uint16_t port)
{
    cJSON *retjson; uint64_t tag; uint32_t timeout; char *jsonstr,*hexmsg,*method,*retjsonstr,*retstr = 0;
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
        if ( (method= jstr(json,"method")) != 0 && strcmp(method,"DHT") == 0 && remoteaddr != 0 && (hexmsg= jstr(json,"hexmsg")) != 0 )
        {
            //printf("hexmsgprocess myinfo.%p\n",myinfo);
            SuperNET_hexmsgprocess(myinfo,0,json,hexmsg,remoteaddr);
            return(clonestr("{\"result\":\"processed remote DHT\"}"));
        }
        jsonstr = jprint(json,0);
        //printf("RPC? (%s)\n",jsonstr);
        if ( (remoteaddr == 0 || remoteaddr[0] == 0 || jstr(json,"immediate") != 0) && port == IGUANA_RPCPORT )
            retjsonstr = SuperNET_jsonstr(myinfo,jsonstr,remoteaddr,port);
        else retjsonstr = iguana_blockingjsonstr(myinfo,jsonstr,tag,timeout,remoteaddr,port);
        if ( retjsonstr != 0 )
        {
            if ( (retjsonstr[0] == '{' || retjsonstr[0] == '[') && (retjson= cJSON_Parse(retjsonstr)) != 0 )
            {
                if ( is_cJSON_Array(retjson) == 0 )
                {
                    if ( j64bits(retjson,"tag") != tag )
                    {
                        if ( jobj(retjson,"tag") != 0 )
                            jdelete(retjson,"tag");
                        jadd64bits(retjson,"tag",tag);
                    }
                    retstr = jprint(retjson,1);
                    free(retjsonstr);//,strlen(retjsonstr)+1);
                    //printf("retstr.(%s) retjsonstr.%p retjson.%p\n",retstr,retjsonstr,retjson);
                } else retstr = retjsonstr;
            } else retstr = retjsonstr;
        }
        free(jsonstr);
    } else retstr = clonestr("{\"error\":\"cant parse JSON\"}");
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null return\"}");
    //printf("processJSON.(%s)\n",retstr);
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
                                iguana_send_supernet(&Coins[i]->peers.active[j],stopstr,0);
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

#ifndef _WIN32
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
#endif

void iguana_signalsinit()
{
#ifndef _WIN32
    signal(SIGABRT,sigabort_func);
    signal(SIGINT,sigint_func);
    signal(SIGILL,sigillegal_func);
    signal(SIGHUP,sighangup_func);
    //signal(SIGKILL,sigkill_func);
    signal(SIGQUIT,sigquit_func);
    signal(SIGCHLD,sigchild_func);
    signal(SIGALRM,sigalarm_func);
    signal(SIGCONT,sigcontinue_func);
#endif
}

// mksquashfs DB/BTC BTC.squash -b 1048576 -> 19GB?
// mksquashfs DB/BTC BTC.lzo -comp lzo -b 1048576 -> takes a really long time -> 20GB
// mksquashfs DB/BTC BTC.xz -b 1048576 -comp xz -Xdict-size 512K -> takes a long time -> 16GB
// mksquashfs DB/BTC BTC.xz1m -b 1048576 -comp xz -Xdict-size 1024K -> takes a long time ->
/*
 mksquashfs DB/BTC BTC.xz -comp xz
 mksquashfs DB/BTC BTC.xzs -b 16384 -comp xz -Xdict-size 8K
 mksquashfs DB/BTC BTC.xz1m -b 1048576 -comp xz -Xdict-size 1024K
 mksquashfs DB/BTC BTC.xz8k -comp xz -Xdict-size 8K
mksquashfs DB/BTC BTC.lzo -comp lzo
mksquashfs DB/BTC BTC.lzo1m -comp lzo -b 1048576
mksquashfs DB/BTC BTC.squash
mksquashfs DB/BTC BTC.squash1M -b 1048576
 
rm BTC.xz; mksquashfs DB/BTC BTC.xz -comp xz -b 1048576 -comp xz -Xdict-size 1024K
 sudo mount BTC.xz DB/ro/BTC -t squashfs -o loop
 https://github.com/vasi/squashfuse
*/


void mainloop(struct supernet_info *myinfo)
{
    int32_t i,j,n,flag,isRT,numpeers; struct iguana_info *coin; struct iguana_bundle *bp;
    sleep(3);
    printf("mainloop\n");
    while ( 1 )
    {
        //printf("main iteration\n");
        if ( myinfo->expiration != 0 && time(NULL) > myinfo->expiration )
            iguana_walletlock(myinfo,0);
        flag = 0;
        isRT = 1;
        numpeers = 0;
        if ( 1 )
        {
            for (i=0; i<IGUANA_MAXCOINS; i++)
                if ( (coin= Coins[i]) != 0 && coin->current != 0 )
                {
                    if ( coin->active != 0 && coin->started != 0 )
                    {
                        isRT *= coin->isRT;
                        numpeers += coin->peers.numranked;
                        if ( time(NULL) > coin->startutc+10 && coin->spendvectorsaved == 0 && coin->blocks.hwmchain.height/coin->chain->bundlesize >= (coin->longestchain-coin->minconfirms)/coin->chain->bundlesize )
                        {
                            n = coin->bundlescount-1;
                            if ( iguana_emitfinished(coin,1) >= n )
                            {
                                if ( coin->PREFETCHLAG >= 0 && coin->fastfind == 0 )
                                {
                                    for (j=0; j<n; j++)
                                        iguana_alloctxbits(coin,&coin->bundles[j]->ramchain);
                                    sleep(3);
                                }
                                if ( iguana_validated(coin) < n || iguana_utxofinished(coin) < n || iguana_balancefinished(coin) < n )
                                {
                                    coin->spendvectorsaved = 1;
                                    printf("update volatile data, need.%d vs utxo.%d balances.%d validated.%d\n",n,iguana_utxofinished(coin),iguana_balancefinished(coin),iguana_validated(coin));
                                }
                                else
                                {
                                    coin->spendvectorsaved = (uint32_t)time(NULL);
                                    //printf("already done UTXOGEN (%d %d) (%d %d)\n",iguana_utxofinished(coin),n,iguana_balancefinished(coin),n);
                                }
                            } //else printf("only emit.%d vs %d\n",iguana_emitfinished(coin),n);
                        }
                        if ( (bp= coin->current) != 0 && coin->stucktime != 0 && coin->isRT == 0 && coin->RTheight == 0 && (time(NULL) - coin->stucktime) > coin->MAXSTUCKTIME )
                        {
                            if ( 0 )
                            {
                                printf("%s is stuck too long, restarting due to %d\n",coin->symbol,bp->hdrsi);
                                if ( coin->started != 0 )
                                {
                                    iguana_coinpurge(coin);
                                    sleep(3);
                                    while ( coin->started == 0 )
                                    {
                                        printf("wait for coin to reactivate\n");
                                        sleep(1);
                                    }
                                    sleep(3);
                                }
                            }
                        }
                        if ( 0 && flag != 0 )
                            printf("call RT update busy.%d\n",coin->RTramchain_busy);
                    }
                }
        }
        pangea_queues(SuperNET_MYINFO(0));
        if ( flag == 0 )
            usleep(10000 + isRT*100000 + (numpeers == 0)*1000000);
        //iguana_jsonQ(); // cant do this here safely, need to send to coin specific queue
    }
}

int32_t calcmofn(uint8_t *allshares,uint8_t *myshares[],uint8_t *sharenrs,int32_t M,uint8_t *data,int32_t datasize,int32_t N)
{
    int32_t j;
    calc_shares(allshares,(void *)data,datasize,datasize,M,N,sharenrs);
    for (j=0; j<N; j++)
        myshares[j] = &allshares[j * datasize];
    return(datasize);
}

uint8_t *recoverdata(uint8_t *shares[],uint8_t *sharenrs,int32_t M,int32_t datasize,int32_t N)
{
    void *G; int32_t i; uint8_t *recover,recovernrs[255];
    if ( (recover= calloc(1,datasize)) == 0 )
    {
        printf("cards777_recover: unexpected out of memory error\n");
        return(0);
    }
    memset(recovernrs,0,sizeof(recovernrs));
    for (i=0; i<N; i++)
        if ( shares[i] != 0 )
            recovernrs[i] = sharenrs[i];
    G = gfshare_ctx_init_dec(recovernrs,N,datasize);
    for (i=0; i<N; i++)
        if ( shares[i] != 0 )
            gfshare_ctx_dec_giveshare(G,i,shares[i]);
    gfshare_ctx_dec_newshares(G,recovernrs);
    gfshare_ctx_dec_extract(G,recover);
    gfshare_ctx_free(G);
    return(recover);
}

static uint8_t logs[256] = {
    0x00, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1a, 0xc6,
    0x03, 0xdf, 0x33, 0xee, 0x1b, 0x68, 0xc7, 0x4b,
    0x04, 0x64, 0xe0, 0x0e, 0x34, 0x8d, 0xef, 0x81,
    0x1c, 0xc1, 0x69, 0xf8, 0xc8, 0x08, 0x4c, 0x71,
    0x05, 0x8a, 0x65, 0x2f, 0xe1, 0x24, 0x0f, 0x21,
    0x35, 0x93, 0x8e, 0xda, 0xf0, 0x12, 0x82, 0x45,
    0x1d, 0xb5, 0xc2, 0x7d, 0x6a, 0x27, 0xf9, 0xb9,
    0xc9, 0x9a, 0x09, 0x78, 0x4d, 0xe4, 0x72, 0xa6,
    0x06, 0xbf, 0x8b, 0x62, 0x66, 0xdd, 0x30, 0xfd,
    0xe2, 0x98, 0x25, 0xb3, 0x10, 0x91, 0x22, 0x88,
    0x36, 0xd0, 0x94, 0xce, 0x8f, 0x96, 0xdb, 0xbd,
    0xf1, 0xd2, 0x13, 0x5c, 0x83, 0x38, 0x46, 0x40,
    0x1e, 0x42, 0xb6, 0xa3, 0xc3, 0x48, 0x7e, 0x6e,
    0x6b, 0x3a, 0x28, 0x54, 0xfa, 0x85, 0xba, 0x3d,
    0xca, 0x5e, 0x9b, 0x9f, 0x0a, 0x15, 0x79, 0x2b,
    0x4e, 0xd4, 0xe5, 0xac, 0x73, 0xf3, 0xa7, 0x57,
    0x07, 0x70, 0xc0, 0xf7, 0x8c, 0x80, 0x63, 0x0d,
    0x67, 0x4a, 0xde, 0xed, 0x31, 0xc5, 0xfe, 0x18,
    0xe3, 0xa5, 0x99, 0x77, 0x26, 0xb8, 0xb4, 0x7c,
    0x11, 0x44, 0x92, 0xd9, 0x23, 0x20, 0x89, 0x2e,
    0x37, 0x3f, 0xd1, 0x5b, 0x95, 0xbc, 0xcf, 0xcd,
    0x90, 0x87, 0x97, 0xb2, 0xdc, 0xfc, 0xbe, 0x61,
    0xf2, 0x56, 0xd3, 0xab, 0x14, 0x2a, 0x5d, 0x9e,
    0x84, 0x3c, 0x39, 0x53, 0x47, 0x6d, 0x41, 0xa2,
    0x1f, 0x2d, 0x43, 0xd8, 0xb7, 0x7b, 0xa4, 0x76,
    0xc4, 0x17, 0x49, 0xec, 0x7f, 0x0c, 0x6f, 0xf6,
    0x6c, 0xa1, 0x3b, 0x52, 0x29, 0x9d, 0x55, 0xaa,
    0xfb, 0x60, 0x86, 0xb1, 0xbb, 0xcc, 0x3e, 0x5a,
    0xcb, 0x59, 0x5f, 0xb0, 0x9c, 0xa9, 0xa0, 0x51,
    0x0b, 0xf5, 0x16, 0xeb, 0x7a, 0x75, 0x2c, 0xd7,
    0x4f, 0xae, 0xd5, 0xe9, 0xe6, 0xe7, 0xad, 0xe8,
    0x74, 0xd6, 0xf4, 0xea, 0xa8, 0x50, 0x58, 0xaf };

static uint8_t exps[510] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1d, 0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13, 0x26,
    0x4c, 0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9,
    0x8f, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0,
    0x9d, 0x27, 0x4e, 0x9c, 0x25, 0x4a, 0x94, 0x35,
    0x6a, 0xd4, 0xb5, 0x77, 0xee, 0xc1, 0x9f, 0x23,
    0x46, 0x8c, 0x05, 0x0a, 0x14, 0x28, 0x50, 0xa0,
    0x5d, 0xba, 0x69, 0xd2, 0xb9, 0x6f, 0xde, 0xa1,
    0x5f, 0xbe, 0x61, 0xc2, 0x99, 0x2f, 0x5e, 0xbc,
    0x65, 0xca, 0x89, 0x0f, 0x1e, 0x3c, 0x78, 0xf0,
    0xfd, 0xe7, 0xd3, 0xbb, 0x6b, 0xd6, 0xb1, 0x7f,
    0xfe, 0xe1, 0xdf, 0xa3, 0x5b, 0xb6, 0x71, 0xe2,
    0xd9, 0xaf, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88,
    0x0d, 0x1a, 0x34, 0x68, 0xd0, 0xbd, 0x67, 0xce,
    0x81, 0x1f, 0x3e, 0x7c, 0xf8, 0xed, 0xc7, 0x93,
    0x3b, 0x76, 0xec, 0xc5, 0x97, 0x33, 0x66, 0xcc,
    0x85, 0x17, 0x2e, 0x5c, 0xb8, 0x6d, 0xda, 0xa9,
    0x4f, 0x9e, 0x21, 0x42, 0x84, 0x15, 0x2a, 0x54,
    0xa8, 0x4d, 0x9a, 0x29, 0x52, 0xa4, 0x55, 0xaa,
    0x49, 0x92, 0x39, 0x72, 0xe4, 0xd5, 0xb7, 0x73,
    0xe6, 0xd1, 0xbf, 0x63, 0xc6, 0x91, 0x3f, 0x7e,
    0xfc, 0xe5, 0xd7, 0xb3, 0x7b, 0xf6, 0xf1, 0xff,
    0xe3, 0xdb, 0xab, 0x4b, 0x96, 0x31, 0x62, 0xc4,
    0x95, 0x37, 0x6e, 0xdc, 0xa5, 0x57, 0xae, 0x41,
    0x82, 0x19, 0x32, 0x64, 0xc8, 0x8d, 0x07, 0x0e,
    0x1c, 0x38, 0x70, 0xe0, 0xdd, 0xa7, 0x53, 0xa6,
    0x51, 0xa2, 0x59, 0xb2, 0x79, 0xf2, 0xf9, 0xef,
    0xc3, 0x9b, 0x2b, 0x56, 0xac, 0x45, 0x8a, 0x09,
    0x12, 0x24, 0x48, 0x90, 0x3d, 0x7a, 0xf4, 0xf5,
    0xf7, 0xf3, 0xfb, 0xeb, 0xcb, 0x8b, 0x0b, 0x16,
    0x2c, 0x58, 0xb0, 0x7d, 0xfa, 0xe9, 0xcf, 0x83,
    0x1b, 0x36, 0x6c, 0xd8, 0xad, 0x47, 0x8e, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1d,
    0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13, 0x26, 0x4c,
    0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9, 0x8f,
    0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0, 0x9d,
    0x27, 0x4e, 0x9c, 0x25, 0x4a, 0x94, 0x35, 0x6a,
    0xd4, 0xb5, 0x77, 0xee, 0xc1, 0x9f, 0x23, 0x46,
    0x8c, 0x05, 0x0a, 0x14, 0x28, 0x50, 0xa0, 0x5d,
    0xba, 0x69, 0xd2, 0xb9, 0x6f, 0xde, 0xa1, 0x5f,
    0xbe, 0x61, 0xc2, 0x99, 0x2f, 0x5e, 0xbc, 0x65,
    0xca, 0x89, 0x0f, 0x1e, 0x3c, 0x78, 0xf0, 0xfd,
    0xe7, 0xd3, 0xbb, 0x6b, 0xd6, 0xb1, 0x7f, 0xfe,
    0xe1, 0xdf, 0xa3, 0x5b, 0xb6, 0x71, 0xe2, 0xd9,
    0xaf, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88, 0x0d,
    0x1a, 0x34, 0x68, 0xd0, 0xbd, 0x67, 0xce, 0x81,
    0x1f, 0x3e, 0x7c, 0xf8, 0xed, 0xc7, 0x93, 0x3b,
    0x76, 0xec, 0xc5, 0x97, 0x33, 0x66, 0xcc, 0x85,
    0x17, 0x2e, 0x5c, 0xb8, 0x6d, 0xda, 0xa9, 0x4f,
    0x9e, 0x21, 0x42, 0x84, 0x15, 0x2a, 0x54, 0xa8,
    0x4d, 0x9a, 0x29, 0x52, 0xa4, 0x55, 0xaa, 0x49,
    0x92, 0x39, 0x72, 0xe4, 0xd5, 0xb7, 0x73, 0xe6,
    0xd1, 0xbf, 0x63, 0xc6, 0x91, 0x3f, 0x7e, 0xfc,
    0xe5, 0xd7, 0xb3, 0x7b, 0xf6, 0xf1, 0xff, 0xe3,
    0xdb, 0xab, 0x4b, 0x96, 0x31, 0x62, 0xc4, 0x95,
    0x37, 0x6e, 0xdc, 0xa5, 0x57, 0xae, 0x41, 0x82,
    0x19, 0x32, 0x64, 0xc8, 0x8d, 0x07, 0x0e, 0x1c,
    0x38, 0x70, 0xe0, 0xdd, 0xa7, 0x53, 0xa6, 0x51,
    0xa2, 0x59, 0xb2, 0x79, 0xf2, 0xf9, 0xef, 0xc3,
    0x9b, 0x2b, 0x56, 0xac, 0x45, 0x8a, 0x09, 0x12,
    0x24, 0x48, 0x90, 0x3d, 0x7a, 0xf4, 0xf5, 0xf7,
    0xf3, 0xfb, 0xeb, 0xcb, 0x8b, 0x0b, 0x16, 0x2c,
    0x58, 0xb0, 0x7d, 0xfa, 0xe9, 0xcf, 0x83, 0x1b,
    0x36, 0x6c, 0xd8, 0xad, 0x47, 0x8e };

/*
 * This file is Copyright Daniel Silverstone <dsilvers@digital-scurf.org> 2006,2015
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

//#include "config.h"
//#include "libgfshare.h"
//#include "libgfshare_tables.h"

#ifndef LIBGFSHARE_H
#define LIBGFSHARE_H


typedef struct _gfshare_ctx gfshare_ctx;

typedef void (*gfshare_rand_func_t)(uint8_t*, unsigned int);

/* This will, use random(). It's not very good so you should not use it unless
 * you must.  If you can't be bothered to write your own, be sure to srandom()
 * before you use any of the gfshare_ctx_enc_* functions
 */
extern const gfshare_rand_func_t gfshare_bad_idea_but_fill_rand_using_random;
/* This must be filled out before running any of the gfshare_ctx_enc_* calls
 * or bad things will happen since it is initialised to NULL be default.
 * You should fill this with a routine which uses urandom or similar ideally.
 * If you cannot do that on your platform, you can use the function provided
 * which does random() calls, but I recommend against it unless you must.
 */
extern gfshare_rand_func_t gfshare_fill_rand;

/* ------------------------------------------------------[ Preparation ]---- */

/* Initialise a gfshare context for producing shares */
gfshare_ctx* gfshare_ctx_init_enc(uint8_t* /* sharenrs */,unsigned int /* sharecount */, uint8_t /* threshold */,unsigned int /* size */);

/* Initialise a gfshare context for recombining shares */
gfshare_ctx* gfshare_ctx_init_dec(uint8_t* /* sharenrs */,unsigned int /* sharecount */,unsigned int /* size */);

/* Free a share context's memory. */
void gfshare_ctx_free(gfshare_ctx* /* ctx */);

/* --------------------------------------------------------[ Splitting ]---- */

/* Provide a secret to the encoder. (this re-scrambles the coefficients) */
void gfshare_ctx_enc_setsecret(gfshare_ctx* /* ctx */,uint8_t* /* secret */);

/* Extract a share from the context.
 * 'share' must be preallocated and at least 'size' bytes long.
 * 'sharenr' is the index into the 'sharenrs' array of the share you want.
 */
void gfshare_ctx_enc_getshare(gfshare_ctx* /* ctx */,uint8_t /* sharenr */,uint8_t* /* share */);

/* ----------------------------------------------------[ Recombination ]---- */

/* Inform a recombination context of a change in share indexes */
void gfshare_ctx_dec_newshares(gfshare_ctx* /* ctx */, uint8_t* /* sharenrs */);

/* Provide a share context with one of the shares.
 * The 'sharenr' is the index into the 'sharenrs' array
 */
void gfshare_ctx_dec_giveshare(gfshare_ctx* /* ctx */,uint8_t /* sharenr */,uint8_t* /* share */);

/* Extract the secret by interpolation of the shares.
 * secretbuf must be allocated and at least 'size' bytes long
 */
void gfshare_ctx_dec_extract(gfshare_ctx* /* ctx */,uint8_t* /* secretbuf */);

#endif /* LIBGFSHARE_H */


#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define XMALLOC malloc
#define XFREE free

struct _gfshare_ctx {
    unsigned int sharecount;
    unsigned int threshold;
    unsigned int size;
    uint8_t* sharenrs;
    uint8_t* buffer;
    unsigned int buffersize;
};

static void _gfshare_fill_rand_using_random( uint8_t* buffer,unsigned int count )
{
    OS_randombytes(buffer,count);
    /*unsigned int i;
    for( i = 0; i < count; ++i )
        buffer[i] = (random() & 0xff00) >> 8;  apparently the bottom 8 aren't
                                               * very random but the middles ones
                                               * are
                                               */
}
const gfshare_rand_func_t gfshare_bad_idea_but_fill_rand_using_random = (void *)_gfshare_fill_rand_using_random;
gfshare_rand_func_t gfshare_fill_rand = NULL;

/* ------------------------------------------------------[ Preparation ]---- */

static gfshare_ctx * _gfshare_ctx_init_core( uint8_t *sharenrs,unsigned int sharecount,uint8_t threshold,unsigned int size )
{
    gfshare_ctx *ctx;
    
    ctx = XMALLOC( sizeof(struct _gfshare_ctx) );
    if( ctx == NULL )
        return NULL; /* errno should still be set from XMALLOC() */
    
    ctx->sharecount = sharecount;
    ctx->threshold = threshold;
    ctx->size = size;
    ctx->sharenrs = XMALLOC( sharecount );
    
    if( ctx->sharenrs == NULL ) {
        int saved_errno = errno;
        XFREE( ctx );
        errno = saved_errno;
        return NULL;
    }
    
    memcpy( ctx->sharenrs, sharenrs, sharecount );
    ctx->buffersize = threshold * size;
    ctx->buffer = XMALLOC( ctx->buffersize );
    
    if( ctx->buffer == NULL ) {
        int saved_errno = errno;
        XFREE( ctx->sharenrs );
        XFREE( ctx );
        errno = saved_errno;
        return NULL;
    }
    
    return ctx;
}

/* Initialise a gfshare context for producing shares */
gfshare_ctx * gfshare_ctx_init_enc( uint8_t* sharenrs,unsigned int sharecount,uint8_t threshold,unsigned int size )
{
    unsigned int i;
    
    for (i = 0; i < sharecount; i++) {
        if (sharenrs[i] == 0) {
            /* can't have x[i] = 0 - that would just be a copy of the secret, in
             * theory (in fact, due to the way we use exp/log for multiplication and
             * treat log(0) as 0, it ends up as a copy of x[i] = 1) */
            errno = EINVAL;
            return NULL;
        }
    }
    
    return _gfshare_ctx_init_core( sharenrs, sharecount, threshold, size );
}

/* Initialise a gfshare context for recombining shares */
gfshare_ctx* gfshare_ctx_init_dec( uint8_t* sharenrs,unsigned int sharecount,unsigned int size )
{
    gfshare_ctx *ctx = _gfshare_ctx_init_core( sharenrs, sharecount, sharecount, size );
    
    if( ctx != NULL )
        ctx->threshold = 0;
    
    return ctx;
}

/* Free a share context's memory. */
void gfshare_ctx_free( gfshare_ctx* ctx )
{
    gfshare_fill_rand( ctx->buffer, ctx->buffersize );
    gfshare_fill_rand( ctx->sharenrs, ctx->sharecount );
    XFREE( ctx->sharenrs );
    XFREE( ctx->buffer );
    gfshare_fill_rand( (uint8_t*)ctx, sizeof(struct _gfshare_ctx) );
    XFREE( ctx );
}

/* --------------------------------------------------------[ Splitting ]---- */

/* Provide a secret to the encoder. (this re-scrambles the coefficients) */
void gfshare_ctx_enc_setsecret( gfshare_ctx* ctx,uint8_t* secret)
{
    memcpy( ctx->buffer + ((ctx->threshold-1) * ctx->size),
           secret,
           ctx->size );
    gfshare_fill_rand( ctx->buffer, (ctx->threshold-1) * ctx->size );
}

/* Extract a share from the context.
 * 'share' must be preallocated and at least 'size' bytes long.
 * 'sharenr' is the index into the 'sharenrs' array of the share you want.
 */
void gfshare_ctx_enc_getshare( gfshare_ctx* ctx,uint8_t sharenr,uint8_t* share)
{
    unsigned int pos, coefficient;
    unsigned int ilog = logs[ctx->sharenrs[sharenr]];
    uint8_t *coefficient_ptr = ctx->buffer;
    uint8_t *share_ptr;
    for( pos = 0; pos < ctx->size; ++pos )
        share[pos] = *(coefficient_ptr++);
    for( coefficient = 1; coefficient < ctx->threshold; ++coefficient ) {
        share_ptr = share;
        for( pos = 0; pos < ctx->size; ++pos ) {
            uint8_t share_byte = *share_ptr;
            if( share_byte )
                share_byte = exps[ilog + logs[share_byte]];
            *share_ptr++ = share_byte ^ *coefficient_ptr++;
        }
    }
}

/* ----------------------------------------------------[ Recombination ]---- */

/* Inform a recombination context of a change in share indexes */
void gfshare_ctx_dec_newshares( gfshare_ctx* ctx,uint8_t* sharenrs)
{
    memcpy( ctx->sharenrs, sharenrs, ctx->sharecount );
}

/* Provide a share context with one of the shares.
 * The 'sharenr' is the index into the 'sharenrs' array
 */
void gfshare_ctx_dec_giveshare( gfshare_ctx* ctx,uint8_t sharenr,uint8_t* share )                       
{
    memcpy( ctx->buffer + (sharenr * ctx->size), share, ctx->size );
}

/* Extract the secret by interpolation of the shares.
 * secretbuf must be allocated and at least 'size' bytes long
 */
void gfshare_ctx_dec_extract( gfshare_ctx* ctx,uint8_t* secretbuf )
{
    unsigned int i, j;
    uint8_t *secret_ptr, *share_ptr, sharei,sharej;
    
    for( i = 0; i < ctx->size; ++i )
        secretbuf[i] = 0;
    
    for( i = 0; i < ctx->sharecount; ++i )
    {
        // Compute L(i) as per Lagrange Interpolation
        unsigned Li_top = 0, Li_bottom = 0;
        if ( (sharei= ctx->sharenrs[i]) != 0 )
        {
            for ( j = 0; j < ctx->sharecount; ++j )
            {
                if ( i != j && sharei != (sharej= ctx->sharenrs[j]) )
                {
                    if ( sharej == 0 )
                        continue; // skip empty share */
                    Li_top += logs[sharej];
                    if ( Li_top >= 0xff )
                        Li_top -= 0xff;
                    Li_bottom += logs[sharei ^ sharej];
                    if ( Li_bottom >= 0xff )
                        Li_bottom -= 0xff;
                }
            }
            if ( Li_bottom  > Li_top )
                Li_top += 0xff;
            Li_top -= Li_bottom; // Li_top is now log(L(i))
            secret_ptr = secretbuf, share_ptr = ctx->buffer + (ctx->size * i);
            for (j=0; j<ctx->size; j++)
            {
                if ( *share_ptr != 0 )
                    *secret_ptr ^= exps[Li_top + logs[*share_ptr]];
                share_ptr++, secret_ptr++;
            }
        }
    }
}
void calc_share(uint8_t *buffer,int32_t size,int32_t M,uint32_t ilog,uint8_t *share)
{
    uint32_t pos,coefficient;//,ilog = ctx_logs[ctx->sharenrs[sharenr]];
    //uint8_t *coefficient_ptr = buffer;
    uint8_t *share_ptr,share_byte;
    for (pos=0; pos<size; pos++)
        share[pos] = *(buffer++);
    for (coefficient=1; coefficient<M; coefficient++)
    {
        share_ptr = share;
        for (pos=0; pos<size; pos++)
        {
            share_byte = *share_ptr;
            if ( share_byte != 0 )
                share_byte = exps[ilog + logs[share_byte]];
            *share_ptr++ = (share_byte ^ *buffer++);
        }
    }
}

void calc_shares(uint8_t *shares,uint8_t *secret,int32_t size,int32_t width,int32_t M,int32_t N,uint8_t *sharenrs)
{
    int32_t i;
    uint8_t *buffer = calloc(M,width);
    memset(shares,0,N*width);
    memcpy(buffer + ((M - 1) * size),secret,size);
    //gfshare_fill_rand(buffer,(M - 1) * size);
    OS_randombytes(buffer,(M - 1) * size);
    for (i=0; i<N; i++)
    {
        //uint32_t _crc32(uint32_t crc, const void *buf, size_t size);
        calc_share(buffer,size,M,logs[sharenrs[i]],&shares[i * width]);
        printf("(%02x %08x) ",sharenrs[i],calc_crc32(0,&shares[i*width],size));
    }
    free(buffer);
}

//#include <stdio.h>

int32_t test(int32_t M,int32_t N,int32_t datasize)
{
    int ok = 1, i;
    uint8_t * secret = malloc(datasize);
    uint8_t *shares[255];
    uint8_t *recomb = malloc(datasize);
    uint8_t sharenrs[255],newsharenrs[255];// = (uint8_t *)strdup("0124z89abehtr");
    gfshare_ctx *G;
    gfshare_fill_rand = gfshare_bad_idea_but_fill_rand_using_random;
    for (i=0; i<N; i++)
    {
        sharenrs[i] = i+1;
        shares[i] = malloc(datasize);
    }
    /* Stage 1, make a secret */
    for( i = 0; i < datasize; ++i )
        secret[i] = (rand() & 0xff00) >> 8;
    /* Stage 2, split it N ways with a threshold of M */
    G = gfshare_ctx_init_enc( sharenrs, N, M, datasize );
    gfshare_ctx_enc_setsecret( G, secret );
    for (i=0; i<N; i++)
        gfshare_ctx_enc_getshare( G, i, shares[i] );
    gfshare_ctx_free( G );
    /* Prep the decode shape */
    G = gfshare_ctx_init_dec( sharenrs, N, datasize );
    memset(newsharenrs,0,N);
    int32_t j,r;
    for (i=0; i<M; i++)
    {
        r = rand() % N;
        while ( (j= sharenrs[r]) == 0 || newsharenrs[r] != 0 )
            r = rand() % N;
        newsharenrs[r] = j;
        sharenrs[r] = 0;
    }
    for (i=0; i<N; i++)
    {
        if ( newsharenrs[i] != 0 )
            gfshare_ctx_dec_giveshare( G, i, shares[i] );
        //newsharenrs[i] = sharenrs[i];
    }
    /* Stage 3, attempt a recombination with shares 1 and 2 */
    //sharenrs[2] = 0;
    gfshare_ctx_dec_newshares( G, newsharenrs );
    gfshare_ctx_dec_extract( G, recomb );
    for( i = 0; i < datasize; ++i )
        if( secret[i] != recomb[i] )
            ok = 0;
    printf("M.%-3d N.%-3d ok.%d datalen.%d\n",M,N,ok,datasize);
    free(recomb), free(secret);
    for (i=0; i<N; i++)
        free(shares[i]);
     return ok!=1;
}

int32_t init_sharenrs(uint8_t sharenrs[255],uint8_t *orig,int32_t m,int32_t n)
{
    uint8_t *randvals,valid[255];
    int32_t i,j,r,remains,orign;
    if ( m > n || n >= 0xff ) // reserve 255 for illegal sharei
    {
        printf("illegal M.%d of N.%d\n",m,n);
        return(-1);
    }
    randvals = calloc(1,65536);
    OS_randombytes(randvals,65536);
    if ( orig == 0 && n == m )
    {
        memset(sharenrs,0,n);
        for (i=0; i<255; i++)
            valid[i] = (i + 1);
        remains = orign = 255;
        for (i=0; i<n; i++)
        {
            r = (randvals[i] % remains);
            sharenrs[i] = valid[r];
            printf("%d ",sharenrs[i]);
            valid[r] = valid[--remains];
        }
        printf("FULL SET\n");
    }
    else
    {
        memcpy(valid,orig,n);
        memset(sharenrs,0,n);
        for (i=0; i<n; i++)
            printf("%d ",valid[i]);
        printf("valid\n");
        for (i=0; i<m; i++)
        {
            r = rand() % n;
            while ( (j= valid[r]) == 0 )
            {
                //printf("i.%d j.%d m.%d n.%d r.%d\n",i,j,m,n,r);
                r = rand() % n;
            }
            sharenrs[i] = j;
            valid[r] = 0;
        }
        for (i=0; i<n; i++)
            printf("%d ",valid[i]);
        printf("valid\n");
        for (i=0; i<m; i++)
            printf("%d ",sharenrs[i]);
        printf("sharenrs vals m.%d of n.%d\n",m,n);
        //getchar();
    }
    free(randvals);
    for (i=0; i<m; i++)
    {
        for (j=0; j<m; j++)
        {
            if ( i == j )
                continue;
            if ( sharenrs[i] != 0 && sharenrs[i] == sharenrs[j] )
            {
                printf("FATAL: duplicate entry sharenrs[%d] %d vs %d sharenrs[%d]\n",i,sharenrs[i],sharenrs[j],j);
                return(-1);
            }
        }
    }
    return(0);
}

/* Construct and write out the tables for the gfshare code */

int maingen(int argc, char** argv)
{
    uint8_t logs[256];
    uint8_t exps[255];
    unsigned int x;
    unsigned int i;
    
    x = 1;
    for( i = 0; i < 255; ++i ) {
        exps[i] = x;
        logs[x] = i;
        x <<= 1;
        if( x & 0x100 )
            x ^= 0x11d; /* Unset the 8th bit and mix in 0x1d */
    }
    logs[0] = 0; /* can't log(0) so just set it neatly to 0 */
    
    /* The above generation algorithm clearly demonstrates that
     * logs[exps[i]] == i for 0 <= i <= 254
     * exps[logs[i]] == i for 1 <= i <= 255
     */
    
    /* Spew out the tables */
    
    fprintf(stdout, "\
            /*\n\
            * This file is autogenerated by gfshare_maketable.\n\
            */\n\
            \n\
            static uint8_t logs[256] = {\n  ");
    for( i = 0; i < 256; ++i ) {
        fprintf(stdout, "0x%02x", logs[i]);
        if( i == 255 )
            fprintf(stdout, " };\n");
        else if( (i % 8) == 7 )
            fprintf(stdout, ",\n  ");
        else
            fprintf(stdout, ", ");
    }
    
    /* The exp table we output from 0 to 509 because that way when we
     * do the lagrange interpolation we don't have to be quite so strict
     * with staying inside the field which makes it quicker
     */
    
    fprintf(stdout, "\
            \n\
            static uint8_t exps[510] = {\n  ");
    for( i = 0; i < 510; ++i ) {
        fprintf(stdout, "0x%02x", exps[i % 255]); /* exps[255]==exps[0] */
        if( i == 509 )
            fprintf(stdout, " };\n");
        else if( (i % 8) == 7)
            fprintf(stdout, ",\n  ");
        else
            fprintf(stdout, ", ");
    }
    
    return 0;
}

void iguana_appletests(struct supernet_info *myinfo)
{
    char *str;
    //iguana_chaingenesis(1,1403138561,0x1e0fffff,8359109,bits256_conv("fd1751cc6963d88feca94c0d01da8883852647a37a0a67ce254d62dd8c9d5b2b")); // BTCD
    if ( 0 )
    {
    char genesisblock[1024];
    //iguana_chaingenesis("VPN",0,bits256_conv("00000ac7d764e7119da60d3c832b1d4458da9bc9ef9d5dd0d91a15f690a46d99"),genesisblock,"scrypt",1,1409839200,0x1e0fffff,64881664,bits256_conv("698a93a1cacd495a7a4fb3864ad8d06ed4421dedbc57f9aaad733ea53b1b5828")); // VPN
    
    iguana_chaingenesis("LTC",0,bits256_conv("12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"),genesisblock,"scrypt",1,1317972665,0x1e0ffff0,2084524493,bits256_conv("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9")); // LTC
        char *Str = "01000000f615f7ce3b4fc6b8f61e8f89aedb1d0852507650533a9e3b10b9bbcc30639f279fcaa86746e1ef52d3edb3c4ad8259920d509bd073605c9bf1d59983752a6b06b817bb4ea78e011d012d59d4";
        uint8_t buf[1000]; bits256 shash; char str[65];
        decode_hex(buf,(int32_t)strlen(Str)>>1,Str);
        calc_scrypthash(shash.uints,buf);
        printf("shash -> %s\n",bits256_str(str,shash));
    getchar();
    }
    if ( 1 )
    {
        if ( 1 && (str= SuperNET_JSON(myinfo,cJSON_Parse("{\"userhome\":\"/Users/jimbolaptop/Library/Application Support\",\"RELAY\":1,\"VALIDATE\":1,\"prefetchlag\":-1,\"agent\":\"iguana\",\"method\":\"addcoin\",\"startpend\":4,\"endpend\":4,\"services\":128,\"maxpeers\":128,\"newcoin\":\"BTCD\",\"active\":1,\"numhelpers\":4,\"poll\":100}"),0,myinfo->rpcport)) != 0 )
        {
            free(str);
            if ( 1 && (str= SuperNET_JSON(myinfo,cJSON_Parse("{\"userhome\":\"/Users/jimbolaptop/Library/Application Support\",\"RELAY\":0,\"VALIDATE\":0,\"prefetchlag\":-1,\"agent\":\"iguana\",\"method\":\"addcoin\",\"startpend\":4,\"endpend\":4,\"services\":129,\"maxpeers\":64,\"newcoin\":\"BTC\",\"active\":0,\"numhelpers\":4,\"poll\":100}"),0,myinfo->rpcport)) != 0 )
            {
                free(str);
                if ( 0 && (str= SuperNET_JSON(myinfo,cJSON_Parse("{\"agent\":\"SuperNET\",\"method\":\"login\",\"handle\":\"alice\",\"password\":\"alice\",\"passphrase\":\"alice\"}"),0,myinfo->rpcport)) != 0 )
                {
                    free(str);
                    if ( (str= SuperNET_JSON(myinfo,cJSON_Parse("{\"agent\":\"SuperNET\",\"method\":\"login\",\"handle\":\"bob\",\"password\":\"bob\",\"passphrase\":\"bob\"}"),0,myinfo->rpcport)) != 0 )
                        free(str);
                }
            }
        }
        sleep(1);
    }
}

void iguana_commandline(struct supernet_info *myinfo,char *arg)
{
    cJSON *argjson,*array; char *coinargs,*argstr,*str; int32_t i,n; long filesize = 0;
    if ( arg == 0 )
        arg = "iguana.conf";
    if ( arg != 0 )
    {
        if ( arg[0] == '{' || arg[0] == '[' )
            argstr = arg;
        else argstr = OS_filestr(&filesize,arg);
        if ( (argjson= cJSON_Parse(argstr)) != 0 )
        {
            IGUANA_NUMHELPERS = juint(argjson,"numhelpers");
            if ( (myinfo->rpcport= juint(argjson,"port")) == 0 )
                myinfo->rpcport = IGUANA_RPCPORT;
            if ( (myinfo->publicRPC= juint(argjson,"publicRPC")) != 0 && myinfo->publicRPC != myinfo->rpcport )
                myinfo->publicRPC = 0;
            if ( jstr(argjson,"rpccoin") != 0 )
                safecopy(myinfo->rpcsymbol,jstr(argjson,"rpccoin"),sizeof(myinfo->rpcsymbol));
            safecopy(Userhome,jstr(argjson,"userhome"),sizeof(Userhome));
            if ( jstr(argjson,"tmpdir") != 0 )
            {
                safecopy(GLOBAL_TMPDIR,jstr(argjson,"tmpdir"),sizeof(GLOBAL_TMPDIR));
                printf("GLOBAL tmpdir.(%s)\n",GLOBAL_TMPDIR);
            }
            printf("call argv JSON.(%s)\n",(char *)arg);
            SuperNET_JSON(myinfo,argjson,0,myinfo->rpcport);
            if ( (coinargs= SuperNET_keysinit(myinfo,arg)) != 0 )
                iguana_launch(0,"iguana_coins",iguana_coins,coinargs,IGUANA_PERMTHREAD);
            if ( (array= jarray(&n,argjson,"commands")) != 0 )
            {
                for (i=0; i<n; i++)
                    if ( (str= SuperNET_JSON(myinfo,jitem(array,i),0,myinfo->rpcport)) != 0 )
                        free(str);
            }
            free_json(argjson);
        } else printf("error parsing.(%s)\n",(char *)argstr);
        if ( argstr != arg )
            free(argstr);
    }
}

void iguana_ensuredirs()
{
    char dirname[512];
    sprintf(dirname,"%s",GLOBAL_HELPDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s",GLOBAL_CONFSDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s",GLOBAL_TMPDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s",GLOBAL_VALIDATEDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/ECB",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/BTC",GLOBAL_VALIDATEDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/BTCD",GLOBAL_VALIDATEDIR), OS_ensure_directory(dirname);
}

void iguana_Qinit()
{
    iguana_initQ(&helperQ,"helperQ");
    iguana_initQ(&jsonQ,"jsonQ");
    iguana_initQ(&finishedQ,"finishedQ");
    iguana_initQ(&bundlesQ,"bundlesQ");
    iguana_initQ(&emitQ,"emitQ");
    iguana_initQ(&TerminateQ,"TerminateQ");
}

void iguana_helpinit(struct supernet_info *myinfo)
{
    char *tmpstr = 0;
    if ( (tmpstr= SuperNET_JSON(myinfo,cJSON_Parse("{\"agent\":\"SuperNET\",\"method\":\"help\"}"),0,myinfo->rpcport)) != 0 )
    {
        if ( (API_json= cJSON_Parse(tmpstr)) != 0 && (API_json= jobj(API_json,"result")) != 0 )
            API_json = jobj(API_json,"API");
        else printf("couldnt parse tmpstr\n");
        free(tmpstr);
    }
    printf("generated API_json tmpstr.%p\n",tmpstr);
}

void iguana_urlinit(struct supernet_info *myinfo,int32_t ismainnet,int32_t usessl)
{
    int32_t iter,j; FILE *fp; char line[4096],NXTaddr[64]; uint8_t pubkey[32];
    strcpy(myinfo->NXTAPIURL,"http://127.0.0.1:7876/nxt");
    for (iter=0; iter<2; iter++)
    {
        if ( (fp= fopen(iter == 0 ? "nxtpasswords" : "fimpasswords","rb")) != 0 )
        {
            while ( fgets(line,sizeof(line),fp) > 0 )
            {
                j = (int32_t)strlen(line) - 1;
                line[j] = 0;
                calc_NXTaddr(NXTaddr,pubkey,(uint8_t *)line,j);
                printf("FORGING %s (%s)\n",NXTaddr,issue_startForging(myinfo,line));
            }
            fclose(fp);
        }
        strcpy(myinfo->NXTAPIURL,"http://127.0.0.1:7886/nxt");
    }
    if ( usessl == 0 )
        strcpy(myinfo->NXTAPIURL,"http://127.0.0.1:");
    else strcpy(myinfo->NXTAPIURL,"https://127.0.0.1:");
    if ( ismainnet != 0 )
        strcat(myinfo->NXTAPIURL,"7876/nxt");
    else strcat(myinfo->NXTAPIURL,"6876/nxt");
}

void iguana_launchdaemons(struct supernet_info *myinfo)
{
    int32_t i; char *helperargs,helperstr[512];
    if ( IGUANA_NUMHELPERS == 0 )
        IGUANA_NUMHELPERS = 1;
    for (i=0; i<IGUANA_NUMHELPERS; i++)
    {
        sprintf(helperstr,"{\"helperid\":%d}",i);
        helperargs = clonestr(helperstr);
        printf("launch[%d] of %d (%s)\n",i,IGUANA_NUMHELPERS,helperstr);
        iguana_launch(0,"iguana_helper",iguana_helper,helperargs,IGUANA_PERMTHREAD);
    }
    iguana_launch(0,"rpcloop",iguana_rpcloop,myinfo,IGUANA_PERMTHREAD);
    printf("launch mainloop\n");
    mainloop(myinfo);
}

int32_t iguana_isbigendian()
{
    int32_t i,littleendian,bigendian; uint64_t val = 0x0001020304050607;
    for (i=bigendian=littleendian=0; i<sizeof(val); i++)
    {
        if ( ((uint8_t *)&val)[i] == i )
            bigendian++;
        else if ( ((uint8_t *)&val)[sizeof(val)-1-i] == i )
            littleendian++;
    }
    if ( littleendian == sizeof(val) )
        return(0);
    else if ( bigendian == sizeof(val) )
        return(1);
    else return(-1);
}

void iguana_main(void *arg)
{
    int32_t usessl = 0, ismainnet = 1; struct supernet_info *myinfo; cJSON *argjson = 0;
    if ( (IGUANA_BIGENDIAN= iguana_isbigendian()) > 0 )
        printf("BIGENDIAN\n");
    else if ( IGUANA_BIGENDIAN == 0 )
        printf("LITTLE ENDIAN arg.%p\n",arg);
    else printf("ENDIAN ERROR\n");
    mycalloc(0,0,0);
    if ( 0 )
        iguana_signalsinit();
    iguana_ensuredirs();
    iguana_Qinit();
    myinfo = SuperNET_MYINFO(0);
    myinfo->rpcport = IGUANA_RPCPORT;
    strcpy(myinfo->rpcsymbol,"BTCD");
    iguana_urlinit(myinfo,ismainnet,usessl);
    category_init(myinfo);
    exchange_create("bitcoin",0);
    argjson = arg != 0 ? cJSON_Parse(arg) : cJSON_Parse("{}");
    iguana_coinadd("BTC",argjson);
    free_json(argjson);
    iguana_helpinit(myinfo);
    iguana_commandline(myinfo,arg);
#ifdef __APPLE__
    iguana_appletests(myinfo);
#endif
    iguana_launchdaemons(myinfo);
}

