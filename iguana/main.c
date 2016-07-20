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
#define ACTIVELY_DECLARE
#define HAVE_STRUCT_TIMESPEC
#include "../pnacl_main.h"
#include "iguana777.h"

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
        OS_randombytes(MYINFO.privkey.bytes,sizeof(MYINFO.privkey));
        MYINFO.myaddr.pubkey = curve25519(MYINFO.privkey,curve25519_basepoint9());
        printf("SuperNET_MYINFO: generate session keypair\n");
        MYINFO.RELAYID = -1;
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
    //printf("SuperNET_jsonstr.(%s)\n",jsonstr);
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
        printf("finished.(%s) -> (%s) %.0f\n",ptr->jsonstr,ptr->retjsonstr!=0?ptr->retjsonstr:"null return",OS_milliseconds());
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
    cJSON *retjson; uint64_t tag; uint32_t timeout; char *jsonstr,*retjsonstr,*retstr = 0; //*hexmsg,*method,
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
        /*if ( (method= jstr(json,"method")) != 0 && strcmp(method,"DHT") == 0 && remoteaddr != 0 && (hexmsg= jstr(json,"hexmsg")) != 0 )
        {
            //printf("hexmsgprocess myinfo.%p\n",myinfo);
            SuperNET_hexmsgprocess(myinfo,0,json,hexmsg,remoteaddr);
            return(clonestr("{\"result\":\"processed remote DHT\"}"));
        }*/
        jsonstr = jprint(json,0);
        //printf("RPC? (%s)\n",jsonstr);
        if ( jstr(json,"immediate") != 0 || ((remoteaddr == 0 || remoteaddr[0] == 0) && port == IGUANA_RPCPORT) )
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

char *SuperNET_JSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr,uint16_t port)
{
    int32_t autologin = 0; uint32_t timestamp; char *retstr=0,*agent=0,*method=0,*jsonstr=0; uint64_t tag;
    //printf("SuperNET_JSON.(%s)\n",jprint(json,0));
    if ( remoteaddr != 0 && strcmp(remoteaddr,"127.0.0.1") == 0 )
        remoteaddr = 0;
    if ( (agent = jstr(json,"agent")) == 0 )
        agent = "bitcoinrpc";
    if ( (method= jstr(json,"method")) == 0 )
    {
        printf("no method in request.(%s)\n",jprint(json,0));
        return(clonestr("{\"error\":\"no method\"}"));
    }
    if ( remoteaddr == 0 )
    {
        if ( jobj(json,"timestamp") != 0 )
            jdelete(json,"timestamp");
        timestamp = (uint32_t)time(NULL);
        jaddnum(json,"timestamp",timestamp);
    }
    if ( (tag= j64bits(json,"tag")) == 0 )
    {
        OS_randombytes((uint8_t *)&tag,sizeof(tag));
        jadd64bits(json,"tag",tag);
    }
    if ( (retstr= SuperNET_processJSON(myinfo,json,remoteaddr,port)) == 0 )
        printf("null retstr from SuperNET_JSON\n");
    if ( jsonstr != 0 )
        free(jsonstr);
    if ( autologin != 0 )
        SuperNET_logout(myinfo,0,json,remoteaddr);
    return(retstr);
}

void iguana_exit()
{
    int32_t j,iter; struct iguana_info *coin,*tmp;
    printf("start EXIT\n");
    for (iter=0; iter<3; iter++)
    {
        if ( iter == 0 )
            basilisk_request_goodbye(SuperNET_MYINFO(0));
        else
        {
            //portable_mutex_lock(&Allcoins_mutex);
            HASH_ITER(hh,Allcoins,coin,tmp)
            {
                if ( coin->peers != 0 )
                {
                    for (j=0; j<IGUANA_MAXPEERS; j++)
                    {
                        switch ( iter )
                        {
                            case 1: coin->peers->active[j].dead = (uint32_t)time(NULL); break;
                            case 2:
                                if ( coin->peers->active[j].usock >= 0 )
                                    closesocket(coin->peers->active[j].usock);
                                break;
                        }
                    }
                }
            }
            //portable_mutex_unlock(&Allcoins_mutex);
        }
        sleep(3);
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
    int32_t j,n,flag,isRT,numpeers; struct iguana_info *coin,*tmp; struct iguana_bundle *bp;
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
            coin = 0;
            //portable_mutex_lock(&myinfo->allcoins_mutex);
            HASH_ITER(hh,myinfo->allcoins,coin,tmp)
            {
                if ( coin->current != 0 && coin->active != 0 && coin->started != 0 )
                {
                    isRT *= coin->isRT;
                    if ( coin->peers != 0 )
                        numpeers += coin->peers->numranked;
                    if ( time(NULL) > coin->startutc+10 && coin->spendvectorsaved == 0 && coin->blocks.hwmchain.height/coin->chain->bundlesize >= (coin->longestchain-coin->minconfirms)/coin->chain->bundlesize )
                    {
                        n = coin->bundlescount-1;
                        //printf("%s n.%d emitfinished.%d\n",coin->symbol,n,iguana_emitfinished(coin,1));
                        if ( iguana_emitfinished(coin,1) >= n )
                        {
                            if ( coin->PREFETCHLAG >= 0 && coin->fastfind == 0 )
                            {
                                for (j=0; j<n; j++)
                                    if ( coin->bundles[j] != 0 )
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
            //portable_mutex_unlock(&myinfo->allcoins_mutex);
        }
        //pangea_queues(SuperNET_MYINFO(0));
        if ( flag == 0 )
            usleep(100000 + isRT*100000 + (numpeers == 0)*1000000);
        //iguana_jsonQ(); // cant do this here safely, need to send to coin specific queue
    }
}

void iguana_appletests(struct supernet_info *myinfo)
{
    char *str;
    //iguana_chaingenesis(1,1403138561,0x1e0fffff,8359109,bits256_conv("fd1751cc6963d88feca94c0d01da8883852647a37a0a67ce254d62dd8c9d5b2b")); // BTCD
    if ( 0 )
    {
    char genesisblock[1024];
    //iguana_chaingenesis("VPN",0,bits256_conv("00000ac7d764e7119da60d3c832b1d4458da9bc9ef9d5dd0d91a15f690a46d99"),genesisblock,"scrypt",1,1409839200,0x1e0fffff,64881664,bits256_conv("698a93a1cacd495a7a4fb3864ad8d06ed4421dedbc57f9aaad733ea53b1b5828")); // VPN
    
    iguana_chaingenesis("LTC",0,0,0,bits256_conv("12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"),genesisblock,"sha256",1,1317972665,0x1e0ffff0,2084524493,bits256_conv("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9")); // LTC
        //char *Str = "01000000f615f7ce3b4fc6b8f61e8f89aedb1d0852507650533a9e3b10b9bbcc30639f279fcaa86746e1ef52d3edb3c4ad8259920d509bd073605c9bf1d59983752a6b06b817bb4ea78e011d012d59d4";
        // https://litecoin.info/Scrypt  0000000110c8357966576df46f3b802ca897deb7ad18b12f1c24ecff6386ebd9
        //uint8_t buf[1000]; bits256 shash,hash2; char str[65],str2[65];
        //decode_hex(buf,(int32_t)strlen(Str)>>1,Str);
        //calc_scrypthash(shash.uints,buf);
        //blockhash_sha256(&hash2,buf,80);
        //printf("shash -> %s sha256x2 %s\n",bits256_str(str,shash),bits256_str(str2,hash2));
    getchar();
    }
    if ( 1 )
    {
        /*int32_t i; ;bits256 hash2; uint8_t pubkey[33];
        double startmillis = OS_milliseconds();
        for (i=0; i<1000; i++)
            hash2 = curve25519_shared(hash2,rand256(0));
        printf("curve25519 elapsed %.3f for %d iterations\n",OS_milliseconds() - startmillis,i);
        startmillis = OS_milliseconds();
        bitcoin_pubkey33(myinfo->ctx,pubkey,hash2);
        for (i=0; i<1000; i++)
            bitcoin_sharedsecret(myinfo->ctx,hash2,pubkey,33);
        printf("secp256k1 elapsed %.3f for %d iterations\n",OS_milliseconds() - startmillis,i);
       getchar();**/
        if ( 1 && (str= SuperNET_JSON(myinfo,cJSON_Parse("{\"protover\":70002,\"RELAY\":1,\"VALIDATE\":0,\"portp2p\":14631,\"rpc\":14632,\"agent\":\"iguana\",\"method\":\"addcoin\",\"startpend\":64,\"endpend\":64,\"services\":129,\"maxpeers\":8,\"newcoin\":\"BTCD\",\"active\":1,\"numhelpers\":1,\"poll\":1}"),0,myinfo->rpcport)) != 0 )
        {
            free(str);
            if ( 0 && (str= SuperNET_JSON(myinfo,cJSON_Parse("{\"portp2p\":8333,\"RELAY\":0,\"VALIDATE\":0,\"agent\":\"iguana\",\"method\":\"addcoin\",\"startpend\":1,\"endpend\":1,\"services\":128,\"maxpeers\":8,\"newcoin\":\"BTC\",\"active\":0,\"numhelpers\":1,\"poll\":100}"),0,myinfo->rpcport)) != 0 )
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
            if ( 0 )
            {
                uint32_t buf[81],c;
                OS_randombytes((void *)buf,sizeof(buf));
                printf("(");
                for (i=0; i<81; i++)
                {
                    c = buf[i] % 27;
                    if ( c == 26 )
                        c = '9';
                    else c += 'a';
                    printf("%c",c);
                }
                printf(") <- IOTA random passphrase\n");
            }
        } else printf("error parsing.(%s)\n",(char *)argstr);
        if ( argstr != arg )
            free(argstr);
    }
}

void iguana_ensuredirs()
{
    char dirname[512];
    sprintf(dirname,"%s",GLOBAL_HELPDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s",GLOBAL_GENESISDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s",GLOBAL_CONFSDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/purgeable",GLOBAL_DBDIR), OS_ensure_directory(dirname);
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
    //iguana_initQ(&TerminateQ,"TerminateQ");
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

void *SuperNET_deciphercalc(void **ptrp,int32_t *msglenp,bits256 privkey,bits256 srcpubkey,uint8_t *cipher,int32_t cipherlen,uint8_t *buf,int32_t bufsize)
{
    uint8_t *origptr,*nonce,*message; void *retptr;
    if ( bits256_nonz(privkey) == 0 )
        privkey = GENESIS_PRIVKEY;
    *ptrp = 0;
    if ( cipherlen > bufsize )
    {
        message = calloc(1,cipherlen);
        *ptrp = (void *)message;
    }
    else message = buf;
    origptr = cipher;
    if ( bits256_nonz(srcpubkey) == 0 )
    {
        memcpy(srcpubkey.bytes,cipher,sizeof(srcpubkey));
        char str[65]; printf("use attached pubkey.(%s)\n",bits256_str(str,srcpubkey));
        cipher += sizeof(srcpubkey);
        cipherlen -= sizeof(srcpubkey);
    }
    nonce = cipher;
    cipher += crypto_box_NONCEBYTES, cipherlen -= crypto_box_NONCEBYTES;
    *msglenp = cipherlen - crypto_box_ZEROBYTES;
    if ( (retptr= _SuperNET_decipher(nonce,cipher,message,cipherlen,srcpubkey,privkey)) == 0 )
    {
        *msglenp = -1;
        free(*ptrp);
    }
    return(retptr);
}

uint8_t *SuperNET_ciphercalc(void **ptrp,int32_t *cipherlenp,bits256 *privkeyp,bits256 *destpubkeyp,uint8_t *data,int32_t datalen,uint8_t *space2,int32_t space2size)
{
    bits256 mypubkey; uint8_t *buf,*nonce,*cipher,*origptr,space[8192]; int32_t onetimeflag=0,allocsize;
    *ptrp = 0;
    allocsize = (datalen + crypto_box_NONCEBYTES + crypto_box_ZEROBYTES);
    if ( bits256_nonz(*destpubkeyp) == 0 || memcmp(destpubkeyp->bytes,GENESIS_PUBKEY.bytes,sizeof(*destpubkeyp)) == 0 )
    {
        *destpubkeyp = GENESIS_PUBKEY;
        onetimeflag = 2; // prevent any possible leakage of privkey by encrypting to known destpub
    }
    if ( bits256_nonz(*privkeyp) == 0 )
        onetimeflag = 1;
    if ( onetimeflag != 0 )
    {
        crypto_box_keypair(mypubkey.bytes,privkeyp->bytes);
        allocsize += sizeof(bits256);
    }
    if ( allocsize > sizeof(space) )
        buf = calloc(1,allocsize);
    else buf = space;
    if ( allocsize+sizeof(struct iguana_msghdr) > space2size )
    {
        cipher = calloc(1,allocsize + sizeof(struct iguana_msghdr));
        *ptrp = (void *)cipher;
    } else cipher = space2;
    cipher = &cipher[sizeof(struct iguana_msghdr)];
    origptr = nonce = cipher;
    if ( onetimeflag != 0 )
    {
        memcpy(cipher,mypubkey.bytes,sizeof(mypubkey));
        nonce = &cipher[sizeof(mypubkey)];
    }
    OS_randombytes(nonce,crypto_box_NONCEBYTES);
    cipher = &nonce[crypto_box_NONCEBYTES];
    _SuperNET_cipher(nonce,cipher,(void *)data,datalen,*destpubkeyp,*privkeyp,buf);
    if ( buf != space )
        free(buf);
    *cipherlenp = allocsize;
    return(origptr);
}

cJSON *SuperNET_rosettajson(bits256 privkey,int32_t showprivs)
{
    uint8_t rmd160[20],pub[33]; uint64_t nxt64bits; bits256 pubkey;
    char str2[41],wifbuf[64],addr[64],str[128]; cJSON *retjson;
    pubkey = acct777_pubkey(privkey);
    nxt64bits = acct777_nxt64bits(pubkey);
    retjson = cJSON_CreateObject();
    jaddbits256(retjson,"pubkey",pubkey);
    RS_encode(str,nxt64bits);
    jaddstr(retjson,"RS",str);
    jadd64bits(retjson,"NXT",nxt64bits);
    bitcoin_pubkey33(0,pub,privkey);
    init_hexbytes_noT(str,pub,33);
    jaddstr(retjson,"btcpubkey",str);
    calc_OP_HASH160(str2,rmd160,str);
    jaddstr(retjson,"rmd160",str2);
    if ( bitcoin_address(addr,0,pub,33) != 0 )
    {
        jaddstr(retjson,"BTC",addr);
        if ( showprivs != 0 )
        {
            bitcoin_priv2wif(wifbuf,privkey,128);
            jaddstr(retjson,"BTCwif",wifbuf);
        }
    }
    if ( bitcoin_address(addr,60,pub,33) != 0 )
    {
        jaddstr(retjson,"BTCD",addr);
        if ( showprivs != 0 )
        {
            bitcoin_priv2wif(wifbuf,privkey,188);
            jaddstr(retjson,"BTCDwif",wifbuf);
        }
    }
    if ( showprivs != 0 )
        jaddbits256(retjson,"privkey",privkey);
    return(retjson);
}

cJSON *SuperNET_peerarray(struct iguana_info *coin,int32_t max,int32_t supernetflag)
{
    int32_t i,r,j,n = 0; struct iguana_peer *addr; cJSON *array = cJSON_CreateArray();
    if ( coin->peers == 0 )
        return(array);
    r = rand();
    for (j=0; j<IGUANA_MAXPEERS; j++)
    {
        i = (r + j) % IGUANA_MAXPEERS;
        addr = &coin->peers->active[i];
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
        jaddstr(item,"coin",coin->symbol);
        jadd(item,"peers",array);
        jaddi(SNjson,item);
    }
    if ( max > 0 && (array= SuperNET_peerarray(coin,max,0)) != 0 )
    {
        max -= cJSON_GetArraySize(array);
        item = cJSON_CreateObject();
        jaddstr(item,"coin",coin->symbol);
        jadd(item,"peers",array);
        jaddi(rawjson,item);
    }
    return(max);
}

void SuperNET_remotepeer(struct supernet_info *myinfo,struct iguana_info *coin,char *symbol,char *ipaddr,int32_t supernetflag)
{
    uint64_t ipbits; struct iguana_peer *addr;
    ipbits = calc_ipbits(ipaddr);
    printf("got %s remotepeer.(%s) supernet.%d\n",symbol,ipaddr,supernetflag);
    if ( supernetflag != 0 && (uint32_t)myinfo->myaddr.selfipbits != (uint32_t)ipbits )
    {
        if ( (addr= iguana_peerslot(coin,ipbits,0)) != 0 )
        {
            printf("launch startconnection to supernet peer.(%s)\n",ipaddr);
            iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
            return;
        }
    }
    iguana_possible_peer(coin,ipaddr);
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

STRING_ARG(SuperNET,addr2rmd160,address)
{
    uint8_t addrtype,rmd160[20]; char rmdstr[41]; cJSON *retjson;
    bitcoin_addr2rmd160(&addrtype,rmd160,address);
    init_hexbytes_noT(rmdstr,rmd160,sizeof(rmd160));
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",rmdstr);
    jaddnum(retjson,"addrtype",addrtype);
    jaddstr(retjson,"address",address);
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,rmd160conv,rmd160)
{
    uint8_t rmdbuf[20]; char coinaddr[64],p2shaddr[64]; cJSON *retjson = cJSON_CreateObject();
    if ( rmd160 != 0 && strlen(rmd160) == 40 )
    {
        decode_hex(rmdbuf,20,rmd160);
        bitcoin_address(coinaddr,coin->chain->pubtype,rmdbuf,20);
        bitcoin_address(p2shaddr,coin->chain->p2shtype,rmdbuf,20);
        jaddstr(retjson,"result","success");
        jaddstr(retjson,"address",coinaddr);
        jaddstr(retjson,"p2sh",p2shaddr);
    }
    return(jprint(retjson,1));
}

HASH_AND_INT(SuperNET,priv2pub,privkey,addrtype)
{
    cJSON *retjson; bits256 pub; uint8_t pubkey[33]; char coinaddr[64],pubkeystr[67];
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    crypto_box_priv2pub(pub.bytes,privkey.bytes);
    jaddbits256(retjson,"curve25519",pub);
    pub = bitcoin_pubkey33(myinfo->ctx,pubkey,privkey);
    init_hexbytes_noT(pubkeystr,pubkey,33);
    jaddstr(retjson,"secp256k1",pubkeystr);
    bitcoin_address(coinaddr,addrtype,pubkey,33);
    jaddstr(retjson,"result",coinaddr);
    return(jprint(retjson,1));
}

ZERO_ARGS(SuperNET,keypair)
{
    cJSON *retjson; bits256 pubkey,privkey;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    crypto_box_keypair(pubkey.bytes,privkey.bytes);
    jaddstr(retjson,"result","generated keypair");
    jaddbits256(retjson,"privkey",privkey);
    jaddbits256(retjson,"pubkey",pubkey);
    return(jprint(retjson,1));
}

TWOHASHES_AND_STRING(SuperNET,decipher,privkey,srcpubkey,cipherstr)
{
    int32_t cipherlen=0,msglen; char *retstr; cJSON *retjson; void *ptr = 0; uint8_t *cipher,*message,space[8192];
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( cipherstr != 0 )
        cipherlen = (int32_t)strlen(cipherstr) >> 1;
    if ( cipherlen < crypto_box_NONCEBYTES )
        return(clonestr("{\"error\":\"cipher is too short\"}"));
    cipher = calloc(1,cipherlen);
    decode_hex(cipher,cipherlen,cipherstr);
    if ( (message= SuperNET_deciphercalc(&ptr,&msglen,privkey,srcpubkey,cipher,cipherlen,space,sizeof(space))) != 0 )
    {
        message[msglen] = 0;
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","deciphered message");
        jaddstr(retjson,"message",(char *)message);
        retstr = jprint(retjson,1);
        if ( ptr != 0 )
            free(ptr);
    } else retstr = clonestr("{\"error\":\"couldnt decipher message\"}");
    return(retstr);
}

TWOHASHES_AND_STRING(SuperNET,cipher,privkey,destpubkey,message)
{
    cJSON *retjson; char *retstr,*hexstr,space[8129]; uint8_t space2[8129];
    uint8_t *cipher; int32_t cipherlen,onetimeflag; bits256 origprivkey; void *ptr = 0;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( (cipher= SuperNET_ciphercalc(&ptr,&cipherlen,&privkey,&destpubkey,(uint8_t *)message,(int32_t)strlen(message)+1,space2,sizeof(space2))) != 0 )
    {
        if ( cipherlen > sizeof(space)/2 )
            hexstr = calloc(1,(cipherlen<<1)+1);
        else hexstr = (void *)space;
        init_hexbytes_noT(hexstr,cipher,cipherlen);
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result",hexstr);
        onetimeflag = memcmp(origprivkey.bytes,privkey.bytes,sizeof(privkey));
        if ( onetimeflag != 0 )
        {
            //jaddbits256(retjson,"onetime_privkey",privkey);
            jaddbits256(retjson,"onetime_pubkey",destpubkey);
            if ( onetimeflag == 2 )
                jaddstr(retjson,"warning","onetime keypair was used to broadcast");
        }
        retstr = jprint(retjson,1);
        if ( hexstr != (void *)space )
            free(hexstr);
        if ( ptr != 0 )
            free(ptr);
        return(retstr);
    }
    printf("error encrypting message.(%s)\n",message);
    return(clonestr("{\"error\":\"cant encrypt message\"}"));
}

bits256 SuperNET_pindecipher(IGUANA_ARGS,char *pin,char *privcipher)
{
    cJSON *testjson; char *mstr,*cstr; bits256 privkey,pinpriv,pinpub;
    conv_NXTpassword(pinpriv.bytes,pinpub.bytes,(uint8_t *)pin,(int32_t)strlen(pin));
    privkey = GENESIS_PRIVKEY;
    if ( (cstr= SuperNET_decipher(IGUANA_CALLARGS,pinpriv,pinpub,privcipher)) != 0 )
    {
        if ( (testjson= cJSON_Parse(cstr)) != 0 )
        {
            if ( (mstr= jstr(testjson,"message")) != 0 && strlen(mstr) == sizeof(bits256)*2 )
            {
                decode_hex(privkey.bytes,sizeof(privkey),mstr);
            } else printf("error cant find message privcipher\n");
            free_json(testjson);
        } else printf("Error decipher.(%s)\n",cstr);
        free(cstr);
    } else printf("null return from deciphering privcipher\n");
    return(privkey);
}

THREE_STRINGS(SuperNET,rosetta,passphrase,pin,showprivkey)
{
    uint8_t flag = 0; uint64_t nxt64bits; bits256 check,privkey,pubkey,pinpriv,pinpub;
    char str[128],privcipher[512],*privcipherstr,*cstr; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    nxt64bits = conv_NXTpassword(privkey.bytes,pubkey.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
    if ( showprivkey != 0 && strcmp(showprivkey,"yes") == 0 )
        flag = 1;
    privcipher[0] = 0;
    conv_NXTpassword(pinpriv.bytes,pinpub.bytes,(uint8_t *)pin,(int32_t)strlen(pin));
    if ( (cstr= SuperNET_cipher(IGUANA_CALLARGS,pinpriv,pinpub,bits256_str(str,privkey))) != 0 )
    {
        if ( (retjson= cJSON_Parse(cstr)) != 0 )
        {
            if ( (privcipherstr= jstr(retjson,"result")) != 0 )
                strcpy(privcipher,privcipherstr);
            free_json(retjson);
        } else printf("error parsing cipher retstr.(%s)\n",cstr);
        free(cstr);
    } else printf("error SuperNET_cipher null return\n");
    retjson = SuperNET_rosettajson(privkey,flag);
    jaddstr(retjson,"privcipher",privcipher);
    check = SuperNET_pindecipher(IGUANA_CALLARGS,pin,privcipher);
    if ( memcmp(check.bytes,privkey.bytes,sizeof(check)) != 0 )
    {
        jaddbits256(retjson,"deciphered",check);
        jaddstr(retjson,"error","cant recreate privkey from (pin + privcipher)");
    }
    else if ( flag != 0 )
        jaddbits256(retjson,"deciphered",check);
    if ( jobj(retjson,"error") == 0 )
        jaddstr(retjson,"result","use pin and privcipher to access wallet");
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,broadcastcipher,message)
{
    bits256 zero;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_cipher(IGUANA_CALLARGS,zero,zero,message));
}

STRING_ARG(SuperNET,broadcastdecipher,message)
{
    bits256 zero;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_decipher(IGUANA_CALLARGS,zero,zero,message));
}

HASH_AND_STRING(SuperNET,multicastcipher,pubkey,message)
{
    bits256 zero;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_cipher(IGUANA_CALLARGS,zero,pubkey,message));
}

HASH_AND_STRING(SuperNET,multicastdecipher,privkey,cipherstr)
{
    bits256 zero;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_decipher(IGUANA_CALLARGS,privkey,zero,cipherstr));
}

ZERO_ARGS(SuperNET,stop)
{
    if ( remoteaddr == 0 || strncmp(remoteaddr,"127.0.0.1",strlen("127.0.0.1")) == 0 )
    {
        iguana_exit();
        return(clonestr("{\"result\":\"exit started\"}"));
    } else return(clonestr("{\"error\":\"cant do a remote stop of this node\"}"));
}

TWO_ARRAYS(SuperNET,mypeers,supernet,rawpeers)
{
    SuperNET_parsepeers(myinfo,supernet,cJSON_GetArraySize(supernet),1);
    SuperNET_parsepeers(myinfo,rawpeers,cJSON_GetArraySize(rawpeers),0);
    return(clonestr("{\"result\":\"peers parsed\"}"));
}

STRING_ARG(SuperNET,getpeers,activecoin)
{
    int32_t max = 64; struct iguana_info *tmp; cJSON *SNjson,*rawjson,*retjson = cJSON_CreateObject();
    SNjson = cJSON_CreateArray();
    rawjson = cJSON_CreateArray();
    if ( coin != 0 )
        max = SuperNET_coinpeers(coin,SNjson,rawjson,max);
    else
    {
        //portable_mutex_lock(&myinfo->allcoins_mutex);
        HASH_ITER(hh,myinfo->allcoins,coin,tmp)
        {
            max = SuperNET_coinpeers(coin,SNjson,rawjson,max);
        }
        //portable_mutex_unlock(&myinfo->allcoins_mutex);
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

/*TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(SuperNET,DHT,hexmsg,destip,categoryhash,subhash,maxdelay,broadcast)
 {
 if ( remoteaddr != 0 )
 return(clonestr("{\"error\":\"cant remote DHT\"}"));
 else if ( hexmsg == 0 || is_hexstr(hexmsg,(int32_t)strlen(hexmsg)) <= 0 )
 return(clonestr("{\"error\":\"hexmsg missing or not in hex\"}"));
 return(SuperNET_DHTencode(myinfo,destip,categoryhash,subhash,hexmsg,maxdelay,broadcast,juint(json,"plaintext")!=0));
 }*/

HASH_AND_STRING(SuperNET,saveconf,wallethash,confjsonstr)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(clonestr("{\"result\":\"saveconf here\"}"));
}

HASH_ARRAY_STRING(SuperNET,layer,mypriv,otherpubs,str)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(clonestr("{\"result\":\"layer encrypt here\"}"));
}

/*TWO_STRINGS(SuperNET,categoryhashes,category,subcategory)
{
    bits256 categoryhash,subhash; cJSON *retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    jaddstr(retjson,"result","category hashes calculated");
    jaddbits256(retjson,"categoryhash",categoryhash);
    jaddbits256(retjson,"subhash",subhash);
    return(jprint(retjson,1));
}

TWO_STRINGS(SuperNET,subscribe,category,subcategory)
{
    bits256 categoryhash,subhash;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    if ( category_subscribe(myinfo,categoryhash,subhash) != 0 )
        return(clonestr("{\"result\":\"subscribed\"}"));
    else return(clonestr("{\"error\":\"couldnt subscribe\"}"));
}

TWO_STRINGS(SuperNET,gethexmsg,category,subcategory)
{
    bits256 categoryhash,subhash; struct category_msg *m; char *hexstr; cJSON *retjson; struct private_chain *cat;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    if ( (m= category_gethexmsg(myinfo,&cat,categoryhash,subhash)) != 0 )
    {
        hexstr = calloc(1,m->len*2+1);
        init_hexbytes_noT(hexstr,m->msg,m->len);
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result",hexstr);
        free(hexstr);
        return(jprint(retjson,1));
    } else return(clonestr("{\"result\":\"no message\"}"));
}

THREE_STRINGS(SuperNET,posthexmsg,category,subcategory,hexmsg)
{
    bits256 categoryhash,subhash;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    category_posthexmsg(myinfo,categoryhash,subhash,hexmsg,tai_now(),remoteaddr);
    return(clonestr("{\"result\":\"posted message\"}"));
}

THREE_STRINGS(SuperNET,announce,category,subcategory,message)
{
    bits256 categoryhash,subhash;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    return(SuperNET_categorymulticast(myinfo,0,categoryhash,subhash,message,juint(json,"maxdelay"),juint(json,"broadcast"),juint(json,"plaintext"),json,remoteaddr));
}

THREE_STRINGS(SuperNET,survey,category,subcategory,message)
{
    bits256 categoryhash,subhash;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    return(SuperNET_categorymulticast(myinfo,1,categoryhash,subhash,message,juint(json,"maxdelay"),juint(json,"broadcast"),juint(json,"plaintext"),json,remoteaddr));
}*/

STRING_ARG(SuperNET,wif2priv,wif)
{
    bits256 privkey; char str[65]; uint8_t privkeytype; cJSON *retjson = cJSON_CreateObject();
    if ( bitcoin_wif2priv(&privkeytype,&privkey,wif) == sizeof(privkey) )
    {
        jaddstr(retjson,"result","success");
        jaddstr(retjson,"privkey",bits256_str(str,privkey));
        jaddnum(retjson,"type",privkeytype);
    } else jaddstr(retjson,"error","couldnt convert wif");
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,priv2wif,priv)
{
    bits256 privkey; char wifstr[65]; uint8_t wiftype; cJSON *retjson = cJSON_CreateObject();
    if ( is_hexstr(priv,0) == sizeof(bits256)*2 )
    {
        wiftype = coin != 0 ? coin->chain->wiftype : 0x80;
        decode_hex(privkey.bytes,sizeof(privkey),priv);
        if ( bitcoin_priv2wif(wifstr,privkey,wiftype) > 0 )
        {
            jaddstr(retjson,"result","success");
            jaddstr(retjson,"privkey",priv);
            jaddnum(retjson,"type",wiftype);
            jaddstr(retjson,"wif",wifstr);
        } else jaddstr(retjson,"error","couldnt convert privkey");
    } else jaddstr(retjson,"error","non 32 byte hex privkey");
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,myipaddr,ipaddr)
{
    int32_t i; cJSON *retjson = cJSON_CreateObject();
    myinfo->RELAYID = -1;
    if ( myinfo->ipaddr[0] == 0 )
    {
        if ( is_ipaddr(ipaddr) != 0 )
        {
            strcpy(myinfo->ipaddr,ipaddr);
            myinfo->myaddr.myipbits = (uint32_t)calc_ipbits(ipaddr);
            for (i=0; i<myinfo->numrelays; i++)
                if ( myinfo->relays[i].ipbits == myinfo->myaddr.myipbits )
                {
                    myinfo->RELAYID = i;
                    break;
                }
        }
    }
    jaddstr(retjson,"result",myinfo->ipaddr);
    if ( myinfo->RELAYID >= 0 )
    {
        jaddnum(retjson,"relayid",myinfo->RELAYID);
        jaddnum(retjson,"numrelays",myinfo->numrelays);
    }
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,setmyipaddr,ipaddr)
{
    cJSON *retjson = cJSON_CreateObject();
    if ( is_ipaddr(ipaddr) != 0 )
    {
        strcpy(myinfo->ipaddr,ipaddr);
        jaddstr(retjson,"result",myinfo->ipaddr);
    } else jaddstr(retjson,"error","illegal ipaddr");
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,utime2utc,utime)
{
    uint32_t utc = 0; cJSON *retjson = cJSON_CreateObject();
    utc = OS_conv_utime(utime);
    char str[65]; printf("utime.%s -> %u -> %s\n",utime,utc,utc_str(str,utc));
    jaddnum(retjson,"result",utc);
    return(jprint(retjson,1));
}

INT_ARG(SuperNET,utc2utime,utc)
{
    char str[65]; cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",utc_str(str,utc));
    return(jprint(retjson,1));
}

ZERO_ARGS(SuperNET,logout)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    iguana_walletlock(myinfo,coin);
    return(clonestr("{\"result\":\"logged out\"}"));
}

ZERO_ARGS(SuperNET,activehandle)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = SuperNET_rosettajson(myinfo->persistent_priv,0);
    jaddstr(retjson,"result","success");
    jaddstr(retjson,"handle",myinfo->handle);
    jaddbits256(retjson,"persistent",myinfo->myaddr.persistent);
    if ( myinfo->expiration != 0 )
    {
        jaddstr(retjson,"status","unlocked");
        jaddnum(retjson,"duration",myinfo->expiration - time(NULL));
    } else jaddstr(retjson,"status","locked");
    SuperNET_MYINFOadd(myinfo);
    return(jprint(retjson,1));
}

struct supernet_info *SuperNET_accountfind(cJSON *json)
{
    int32_t num; char *decryptstr; struct supernet_info M,*myinfo; struct iguana_info *coin = 0;
    char *password,*permanentfile,*passphrase,*remoteaddr,*perspriv;
    myinfo = 0;
    if ( (password= jstr(json,"password")) == 0 )
        password = "";
    if ( (permanentfile= jstr(json,"permanentfile")) == 0 )
        permanentfile = "";
    if ( (passphrase= jstr(json,"passphrase")) == 0 )
        passphrase = "";
    remoteaddr = jstr(json,"remoteaddr");
    if ( (passphrase == 0 || passphrase[0] == 0) && (decryptstr= SuperNET_decryptjson(IGUANA_CALLARGS,password,permanentfile)) != 0 )
    {
        if ( (json= cJSON_Parse(decryptstr)) != 0 )
        {
            memset(&M,0,sizeof(M));
            if ( (perspriv= jstr(json,"persistent_priv")) != 0 && strlen(perspriv) == sizeof(bits256)*2 )
            {
                M.persistent_priv = bits256_conv(perspriv);
                SuperNET_setkeys(&M,0,0,0);
                if ( (myinfo = SuperNET_MYINFOfind(&num,M.myaddr.persistent)) != 0 )
                {
                    //printf("found account.(%s) %s %llu\n",myinfo!=0?myinfo->handle:"",M.myaddr.NXTADDR,(long long)M.myaddr.nxt64bits);
                    return(myinfo);
                }
            }
            else if ( (passphrase= jstr(json,"result")) != 0 || (passphrase= jstr(json,"passphrase")) != 0 )
            {
                SuperNET_setkeys(&M,passphrase,(int32_t)strlen(passphrase),1);
                if ( (myinfo= SuperNET_MYINFOfind(&num,M.myaddr.persistent)) != 0 )
                {
                    //printf("found account.(%s) %s %llu\n",myinfo!=0?myinfo->handle:"",M.myaddr.NXTADDR,(long long)M.myaddr.nxt64bits);
                    return(myinfo);
                }
            } else printf("no passphrase in (%s)\n",jprint(json,0));
            free_json(json);
        } else printf("cant parse.(%s)\n",decryptstr);
        free(decryptstr);
    }
    return(SuperNET_MYINFO(0));
}

FOUR_STRINGS(SuperNET,login,handle,password,permanentfile,passphrase)
{
    char *str,*decryptstr = 0; cJSON *argjson,*item,*walletitem;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( handle != 0 && handle[0] != 0 )
        safecopy(myinfo->handle,handle,sizeof(myinfo->handle));
    else memset(myinfo->handle,0,sizeof(myinfo->handle));
    if ( password == 0 || password[0] == 0 )
        password = passphrase;
    /*if ( password != 0 && password[0] != 0 )
     safecopy(myinfo->secret,password,sizeof(myinfo->secret));
     else if ( passphrase != 0 && passphrase[0] != 0 )
     safecopy(myinfo->secret,passphrase,sizeof(myinfo->secret));*/
    if ( permanentfile != 0 )
        safecopy(myinfo->permanentfile,permanentfile,sizeof(myinfo->permanentfile));
    if ( (decryptstr= SuperNET_decryptjson(IGUANA_CALLARGS,password,myinfo->permanentfile)) != 0 )
    {
        if ( (argjson= cJSON_Parse(decryptstr)) != 0 )
        {
            if ( jobj(argjson,"error") == 0 )
            {
                //printf("decrypted.(%s) exp.%u pass.(%s)\n",decryptstr,myinfo->expiration,password);
                if ( myinfo->decryptstr != 0 )
                    free(myinfo->decryptstr);
                myinfo->decryptstr = decryptstr;
                if ( (passphrase= jstr(argjson,"passphrase")) != 0 )
                {
                    SuperNET_setkeys(myinfo,passphrase,(int32_t)strlen(passphrase),1);
                    free_json(argjson);
                    myinfo->expiration = (uint32_t)(time(NULL) + 3600);
                    return(SuperNET_activehandle(IGUANA_CALLARGS));
                }
                else
                {
                    free_json(argjson);
                    return(clonestr("{\"error\":\"cant find passphrase in decrypted json\"}"));
                }
            } else free_json(argjson);
        }
        else
        {
            free(decryptstr);
            return(clonestr("{\"error\":\"cant parse decrypted json\"}"));
        }
    }
    if ( passphrase != 0 && passphrase[0] != 0 )
    {
        SuperNET_setkeys(myinfo,passphrase,(int32_t)strlen(passphrase),1);
        if ( myinfo->decryptstr != 0 && (argjson= cJSON_Parse(myinfo->decryptstr)) != 0 )
        {
            if ( jobj(argjson,"passphrase") != 0 )
                jdelete(argjson,"passphrase");
            if ( jobj(argjson,"error") != 0 )
                jdelete(argjson,"error");
        }
        else
        {
            char rmd160str[41],str[65]; uint8_t rmd160[20];
            item = cJSON_CreateObject();
            calc_rmd160_sha256(rmd160,myinfo->persistent_pubkey33,33);
            init_hexbytes_noT(rmd160str,rmd160,20);
            jaddstr(item,rmd160str,bits256_str(str,myinfo->persistent_priv));
            walletitem = cJSON_CreateObject();
            jadd(walletitem,"default",item);
            argjson = cJSON_CreateObject();
            jadd(argjson,"wallet",walletitem);
            myinfo->dirty = (uint32_t)time(NULL);
        }
        jaddstr(argjson,"passphrase",passphrase);
        if ( (str= SuperNET_encryptjson(myinfo,coin,argjson,remoteaddr,password,myinfo->permanentfile,myinfo->decryptstr == 0 ? "" : myinfo->decryptstr)) != 0 )
            free(str);
        myinfo->expiration = (uint32_t)(time(NULL) + 3600);
        return(SuperNET_activehandle(IGUANA_CALLARGS));
    } else return(clonestr("{\"error\":\"need passphrase\"}"));
    printf("logged into (%s) %s %s\n",myinfo->myaddr.NXTADDR,myinfo->myaddr.BTC,myinfo->myaddr.BTCD);
    return(SuperNET_activehandle(IGUANA_CALLARGS));
}

#include "../includes/iguana_apiundefs.h"


void iguana_main(void *arg)
{
    int32_t usessl = 0, ismainnet = 1; struct supernet_info *myinfo; //cJSON *argjson = 0;
    if ( (IGUANA_BIGENDIAN= iguana_isbigendian()) > 0 )
        printf("BIGENDIAN\n");
    else if ( IGUANA_BIGENDIAN == 0 )
        printf("LITTLE ENDIAN arg.%p\n",arg);
    else printf("ENDIAN ERROR\n");
    mycalloc(0,0,0);
    decode_hex(CRYPTO777_RMD160,20,CRYPTO777_RMD160STR);
    decode_hex(CRYPTO777_PUBSECP33,33,CRYPTO777_PUBSECPSTR);
    if ( 0 )
        iguana_signalsinit();
    if ( 0 )
    {
        int32_t i,max=10000000; FILE *fp; bits256 check,val,hash = rand256(0);
        if ( (fp= fopen("/tmp/seeds2","rb")) != 0 )
        {
            if ( fread(&check,1,sizeof(check),fp) != sizeof(check) )
                printf("check read error\n");
            for (i=1; i<max; i++)
            {
                if ( (i % 1000000) == 0 )
                    fprintf(stderr,".");
                if ( fread(&val,1,sizeof(val),fp) != sizeof(val) )
                    printf("val read error\n");
                hash = bits256_sha256(val);
                hash = bits256_sha256(hash);
                if ( bits256_cmp(hash,check) != 0 )
                    printf("hash error at i.%d\n",i);
                check = val;
            }
            printf("validated %d seeds\n",max);
            getchar();
        }
        else if ( (fp= fopen("/tmp/seeds2","wb")) != 0 )
        {
            for (i=0; i<max; i++)
            {
                if ( (i % 1000000) == 0 )
                    fprintf(stderr,".");
                hash = bits256_sha256(hash);
                hash = bits256_sha256(hash);
                fseek(fp,(max-i-1) * sizeof(bits256),SEEK_SET);
                if ( fwrite(hash.bytes,1,sizeof(hash),fp) != sizeof(hash) )
                    printf("error writing hash[%d] i.%d\n",(max-i-1),i);
            }
            fclose(fp);
        }
    }
    iguana_ensuredirs();
    iguana_Qinit();
    myinfo = SuperNET_MYINFO(0);
    libgfshare_init(myinfo,myinfo->logs,myinfo->exps);
    if ( 0 )
    {
        int32_t i; for (i=0; i<10; i++)
            iguana_schnorr(myinfo);
        getchar();
    }
    myinfo->rpcport = IGUANA_RPCPORT;
    strcpy(myinfo->rpcsymbol,"BTCD");
    iguana_urlinit(myinfo,ismainnet,usessl);
    //category_init(myinfo);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create("bitcoin",0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create("poloniex",0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create("bittrex",0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create("btc38",0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create("huobi",0);
    //argjson = arg != 0 ? cJSON_Parse(arg) : cJSON_Parse("{}");
    //iguana_coinadd("BTC",argjson); dont do this here, coin args not set
    ///iguana_coinadd("LTC",argjson);
    //free_json(argjson);
    printf("helpinit\n");
    iguana_helpinit(myinfo);
    printf("basilisks_init\n");
    basilisks_init(myinfo);
    printf("iguana_commandline\n");
    iguana_commandline(myinfo,arg);
#ifdef __APPLE__
    iguana_appletests(myinfo);
#endif
    printf("iguana_launchdaemons\n");
    iguana_launchdaemons(myinfo);
}

