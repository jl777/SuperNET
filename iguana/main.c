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

void iguana_main(void *arg)
{
    FILE *fp; cJSON *json; uint8_t *space,secretbuf[512],x; uint32_t r; long allocsize; bits256 pangeahash;
    char helperstr[64],fname[512],*wallet2,*wallet2str,*tmpstr,*confstr,*helperargs,*ipaddr,*coinargs=0,*secret,*jsonstr = arg;
    struct supernet_info *myinfo;
    int32_t i,len,flag,c; bits256 acct,seed,checkhash,wallethash,walletpub,wallet2shared,wallet2priv,wallet2pub;
    myinfo = SuperNET_MYINFO(0);
    char str[65]; uint32_t t,s;
    t = 1409839200;//(uint32_t)time(NULL);
    for (i=0; i<1; i++)
    {
        utc_str(str,t-i);
        s = OS_conv_utime(str);
        //if ( s != t-i )
            printf("t.%u -> %s -> %u diff.[%d]\n",t-i,str,s,(t-i) - s);
    }
    iguana_chaingenesis(1,1403138561,0x1e0fffff,8359109,bits256_conv("fd1751cc6963d88feca94c0d01da8883852647a37a0a67ce254d62dd8c9d5b2b"));
    iguana_chaingenesis(1,1409839200,0x1e0fffff,64881664,bits256_conv("698a93a1cacd495a7a4fb3864ad8d06ed4421dedbc57f9aaad733ea53b1b5828"));

    mycalloc(0,0,0);
    iguana_initQ(&helperQ,"helperQ");
    OS_ensure_directory("confs");
    OS_ensure_directory("DB");
    OS_ensure_directory("tmp");
    if ( (tmpstr= SuperNET_JSON(myinfo,cJSON_Parse("{\"agent\":\"SuperNET\",\"method\":\"help\"}"),0)) != 0 )
    {
        if ( (API_json= cJSON_Parse(tmpstr)) != 0 && (API_json= jobj(API_json,"result")) != 0 )
            API_json = jobj(API_json,"API");
        free(tmpstr);
    }
    memset(wallet2shared.bytes,0,sizeof(wallet2shared));
    wallethash = GENESIS_PRIVKEY;
    wallet2pub = GENESIS_PUBKEY;
    if ( jsonstr != 0 && (json= cJSON_Parse(jsonstr)) != 0 )
    {
        printf("ARGSTR.(%s)\n",jsonstr);
        if ( jobj(json,"numhelpers") != 0 )
            IGUANA_NUMHELPERS = juint(json,"numhelpers");
        if ( (secret= jstr(json,"wallet")) != 0 )
        {
            len = (int32_t)strlen(secret);
            if ( is_hexstr(secret,0) != 0 && len == 128 )
            {
                len >>= 1;
                decode_hex(secretbuf,len,secret);
            } else vcalc_sha256(0,secretbuf,(void *)secret,len), len = sizeof(bits256);
            memcpy(wallethash.bytes,secretbuf,sizeof(wallethash));
            char str[65]; printf("wallethash.(%s)\n",bits256_str(str,wallethash));
        }
        if ( (wallet2= jstr(json,"2fafile")) != 0 )
        {
            if ( (wallet2str= OS_filestr(&allocsize,wallet2)) != 0 )
            {
                r = calc_crc32(0,wallet2str,(int32_t)allocsize);
                r %= 32;
                for (i=0; i<allocsize; i++)
                    wallet2str[i] ^= wallethash.bytes[(i + r) % 32];
                vcalc_sha256(0,wallet2priv.bytes,(void *)wallet2str,(int32_t)allocsize);
                wallet2pub = curve25519(wallet2priv,curve25519_basepoint9());
                seed = curve25519_shared(wallethash,wallet2pub);
                vcalc_sha256(0,wallet2shared.bytes,seed.bytes,sizeof(bits256));
                char str[65],str2[65]; printf("have 2fafile.(%s) -> pub.%s shared.%s\n",wallet2,bits256_str(str,wallet2pub),bits256_str(str2,wallet2shared));
                free(wallet2str);
            }
        }
        if ( jobj(json,"coins") != 0 )
            coinargs = jsonstr;
    }
    walletpub = curve25519(wallethash,curve25519_basepoint9());
    seed = curve25519_shared(wallethash,wallet2pub);
    vcalc_sha256(0,wallet2shared.bytes,seed.bytes,sizeof(bits256));
    OS_randombytes(myinfo->persistent_priv.bytes,sizeof(myinfo->privkey));
    myinfo->myaddr.persistent = curve25519(myinfo->persistent_priv,curve25519_basepoint9());
    vcalc_sha256(0,acct.bytes,(void *)myinfo->myaddr.persistent.bytes,sizeof(bits256));
    myinfo->myaddr.nxt64bits = acct.txid;
    RS_encode(myinfo->myaddr.NXTADDR,myinfo->myaddr.nxt64bits);
    if ( bits256_nonz(wallet2shared) > 0 )
        sprintf(fname,"confs/iguana.%llu",(long long)wallet2shared.txid);
    else sprintf(fname,"confs/iguana.conf");
    printf("check conf.(%s)\n",fname);
    if ( (confstr= OS_filestr(&allocsize,fname)) != 0 )
    {
        if ( bits256_nonz(wallet2shared) > 0 )
        {
            space = malloc(IGUANA_MAXPACKETSIZE);
            json = cJSON_Parse(confstr);
            //json = SuperNET_bits2json(walletpub,wallet2shared,(uint8_t *)confstr,space,(int32_t)allocsize,1);
            free(space);
            printf("decoded.(%s)\n",jprint(json,0));
        } else json = cJSON_Parse(confstr), printf("CONF.(%s)\n",confstr);
        if ( json != 0 )
        {
            if ( (ipaddr= jstr(json,"ipaddr")) != 0 && is_ipaddr(ipaddr) != 0 )
                strcpy(myinfo->ipaddr,ipaddr);
            if ( (secret= jstr(json,"secret")) != 0 )
            {
                myinfo->myaddr.nxt64bits = conv_NXTpassword(myinfo->persistent_priv.bytes,myinfo->myaddr.persistent.bytes,(uint8_t *)secret,(int32_t)strlen(secret));
                RS_encode(myinfo->myaddr.NXTADDR,myinfo->myaddr.nxt64bits);
            }
            else
            {
                myinfo->persistent_priv = jbits256(json,"persistent_priv");
                if ( bits256_nonz(myinfo->persistent_priv) == 0 )
                {
                    printf("null persistent_priv? generate new one\n");
                    OS_randombytes(myinfo->persistent_priv.bytes,sizeof(myinfo->privkey));
                }
                myinfo->myaddr.persistent = jbits256(json,"persistent_pub");
                checkhash = curve25519(myinfo->persistent_priv,curve25519_basepoint9());
            }
            free_json(json);
            if ( memcmp(checkhash.bytes,myinfo->myaddr.persistent.bytes,sizeof(checkhash)) != 0 )
            {
                printf("persistent pubkey mismatches one in iguana.conf\n");
                myinfo->myaddr.persistent = checkhash;
                confstr = 0;
            }
        } else printf("Cant parse.(%s)\n",confstr), confstr = 0;
        if ( confstr != 0 )
            free(confstr);
    }
    else if ( (ipaddr= OS_filestr(&allocsize,"ipaddr")) != 0 )
    {
        printf("got ipaddr.(%s)\n",ipaddr);
        len = (int32_t)strlen(ipaddr) - 1;
        while ( len > 8 && ((c= ipaddr[len]) == '\r' || c == '\n' || c == ' ' || c == '\t') )
            ipaddr[len] = 0, len--;
        printf("got ipaddr.(%s) %x\n",ipaddr,is_ipaddr(ipaddr));
        if ( is_ipaddr(ipaddr) != 0 )
        {
            strcpy(myinfo->ipaddr,ipaddr);
            myinfo->myaddr.selfipbits = (uint32_t)calc_ipbits(ipaddr);
        }
        free(ipaddr);
    }
    if ( myinfo->myaddr.selfipbits == 0 )
    {
        strcpy(myinfo->ipaddr,"127.0.0.1");
        myinfo->myaddr.selfipbits = (uint32_t)calc_ipbits(myinfo->ipaddr);
    }
#ifdef __APPLE__
    x = 1;
#else
    x = 0;
#endif
    while ( myinfo->myaddr.pubkey.bytes[0] != x )
    {
        OS_randombytes(myinfo->privkey.bytes,sizeof(myinfo->privkey));
        myinfo->myaddr.pubkey = curve25519(myinfo->privkey,curve25519_basepoint9());
    }
    vcalc_sha256(0,acct.bytes,(void *)myinfo->myaddr.persistent.bytes,sizeof(bits256));
    myinfo->myaddr.nxt64bits = acct.txid;
    RS_encode(myinfo->myaddr.NXTADDR,myinfo->myaddr.nxt64bits);
    char str2[65]; printf("%s %llu %p PRIV.%s PUB.%s persistent.%llx %llx\n",myinfo->myaddr.NXTADDR,(long long)myinfo->myaddr.nxt64bits,&myinfo->privkey,bits256_str(str,myinfo->privkey),bits256_str(str2,myinfo->myaddr.pubkey),(long long)myinfo->persistent_priv.txid,(long long)myinfo->myaddr.persistent.txid);
    if ( confstr == 0 )
    {
        uint8_t *compressed,*serialized; int32_t complen,maxsize = IGUANA_MAXPACKETSIZE;
        json = cJSON_CreateObject();
        jaddstr(json,"agent","SuperNET");
        jaddstr(json,"method","saveconf");
        jaddstr(json,"myipaddr",myinfo->ipaddr);
        jaddbits256(json,"persistent_priv",myinfo->persistent_priv);
        jaddbits256(json,"persistent_pub",myinfo->myaddr.persistent);
        compressed = calloc(1,maxsize);
        serialized = calloc(1,maxsize);
        if ( strcmp("confs/iguana.conf",fname) != 0 )
        {
            //sprintf(fname,"confs/iguana.%llu",(long long)wallet2shared.txid);
            //if ( SuperNET_json2bits(myinfo->ipaddr,wallethash,walletpub,wallet2shared,serialized,&complen,compressed,maxsize,myinfo->ipaddr,wallet2pub,json) > 0 )
            {
                complen = (int32_t)strlen(jprint(json,0));
                printf("save (%s) <- %d\n",fname,complen);
                if ( (fp= fopen(fname,"wb")) != 0 )
                {
                    fwrite(compressed,1,complen,fp);
                    fclose(fp);
                }
            }// else printf("error saving.(%s) json2bits.(%s)\n",fname,jprint(json,0));
        }
        else
        {
            char *str = jprint(json,0);
            //sprintf(fname,"confs/iguana.conf");
            printf("save (%s) <- (%s)\n",fname,str);
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                fwrite(str,1,strlen(str),fp);
                fclose(fp);
            }
            free(str);
        }
        free(compressed), free(serialized);
        free_json(json);
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
    if ( IGUANA_NUMHELPERS == 0 )
        IGUANA_NUMHELPERS = 1;
    category_subscribe(&MYINFO,GENESIS_PUBKEY,GENESIS_PUBKEY);
    pangeahash = calc_categoryhashes(0,"pangea",0);
    category_subscribe(myinfo,pangeahash,GENESIS_PUBKEY);
    category_processfunc(pangeahash,pangea_hexmsg);
    for (i=0; i<IGUANA_NUMHELPERS; i++)
    {
        sprintf(helperstr,"{\"name\":\"helper.%d\"}",i);
        helperargs = clonestr(helperstr);
        iguana_launch(iguana_coinadd("BTCD"),"iguana_helper",iguana_helper,helperargs,IGUANA_PERMTHREAD);
    }
    iguana_launch(iguana_coinadd("BTCD"),"rpcloop",iguana_rpcloop,SuperNET_MYINFO(0),IGUANA_PERMTHREAD);
    if ( coinargs != 0 )
        iguana_launch(iguana_coinadd("BTCD"),"iguana_coins",iguana_coins,coinargs,IGUANA_PERMTHREAD);
    else if ( 1 )
    {
#ifdef __APPLE__
        sleep(1);
        char *str;
        if ( (str= SuperNET_JSON(&MYINFO,cJSON_Parse("{\"wallet\":\"password\",\"agent\":\"iguana\",\"method\":\"addcoin\",\"services\":128,\"maxpeers\":128,\"newcoin\":\"VPN\",\"active\":1}"),0)) != 0 )
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
            else pangea_queues(SuperNET_MYINFO(0));
        }
        if ( flag == 0 )
            sleep(1);
    }
}

