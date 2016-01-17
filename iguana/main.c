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
struct supernet_info MYINFO;
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

int32_t SuperNET_confirmip(struct supernet_info *myinfo,uint32_t ipbits)
{
    int32_t i,j,total = 0; uint32_t x;
    for (i=0; i<IGUANA_MAXCOINS; i++)
    {
        if ( Coins[i] != 0 )
        {
            for (j=0; j<IGUANA_MAXPEERS; j++)
            {
                if ( (x= Coins[i]->peers.active[j].myipbits) != 0 )
                {
                    if ( x == ipbits )
                        total++;
                    else total--;
                }
            }
        }
    }
    return(total);
}

void SuperNET_myipaddr(struct supernet_info *myinfo,struct iguana_peer *addr,char *myipaddr,char *remoteaddr)
{
    uint32_t myipbits = (uint32_t)calc_ipbits(myipaddr);
    if ( addr->myipbits == 0 )
        addr->myipbits = myipbits;
    else if ( addr->myipbits != myipbits )
    {
        printf("%s: myipaddr conflict %x != %x?\n",addr->ipaddr,addr->myipbits,myipbits);
        addr->myipbits = 0;
    }
    if ( addr->myipbits != 0 && myinfo->myaddr.myipbits == 0 )
        myinfo->myaddr.myipbits = addr->myipbits;
    if ( addr->myipbits == myinfo->myaddr.myipbits )
    {
        myinfo->myaddr.confirmed++;
        if ( myinfo->myaddr.selfipbits == 0 || myinfo->ipaddr[0] == 0 )
        {
            if ( (myinfo->myaddr.totalconfirmed= SuperNET_confirmip(myinfo,addr->myipbits)) > 3 )
                myinfo->myaddr.selfipbits = addr->myipbits;
        }
    }
    else myinfo->myaddr.confirmed--;
    if ( myinfo->myaddr.selfipbits == myinfo->myaddr.myipbits )
    {
        expand_ipbits(myinfo->ipaddr,myinfo->myaddr.selfipbits);
        vcalc_sha256(0,myinfo->myaddr.iphash.bytes,(uint8_t *)&myinfo->myaddr.selfipbits,sizeof(myinfo->myaddr.selfipbits));
    }
}

void SuperNET_remotepeer(struct supernet_info *myinfo,struct iguana_info *coin,char *symbol,char *ipaddr,int32_t supernetflag)
{
    uint64_t ipbits; struct iguana_peer *addr;
    printf("got %s remotepeer.(%s) supernet.%d\n",symbol,ipaddr,supernetflag);
    if ( supernetflag != 0 )
    {
        ipbits = calc_ipbits(ipaddr);
        if ( (addr= iguana_peerslot(coin,ipbits)) != 0 )
        {
            printf("launch startconnection to supernet peer.(%s)\n",ipaddr);
            iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
            return;
        }
    }
    iguana_possible_peer(coin,ipaddr);
}

int32_t iguana_send_supernet(struct iguana_info *coin,struct iguana_peer *addr,void *data,long datalen,int32_t delaymillis)
{
    uint64_t r; char *jsonstr = data; int32_t flag=0,qlen = -1; uint8_t serialized[8192],*buf; cJSON *json;
    if ( (json= cJSON_Parse((char *)data)) != 0 )
    {
        if ( j64bits(json,"tag") == 0 )
        {
            OS_randombytes((uint8_t *)&r,sizeof(r));
            jadd64bits(json,"tag",r);
        }
        jdelete(json,"yourip");
        jaddstr(json,"yourip",addr->ipaddr);
        jsonstr = jprint(json,1);
        datalen = strlen(jsonstr)+1;
        flag = 1;
    }
    buf = serialized;
    if ( datalen > sizeof(serialized)-sizeof(struct iguana_msghdr) )
        buf = calloc(1,datalen+sizeof(struct iguana_msghdr));
    memcpy(&buf[sizeof(struct iguana_msghdr)],jsonstr,datalen);
    printf("SUPERSEND.(%s) -> (%s) delaymillis.%d\n",jsonstr,addr->ipaddr,delaymillis);
    qlen = iguana_queue_send(coin,addr,delaymillis,serialized,"SuperNET",(int32_t)datalen,0,1);
    if ( buf != serialized )
        free(buf);
    if ( flag != 0 )
        free(jsonstr);
    return(qlen);
}

uint64_t Packetcache[1024];
int32_t SuperNET_DHTsend(struct supernet_info *myinfo,bits256 routehash,uint8_t *data,int32_t datalen,int32_t maxdelay)
{
    static int lastpurge;
    bits256 packethash; int32_t i,j,firstz,iter,n = 0; struct iguana_peer *addr;
    vcalc_sha256(0,packethash.bytes,data,datalen);
    firstz = -1;
    for (i=0; i<sizeof(Packetcache)/sizeof(*Packetcache); i++)
    {
        if ( Packetcache[i] == 0 )
        {
            Packetcache[i] = packethash.txid;
            printf("add.%llx packetcache(%s)\n",(long long)packethash.txid,(char *)data);
            break;
        }
        else if ( Packetcache[i] == packethash.txid )
        {
            printf("SuperNET_DHTsend reject repeated packet.%llx (%s)\n",(long long)packethash.txid,(char *)data);
            return(-1);
        }
    }
    if ( i == sizeof(Packetcache)/sizeof(*Packetcache) )
    {
        printf("purge slot[%d]\n",lastpurge);
        Packetcache[lastpurge++] = packethash.txid;
        if ( lastpurge >= sizeof(Packetcache)/sizeof(*Packetcache) )
            lastpurge = 0;
    }
    for (iter=0; iter<2; iter++)
    {
        for (i=0; i<IGUANA_MAXCOINS; i++)
        {
            if ( Coins[i] != 0 )
            {
                for (j=0; j<IGUANA_MAXPEERS; j++)
                {
                    addr = &Coins[i]->peers.active[j];
                    if ( addr->usock >= 0 )
                    {
                        if ( iter == 0 && memcmp(addr->iphash.bytes,routehash.bytes,sizeof(addr->iphash)) == 0 )
                        {
                            iguana_send_supernet(Coins[i],addr,data,datalen,maxdelay==0?0:rand()%maxdelay);
                            return(100);
                        }
                        else if ( iter == 1 )
                        {
                            if ( bits256_cmp(addr->iphash,myinfo->myaddr.iphash) < 0 )
                            {
                                iguana_send_supernet(Coins[i],addr,data,datalen,maxdelay==0?0:rand()%maxdelay);
                                n++;
                            }
                        }
                    }
                }
            }
        }
    }
    return(n);
}

int32_t SuperNET_mypacket(struct supernet_info *myinfo,uint32_t destipbits,bits256 destpub)
{
    if ( destipbits == myinfo->myaddr.selfipbits )
        return(0);
    if ( memcmp(destpub.bytes,myinfo->myaddr.pubkey.bytes,sizeof(destpub)) == 0 )
        return(0);
    // check for encrypted packets
    return(-1);
}

char *SuperNET_p2p(struct iguana_info *coin,struct iguana_peer *addr,int32_t *delaymillisp,char *ipaddr,uint8_t *data,int32_t datalen)
{
    cJSON *json,*retjson; bits256 destpub,routehash; uint32_t n,destipbits = 0;
    char *destip,*agent,*myipaddr,*method,retbuf[512],*retstr = 0;
    *delaymillisp = 0;
    if ( (json= cJSON_Parse((char *)data)) != 0 )
    {
        printf("GOT >>>>>>>> SUPERNET P2P.(%s) from.%s\n",(char *)data,coin->symbol);
        if ( (myipaddr= jstr(json,"yourip")) != 0 )
            SuperNET_myipaddr(&MYINFO,addr,myipaddr,ipaddr);
        if ( (destip= jstr(json,"destip")) != 0 )
            destipbits = (uint32_t)calc_ipbits(destip);
        destpub = jbits256(json,"destpub");
        if ( SuperNET_mypacket(&MYINFO,destipbits,destpub) < 0 )
        {
            if ( destipbits != 0 )
                vcalc_sha256(0,routehash.bytes,(uint8_t *)&destipbits,sizeof(destipbits));
            else routehash = destpub;
            n = SuperNET_DHTsend(&MYINFO,routehash,data,datalen,juint(json,"delay"));
            free_json(json);
            if ( n > 0 )
            {
                if ( n == 100 )
                    sprintf(retbuf,"{\"result\":\"packet sent to destination\"}");
                else sprintf(retbuf,"{\"result\":\"packet forwarded to superDHT\",\"branches\":%d}",n);
            } else return(clonestr("{\"error\":\"no nodes to forward packet to\"}"));
        }
        if ( (agent= jstr(json,"agent")) != 0 && (method= jstr(json,"method")) != 0 )
        {
            if ( strcmp(agent,"SuperNET") == 0 && strcmp(method,"stop") == 0 )
            {
                addr->dead = (uint32_t)time(NULL);
                free_json(json);
                return(clonestr("{\"result\":\"peer marked as dead\"}"));
            }
            jaddstr(json,"fromp2p",coin->symbol);
            if ( (retstr= SuperNET_JSON(0,json,ipaddr)) != 0 )
            {
                //printf("retstr.(%s)\n",retstr);
                if ( (retjson= cJSON_Parse(retstr)) != 0 )
                {
                    if ( jobj(retjson,"result") != 0 || jobj(retjson,"error") != 0 || jobj(retjson,"method") == 0 )
                    {
                        //printf("it is a result, dont return\n");
                        free(retstr);
                        retstr = 0;
                    }
                    else *delaymillisp = (rand() % 1000);
                    free_json(retjson);
                }
            } else printf("null retstr from SuperNET_JSON\n");
        }
        free_json(json);
    }
    return(retstr);
}

void iguana_exit()
{
    int32_t i,j,k; char *stopstr = "{\"agent\":\"SuperNET\",\"method\":\"stop\"}";
    printf("start EXIT\n");
    for (i=0; i<IGUANA_MAXCOINS; i++)
    {
        if ( Coins[i] != 0 )
        {
            for (j=0; j<IGUANA_MAXPEERS; j++)
            {
                if ( Coins[i]->peers.active[j].usock >= 0 && Coins[i]->peers.active[j].supernet != 0 )
                    iguana_send_supernet(Coins[i],&Coins[i]->peers.active[j],stopstr,strlen(stopstr)+1,0);
            }
        }
    }
    sleep(3);
    for (i=0; i<IGUANA_MAXCOINS; i++)
    {
        if ( Coins[i] != 0 )
        {
            for (j=0; j<IGUANA_MAXPEERS; j++)
            {
                Coins[i]->peers.active[j].dead = (uint32_t)time(NULL);
                for (k=0; k<3; k++)
                {
                    if ( Coins[i]->peers.active[j].usock >= 0 )
                        printf("wait for %s\n",Coins[i]->peers.active[j].ipaddr), sleep(1);
                }
                if ( Coins[i]->peers.active[j].usock >= 0 )
                    closesocket(Coins[i]->peers.active[j].usock);
            }
        }
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
    char helperstr[64],*helperargs,*ipaddr,*coinargs=0,*secret,*jsonstr = arg;
    int32_t i,len,flag,c; cJSON *json; uint8_t secretbuf[512]; int64_t allocsize;
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
    signal(SIGINT,sigint_func);
    signal(SIGILL,sigillegal_func);
    signal(SIGHUP,sighangup_func);
    signal(SIGKILL,sigkill_func);
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
    memset(&MYINFO,0,sizeof(MYINFO));
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

