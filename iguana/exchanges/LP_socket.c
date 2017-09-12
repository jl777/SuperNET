/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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

/**
 * - we need to include WinSock2.h header to correctly use windows structure
 * as the application is still using 32bit structure from mingw so, we need to
 * add the include based on checking
 * @author - fadedreamz@gmail.com
 * @remarks - #if (defined(_M_X64) || defined(__amd64__)) && defined(WIN32)
 *     is equivalent to #if defined(_M_X64) as _M_X64 is defined for MSVC only
 */
#if defined(_M_X64)
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#endif

#define ELECTRUM_TIMEOUT 2

int32_t LP_socket(int32_t bindflag,char *hostname,uint16_t port)
{
    int32_t opt,sock,result; char ipaddr[64],checkipaddr[64]; struct timeval timeout;
    struct sockaddr_in saddr; socklen_t addrlen,slen;
    addrlen = sizeof(saddr);
    struct hostent *hostent;
    
    /**
     * gethostbyname() is deprecated and cause crash on x64 windows
     * the solution is to implement similar functionality by using getaddrinfo()
     * it is standard posix function and is correctly supported in win32/win64/linux
     * @author - fadedreamz@gmail.com
     */
#if defined(_M_X64)
    struct addrinfo *addrresult = NULL;
    struct addrinfo *returnptr = NULL;
    struct addrinfo hints;
    struct sockaddr_in * sockaddr_ipv4;
    int retVal;
    int found = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
#endif
    
    if ( parse_ipaddr(ipaddr,hostname) != 0 )
        port = parse_ipaddr(ipaddr,hostname);
    
#if defined(_M_X64)
    retVal = getaddrinfo(ipaddr, NULL, &hints, &addrresult);
    for (returnptr = addrresult; returnptr != NULL && found == 0; returnptr = returnptr->ai_next) {
        switch (returnptr->ai_family) {
            case AF_INET:
                sockaddr_ipv4 = (struct sockaddr_in *) returnptr->ai_addr;
                // we want to break from the loop after founding the first ipv4 address
                found = 1;
                break;
        }
    }
    
    // if we iterate through the loop and didn't find anything,
    // that means we failed in the dns lookup
    if (found == 0) {
        printf("getaddrinfo(%s) returned error\n", hostname);
        freeaddrinfo(addrresult);
        return(-1);
    }
#else
    hostent = gethostbyname(ipaddr);
    if ( hostent == NULL )
    {
        printf("gethostbyname(%s) returned error: %d port.%d ipaddr.(%s)\n",hostname,errno,port,ipaddr);
        return(-1);
    }
#endif
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    //#ifdef WIN32
    //   saddr.sin_addr.s_addr = (uint32_t)calc_ipbits("127.0.0.1");
    //#else
    
#if defined(_M_X64)
    saddr.sin_addr.s_addr = sockaddr_ipv4->sin_addr.s_addr;
    // graceful cleanup
    sockaddr_ipv4 = NULL;
    freeaddrinfo(addrresult);
#else
    memcpy(&saddr.sin_addr.s_addr,hostent->h_addr_list[0],hostent->h_length);
#endif
    expand_ipbits(checkipaddr,saddr.sin_addr.s_addr);
    if ( strcmp(ipaddr,checkipaddr) != 0 )
        printf("bindflag.%d iguana_socket mismatch (%s) -> (%s)?\n",bindflag,checkipaddr,ipaddr);
    //#endif
    if ( (sock= socket(AF_INET,SOCK_STREAM,0)) < 0 )
    {
        if ( errno != ETIMEDOUT )
            printf("socket() failed: %s errno.%d", strerror(errno),errno);
        return(-1);
    }
    opt = 1;
    slen = sizeof(opt);
    //printf("set keepalive.%d\n",setsockopt(sock,SOL_SOCKET,SO_KEEPALIVE,(void *)&opt,slen));
#ifndef WIN32
    if ( 1 )//&& bindflag != 0 )
    {
        opt = 0;
        getsockopt(sock,SOL_SOCKET,SO_KEEPALIVE,(void *)&opt,&slen);
        opt = 1;
        //printf("keepalive.%d\n",opt);
    }
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(void *)&opt,sizeof(opt));
#ifdef __APPLE__
    setsockopt(sock,SOL_SOCKET,SO_NOSIGPIPE,&opt,sizeof(opt));
#endif
#endif
    if ( bindflag == 0 )
    {
        printf("call connect sock.%d\n",sock);
        result = connect(sock,(struct sockaddr *)&saddr,addrlen);
        printf("called connect result.%d\n",result);
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(void *)&timeout,sizeof(timeout));
        if ( result != 0 )
        {
            if ( errno != ECONNRESET && errno != ENOTCONN && errno != ECONNREFUSED && errno != ETIMEDOUT && errno != EHOSTUNREACH )
            {
                //printf("%s(%s) port.%d failed: %s sock.%d. errno.%d\n",bindflag!=0?"bind":"connect",hostname,port,strerror(errno),sock,errno);
            }
            if ( sock >= 0 )
                closesocket(sock);
            return(-1);
        }
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(void *)&timeout,sizeof(timeout));
    }
    else
    {
        while ( (result= bind(sock,(struct sockaddr*)&saddr,addrlen)) != 0 )
        {
            if ( errno == EADDRINUSE )
            {
                sleep(1);
                printf("ERROR BINDING PORT.%d. this is normal tcp timeout, unless another process is using port\n",port);
                fflush(stdout);
                sleep(3);
                printf("%s(%s) port.%d try again: %s sock.%d. errno.%d\n",bindflag!=0?"bind":"connect",hostname,port,strerror(errno),sock,errno);
                if ( bindflag == 1 )
                {
                    closesocket(sock);
                    return(-1);
                }
                sleep(13);
                //continue;
            }
            if ( errno != ECONNRESET && errno != ENOTCONN && errno != ECONNREFUSED && errno != ETIMEDOUT && errno != EHOSTUNREACH )
            {
                printf("%s(%s) port.%d failed: %s sock.%d. errno.%d\n",bindflag!=0?"bind":"connect",hostname,port,strerror(errno),sock,errno);
                closesocket(sock);
                return(-1);
            }
        }
        if ( listen(sock,64) != 0 )
        {
            printf("listen(%s) port.%d failed: %s sock.%d. errno.%d\n",hostname,port,strerror(errno),sock,errno);
            if ( sock >= 0 )
                closesocket(sock);
            return(-1);
        }
    }
#ifdef __APPLE__
    //timeout.tv_sec = 0;
    //timeout.tv_usec = 30000;
    //setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(void *)&timeout,sizeof(timeout));
    timeout.tv_sec = 0;
    timeout.tv_usec = 10000;
    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(void *)&timeout,sizeof(timeout));
#endif
    return(sock);
}

int32_t LP_socketsend(int32_t sock,uint8_t *serialized,int32_t len)
{
    int32_t numsent,remains,flags = 0;
#ifndef _WIN32
    flags = MSG_NOSIGNAL;
#endif
    remains = len;
    while ( remains > 0 )
    {
        if ( (numsent= (int32_t)send(sock,serialized,remains,flags)) < 0 )
        {
            if ( errno == EAGAIN || errno == EWOULDBLOCK )
            {
                sleep(1);
                continue;
            }
            printf("(%s): numsent.%d vs remains.%d len.%d errno.%d (%s) usock.%d\n",serialized,numsent,remains,len,errno,strerror(errno),sock);
            return(-errno);
        }
        else if ( remains > 0 )
        {
            remains -= numsent;
            serialized += numsent;
            if ( remains > 0 )
                printf("%d LP_socket sent.%d remains.%d of len.%d\n",sock,numsent,remains,len);
        }
        //printf("numsent.%d vs remains.%d len.%d sock.%d\n",numsent,remains,len,sock);
    }
    return(len);
}

int32_t LP_socketrecv(int32_t sock,uint8_t *recvbuf,int32_t maxlen)
{
    int32_t recvlen = -1;
    while ( 1 )
    {
        if ( (recvlen= (int32_t)recv(sock,recvbuf,maxlen,0)) < 0 )
        {
            if ( errno == EAGAIN )
            {
                //printf("%s recv errno.%d %s len.%d remains.%d\n",ipaddr,errno,strerror(errno),len,remains);
                //printf("EAGAIN for len %d, remains.%d\n",len,remains);
                sleep(1);
            } else return(-errno);
        } else break;
    }
    return(recvlen);
}

struct electrum_info
{
    queue_t sendQ,pendingQ;
    int32_t bufsize,sock;
    uint32_t stratumid,lasttime,pending;
    char ipaddr[64],symbol[16];
    uint16_t port;
    uint8_t buf[];
} *Electrums[8192];
int32_t Num_electrums;

// purge timedout

struct electrum_info *electrum_server(char *symbol,struct electrum_info *ep)
{
    struct electrum_info *rbuf[128],*recent_ep; uint32_t recent,mostrecent = 0; int32_t i,n = 0;
    portable_mutex_lock(&LP_electrummutex);
    if ( ep == 0 )
    {
        //printf("find random electrum.%s from %d\n",symbol,Num_electrums);
        memset(rbuf,0,sizeof(rbuf));
        recent_ep = 0;
        recent = (uint32_t)time(NULL) - 300;
        for (i=0; i<Num_electrums; i++)
        {
            ep = Electrums[i];
            if ( strcmp(symbol,ep->symbol) == 0 && ep->sock >= 0 )
            {
                if ( ep->lasttime > recent )
                {
                    rbuf[n++] = ep;
                    if ( n == sizeof(rbuf)/sizeof(*rbuf) )
                        break;
                }
                else if ( ep->lasttime > mostrecent )
                {
                    mostrecent = ep->lasttime;
                    recent_ep = ep;
                }
            }
        }
        ep = recent_ep;
        if ( n > 0 )
        {
            i = (rand() % n);
            ep = rbuf[i];
        }
    }
    else if ( Num_electrums < sizeof(Electrums)/sizeof(*Electrums) )
        Electrums[Num_electrums++] = ep;
    else printf("Electrum server pointer buf overflow %d\n",Num_electrums);
    portable_mutex_unlock(&LP_electrummutex);
    return(ep);
}

struct electrum_info *LP_electrum_info(char *symbol,char *ipaddr,uint16_t port,int32_t bufsize)
{
    struct electrum_info *ep=0; int32_t i; struct stritem *sitem; char name[512],*str = "init string";
    printf("electrum info\n");
    portable_mutex_lock(&LP_electrummutex);
    for (i=0; i<Num_electrums; i++)
    {
        ep = Electrums[i];
        printf("i.%d %p\n",i,ep);
        if ( strcmp(ep->ipaddr,ipaddr) == 0 && ep->port == port && strcmp(ep->symbol,symbol) == 0 )
        {
            printf("%s.(%s:%u) already an electrum server\n",symbol,ipaddr,port);
            break;
        }
        ep = 0;
    }
    portable_mutex_unlock(&LP_electrummutex);
    printf("electrum info ep.%p\n",ep);
    if ( ep == 0 )
    {
        ep = calloc(1,sizeof(*ep) + bufsize);
        ep->sock = LP_socket(0,ipaddr,port);
        safecopy(ep->symbol,symbol,sizeof(ep->symbol));
        safecopy(ep->ipaddr,ipaddr,sizeof(ep->ipaddr));
        ep->port = port;
        ep->bufsize = bufsize;
        ep->lasttime = (uint32_t)time(NULL);
        sprintf(name,"%s_%s_%u_electrum_sendQ",symbol,ipaddr,port);
        printf("create queue.%s\n",name);
        queue_enqueue(name,&ep->sendQ,queueitem(str));
        if ( (sitem= queue_dequeue(&ep->sendQ)) == 0 && strcmp(sitem->str,str) != 0 )
            printf("error with string sendQ sitem.%p (%s)\n",sitem,sitem==0?0:sitem->str);
        sprintf(name,"%s_%s_%u_electrum_pendingQ",symbol,ipaddr,port);
        printf("create queue.%s\n",name);
        queue_enqueue(name,&ep->pendingQ,queueitem(str));
        if ( (sitem= queue_dequeue(&ep->pendingQ)) == 0 && strcmp(sitem->str,str) != 0 )
            printf("error with string pendingQ sitem.%p (%s)\n",sitem,sitem==0?0:sitem->str);
        printf("call electrum server\n");
        electrum_server(symbol,ep);
    }
    return(ep);
}

int32_t LP_recvfunc(struct electrum_info *ep,char *str,int32_t len)
{
    cJSON *strjson; uint32_t idnum=0; struct stritem *stritem; struct queueitem *item = 0;
    ep->lasttime = (uint32_t)time(NULL);
    if ( (strjson= cJSON_Parse(str)) != 0 )
    {
        idnum = juint(strjson,"id");
        portable_mutex_lock(&ep->pendingQ.mutex);
        if ( ep->pendingQ.list != 0 )
        {
            DL_FOREACH(ep->pendingQ.list,item)
            {
                stritem = (struct stritem *)item;
                if ( item->type == idnum )
                {
                    //printf("matched idnum.%d\n",idnum);
                    DL_DELETE(ep->pendingQ.list,item);
                    break;
                }
                if ( stritem->expiration < ep->lasttime )
                {
                    DL_DELETE(ep->pendingQ.list,item);
                    printf("expired (%s)\n",stritem->str);
                    strjson = cJSON_CreateObject();
                    jaddnum(strjson,"id",item->type);
                    jaddstr(strjson,"error","timeout");
                    if ( stritem->retptrp != 0 )
                        *((cJSON **)stritem->retptrp) = strjson;
                    else free_json(strjson);
                }
                item = 0;
            }
        }
        portable_mutex_unlock(&ep->pendingQ.mutex);
        if ( item != 0 )
        {
            // do callback
            stritem = (struct stritem *)item;
            printf("callback (%s) -> (%s)\n",stritem->str,jprint(strjson,0));
            if ( stritem->retptrp != 0 )
                *((cJSON **)stritem->retptrp) = strjson;
            else free_json(strjson);
            free(item);
        }
        if ( strjson != 0 )
            free_json(strjson);
    }
    return(item != 0);
}

void LP_dedicatedloop(void *arg)
{
    struct pollfd fds; int32_t i,len,flag,timeout = 10; struct stritem *sitem; struct electrum_info *ep = arg;
    printf("LP_dedicatedloop ep.%p sock.%d for %s:%u num.%d %p\n",ep,ep->sock,ep->ipaddr,ep->port,Num_electrums,&Num_electrums);
    while ( ep->sock >= 0 )
    {
        flag = 0;
        memset(&fds,0,sizeof(fds));
        fds.fd = ep->sock;
        fds.events |= (POLLOUT | POLLIN);
        if (  poll(&fds,1,timeout) > 0 && (fds.revents & POLLOUT) != 0 && ep->pending == 0 && (sitem= queue_dequeue(&ep->sendQ)) != 0 )
        {
            ep->pending = (uint32_t)time(NULL);
            if ( LP_socketsend(ep->sock,(uint8_t *)sitem->str,(int32_t)strlen(sitem->str)) <= 0 )
            {
                printf("%s:%u is dead\n",ep->ipaddr,ep->port);
                closesocket(ep->sock);
                ep->sock = -1;
                break;
            }
            queue_enqueue("pendingQ",&ep->pendingQ,(struct queueitem *)sitem);
            flag++;
        }
        if ( flag == 0 )
        {
            if ( (fds.revents & POLLIN) != 0 )
            {
                if ( (len= LP_socketrecv(ep->sock,ep->buf,ep->bufsize)) > 0 )
                {
                    ep->pending = 0;
                    LP_recvfunc(ep,(char *)ep->buf,len);
                    flag++;
                }
            }
            if ( flag == 0 )
                usleep(100000);
        }
    }
    printf("close %s:%u\n",ep->ipaddr,ep->port);
    if ( Num_electrums > 0 )
    {
        portable_mutex_lock(&LP_electrummutex);
        for (i=0; i<Num_electrums; i++)
        {
            if ( Electrums[i] == ep )
            {
                Electrums[i] = Electrums[--Num_electrums];
                Electrums[Num_electrums] = 0;
                break;
            }
        }
        portable_mutex_unlock(&LP_electrummutex);
    }
    free(ep);
}

cJSON *LP_electrumserver(struct iguana_info *coin,char *ipaddr,uint16_t port)
{
    struct electrum_info *ep; cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"ipaddr",ipaddr);
    jaddnum(retjson,"port",port);
    ep = LP_electrum_info(coin->symbol,ipaddr,port,IGUANA_MAXPACKETSIZE * 10);
    printf("ep.%p electrum server %s:%u\n",ep,ipaddr,port);
    if ( ep != 0 && OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_dedicatedloop,(void *)ep) != 0 )
    {
        printf("error launching LP_dedicatedloop %s.(%s:%u)\n",coin->symbol,ep->ipaddr,ep->port);
        jaddstr(retjson,"error","couldnt launch electrum thread");
    }
    else
    {
        printf("launched.(%s:%u)\n",ep->ipaddr,ep->port);
        jaddstr(retjson,"result","success");
        coin->electrum = ep;
    }
    printf("(%s)\n",jprint(retjson,0));
    return(retjson);
}

/*
if ( (retjson= electrum_address_listunspent(symbol,ep,0,addr)) != 0 )
you can call it like the above, where symbol is the coin, ep is the electrum server info pointer, the 0 is a callback ptr where 0 means to block till it is done
all the API calls have the same three args
if the callback ptr is &retjson, then on completion it will put the cJSON *ptr into it, so to spawn a bunch of calls you need to call with symbol,ep,&retjsons[i],...
default timeout is set to 2 seconds, not sure if that is enough, on each receive from any server, requests that are timeout are purged (and if a callback set, will just return and "error" timeout JSON
a null value for ep will make it choose a random server for that coin
 */
                                                                                                                                        
cJSON *electrum_submit(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *method,char *params,int32_t timeout)
{
    // queue id and string and callback
    char stratumreq[16384]; struct stritem *sitem; cJSON *retjson = 0;
    if ( ep == 0 )
        ep = electrum_server(symbol,0);
    if ( ep != 0 )
    {
        sprintf(stratumreq,"{ \"jsonrpc\":\"2.0\", \"id\": %u, \"method\":\"%s\", \"params\": %s }\n",ep->stratumid,method,params);
        //printf("stratumreq.(%s)\n",stratumreq);
        ep->buf[0] = 0;
        sitem = (struct stritem *)queueitem(stratumreq);
        sitem->DL.type = ep->stratumid++;
        if ( retjsonp != 0 )
            sitem->retptrp = (void **)retjsonp;
        else sitem->retptrp = (void **)&retjson;
        queue_enqueue("sendQ",&ep->sendQ,&sitem->DL);
    } else printf("couldnt find electrum server for (%s %s)\n",method,params);
    return(retjson);
}

cJSON *electrum_noargs(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *method,int32_t timeout)
{
    return(electrum_submit(symbol,ep,retjsonp,method,"[]",timeout));
}

cJSON *electrum_strarg(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *method,char *arg,int32_t timeout)
{
    char params[16384];
    if ( strlen(arg) < sizeof(params) )
    {
        sprintf(params,"[\"%s\"]",arg);
        return(electrum_submit(symbol,ep,retjsonp,method,params,timeout));
    } else return(0);
}

cJSON *electrum_intarg(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *method,int32_t arg,int32_t timeout)
{
    char params[64];
    sprintf(params,"[\"%d\"]",arg);
    return(electrum_submit(symbol,ep,retjsonp,method,params,timeout));
}

cJSON *electrum_hasharg(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *method,bits256 arg,int32_t timeout)
{
    char params[128],str[65];
    sprintf(params,"[\"%s\"]",bits256_str(str,arg));
    return(electrum_submit(symbol,ep,retjsonp,method,params,timeout));
}

//" "--blockchain.numblocks.subscribe", "--blockchain.address.get_proof", "--blockchain.utxo.get_address",

cJSON *electrum_version(char *symbol,struct electrum_info *ep,cJSON **retjsonp) { return(electrum_noargs(symbol,ep,retjsonp,"server.version",ELECTRUM_TIMEOUT)); }
cJSON *electrum_banner(char *symbol,struct electrum_info *ep,cJSON **retjsonp) { return(electrum_noargs(symbol,ep,retjsonp,"server.banner",ELECTRUM_TIMEOUT)); }
cJSON *electrum_donation(char *symbol,struct electrum_info *ep,cJSON **retjsonp) { return(electrum_noargs(symbol,ep,retjsonp,"server.donation_address",ELECTRUM_TIMEOUT)); }
cJSON *electrum_peers(char *symbol,struct electrum_info *ep,cJSON **retjsonp) { return(electrum_noargs(symbol,ep,retjsonp,"server.peers.subscribe",ELECTRUM_TIMEOUT)); }
cJSON *electrum_features(char *symbol,struct electrum_info *ep,cJSON **retjsonp) { return(electrum_noargs(symbol,ep,retjsonp,"server.features",ELECTRUM_TIMEOUT)); }
cJSON *electrum_headers_subscribe(char *symbol,struct electrum_info *ep,cJSON **retjsonp) { return(electrum_noargs(symbol,ep,retjsonp,"blockchain.headers.subscribe",ELECTRUM_TIMEOUT)); }

cJSON *electrum_script_getbalance(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *script) { return(electrum_strarg(symbol,ep,retjsonp,"blockchain.scripthash.get_balance",script,ELECTRUM_TIMEOUT)); }
cJSON *electrum_script_gethistory(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *script) { return(electrum_strarg(symbol,ep,retjsonp,"blockchain.scripthash.get_history",script,ELECTRUM_TIMEOUT)); }
cJSON *electrum_script_getmempool(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *script) { return(electrum_strarg(symbol,ep,retjsonp,"blockchain.scripthash.get_mempool",script,ELECTRUM_TIMEOUT)); }
cJSON *electrum_script_listunspent(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *script) { return(electrum_strarg(symbol,ep,retjsonp,"blockchain.scripthash.listunspent",script,ELECTRUM_TIMEOUT)); }
cJSON *electrum_script_subscribe(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *script) { return(electrum_strarg(symbol,ep,retjsonp,"blockchain.scripthash.subscribe",script,ELECTRUM_TIMEOUT)); }

cJSON *electrum_address_subscribe(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *addr) { return(electrum_strarg(symbol,ep,retjsonp,"blockchain.address.subscribe",addr,ELECTRUM_TIMEOUT)); }
cJSON *electrum_address_gethistory(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *addr) { return(electrum_strarg(symbol,ep,retjsonp,"blockchain.address.get_history",addr,ELECTRUM_TIMEOUT)); }
cJSON *electrum_address_getmempool(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *addr) { return(electrum_strarg(symbol,ep,retjsonp,"blockchain.address.get_mempool",addr,ELECTRUM_TIMEOUT)); }
cJSON *electrum_address_getbalance(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *addr) { return(electrum_strarg(symbol,ep,retjsonp,"blockchain.address.get_balance",addr,ELECTRUM_TIMEOUT)); }
cJSON *electrum_address_listunspent(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *addr) { return(electrum_strarg(symbol,ep,retjsonp,"blockchain.address.listunspent",addr,ELECTRUM_TIMEOUT)); }

cJSON *electrum_addpeer(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *endpoint) { return(electrum_strarg(symbol,ep,retjsonp,"server.add_peer",endpoint,ELECTRUM_TIMEOUT)); }
cJSON *electrum_sendrawtransaction(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *rawtx) { return(electrum_strarg(symbol,ep,retjsonp,"blockchain.transaction.broadcast",rawtx,ELECTRUM_TIMEOUT)); }

cJSON *electrum_estimatefee(char *symbol,struct electrum_info *ep,cJSON **retjsonp,int32_t numblocks) { return(electrum_intarg(symbol,ep,retjsonp,"blockchain.estimatefee",numblocks,ELECTRUM_TIMEOUT)); }
cJSON *electrum_getheader(char *symbol,struct electrum_info *ep,cJSON **retjsonp,int32_t n) { return(electrum_intarg(symbol,ep,retjsonp,"blockchain.block.get_header",n,ELECTRUM_TIMEOUT)); }
cJSON *electrum_getchunk(char *symbol,struct electrum_info *ep,cJSON **retjsonp,int32_t n) { return(electrum_intarg(symbol,ep,retjsonp,"blockchain.block.get_chunk",n,ELECTRUM_TIMEOUT)); }
cJSON *electrum_transaction(char *symbol,struct electrum_info *ep,cJSON **retjsonp,bits256 txid) { return(electrum_hasharg(symbol,ep,retjsonp,"blockchain.transaction.get",txid,ELECTRUM_TIMEOUT)); }

cJSON *electrum_getmerkle(char *symbol,struct electrum_info *ep,cJSON **retjsonp,bits256 txid,int32_t height)
{
    char params[128],str[65];
    sprintf(params,"[\"%s\", %d]",bits256_str(str,txid),height);
    return(electrum_submit(symbol,ep,retjsonp,"blockchain.transaction.get_merkle",params,ELECTRUM_TIMEOUT));
}

void electrum_test()
{
    cJSON *retjson; bits256 hash; struct electrum_info *ep = 0; char *addr,*script,*symbol = "BTC";
    while ( Num_electrums == 0 )
    {
        sleep(1);
        printf("Num_electrums %p -> %d\n",&Num_electrums,Num_electrums);
    }
    printf("found electrum server\n");
    if ( (retjson= electrum_version(symbol,ep,0)) != 0 )
        printf("electrum_version %s\n",jprint(retjson,1));
    if ( (retjson= electrum_banner(symbol,ep,0)) != 0 )
        printf("electrum_banner %s\n",jprint(retjson,1));
    if ( (retjson= electrum_donation(symbol,ep,0)) != 0 )
        printf("electrum_donation %s\n",jprint(retjson,1));
    if ( (retjson= electrum_features(symbol,ep,0)) != 0 )
        printf("electrum_features %s\n",jprint(retjson,1));
    if ( (retjson= electrum_estimatefee(symbol,ep,0,6)) != 0 )
        printf("electrum_estimatefee %s\n",jprint(retjson,1));
    decode_hex(hash.bytes,sizeof(hash),"0000000000000000005087f8845f9ed0282559017e3c6344106de15e46c07acd");
    if ( (retjson= electrum_getheader(symbol,ep,0,3)) != 0 )
        printf("electrum_getheader %s\n",jprint(retjson,1));
    //if ( (retjson= electrum_getchunk(symbol,ep,0,3)) != 0 )
    //    printf("electrum_getchunk %s\n",jprint(retjson,1));
    decode_hex(hash.bytes,sizeof(hash),"b967a7d55889fe11e993430921574ec6379bc8ce712a652c3fcb66c6be6e925c");
    if ( (retjson= electrum_getmerkle(symbol,ep,0,hash,403000)) != 0 )
        printf("electrum_getmerkle %s\n",jprint(retjson,1));
    if ( (retjson= electrum_transaction(symbol,ep,0,hash)) != 0 )
        printf("electrum_transaction %s\n",jprint(retjson,1));
    addr = "14NeevLME8UAANiTCVNgvDrynUPk1VcQKb";
    if ( (retjson= electrum_address_gethistory(symbol,ep,0,addr)) != 0 )
        printf("electrum_address_gethistory %s\n",jprint(retjson,1));
    if ( (retjson= electrum_address_getmempool(symbol,ep,0,addr)) != 0 )
        printf("electrum_address_getmempool %s\n",jprint(retjson,1));
    if ( (retjson= electrum_address_getbalance(symbol,ep,0,addr)) != 0 )
        printf("electrum_address_getbalance %s\n",jprint(retjson,1));
    if ( (retjson= electrum_address_listunspent(symbol,ep,0,addr)) != 0 )
        printf("electrum_address_listunspent %s\n",jprint(retjson,1));
    if ( (retjson= electrum_addpeer(symbol,ep,0,"electrum.be:50001")) != 0 )
        printf("electrum_addpeer %s\n",jprint(retjson,1));
    if ( (retjson= electrum_sendrawtransaction(symbol,ep,0,"0100000001b7e6d69a0fd650926bd5fbe63cc8578d976c25dbdda8dd61db5e05b0de4041fe000000006b483045022100de3ae8f43a2a026bb46f6b09b890861f8aadcb16821f0b01126d70fa9ae134e4022000925a842073484f1056c7fc97399f2bbddb9beb9e49aca76835cdf6e9c91ef3012103cf5ce3233e6d6e22291ebef454edff2b37a714aed685ce94a7eb4f83d8e4254dffffffff014c4eaa0b000000001976a914b598062b55362952720718e7da584a46a27bedee88ac00000000")) != 0 )
        printf("electrum_sendrawtransaction %s\n",jprint(retjson,1));
 
    if ( 0 )
    {
        script = "76a914b598062b55362952720718e7da584a46a27bedee88ac";
        if ( (retjson= electrum_script_gethistory(symbol,ep,0,script)) != 0 )
            printf("electrum_script_gethistory %s\n",jprint(retjson,1));
        if ( (retjson= electrum_script_getmempool(symbol,ep,0,script)) != 0 )
            printf("electrum_script_getmempool %s\n",jprint(retjson,1));
        if ( (retjson= electrum_script_getbalance(symbol,ep,0,script)) != 0 )
            printf("electrum_script_getbalance %s\n",jprint(retjson,1));
        if ( (retjson= electrum_script_listunspent(symbol,ep,0,script)) != 0 )
            printf("electrum_script_listunspent %s\n",jprint(retjson,1));
        if ( (retjson= electrum_script_subscribe(symbol,ep,0,script)) != 0 )
            printf("electrum_script_subscribe %s\n",jprint(retjson,1));
    }
    if ( (retjson= electrum_headers_subscribe(symbol,ep,0)) != 0 )
        printf("electrum_headers %s\n",jprint(retjson,1));
    if ( (retjson= electrum_peers(symbol,ep,0)) != 0 )
        printf("electrum_peers %s\n",jprint(retjson,1));
    if ( (retjson= electrum_address_subscribe(symbol,ep,0,addr)) != 0 )
        printf("electrum_address_subscribe %s\n",jprint(retjson,1));
}
