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
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(void *)&timeout,sizeof(timeout));
        result = connect(sock,(struct sockaddr *)&saddr,addrlen);
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
        timeout.tv_sec = 10000000;
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

int32_t LP_electrum_maxlen; void *LP_electrum_buf;

void LP_dedicatedloop(int32_t (*recvfunc)(char *ipaddr,char *str,int32_t len),char **sendstrp,char *ipaddr,uint16_t port)
{
    struct pollfd fds; uint8_t *buf; char *str; int32_t len,sock,bufsize,flag,timeout = 10;
    LP_electrum_maxlen = bufsize = IGUANA_MAXPACKETSIZE * 2;
    LP_electrum_buf = buf = malloc(bufsize);
    sock = LP_socket(0,ipaddr,port);
    while ( sock >= 0 )
    {
        flag = 0;
        memset(&fds,0,sizeof(fds));
        fds.fd = sock;
        fds.events |= (POLLOUT | POLLIN);
        if (  poll(&fds,1,timeout) > 0 && (fds.revents & POLLOUT) != 0 && (str= *sendstrp) != 0 )
        {
            *sendstrp = 0;
            //printf("sending.(%s)\n",str);
            if ( LP_socketsend(sock,(uint8_t *)str,(int32_t)strlen(str)) <= 0 )
            {
                printf("%s:%u is dead\n",ipaddr,port);
                closesocket(sock);
                sock = -1;
                break;
            }
            flag++;
        }
        if ( flag == 0 )
        {
            if ( (fds.revents & POLLIN) != 0 )
            {
                if ( (len= LP_socketrecv(sock,buf,bufsize)) > 0 )
                {
                    (*recvfunc)(ipaddr,(char *)buf,len);
                    flag++;
                }
            }
            if ( flag == 0 )
                usleep(100000);
        }
    }
    free(buf);
}

// create new electrum server connection, add to list of electrum servers, sendstr, Q, etc.

int32_t LP_recvfunc(char *ipaddr,char *str,int32_t len)
{
    printf("RECV.(%s) from %s\n",str,ipaddr);
    // get callback for id and callback
    return(0);
}

cJSON *electrum_submit(char *method,char *params,int32_t timeout)
{
    static uint32_t stratumid;
    // queue id and string and callback
    char stratumreq[16384];
    while ( LP_sendstr != 0 )
        usleep(10000);
    ((char *)LP_electrum_buf)[0] = 0;
    sprintf(stratumreq,"{ \"jsonrpc\":\"2.0\", \"id\": %u, \"method\":\"%s\", \"params\": %s }\n",stratumid++,method,params);
    LP_sendstr = stratumreq;
    while ( LP_sendstr != 0 )
        usleep(10000);
    if ( ((char *)LP_electrum_buf)[0] != 0 )
        return(cJSON_Parse(LP_electrum_buf));
    else return(0);
}

cJSON *electrum_noargs(char *method,int32_t timeout)
{
    return(electrum_submit(method,"[]",timeout));
}

cJSON *electrum_strarg(char *method,char *arg,int32_t timeout)
{
    char params[16384];
    if ( strlen(arg) < sizeof(params) )
    {
        sprintf(params,"[\"%s\"]",arg);
        return(electrum_submit(method,params,timeout));
    } else return(0);
}

cJSON *electrum_intarg(char *method,int32_t arg,int32_t timeout)
{
    char params[64];
    sprintf(params,"[\"%d\"]",arg);
    return(electrum_submit(method,params,timeout));
}

cJSON *electrum_hasharg(char *method,bits256 arg,int32_t timeout)
{
    char params[128],str[65];
    sprintf(params,"[\"%s\"]",bits256_str(str,arg));
    return(electrum_submit(method,params,timeout));
}

#define ELECTRUM_TIMEOUT 2
//" "--blockchain.numblocks.subscribe", "--blockchain.address.get_proof", "--blockchain.utxo.get_address",

cJSON *electrum_version() { return(electrum_noargs("server.version",ELECTRUM_TIMEOUT)); }
cJSON *electrum_banner() { return(electrum_noargs("server.banner",ELECTRUM_TIMEOUT)); }
cJSON *electrum_donation() { return(electrum_noargs("server.donation_address",ELECTRUM_TIMEOUT)); }
cJSON *electrum_peers() { return(electrum_noargs("server.peers.subscribe",ELECTRUM_TIMEOUT)); }
cJSON *electrum_features() { return(electrum_noargs("server.features",ELECTRUM_TIMEOUT)); }
cJSON *electrum_headers() { return(electrum_noargs("blockchain.headers.subscribe",ELECTRUM_TIMEOUT)); }

cJSON *electrum_script_getbalance(char *script) { return(electrum_strarg("blockchain.scripthash.get_balance",script,ELECTRUM_TIMEOUT)); }
cJSON *electrum_script_gethistory(char *script) { return(electrum_strarg("blockchain.scripthash.get_history",script,ELECTRUM_TIMEOUT)); }
cJSON *electrum_script_getmempool(char *script) { return(electrum_strarg("blockchain.scripthash.get_mempool",script,ELECTRUM_TIMEOUT)); }
cJSON *electrum_script_listunspent(char *script) { return(electrum_strarg("blockchain.scripthash.listunspent",script,ELECTRUM_TIMEOUT)); }
cJSON *electrum_script_subscribe(char *script) { return(electrum_strarg("blockchain.scripthash.subscribe",script,ELECTRUM_TIMEOUT)); }

cJSON *electrum_address_subscribe(char *addr) { return(electrum_strarg("blockchain.address.subscribe",addr,ELECTRUM_TIMEOUT)); }
cJSON *electrum_address_gethistory(char *addr) { return(electrum_strarg("blockchain.address.get_history",addr,ELECTRUM_TIMEOUT)); }
cJSON *electrum_address_getmempool(char *addr) { return(electrum_strarg("blockchain.address.get_mempool",addr,ELECTRUM_TIMEOUT)); }
cJSON *electrum_address_getbalance(char *addr) { return(electrum_strarg("blockchain.address.get_balance",addr,ELECTRUM_TIMEOUT)); }
cJSON *electrum_address_listunspent(char *addr) { return(electrum_strarg("blockchain.address.listunspent",addr,ELECTRUM_TIMEOUT)); }

cJSON *electrum_addpeer(char *endpoint) { return(electrum_strarg("server.add_peer",endpoint,ELECTRUM_TIMEOUT)); }
cJSON *electrum_sendrawtransaction(char *rawtx) { return(electrum_strarg("blockchain.transaction.broadcast",rawtx,ELECTRUM_TIMEOUT)); }

cJSON *electrum_estimatefee(int32_t numblocks) { return(electrum_intarg("blockchain.estimatefee",numblocks,ELECTRUM_TIMEOUT)); }
cJSON *electrum_getheader(bits256 blockhash) { return(electrum_hasharg("blockchain.block.get_header",blockhash,ELECTRUM_TIMEOUT)); }
cJSON *electrum_getchunk(bits256 blockhash) { return(electrum_hasharg("blockchain.block.get_chunk",blockhash,ELECTRUM_TIMEOUT)); }
cJSON *electrum_getmerkle(bits256 txid) { return(electrum_hasharg("blockchain.transaction.get_merkle",txid,ELECTRUM_TIMEOUT)); }
cJSON *electrum_transaction(bits256 txid) { return(electrum_hasharg("blockchain.transaction.get",txid,ELECTRUM_TIMEOUT)); }

void electrum_test()
{
    cJSON *retjson; bits256 hash; char *addr,*script;
    if ( (retjson= electrum_version()) != 0 )
        printf("electrum_version %s\n",jprint(retjson,1));
    if ( (retjson= electrum_banner()) != 0 )
        printf("electrum_banner %s\n",jprint(retjson,1));
    if ( (retjson= electrum_donation()) != 0 )
        printf("electrum_donation %s\n",jprint(retjson,1));
    if ( (retjson= electrum_peers()) != 0 )
        printf("electrum_peers %s\n",jprint(retjson,1));
    if ( (retjson= electrum_features()) != 0 )
        printf("electrum_features %s\n",jprint(retjson,1));
    if ( (retjson= electrum_headers()) != 0 )
        printf("electrum_headers %s\n",jprint(retjson,1));
    if ( (retjson= electrum_estimatefee(6)) != 0 )
        printf("electrum_estimatefee %s\n",jprint(retjson,1));
    decode_hex(hash.bytes,sizeof(hash),"0000000000000000005087f8845f9ed0282559017e3c6344106de15e46c07acd");
    if ( (retjson= electrum_getheader(hash)) != 0 )
        printf("electrum_getheader %s\n",jprint(retjson,1));
    if ( (retjson= electrum_getchunk(hash)) != 0 )
        printf("electrum_getchunk %s\n",jprint(retjson,1));
    decode_hex(hash.bytes,sizeof(hash),"b967a7d55889fe11e993430921574ec6379bc8ce712a652c3fcb66c6be6e925c");
    if ( (retjson= electrum_getmerkle(hash)) != 0 )
        printf("electrum_getmerkle %s\n",jprint(retjson,1));
    if ( (retjson= electrum_transaction(hash)) != 0 )
        printf("electrum_transaction %s\n",jprint(retjson,1));
    addr = "14NeevLME8UAANiTCVNgvDrynUPk1VcQKb";
    //if ( (retjson= electrum_address_subscribe(addr)) != 0 )
    //    printf("electrum_address_subscribe %s\n",jprint(retjson,1));
    if ( (retjson= electrum_address_gethistory(addr)) != 0 )
        printf("electrum_address_gethistory %s\n",jprint(retjson,1));
    if ( (retjson= electrum_address_getmempool(addr)) != 0 )
        printf("electrum_address_getmempool %s\n",jprint(retjson,1));
    if ( (retjson= electrum_address_getbalance(addr)) != 0 )
        printf("electrum_address_getbalance %s\n",jprint(retjson,1));
    if ( (retjson= electrum_address_listunspent(addr)) != 0 )
        printf("electrum_address_listunspent %s\n",jprint(retjson,1));
    script = "76a914b598062b55362952720718e7da584a46a27bedee88ac";
    //if ( (retjson= electrum_script_subscribe(script)) != 0 )
    //    printf("electrum_script_subscribe %s\n",jprint(retjson,1));
    if ( (retjson= electrum_script_gethistory(script)) != 0 )
        printf("electrum_script_gethistory %s\n",jprint(retjson,1));
    if ( (retjson= electrum_script_getmempool(script)) != 0 )
        printf("electrum_script_getmempool %s\n",jprint(retjson,1));
    if ( (retjson= electrum_script_getbalance(script)) != 0 )
        printf("electrum_script_getbalance %s\n",jprint(retjson,1));
    if ( (retjson= electrum_script_listunspent(script)) != 0 )
        printf("electrum_script_listunspent %s\n",jprint(retjson,1));

    if ( (retjson= electrum_addpeer("electrum.be")) != 0 )
        printf("electrum_addpeer %s\n",jprint(retjson,1));
    if ( (retjson= electrum_sendrawtransaction("0100000001b7e6d69a0fd650926bd5fbe63cc8578d976c25dbdda8dd61db5e05b0de4041fe000000006b483045022100de3ae8f43a2a026bb46f6b09b890861f8aadcb16821f0b01126d70fa9ae134e4022000925a842073484f1056c7fc97399f2bbddb9beb9e49aca76835cdf6e9c91ef3012103cf5ce3233e6d6e22291ebef454edff2b37a714aed685ce94a7eb4f83d8e4254dffffffff014c4eaa0b000000001976a914b598062b55362952720718e7da584a46a27bedee88ac00000000")) != 0 )
        printf("electrum_sendrawtransaction %s\n",jprint(retjson,1));
}
