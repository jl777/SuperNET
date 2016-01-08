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

#define CHROMEAPP_NAME SuperNET
#define CHROMEAPP_STR "SuperNET"
#define CHROMEAPP_CONF "SuperNET.conf"
#define CHROMEAPP_MAIN SuperNET_main
#define CHROMEAPP_JSON SuperNET_JSON
#define CHROMEAPP_HANDLER Handler_SuperNET

#include "../pnacl_main.h"
#include "SuperNET.h"

// ALL globals must be here!
int32_t PULLsock;


int32_t badass_servers(char servers[][MAX_SERVERNAME],int32_t max,int32_t port)
{
    int32_t n = 0;
    strcpy(servers[n++],"89.248.160.237");
    strcpy(servers[n++],"89.248.160.238");
    strcpy(servers[n++],"89.248.160.239");
    strcpy(servers[n++],"89.248.160.240");
    strcpy(servers[n++],"89.248.160.241");
    strcpy(servers[n++],"89.248.160.242");
    //strcpy(servers[n++],"89.248.160.243");
    //strcpy(servers[n++],"89.248.160.244");
    //strcpy(servers[n++],"89.248.160.245");
    return(n);
}

int32_t crackfoo_servers(char servers[][MAX_SERVERNAME],int32_t max,int32_t port)
{
    int32_t n = 0;
    /*strcpy(servers[n++],"192.99.151.160");
     strcpy(servers[n++],"167.114.96.223");
     strcpy(servers[n++],"167.114.113.197");
     strcpy(servers[n++],"5.9.105.170");
     strcpy(servers[n++],"136.243.5.70");
     strcpy(servers[n++],"5.9.155.145");*/
    if ( 1 )
    {
        strcpy(servers[n++],"167.114.96.223");
        strcpy(servers[n++],"167.114.113.25");
        strcpy(servers[n++],"167.114.113.27");
        strcpy(servers[n++],"167.114.113.194");
        strcpy(servers[n++],"167.114.113.197");
        strcpy(servers[n++],"167.114.113.201");
        strcpy(servers[n++],"167.114.113.246");
        strcpy(servers[n++],"167.114.113.249");
        strcpy(servers[n++],"167.114.113.250");
        strcpy(servers[n++],"192.99.151.160");
        strcpy(servers[n++],"167.114.96.222");
    }
    return(n);
}

int32_t iguana_socket(int32_t bindflag,char *hostname,uint16_t port)
{
    int32_t opt,sock,result; uint32_t ipbits; char ipaddr[64]; struct timeval timeout;
    struct sockaddr_in saddr; socklen_t addrlen;
    addrlen = sizeof(saddr);
    struct hostent *hostent = gethostbyname(hostname);
    if ( hostent == NULL )
    {
        printf("gethostbyname() returned error: %d",errno);
        return(-1);
    }
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    memcpy(&saddr.sin_addr.s_addr,hostent->h_addr_list[0],hostent->h_length);
    ipbits = (uint32_t)calc_ipbits(hostname);
    //printf("ipbits.%08x vs %08x\n",ipbits,saddr.sin_addr.s_addr);
    expand_ipbits(ipaddr,saddr.sin_addr.s_addr);
    //if ( bindflag != 0 )
    //    printf("iguana_socket.(%s:%d) bind.%d\n",ipaddr,port,bindflag), getchar();
    if ( strcmp(ipaddr,hostname) != 0 )
        printf("iguana_socket mismatch (%s) -> (%s)?\n",hostname,ipaddr);
    if ( (sock= socket(AF_INET,SOCK_STREAM,0)) < 0 )
    {
        if ( errno != ETIMEDOUT )
            printf("socket() failed: %s errno.%d", strerror(errno),errno);
        return(-1);
    }
    if ( 0 && bindflag != 0 )
    {
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout));
    }
    opt = 1;
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(void*)&opt,sizeof(opt));
#ifdef __APPLE__
    setsockopt(sock,SOL_SOCKET,SO_NOSIGPIPE,&opt,sizeof(opt));
#endif
    result = (bindflag != 0) ? bind(sock,(struct sockaddr*)&saddr,addrlen) : connect(sock,(struct sockaddr *)&saddr,addrlen);
    if ( result != 0 )
    {
        if ( errno != ECONNRESET && errno != ENOTCONN && errno != ECONNREFUSED && errno != ETIMEDOUT && errno != EHOSTUNREACH )
            printf("connect(%s) port.%d failed: %s sock.%d. errno.%d\n",hostname,port,strerror(errno),sock,errno);
        if ( sock >= 0 )
            close(sock);
        return(-1);
    }
    if ( bindflag != 0 && listen(sock,3) != 0 )
    {
        printf("listen(%s) port.%d failed: %s sock.%d. errno.%d\n",hostname,port,strerror(errno),sock,errno);
        if ( sock >= 0 )
            close(sock);
        return(-1);
    }
    return(sock);
}

/*void iguana_parsebuf(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msghdr *H,uint8_t *buf,int32_t len)
{
    struct iguana_msghdr checkH;
    memset(&checkH,0,sizeof(checkH));
    iguana_sethdr(&checkH,coin->chain->netmagic,H->command,buf,len);
    if ( memcmp(&checkH,H,sizeof(checkH)) == 0 )
    {
        //if ( strcmp(addr->ipaddr,"127.0.0.1") == 0 )
        //printf("%s parse.(%s) len.%d\n",addr->ipaddr,H.command,len);
        //printf("addr->dead.%u\n",addr->dead);
        if ( strcmp(H->command,"block") == 0 || strcmp(H->command,"tx") == 0 )
        {
            if ( addr->RAWMEM.ptr == 0 )
                iguana_meminit(&addr->RAWMEM,addr->ipaddr,0,IGUANA_MAXPACKETSIZE,0);
            if ( addr->TXDATA.ptr == 0 )
                iguana_meminit(&addr->TXDATA,"txdata",0,IGUANA_MAXPACKETSIZE,0);
            if ( addr->HASHMEM.ptr == 0 )
                iguana_meminit(&addr->HASHMEM,"HASHPTRS",0,256,0);//IGUANA_MAXPACKETSIZE*16,0);
            //printf("Init %s memory %p %p %p\n",addr->ipaddr,addr->RAWMEM.ptr,addr->TXDATA.ptr,addr->HASHMEM.ptr);
        }
        if ( iguana_parser(coin,addr,&addr->RAWMEM,&addr->TXDATA,&addr->HASHMEM,H,buf,len) < 0 || addr->dead != 0 )
        {
            printf("%p addr->dead.%d or parser break at %u\n",&addr->dead,addr->dead,(uint32_t)time(NULL));
            addr->dead = (uint32_t)time(NULL);
        }
        else
        {
            addr->numpackets++;
            addr->totalrecv += len;
            coin->totalrecv += len, coin->totalpackets++;
            //printf("next iter.(%s) numreferrals.%d numpings.%d\n",addr->ipaddr,addr->numreferrals,addr->numpings);
        }
    } else printf("header error from %s\n",addr->ipaddr);
}*/


int32_t SuperNET_recv(int32_t sock,uint8_t *recvbuf,int32_t len)
{
    int32_t recvlen,remains = len;
    while ( remains > 0 )
    {
        if ( (recvlen= (int32_t)recv(sock,recvbuf,remains,0)) < 0 )
        {
            if ( errno == EAGAIN )
            {
                //printf("EAGAIN for len %d, remains.%d\n",len,remains);
                usleep(10000);
            }
            else return(-errno);
        }
        else
        {
            if ( recvlen > 0 )
            {
                remains -= recvlen;
                recvbuf = &recvbuf[recvlen];
            } else usleep(10000);
        }
    }
    return(len);
}

int32_t SuperNET_recvmsg(char *ipaddr,int32_t sock,uint8_t *_buf,int32_t maxlen)
{
    int32_t len,recvlen; void *buf = _buf; struct iguana_msghdr H;
    printf("got.(%s) from %s | sock.%d\n",H.command,ipaddr,sock);
    memset(&H,0,sizeof(H));
    if ( (recvlen= (int32_t)SuperNET_recv(sock,(uint8_t *)&H,sizeof(H))) == sizeof(H) )
    {
        //printf("%p got.(%s) recvlen.%d from %s | usock.%d ready.%u dead.%u\n",addr,H.command,recvlen,addr->ipaddr,addr->usock,addr->ready,addr->dead);
        if ( (len= iguana_validatehdr(&H)) >= 0 )
        {
            if ( len > 0 )
            {
                if ( len > IGUANA_MAXPACKETSIZE )
                {
                    printf("buffer %d too small for %d\n",IGUANA_MAXPACKETSIZE,len);
                    return(-1);;
                }
                if ( len > maxlen )
                    buf = calloc(1,len);
                if ( (recvlen= SuperNET_recv(sock,buf,len)) < 0 )
                {
                    printf("recv error on (%s) len.%d errno.%d (%s)\n",H.command,len,-recvlen,strerror(-recvlen));
                    if ( buf != _buf )
                        free(buf);
                    //addr->dead = (uint32_t)time(NULL);
                    return(recvlen);
                }
            }
            //iguana_parsebuf(coin,addr,&H,buf,len);
            if ( buf != _buf )
                free(buf);
            return(recvlen);
        }
        printf("invalid header received from (%s)\n",ipaddr);
    }
    printf("%s recv error on hdr errno.%d (%s)\n",ipaddr,-recvlen,strerror(-recvlen));
    return(-1);
}

struct supernet_accept { struct queueitem DL; char ipaddr[64]; uint32_t ipbits; int32_t sock; uint16_t port; } Accepts[SUPERNET_MAXPEERS];
queue_t AcceptQ;

int32_t Supernet_poll(uint8_t *buf,int32_t bufsize,struct supernet_accept *accepts,int32_t num,int32_t timeout)
{
    struct pollfd fds[SUPERNET_MAXPEERS]; int32_t i,j,n,r,nonz,flag; struct supernet_accept *ptr;
    if ( num == 0 )
        return(0);;
    memset(fds,0,sizeof(fds));
    flag = 0;
    r = (rand() % num);
    for (j=n=nonz=0; j<num&&j<sizeof(fds)/sizeof(*fds)-1; j++)
    {
        i = (j + r) % num;
        ptr = &accepts[i];
        fds[i].fd = -1;
        if ( ptr->sock >= 0 )
        {
            fds[i].fd = ptr->sock;
            fds[i].events = (POLLIN | POLLOUT);
            nonz++;
        }
    }
    if ( nonz != 0 && poll(fds,num,timeout) > 0 )
    {
        for (j=0; j<num; j++)
        {
            i = (j + r) % num;
            ptr = &accepts[i];
            if ( ptr->sock < 0 )
                continue;
            if ( (fds[i].revents & POLLIN) != 0 )
            {
                return(SuperNET_recvmsg(ptr->ipaddr,ptr->sock,buf,bufsize));
            }
            if ( (fds[i].revents & POLLOUT) != 0 )
            {
                //if ( iguana_pollsendQ(coin,addr) == 0 )
                //    flag += iguana_poll(coin,addr);
                //else flag++;
            }
        }
    }
    return(0);
}

void SuperNET_acceptloop(void *args)
{
    int32_t bindsock,sock; struct supernet_accept *ptr; struct supernet_info *myinfo = args;
    socklen_t clilen; struct sockaddr_in cli_addr; char ipaddr[64]; uint32_t ipbits;
    bindsock = iguana_socket(1,"127.0.0.1",myinfo->portp2p);
    printf("iguana_bindloop 127.0.0.1:%d bind sock.%d\n",myinfo->portp2p,bindsock);
    while ( bindsock >= 0 )
    {
        clilen = sizeof(cli_addr);
        printf("ACCEPT (%s:%d) on sock.%d\n","127.0.0.1",myinfo->portp2p,bindsock);
        sock = accept(bindsock,(struct sockaddr *)&cli_addr,&clilen);
        if ( sock < 0 )
        {
            printf("ERROR on accept bindsock.%d errno.%d (%s)\n",bindsock,errno,strerror(errno));
            continue;
        }
        memcpy(&ipbits,&cli_addr.sin_addr.s_addr,sizeof(ipbits));
        expand_ipbits(ipaddr,ipbits);
        printf("NEWSOCK.%d for %x (%s)\n",sock,ipbits,ipaddr);
        ptr = calloc(1,sizeof(*ptr));
        strcpy(ptr->ipaddr,ipaddr);
        ptr->ipbits = ipbits;
        ptr->sock = sock;
        ptr->port = myinfo->portp2p;
        queue_enqueue("acceptQ",&AcceptQ,&ptr->DL,0);
    }
}

int32_t SuperNET_acceptport(struct supernet_info *myinfo,uint16_t port)
{
    struct supernet_info *ptr;
    ptr = calloc(1,sizeof(*myinfo));
    *ptr = *myinfo;
    ptr->portp2p = port;
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)SuperNET_acceptloop,(void *)ptr) != 0 )
    {
        printf("error launching accept thread for port.%u\n",port);
        return(-1);
    }
    return(0);
}

void SuperNET_main(void *arg)
{
    struct supernet_info MYINFO; struct supernet_accept *ptr; char buf[8192];
    cJSON *json,*array; uint16_t port; int32_t i,n = 0;
    memset(&MYINFO,0,sizeof(MYINFO));
    if ( 0 )
    {
        strcpy(MYINFO.transport,"tcp");
        strcpy(MYINFO.ipaddr,"127.0.0.1");
        MYINFO.port = SUPERNET_PORT; MYINFO.serviceport = SUPERNET_PORT - 2;
        SuperNET_init(&MYINFO,arg);
    }
    if ( arg == 0 || (json= cJSON_Parse(arg)) == 0 )
        SuperNET_acceptport(&MYINFO,14631);
    else
    {
        if ( (array= jarray(&n,json,"accept")) != 0 )
        {
            for (i=0; i<n; i++)
                if ( (port= juint(jitem(array,i),0)) != 0 )
                    SuperNET_acceptport(&MYINFO,port);
        }
        free_json(json);
    }
    sleep(3);
    printf("start SuperNET_loop\n");
    while ( MYINFO.dead == 0 )
    {
        //if ( busdata_poll(&MYINFO) == 0 && MYINFO.APISLEEP > 0 )
        //    usleep(MYINFO.APISLEEP * 1000);
        if ( (ptr= queue_dequeue(&AcceptQ,0)) != 0 )
        {
            if ( n < sizeof(Accepts)/sizeof(*Accepts)-1 )
            {
                Accepts[n++] = *ptr;
                free(ptr);
            }
            PostMessage("SuperNET.[%d] got new socket %d for %s:%d\n",n,ptr->sock,ptr->ipaddr,ptr->port);
        }
        if ( n > 0 )
            Supernet_poll(buf,sizeof(buf),Accepts,n,7);
        sleep(1);
    }
}
