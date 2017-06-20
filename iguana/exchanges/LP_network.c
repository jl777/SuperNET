
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
//
//  LP_network.c
//  marketmaker
//

#define PSOCK_IDLETIMEOUT (2 * INSTANTDEX_LOCKTIME + 600)
struct psock
{
    uint32_t lasttime,lastping;
    int32_t recvsock,sendsock,ispaired;
    uint16_t recvport,sendport;
    char sendaddr[128],publicaddr[128];
} *PSOCKS;

uint16_t Numpsocks,Psockport = 10000;

char *nanomsg_transportname(int32_t bindflag,char *str,char *ipaddr,uint16_t port)
{
    sprintf(str,"tcp://%s:%u",bindflag == 0 ? ipaddr : "*",port);
    return(str);
}

int32_t LP_send(int32_t sock,char *msg,int32_t freeflag)
{
    int32_t sentbytes,len,i; struct nn_pollfd pfd;
    if ( sock < 0 )
    {
        printf("LP_send.(%s) to illegal socket\n",msg);
        if ( freeflag != 0 )
            free(msg);
        return(-1);
    }
    len = (int32_t)strlen(msg) + 1;
    for (i=0; i<1000; i++)
    {
        pfd.fd = sock;
        pfd.events = NN_POLLOUT;
        //portable_mutex_lock(&LP_networkmutex);
        if ( nn_poll(&pfd,1,1) > 0 )
        {
            if ( (sentbytes= nn_send(sock,msg,len,0)) != len )
                printf("LP_send sent %d instead of %d\n",sentbytes,len);
            //else printf("SENT.(%s)\n",msg);
            if ( freeflag != 0 )
                free(msg);
            //portable_mutex_unlock(&LP_networkmutex);
            return(sentbytes);
        }
        //portable_mutex_unlock(&LP_networkmutex);
        usleep(1000);
    }
    printf("error LP_send sock.%d, i.%d timeout.(%s) %s\n",sock,i,msg,nn_strerror(nn_errno()));
    //if ( (sentbytes= nn_send(sock,msg,len,0)) != len )
    //   printf("LP_send sent %d instead of %d\n",sentbytes,len);
    if ( freeflag != 0 )
        free(msg);
    return(-1);
}

uint32_t LP_swapsend(int32_t pairsock,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t nextbits,uint32_t crcs[2])
{
    uint8_t *buf; int32_t sentbytes,offset=0,i;
    buf = malloc(datalen + sizeof(msgbits) + sizeof(swap->I.req.quoteid) + sizeof(bits256)*2);
    for (i=0; i<32; i++)
        buf[offset++] = swap->I.myhash.bytes[i];
    for (i=0; i<32; i++)
        buf[offset++] = swap->I.otherhash.bytes[i];
    offset += iguana_rwnum(1,&buf[offset],sizeof(swap->I.req.quoteid),&swap->I.req.quoteid);
    offset += iguana_rwnum(1,&buf[offset],sizeof(msgbits),&msgbits);
    if ( datalen > 0 )
        memcpy(&buf[offset],data,datalen), offset += datalen;
    if ( (sentbytes= nn_send(pairsock,buf,offset,0)) != offset )
    {
        printf("sentbytes.%d vs offset.%d\n",sentbytes,offset);
        if ( sentbytes < 0 )
        {
        }
    }
    //printf("sent %d bytes\n",sentbytes);
    //else printf("send.[%d] %x offset.%d datalen.%d [%llx]\n",sentbytes,msgbits,offset,datalen,*(long long *)data);
    free(buf);
    return(nextbits);
}

void LP_psockloop(void *_ptr)
{
    int32_t i,n,nonz,iter,retval,size=0,sentbytes,sendsock = -1; uint32_t now; struct psock *ptr=0; void *buf=0; struct nn_pollfd pfd,*pfds; char keepalive[512];//,*myipaddr = _ptr;
    while ( 1 )
    {
        now = (uint32_t)time(NULL);
        if ( buf != 0 && ptr != 0 && sendsock >= 0 )
        {
            if ( size > 0 )
            {
                if ( (sentbytes= LP_send(sendsock,buf,0)) > 0 )
                    printf("PSOCKS (%d %d %d) (%s) -> %d/%d bytes %s\n",ptr->recvsock,ptr->sendsock,sendsock,(char *)buf,size,sentbytes,ptr->sendaddr);
                else printf("send error to %s\n",ptr->sendaddr);
                if ( buf != 0 )
                {
                    if ( buf != keepalive )
                        nn_freemsg(buf);
                    buf = 0;
                    size = 0;
                    ptr = 0;
                    sendsock = -1;
                }
            }
            /* pfd.fd = ptr->sendsock;
             pfd.events = NN_POLLOUT;
             if ( nn_poll(&pfd,1,1) > 0 )
             {
             if ( (sentbytes= nn_send(sendsock,buf,size,0)) > 0 )
             {
             printf("PSOCKS (%d %d %d) (%s) -> %d/%d bytes %s\n",ptr->recvsock,ptr->sendsock,sendsock,(char *)buf,size,sentbytes,ptr->sendaddr);
             } else printf("send error to %s\n",ptr->sendaddr);
             if ( buf != 0 )
             {
             if ( buf != keepalive )
             nn_freemsg(buf);
             buf = 0;
             size = 0;
             ptr = 0;
             sendsock = -1;
             }
             }*/
        }
        else if ( Numpsocks > 0 )
        {
            pfds = calloc(Numpsocks,sizeof(*pfds) * 2);
            portable_mutex_lock(&LP_psockmutex);
            for (iter=0; iter<2; iter++)
            {
                for (i=n=0; i<Numpsocks; i++)
                {
                    ptr = &PSOCKS[i];
                    if ( iter == 0 )
                    {
                        pfds[n].fd = ptr->recvsock;
                        pfds[n].events = POLLIN;
                    }
                    else
                    {
                        if ( pfds[n].fd != ptr->recvsock )
                        {
                            printf("unexpected fd.%d mismatched recvsock.%d\n",pfds[n].fd,ptr->recvsock);
                            break;
                        }
                        else if ( (pfds[n].revents & POLLIN) != 0 )
                        {
                            printf("%s has pollin\n",ptr->sendaddr);
                            if ( (size= nn_recv(ptr->recvsock,&buf,NN_MSG,0)) > 0 )
                            {
                                ptr->lasttime = now;
                                sendsock = ptr->sendsock;
                                printf("[%s]\n",(char *)buf);
                                break;
                            }
                        }
                    }
                    n++;
                    if ( ptr->ispaired != 0 )
                    {
                        if ( iter == 0 )
                        {
                            pfds[n].fd = ptr->sendsock;
                            pfds[n].events = POLLIN;
                        }
                        else
                        {
                            if ( pfds[n].fd != ptr->sendsock )
                            {
                                printf("unexpected fd.%d mismatched sendsock.%d\n",pfds[n].fd,ptr->sendsock);
                                break;
                            }
                            else if ( (pfds[n].revents & POLLIN) != 0 )
                            {
                                printf("%s paired has pollin\n",ptr->sendaddr);
                                if ( (size= nn_recv(ptr->sendsock,&buf,NN_MSG,0)) > 0 )
                                {
                                    ptr->lasttime = now;
                                    sendsock = ptr->recvsock;
                                    break;
                                }
                            }
                        }
                        n++;
                    }
                }
                if ( iter == 0 )
                {
                    if ( (retval= nn_poll(pfds,n,10)) <= 0 )
                    {
                        if ( retval != 0 )
                            printf("nn_poll retval.%d\n",retval);
                        break;
                    }
                }
            }
            portable_mutex_unlock(&LP_psockmutex);
            free(pfds);
            if ( sendsock < 0 )
            {
                for (i=nonz=0; i<Numpsocks; i++)
                {
                    if ( i < Numpsocks )
                    {
                        ptr = &PSOCKS[i];
                        /*if ( (size= nn_recv(ptr->recvsock,&buf,NN_MSG,0)) > 0 )
                        {
                            printf("got %d bytes for %s\n",size,ptr->sendaddr);
                            ptr->lasttime = now;
                            sendsock = ptr->sendsock;
                            break;
                        }
                        else*/ if ( now > ptr->lasttime+PSOCK_IDLETIMEOUT )
                        {
                            printf("PSOCKS[%d] of %d (%u %u) lag.%d IDLETIMEOUT\n",i,Numpsocks,ptr->recvport,ptr->sendport,now - ptr->lasttime);
                            if ( ptr->recvsock >= 0 )
                                nn_close(ptr->recvsock);
                            if ( ptr->sendsock >= 0 )
                                nn_close(ptr->sendsock);
                            portable_mutex_lock(&LP_psockmutex);
                            if ( Numpsocks > 1 )
                            {
                                PSOCKS[i] = PSOCKS[--Numpsocks];
                                memset(&PSOCKS[Numpsocks],0,sizeof(*ptr));
                            } else Numpsocks = 0;
                            portable_mutex_unlock(&LP_psockmutex);
                            break;
                        }
                        else if ( now > ptr->lastping+6 )
                        {
                            ptr->lastping = now;
                            sendsock = ptr->sendsock;
                            printf("keep %s alive\n",ptr->sendaddr);
                            sprintf(keepalive,"{\"method\":\"keepalive\",\"endpoint\":\"%s\"}",ptr->sendaddr);
                            size = (int32_t)strlen(keepalive) + 1;
                            buf = keepalive;
                            break;
                        }
                    }
                }
                if ( nonz == 0 && i == Numpsocks )
                    usleep(100000);
            }
        } else usleep(100000);
    }
}

void LP_psockadd(int32_t ispaired,int32_t recvsock,uint16_t recvport,int32_t sendsock,uint16_t sendport,char *subaddr,char *publicaddr)
{
    struct psock *ptr;
    portable_mutex_lock(&LP_psockmutex);
    PSOCKS = realloc(PSOCKS,sizeof(*PSOCKS) * (Numpsocks + 1));
    ptr = &PSOCKS[Numpsocks++];
    ptr->ispaired = ispaired;
    ptr->recvsock = recvsock;
    ptr->recvport = recvport;
    ptr->sendsock = sendsock;
    ptr->sendport = sendport;
    safecopy(ptr->sendaddr,subaddr,sizeof(ptr->sendaddr));
    safecopy(ptr->publicaddr,publicaddr,sizeof(ptr->publicaddr));
    ptr->lasttime = (uint32_t)time(NULL);
    portable_mutex_unlock(&LP_psockmutex);
}

int32_t LP_psockmark(char *publicaddr)
{
    int32_t i,retval = -1; struct psock *ptr;
    portable_mutex_lock(&LP_psockmutex);
    for (i=0; i<Numpsocks; i++)
    {
        ptr = &PSOCKS[i];
        if ( strcmp(publicaddr,ptr->publicaddr) == 0 )
        {
            printf("mark PSOCKS[%d] %s for deletion\n",i,publicaddr);
            ptr->lasttime = 0;
            retval = i;
            break;
        }
    }
    portable_mutex_unlock(&LP_psockmutex);
    return(retval);
}

char *LP_psock(char *myipaddr,int32_t ispaired)
{
    char pushaddr[128],subaddr[128]; uint16_t i,pushport,subport; int32_t timeout,maxsize,pullsock=-1,pubsock=-1; cJSON *retjson=0;
    retjson = cJSON_CreateObject();
    pushport = Psockport++;
    subport = Psockport++;
    for (i=0; i<100; i++)
    {
        if ( pushport < 10000 )
            pushport = 10001;
        if ( subport <= pushport )
            subport = pushport +  1;
        pullsock = pubsock = -1;
        nanomsg_transportname(1,pushaddr,myipaddr,pushport), pushport += 2;
        nanomsg_transportname(1,subaddr,myipaddr,subport), subport += 2;
        if ( (pullsock= nn_socket(AF_SP,ispaired!=0?NN_PAIR:NN_PULL)) >= 0 && (pubsock= nn_socket(AF_SP,ispaired!=0?NN_PAIR:NN_PUB)) >= 0 )
        {
            if ( nn_bind(pullsock,pushaddr) >= 0 && nn_bind(pubsock,subaddr) >= 0 )
            {
                timeout = 10;
                nn_setsockopt(pubsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                timeout = 1;
                nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                maxsize = 1024 * 1024;
                nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVBUF,&maxsize,sizeof(maxsize));
                if ( ispaired != 0 )
                {
                    nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                    nn_setsockopt(pubsock,NN_SOL_SOCKET,NN_RCVBUF,&maxsize,sizeof(maxsize));
                    nn_setsockopt(pubsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                }
                nanomsg_transportname(0,pushaddr,myipaddr,pushport);
                nanomsg_transportname(0,subaddr,myipaddr,subport);
                LP_psockadd(ispaired,pullsock,pushport,pubsock,subport,subaddr,pushaddr);
                jaddstr(retjson,"result","success");
                jaddstr(retjson,"LPipaddr",myipaddr);
                jaddstr(retjson,"connectaddr",subaddr);
                jaddnum(retjson,"connectport",subport);
                jaddnum(retjson,"ispaired",ispaired);
                jaddstr(retjson,"publicaddr",pushaddr);
                jaddnum(retjson,"publicport",pushport);
                printf("i.%d publicaddr.(%s) for %s, pullsock.%d pubsock.%d\n",i,pushaddr,subaddr,pullsock,pubsock);
                break;
            } else printf("bind error on %s or %s\n",pushaddr,subaddr);
            if ( pullsock >= 0 )
                nn_close(pullsock);
            if ( pubsock >= 0 )
                nn_close(pubsock);
        }
    }
    if ( Psockport > 60000 )
        Psockport = 10000;
    if ( i == 100 )
        jaddstr(retjson,"error","cant find psock ports");
    return(jprint(retjson,1));
}

/*
 LP_pushaddr_get makes transparent the fact that most nodes cannot bind()!
 
 The idea is to create an LP node NN_PAIR sock that the LP node binds to and client node connects to. Additionally, the LP node creates an NN_PULL that other nodes can NN_PUSH to and returns this address in pushaddr/retval for the client node to register with. The desired result is that other than the initial LP node, all the other nodes do a normal NN_PUSH, requiring no change to the NN_PUSH/NN_PULL logic. Of course, the initial LP node needs to autoforward all packets from the public NN_PULL to the NN_PUB
 
    similar to LP_pushaddr_get, create an NN_PAIR for DEX atomic data, can be assumed to have a max lifetime of 2*INSTANTDEX_LOCKTIME
 
 both are combined in LP_psock_get

*/

int32_t nn_tests(int32_t pullsock,char *pushaddr,int32_t nnother)
{
    int32_t sock,n,timeout,retval = -1; char msg[512],*retstr;
    printf("nn_tests.(%s)\n",pushaddr);
    if ( (sock= nn_socket(AF_SP,nnother)) >= 0 )
    {
        if ( nn_connect(sock,pushaddr) < 0 )
            printf("connect error %s\n",nn_strerror(nn_errno()));
        else
        {
            sleep(1);
            timeout = 1;
            nn_setsockopt(sock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
            sprintf(msg,"{\"method\":\"nn_tests\",\"ipaddr\":\"%s\"}",pushaddr);
            n = LP_send(sock,msg,0);
            LP_pullsock_check(&retstr,"127.0.0.1",-1,pullsock,0.);
            printf(">>>>>>>>>>>>>>>>>>>>>> sent %d bytes -> %d (%s)\n",n,pullsock,retstr!=0?retstr:"");
            if ( retstr != 0 )
            {
                free(retstr);
                retval = 0;
            }
        }
        nn_close(sock);
    }
    return(retval);
}

int32_t LP_initpublicaddr(uint16_t *mypullportp,char *publicaddr,char *myipaddr,uint16_t mypullport,int32_t ispaired)
{
    int32_t nntype,pullsock,timeout,maxsize; char bindaddr[128],connectaddr[128];
    *mypullportp = mypullport;
    if ( ispaired == 0 )
    {
        if ( LP_canbind != 0 )
            nntype = LP_COMMAND_RECVSOCK;
        else nntype = NN_SUB;
    }
    else nntype = NN_PAIR;
    if ( LP_canbind != 0 )
    {
        nanomsg_transportname(0,publicaddr,myipaddr,mypullport);
        nanomsg_transportname(1,bindaddr,myipaddr,mypullport);
    }
    else
    {
        *mypullportp = 0;
        while ( *mypullportp == 0 )
        {
            if ( (*mypullportp= LP_psock_get(connectaddr,publicaddr,ispaired)) != 0 )
                break;
            sleep(10);
            printf("try to get publicaddr again\n");
        }
    }
    if ( (pullsock= nn_socket(AF_SP,nntype)) >= 0 )
    {
        if ( LP_canbind == 0 )
        {
            if ( nn_connect(pullsock,connectaddr) < 0 )
            {
                printf("bind to %s error for %s: %s\n",connectaddr,publicaddr,nn_strerror(nn_errno()));
                exit(-1);
            } else printf("nntype.%d NN_SUB.%d connect to %s pullsock.%d\n",nntype,NN_SUB,connectaddr,pullsock);
            while ( 0 )
            {
                int32_t size; void *buf;
                if ( (size= nn_recv(pullsock,&buf,NN_MSG,0)) > 0 )
                    printf("SUBPULL.(%s)\n",(char *)buf);
                else printf("size.%d\n",size);
                sleep(10);
            }
        }
        else
        {
            if ( nn_bind(pullsock,bindaddr) < 0 )
            {
                printf("bind to %s error for %s: %s\n",bindaddr,publicaddr,nn_strerror(nn_errno()));
                exit(-1);
            }
        }
        timeout = 1;
        nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
        if ( nntype == NN_PAIR )
            nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
        maxsize = 2 * 1024 * 1024;
        nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVBUF,&maxsize,sizeof(maxsize));
        if ( nntype == NN_SUB )
            nn_setsockopt(pullsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
    }
    if ( 0 && ispaired == 0 && nn_tests(pullsock,publicaddr,LP_COMMAND_SENDSOCK) < 0 )
    {
        printf("command socket didnt work\n");
        exit(-1);
    }
    return(pullsock);
}
