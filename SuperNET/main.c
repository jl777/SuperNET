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

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000	// Do not generate SIGPIPE
#endif

// ALL globals must be here!

int32_t nn_typelist[] = { NN_REP, NN_REQ, NN_RESPONDENT, NN_SURVEYOR, NN_PUB, NN_SUB, NN_PULL, NN_PUSH, NN_BUS, NN_PAIR };
char *nn_transports[] = { "tcp", "ws", "ipc", "inproc", "tcpmux", "", "", "" };

void expand_epbits(char *endpoint,struct endpoint epbits)
{
    char ipaddr[64];
    if ( epbits.ipbits != 0 )
        expand_ipbits(ipaddr,epbits.ipbits);
    else strcpy(ipaddr,"*");
    sprintf(endpoint,"%s://%s:%d",nn_transports[epbits.transport],ipaddr,epbits.port);
}

struct endpoint calc_epbits(char *transport,uint32_t ipbits,uint16_t port,int32_t type)
{
    int32_t i; struct endpoint epbits;
    memset(&epbits,0,sizeof(epbits));
    for (i=0; i<(int32_t)(sizeof(nn_transports)/sizeof(*nn_transports)); i++)
        if ( strcmp(transport,nn_transports[i]) == 0 )
        {
            epbits.ipbits = ipbits;
            epbits.port = port;
            epbits.transport = i;
            epbits.nn = type;
            break;
        }
    return(epbits);
}

int32_t ismyaddress(struct supernet_info *myinfo,char *server)
{
    uint32_t ipbits; int32_t i,tlen; char str[64];
    for (i=0; i<sizeof(nn_transports)/sizeof(*nn_transports); i++)
    {
        if ( nn_transports[i] == 0 )
            break;
        sprintf(str,"%s://",nn_transports[i]);
        tlen = (int32_t)strlen(str);
        if ( strncmp(server,str,tlen) == 0 )
        {
            server += tlen;
            break;
        }
    }
    if ( (ipbits= is_ipaddr(server)) != 0 )
    {
        if ( strcmp(server,myinfo->ipaddr) == 0 || myinfo->ipbits == ipbits )
        {
            printf("(%s) MATCHES me (%s)\n",server,myinfo->ipaddr);
            return(1);
        }
    }
    else if ( myinfo->my64bits == ipbits )
        return(1);
    //printf("(%s) is not me (%s)\n",server,myipaddr);
    return(0);
}

char *nn_typestr(int32_t type)
{
    switch ( type )
    {
            // Messages that need a response from the set of peers: SURVEY
        case NN_SURVEYOR: return("NN_SURVEYOR"); break;
        case NN_RESPONDENT: return("NN_RESPONDENT"); break;
            // Messages that need a response, but only from one peer: REQ/REP
        case NN_REQ: return("NN_REQ"); break;
        case NN_REP: return("NN_REP"); break;
            // One-way messages to one peer: PUSH/PULL
        case NN_PUSH: return("NN_PUSH"); break;
        case NN_PULL: return("NN_PULL"); break;
            //  One-way messages to all: PUB/SUB
        case NN_PUB: return("NN_PUB"); break;
        case NN_SUB: return("NN_SUB"); break;
        case NN_BUS: return("NN_BUS"); break;
        case NN_PAIR: return("NN_PAIR"); break;
    }
    return("NN_ERROR");
}

int32_t nn_oppotype(int32_t type)
{
    switch ( type )
    {
            // Messages that need a response from the set of peers: SURVEY
        case NN_SURVEYOR: return(NN_RESPONDENT); break;
        case NN_RESPONDENT: return(NN_SURVEYOR); break;
            // Messages that need a response, but only from one peer: REQ/REP
        case NN_REQ: return(NN_REP); break;
        case NN_REP: return(NN_REQ); break;
            // One-way messages to one peer: PUSH/PULL
        case NN_PUSH: return(NN_PULL); break;
        case NN_PULL: return(NN_PUSH); break;
            //  One-way messages to all: PUB/SUB
        case NN_PUB: return(NN_SUB); break;
        case NN_SUB: return(NN_PUB); break;
        case NN_BUS: return(NN_BUS); break;
        case NN_PAIR: return(NN_PAIR); break;
    }
    return(-1);
}

int32_t nn_portoffset(int32_t type)
{
    int32_t i;
    for (i=0; i<(int32_t)(sizeof(nn_typelist)/sizeof(*nn_typelist)); i++)
        if ( nn_typelist[i] == type )
            return(i + 2);
    return(-1);
}

int32_t nn_socket_status(int32_t nnsock,int32_t timeoutmillis)
{
    struct nn_pollfd pfd;
    int32_t rc;
    pfd.fd = nnsock;
    pfd.events = NN_POLLIN | NN_POLLOUT;
    if ( (rc= nn_poll(&pfd,1,timeoutmillis)) == 0 )
        return(pfd.revents);
    else return(-1);
}

int32_t SuperNET_msglen(struct supernet_msghdr *msg)
{
    return(msg->serlen[0] + ((int32_t)msg->serlen[1] << 8) + ((int32_t)msg->serlen[2] << 16));
}

int32_t SuperNET_msgvalidate(struct supernet_msghdr *msg)
{
    int32_t msglen = 0;
    msglen = SuperNET_msglen(msg);
    return(msglen);
}

int32_t nn_settimeouts(int32_t sock,int32_t sendtimeout,int32_t recvtimeout)
{
    int32_t retrymillis,maxmillis;
    if ( (maxmillis= SUPERNET_NETWORKTIMEOUT) == 0 )
        maxmillis = 3000;
    retrymillis = maxmillis/40;
    if ( nn_setsockopt(sock,NN_SOL_SOCKET,NN_RECONNECT_IVL,&retrymillis,sizeof(retrymillis)) < 0 )
        fprintf(stderr,"error setting NN_REQ NN_RECONNECT_IVL_MAX socket %s\n",nn_errstr());
    else if ( nn_setsockopt(sock,NN_SOL_SOCKET,NN_RECONNECT_IVL_MAX,&maxmillis,sizeof(maxmillis)) < 0 )
        fprintf(stderr,"error setting NN_REQ NN_RECONNECT_IVL_MAX socket %s\n",nn_errstr());
    else if ( sendtimeout > 0 && nn_setsockopt(sock,NN_SOL_SOCKET,NN_SNDTIMEO,&sendtimeout,sizeof(sendtimeout)) < 0 )
        fprintf(stderr,"error setting sendtimeout %s\n",nn_errstr());
    else if ( recvtimeout > 0 && nn_setsockopt(sock,NN_SOL_SOCKET,NN_RCVTIMEO,&recvtimeout,sizeof(recvtimeout)) < 0 )
        fprintf(stderr,"error setting sendtimeout %s\n",nn_errstr());
    else return(0);
    return(-1);
}

int32_t nn_createsocket(struct supernet_info *myinfo,char *endpoint,int32_t bindflag,char *name,int32_t type,uint16_t port,int32_t sendtimeout,int32_t recvtimeout)
{
    int32_t sock;
    if ( (sock= nn_socket(AF_SP,type)) < 0 )
        fprintf(stderr,"error getting socket %s\n",nn_errstr());
    if ( bindflag != 0 )
    {
        if ( endpoint[0] == 0 )
            expand_epbits(endpoint,calc_epbits(myinfo->transport,0,port,type));
        if ( nn_bind(sock,endpoint) < 0 )
            fprintf(stderr,"error binding to relaypoint sock.%d type.%d to (%s) (%s) %s\n",sock,type,name,endpoint,nn_errstr());
        else fprintf(stderr,"BIND.(%s) <- %s\n",endpoint,name);
    }
    else if ( bindflag == 0 && endpoint != 0 && endpoint[0] != 0 )
    {
        if ( nn_connect(sock,endpoint) < 0 )
            fprintf(stderr,"error connecting to relaypoint sock.%d type.%d to (%s) (%s) %s\n",sock,type,name,endpoint,nn_errstr());
        else fprintf(stderr,"%s -> CONNECT.(%s)\n",name,endpoint);
    }
    if ( nn_settimeouts(sock,sendtimeout,recvtimeout) < 0 )
    {
        fprintf(stderr,"nn_createsocket.(%s) %d\n",name,sock);
        return(-1);
    }
    return(sock);
}

bits256 SuperNET_OPRETURN(struct supernet_info *myinfo,char *symbol,double fee,uint8_t *buf,int32_t len)
{
    bits256 txid;
    printf("send OPRETURN\n");
    return(txid);
}

bits256 SuperNET_agentannounce(struct supernet_info *myinfo,struct supernet_agent *agent,cJSON *network)
{
    static const bits256 zero;
    uint8_t buf[80 + sizeof(struct iguana_msghdr)],*data;
    bits256 pubkey,sig; int32_t i,len=0; uint8_t netmagic[4]; char *sigstr,*announce,*pubkeystr;
    memset(buf,0,sizeof(buf));
    data = &buf[sizeof(struct iguana_msghdr)];
    if ( (announce= jstr(network,"announce")) != 0 )
    {
        data[len++] = SCRIPT_OPRETURN;
        data[len++] = 75;
        iguana_rwnum(1,&data[len],sizeof(myinfo->ipbits),&myinfo->ipbits);
        for (i=0; i<7; i++)
            if ( (data[len+i]= announce[i]) == 0 )
                break;
        len = 13;
        if ( (pubkeystr= jstr(network,"pubkey")) == 0 || strlen(pubkeystr) != sizeof(bits256)*2 )
            pubkeystr = GENESIS_PUBKEYSTR;
        decode_hex(pubkey.bytes,sizeof(pubkey),pubkeystr);
        len += iguana_rwbignum(1,&data[len],sizeof(pubkey),pubkey.bytes); // 45 bytes
        if ( (sigstr= jstr(network,"sig")) != 0 && strlen(sigstr) == sizeof(bits256)*2 )
        {
            sigstr = GENESIS_PUBKEYSTR;
            len += iguana_rwbignum(1,&data[len],sizeof(sig),sig.bytes); // 77 bytes
        }
        decode_hex(netmagic,4,"e4c2d8e6");
        iguana_sethdr((struct iguana_msghdr *)buf,netmagic,"SuperNET",data,len);
        return(SuperNET_OPRETURN(myinfo,"BTCD",.001,buf,len));
    }
    printf("invalid SuperNET OPRETURN protocol.(%s)\n",announce!=0?announce:"");
    return(zero);
}

void Supernet_networkadd(struct supernet_info *myinfo,struct supernet_agent *agent,cJSON *network)
{
    int32_t sendtimeout=0,recvtimeout=0;
    agent->pubpoint[0] = agent->reppoint[0] = 0;
    if ( (agent->pubport= juint(network,"pubport")) > 1000 )
    {
        agent->pubsock = nn_createsocket(myinfo,agent->pubpoint,1,"NN_PUB",NN_PUB,agent->pubport,sendtimeout,recvtimeout);
        SuperNET_agentannounce(myinfo,agent,network);
    }
    else agent->pubport = -1;
    if ( (agent->repport= juint(network,"repport")) > 1000 )
        agent->repsock = nn_createsocket(myinfo,agent->reppoint,1,"NN_REP",NN_REP,agent->repport,sendtimeout,recvtimeout);
    else agent->repport = -1;
    agent->subsock = nn_createsocket(myinfo,0,0,"NN_SUB",NN_SUB,0,sendtimeout,recvtimeout);
    nn_setsockopt(agent->subsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
    agent->reqsock = nn_createsocket(myinfo,0,0,"NN_REQ",NN_REQ,0,sendtimeout,recvtimeout);
}

int32_t SuperNET_agentcommand(struct supernet_info *myinfo,struct supernet_agent *agent,struct supernet_msghdr *H,uint8_t *buf,int32_t buflen)
{
    char *name; cJSON *json; int32_t i;
    if ( strcmp(H->command,"register") == 0 )
    {
        if ( (json= cJSON_Parse((char *)buf)) != 0 )
        {
            if ( (name= jstr(json,"name")) != 0 )
            {
                memset(agent->name,0,sizeof(agent->name));
                strncpy(agent->name,name,sizeof(agent->name)-1);
                if ( (agent->networks= jarray(&agent->num,json,"networks")) != 0 )
                {
                    for (i=0; i<agent->num; i++)
                        Supernet_networkadd(myinfo,agent,jitem(agent->networks,i));
                }
            } else free_json(json);
        }
    }
    return(0);
}

int32_t SuperNET_socket(int32_t bindflag,char *hostname,uint16_t port)
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

int32_t SuperNET_send(struct supernet_info *myinfo,struct supernet_agent *agent,uint8_t *serialized,int32_t len)
{
    int32_t numsent,remains,sock;
    if ( agent == 0 )
        return(-1);
    if ( (sock= agent->sock) < 0 || agent->dead != 0 )
    {
        return(-1);
    }
    remains = len;
    while ( remains > 0 )
    {
        if ( (numsent= (int32_t)send(sock,serialized,remains,MSG_NOSIGNAL)) < 0 )
        {
            printf("send errno.%d %s\n",errno,strerror(errno));
            if ( errno != EAGAIN && errno != EWOULDBLOCK )
            {
                printf("bad errno.%d %s zombify.%p\n",errno,strerror(errno),agent->name);
                agent->dead = (uint32_t)time(NULL);
                return(-errno);
            } //else usleep(*sleeptimep), *sleeptimep *= 1.1;
        }
        else if ( remains > 0 )
        {
            remains -= numsent;
            serialized += numsent;
            if ( remains > 0 )
                printf("SuperNET sent.%d remains.%d of len.%d\n",numsent,remains,len);
        }
    }
    agent->totalsent += len;
    //printf(" sent.%d bytes to %s\n",len,addr->ipaddr);// getchar();
    return(len);
}

char *SuperNET_JSON(struct supernet_info *myinfo,cJSON *argjson,char *remoteaddr)
{
    char *agent,*method;
    if ( (agent= jstr(argjson,"agent")) == 0 || (method= jstr(argjson,"method")) == 0 )
        return(clonestr("{\"error\":\"need both agent and method\"}"));
}

void SuperNET_rpcloop(void *args)
{
    struct supernet_info *myinfo = args;
    int32_t recvlen,bindsock,postflag,sock,remains,numsent,len; socklen_t clilen;
    char remoteaddr[64],jsonbuf[8192],*buf,*retstr,*space;//,*retbuf; ,n,i,m
    struct sockaddr_in cli_addr; uint32_t ipbits,i; uint16_t port;
    int32_t size = 1024 * 1024 * 2;
    port = SUPERNET_PORT;
    bindsock = SuperNET_socket(1,"127.0.0.1",port);
    printf("SuperNET_rpcloop 127.0.0.1:%d bind sock.%d\n",port,bindsock);
    space = calloc(1,size);
    while ( bindsock >= 0 )
    {
        clilen = sizeof(cli_addr);
        //printf("ACCEPT (%s:%d) on sock.%d\n","127.0.0.1",port,bindsock);
        sock = accept(bindsock,(struct sockaddr *)&cli_addr,&clilen);
        if ( sock < 0 )
        {
            //printf("iguana_rpcloop ERROR on accept usock.%d\n",sock);
            continue;
        }
        memcpy(&ipbits,&cli_addr.sin_addr.s_addr,sizeof(ipbits));
        expand_ipbits(remoteaddr,ipbits);
        memset(jsonbuf,0,sizeof(jsonbuf));
        remains = (int32_t)(sizeof(jsonbuf) - 1);
        buf = jsonbuf;
        recvlen = 0;
        retstr = 0;
        while ( remains > 0 )
        {
            if ( (len= (int32_t)recv(sock,buf,remains,0)) < 0 )
            {
                if ( errno == EAGAIN )
                {
                    printf("EAGAIN for len %d, remains.%d\n",len,remains);
                    usleep(10000);
                }
                break;
            }
            else
            {
                if ( len > 0 )
                {
                    remains -= len;
                    recvlen += len;
                    buf = &buf[len];
                    retstr = SuperNET_rpcparse(myinfo,space,size,&postflag,jsonbuf,remoteaddr);
                    break;
                } else usleep(10000);
            }
        }
        if ( retstr != 0 )
        {
            i = 0;
            if ( postflag == 0 )
            {
                //retstr = SuperNET_htmlresponse(space,size,&remains,1,retstr,1);
            }
            else remains = (int32_t)strlen(retstr);
            printf("RETBUF.(%s)\n",retstr);
            while ( remains > 0 )
            {
                if ( (numsent= (int32_t)send(sock,&retstr[i],remains,MSG_NOSIGNAL)) < 0 )
                {
                    if ( errno != EAGAIN && errno != EWOULDBLOCK )
                    {
                        //printf("%s: %s numsent.%d vs remains.%d len.%d errno.%d (%s) usock.%d\n",retstr,ipaddr,numsent,remains,recvlen,errno,strerror(errno),sock);
                        break;
                    }
                }
                else if ( remains > 0 )
                {
                    remains -= numsent;
                    i += numsent;
                    if ( remains > 0 )
                        printf("iguana sent.%d remains.%d of len.%d\n",numsent,remains,recvlen);
                }
            }
            if ( retstr != space )
                free(retstr);
        }
        //printf("done response sock.%d\n",sock);
        closesocket(sock);
    }
}

int32_t SuperNET_msgrecv(struct supernet_info *myinfo,struct supernet_agent *agent,uint8_t *_buf,int32_t maxlen)
{
    int32_t len,recvlen; void *buf = _buf; struct supernet_msghdr H;
    printf("got.(%s) from %s | sock.%d\n",H.command,agent->ipaddr,agent->sock);
    memset(&H,0,sizeof(H));
    if ( (recvlen= (int32_t)SuperNET_recv(agent->sock,(uint8_t *)&H,sizeof(H))) == sizeof(H) )
    {
        agent->totalrecv += recvlen;
        if ( (len= SuperNET_msgvalidate(&H)) >= 0 )
        {
            recvlen = 0;
            if ( len > 0 )
            {
                if ( len > maxlen )
                    buf = calloc(1,len);
                if ( (recvlen= SuperNET_recv(agent->sock,buf,len)) < 0 )
                {
                    printf("recv error on (%s) len.%d errno.%d (%s)\n",H.command,len,-recvlen,strerror(-recvlen));
                    if ( buf != _buf )
                        free(buf);
                    agent->dead = (uint32_t)time(NULL);
                    return(recvlen);
                } else agent->totalrecv += recvlen;
            }
            printf("PROCESS.%c NNRECV(%s) recvlen.%d\n",H.type,H.command,recvlen);
            if ( H.type == 'C' )
                SuperNET_agentcommand(myinfo,agent,&H,buf,recvlen);
            else if ( agent->recvfunc != 0 )
                (*agent->recvfunc)(myinfo,agent,&H,buf,recvlen);
            if ( buf != _buf )
                free(buf);
            return(recvlen);
        }
        printf("invalid header received from (%s)\n",agent->ipaddr);
    }
    printf("%s recv error on hdr errno.%d (%s)\n",agent->ipaddr,-recvlen,strerror(-recvlen));
    return(-1);
}

int32_t SuperNET_msgsend(struct supernet_info *myinfo,struct supernet_agent *agent,struct supernet_msghdr *msg)
{
    return(SuperNET_send(myinfo,agent,(uint8_t *)msg,SuperNET_msglen(msg) + sizeof(*msg)));
}

int32_t SuperNET_nnsend(struct supernet_info *myinfo,struct supernet_endpoint *ptr,int32_t ind,struct supernet_msghdr *msg)
{
    return(nn_send(ptr->eps[ind].nnsock,(uint8_t *)msg,SuperNET_msglen(msg) + sizeof(*msg),0));
}

struct supernet_msghdr *SuperNET_msgpending(struct supernet_info *myinfo,struct supernet_agent *agent)
{
    return(queue_dequeue(&agent->recvQ,0));
}

struct supernet_msghdr *SuperNET_nnpending(struct supernet_info *myinfo,struct supernet_endpoint *ptr,int32_t ind)
{
    return(queue_dequeue(&ptr->eps[ind].nnrecvQ,0));
}

int32_t SuperNET_nnrecv(struct supernet_info *myinfo,struct supernet_endpoint *ptr,int32_t ind)
{
    void *msg; int32_t nnlen;
    if ( (nnlen= nn_recv(ptr->eps[ind].nnsock,&msg,NN_MSG,0)) > 0 )
    {
        printf("PROCESS NNRECV(%s)\n",msg);
        if ( ptr->nnrecvfunc != 0 )
            (*ptr->nnrecvfunc)(myinfo,ptr,ind,msg,nnlen);
        nn_freemsg(msg);
    }
    return(nnlen);
}

int32_t Supernet_poll(struct supernet_info *myinfo,uint8_t *buf,int32_t bufsize,struct supernet_agent *agents,int32_t num,int32_t timeout)
{
    struct pollfd fds[SUPERNET_MAXAGENTS]; int32_t i,nonz,flag; struct supernet_msghdr *msg; struct supernet_agent *agent;
    if ( num == 0 )
        return(0);;
    memset(fds,0,sizeof(fds));
    flag = 0;
    for (i=nonz=0; i<num; i++)
    {
        agent = &agents[i];
        fds[i].fd = -1;
        if ( agent->sock >= 0 )
        {
            fds[i].fd = agent->sock;
            fds[i].events = (POLLIN | POLLOUT);
            nonz++;
        }
    }
    if ( nonz != 0 && poll(fds,num,timeout) > 0 )
    {
        for (i=0; i<num; i++)
        {
            agent = &agents[i];
            if ( agent->sock < 0 )
                continue;
            if ( (fds[i].revents & POLLIN) != 0 && SuperNET_msgrecv(myinfo,agent,buf,bufsize) >= 0 )
                flag++;
            if ( (fds[i].revents & POLLOUT) != 0 )
            {
                if ( (msg= SuperNET_msgpending(myinfo,agent)) != 0 && SuperNET_msgsend(myinfo,agent,msg) > 0 )
                    flag++;
            }
        }
    }
    return(flag);
}

int32_t Supernet_nnpoll(struct supernet_info *myinfo,uint8_t *buf,int32_t bufsize,struct supernet_endpoint **eps,int32_t num,int32_t timeout)
{
    struct nn_pollfd fds[1024]; int32_t i,j,n,k,r,starti,nonz,flag; struct supernet_msghdr *msg; struct supernet_endpoint *ptr;
    if ( num == 0 )
        return(0);
    memset(fds,0,sizeof(fds));
    flag = 0;
    r = rand();
    for (j=k=nonz=n=0; j<num; j++)
    {
        i = (j + r) % num;
        ptr = eps[i];
        starti = n;
        for (k=0; k<ptr->num; k++,n++)
        {
            fds[n].fd = -1;
            if ( ptr->eps[k].nnsock >= 0 )
            {
                fds[n].fd = ptr->eps[k].nnsock;
                fds[n].events = (POLLIN | POLLOUT);
                nonz++;
            }
        }
    }
    if ( nonz != 0 && nn_poll(fds,num,timeout) > 0 )
    {
        for (j=k=0; j<num; j++)
        {
            i = (j + r) % num;
            ptr = eps[i];
            starti = n;
            for (k=0; k<ptr->num; k++,n++)
            {
                if ( (fds[i].revents & POLLIN) != 0 && SuperNET_nnrecv(myinfo,ptr,n - starti) >= 0 )
                    flag++;
                if ( (fds[i].revents & POLLOUT) != 0 )
                {
                    if ( (msg= SuperNET_nnpending(myinfo,ptr,n - starti)) != 0 && SuperNET_nnsend(myinfo,ptr,n - starti,msg) > 0 )
                        flag++;
                }
            }
        }
    }
    return(flag);
}

void SuperNET_acceptloop(void *args)
{
    int32_t bindsock,sock; struct supernet_agent *agent; struct supernet_info *myinfo = args;
    socklen_t clilen; uint16_t agentport; struct sockaddr_in cli_addr; char ipaddr[64]; uint32_t ipbits;
    bindsock = SuperNET_socket(1,"127.0.0.1",myinfo->acceptport);
    printf("SuperNET_acceptloop 127.0.0.1:%d bind sock.%d\n",myinfo->acceptport,bindsock);
    while ( bindsock >= 0 )
    {
        clilen = sizeof(cli_addr);
        printf("ACCEPT (%s:%d) on sock.%d\n","127.0.0.1",myinfo->acceptport,bindsock);
        sock = accept(bindsock,(struct sockaddr *)&cli_addr,&clilen);
        if ( sock < 0 )
        {
            printf("ERROR on accept bindsock.%d errno.%d (%s)\n",bindsock,errno,strerror(errno));
            continue;
        }
        memcpy(&ipbits,&cli_addr.sin_addr.s_addr,sizeof(ipbits));
        agentport = cli_addr.sin_port;
        expand_ipbits(ipaddr,ipbits);
        printf("NEWSOCK.%d for %x (%s:%u)\n",sock,ipbits,ipaddr,agentport);
        agent = calloc(1,sizeof(*agent));
        strcpy(agent->ipaddr,ipaddr);
        sprintf(agent->name,"%s:%d",ipaddr,agentport);
        agent->ipbits = ipbits;
        agent->sock = sock;
        agent->port = myinfo->acceptport;
        queue_enqueue("acceptQ",&myinfo->acceptQ,&agent->DL,0);
    }
}

int32_t SuperNET_acceptport(struct supernet_info *myinfo,uint16_t port)
{
    struct supernet_info *ptr;
    ptr = calloc(1,sizeof(*myinfo));
    *ptr = *myinfo;
    ptr->acceptport = port;
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)SuperNET_acceptloop,(void *)ptr) != 0 )
    {
        printf("error launching accept thread for port.%u\n",port);
        return(-1);
    }
    return(0);
}

void SuperNET_loop(struct supernet_info *myinfo)
{
    struct supernet_agent *ptr; char *buf; int32_t bufsize = 65536 * 32;
    buf = calloc(1,bufsize);
    while ( myinfo->dead == 0 )
    {
        if ( (ptr= queue_dequeue(&myinfo->acceptQ,0)) != 0 )
        {
            if ( myinfo->numagents < sizeof(myinfo->agents)/sizeof(*myinfo->agents)-1 )
            {
                myinfo->agents[myinfo->numagents++] = *ptr;
                free(ptr);
            }
            printf("SuperNET.[%d] got new socket %d for %s:%d\n",myinfo->numagents,ptr->sock,ptr->ipaddr,ptr->port);
        }
        else if ( Supernet_poll(myinfo,(uint8_t *)buf,bufsize,myinfo->agents,myinfo->numagents,myinfo->POLLTIMEOUT) <= 0 )
            usleep(10000);
    }
    free(buf);
}

void SuperNET_main(void *arg)
{
    struct supernet_info MYINFO; int32_t i;//cJSON *json,*array; uint16_t port;,n = 0;
    memset(&MYINFO,0,sizeof(MYINFO));
    if ( 1 )
    {
        strcpy(MYINFO.transport,"tcp");
        strcpy(MYINFO.ipaddr,"127.0.0.1");
        MYINFO.acceptport = SUPERNET_PORT; MYINFO.serviceport = SUPERNET_PORT - 2;
        // SuperNET_init(&MYINFO,arg); parse supernet.conf
        if ( MYINFO.POLLTIMEOUT == 0 )
            MYINFO.POLLTIMEOUT = SUPERNET_POLLTIMEOUT;
    }
    /*if ( arg == 0 || (json= cJSON_Parse(arg)) == 0 )
        SuperNET_acceptport(&MYINFO,MYINFO.acceptport);
    else
    {
        if ( (array= jarray(&n,json,"accept")) != 0 )
        {
            for (i=0; i<n; i++)
                if ( (port= juint(jitem(array,i),0)) != 0 )
                    SuperNET_acceptport(&MYINFO,port);
        }
        free_json(json);
    }*/
    printf("start SuperNET_loop on port.%u\n",SUPERNET_PORT);
    OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)SuperNET_rpcloop,&MYINFO);
    for (i=0; i<sizeof(MYINFO.agents)/sizeof(*MYINFO.agents); i++)
        MYINFO.agents[i].sock = -1;
    SuperNET_loop(&MYINFO);
}
