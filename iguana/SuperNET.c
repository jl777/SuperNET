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

#ifndef MINIGUANA

#include "../crypto777/OS_portable.h"
#include "SuperNET.h"
#include "iguana777.h"

int32_t nn_typelist[] = { NN_REP, NN_REQ, NN_RESPONDENT, NN_SURVEYOR, NN_PUB, NN_SUB, NN_PULL, NN_PUSH, NN_BUS, NN_PAIR };
char *nn_transports[] = { "tcp", "ws", "ipc", "inproc", "tcpmux", "", "", "" };

int32_t SuperNET_msglen(struct supernet_msghdr *msg)
{
    return(msg->serlen[0] + ((int32_t)msg->serlen[1] << 8) + ((int32_t)msg->serlen[2] << 16));
}

int32_t SuperNET_msgvalidate(struct supernet_info *myinfo,struct supernet_msghdr *msg)
{
    int32_t msglen = 0;
    msglen = SuperNET_msglen(msg);
    return(msglen);
}

struct supernet_msghdr *SuperNET_msgcreate(struct supernet_info *myinfo,struct supernet_info *dest,uint8_t type,uint8_t *buf,int32_t maxlen,uint8_t *data,long datalen,uint32_t duration)
{
    uint32_t i,timestamp; struct supernet_msghdr *msg = 0;
    if ( (datalen + sizeof(*msg)) < maxlen )
    {
        msg = (struct supernet_msghdr *)buf;
        memset(msg,0,sizeof(*msg));
        memcpy(msg->data,data,datalen);
        msg->type = type;
        timestamp = (uint32_t)time(NULL);
        for (i=0; i<3; i++)
            msg->serlen[i] = datalen & 0xff, datalen >>= 8;
        for (i=0; i<4; i++)
            msg->ser_timestamp[i] = timestamp & 0xff, timestamp >>= 8;
        for (i=0; i<4; i++)
            msg->ser_duration[i] = duration & 0xff, duration >>= 8;
        // add sig here
    }
    return(msg);
}

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
    static bits256 zero;
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
    if ( (agent->repport= juint(network,"LBport")) > 1000 )
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


int32_t nn_add_LBendpoints(struct supernet_info *myinfo,uint16_t LBport,uint16_t PUBport,int32_t reqsock,int32_t subsock,int32_t priority,char endpoints[][MAX_SERVERNAME],int32_t num)
{
    int32_t i; char endpoint[512]; struct endpoint epbits; uint32_t ipbits;
    if ( num > 0 && endpoints != 0 && nn_setsockopt(reqsock,NN_SOL_SOCKET,NN_SNDPRIO,&priority,sizeof(priority)) >= 0 )
    {
        for (i=0; i<num; i++)
        {
            if ( (ipbits= (uint32_t)calc_ipbits(endpoints[i])) == 0 )
            {
                printf("null ipbits.(%s)\n",endpoints[i]);
                continue;
            }
            //printf("epbits.%llx ipbits.%x %s\n",*(long long *)&epbits,(uint32_t)ipbits,endpoint);
            if ( ismyaddress(myinfo,endpoints[i]) == 0 )
            {
                epbits = calc_epbits("tcp",ipbits,LBport,NN_REP), expand_epbits(endpoint,epbits);
                if ( reqsock >= 0 && nn_connect(reqsock,endpoint) >= 0 )
                    printf("+R%s ",endpoint);
                epbits = calc_epbits("tcp",ipbits,PUBport,NN_PUB), expand_epbits(endpoint,epbits);
                if ( subsock >= 0 && nn_connect(subsock,endpoint) >= 0 )
                    printf("+P%s ",endpoint);
            }
        }
        printf("added priority.%d\n",priority);
        priority++;
    } else printf("error setting priority.%d (%s)\n",priority,nn_errstr());
    return(priority);
}

int32_t _req_socket(struct supernet_info *myinfo,uint16_t LBport,uint16_t PUBport,int32_t subsock,int32_t maxmillis,char endpoints[][MAX_SERVERNAME],int32_t num,char backups[][MAX_SERVERNAME],int32_t numbacks,char failsafes[][MAX_SERVERNAME],int32_t numfailsafes)
{
    int32_t reqsock,timeout,retrymillis,priority = 1;
    if ( (reqsock= nn_socket(AF_SP,NN_REQ)) >= 0 )
    {
        retrymillis = (maxmillis / 30) + 1;
        printf("!!!!!!!!!!!! reqsock.%d !!!!!!!!!!!\n",reqsock);
        if ( nn_setsockopt(reqsock,NN_SOL_SOCKET,NN_RECONNECT_IVL,&retrymillis,sizeof(retrymillis)) < 0 )
            printf("error setting NN_REQ NN_RECONNECT_IVL_MAX socket %s\n",nn_errstr());
        else if ( nn_setsockopt(reqsock,NN_SOL_SOCKET,NN_RECONNECT_IVL_MAX,&maxmillis,sizeof(maxmillis)) < 0 )
            fprintf(stderr,"error setting NN_REQ NN_RECONNECT_IVL_MAX socket %s\n",nn_errstr());
        if ( (timeout= myinfo->networktimeout) == 0 )
            myinfo->networktimeout = 10000;
        if ( 1 && nn_setsockopt(reqsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout)) < 0 )
            printf("error setting NN_SOL_SOCKET NN_RCVTIMEO socket %s\n",nn_errstr());
        timeout = 100;
        if ( 1 && nn_setsockopt(reqsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout)) < 0 )
            printf("error setting NN_SOL_SOCKET NN_SNDTIMEO socket %s\n",nn_errstr());
        if ( num > 0 )
            priority = nn_add_LBendpoints(myinfo,LBport,PUBport,reqsock,subsock,priority,endpoints,num);
        if ( numbacks > 0 )
            priority = nn_add_LBendpoints(myinfo,LBport,PUBport,reqsock,subsock,priority,backups,numbacks);
        if ( numfailsafes > 0 )
            priority = nn_add_LBendpoints(myinfo,LBport,PUBport,reqsock,subsock,priority,failsafes,numfailsafes);
    } else printf("error getting req socket %s\n",nn_errstr());
    //printf("RELAYS.lb.num %d\n",RELAYS.lb.num);
    return(reqsock);
}

int32_t badass_servers(char servers[][MAX_SERVERNAME],int32_t max)
{
    int32_t n = 0;
    strcpy(servers[n++],"89.248.160.237");
    strcpy(servers[n++],"89.248.160.238");
    strcpy(servers[n++],"89.248.160.239");
    strcpy(servers[n++],"89.248.160.240");
    strcpy(servers[n++],"89.248.160.241");
    strcpy(servers[n++],"89.248.160.242");
    strcpy(servers[n++],"89.248.160.243");
    strcpy(servers[n++],"89.248.160.244");
    strcpy(servers[n++],"89.248.160.245");
    return(n);
}

int32_t crackfoo_servers(char servers[][MAX_SERVERNAME],int32_t max)
{
    int32_t n = 0;
    if ( 0 )
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

int32_t nn_reqsocket(struct supernet_info *myinfo,uint16_t LBport,uint16_t PUBport,int32_t subsock,int32_t maxmillis)
{
    char Cservers[32][MAX_SERVERNAME],Bservers[32][MAX_SERVERNAME],failsafes[4][MAX_SERVERNAME];
    int32_t n,m,reqsock,numfailsafes = 0;
    strcpy(failsafes[numfailsafes++],"5.9.102.210");
    n = crackfoo_servers(Cservers,sizeof(Cservers)/sizeof(*Cservers));
    m = badass_servers(Bservers,sizeof(Bservers)/sizeof(*Bservers));
    reqsock = _req_socket(myinfo,LBport,PUBport,subsock,maxmillis,Bservers,m,Cservers,n,failsafes,numfailsafes);
    return(reqsock);
}

void SuperNET_announce(struct supernet_info *myinfo,char *servicename)
{
    struct supernet_msghdr *msg; uint8_t buf[512]; char jsonstr[512],str[65]; long len; uint64_t r;
    OS_randombytes((uint8_t *)&r,sizeof(r));
    sprintf(jsonstr,"{\"agent\":\"SuperNET\",\"method\":\"announce\",\"servicepub\":\"%s\",\"service\":\"%s\",\"tag\":\"%llu\"}",bits256_str(str,myinfo->myaddr.pubkey),servicename,(long long)r);
    len = strlen(jsonstr)+1;
    if ( (msg= SuperNET_msgcreate(myinfo,0,0,buf,sizeof(buf),(uint8_t *)jsonstr,len,0)) != 0 )
    {
        nn_send(myinfo->reqsock,jsonstr,len,0);
    }
}

void SuperNET_recv(struct supernet_info *myinfo,int32_t insock,int32_t LBreq)
{
    int32_t recvlen,datalen; struct supernet_msghdr *msg;
    if ( myinfo->recvbuf == 0 )
        myinfo->recvbuf = calloc(1,SUPERNET_MAXRECVBUF);
    if ( (recvlen= nn_recv(insock,myinfo->recvbuf,SUPERNET_MAXRECVBUF,0)) > 0 )
    {
        msg = (void *)myinfo->recvbuf;
        if ( (datalen= SuperNET_msgvalidate(myinfo,msg)) == 0 )
        {
            printf("superRECV.(%s) len.%d\n",msg->data,datalen);
            if ( myinfo->LBsock >= 0 )
            {
                printf("deal with packet\n");
            }
        }
    }
}

void SuperNET_loop(void *args)
{
    struct supernet_info *myinfo = args;
    while ( 1 )
    {
        if ( (nn_socket_status(myinfo->LBsock,1000) & POLLIN) != 0 )
            SuperNET_recv(myinfo,myinfo->LBsock,1); // req
        else if ( (nn_socket_status(myinfo->subsock,1000) & POLLIN) != 0 )
            SuperNET_recv(myinfo,myinfo->subsock,0); // info update
        else usleep(10000);
        printf("SuperNET_loop\n");
    }
}

void SuperNET_init(struct supernet_info *myinfo,uint16_t PUBport,uint16_t LBport)
{
    int32_t sendtimeout,recvtimeout,len,c; int64_t allocsize; char *ipaddr;
    if ( (ipaddr = OS_filestr(&allocsize,"myipaddr")) != 0 )
    {
        len = (int32_t)strlen(ipaddr) - 1;
        while ( len > 8 && ((c= ipaddr[len]) == '\r' || c == '\n' || c == ' ' || c == '\t') )
            ipaddr[len] = 0, len--;
        if ( is_ipaddr(ipaddr) != 0 )
            strcpy(myinfo->ipaddr,ipaddr);
        free(ipaddr), ipaddr = 0;
    }
    sendtimeout = 100;
    recvtimeout = 1000;
    myinfo->PUBpoint[0] = myinfo->LBpoint[0] = 0;
    myinfo->PUBport = myinfo->LBport = 0;
    myinfo->PUBsock = myinfo->LBsock = -1;
    strcpy(myinfo->transport,"tcp");
    if ( PUBport == 0 )
        PUBport = SUPERNET_PUBPORT;
    if ( LBport == 0 )
        LBport = SUPERNET_LBPORT;
    if ( (myinfo->PUBport= PUBport) != 0 )
    {
        myinfo->subsock = nn_createsocket(myinfo,0,0,"NN_SUB",NN_SUB,0,sendtimeout,recvtimeout);
        nn_setsockopt(myinfo->subsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
        if ( ipaddr != 0 )
            myinfo->PUBsock = nn_createsocket(myinfo,myinfo->PUBpoint,1,"NN_PUB",NN_PUB,myinfo->PUBport,sendtimeout,recvtimeout);
    } else myinfo->subsock = -1;
    if ( (myinfo->LBport= LBport) != 0 )
    {
        myinfo->reqsock = nn_reqsocket(myinfo,myinfo->LBport,myinfo->PUBport,myinfo->subsock,60000);
        if ( ipaddr != 0 )
            myinfo->LBsock = nn_createsocket(myinfo,myinfo->LBpoint,1,"NN_REP",NN_REP,myinfo->LBport,sendtimeout,recvtimeout);
    } else myinfo->reqsock = -1;
    if ( myinfo->LBsock >= 0 || myinfo->PUBsock >= 0 )
    {
        iguana_launch(iguana_coinadd("BTCD"),"SuperNET",SuperNET_loop,myinfo,IGUANA_PERMTHREAD);
        SuperNET_announce(myinfo,"ramchain");
    } else SuperNET_announce(myinfo,"pangea");
}

#endif
