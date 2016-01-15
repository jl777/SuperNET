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

// maxlen of 7!
#define SUPERNET_RAMCHAIN "rmchain"
#define SUPERNET_PANGEA "pangea"
#define SUPERNET_BITCOIN "bitcoin"

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

struct supernet_msghdr *SuperNET_msgcreate(struct supernet_info *myinfo,uint8_t type,bits256 *senderpub,bits256 *destpub,struct supernet_msghdr *msg,int32_t maxlen,char *agent,uint8_t *data,long datalen,uint32_t duration,uint32_t nonce)
{
    uint32_t i,len,timestamp;
    if ( (datalen + sizeof(*msg)) <= maxlen )
    {
        memset(msg,0,sizeof(*msg));
        if ( datalen > 0 )
        {
            if ( msg->data != data )
                memcpy(msg->data,data,datalen);
            else printf("no need to self-copy\n");
        }
        if ( destpub != 0 )
            msg->dest = *destpub;
        if ( senderpub != 0 )
            msg->sender = *senderpub;
        msg->type = type;
        if ( (len= (int32_t)strlen(agent)) > 7 )
            len = 7;
        memcpy(msg->agent,agent,len);
        timestamp = (uint32_t)time(NULL);
        for (i=0; i<3; i++)
            msg->serlen[i] = datalen & 0xff, datalen >>= 8;
        iguana_rwnum(1,msg->ser_nonce,sizeof(nonce),&nonce);
        iguana_rwnum(1,msg->ser_timestamp,sizeof(timestamp),&timestamp);
        iguana_rwnum(1,msg->ser_duration,sizeof(duration),&duration);
         // add sig here
        return(msg);
    } else printf("datalen.%ld + %ld vs maxlen.%d\n",datalen,sizeof(*msg),maxlen);
    return(0);
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
            expand_epbits(endpoint,calc_epbits(myinfo->transport,(uint32_t)calc_ipbits(myinfo->ipaddr),port,type));
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
    if ( strcmp(H->agent,"register") == 0 )
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
                    printf("+%s ",endpoint);
                epbits = calc_epbits("tcp",ipbits,PUBport,NN_PUB), expand_epbits(endpoint,epbits);
                if ( subsock >= 0 && nn_connect(subsock,endpoint) >= 0 )
                    printf("+%s ",endpoint);
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
            timeout = 10000;
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
    if ( 1 )
    {
        strcpy(servers[n++],"89.248.160.237");
        strcpy(servers[n++],"89.248.160.238");
        strcpy(servers[n++],"89.248.160.239");
        strcpy(servers[n++],"89.248.160.240");
        strcpy(servers[n++],"89.248.160.241");
        strcpy(servers[n++],"89.248.160.242");
        strcpy(servers[n++],"89.248.160.243");
        strcpy(servers[n++],"89.248.160.244");
        strcpy(servers[n++],"89.248.160.245");
    }
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

int32_t SuperNET_send(struct supernet_info *myinfo,int32_t sock,bits256 *dest,uint8_t type,struct supernet_msghdr *msg,char *agent,uint8_t *data,int32_t datalen,uint32_t duration,uint32_t nonce)
{
    int32_t sendlen = -1;
    if ( nonce == 0 )
        OS_randombytes((void *)&nonce,sizeof(nonce));
    if ( (msg= SuperNET_msgcreate(myinfo,type,&myinfo->myaddr.pubkey,dest,msg,sizeof(*msg)+datalen,agent,data,datalen,duration,nonce)) != 0 )
    {
        //for (i=0; i<10; i++)
        //    if ( (nn_socket_status(sock,1) & NN_POLLOUT) != 0 )
        //        break;
        if ( (sendlen= nn_send(sock,msg,sizeof(*msg)+datalen,0)) != sizeof(*msg)+datalen )
            printf("SuperNET_send sendlen.%d != len.%ld\n",sendlen,sizeof(*msg)+datalen);
        else printf("SuperNET_send.(%s).%u sendlen.%d\n",msg->agent,nonce,sendlen);
    } else printf("error creating %s.msg\n",agent);
    return(sendlen);
}

struct supernet_msghdr *SuperNET_msgnonce(struct supernet_info *myinfo,struct supernet_msghdr *msg,uint32_t nonce)
{
    static struct supernet_msghdr *msgs[1024];
    int32_t i,datalen,allocsize,checknonce;
    if ( msg != 0 )
    {
        datalen = SuperNET_msglen(msg);
        allocsize = datalen + (int32_t)sizeof(*msg);
        for (i=0; i<sizeof(msgs)/sizeof(*msgs); i++)
        {
            if ( msgs[i] == 0 )
            {
                msgs[i] = calloc(1,allocsize);
                memcpy(msgs[i],msg,allocsize);
                printf("associate datalen.%d with nonce.%u\n",datalen,nonce);
                return(msg);
            }
            else if ( memcmp(msgs[i],msg,sizeof(*msg)) == 0 )
            {
                printf("msgnonce.%u got duplicate\n",nonce);
                return(msg);
            }
        }
        printf("no space left\n");
        return(0);
    }
    else
    {
        for (i=0; i<sizeof(msgs)/sizeof(*msgs); i++)
        {
            if ( (msg= msgs[i]) != 0 )
            {
                iguana_rwnum(0,msg->ser_nonce,sizeof(checknonce),&checknonce);
                if ( checknonce == nonce )
                {
                    msgs[i] = msgs[sizeof(msgs)/sizeof(*msgs) - 1];
                    msgs[sizeof(msgs)/sizeof(*msgs) - 1] = 0;
                    printf("found msg.%u\n",nonce);
                    return(msg);
                } else printf("i.%d: %u vs check.%u\n",i,nonce,checknonce);
            }
        }
        printf("cant find nonce.%u\n",nonce);
        return(0);
    }
}

void SuperNET_msgresponse(struct supernet_info *myinfo,struct supernet_msghdr *msg,struct supernet_msghdr *retmsg)
{
    uint32_t nonce,retlen,flag = 0;
    retlen = SuperNET_msglen(retmsg);
    iguana_rwnum(0,retmsg->ser_nonce,sizeof(nonce),&nonce);
    if ( msg == 0 )
        msg = SuperNET_msgnonce(myinfo,0,nonce), flag = 1;
    if ( msg != 0 )
    {
        printf("Got response to (%s).%u retlen.%d\n",msg->agent,nonce,retlen);
        if ( flag != 0 )
            free(msg);
    } else printf("cant find nonce.%u\n",nonce);
}

int32_t SuperNET_reqhandler(struct supernet_info *myinfo,struct supernet_msghdr *retmsg,int32_t maxlen,struct supernet_msghdr *msg,int32_t datalen)
{
    uint32_t nonce,timestamp,duration; int32_t retdatalen;
    iguana_rwnum(0,msg->ser_timestamp,sizeof(timestamp),&timestamp);
    iguana_rwnum(0,msg->ser_duration,sizeof(duration),&duration);
    iguana_rwnum(0,msg->ser_nonce,sizeof(nonce),&nonce);
    retdatalen = 0;
    printf("reqhandle.(%c) (%s) datalen.%d t%u:%d nonce.%u retdatalen.%d\n",msg->type,msg->agent,datalen,timestamp,duration,nonce,retdatalen);
    if ( (retmsg= SuperNET_msgcreate(myinfo,'R',&myinfo->myaddr.pubkey,bits256_nonz(msg->dest)>0?&msg->dest:0,retmsg,sizeof(*retmsg)+retdatalen,msg->agent,retmsg->data,retdatalen,60,nonce)) != 0 )
    {
        return(retdatalen);
    }
    return(-1);
}

int32_t SuperNET_LBrequest(struct supernet_info *myinfo,bits256 *dest,uint8_t type,char *agent,uint8_t *data,int32_t datalen,int32_t duration)
{
    struct supernet_msghdr *msg,*retmsg; int32_t i,sendlen,recvlen,sock; uint32_t nonce;
    if ( (sock= myinfo->reqsock) < 0 )
    {
        printf("SuperNET_LBrequest no reqsock for.(%s)\n",agent);
        return(-1);
    }
    if ( myinfo->recvbuf[1] == 0 )
        myinfo->recvbuf[1] = calloc(1,SUPERNET_MAXRECVBUF+sizeof(*msg));
    if ( myinfo->recvbuf[4] == 0 )
        myinfo->recvbuf[4] = calloc(1,SUPERNET_MAXRECVBUF+sizeof(*msg));
    if ( myinfo->recvbuf[5] == 0 )
        myinfo->recvbuf[5] = calloc(1,SUPERNET_MAXRECVBUF+sizeof(*msg));
    msg = (void *)myinfo->recvbuf[4];
    if ( (sendlen= SuperNET_send(myinfo,sock,dest,type,msg,agent,data,datalen,duration,0)) == datalen+sizeof(*msg) )
    {
        retmsg = (void *)myinfo->recvbuf[1];
        iguana_rwnum(0,msg->ser_nonce,sizeof(nonce),&nonce);
        //for (i=0; i<10; i++)
        //    if ( (nn_socket_status(sock,1) & NN_POLLIN) != 0 )
        //        break;
        if ( (recvlen= nn_recv(sock,retmsg,SUPERNET_MAXRECVBUF,0)) > 0 )
        {
            printf("LBrequest recvlen.%d nonce.%u\n",recvlen,nonce);
            if ( retmsg->type == 'R' )
                SuperNET_msgresponse(myinfo,msg,retmsg);
            else if ( retmsg->type == 'F' )
                SuperNET_msgnonce(myinfo,msg,nonce);
            else if ( retmsg->type == 'E' )
                printf("error sending LBrequest.(%s) datalen.%d\n",agent,datalen);
        }
        else
        {
            SuperNET_msgnonce(myinfo,msg,nonce);
            printf("LBrequest recvlen.%d\n",recvlen);
        }
    }
    return(sendlen);
}

void SuperNET_recv(struct supernet_info *myinfo,int32_t sock,int32_t LBreq)
{
    int32_t i,recvlen,datalen,retlen,type; uint32_t nonce,duration,timestamp; uint8_t *retbuf; struct supernet_msghdr *msg;
    LBreq <<= 1;
    if ( myinfo->recvbuf[LBreq] == 0 )
        myinfo->recvbuf[LBreq] = calloc(1,SUPERNET_MAXRECVBUF+sizeof(*msg));
    if ( myinfo->recvbuf[LBreq + 1] == 0 )
        myinfo->recvbuf[LBreq + 1] = calloc(1,SUPERNET_MAXRECVBUF+sizeof(*msg));
    //for (i=0; i<10; i++)
    //    if ( (nn_socket_status(sock,1) & NN_POLLIN) != 0 )
    //        break;
    if ( (recvlen= nn_recv(sock,myinfo->recvbuf[LBreq],SUPERNET_MAXRECVBUF,0)) > 0 )
    {
        msg = (void *)myinfo->recvbuf[LBreq];
        iguana_rwnum(0,msg->ser_timestamp,sizeof(timestamp),&timestamp);
        iguana_rwnum(0,msg->ser_duration,sizeof(duration),&duration);
        iguana_rwnum(0,msg->ser_nonce,sizeof(nonce),&nonce);
        printf(">>>>>>>>>>>>>>>>>>>>>>>> superRECV.(%s) len.%d LBreq.%d nonce.%u\n",msg->agent,recvlen,LBreq,nonce);
        if ( (datalen= SuperNET_msgvalidate(myinfo,msg)) >= 0 )
        {
            retbuf = myinfo->recvbuf[LBreq + 1];
            if ( LBreq != 0 )
            {
                if ( (retlen= SuperNET_reqhandler(myinfo,(struct supernet_msghdr *)&retbuf[sizeof(*msg)],SUPERNET_MAXRECVBUF,msg,datalen)) < 0 )
                {
                    if ( myinfo->PUBsock >= 0 && SuperNET_send(myinfo,myinfo->PUBsock,bits256_nonz(msg->dest)>0?&msg->dest:0,tolower(msg->type),(void *)msg,msg->agent,msg->data,datalen,duration,nonce) != sizeof(*msg)+datalen )
                        type = 'E';
                    else type = 'F';
                    retlen = 0;
                } else type = 'R'; // request handled locally
                printf("respond.%c %u -> sock.%d\n",type,nonce,sock);
                SuperNET_send(myinfo,sock,&msg->sender,type,(struct supernet_msghdr *)retbuf,msg->agent,&retbuf[sizeof(*msg)],retlen,60,nonce);
            }
            else if ( myinfo->PUBsock >= 0 )
            {
                printf("publisher received len.%d\n",datalen);
                if ( (retlen= SuperNET_reqhandler(myinfo,(struct supernet_msghdr *)&retbuf[sizeof(*msg)],SUPERNET_MAXRECVBUF,msg,datalen)) >= 0 ) // forwarded request handled
                {
                    SuperNET_send(myinfo,myinfo->PUBsock,&msg->sender,'R',(struct supernet_msghdr *)retbuf,msg->agent,&retbuf[sizeof(*msg)],retlen,60,nonce);
                } // else nothing to do
            }
            else // originator's subsock
            {
                printf("subsock received len.%d type.%c\n",datalen,msg->type);
                if ( msg->type == 'R' || bits256_nonz(msg->dest) == 0 || memcmp(msg->dest.bytes,myinfo->myaddr.pubkey.bytes,sizeof(msg->dest)) == 0 )
                {
                    SuperNET_msgresponse(myinfo,0,msg);
                }
            }
        } else printf("recv error.%d\n",recvlen);
    } else printf("nn_recv error %d %s\n",recvlen,nn_strerror(nn_errno()));
}

void SuperNET_subloop(void *args)
{
    struct supernet_info *myinfo = args;
    printf("start SuperNET_subloop\n");
    while ( myinfo->subsock >= 0 )
    {
        SuperNET_recv(myinfo,myinfo->subsock,0); // req
        //printf("SuperNET_subloop\n");
    }
}

void SuperNET_loop(void *args)
{
    struct supernet_info *myinfo = args;
    printf("start SuperNET_loop\n");
    while ( myinfo->LBsock >= 0 )
    {
        SuperNET_recv(myinfo,myinfo->LBsock,1); // req
        //printf("SuperNET_loop\n");
    }
}

void SuperNET_init(struct supernet_info *myinfo,uint16_t PUBport,uint16_t LBport)
{
    int32_t i,sendtimeout,recvtimeout,len,c; int64_t allocsize; char *ipaddr;
    if ( (ipaddr= OS_filestr(&allocsize,"ipaddr")) != 0 )
    {
        printf("got ipaddr.(%s)\n",ipaddr);
        len = (int32_t)strlen(ipaddr) - 1;
        while ( len > 8 && ((c= ipaddr[len]) == '\r' || c == '\n' || c == ' ' || c == '\t') )
            ipaddr[len] = 0, len--;
        printf("got ipaddr.(%s) %x\n",ipaddr,is_ipaddr(ipaddr));
        if ( is_ipaddr(ipaddr) != 0 )
            strcpy(myinfo->ipaddr,ipaddr);
        else free(ipaddr), ipaddr = 0;
    }
    sendtimeout = 100;
    recvtimeout = 30000;
    myinfo->PUBpoint[0] = myinfo->LBpoint[0] = 0;
    myinfo->PUBport = myinfo->LBport = 0;
    myinfo->PUBsock = myinfo->LBsock = -1;
    OS_randombytes(myinfo->myaddr.pubkey.bytes,sizeof(myinfo->myaddr.pubkey));
    strcpy(myinfo->transport,"tcp");
    if ( PUBport == 0 )
        PUBport = SUPERNET_PUBPORT;
    if ( LBport == 0 )
        LBport = SUPERNET_LBPORT;
    if ( (myinfo->PUBport= PUBport) != 0 )
    {
        myinfo->subsock = nn_createsocket(myinfo,0,0,"NN_SUB",NN_SUB,0,sendtimeout,0*recvtimeout);
        nn_setsockopt(myinfo->subsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
        if ( ipaddr != 0 )
            myinfo->PUBsock = nn_createsocket(myinfo,myinfo->PUBpoint,1,"NN_PUB",NN_PUB,myinfo->PUBport,sendtimeout,recvtimeout);
    } else myinfo->subsock = -1;
    if ( (myinfo->LBport= LBport) != 0 )
    {
        myinfo->reqsock = nn_reqsocket(myinfo,myinfo->LBport,myinfo->PUBport,myinfo->subsock,60000);
        if ( ipaddr != 0 )
            myinfo->LBsock = nn_createsocket(myinfo,myinfo->LBpoint,1,"NN_REP",NN_REP,myinfo->LBport,sendtimeout,0*recvtimeout);
    } else myinfo->reqsock = -1;
    iguana_launch(iguana_coinadd("BTCD"),"SuperNET_sub",SuperNET_subloop,myinfo,IGUANA_PERMTHREAD);
    if ( myinfo->LBsock >= 0 || myinfo->PUBsock >= 0 )
    {
        iguana_launch(iguana_coinadd("BTCD"),"SuperNET",SuperNET_loop,myinfo,IGUANA_PERMTHREAD);
        /*SuperNET_LBrequest(myinfo,0,'A',SUPERNET_RAMCHAIN,0,0,0);
        for (i=0; i<1000; i++)
        {
            SuperNET_LBrequest(myinfo,0,'A',SUPERNET_RAMCHAIN,0,0,0);
            sleep(10);
        }*/
    }
    else
    {
        double startmillis = OS_milliseconds();
        for (i=0; i<1000; i++)
        {
            SuperNET_LBrequest(myinfo,0,'A',SUPERNET_PANGEA,0,0,0);
            printf("%d: %.3f [%.4f]\n",i,OS_milliseconds() - startmillis,(OS_milliseconds() - startmillis)/(i+1));
            //sleep(10);
        }
    }
    printf("%s LBsock.%d %d, %s PUBsock.%d %d\n",myinfo->LBpoint,myinfo->LBsock,myinfo->reqsock,myinfo->PUBpoint,myinfo->PUBsock,myinfo->subsock);
}

#endif
