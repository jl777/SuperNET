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

#include "SuperNET.h"
#ifdef later

int32_t nn_typelist[] = { NN_REP, NN_REQ, NN_RESPONDENT, NN_SURVEYOR, NN_PUB, NN_SUB, NN_PULL, NN_PUSH, NN_BUS, NN_PAIR };
char *nn_transports[] = { "tcp", "ws", "ipc", "inproc", "tcpmux", "tbd1", "tbd2", "tbd3" };

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

int32_t ismyaddress(char *server,struct supernet_info *myinfo)
{
    uint32_t ipbits;
    if ( strncmp(server,"tcp://",6) == 0 )
        server += 6;
    else if ( strncmp(server,"ws://",5) == 0 )
        server += 5;
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

int32_t nn_socket_status(int32_t sock,int32_t timeoutmillis)
{
    struct nn_pollfd pfd;
    int32_t rc;
    pfd.fd = sock;
    pfd.events = NN_POLLIN | NN_POLLOUT;
    if ( (rc= nn_poll(&pfd,1,timeoutmillis)) == 0 )
        return(pfd.revents);
    else return(-1);
}

struct endpoint find_epbits(struct relay_info *list,uint32_t ipbits,uint16_t port,int32_t type)
{
    int32_t i; struct endpoint epbits;
    memset(&epbits,0,sizeof(epbits));
    if ( list != 0 && list->num > 0 )
    {
        if ( type >= 0 )
            type = nn_portoffset(type);
        for (i=0; i<list->num&&i<(int32_t)(sizeof(list->connections)/sizeof(*list->connections)); i++)
            if ( list->connections[i].ipbits == ipbits && (port == 0 || port == list->connections[i].port)  && (type < 0 || type == list->connections[i].nn) )
                return(list->connections[i]);
    }
    return(epbits);
}

int32_t add_relay(struct relay_info *list,struct endpoint epbits)
{
    list->connections[list->num % (sizeof(list->connections)/sizeof(*list->connections))] = epbits, list->num++;
    if ( list->num > (sizeof(list->connections)/sizeof(*list->connections)) )
        printf("add_relay warning num.%d > %ld\n",list->num,(long)(sizeof(list->connections)/sizeof(*list->connections)));
    return(list->num);
}

int32_t nn_add_lbservers(struct supernet_info *myinfo,uint16_t port,uint16_t globalport,uint16_t relaysport,int32_t priority,int32_t sock,char servers[][MAX_SERVERNAME],int32_t num)
{
    int32_t i; char endpoint[512],pubendpoint[512]; struct endpoint epbits; uint32_t ipbits;
    if ( num > 0 && servers != 0 && nn_setsockopt(sock,NN_SOL_SOCKET,NN_SNDPRIO,&priority,sizeof(priority)) >= 0 )
    {
        for (i=0; i<num; i++)
        {
            if ( (ipbits= (uint32_t)calc_ipbits(servers[i])) == 0 )
            {
                printf("null ipbits.(%s)\n",servers[i]);
                continue;
            }
            //printf("epbits.%llx ipbits.%x %s\n",*(long long *)&epbits,(uint32_t)ipbits,endpoint);
            if ( ismyaddress(servers[i],myinfo) == 0 )
            {
                epbits = calc_epbits("tcp",ipbits,port,NN_REP);
                expand_epbits(endpoint,epbits);
                if ( nn_connect(sock,endpoint) >= 0 )
                {
                    printf("+R%s ",endpoint);
                    add_relay(&myinfo->active,epbits);
                }
                if ( myinfo->subclient >= 0 )
                {
                    if ( myinfo->iamrelay != 0 )
                    {
                        epbits = calc_epbits("tcp",ipbits,relaysport,NN_PUB);
                        expand_epbits(pubendpoint,epbits);
                        if ( nn_connect(myinfo->subclient,pubendpoint) >= 0 )
                            printf("+P%s ",pubendpoint);
                    }
                    epbits = calc_epbits("tcp",ipbits,globalport,NN_PUB);
                    expand_epbits(pubendpoint,epbits);
                    if ( nn_connect(myinfo->subclient,pubendpoint) >= 0 )
                        printf("+P%s ",pubendpoint);
                }
            }
        }
        printf("added priority.%d\n",priority);
        priority++;
    } else printf("error setting priority.%d (%s)\n",priority,nn_errstr());
    return(priority);
}

int32_t _lb_socket(struct supernet_info *myinfo,uint16_t port,uint16_t globalport,uint16_t relaysport,int32_t maxmillis,char servers[][MAX_SERVERNAME],int32_t num,char backups[][MAX_SERVERNAME],int32_t numbacks,char failsafes[][MAX_SERVERNAME],int32_t numfailsafes)
{
    int32_t lbsock,timeout,retrymillis,priority = 1;
    if ( (lbsock= nn_socket(AF_SP,NN_REQ)) >= 0 )
    {
        retrymillis = (maxmillis / 30) + 1;
        printf("!!!!!!!!!!!! lbsock.%d !!!!!!!!!!!\n",lbsock);
        if ( nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_RECONNECT_IVL,&retrymillis,sizeof(retrymillis)) < 0 )
            printf("error setting NN_REQ NN_RECONNECT_IVL_MAX socket %s\n",nn_errstr());
        else if ( nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_RECONNECT_IVL_MAX,&maxmillis,sizeof(maxmillis)) < 0 )
            fprintf(stderr,"error setting NN_REQ NN_RECONNECT_IVL_MAX socket %s\n",nn_errstr());
        timeout = SUPERNET_TIMEOUT;
        if ( 1 && nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout)) < 0 )
            printf("error setting NN_SOL_SOCKET NN_RCVTIMEO socket %s\n",nn_errstr());
        timeout = 100;
        if ( 1 && nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout)) < 0 )
            printf("error setting NN_SOL_SOCKET NN_SNDTIMEO socket %s\n",nn_errstr());
        if ( num > 0 )
            priority = nn_add_lbservers(myinfo,port,globalport,relaysport,priority,lbsock,servers,num);
        if ( numbacks > 0 )
            priority = nn_add_lbservers(myinfo,port,globalport,relaysport,priority,lbsock,backups,numbacks);
        if ( numfailsafes > 0 )
            priority = nn_add_lbservers(myinfo,port,globalport,relaysport,priority,lbsock,failsafes,numfailsafes);
    } else printf("error getting req socket %s\n",nn_errstr());
    //printf("myinfo->lb.num %d\n",myinfo->lb.num);
    return(lbsock);
}

int32_t nn_lbsocket(struct supernet_info *myinfo,int32_t maxmillis,int32_t port,uint16_t globalport,uint16_t relaysport)
{
    char Cservers[32][MAX_SERVERNAME],Bservers[32][MAX_SERVERNAME],failsafes[4][MAX_SERVERNAME];
    int32_t n,m,lbsock,numfailsafes = 0;
    //strcpy(failsafes[numfailsafes++],"5.9.56.103");
    //strcpy(failsafes[numfailsafes++],"5.9.102.210");
    n = crackfoo_servers(Cservers,sizeof(Cservers)/sizeof(*Cservers),port);
    m = badass_servers(Bservers,sizeof(Bservers)/sizeof(*Bservers),port);
    lbsock = _lb_socket(myinfo,port,globalport,relaysport,maxmillis,Bservers,m,Cservers,n*0,failsafes,numfailsafes);
    return(lbsock);
}

int32_t nn_settimeouts(int32_t sock,int32_t sendtimeout,int32_t recvtimeout)
{
    int32_t retrymillis,maxmillis;
    if ( (maxmillis= SUPERNET_TIMEOUT) == 0 )
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
    else if ( bindflag == 0 && endpoint[0] != 0 )
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

void add_standard_fields(char *request)
{
    cJSON *json; uint64_t tag;
    if ( (json= cJSON_Parse(request)) != 0 )
    {
        if ( get_API_nxt64bits(cJSON_GetObjectItem(json,"NXT")) == 0 )
        {
            randombytes((void *)&tag,sizeof(tag));
            sprintf(request + strlen(request) - 1,",\"NXT\":\"%s\",\"tag\":\"%llu\"}",myinfo->NXTADDR,(long long)tag);
            if ( myinfo->iamrelay != 0 && (myinfo->hostname[0] != 0 || myinfo->ipaddr[0] != 0) )
                sprintf(request + strlen(request) - 1,",\"iamrelay\":\"%s\"}",myinfo->hostname[0]!=0?myinfo->hostname:myinfo->myipaddr);
        }
        free_json(json);
    }
}
#endif

char *nn_loadbalanced(struct supernet_info *myinfo,uint8_t *data,int32_t len)
{
    char *msg,*jsonstr = 0;
    int32_t sendlen,i,lbsock,recvlen = 0;
    if ( (lbsock= myinfo->lbclient) < 0 )
        return(clonestr("{\"error\":\"invalid load balanced socket\"}"));
    for (i=0; i<10; i++)
        if ( (nn_socket_status(lbsock,1) & NN_POLLOUT) != 0 )
            break;
    if ( myinfo->Debuglevel > 2 )
        printf("sock.%d NN_LBSEND.(%s)\n",lbsock,data);
    //fprintf(stderr,"send to network\n");
    if ( (sendlen= nn_send(lbsock,data,len,0)) == len )
    {
        for (i=0; i<10; i++)
            if ( (nn_socket_status(lbsock,1) & NN_POLLIN) != 0 )
                break;
        if ( (recvlen= nn_recv(lbsock,&msg,NN_MSG,0)) > 0 )
        {
            if ( myinfo->Debuglevel > 2 )
                printf("LBRECV.(%s)\n",msg);
            jsonstr = clonestr((char *)msg);
            nn_freemsg(msg);
        }
        else
        {
            printf("nn_loadbalanced got recvlen.%d %s\n",recvlen,nn_errstr());
            jsonstr = clonestr("{\"error\":\"lb recv error, probably timeout\"}");
        }
    } else printf("got sendlen.%d instead of %d %s\n",sendlen,len,nn_errstr()), jsonstr = clonestr("{\"error\":\"lb send error\"}");
    return(jsonstr);
}

cJSON *relay_json(struct relay_info *list)
{
    cJSON *json,*array; char endpoint[512]; int32_t i;
    if ( list == 0 || list->num == 0 )
        return(0);
    array = cJSON_CreateArray();
    for (i=0; i<list->num&&i<(int32_t)(sizeof(list->connections)/sizeof(*list->connections)); i++)
    {
        expand_epbits(endpoint,list->connections[i]);
        jaddistr(array,endpoint);
    }
    json = cJSON_CreateObject();
    jadd(json,"endpoints",array);
    //cJSON_AddItemToObject(json,"type",cJSON_CreateString(nn_typestr(list->mytype)));
    //cJSON_AddItemToObject(json,"dest",cJSON_CreateString(nn_typestr(list->desttype)));
    jaddnum(json,"total",list->num);
    return(json);
}

char *relays_jsonstr(struct supernet_info *myinfo,char *jsonstr,cJSON *argjson)
{
    cJSON *json;
    if ( myinfo->iamrelay != 0 && myinfo->ipaddr[0] != 0 )
    {
        json = cJSON_CreateObject();
        jaddstr(json,"relay",myinfo->ipaddr);
        if ( myinfo->active.num > 0 )
            jadd(json,"relays",relay_json(&myinfo->active));
        return(jprint(json,1));
    }
    else return(clonestr("{\"error\":\"get relay list from relay\"}"));
}

int32_t init_SUPERNET_pullsock(struct supernet_info *myinfo,int32_t sendtimeout,int32_t recvtimeout)
{
    char bindaddr[64],*transportstr; int32_t iter;
    myinfo->pullsock = -1;
    if ( (myinfo->pullsock= nn_socket(AF_SP,NN_PULL)) < 0 )
    {
        printf("error creating pullsock %s\n",nn_strerror(nn_errno()));
        return(-1);
    }
    printf("got pullsock.%d\n",myinfo->pullsock);
    if ( nn_settimeouts(myinfo->pullsock,sendtimeout,recvtimeout) < 0 )
    {
        printf("error settime pullsock timeouts %s\n",nn_strerror(nn_errno()));
        return(-1);
    }
    printf("PULLsock.%d\n",myinfo->pullsock);
    for (iter=0; iter<2; iter++)
    {
        transportstr = (iter == 0) ? "ipc" : "inproc";
        sprintf(bindaddr,"%s://SuperNET.agents",transportstr);
        if ( nn_bind(myinfo->pullsock,bindaddr) < 0 )
        {
            printf("error binding pullsock to (%s) %s\n",bindaddr,nn_strerror(nn_errno()));
            return(-1);
        }
    }
    return(0);
}

void busdata_init(struct supernet_info *myinfo,int32_t sendtimeout,int32_t recvtimeout,int32_t firstiter)
{
    char endpoint[512]; int32_t i;
    myinfo->servicesock = myinfo->pubglobal = myinfo->pubrelays = myinfo->lbserver = -1;
    endpoint[0] = 0;
    if ( (myinfo->subclient= nn_createsocket(myinfo,endpoint,0,"NN_SUB",NN_SUB,0,sendtimeout,recvtimeout)) >= 0 )
    {
        myinfo->pfd[myinfo->numservers++].fd = myinfo->subclient, printf("numservers.%d\n",myinfo->numservers);
        nn_setsockopt(myinfo->subclient,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
    } else printf("error creating subclient\n");
    myinfo->lbclient = nn_lbsocket(myinfo,SUPERNET_TIMEOUT,SUPERNET_PORT + LB_OFFSET,myinfo->port + PUBGLOBALS_OFFSET,myinfo->port + PUBRELAYS_OFFSET);
    printf("LBclient.%d port.%d\n",myinfo->lbclient,SUPERNET_PORT + LB_OFFSET);
    sprintf(endpoint,"%s://%s:%u",myinfo->transport,myinfo->ipaddr,myinfo->serviceport);
    if ( (myinfo->servicesock= nn_createsocket(myinfo,endpoint,1,"NN_REP",NN_REP,myinfo->serviceport,sendtimeout,recvtimeout)) >= 0 )
        myinfo->pfd[myinfo->numservers++].fd = myinfo->servicesock, printf("numservers.%d\n",myinfo->numservers);
    else printf("error creating servicesock\n");
    for (i=0; i<myinfo->numservers; i++)
        myinfo->pfd[i].events = NN_POLLIN | NN_POLLOUT;
    printf("myinfo->iamrelay %d, numservers.%d ipaddr.(%s://%s) port.%d serviceport.%d\n",myinfo->iamrelay,myinfo->numservers,myinfo->transport,myinfo->ipaddr,myinfo->port,myinfo->serviceport);
}
#endif

char *SuperNET_JSON(struct supernet_info *myinfo,char *jsonstr)
{
    return(clonestr("{\"error\":\"SuperNET is just a stub for now\"}"));
}

void SuperNET_init(struct supernet_info *myinfo,char *jsonstr)
{
    char *str;
    if ( jsonstr != 0 && (str= SuperNET_JSON(myinfo,jsonstr)) != 0 )
        free(str);
    //busdata_init(myinfo,10,1,0);
    //init_SUPERNET_pullsock(myinfo,10,10);
}

