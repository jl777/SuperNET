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

#include "../crypto777/OS_portable.h"
#include "SuperNET.h"

void SuperNET_rpcloop(void *args)
{
    struct supernet_info *myinfo = args;
    int32_t recvlen,bindsock,postflag,sock,remains,jsonflag,numsent,len; socklen_t clilen;
    char remoteaddr[64],jsonbuf[8192],*buf,*retstr,*space;//,*retbuf; ,n,i,m
    struct sockaddr_in cli_addr; uint32_t ipbits,i; uint16_t port;
    int32_t size = 1024 * 1024 * 2;
    port = SUPERNET_PORT;
    bindsock = iguana_socket(1,"127.0.0.1",port);
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
                    retstr = SuperNET_rpcparse(myinfo,space,size,&jsonflag,&postflag,jsonbuf,remoteaddr);
                    break;
                } else usleep(10000);
            }
        }
        if ( retstr != 0 )
        {
            i = 0;
            if ( postflag == 0 && jsonflag == 0 )
                retstr = SuperNET_htmlresponse(space,size,&remains,1,retstr,1);
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
/*
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
        timeout = SUPERNET_NETWORKTIMEOUT;
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
    printf("redo lbsocket()\n"), exit(-1);
    //strcpy(failsafes[numfailsafes++],"5.9.56.103");
    //strcpy(failsafes[numfailsafes++],"5.9.102.210");
   // n = crackfoo_servers(Cservers,sizeof(Cservers)/sizeof(*Cservers),port);
   // m = badass_servers(Bservers,sizeof(Bservers)/sizeof(*Bservers),port);
    lbsock = _lb_socket(myinfo,port,globalport,relaysport,maxmillis,Bservers,m,Cservers,n*0,failsafes,numfailsafes);
    return(lbsock);
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
    myinfo->lbclient = nn_lbsocket(myinfo,SUPERNET_NETWORKTIMEOUT,SUPERNET_PORT + LB_OFFSET,myinfo->port + PUBGLOBALS_OFFSET,myinfo->port + PUBRELAYS_OFFSET);
    printf("LBclient.%d port.%d\n",myinfo->lbclient,SUPERNET_PORT + LB_OFFSET);
    sprintf(endpoint,"%s://%s:%u",myinfo->transport,myinfo->ipaddr,myinfo->serviceport);
    if ( (myinfo->servicesock= nn_createsocket(myinfo,endpoint,1,"NN_REP",NN_REP,myinfo->serviceport,sendtimeout,recvtimeout)) >= 0 )
        myinfo->pfd[myinfo->numservers++].fd = myinfo->servicesock, printf("numservers.%d\n",myinfo->numservers);
    else printf("error creating servicesock\n");
    for (i=0; i<myinfo->numservers; i++)
        myinfo->pfd[i].events = NN_POLLIN | NN_POLLOUT;
    printf("myinfo->iamrelay %d, numservers.%d ipaddr.(%s://%s) port.%d serviceport.%d\n",myinfo->iamrelay,myinfo->numservers,myinfo->transport,myinfo->ipaddr,myinfo->port,myinfo->serviceport);
}

void SuperNET_init(struct supernet_info *myinfo,char *jsonstr)
{
    char *str;
    if ( jsonstr != 0 && (str= SuperNET_JSON(myinfo,jsonstr)) != 0 )
        free(str);
    busdata_init(myinfo,10,1,0);
    init_SUPERNET_pullsock(myinfo,10,10);
}*/

int32_t Supernet_lineparse(char *key,int32_t keymax,char *value,int32_t valuemax,char *src)
{
    int32_t a,b,c,n = 0;
    key[0] = value[0] = 0;
    while ( (c= src[n]) == ' ' || c == '\t' || c == '\n' || c == '\t' )
        n++;
    while ( (c= src[n]) != ':' && c != 0 )
    {
        *key++ = c;
        if ( ++n >= keymax-1 )
        {
            *key = 0;
            printf("lineparse overflow key.(%s)\n",src);
            return(-1);
        }
    }
    *key = 0;
    if ( src[n] != ':' )
        return(n);
    n++;
    while ( (c= src[n]) == ' ' || c == '\t' )
        n++;
    while ( (c= src[n]) != 0 && c != '\r' && c != '\n' )
    {
        if ( c == '%' && (a= src[n+1]) != 0 && (b= src[n+2]) != 0 )
            c = ((unhex(a) << 4) | unhex(b)), n += 2;
        *value++ = c;
        n++;
        if ( n >= valuemax-1 )
        {
            *value = 0;
            printf("lineparse overflow.(%s)\n",src);
            return(-1);
        }
    }
    *value = 0;
    if ( src[n] != 0 )
    {
        n++;
        while ( (c= src[n]) == '\r' || c == '\n' )
            n++;
    }
    return(n);
}

cJSON *SuperNET_urlconv(char *value,int32_t bufsize,char *urlstr)
{
    int32_t i,n,totallen,datalen,len = 0; cJSON *json,*array; char key[8192],*data;
    json = cJSON_CreateObject();
    array = cJSON_CreateArray();
    totallen = (int32_t)strlen(urlstr);
    while ( 1 )
    {
        for (i=len; urlstr[i]!=0; i++)
            if ( urlstr[i] == '\r' || urlstr[i] == '\n' )
                break;
        if ( i == len && (urlstr[len] == '\r' || urlstr[len] == '\n') )
        {
            len++;
            continue;
        }
        urlstr[i] = 0;
        if ( (n= Supernet_lineparse(key,sizeof(key),value,bufsize,&urlstr[len])) > 0 )
        {
            if ( value[0] != 0 )
                jaddstr(json,key,value);
            else jaddistr(array,key);
            len += (n + 1);
            if ( strcmp(key,"Content-Length") == 0 && (datalen= atoi(value)) > 0 )
            {
                data = &urlstr[totallen - datalen];
                data[-1] = 0;
                //printf("post.(%s) (%c)\n",data,data[0]);
                jaddstr(json,"POST",data);
            }
        } else break;
    }
    jadd(json,"lines",array);
    return(json);
}

char *SuperNET_rpcparse(struct supernet_info *myinfo,char *retbuf,int32_t bufsize,int32_t *jsonflagp,int32_t *postflagp,char *urlstr,char *remoteaddr)
{
    cJSON *tokens,*argjson,*json = 0; char urlmethod[16],*data,url[1024],*retstr,*token = 0; int32_t i,j,n;
    //printf("rpcparse.(%s)\n",urlstr);
    for (i=0; i<sizeof(urlmethod)-1&&urlstr[i]!=0&&urlstr[i]!=' '; i++)
        urlmethod[i] = urlstr[i];
    urlmethod[i++] = 0;
    n = i;
    //printf("URLMETHOD.(%s)\n",urlmethod);
    *postflagp = (strcmp(urlmethod,"POST") == 0);
    for (i=0; i<sizeof(url)-1&&urlstr[n+i]!=0&&urlstr[n+i]!=' '; i++)
        url[i] = urlstr[n+i];
    url[i++] = 0;
    n += i;
    //printf("URL.(%s)\n",url);
    tokens = cJSON_CreateArray();
    j = i = 0;
    if ( strncmp(&url[i],"/api",strlen("/url")) == 0 )
    {
        *jsonflagp = 1;
        i += strlen("/api");
    } else *jsonflagp = 0;
    if ( strncmp(&url[i],"/bitmap",strlen("/bitmap")) == 0 )
    {
        i += strlen("/bitmap");
        *jsonflagp = 2;
        iguana_bitmap(retbuf,bufsize,&url[i]);
        return(retbuf);
    }
    if ( url[i] != '/' )
        token = url;
    for (; url[i]!=0; i++)
    {
        if ( url[i] == '/' )
        {
            url[i] = 0;
            if ( token != 0 )
                jaddistr(tokens,token);
            token = &url[i+1];
            continue;
        }
    }
    if ( token != 0 )
        jaddistr(tokens,token);
    if ( (json= SuperNET_urlconv(retbuf,bufsize,urlstr+n)) != 0 )
    {
        jadd(json,"tokens",tokens);
        jaddstr(json,"urlmethod",urlmethod);
        if ( (data= jstr(json,"POST")) == 0 || (argjson= cJSON_Parse(data)) == 0 )
        {
            argjson = cJSON_CreateObject();
            if ( (n= cJSON_GetArraySize(tokens)) > 0 )
            {
                jaddstr(argjson,"agent",jstri(tokens,0));
                if ( n > 1 )
                    jaddstr(argjson,"method",jstri(tokens,1));
                for (i=2; i<n; i++)
                {
                    if ( i == n-1 )
                        jaddstr(argjson,"data",jstri(tokens,i));
                    else
                    {
                        jaddstr(argjson,jstri(tokens,i),jstri(tokens,i+1));
                        i++;
                    }
                }
            }
        }
        retstr = SuperNET_JSON(myinfo,argjson,remoteaddr);
        printf("(%s) -> (%s) postflag.%d (%s)\n",urlstr,cJSON_Print(json),*postflagp,jprint(argjson,0));
        return(retstr);
    }
    return(clonestr("{\"error\":\"couldnt process packet\"}"));
}

