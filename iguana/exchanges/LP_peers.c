
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
//  LP_peers.c
//  marketmaker
//

struct LP_peerinfo *LP_peerfind(uint32_t ipbits,uint16_t port)
{
    struct LP_peerinfo *peer=0; uint64_t ip_port;
    ip_port = ((uint64_t)port << 32) | ipbits;
    portable_mutex_lock(&LP_peermutex);
    HASH_FIND(hh,LP_peerinfos,&ip_port,sizeof(ip_port),peer);
    portable_mutex_unlock(&LP_peermutex);
    return(peer);
}

cJSON *LP_peerjson(struct LP_peerinfo *peer)
{
    cJSON *item = cJSON_CreateObject();
    jaddstr(item,"ipaddr",peer->ipaddr);
    jaddnum(item,"port",peer->port);
    jaddnum(item,"profit",peer->profitmargin);
    return(item);
}

char *LP_peers()
{
    struct LP_peerinfo *peer,*tmp; cJSON *peersjson = cJSON_CreateArray();
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        jaddi(peersjson,LP_peerjson(peer));
    }
    return(jprint(peersjson,1));
}

struct LP_peerinfo *LP_addpeer(int32_t amclient,struct LP_peerinfo *mypeer,int32_t mypubsock,char *ipaddr,uint16_t port,uint16_t pushport,uint16_t subport,double profitmargin,int32_t numpeers,int32_t numutxos)
{
    uint32_t ipbits; int32_t pushsock,subsock,timeout,enabled; char checkip[64],pushaddr[64],subaddr[64]; struct LP_peerinfo *peer = 0;
    /*if ( strcmp(ipaddr,"173.208.149.42") == 0 )
        return(0);
    if ( strncmp(ipaddr,"5.9.253",strlen("5.9.253")) != 0 )
        return(0);*/
    ipbits = (uint32_t)calc_ipbits(ipaddr);
    expand_ipbits(checkip,ipbits);
    if ( strcmp(checkip,ipaddr) == 0 )
    {
        if ( (peer= LP_peerfind(ipbits,port)) != 0 )
        {
            if ( peer->profitmargin == 0. )
                peer->profitmargin = profitmargin;
            if ( numpeers > peer->numpeers )
                peer->numpeers = numpeers;
            if ( numutxos > peer->numutxos )
                peer->numutxos = numutxos;
        }
        else
        {
            //printf("LPaddpeer %s\n",ipaddr);
            peer = calloc(1,sizeof(*peer));
            peer->pushsock = peer->subsock = pushsock = subsock = -1;
            strcpy(peer->ipaddr,ipaddr);
            if ( amclient == 0 )
                enabled = 1;
            else enabled = 1;//(rand() % (1 << Client_connections)) == 0;
            if ( pushport != 0 && subport != 0 && (pushsock= nn_socket(AF_SP,NN_PUSH)) >= 0 )
            {
                timeout = 1000;
                nn_setsockopt(pushsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                nanomsg_tcpname(pushaddr,peer->ipaddr,pushport);
                if ( nn_connect(pushsock,pushaddr) >= 0 )
                {
                    printf("connected to push.(%s) %d\n",pushaddr,pushsock);
                    peer->connected = (uint32_t)time(NULL);
                    peer->pushsock = pushsock;
                    if ( enabled != 0 && (subsock= nn_socket(AF_SP,NN_SUB)) >= 0 )
                    {
                        timeout = 1;
                        nn_setsockopt(subsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                        nn_setsockopt(subsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
                        nanomsg_tcpname(subaddr,peer->ipaddr,subport);
                        if ( nn_connect(subsock,subaddr) >= 0 )
                        {
                            peer->subsock = subsock;
                            printf("connected to sub.(%s) %d\n",subaddr,peer->subsock);
                            Client_connections += amclient;
                        } else nn_close(subsock);
                    }
                }
                else
                {
                    nn_close(pushsock);
                    printf("error connecting to push.(%s)\n",pushaddr);
                }
            } else printf("%s pushport.%u subport.%u pushsock.%d\n",ipaddr,pushport,subport,pushsock);
            peer->profitmargin = profitmargin;
            peer->ipbits = ipbits;
            peer->port = port;
            peer->ip_port = ((uint64_t)port << 32) | ipbits;
            portable_mutex_lock(&LP_peermutex);
            HASH_ADD(hh,LP_peerinfos,ip_port,sizeof(peer->ip_port),peer);
            if ( mypeer != 0 )
            {
                mypeer->numpeers++;
                printf("_LPaddpeer %s -> numpeers.%d mypubsock.%d other.(%d %d)\n",ipaddr,mypeer->numpeers,mypubsock,numpeers,numutxos);
            } else peer->numpeers = 1; // will become mypeer
            portable_mutex_unlock(&LP_peermutex);
            if ( mypubsock >= 0 )
                LP_send(mypubsock,jprint(LP_peerjson(peer),1),1);
        }
    } else printf("LP_addpeer: checkip.(%s) vs (%s)\n",checkip,ipaddr);
    return(peer);
}

int32_t LP_peersparse(int32_t amclient,struct LP_peerinfo *mypeer,int32_t mypubsock,char *destipaddr,uint16_t destport,char *retstr,uint32_t now)
{
    struct LP_peerinfo *peer; uint32_t argipbits; char *argipaddr; uint16_t argport,pushport,subport; cJSON *array,*item; int32_t i,n=0;
    if ( (array= cJSON_Parse(retstr)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                if ( (argipaddr= jstr(item,"ipaddr")) != 0 && (argport= juint(item,"port")) != 0 )
                {
                    if ( (pushport= juint(item,"push")) == 0 )
                        pushport = argport + 1;
                    if ( (subport= juint(item,"sub")) == 0 )
                        subport = argport + 2;
                    argipbits = (uint32_t)calc_ipbits(argipaddr);
                    if ( (peer= LP_peerfind(argipbits,argport)) == 0 )
                    {
                        peer = LP_addpeer(amclient,mypeer,mypubsock,argipaddr,argport,pushport,subport,jdouble(item,"profit"),jint(item,"numpeers"),jint(item,"numutxos"));
                    }
                    if ( peer != 0 )
                    {
                        peer->lasttime = now;
                        if ( strcmp(argipaddr,destipaddr) == 0 && destport == argport && peer->numpeers != n )
                            peer->numpeers = n;
                    }
                }
            }
        }
        free_json(array);
    }
    return(n);
}

void LP_peersquery(int32_t amclient,struct LP_peerinfo *mypeer,int32_t mypubsock,char *destipaddr,uint16_t destport,char *myipaddr,uint16_t myport,double myprofit)
{
    char *retstr; struct LP_peerinfo *peer,*tmp; uint32_t now,flag = 0;
    peer = LP_peerfind((uint32_t)calc_ipbits(destipaddr),destport);
    if ( peer != 0 && peer->errors > 0 )
        return;
    if ( (retstr= issue_LP_getpeers(destipaddr,destport,myipaddr,myport,myprofit,mypeer!=0?mypeer->numpeers:0,mypeer!=0?mypeer->numutxos:0)) != 0 )
    {
        //printf("got.(%s)\n",retstr);
        now = (uint32_t)time(NULL);
        LP_peersparse(amclient,mypeer,mypubsock,destipaddr,destport,retstr,now);
        free(retstr);
        if ( amclient == 0 )
        {
            HASH_ITER(hh,LP_peerinfos,peer,tmp)
            {
                if ( peer->lasttime != now )
                {
                    printf("{%s:%u %.6f}.%d ",peer->ipaddr,peer->port,peer->profitmargin,peer->lasttime - now);
                    flag++;
                    if ( (retstr= issue_LP_notify(destipaddr,destport,peer->ipaddr,peer->port,peer->profitmargin,peer->numpeers,0)) != 0 )
                        free(retstr);
                }
            }
            if ( flag != 0 )
                printf(" <- missing peers\n");
        }
    } else if ( peer != 0 )
        peer->errors++;
}
