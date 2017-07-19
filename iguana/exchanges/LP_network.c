
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

struct psock
{
    uint32_t lasttime,lastping,errors;
    int32_t publicsock,sendsock,ispaired;
    uint16_t publicport,sendport;
    char sendaddr[128],publicaddr[128];
} *PSOCKS;

uint16_t Numpsocks,Psockport = MIN_PSOCK_PORT;

char *nanomsg_transportname(int32_t bindflag,char *str,char *ipaddr,uint16_t port)
{
    sprintf(str,"tcp://%s:%u",bindflag == 0 ? ipaddr : "*",port); // ws is worse
    return(str);
}

int32_t _LP_send(int32_t sock,void *msg,int32_t sendlen,int32_t freeflag)
{
    int32_t sentbytes;
    if ( sock < 0 )
    {
        printf("LP_send.(%s) to illegal socket\n",(char *)msg);
        if ( freeflag != 0 )
            free(msg);
        return(-1);
    }
    if ( (sentbytes= nn_send(sock,msg,sendlen,0)) != sendlen )
        printf("LP_send sent %d instead of %d\n",sentbytes,sendlen);
    //else printf("SENT.(%s)\n",msg);
    if ( freeflag != 0 )
        free(msg);
    return(sentbytes);
}

int32_t LP_sockcheck(int32_t sock)
{
    struct nn_pollfd pfd;
    pfd.fd = sock;
    pfd.events = NN_POLLOUT;
    if ( nn_poll(&pfd,1,1) > 0 )
        return(1);
    else return(-1);
}

int32_t LP_peerindsock(int32_t *peerindp)
{
    struct LP_peerinfo *peer,*tmp; int32_t peerind = 0;
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        peerind++;
        if ( peer->errors < LP_MAXPEER_ERRORS && peer->pushsock >= 0 )
        {
            if ( peerind < *peerindp )
                continue;
            *peerindp = peerind;
            //printf("peerind.%d -> sock %d\n",peerind,peer->pushsock);
            return(peer->pushsock);
        }
    }
    return(-1);
}

struct LP_queue
{
    struct LP_queue *next,*prev;
    int32_t sock,peerind,msglen;
    uint32_t starttime,crc32;
    uint8_t msg[];
} *LP_Q;
int32_t LP_Qenqueued,LP_Qerrors,LP_Qfound;

void _LP_sendqueueadd(uint32_t crc32,int32_t sock,uint8_t *msg,int32_t msglen,int32_t peerind)
{
    struct LP_queue *ptr;
    ptr = calloc(1,sizeof(*ptr) + msglen);
    ptr->crc32 = crc32;
    ptr->sock = sock;
    ptr->peerind = peerind;
    ptr->msglen = msglen;
    memcpy(ptr->msg,msg,msglen);
    DL_APPEND(LP_Q,ptr);
    LP_Qenqueued++;
    //printf("Q.%p: peerind.%d msglen.%d\n",ptr,peerind,msglen);
}

void queue_loop(void *ignore)
{
    struct LP_queue *ptr,*tmp; int32_t sentbytes,nonz,flag,duplicate,n=0;
    while ( 1 )
    {
        nonz = 0;
        //printf("LP_Q.%p next.%p prev.%p\n",LP_Q,LP_Q!=0?LP_Q->next:0,LP_Q!=0?LP_Q->prev:0);
        n = 0;
        DL_FOREACH_SAFE(LP_Q,ptr,tmp)
        {
            n++;
            flag = 0;
            if ( ptr->sock >= 0 )
            {
                if ( LP_sockcheck(ptr->sock) > 0 )
                {
                    if ( (sentbytes= nn_send(ptr->sock,ptr->msg,ptr->msglen,0)) != ptr->msglen )
                        printf("%d LP_send sent %d instead of %d\n",n,sentbytes,ptr->msglen);
                    // else printf("%d %p qsent %u msglen.%d peerind.%d\n",n,ptr,ptr->crc32,ptr->msglen,ptr->peerind);
                    ptr->sock = -1;
                    if ( ptr->peerind > 0 )
                        ptr->starttime = (uint32_t)time(NULL);
                    else flag = 1;
                }
            }
            else if ( time(NULL) > ptr->starttime+13 )
            {
                LP_crc32find(&duplicate,-1,ptr->crc32);
                if ( duplicate > 0 )
                {
                    LP_Qfound++;
                    if ( (LP_Qenqueued % 10) == 0 )
                        printf("found.%u Q.%d err.%d match.%d\n",ptr->crc32,LP_Qenqueued,LP_Qerrors,LP_Qfound);
                    flag = 1;
                }
                else
                {
                    printf("couldnt find.%u (%s) peerind.%d Q.%d err.%d match.%d\n",ptr->crc32,(char *)ptr->msg,ptr->peerind,LP_Qenqueued,LP_Qerrors,LP_Qfound);
                    ptr->peerind++;
                    if ( (ptr->sock= LP_peerindsock(&ptr->peerind)) < 0 )
                    {
                        printf("%d no more peers to try at peerind.%d %p Q_LP.%p\n",n,ptr->peerind,ptr,LP_Q);
                        flag = 1;
                        LP_Qerrors++;
                     }
                }
            }
            if ( flag != 0 )
            {
                nonz++;
                portable_mutex_lock(&LP_networkmutex);
                DL_DELETE(LP_Q,ptr);
                portable_mutex_unlock(&LP_networkmutex);
                free(ptr);
                ptr = 0;
            }
        }
        //if ( n != 0 )
        //    printf("LP_Q.[%d]\n",n);
        if ( nonz == 0 )
            usleep(500000);
    }
}

void _LP_queuesend(uint32_t crc32,int32_t sock0,int32_t sock1,uint8_t *msg,int32_t msglen,int32_t needack)
{
    int32_t sentbytes,peerind = 0;
    if ( sock0 >= 0 || sock1 >= 0 )
    {
        if ( sock0 >= 0 && LP_sockcheck(sock0) > 0 )
        {
            if ( (sentbytes= nn_send(sock0,msg,msglen,0)) != msglen )
                printf("_LP_queuesend0 sent %d instead of %d\n",sentbytes,msglen);
            else
            {
                printf("Q sent %u\n",crc32);
                sock0 = -1;
            }
        }
        if ( sock1 >= 0 && LP_sockcheck(sock1) > 0 )
        {
            if ( (sentbytes= nn_send(sock1,msg,msglen,0)) != msglen )
                printf("_LP_queuesend1 sent %d instead of %d\n",sentbytes,msglen);
            else sock1 = -1;
        }
        if ( sock0 < 0 && sock1 < 0 )
            return;
    }
    else
    {
        peerind = 1;
        sock0 = LP_peerindsock(&peerind);
    }
    portable_mutex_lock(&LP_networkmutex);
    if ( sock0 >= 0 )
        _LP_sendqueueadd(crc32,sock0,msg,msglen,needack * peerind);
    if ( sock1 >= 0 )
        _LP_sendqueueadd(crc32,sock1,msg,msglen,needack);
    portable_mutex_unlock(&LP_networkmutex);
}

void LP_queuesend(uint32_t crc32,int32_t pubsock,char *base,char *rel,uint8_t *msg,int32_t msglen)
{
    //struct iguana_info *coin; int32_t flag=0,socks[2];
    if ( pubsock >= 0 )
    {
        //socks[0] = socks[1] = -1;
        //if ( rel != 0 && rel[0] != 0 && (coin= LP_coinfind(rel)) != 0 && coin->bussock >= 0 )
        //    socks[flag++] = coin->bussock;
        //if ( base != 0 && base[0] != 0 && (coin= LP_coinfind(base)) != 0 && coin->bussock >= 0 )
        //    socks[flag++] = coin->bussock;
        //if ( flag == 0 && pubsock >= 0 )
            _LP_queuesend(crc32,pubsock,-1,msg,msglen,0);
        //else _LP_queuesend(socks[0],socks[1],msg,msglen,0);
    } else _LP_queuesend(crc32,-1,-1,msg,msglen,1);
}

// first 2 bytes == (crc32 & 0xffff) if encrypted, then nonce is next crypto_box_NONCEBYTES
// GENESIS_PRIVKEY is always the sender

void LP_broadcast_finish(int32_t pubsock,char *base,char *rel,uint8_t *msg,cJSON *argjson,uint32_t crc32)
{
    int32_t msglen;
    msg = (void *)jprint(argjson,0);
    msglen = (int32_t)strlen((char *)msg) + 1;
    if ( crc32 == 0 )
        crc32 = calc_crc32(0,&msg[2],msglen - 2);
    if ( IAMLP == 0 )
    {
        free(msg);
        jdelete(argjson,"method");
        jaddstr(argjson,"method","broadcast");
        msg = (void *)jprint(argjson,0);
        msglen = (int32_t)strlen((char *)msg) + 1;
        LP_queuesend(crc32,-1,base,rel,msg,msglen);
    } else LP_queuesend(crc32,pubsock,base,rel,msg,msglen);
    free(msg);
}

void LP_broadcast_message(int32_t pubsock,char *base,char *rel,bits256 destpub25519,char *msgstr)
{
    uint8_t encoded[LP_ENCRYPTED_MAXSIZE],space[sizeof(encoded)],*msg,*nonce,*cipher; int32_t encrypted=0,msglen; uint32_t crc32=0; cJSON *argjson; char *methodstr,method[64],cipherstr[LP_ENCRYPTED_MAXSIZE*2+1];
    msglen = (int32_t)strlen(msgstr) + 1;
    msg = (void *)msgstr;
    if ( bits256_nonz(destpub25519) != 0 )
    {
        nonce = &encoded[2];
        OS_randombytes(nonce,crypto_box_NONCEBYTES);
        cipher = &encoded[2 + crypto_box_NONCEBYTES];
        msglen = _SuperNET_cipher(nonce,&encoded[2 + crypto_box_NONCEBYTES],msg,msglen,destpub25519,GENESIS_PRIVKEY,space);
        msglen += crypto_box_NONCEBYTES;
        crc32 = calc_crc32(0,&encoded[2],msglen);
        encoded[0] = crc32 & 0xff;
        encoded[1] = (crc32 >> 8) & 0xff;
        msg = encoded;
        msglen += 2;
        encrypted = 1;
        //printf("msgstr.(%s)\n",msgstr);
        free(msgstr), msgstr = 0;
    }
    if ( encrypted == 0 )
    {
        if ( (argjson= cJSON_Parse(msgstr)) != 0 )
        {
            if ( (methodstr= jstr(argjson,"method")) != 0 && strlen(methodstr) <= sizeof(method) )
            {
                strcpy(method,methodstr);
                jdelete(argjson,"method");
                if ( jobj(argjson,"method2") != 0 )
                    jdelete(argjson,"method2");
                jaddstr(argjson,"method2",method);
                jaddstr(argjson,"method",method);
                //printf("CRC32.%u (%s)\n",crc32,(char *)msg);
                LP_broadcast_finish(pubsock,base,rel,msg,argjson,0);
            } // else printf("no valid method in (%s)\n",msgstr);
            free_json(argjson);
        } else printf("couldnt parse (%s)\n",msgstr);
    }
    else
    {
        argjson = cJSON_CreateObject();
        init_hexbytes_noT(cipherstr,msg,msglen);
        jaddstr(argjson,"cipher",cipherstr);
        jaddstr(argjson,"method2","encrypted");
        jaddstr(argjson,"method","encrypted");
        LP_broadcast_finish(pubsock,base,rel,msg,argjson,crc32);
        free_json(argjson);
    }
    if ( msgstr != 0 )
        free(msgstr);
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

void LP_psockloop(void *_ptr) // printouts seem to be needed for forwarding to work
{
    static struct nn_pollfd *pfds;
    int32_t i,n,nonz,iter,retval,sentbytes,size=0,sendsock = -1; uint32_t now; struct psock *ptr=0; void *buf=0; char keepalive[512];
    while ( 1 )
    {
        now = (uint32_t)time(NULL);
        if ( buf != 0 && ptr != 0 && sendsock >= 0 )
        {
            if ( size > 0 )
            {
                if ( (sentbytes= nn_send(sendsock,buf,size,0)) != size ) // need tight loop
                    printf("LP_psockloop sent %d instead of %d\n",sentbytes,size);
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
        }
        else if ( Numpsocks > 0 )
        {
            if ( pfds == 0 )
                pfds = calloc(MAX_PSOCK_PORT,sizeof(*pfds));
            portable_mutex_lock(&LP_psockmutex);
            memset(pfds,0,sizeof(*pfds) * ((Numpsocks*2 <= MAX_PSOCK_PORT) ? Numpsocks*2 : MAX_PSOCK_PORT));
            for (iter=0; iter<2; iter++)
            {
                for (i=n=0; i<Numpsocks; i++)
                {
                    ptr = &PSOCKS[i];
                    if ( iter == 0 )
                    {
                        pfds[n].fd = ptr->publicsock;
                        pfds[n].events = POLLIN;
                    }
                    else
                    {
                        if ( pfds[n].fd != ptr->publicsock )
                        {
                            printf("unexpected fd.%d mismatched publicsock.%d\n",pfds[n].fd,ptr->publicsock);
                            break;
                        }
                        else if ( (pfds[n].revents & POLLIN) != 0 )
                        {
                            printf("publicsock.%d %s has pollin\n",ptr->publicsock,ptr->publicaddr);
                            if ( (size= nn_recv(ptr->publicsock,&buf,NN_MSG,0)) > 0 )
                            {
                                ptr->lasttime = now;
                                sendsock = ptr->sendsock;
                                break;
                            }
                        }
                    }
                    n++;
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
                            if ( (size= nn_recv(ptr->sendsock,&buf,NN_MSG,0)) > 0 )
                            {
                                //printf("%s paired has pollin (%s)\n",ptr->sendaddr,(char *)buf);
                                ptr->lasttime = now;
                                if ( ptr->ispaired != 0 )
                                {
                                    sendsock = ptr->publicsock;
                                    break;
                                }
                                else
                                {
                                    nn_freemsg(buf);
                                    buf = 0;
                                    size = 0;
                                }
                            }
                        }
                    }
                    n++;
                }
                if ( iter == 0 )
                {
                    if ( (retval= nn_poll(pfds,n,1)) <= 0 )
                    {
                        if ( retval != 0 )
                            printf("nn_poll retval.%d\n",retval);
                        break;
                    } else printf("num pfds.%d retval.%d\n",n,retval);
                }
            }
            //free(pfds);
            //printf("sendsock.%d Numpsocks.%d\n",sendsock,Numpsocks);
            if ( sendsock < 0 )
            {
                for (i=nonz=0; i<Numpsocks; i++)
                {
                    if ( i < Numpsocks )
                    {
                        ptr = &PSOCKS[i];
                        if ( now > ptr->lasttime+PSOCK_KEEPALIVE )
                        {
                            printf("PSOCKS[%d] of %d (%u %u) lag.%d IDLETIMEOUT\n",i,Numpsocks,ptr->publicport,ptr->sendport,now - ptr->lasttime);
                            if ( ptr->publicsock >= 0 )
                                nn_close(ptr->publicsock);
                            if ( ptr->sendsock >= 0 )
                                nn_close(ptr->sendsock);
                            //portable_mutex_lock(&LP_psockmutex);
                            if ( Numpsocks > 1 )
                            {
                                PSOCKS[i] = PSOCKS[--Numpsocks];
                                memset(&PSOCKS[Numpsocks],0,sizeof(*ptr));
                            } else Numpsocks = 0;
                            //portable_mutex_unlock(&LP_psockmutex);
                            break;
                        }
                        else if ( now > ptr->lastping+PSOCK_KEEPALIVE/2 && ptr->errors < 3 )
                        {
                            ptr->lastping = now;
                            if ( 0 )
                            {
                                sendsock = ptr->sendsock;
                                sprintf(keepalive,"{\"method\":\"keepalive\",\"endpoint\":\"%s\"}",ptr->sendaddr);
                                size = (int32_t)strlen(keepalive) + 1;
                                buf = keepalive;
                                printf("send keepalive.(%s)\n",keepalive);
                            }
                            break;
                        }
                    }
                }
                if ( nonz == 0 && i == Numpsocks )
                    usleep(100000);
            }
            portable_mutex_unlock(&LP_psockmutex);
        } else usleep(100000);
    }
}

void LP_psockadd(int32_t ispaired,int32_t publicsock,uint16_t recvport,int32_t sendsock,uint16_t sendport,char *subaddr,char *publicaddr)
{
    struct psock *ptr;
    portable_mutex_lock(&LP_psockmutex);
    PSOCKS = realloc(PSOCKS,sizeof(*PSOCKS) * (Numpsocks + 1));
    ptr = &PSOCKS[Numpsocks++];
    ptr->ispaired = ispaired;
    ptr->publicsock = publicsock;
    ptr->publicport = recvport;
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
    char pushaddr[128],subaddr[128]; uint16_t i,publicport,subport,maxiters=100; int32_t timeout,pullsock=-1,pubsock=-1; cJSON *retjson=0;
    retjson = cJSON_CreateObject();
    publicport = Psockport++;
    subport = Psockport++;
    for (i=0; i<maxiters; i++,publicport+=2,subport+=2)
    {
        if ( publicport < MIN_PSOCK_PORT )
            publicport = MIN_PSOCK_PORT+1;
        if ( subport <= publicport )
            subport = publicport +  1;
        pullsock = pubsock = -1;
        nanomsg_transportname(1,pushaddr,myipaddr,publicport);
        nanomsg_transportname(1,subaddr,myipaddr,subport);
        if ( (pullsock= nn_socket(AF_SP,ispaired!=0?NN_PAIR:NN_PULL)) >= 0 && (pubsock= nn_socket(AF_SP,ispaired!=0?NN_PAIR:NN_PAIR)) >= 0 )
        {
            if ( nn_bind(pullsock,pushaddr) >= 0 && nn_bind(pubsock,subaddr) >= 0 )
            {
                timeout = 1;
                nn_setsockopt(pubsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                if ( ispaired != 0 )
                {
                    //maxsize = 1024 * 1024;
                    //nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVBUF,&maxsize,sizeof(maxsize));
                }
                //if ( ispaired != 0 )
                {
                    nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                    nn_setsockopt(pubsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                }
                nanomsg_transportname(0,pushaddr,myipaddr,publicport);
                nanomsg_transportname(0,subaddr,myipaddr,subport);
                LP_psockadd(ispaired,pullsock,publicport,pubsock,subport,subaddr,pushaddr);
                jaddstr(retjson,"result","success");
                jaddstr(retjson,"LPipaddr",myipaddr);
                jaddstr(retjson,"connectaddr",subaddr);
                jaddnum(retjson,"connectport",subport);
                jaddnum(retjson,"ispaired",ispaired);
                jaddstr(retjson,"publicaddr",pushaddr);
                jaddnum(retjson,"publicport",publicport);
                printf("i.%d publicaddr.(%s) for subaddr.(%s), pullsock.%d pubsock.%d\n",i,pushaddr,subaddr,pullsock,pubsock);
                break;
            } else printf("bind error on %s or %s\n",pushaddr,subaddr);
            if ( pullsock >= 0 )
                nn_close(pullsock);
            if ( pubsock >= 0 )
                nn_close(pubsock);
        }
    }
    if ( Psockport > MAX_PSOCK_PORT )
        Psockport = MIN_PSOCK_PORT;
    if ( i == maxiters )
        jaddstr(retjson,"error","cant find psock ports");
    return(jprint(retjson,1));
}

/*
 LP_pushaddr_get makes transparent the fact that most nodes cannot bind()!
 
 The idea is to create an LP node NN_PAIR sock that the LP node binds to and client node connects to. Additionally, the LP node creates an NN_PULL that other nodes can NN_PUSH to and returns this address in pushaddr/retval for the client node to register with. The desired result is that other than the initial LP node, all the other nodes do a normal NN_PUSH, requiring no change to the NN_PUSH/NN_PULL logic. Of course, the initial LP node needs to autoforward all packets from the public NN_PULL to the NN_PUB
 
    similar to LP_pushaddr_get, create an NN_PAIR for DEX atomic data, can be assumed to have a max lifetime of 2*INSTANTDEX_LOCKTIME
 
 both are combined in LP_psock_get

*/

int32_t LP_initpublicaddr(void *ctx,uint16_t *mypullportp,char *publicaddr,char *myipaddr,uint16_t mypullport,int32_t ispaired)
{
    int32_t nntype,pullsock,timeout; char bindaddr[128],connectaddr[128];
    *mypullportp = mypullport;
    if ( ispaired == 0 )
    {
        if ( LP_canbind != 0 )
            nntype = LP_COMMAND_RECVSOCK;
        else nntype = NN_PAIR;//NN_SUB;
    } else nntype = NN_PAIR;
    if ( LP_canbind != 0 )
    {
        nanomsg_transportname(0,publicaddr,myipaddr,mypullport);
        nanomsg_transportname(1,bindaddr,myipaddr,mypullport);
    }
    else
    {
        *mypullportp = 0;
        if ( ispaired == 0 )
        {
            strcpy(publicaddr,"127.0.0.1");
            return(-1);
        }
        while ( *mypullportp == 0 )
        {
            if ( (*mypullportp= LP_psock_get(connectaddr,publicaddr,ispaired)) != 0 )
                break;
            sleep(10);
            printf("try to get publicaddr again\n");
        }
    }
    while ( 1 )
    {
        if ( (pullsock= nn_socket(AF_SP,nntype)) >= 0 )
        {
            if ( LP_canbind == 0 )
            {
                if ( nn_connect(pullsock,connectaddr) < 0 )
                {
                    printf("bind to %s error for %s: %s\n",connectaddr,publicaddr,nn_strerror(nn_errno()));
                    exit(-1);
                } else printf("nntype.%d NN_PAIR.%d connect to %s connectsock.%d\n",nntype,NN_PAIR,connectaddr,pullsock);
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
            nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
            //maxsize = 2 * 1024 * 1024;
            //nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVBUF,&maxsize,sizeof(maxsize));
            if ( nntype == NN_SUB )
                nn_setsockopt(pullsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
        }
        //if ( LP_canbind != 0 || ispaired != 0 || nn_tests(ctx,pullsock,publicaddr,NN_PUSH) >= 0 )
        //    break;
        //printf("nn_tests failed, try again\n");
        //sleep(3);
        break;
        if ( pullsock >= 0 )
            nn_close(pullsock);
    }
    return(pullsock);
}
