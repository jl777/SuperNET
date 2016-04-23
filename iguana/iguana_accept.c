/******************************************************************************
 * Copyright © 2014-2016 The SuperNET Developers.                             *
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

#include "iguana777.h"

struct iguana_accept { struct queueitem DL; char ipaddr[64]; uint32_t ipbits; int32_t sock; uint16_t port; };

int32_t iguana_acceptspoll(uint8_t *buf,int32_t bufsize,struct iguana_accept *accepts,int32_t num,int32_t timeout)
{
    struct pollfd fds[IGUANA_MAXPEERS]; int32_t i,j,n,r,nonz,flag; struct iguana_accept *ptr;
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
                //return(iguana_recvmsg(ptr->ipaddr,ptr->sock,buf,bufsize));
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

void iguana_acceptloop(void *args)
{
    struct iguana_peer *addr; struct iguana_info *coin = args;
    struct pollfd pfd; int32_t sock; struct iguana_accept *ptr; uint16_t port = coin->chain->portp2p;
    socklen_t clilen; struct sockaddr_in cli_addr; char ipaddr[64]; uint32_t i,ipbits;
    while ( (coin->bindsock= iguana_socket(1,"0.0.0.0",port)) < 0 )
    {
        if ( coin->peers.localaddr != 0 )
        {
            printf("another daemon running, no need to have iguana accept connections\n");
            return;
        }
        if ( port != IGUANA_RPCPORT )
            return;
        sleep(5);
    }
    printf(">>>>>>>>>>>>>>>> iguana_bindloop 127.0.0.1:%d bind sock.%d\n",port,coin->bindsock);
    printf("START ACCEPTING\n");
    while ( coin->bindsock >= 0 )
    {
        memset(&pfd,0,sizeof(pfd));
        pfd.fd = coin->bindsock;
        pfd.events = POLLIN;
        if ( poll(&pfd,1,100) <= 0 )
            continue;
        clilen = sizeof(cli_addr);
        //printf("ACCEPT (%s:%d) on sock.%d\n","127.0.0.1",coin->chain->portp2p,coin->bindsock);
        sock = accept(coin->bindsock,(struct sockaddr *)&cli_addr,&clilen);
        if ( sock < 0 )
        {
            printf("ERROR on accept bindsock.%d errno.%d (%s)\n",coin->bindsock,errno,strerror(errno));
            continue;
        }
        memcpy(&ipbits,&cli_addr.sin_addr.s_addr,sizeof(ipbits));
        expand_ipbits(ipaddr,ipbits);
        for (i=0; i<IGUANA_MAXPEERS; i++)
        {
            if ( coin->peers.active[i].ipbits == (uint32_t)ipbits && coin->peers.active[i].usock >= 0 )
            {
                printf("found existing peer.(%s) in slot[%d]\n",ipaddr,i);
                close(sock);
                sock = -1;
                //iguana_iAkill(coin,&coin->peers.active[i],0);
                //sleep(1);
                break;
            }
        }
        if ( sock < 0 )
            continue;
        printf("NEWSOCK.%d for %x (%s)\n",sock,ipbits,ipaddr);
        /*if ( (uint32_t)ipbits == myinfo->myaddr.myipbits )
        {
            
        }*/
        if ( (addr= iguana_peerslot(coin,ipbits,0)) == 0 )
        {
            ptr = mycalloc('a',1,sizeof(*ptr));
            strcpy(ptr->ipaddr,ipaddr);
            ptr->ipbits = ipbits;
            ptr->sock = sock;
            ptr->port = coin->chain->portp2p;
            printf("queue PENDING ACCEPTS\n");
            queue_enqueue("acceptQ",&coin->acceptQ,&ptr->DL,0);
        }
        else
        {
            printf("LAUNCH DEDICATED THREAD for %s\n",ipaddr);
            addr->usock = sock;
            addr->dead = 0;
            strcpy(addr->symbol,coin->symbol);
            iguana_launch(coin,"accept",iguana_dedicatedglue,addr,IGUANA_CONNTHREAD);
            //iguana_dedicatedloop(coin,addr);
        }
    }
}

int32_t iguana_pendingaccept(struct iguana_info *coin)
{
    struct iguana_accept *ptr; char ipaddr[64]; struct iguana_peer *addr;
    if ( (ptr= queue_dequeue(&coin->acceptQ,0)) != 0 )
    {
        if ( (addr= iguana_peerslot(coin,ptr->ipbits,0)) != 0 )
        {
            expand_ipbits(ipaddr,ptr->ipbits);
            printf("iguana_pendingaccept LAUNCH DEDICATED THREAD for %s\n",ipaddr);
            addr->usock = ptr->sock;
            strcpy(addr->symbol,coin->symbol);
            iguana_launch(coin,"accept",iguana_dedicatedglue,addr,IGUANA_CONNTHREAD);
            myfree(ptr,sizeof(*ptr));
            return(1);
        } else queue_enqueue("requeue_acceptQ",&coin->acceptQ,&ptr->DL,0);
    }
    return(0);
}

/*int32_t iguana_acceptport(struct iguana_info *coin,uint16_t port)
{
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)iguana_acceptloop,(void *)coin) != 0 )
    {
        printf("error launching accept thread for port.%u\n",port);
        return(-1);
    }
    return(0);
}*/

void iguana_msgrequestQ(struct iguana_info *coin,struct iguana_peer *addr,int32_t type,bits256 hash2)
{
    struct iguana_peermsgrequest *msg;
    msg = calloc(1,sizeof(*msg));
    msg->addr = addr;
    msg->hash2 = hash2;
    msg->type = type;
    queue_enqueue("msgrequest",&coin->msgrequestQ,&msg->DL,0);
}

int32_t iguana_process_msgrequestQ(struct iguana_info *coin)
{
    struct iguana_peermsgrequest *msg; int32_t height,len,flag = 0; bits256 checktxid; struct iguana_txid *tx,T;
    if ( (msg= queue_dequeue(&coin->msgrequestQ,0)) != 0 )
    {
        flag = 1;
        if ( msg->addr != 0 )
        {
            char str[65]; printf("send type.%d %s -> (%s)\n",msg->type,bits256_str(str,msg->hash2),msg->addr->ipaddr);
            if ( msg->type == MSG_BLOCK )
            {
                if ( coin->RELAYNODE != 0 || coin->VALIDATENODE )
                {
                    if ( (len= iguana_peerblockrequest(coin,&coin->blockspace[sizeof(struct iguana_msghdr)],sizeof(coin->blockspace),0,msg->hash2,0)) > 0 )
                    {
                        iguana_queue_send(coin,msg->addr,0,coin->blockspace,"block",len,0,0);
                    }
                }
            }
            else if ( msg->type == MSG_TX )
            {
                if ( coin->RELAYNODE != 0 || coin->VALIDATENODE )
                {
                    if ( (tx= iguana_txidfind(coin,&height,&T,msg->hash2,coin->bundlescount-1)) != 0 )
                    {
                        if ( (len= iguana_ramtxbytes(coin,&coin->blockspace[sizeof(struct iguana_msghdr)],sizeof(coin->blockspace),&checktxid,tx,height,0,0,0)) > 0 )
                        {
                            char str[65],str2[65];
                            if ( bits256_cmp(msg->hash2,checktxid) == 0 )
                                iguana_queue_send(coin,msg->addr,0,coin->blockspace,"block",len,0,0);
                            else printf("checktxid mismatch (%s) != (%s)\n",bits256_str(str,msg->hash2),bits256_str(str2,checktxid));
                        }
                    }
                }
            }
            else if ( msg->type == MSG_FILTERED_BLOCK )
            {
                
            }
            else if ( msg->type == MSG_BUNDLE_HEADERS )
            {
                
            }
            else if ( msg->type == MSG_BUNDLE )
            {
                
            }
        }
        free(msg);
    }
    return(flag);
}

int32_t iguana_peerdatarequest(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *data,int32_t recvlen)
{
    int32_t i,type,len = 0; uint64_t x; bits256 hash2;
    len += iguana_rwvarint(0,data,&x);
    //for (i=0; i<10; i++)
    //    printf("%02x ",data[i]);
    //printf("x.%d recvlen.%d\n",(int32_t)x,recvlen);
    if ( x < IGUANA_MAXINV )
    {
        for (i=0; i<x; i++)
        {
            len += iguana_rwnum(0,&data[len],sizeof(uint32_t),&type);
            len += iguana_rwbignum(0,&data[len],sizeof(bits256),hash2.bytes);
            iguana_msgrequestQ(coin,addr,type,hash2);
        }
    }
    return(len);
}

int32_t iguana_peerhdrrequest(struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_peer *addr,bits256 hash2)
{
    int32_t len=0,i,height,firstvout,retval=-1; struct iguana_block *block; struct iguana_msgblock msgB; bits256 checkhash2;
    if ( (firstvout= iguana_unspentindfind(coin,&height,hash2,0,coin->bundlescount-1)) != 0 )
    {
        for (i=0; i<coin->chain->bundlesize; i++)
        {
            if ( (block= iguana_blockptr("peerhdr",coin,height + i)) != 0 )
            {
                iguana_blockunconv(&msgB,block,1);
                len += iguana_rwblock(1,&checkhash2,&serialized[sizeof(struct iguana_msghdr) + len],&msgB);
                if ( bits256_cmp(checkhash2,block->RO.hash2) != 0 )
                {
                    char str[65],str2[65];
                    printf("iguana_peerhdrrequest blockhash.%d error (%s) vs (%s)\n",height+i,bits256_str(str,checkhash2),bits256_str(str2,block->RO.hash2));
                    return(-1);
                }
            } else printf("cant find block at ht.%d\n",height+i);
        }
        retval = iguana_queue_send(coin,addr,0,serialized,"headers",len,0,0);
        printf("hdrs request retval.%d len.%d\n",retval,len);
    } //else printf("couldnt find header\n");
    return(retval);
}

int32_t iguana_peergetrequest(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *data,int32_t recvlen,int32_t getblock)
{
    int32_t i,reqvers,len,n,flag = 0; bits256 hash2;
    if ( getblock != 0 )
        addr->msgcounts.getblocks++;
    else addr->msgcounts.getheaders++;
    len = iguana_rwnum(0,&data[0],sizeof(uint32_t),&reqvers);
    len += iguana_rwvarint32(0,&data[len],(uint32_t *)&n);
    for (i=0; i<n&&len<=recvlen-sizeof(bits256)*2; i++)
    {
        len += iguana_rwbignum(0,&data[len],sizeof(bits256),hash2.bytes);
        if ( bits256_nonz(hash2) == 0 )
            break;
        if ( flag == 0 )
        {
            if ( getblock != 0 && iguana_peerblockrequest(coin,addr->blockspace,sizeof(addr->blockspace),addr,hash2,0) > 0 )
                flag = 1;
            else if ( getblock == 0 && iguana_peerhdrrequest(coin,addr->blockspace,sizeof(addr->blockspace),addr,hash2) > 0 )
                flag = 1;
        }
    }
    len += iguana_rwbignum(0,&data[len],sizeof(bits256),hash2.bytes);
    //for (i=0; i<69; i++)
    //    printf("%02x ",data[i]);
    //printf("version.%d num blocks.%d recvlen.%d len.%d\n",reqvers,n,recvlen,len);
    return(len);
}

int32_t iguana_peeraddrrequest(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *space,int32_t spacesize)
{
    int32_t i,iter,n,max,sendlen; uint64_t x; struct iguana_msghdr H; struct iguana_peer *tmpaddr;
    sendlen = 0;
    max = (IGUANA_MINPEERS + IGUANA_MAXPEERS) / 2;
    if ( max > coin->peers.numranked )
        max = coin->peers.numranked;
    x = 0;
    sendlen = iguana_rwvarint(1,&space[sizeof(H)],&x);
    for (iter=0; iter<2; iter++)
    {
        for (i=n=0; i<max; i++)
        {
            if ( (tmpaddr= coin->peers.ranked[i]) != 0 && ((iter == 0 && tmpaddr->supernet != 0) || (iter == 1 && tmpaddr->supernet == 0)) && tmpaddr->ipaddr[0] != 0 )
            {
                sendlen += iguana_rwaddr(1,&space[sizeof(H) + sendlen],&tmpaddr->A,(int32_t)tmpaddr->protover);
                printf("(%s) ",tmpaddr->ipaddr);
                x++;
            }
        }
    }
    iguana_rwvarint(1,&space[sizeof(H)],&x);
    printf("addrrequest: sendlen.%d x.%d\n",sendlen,(int32_t)x);
    if ( x == 0 )
        return(-1);
    return(sendlen);
}