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


int32_t iguana_peerhdrrequest(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2)
{
    struct iguana_txid *tx,T; int32_t len=0,i,height,retval=-1; struct iguana_block *block; struct iguana_msgblock msgB; uint8_t *serialized; bits256 checkhash2;
    if ( (tx= iguana_txidfind(coin,&height,&T,hash2,coin->bundlescount-1)) != 0 )
    {
        serialized = calloc(coin->chain->bundlesize,sizeof(msgB));
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
                    free(serialized);
                    return(-1);
                }
            }
        }
        if ( i == coin->chain->bundlesize || (i > 0 && height/coin->chain->bundlesize >= coin->blocks.hwmchain.height/coin->chain->bundlesize) )
        {
            retval = iguana_queue_send(coin,addr,0,serialized,"headers",len,0,0);
            printf("hdrs request retval.%d len.%d\n",retval,len);
        }
        free(serialized);
    }
    return(retval);
}

int32_t iguana_peerinvrequest(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *space,int32_t max)
{
    int32_t i,type,len = 0; uint64_t x; struct iguana_bundle *bp;
    x = coin->bundlescount;
    len += iguana_rwvarint(1,&space[sizeof(struct iguana_msghdr) + len],&x);
    for (i=0; i<x; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            type = MSG_BLOCK;
            len += iguana_rwnum(1,&space[sizeof(struct iguana_msghdr) + len],sizeof(uint32_t),&type);
            len += iguana_rwbignum(1,&space[sizeof(struct iguana_msghdr) + len],sizeof(bits256),bp->hashes[0].bytes);
        }
    }
    return(len);
}

int32_t iguana_peeraddrrequest(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *space,int32_t spacesize)
{
    int32_t i,iter,n,max,sendlen; uint64_t x; struct iguana_msghdr H; struct iguana_msgaddress A; struct iguana_peer *tmpaddr;
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
            memset(&A,0,sizeof(A));
            if ( (tmpaddr= coin->peers.ranked[i]) != 0 && ((iter == 0 && tmpaddr->supernet != 0) || (iter == 1 && tmpaddr->supernet == 0)) )
            {
                sendlen += iguana_rwaddr(1,&space[sizeof(H) + sendlen],&tmpaddr->A,(int32_t)tmpaddr->protover);
                x++;
            }
        }
    }
    sendlen = iguana_rwvarint(1,&space[sizeof(H)],&x);
    printf("addrrequest: sendlen.%d x.%d\n",sendlen,(int32_t)x);
    return(sendlen);
}