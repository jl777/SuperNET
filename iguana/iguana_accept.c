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
    int32_t bindsock,sock; struct iguana_accept *ptr; struct iguana_peer *addr; struct iguana_info *coin = args;
    socklen_t clilen; struct sockaddr_in cli_addr; char ipaddr[64]; uint32_t ipbits;
    bindsock = iguana_socket(1,"0.0.0.0",coin->chain->portp2p);
    printf("iguana_bindloop 127.0.0.1:%d bind sock.%d\n",coin->chain->portp2p,bindsock);
    while ( bindsock >= 0 )
    {
        clilen = sizeof(cli_addr);
        printf("ACCEPT (%s:%d) on sock.%d\n","127.0.0.1",coin->chain->portp2p,bindsock);
        sock = accept(bindsock,(struct sockaddr *)&cli_addr,&clilen);
        if ( sock < 0 )
        {
            //printf("ERROR on accept bindsock.%d errno.%d (%s)\n",bindsock,errno,strerror(errno));
            continue;
        }
        memcpy(&ipbits,&cli_addr.sin_addr.s_addr,sizeof(ipbits));
        expand_ipbits(ipaddr,ipbits);
        printf("NEWSOCK.%d for %x (%s)\n",sock,ipbits,ipaddr);
        if ( (addr= iguana_peerslot(coin,ipbits)) == 0 )
        {
            ptr = mycalloc('a',1,sizeof(*ptr));
            strcpy(ptr->ipaddr,ipaddr);
            ptr->ipbits = ipbits;
            ptr->sock = sock;
            ptr->port = coin->chain->portp2p;
            printf("NEED TO DEAL WITH PENDING ACCEPTS\n");
            queue_enqueue("acceptQ",&coin->acceptQ,&ptr->DL,0);
        }
        else
        {
            printf("LAUNCH DEDICATED THREAD for %s\n",ipaddr);
            addr->usock = sock;
            iguana_dedicatedloop(coin,addr);
        }
    }
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
