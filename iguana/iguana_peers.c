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

#define _iguana_hashfind(coin,ipbits) _iguana_hashset(coin,ipbits,-1)
struct iguana_iAddr *iguana_iAddrhashfind(struct iguana_info *coin,uint32_t ipbits,int32_t createflag);

struct iguana_iAddr *_iguana_hashset(struct iguana_info *coin,uint32_t ipbits,int32_t itemind)
{
    struct iguana_iAddr *ptr = 0; int32_t allocsize; char str[65]; struct OS_memspace *mem = 0;
    expand_ipbits(str,ipbits);
    HASH_FIND(hh,coin->iAddrs,&ipbits,sizeof(ipbits),ptr);
    //printf("%p hashset.(%s) -> ptr.%p itemind.%d keylen.%ld %x\n",coin->iAddrs,str,ptr,itemind,sizeof(ipbits),ipbits);
    if ( itemind >= 0 )
    {
        if ( ptr == 0 )
        {
            allocsize = (int32_t)(sizeof(*ptr));
            if ( mem != 0 )
                ptr = iguana_memalloc(mem,allocsize,1);
            else ptr = mycalloc('t',1,allocsize);
            if ( ptr == 0 )
                printf("fatal alloc error in hashset\n"), exit(-1);
            //printf("ptr.%p allocsize.%d key.%p keylen.%d itemind.%d\n",ptr,allocsize,key,keylen,itemind);
            ptr->hh.itemind = itemind;
            ptr->ipbits = ipbits;
            HASH_ADD(hh,coin->iAddrs,ipbits,sizeof(ipbits),ptr);
            {
                struct iguana_iAddr *tmp;
                HASH_FIND(hh,coin->iAddrs,&ipbits,sizeof(ipbits),tmp);
                if ( tmp != ptr )
                    printf("%s itemind.%d search error %p != %p\n",str,itemind,ptr,tmp);
                //else printf("%p added.(%s) ind.%d:%d %p tmp.%p %x\n",coin->iAddrs,str,itemind,ptr->hh.itemind,ptr,tmp,ipbits);
            }
        }
        else ptr->hh.itemind = itemind;
    }
    return(ptr);
}

struct iguana_iAddr *iguana_iAddrhashset(struct iguana_info *coin,struct iguana_iAddr *iA,int32_t ind)
{
    struct iguana_iAddr *tmp,*item;
    if ( iA == 0 || iA->ipbits == 0 )
    {
        printf("null iA.%p or ipbits.%x ind.%d status.%d\n",iA,iA!=0?iA->ipbits:0,iA!=0?iA->hh.itemind:0,iA!=0?iA->status:0);
        exit(-1);
        return(0);
    }
    portable_mutex_lock(&coin->peers_mutex);
    if ( (item= _iguana_hashfind(coin,iA->ipbits)) == 0 )
    {
        tmp = mycalloc('i',1,sizeof(*iA));
        *tmp = *iA;
        iA = tmp;
        if ( ind <= 0 )
            ind = coin->numiAddrs + 1;
        //printf("coin->iAddrs.%p call set.(%x) ind.%d\n",coin->iAddrs,iA->ipbits,iA->ind);
        if ( (item= _iguana_hashset(coin,iA->ipbits,ind)) != 0 && item->hh.itemind == coin->numiAddrs+1 )
        {
            *item = *iA;
            iA = item;
            coin->numiAddrs++;
        } else printf("iguana_hashset error numiAddrs.%d ind.%d\n",coin->numiAddrs,iA->hh.itemind);
    }
    else
    {
        *item = *iA;
        iA = item;
        iA->hh.itemind = ind;
    }
    portable_mutex_unlock(&coin->peers_mutex);
    //printf("return iA.%p ind.%d %x\n",iA,iA->hh.itemind,iA->ipbits);
    return(iA);
}

struct iguana_iAddr *iguana_iAddrhashfind(struct iguana_info *coin,uint32_t ipbits,int32_t createflag)
{
    int32_t ind; struct iguana_iAddr *item = 0;
    portable_mutex_lock(&coin->peers_mutex);
    if ( ipbits != 0 )
    {
        if ( (item= _iguana_hashfind(coin,ipbits)) == 0 && createflag != 0 )
        {
            ind = coin->numiAddrs + 1;
            _iguana_hashset(coin,ipbits,ind);
            if ( (item= _iguana_hashfind(coin,ipbits)) != 0 )
                coin->numiAddrs++;
        }
    }
    portable_mutex_unlock(&coin->peers_mutex);
    return(item);
}

uint32_t iguana_rwiAddrind(struct iguana_info *coin,int32_t rwflag,struct iguana_iAddr *iA,uint32_t ind)
{
    FILE *fp; char fname[512],hexstr[65]; int32_t i,n,m,retval = 0; struct iguana_iAddr tmp,*ptr;
    sprintf(fname,"DB/%s/peers.dat",coin->symbol);
    OS_compatible_path(fname);
    if ( rwflag < 0 || iA == 0 )
    {
        coin->numiAddrs = 0;
        if ( (fp= fopen(fname,"rb+")) != 0 )
        {
            fseek(fp,0,SEEK_END);
            n = (int32_t)(ftell(fp) / sizeof(*iA));
            for (i=m=0; i<n; i++)
            {
                fseek(fp,i * sizeof(tmp),SEEK_SET);
                if ( ftell(fp) == i*sizeof(tmp) && fread(&tmp,1,sizeof(tmp),fp) == sizeof(tmp) && tmp.ipbits != 0 )
                {
                    portable_mutex_lock(&coin->peers_mutex);
                    HASH_FIND(hh,coin->iAddrs,&tmp.ipbits,sizeof(tmp.ipbits),ptr);
                    if ( ptr == 0 )
                    {
                        ptr = mycalloc('t',1,sizeof(*ptr));
                        if ( ptr == 0 )
                            printf("fatal alloc error in hashset\n"), exit(-1);
                        ptr->hh.itemind = m;
                        ptr->ipbits = tmp.ipbits;
                        HASH_ADD(hh,coin->iAddrs,ipbits,sizeof(tmp.ipbits),ptr);
                        if ( i != m )
                        {
                            tmp.hh.itemind = m;
                            fseek(fp,m*sizeof(tmp),SEEK_SET);
                            fwrite(&tmp,1,sizeof(tmp),fp);
                        }
                        //printf("m.%d %x\n",m,tmp.ipbits);
                        m++;
                        coin->numiAddrs = m;
                        expand_ipbits(hexstr,tmp.ipbits);
                        iguana_possible_peer(coin,hexstr);
                    }
                    portable_mutex_unlock(&coin->peers_mutex);
                }
            }
            fclose(fp);
            printf("i.%d m.%d numiAddrs.%d\n",i,m,coin->numiAddrs);
        }
        return(coin->numiAddrs);
    }
    if ( rwflag == 0 )
    {
        memset(iA,0,sizeof(*iA));
        if ( (fp= fopen(fname,"rb")) != 0 )
        {
            fseek(fp,ind * sizeof(*iA),SEEK_SET);
            if ( ftell(fp) == ind * sizeof(*iA) )
            {
                if ( fread(iA,1,sizeof(*iA),fp) != sizeof(*iA) )
                    printf("iAddr: error loading.[%d]\n",ind);
                else
                {
                    if ( (iA= iguana_iAddrhashset(coin,iA,ind)) != 0 )
                    {
                        retval = iA->hh.itemind+1;
                        //printf("r %p ipbits.%x ind.%d saved iA->ind.%d retval.%d\n",iA,iA->ipbits,ind,iA->hh.itemind,retval);
                    }
                }
            } else printf("iAddr: error seeking.[%d] %ld vs %ld\n",ind,ftell(fp),ind * sizeof(*iA));
            fclose(fp);
        }
    }
    else
    {
        if ( (fp= fopen(fname,"rb+")) == 0 )
            fp = fopen(fname,"wb");
        if ( fp != 0 )
        {
            fseek(fp,ind * sizeof(*iA),SEEK_SET);
            if ( ftell(fp) == ind * sizeof(*iA) )
            {
                iA->hh.itemind = ind;
                if ( fwrite(iA,1,sizeof(*iA),fp) != sizeof(*iA) )
                    printf("iAddr: error saving.[%d]\n",ind);
                else
                {
                    if ( (iA= iguana_iAddrhashset(coin,iA,ind)) != 0 )
                    {
                        retval = iA->hh.itemind+1;
                        //printf("W %p ipbits.%x ind.%d saved iA->ind.%d retval.%d\n",iA,iA->ipbits,ind,iA->hh.   itemind,retval);
                    }
                }
            } else printf("iAddr: error seeking.[%d] %ld vs %ld\n",ind,ftell(fp),ind * sizeof(*iA));
            fclose(fp);
        } else printf("error creating.(%s)\n",fname);
    }
    return(retval);
}

void iguana_iAconnected(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct iguana_iAddr *iA;
    if ( (iA= iguana_iAddrhashfind(coin,addr->ipbits,1)) != 0 )
    {
        iA->status = IGUANA_PEER_READY;
        if ( addr->height > iA->height )
            iA->height = addr->height;
        iA->numconnects++;
        iA->lastconnect = (uint32_t)time(NULL);
        if ( iguana_rwiAddrind(coin,1,iA,iA->hh.itemind) == 0 )
            printf("iguana_iAconnected (%s) save error iA->ind.%d\n",addr->ipaddr,iA->hh.itemind);
        //else printf("iguana_iAconnected.(%s)\n",addr->ipaddr);
    } else printf("iguana_iAconnected error getting iA\n");
}

void iguana_iAkill(struct iguana_info *coin,struct iguana_peer *addr,int32_t markflag)
{
    struct iguana_iAddr *iA; int32_t rank; char ipaddr[64];
    if ( addr->ipbits == 0 )
    {
        printf("cant iAkill null ipbits\n");
        return;
    }
    rank = addr->rank;
    strcpy(ipaddr,addr->ipaddr);
    if ( addr->usock >= 0 )
        close(addr->usock), addr->usock = -1;
    if ( addr == coin->peers.localaddr )
        coin->peers.localaddr = 0;
    //printf("iAkill.(%s)\n",addr->ipaddr);
    if ( (iA= iguana_iAddrhashfind(coin,addr->ipbits,1)) != 0 )
    {
        iA->status = IGUANA_PEER_KILLED;
        if ( addr->height > iA->height )
            iA->height = addr->height;
        if ( markflag != 0 )
        {
            iA->numkilled++;
            iA->lastkilled = (uint32_t)time(NULL);
            if ( iguana_rwiAddrind(coin,1,iA,iA->hh.itemind) == 0 )
                printf("killconnection (%s) save error\n",addr->ipaddr);
        }
    } else printf("killconnection cant get ind for ipaddr.%s\n",addr->ipaddr);
    memset(addr,0,sizeof(*addr));
    addr->usock = -1;
    if ( rank > 0 )
        iguana_possible_peer(coin,ipaddr);
}

/*int32_t pp_bind(char *hostname,uint16_t port)
{
    int32_t opt; struct sockaddr_in addr; socklen_t addrlen = sizeof(addr);
    struct hostent* hostent = gethostbyname(hostname);
    if (hostent == NULL) {
        PostMessage("gethostbyname() returned error: %d", errno);
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr.s_addr, hostent->h_addr_list[0], hostent->h_length);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("socket() failed: %s", strerror(errno));
        return -1;
    }
    opt = 1;
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(void*)&opt,sizeof(opt));
#ifdef __APPLE__
    setsockopt(sock,SOL_SOCKET,SO_NOSIGPIPE,&opt,sizeof(opt));
#endif
    //timeout.tv_sec = 0;
    //timeout.tv_usec = 1000;
    //setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout));
    int result = bind(sock, (struct sockaddr*)&addr, addrlen);
    if (result != 0) {
        printf("bind() failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return(sock);
}*/

int32_t iguana_socket(int32_t bindflag,char *hostname,uint16_t port)
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
        timeout.tv_usec = 10000;
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
    if ( bindflag != 0 && listen(sock,100) != 0 )
    {
        printf("listen(%s) port.%d failed: %s sock.%d. errno.%d\n",hostname,port,strerror(errno),sock,errno);
        if ( sock >= 0 )
            close(sock);
        return(-1);
    }
    return(sock);
}

int32_t iguana_send(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *serialized,int32_t len)
{
    int32_t numsent,remains,usock;
    if ( addr == 0 && coin->peers.numranked > 1 )
        addr = coin->peers.ranked[rand() % coin->peers.numranked];
    if ( addr == 0 )
        return(-1);
    usock = addr->usock;
    if ( usock < 0 || addr->dead != 0 )
        return(-1);
    remains = len;
    //printf(" send.(%s) %d bytes to %s\n",(char *)&serialized[4],len,addr->ipaddr);// getchar();
    if ( strcmp((char *)&serialized[4],"ping") == 0 )
        addr->sendmillis = OS_milliseconds();
    if ( len > IGUANA_MAXPACKETSIZE )
        printf("sending too big! %d\n",len);
    while ( remains > 0 )
    {
        if ( coin->peers.shuttingdown != 0 )
            return(-1);
        if ( (numsent= (int32_t)send(usock,serialized,remains,MSG_NOSIGNAL)) < 0 )
        {
            if ( errno != EAGAIN && errno != EWOULDBLOCK )
            {
                printf("%s: %s numsent.%d vs remains.%d len.%d errno.%d (%s) usock.%d\n",serialized+4,addr->ipaddr,numsent,remains,len,errno,strerror(errno),addr->usock);
                printf("bad errno.%d %s zombify.%p\n",errno,strerror(errno),&addr->dead);
                addr->dead = (uint32_t)time(NULL);
                return(-errno);
            } //else usleep(*sleeptimep), *sleeptimep *= 1.1;
        }
        else if ( remains > 0 )
        {
            remains -= numsent;
            serialized += numsent;
            if ( remains > 0 )
                printf("iguana sent.%d remains.%d of len.%d\n",numsent,remains,len);
        }
    }
    addr->totalsent += len;
    //printf(" sent.%d bytes to %s\n",len,addr->ipaddr);// getchar();
    return(len);
}

int32_t iguana_queue_send(struct iguana_info *coin,struct iguana_peer *addr,int32_t delay,uint8_t *serialized,char *cmd,int32_t len,int32_t getdatablock,int32_t forceflag)
{
    struct iguana_packet *packet; int32_t datalen;
    if ( addr == 0 )
    {
        printf("iguana_queue_send null addr\n");
        exit(-1);
        return(-1);
    }
    datalen = iguana_sethdr((void *)serialized,coin->chain->netmagic,cmd,&serialized[sizeof(struct iguana_msghdr)],len);
    if ( strcmp("getaddr",cmd) == 0 && time(NULL) < addr->lastgotaddr+300 )
        return(0);
    if ( strcmp("version",cmd) == 0 )
        return(iguana_send(coin,addr,serialized,datalen));
    packet = mycalloc('S',1,sizeof(struct iguana_packet) + datalen);
    packet->datalen = datalen;
    packet->addr = addr;
    if ( delay != 0 )
    {
        if ( delay > IGUANA_MAXDELAY_MILLIS )
            delay = IGUANA_MAXDELAY_MILLIS;
        packet->embargo = tai_now();
    }
    memcpy(packet->serialized,serialized,datalen);
    //printf("%p queue send.(%s) %d to (%s) %x\n",packet,serialized+4,datalen,addr->ipaddr,addr->ipbits);
    queue_enqueue("sendQ",&addr->sendQ,&packet->DL,0);
    return(datalen);
}

int32_t iguana_recv(int32_t usock,uint8_t *recvbuf,int32_t len)
{
    int32_t recvlen,remains = len;
    while ( remains > 0 )
    {
        if ( (recvlen= (int32_t)recv(usock,recvbuf,remains,0)) < 0 )
        {
            if ( errno == EAGAIN )
            {
#ifdef IGUANA_DEDICATED_THREADS
                //printf("EAGAIN for len %d, remains.%d\n",len,remains);
#endif
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
            //if ( remains > 0 )
                //printf("got %d remains.%d of total.%d\n",recvlen,remains,len);
        }
    }
    return(len);
}

void iguana_parsebuf(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msghdr *H,uint8_t *buf,int32_t len)
{
    struct iguana_msghdr checkH;
    memset(&checkH,0,sizeof(checkH));
    iguana_sethdr(&checkH,coin->chain->netmagic,H->command,buf,len);
    if ( memcmp(&checkH,H,sizeof(checkH)) == 0 )
    {
        //if ( strcmp(addr->ipaddr,"127.0.0.1") == 0 )
        //printf("%s parse.(%s) len.%d\n",addr->ipaddr,H.command,len);
        //printf("addr->dead.%u\n",addr->dead);
        if ( strcmp(H->command,"block") == 0 || strcmp(H->command,"tx") == 0 )
        {
            if ( addr->RAWMEM.ptr == 0 )
                iguana_meminit(&addr->RAWMEM,addr->ipaddr,0,IGUANA_MAXPACKETSIZE,0);
            if ( addr->TXDATA.ptr == 0 )
                iguana_meminit(&addr->TXDATA,"txdata",0,IGUANA_MAXPACKETSIZE,0);
            if ( addr->HASHMEM.ptr == 0 )
                iguana_meminit(&addr->HASHMEM,"HASHPTRS",0,256,0);//IGUANA_MAXPACKETSIZE*16,0);
            //printf("Init %s memory %p %p %p\n",addr->ipaddr,addr->RAWMEM.ptr,addr->TXDATA.ptr,addr->HASHMEM.ptr);
        }
        if ( iguana_parser(coin,addr,&addr->RAWMEM,&addr->TXDATA,&addr->HASHMEM,H,buf,len) < 0 || addr->dead != 0 )
        {
            printf("%p addr->dead.%d or parser break at %u\n",&addr->dead,addr->dead,(uint32_t)time(NULL));
            addr->dead = (uint32_t)time(NULL);
        }
        else
        {
            addr->numpackets++;
            addr->totalrecv += len;
            coin->totalrecv += len, coin->totalpackets++;
            //printf("next iter.(%s) numreferrals.%d numpings.%d\n",addr->ipaddr,addr->numreferrals,addr->numpings);
        }
    } else printf("header error from %s\n",addr->ipaddr);
}

void _iguana_processmsg(struct iguana_info *coin,int32_t usock,struct iguana_peer *addr,uint8_t *_buf,int32_t maxlen)
{
    int32_t len,recvlen; void *buf = _buf; struct iguana_msghdr H;
    if ( coin->peers.shuttingdown != 0 || addr->dead != 0 )
        return;
    //printf("%p got.(%s) from %s | usock.%d ready.%u dead.%u\n",addr,H.command,addr->ipaddr,addr->usock,addr->ready,addr->dead);
    memset(&H,0,sizeof(H));
    if ( (recvlen= (int32_t)iguana_recv(usock,(uint8_t *)&H,sizeof(H))) == sizeof(H) )
    {
        //printf("%p got.(%s) recvlen.%d from %s | usock.%d ready.%u dead.%u\n",addr,H.command,recvlen,addr->ipaddr,addr->usock,addr->ready,addr->dead);
        if ( coin->peers.shuttingdown != 0 || addr->dead != 0 )
            return;
        if ( (len= iguana_validatehdr(&H)) >= 0 )
        {
            if ( len > 0 )
            {
                if ( len > IGUANA_MAXPACKETSIZE )
                {
                    printf("buffer %d too small for %d\n",IGUANA_MAXPACKETSIZE,len);
                    return;
                }
                if ( len > maxlen )
                    buf = mycalloc('p',1,len);
                if ( (recvlen= iguana_recv(usock,buf,len)) < 0 )
                {
                    printf("recv error on (%s) len.%d errno.%d (%s)\n",H.command,len,-recvlen,strerror(-recvlen));
                    if ( buf != _buf )
                        myfree(buf,len);
                    addr->dead = (uint32_t)time(NULL);
                    return;
                }
            }
            iguana_parsebuf(coin,addr,&H,buf,len);
            if ( buf != _buf )
                myfree(buf,len);
            return;
        }
        printf("invalid header received from (%s)\n",addr->ipaddr);
        addr->dead = 1;
    }
    printf("%s recv error on hdr errno.%d (%s) -> zombify\n",addr->ipaddr,-recvlen,strerror(-recvlen));
#ifndef IGUANA_DEDICATED_THREADS
    addr->dead = 1;
#endif
}

void iguana_gotdata(struct iguana_info *coin,struct iguana_peer *addr,int32_t height)
{
    struct iguana_iAddr *iA;
    if ( addr != 0 && height > addr->height && height < coin->longestchain )
    {
        if ( (iA= iguana_iAddrhashfind(coin,addr->ipbits,0)) != 0 && iA->height < height )
            iA->height = height;
        //iguana_set_iAddrheight(coin,addr->ipbits,height);
        addr->height = height;
    }
}

int32_t iguana_iAddrheight(struct iguana_info *coin,uint32_t ipbits)
{
    struct iguana_iAddr *iA;
    if ( (iA= iguana_iAddrhashfind(coin,ipbits,0)) != 0 )
        return(iA->height);
    return(0);
}

void iguana_startconnection(void *arg)
{
    int32_t i,n; char ipaddr[64]; struct iguana_peer *addr = arg; struct iguana_info *coin = 0;
    if ( addr == 0 || (coin= iguana_coinfind(addr->symbol)) == 0 )
    {
        printf("iguana_startconnection nullptrs addr.%p coin.%p\n",addr,coin);
        return;
    }
    addr->addrind = (int32_t)(((long)addr - (long)&coin->peers.active[0]) / sizeof(*addr));
    if ( addr->usock >= 0 )
    {
        return;
    }
    if ( strcmp(coin->name,addr->coinstr) != 0 )
    {
        printf("iguana_startconnection.%s mismatched coin.%p (%s) vs (%s)\n",addr->ipaddr,coin,coin->symbol,addr->coinstr);
        return;
    }
    if ( strcmp("127.0.0.1",addr->ipaddr) == 0 && (coin->myservices & NODE_NETWORK) != 0 )
    {
        printf("avoid self-loopback\n");
        return;
    }
    //printf("startconnection.(%s) pending.%u usock.%d addrind.%d\n",addr->ipaddr,addr->pending,addr->usock,addr->addrind);
    addr->pending = (uint32_t)time(NULL);
    if ( addr->usock < 0 )
        addr->usock = iguana_socket(0,addr->ipaddr,coin->chain->portp2p);
    if ( addr->usock < 0 || coin->peers.shuttingdown != 0 )
    {
        strcpy(ipaddr,addr->ipaddr);
        iguana_iAkill(coin,addr,1);
        //printf("refused PEER KILLED. for %s:%d usock.%d\n",addr->ipaddr,coin->chain->portp2p,addr->usock);
    }
    else
    {
        addr->ready = (uint32_t)time(NULL);
        addr->ipbits = (uint32_t)calc_ipbits(addr->ipaddr);
        addr->dead = 0;
        addr->pending = 0;
        addr->height = iguana_iAddrheight(coin,addr->ipbits);
        strcpy(addr->symbol,coin->symbol);
        strcpy(addr->coinstr,coin->name);
        coin->peers.lastpeer = (uint32_t)time(NULL);
        for (i=n=0; i<coin->MAXPEERS; i++)
            if ( coin->peers.active[i].usock > 0 )
                n++;
        iguana_iAconnected(coin,addr);
        coin->peers.numconnected++;
        printf("PEER CONNECTED.%d:%d of max.%d! %s:%d usock.%d\n",coin->peers.numconnected,n,coin->MAXPEERS,addr->ipaddr,coin->chain->portp2p,addr->usock);
        if ( strcmp("127.0.0.1",addr->ipaddr) == 0 )
            coin->peers.localaddr = addr;
#ifdef IGUANA_DEDICATED_THREADS
        //iguana_launch("recv",iguana_dedicatedrecv,addr,IGUANA_RECVTHREAD);
        iguana_dedicatedloop(coin,addr);
#endif
    }
}

struct iguana_peer *iguana_peerslot(struct iguana_info *coin,uint32_t ipbits)
{
    int32_t i; struct iguana_peer *addr; char ipaddr[64];
    expand_ipbits(ipaddr,ipbits);
#ifdef IGUANA_DISABLEPEERS
    if ( strcmp("127.0.0.1",ipaddr) != 0 )
        return(0);
#endif
    //portable_mutex_lock(&coin->peers_mutex);
    for (i=0; i<coin->MAXPEERS && i<IGUANA_MAXPEERS; i++)
    {
        addr = &coin->peers.active[i];
        addr->addrind = i;
        if ( addr->usock >= 0 || addr->pending != 0 || addr->ipbits == ipbits || strcmp(ipaddr,addr->ipaddr) == 0 )
        {
            //printf("skip.(%s) usock.%d pending.%d ipbits.%x vs %x lag.%ld\n",addr->ipaddr,addr->usock,addr->pending,addr->ipbits,iA->ipbits,time(NULL)-addr->pending);
            continue;
        }
        portable_mutex_lock(&coin->peers_mutex);
        if ( addr->ipbits == 0 )
        {
            iguana_initpeer(coin,addr,ipbits);
            //addr->pending = (uint32_t)time(NULL);
            portable_mutex_unlock(&coin->peers_mutex);
            return(addr);
        }
        portable_mutex_unlock(&coin->peers_mutex);
    }
    return(0);
}

void *iguana_iAddriterator(struct iguana_info *coin,struct iguana_iAddr *iA)
{
    struct iguana_peer *addr = 0;
    if ( iA != 0 && iA->ipbits != 0 && iguana_numthreads(coin,1 << IGUANA_CONNTHREAD) < IGUANA_MAXCONNTHREADS && iA->status == IGUANA_PEER_ELIGIBLE )
    {
        //printf("%x\n",iA->ipbits);
        //portable_mutex_unlock(&coin->peers_mutex);
        if ( (addr= iguana_peerslot(coin,iA->ipbits)) != 0 )//i < coin->MAXPEERS && i < IGUANA_MAXPEERS && addr != 0 )
        {
            //printf("pend.%d status.%d possible peer.(%s).%x threads %d %d %d %d\n",addr->pending,iA->status,addr->ipaddr,addr->ipbits,iguana_numthreads(coin,0),iguana_numthreads(coin,1),iguana_numthreads(coin,2),iguana_numthreads(coin,3));
            if ( addr->pending == 0 && iA->status != IGUANA_PEER_CONNECTING )
            {
                iA->status = IGUANA_PEER_CONNECTING;
                addr->pending = (uint32_t)time(NULL);
                if ( iguana_rwiAddrind(coin,1,iA,iA->hh.itemind) > 0 )
                {
                    //printf("iA.%p iguana_startconnection.(%s) status.%d pending.%d\n",iA,addr->ipaddr,iA->status,addr->pending);
                    iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
                } else printf("error rwiAddrind.%d\n",iA->hh.itemind);
            }
        } else printf("no open peer slots left\n");
    }
    //else if ( iA != 0 )
    //    printf("iA->ipbits %d, %d iguana_numthreads(coin,1 << IGUANA_CONNTHREAD) status.%d\n",iA->ipbits,iguana_numthreads(coin,1 << IGUANA_CONNTHREAD),iA->status);
    //else printf("connector null iA\n");
    return(0);
}
 
uint32_t iguana_possible_peer(struct iguana_info *coin,char *ipaddr)
{
    char checkaddr[64]; uint32_t ipbits,now = (uint32_t)time(NULL); int32_t i,n; struct iguana_iAddr *iA;
    if ( ipaddr != 0 )
    {
        //printf("%p Q possible peer.(%s)\n",coin,ipaddr);
        queue_enqueue("possibleQ",&coin->possibleQ,queueitem(ipaddr),1);
        return((uint32_t)time(NULL));
    }
    else if ( (ipaddr= queue_dequeue(&coin->possibleQ,1)) == 0 )
        return((uint32_t)time(NULL));
#ifdef IGUANA_DISABLEPEERS
    if ( strcmp(ipaddr,"127.0.0.1") != 0 )
    {
        free_queueitem(ipaddr);
        return((uint32_t)time(NULL));
    }
#endif
    //printf("check possible peer.(%s)\n",ipaddr);
    for (i=n=0; i<coin->MAXPEERS; i++)
    {
        if ( strcmp(ipaddr,coin->peers.active[i].ipaddr) == 0 )
        {
            printf("(%s) already active\n",ipaddr);
            free_queueitem(ipaddr);
            return((uint32_t)time(NULL));
        }
        else if ( coin->peers.active[i].ipaddr != 0 )
            n++;
    }
    if ( n >= coin->MAXPEERS-(coin->MAXPEERS>>3)-1 )
        return((uint32_t)time(NULL));
    if ( strncmp("0.0.0",ipaddr,5) != 0 && strcmp("0.0.255.255",ipaddr) != 0 && strcmp("1.0.0.0",ipaddr) != 0 )
    {
        if ( (ipbits= (uint32_t)calc_ipbits(ipaddr)) != 0 )
        {
            expand_ipbits(checkaddr,ipbits);
            if ( strcmp(checkaddr,ipaddr) == 0 )
            {
                //printf("valid ipaddr.(%s) MAXPEERS.%d\n",ipaddr,coin->MAXPEERS);
                if ( (iA= iguana_iAddrhashfind(coin,ipbits,1)) != 0 )
                {
                    if ( iA->status != IGUANA_PEER_CONNECTING && iA->status != IGUANA_PEER_READY && iA->status != IGUANA_PEER_ELIGIBLE )
                    {
                        if ( (iA->lastconnect == 0 || iA->lastkilled == 0) || (iA->numconnects > 0 && iA->lastconnect > (now - IGUANA_RECENTPEER)) || iA->lastkilled < now-600 )
                        {
                            iA->status = IGUANA_PEER_ELIGIBLE;
                            if ( iguana_rwiAddrind(coin,1,iA,iA->hh.itemind) == 0 )
                                printf("error updating status for (%s) ind.%d\n",ipaddr,iA->hh.itemind);
                            iguana_iAddriterator(coin,iA);
                        } else printf("ignore.(%s) lastconnect.%u lastkilled.%u numconnects.%d\n",ipaddr,iA->lastconnect,iA->lastkilled,iA->numconnects);
                    } //else printf("skip.(%s) ind.%d status.%d\n",ipaddr,iA->hh.itemind,iA->status);
                } else printf("cant find (%s) which should have been created\n",ipaddr);
            } else printf("reject ipaddr.(%s)\n",ipaddr);
        }
    }
    free_queueitem(ipaddr);
    return((uint32_t)time(NULL));
}

void iguana_processmsg(void *ptr)
{
    struct iguana_info *coin; uint8_t buf[32768]; struct iguana_peer *addr = ptr;
    if ( addr == 0 || (coin= iguana_coinfind(addr->symbol)) == 0 || addr->dead != 0 )
    {
        printf("iguana_processmsg cant find addr.%p symbol.%s\n",addr,addr!=0?addr->symbol:0);
        return;
    }
    _iguana_processmsg(coin,addr->usock,addr,buf,sizeof(buf));
    addr->startrecv = 0;
}

int32_t iguana_pollsendQ(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct iguana_packet *packet;
    if ( (packet= queue_dequeue(&addr->sendQ,0)) != 0 )
    {
        //printf("%s: send.(%s) usock.%d dead.%u ready.%u\n",addr->ipaddr,packet->serialized+4,addr->usock,addr->dead,addr->ready);
        if ( strcmp((char *)&packet->serialized[4],"getdata") == 0 )
        {
            printf("unexpected getdata for %s\n",addr->ipaddr);
            myfree(packet,sizeof(*packet) + packet->datalen);
        }
        else if ( packet->embargo.x == 0 )
        {
            
            iguana_send(coin,addr,packet->serialized,packet->datalen);
            myfree(packet,sizeof(*packet) + packet->datalen);
            return(1);
        }
        else queue_enqueue("embargo",&addr->sendQ,&packet->DL,0);
    }
    return(0);
}

int32_t iguana_pollrecv(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *buf,int32_t bufsize)
{
#ifndef IGUANA_DEDICATED_THREADS
    strcpy(addr->symbol,coin->symbol);
    if ( addr != coin->peers.localaddr )
    {
        addr->startrecv = (uint32_t)time(NULL);
        iguana_launch("processmsg",iguana_processmsg,addr,IGUANA_RECVTHREAD);
    }
    else
#endif
        _iguana_processmsg(coin,addr->usock,addr,buf,bufsize);
    return(1);
}

#ifdef IGUANA_PEERALLOC
void *iguana_peeralloc(struct iguana_info *coin,struct iguana_peer *addr,int32_t datalen)
{
    struct OS_memspace *mem; long i,iter; int32_t j,diff,size,bestfit; void *ptr;
    //printf("iguana_peeralloc.%s\n",addr->ipaddr);
    while ( 1 )
    {
        bestfit = -1;
        for (iter=0; iter<3; iter++)
        {
            for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
            {
                mem = addr->SEROUT[i];
                if ( mem->threadsafe != 0 )
                    portable_mutex_lock(&mem->mutex);
                if ( iter < 2 && mem->availptrs > 0 )
                {
                    for (j=0; j<mem->numptrs; j++)
                    {
                        if ( mem->allocsizes[j] == 0 )
                        {
                            size = mem->maxsizes[j];
                            if ( size >= datalen )
                            {
                                diff = (size - datalen);
                                if ( diff == 0 || (iter == 1 && diff == bestfit) )
                                {
                                    mem->allocsizes[j] = datalen;
                                    mem->availptrs--;
                                    //printf("%s availptrs.%d size.%d j.%d diff.%d bestfit.%d %p.%d max.%d\n",mem->name,mem->availptrs,size,j,diff,bestfit,mem->ptrs[j],size,mem->maxsizes[j]);
                                    if ( mem->threadsafe != 0 )
                                        portable_mutex_unlock(&mem->mutex);
                                    return(mem->ptrs[j]);
                                }
                                else if ( iter == 0 && diff < (datalen >> 3) && diff < 4096 )
                                    bestfit = diff;
                            }
                        }
                    }
                }
                else if ( iter == 2 && (ptr= iguana_memalloc(mem,datalen,0)) != 0 )
                {
                    if ( mem->threadsafe != 0 )
                        portable_mutex_unlock(&mem->mutex);
                    ///printf("alloc iter.2\n");
                    return(ptr);
                }
                if ( mem->threadsafe != 0 )
                    portable_mutex_unlock(&mem->mutex);
                //printf("iter.%ld bestfit.%d\n",iter,bestfit);
            }
        }
        printf("iguana_peeralloc: cant find memory. wait and hope...\n");
        sleep(5);
    }
    return(0);
}

int64_t iguana_peerallocated(struct iguana_info *coin,struct iguana_peer *addr)
{
    int32_t i; int64_t total = 0;
    for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
        if ( addr->SEROUT[i] != 0 )
            total += iguana_memallocated(addr->SEROUT[i]);
    return(total);
}

int64_t iguana_peerfree(struct iguana_info *coin,struct iguana_peer *addr,void *ptr,int32_t datalen)
{
    struct OS_memspace *mem; long offset,i; int64_t avail = -1;
    //printf("iguana_peerfree.%p %d\n",ptr,datalen);
    for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
    {
        mem = addr->SEROUT[i];
        offset = ((long)ptr - (long)mem->ptr);
        if ( offset >= 0 && offset+datalen < mem->totalsize )
        {
            if ( iguana_memfree(mem,ptr,datalen) < 0 || (avail= iguana_peerallocated(coin,addr)) < 0 )
            {
                printf("iguana_peerfree: corrupted mem avail.%lld ptr.%p %d\n",(long long)avail,ptr,datalen);
                exit(-1);
            }
            return(avail);
        }
    }
    printf("iguana_peerfree: cant find ptr.%p %d\n",ptr,datalen);
    return(-1);
}
#else
void *iguana_peeralloc(struct iguana_info *coin,struct iguana_peer *addr,int32_t datalen)
{
    addr->allocated += datalen;
    return(calloc(1,datalen));
}

int64_t iguana_peerfree(struct iguana_info *coin,struct iguana_peer *addr,void *ptr,int32_t datalen)
{
    addr->freed += datalen;
    free(ptr);
    return(1);
}

int64_t iguana_peerallocated(struct iguana_info *coin,struct iguana_peer *addr)
{
    return(addr->allocated - addr->freed);
}
#endif

void iguana_dedicatedloop(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct pollfd fds; uint8_t *buf,serialized[64]; struct iguana_bundlereq *req;
    int32_t bufsize,flag,run,timeout = coin->polltimeout == 0 ? 10 : coin->polltimeout;
#ifdef IGUANA_PEERALLOC
    int32_t i;  int64_t remaining; struct OS_memspace *mem[sizeof(addr->SEROUT)/sizeof(*addr->SEROUT)];
    for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
    {
        mem[i] = mycalloc('s',1,sizeof(*mem[i]));
        addr->SEROUT[i] = mem[i];
        mem[i]->totalsize = IGUANA_MAXPACKETSIZE;
        mem[i]->ptr = mycalloc('P',1,mem[i]->totalsize);
        mem[i]->used = 0;
        strcpy(mem[i]->name,addr->ipaddr);
        //mem[i]->threadsafe = 1;
        iguana_memreset(mem[i]);
    }
#endif
    addr->addrind = (int32_t)(((long)addr - (long)&coin->peers.active[0]) / sizeof(*addr));
    printf("start dedicatedloop.%s addrind.%d\n",addr->ipaddr,addr->addrind);
    addr->maxfilehash2 = IGUANA_MAXFILEITEMS;
    bufsize = IGUANA_MAXPACKETSIZE;
    buf = mycalloc('r',1,bufsize);
    printf("send version myservices.%llu to (%s)\n",(long long)coin->myservices,addr->ipaddr);
    sleep(1);
    iguana_send_version(coin,addr,coin->myservices);
    iguana_queue_send(coin,addr,0,serialized,"getaddr",0,0,0);
    printf("after send version\n");
    run = 0;
    while ( addr->usock >= 0 && addr->dead == 0 && coin->peers.shuttingdown == 0 )
    {
        if ( 1 && (req= queue_dequeue(&coin->cacheQ,0)) != 0 )
        {
            if ( req->datalen != 0 )
            {
                //printf("CACHE parse[%d] %s\n",req->recvlen,req->H.command);
                iguana_parsebuf(coin,addr,&req->H,req->serialized,req->recvlen);
            }
            coin->cachefreed++;
            myfree(req,req->allocsize);
            continue;
        }
        flag = 0;
        memset(&fds,0,sizeof(fds));
        fds.fd = addr->usock;
        fds.events |= (POLLOUT | POLLIN);
        if (  poll(&fds,1,timeout) > 0 && (fds.revents & POLLOUT) != 0 )
            flag += iguana_pollsendQ(coin,addr);
        if ( flag == 0 )
        {
            if ( (fds.revents & POLLIN) != 0 )
            {
                flag += iguana_pollrecv(coin,addr,buf,bufsize);
                if ( addr->dead != 0 )
                    break;
            }
            if ( flag == 0 )
            {
                if ( time(NULL) > addr->pendtime+30 )
                {
                    if ( addr->pendblocks > 0 )
                        addr->pendblocks--;
                    if ( addr->pendhdrs > 0 )
                        addr->pendhdrs--;
                    addr->pendtime = 0;
                }
                if ( coin->active != 0 && (fds.revents & POLLOUT) != 0 )
                {
                    flag += iguana_pollQsPT(coin,addr);
                    if ( addr->dead != 0 )
                        break;
                }
            }
            if ( flag == 0 )
            {
                if ( run++ > 10000 )
                {
                    //printf("sleep\n");
                    sleep(1);
                }
                else if ( addr->rank != 1 )
                    usleep(coin->polltimeout*2500 + (rand() % (coin->polltimeout*2500)));
                else usleep(100 + coin->polltimeout*1000);
            }
        }
        if ( flag != 0 )
            run = 0;
        if ( coin->isRT != 0 && addr->rank > coin->MAXPEERS && (rand() % 100) == 0 )
        {
            printf("isRT and low rank.%d ",addr->rank);
            addr->dead = 1;
        }
    }
    printf(">>>>>>>>>>>>>> finish dedicatedloop.%s\n",addr->ipaddr);
    //if ( addr->fp != 0 )
    //    fclose(addr->fp);
    iguana_iAkill(coin,addr,addr->dead != 0);
    myfree(buf,bufsize);
    if ( addr->filehash2 != 0 )
        myfree(addr->filehash2,addr->maxfilehash2*sizeof(*addr->filehash2));
    iguana_mempurge(&addr->RAWMEM);
    iguana_mempurge(&addr->TXDATA);
    iguana_mempurge(&addr->HASHMEM);
#ifdef IGUANA_PEERALLOC
    while ( (remaining= iguana_peerallocated(coin,addr)) > 0 )
    {
        char str[65];
        printf("waiting for helperQ to flush peer mem %s\n",mbstr(str,remaining));
        sleep(5);
    }
    for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
    {
        if ( addr->SEROUT[i] != 0 )
        {
            if ( addr->SEROUT[i]->ptr != 0 )
                myfree(addr->SEROUT[i]->ptr,IGUANA_MAXPACKETSIZE);
            myfree(addr->SEROUT[i],sizeof(*addr->SEROUT[i]));
        }
    }
#endif
    coin->peers.numconnected--;
}

void iguana_peersloop(void *ptr)
{
#ifndef IGUANA_DEDICATED_THREADS
    struct pollfd fds[IGUANA_MAXPEERS]; struct iguana_info *coin = ptr;
    struct iguana_peer *addr; uint8_t *bufs[IGUANA_MAXPEERS];
    int32_t i,j,n,r,nonz,flag,bufsizes[IGUANA_MAXPEERS],timeout=1;
    memset(fds,0,sizeof(fds));
    memset(bufs,0,sizeof(bufs));
    memset(bufsizes,0,sizeof(bufsizes));
    while ( 1 )
    {
        while ( coin->peers.shuttingdown != 0 )
        {
            printf("peers shuttingdown\n");
            sleep(3);
        }
        flag = 0;
        r = (rand() % coin->MAXPEERS);
        for (j=n=nonz=0; j<coin->MAXPEERS; j++)
        {
            i = (j + r) % coin->MAXPEERS;
            addr = &coin->peers.active[i];
            fds[i].fd = -1;
            if ( addr->usock >= 0 && addr->dead == 0 && addr->ready != 0 && (addr->startrecv+addr->startsend) != 0 )
            {
                fds[i].fd = addr->usock;
                fds[i].events = (addr->startrecv != 0) * POLLIN |  (addr->startsend != 0) * POLLOUT;
                nonz++;
            }
        }
        if ( nonz != 0 && poll(fds,coin->MAXPEERS,timeout) > 0 )
        {
            for (j=0; j<coin->MAXPEERS; j++)
            {
                i = (j + r) % coin->MAXPEERS;
                addr = &coin->peers.active[i];
                if ( addr->usock < 0 || addr->dead != 0 || addr->ready == 0 )
                    continue;
                if ( addr->startrecv == 0 && (fds[i].revents & POLLIN) != 0 && iguana_numthreads(1 << IGUANA_RECVTHREAD) < IGUANA_MAXRECVTHREADS )
                {
                    if ( bufs[i] == 0 )
                        bufsizes[i] = IGUANA_MAXPACKETSIZE, bufs[i] = mycalloc('r',1,bufsizes[i]);
                    flag += iguana_pollrecv(coin,addr,bufs[i],bufsizes[i]);
                }
                if ( addr->startsend == 0 && (fds[i].revents & POLLOUT) != 0 && iguana_numthreads(1 << IGUANA_SENDTHREAD) < IGUANA_MAXSENDTHREADS )
                {
                    if ( iguana_pollsendQ(coin,addr) == 0 )
                        flag += iguana_poll(coin,addr);
                    else flag++;
                }
            }
        }
        if ( flag == 0 )
            usleep(1000);
    }
#endif
}
