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

// 1. add rpc hooks, debug
// 2. sig validate in fsm

struct dex_nanomsghdr
{
    uint32_t size,datalen,crc32;
    uint8_t version0,version1,packet[];
} PACKED;

void dex_init(struct supernet_info *myinfo)
{
    strcpy(myinfo->dexseed_ipaddr,"78.47.196.146");
    myinfo->dexipbits[0] = (uint32_t)calc_ipbits(myinfo->dexseed_ipaddr);
    myinfo->numdexipbits = 1;
    portable_mutex_init(&myinfo->dexmutex);
}

char *nanomsg_tcpname(struct supernet_info *myinfo,char *str,char *ipaddr,uint16_t port)
{
    if ( myinfo != 0 ) // bind path)
    {
        if ( myinfo->bindaddr[0] != 0 && strcmp(ipaddr,myinfo->ipaddr) == 0 )
            ipaddr = myinfo->bindaddr;
    }
    sprintf(str,"tcp://%s:%u",ipaddr,port);
    return(str);
}

static int _increasing_ipbits(const void *a,const void *b)
{
#define uint32_a (*(uint32_t *)a)
#define uint32_b (*(uint32_t *)b)
	if ( uint32_b > uint32_a )
		return(-1);
	else if ( uint32_b < uint32_a )
		return(1);
	return(0);
#undef uint32_a
#undef uint32_b
}

void dex_packet(struct supernet_info *myinfo,struct dex_nanomsghdr *dexp,int32_t size)
{
    printf("DEX_PACKET.[%d]\n",size);
}

int32_t dex_reqsend(struct supernet_info *myinfo,uint8_t *data,int32_t datalen)
{
    struct dex_nanomsghdr *dexp; char ipaddr[64],str[128]; int32_t retval=0,timeout,i,n,size,recvbytes,sentbytes = 0; uint32_t crc32,*retptr,ipbits;
    if ( myinfo->reqsock < 0 && (myinfo->reqsock= nn_socket(AF_SP,NN_REQ)) >= 0 )
    {
        if ( nn_connect(myinfo->reqsock,nanomsg_tcpname(0,str,myinfo->dexseed_ipaddr,REP_SOCK)) < 0 )
        {
            nn_close(myinfo->reqsock);
            myinfo->reqsock = -1;
        }
        else
        {
            if ( myinfo->subsock < 0 && (myinfo->subsock= nn_socket(AF_SP,NN_SUB)) >= 0 )
            {
                if ( nn_connect(myinfo->subsock,nanomsg_tcpname(0,str,myinfo->dexseed_ipaddr,PUB_SOCK)) < 0 )
                {
                    nn_close(myinfo->reqsock);
                    myinfo->reqsock = -1;
                    nn_close(myinfo->subsock);
                    myinfo->subsock = -1;
                }
                else
                {
                    timeout = 100;
                    nn_setsockopt(myinfo->reqsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                    nn_setsockopt(myinfo->subsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                    nn_setsockopt(myinfo->reqsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                    nn_setsockopt(myinfo->subsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                    nn_setsockopt(myinfo->subsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
                    printf("DEXINIT req.%d sub.%d\n",myinfo->reqsock,myinfo->subsock);
                }
            }
        }
    }
    if ( myinfo->reqsock >= 0 )
    {
        crc32 = calc_crc32(0,data,datalen);
        size = (int32_t)(sizeof(*dexp) + datalen);
        dexp = calloc(1,size); // endian dependent!
        dexp->size = size;
        dexp->datalen = datalen;
        dexp->crc32 = crc32;
        dexp->version0 = DEX_VERSION & 0xff;
        dexp->version1 = (DEX_VERSION >> 8) & 0xff;
        memcpy(dexp->packet,data,datalen);
        sentbytes = nn_send(myinfo->reqsock,dexp,size,0);
        if ( (recvbytes= nn_recv(myinfo->reqsock,&retptr,NN_MSG,0)) >= 0 )
        {
            portable_mutex_lock(&myinfo->dexmutex);
            ipbits = *retptr;
            expand_ipbits(ipaddr,ipbits);
            printf("req returned.[%d] %08x %s\n",recvbytes,*retptr,ipaddr);
            n = myinfo->numdexipbits;
            for (i=0; i<n; i++)
                if ( ipbits == myinfo->dexipbits[i] )
                    break;
            if ( i == n && n < 64 )
            {
                myinfo->dexipbits[n++] = ipbits;
                qsort(myinfo->dexipbits,n,sizeof(uint32_t),_increasing_ipbits);
                if ( (myinfo->numdexipbits= n) < 3 )
                {
                    if ( myinfo->subsock >= 0 )
                        nn_connect(myinfo->subsock,nanomsg_tcpname(0,str,ipaddr,PUB_SOCK));
                }
                nn_connect(myinfo->reqsock,nanomsg_tcpname(0,str,ipaddr,REP_SOCK));
            }
            portable_mutex_unlock(&myinfo->dexmutex);
            nn_freemsg(retptr);
        } else retval = -2;
        free(dexp);
        printf("DEXREQ.[%d] crc32.%08x datalen.%d sent.%d\n",size,dexp->crc32,datalen,sentbytes);
    } else retval = -1;
    return(retval);
}

int32_t dex_crc32find(struct supernet_info *myinfo,uint32_t crc32)
{
    int32_t i,firstz = -1;
    for (i=0; i<sizeof(myinfo->dexcrcs)/sizeof(*myinfo->dexcrcs); i++)
    {
        if ( myinfo->dexcrcs[i] == crc32 )
        {
            //printf("NANODUPLICATE.%08x\n",crc32);
            return(-1);
        }
        else if ( firstz < 0 && myinfo->dexcrcs[i] == 0 )
            firstz = i;
    }
    if ( firstz < 0 )
        firstz = (rand() % (sizeof(myinfo->dexcrcs)/sizeof(*myinfo->dexcrcs)));
    myinfo->dexcrcs[firstz] = crc32;
    return(firstz);
}

int32_t dex_packetcheck(struct supernet_info *myinfo,struct dex_nanomsghdr *dexp,int32_t size)
{
    int32_t firstz; uint32_t crc32;
    if ( dexp->version0 == (DEX_VERSION & 0xff) && dexp->version1 == ((DEX_VERSION >> 8) & 0xff) )
    {
        if ( dexp->datalen == (size - sizeof(*dexp)) )
        {
            crc32 = calc_crc32(0,dexp->packet,dexp->datalen);
            if ( dexp->crc32 == crc32 && (firstz= dex_crc32find(myinfo,crc32)) >= 0 )
                return(0);
        }
    }
    return(-1);
}

void dex_subsock_poll(struct supernet_info *myinfo)
{
    int32_t size,n=0; struct dex_nanomsghdr *dexp;
    while ( (size= nn_recv(myinfo->subsock,&dexp,NN_MSG,0)) >= 0 )
    {
        n++;
        if ( dex_packetcheck(myinfo,dexp,size) == 0 )
        {
            printf("SUBSOCK.%08x",dexp->crc32);
            dex_packet(myinfo,dexp,size);
        }
        if ( dexp != 0 )
            nn_freemsg(dexp), dexp = 0;
        if ( size == 0 || n++ > 100 )
            break;
    }
}

#if ISNOTARYNODE

struct dpow_nanoutxo
{
    bits256 srcutxo,destutxo;
    uint64_t bestmask,recvmask;
    uint32_t pendingcrcs[2],paxwdcrc;
    uint16_t srcvout,destvout;
    uint8_t sigs[2][DPOW_MAXSIGLEN],siglens[2],pad,bestk;
} PACKED;

struct dpow_nanomsghdr
{
    bits256 srchash,desthash;
    struct dpow_nanoutxo ratify,notarize;
    uint32_t channel,height,size,datalen,crc32,myipbits,numipbits,ipbits[64];
    char symbol[16];
    uint8_t senderind,version0,version1,packet[];
} PACKED;


uint64_t dpow_ratifybest(uint64_t refmask,struct dpow_block *bp,int8_t *lastkp);
struct dpow_block *dpow_heightfind(struct supernet_info *myinfo,struct dpow_info *dp,int32_t height);
int32_t dpow_signedtxgen(struct supernet_info *myinfo,struct dpow_info *dp,struct iguana_info *coin,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t myind,uint32_t deprec,int32_t src_or_dest,int32_t useratified);
void dpow_sigscheck(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,int32_t myind,int32_t src_or_dest,int8_t bestk,uint64_t bestmask,uint8_t pubkeys[64][33],int32_t numratified);

int32_t dpow_addnotary(struct supernet_info *myinfo,struct dpow_info *dp,char *ipaddr)
{
    char str[512]; uint32_t ipbits,*ptr; int32_t i,iter,n,retval = -1;
    portable_mutex_lock(&myinfo->notarymutex);
    if ( myinfo->dpowsock >= 0 && myinfo->dexsock >= 0 )
    {
        ipbits = (uint32_t)calc_ipbits(ipaddr);
        for (iter=0; iter<2; iter++)
        {
            if ( iter == 0 )
            {
                n = myinfo->numdpowipbits;
                ptr = myinfo->dpowipbits;
            }
            else
            {
                n = dp->numipbits;
                ptr = dp->ipbits;
            }
            for (i=0; i<n; i++)
                if ( ipbits == ptr[i] )
                    break;
            if ( i == n && n < 64 )
            {
                ptr[n] = ipbits;
                if ( iter == 0 && strcmp(ipaddr,myinfo->ipaddr) != 0 )
                {
                    retval = nn_connect(myinfo->dpowsock,nanomsg_tcpname(0,str,ipaddr,DPOW_SOCK));
                    printf("NN_CONNECT to (%s)\n",str);
                    retval = nn_connect(myinfo->dexsock,nanomsg_tcpname(0,str,ipaddr,DEX_SOCK));
                }
                n++;
                qsort(ptr,n,sizeof(uint32_t),_increasing_ipbits);
                if ( iter == 0 )
                    myinfo->numdpowipbits = n;
                else dp->numipbits = n;
                //for (i=0; i<n; i++)
                //    printf("%08x ",ptr[i]);
                //printf("addnotary.[%d] (%s) retval.%d (total %d %d) iter.%d\n",n,ipaddr,retval,myinfo->numdpowipbits,dp!=0?dp->numipbits:-1,iter);
            }
            if ( dp == 0 )
                break;
        }
    }
    portable_mutex_unlock(&myinfo->notarymutex);
    return(retval);
}

void dpow_nanomsginit(struct supernet_info *myinfo,char *ipaddr)
{
    char str[512]; int32_t timeout,retval,maxsize;
    if ( myinfo->ipaddr[0] == 0 )
    {
        printf("need to set ipaddr before nanomsg\n");
        return;
    }
    portable_mutex_lock(&myinfo->notarymutex);
    if ( myinfo->dpowsock < 0 && (myinfo->dpowsock= nn_socket(AF_SP,NN_BUS)) >= 0 )
    {
        if ( nn_bind(myinfo->dpowsock,nanomsg_tcpname(myinfo,str,myinfo->ipaddr,DPOW_SOCK)) < 0 )
        {
            printf("error binding to dpowsock (%s)\n",nanomsg_tcpname(myinfo,str,myinfo->ipaddr,DPOW_SOCK));
            nn_close(myinfo->dpowsock);
            myinfo->dpowsock = -1;
        }
        else
        {
            printf("NN_BIND to %s\n",str);
            if ( myinfo->dexsock < 0 && (myinfo->dexsock= nn_socket(AF_SP,NN_BUS)) >= 0 )
            {
                if ( nn_bind(myinfo->dexsock,nanomsg_tcpname(myinfo,str,myinfo->ipaddr,DEX_SOCK)) < 0 )
                {
                    printf("error binding to dexsock (%s)\n",nanomsg_tcpname(myinfo,str,myinfo->ipaddr,DEX_SOCK));
                    nn_close(myinfo->dexsock);
                    myinfo->dexsock = -1;
                    nn_close(myinfo->dpowsock);
                    myinfo->dpowsock = -1;
                }
                else
                {
                    if ( myinfo->pubsock < 0 && (myinfo->pubsock= nn_socket(AF_SP,NN_PUB)) >= 0 )
                    {
                        if ( nn_bind(myinfo->pubsock,nanomsg_tcpname(myinfo,str,myinfo->ipaddr,PUB_SOCK)) < 0 )
                        {
                            printf("error binding to pubsock (%s)\n",nanomsg_tcpname(myinfo,str,myinfo->ipaddr,PUB_SOCK));
                            nn_close(myinfo->pubsock);
                            myinfo->pubsock = -1;
                            nn_close(myinfo->dexsock);
                            myinfo->dexsock = -1;
                            nn_close(myinfo->dpowsock);
                            myinfo->dpowsock = -1;
                        }
                        else
                        {
                            if ( myinfo->repsock < 0 && (myinfo->repsock= nn_socket(AF_SP,NN_REP)) >= 0 )
                            {
                                if ( nn_bind(myinfo->repsock,nanomsg_tcpname(myinfo,str,myinfo->ipaddr,REP_SOCK)) < 0 )
                                {
                                    printf("error binding to repsock (%s)\n",nanomsg_tcpname(myinfo,str,myinfo->ipaddr,REP_SOCK));
                                    nn_close(myinfo->repsock);
                                    myinfo->repsock = -1;
                                    nn_close(myinfo->pubsock);
                                    myinfo->pubsock = -1;
                                    nn_close(myinfo->dexsock);
                                    myinfo->dexsock = -1;
                                    nn_close(myinfo->dpowsock);
                                    myinfo->dpowsock = -1;
                                }
                                else
                                {
                                    timeout = 100;
                                    nn_setsockopt(myinfo->dexsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                                    nn_setsockopt(myinfo->repsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                                    nn_setsockopt(myinfo->dexsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                                    nn_setsockopt(myinfo->repsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                                    maxsize = 1024 * 1024;
                                    printf("RCVBUF.%d\n",nn_setsockopt(myinfo->dexsock,NN_SOL_SOCKET,NN_RCVBUF,&maxsize,sizeof(maxsize)));
                                    printf("RCVBUF.%d\n",nn_setsockopt(myinfo->repsock,NN_SOL_SOCKET,NN_RCVBUF,&maxsize,sizeof(maxsize)));
                                    printf("DEXINIT dpow.%d dex.%d rep.%d\n",myinfo->dpowsock,myinfo->dexsock,myinfo->repsock);
                                }
                            }
                        }
                    }
                }
            }
            myinfo->dpowipbits[0] = (uint32_t)calc_ipbits(myinfo->ipaddr);
            myinfo->numdpowipbits = 1;
            timeout = 1000;
            nn_setsockopt(myinfo->dpowsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
            maxsize = 1024 * 1024;
            printf("RCVBUF.%d\n",nn_setsockopt(myinfo->dpowsock,NN_SOL_SOCKET,NN_RCVBUF,&maxsize,sizeof(maxsize)));
            myinfo->nanoinit = (uint32_t)time(NULL);
        }
    } //else printf("error creating nanosocket\n");
    portable_mutex_unlock(&myinfo->notarymutex);
    dpow_addnotary(myinfo,0,ipaddr);
}

void dpow_bestconsensus(struct dpow_block *bp)
{
    int8_t bestks[64]; int32_t counts[64],i,j,numcrcs=0,numdiff,besti,best,bestmatches = 0,matches = 0; uint64_t masks[64],matchesmask,recvmask; uint32_t crcval=0; char srcaddr[64],destaddr[64];
    memset(masks,0,sizeof(masks));
    memset(bestks,0xff,sizeof(bestks));
    memset(counts,0,sizeof(counts));
    recvmask = 0;
    for (numdiff=i=0; i<bp->numnotaries; i++)
    {
        if ( bits256_nonz(bp->notaries[i].src.prev_hash) != 0 && bits256_nonz(bp->notaries[i].dest.prev_hash) != 0 )
            recvmask |= (1LL << i);
        if ( bp->notaries[i].bestk < 0 || bp->notaries[i].bestmask == 0 )
            continue;
        //if ( bp->require0 != 0 && (bp->notaries[i].bestmask & 1) == 0 )
        //    continue;
        for (j=0; j<numdiff; j++)
            if ( bp->notaries[i].bestk == bestks[j] && bp->notaries[i].bestmask == masks[j] )
            {
                counts[j]++;
                break;
            }
        if ( j == numdiff && bp->notaries[i].bestk >= 0 && bp->notaries[i].bestmask != 0 )
        {
            masks[numdiff] = bp->notaries[i].bestmask;
            bestks[numdiff] = bp->notaries[i].bestk;
            counts[numdiff]++;
            //printf("j.%d numdiff.%d (%d %llx).%d\n",j,numdiff,bp->notaries[i].bestk,(long long)bp->notaries[i].bestmask,counts[numdiff]);
            numdiff++;
        }
    }
    besti = -1, best = 0;
    for (i=0; i<numdiff; i++)
    {
        //printf("(%d %llx).%d ",bestks[i],(long long)masks[i],counts[i]);
        if ( counts[i] > best )
        {
            best = counts[i];
            besti = i;
        }
    }
    if ( besti >= 0 && bestks[besti] >= 0 && masks[besti] != 0 && (recvmask & masks[besti]) == masks[besti] )
    {
        bp->notaries[bp->myind].bestmask = bp->bestmask = masks[besti];
        bp->notaries[bp->myind].bestk = bp->bestk = bestks[besti];
        //printf("set best.%d to (%d %llx) recv.%llx\n",best,bp->bestk,(long long)bp->bestmask,(long long)recvmask);
    }
    bp->recvmask = recvmask;
    if ( bp->bestmask == 0 )//|| (time(NULL) / 180) != bp->lastepoch )
    {
        bp->bestmask = dpow_notarybestk(bp->recvmask,bp,&bp->bestk);
        if ( 0 && (time(NULL) / 180) != bp->lastepoch )
        {
            bp->lastepoch = (uint32_t)(time(NULL) / 180);
            printf("epoch %u\n",bp->lastepoch % bp->numnotaries);
            sleep(1 + (rand() % 3));
        }
    }
}

void dpow_nanoutxoset(struct dpow_nanoutxo *np,struct dpow_block *bp,int32_t isratify)
{
    int32_t i;
    if ( bp->myind < 0 )
        return;
    if ( isratify != 0 )
    {
        np->srcutxo = bp->notaries[bp->myind].ratifysrcutxo;
        np->srcvout = bp->notaries[bp->myind].ratifysrcvout;
        np->destutxo = bp->notaries[bp->myind].ratifydestutxo;
        np->destvout = bp->notaries[bp->myind].ratifydestvout;
        np->bestmask = bp->ratifybestmask;
        np->recvmask = bp->ratifyrecvmask;
        //printf("send ratify best.(%d %llx) siglens.(%d %d)\n", bp->ratifybestk,(long long)bp->ratifybestmask,bp->ratifysiglens[0],bp->ratifysiglens[1]);
        if ( (np->bestk= bp->ratifybestk) >= 0 )
        {
            for (i=0; i<2; i++)
            {
                if ( (np->siglens[i]= bp->ratifysiglens[i]) > 0 )
                    memcpy(np->sigs[i],bp->ratifysigs[i],np->siglens[i]);
            }
        }
    }
    else
    {
        dpow_bestconsensus(bp);
        np->srcutxo = bp->notaries[bp->myind].src.prev_hash;
        np->srcvout = bp->notaries[bp->myind].src.prev_vout;
        np->destutxo = bp->notaries[bp->myind].dest.prev_hash;
        np->destvout = bp->notaries[bp->myind].dest.prev_vout;
        if ( (np->recvmask= bp->recvmask) == 0 )
            np->recvmask = bp->notaries[bp->myind].recvmask;
        if ( (np->bestmask= bp->pendingbestmask) == 0 )
        {
            if ( (np->bestmask= bp->notaries[bp->myind].bestmask) == 0 )
                np->bestmask = bp->bestmask, np->bestk = bp->bestk;
            else np->bestk = bp->notaries[bp->myind].bestk;
        } else np->bestk = bp->pendingbestk;
        if ( (int8_t)np->bestk >= 0 )
        {
            if ( (np->siglens[0]= bp->notaries[bp->myind].src.siglens[bp->bestk]) > 0 )
                memcpy(np->sigs[0],bp->notaries[bp->myind].src.sigs[bp->bestk],np->siglens[0]);
            if ( (np->siglens[1]= bp->notaries[bp->myind].dest.siglens[bp->bestk]) > 0 )
                memcpy(np->sigs[1],bp->notaries[bp->myind].dest.sigs[bp->bestk],np->siglens[1]);
        }
    }
}

void dpow_ratify_update(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,uint8_t senderind,int8_t bestk,uint64_t bestmask,uint64_t recvmask,bits256 srcutxo,uint16_t srcvout,bits256 destutxo,uint16_t destvout,uint8_t siglens[2],uint8_t sigs[2][DPOW_MAXSIGLEN],uint32_t pendingcrcs[2])
{
    int8_t bestks[64]; int32_t counts[64],i,j,numcrcs=0,numdiff,besti,best,bestmatches = 0,matches = 0; uint64_t masks[64],matchesmask; uint32_t crcval=0; char srcaddr[64],destaddr[64];
    //char str[65],str2[65];
    //printf("senderind.%d num.%d %s %s\n",senderind,bp->numnotaries,bits256_str(str,srcutxo),bits256_str(str2,destutxo));
    if ( bp->myind < 0 )
        return;
    if ( bp->isratify != 0 && senderind >= 0 && senderind < bp->numnotaries && bits256_nonz(srcutxo) != 0 && bits256_nonz(destutxo) != 0 )
    {
        memset(masks,0,sizeof(masks));
        memset(bestks,0xff,sizeof(bestks));
        memset(counts,0,sizeof(counts));
        for (i=0; i<2; i++)
            bp->notaries[senderind].pendingcrcs[i] = pendingcrcs[i];
        bp->notaries[senderind].ratifysrcutxo = srcutxo;
        bp->notaries[senderind].ratifysrcvout = srcvout;
        bp->notaries[senderind].ratifydestutxo = destutxo;
        bp->notaries[senderind].ratifydestvout = destvout;
        bp->notaries[senderind].ratifybestmask = bestmask;
        bp->notaries[senderind].ratifyrecvmask = recvmask;
        if ( (bp->notaries[senderind].ratifybestk= bestk) >= 0 )
        {
            for (i=0; i<2; i++)
            {
                if ( (bp->notaries[senderind].ratifysiglens[i]= siglens[i]) != 0 )
                {
                    memcpy(bp->notaries[senderind].ratifysigs[i],sigs[i],siglens[i]);
                    if ( bestk == bp->pendingratifybestk && bestmask == bp->pendingratifybestmask )
                    {
                        if ( ((1LL << senderind) & bestmask) != 0 )
                            bp->ratifysigmasks[i] |= (1LL << senderind);
                    } else bp->ratifysigmasks[i] &= ~(1LL << senderind);
                }
            }
        }
        //printf("RECV from %d best.(%d %llx) sigs.(%d %d) %llx %llx\n",senderind,bestk,(long long)bestmask,siglens[0],siglens[1],(long long)bp->ratifysigmasks[0],(long long)bp->ratifysigmasks[1]);
        bp->ratifyrecvmask = 0;
        bp->ratifybestmask = 0;
        bp->ratifybestk = -1;
        for (numdiff=i=0; i<bp->numnotaries; i++)
        {
            if ( bits256_nonz(bp->notaries[i].ratifysrcutxo) != 0 && bits256_nonz(bp->notaries[i].ratifydestutxo) != 0 )
                bp->ratifyrecvmask |= (1LL << i);
            if ( bp->notaries[i].ratifybestk < 0 || bp->notaries[i].ratifybestmask == 0 )
                continue;
            if ( bp->require0 != 0 && (bp->notaries[i].ratifybestmask & 1) == 0 )
                continue;
            for (j=0; j<numdiff; j++)
                if ( bp->notaries[i].ratifybestk == bestks[j] && bp->notaries[i].ratifybestmask == masks[j] )
                {
                    counts[j]++;
                    break;
                }
            if ( j == numdiff && bp->notaries[i].ratifybestk >= 0 && bp->notaries[i].ratifybestmask != 0 )
            {
                masks[numdiff] = bp->notaries[i].ratifybestmask;
                bestks[numdiff] = bp->notaries[i].ratifybestk;
                counts[numdiff]++;
                //printf("j.%d numdiff.%d (%d %llx).%d\n",j,numdiff,bp->notaries[i].ratifybestk,(long long)bp->notaries[i].ratifybestmask,counts[numdiff]);
                numdiff++;
            }
        }
        besti = -1, best = 0;
        for (i=0; i<numdiff; i++)
        {
            //printf("(%d %llx).%d ",bestks[i],(long long)masks[i],counts[i]);
            if ( counts[i] > best )
            {
                best = counts[i];
                besti = i;
            }
        }
        if ( besti >= 0 && bestks[besti] >= 0 && masks[besti] != 0 && (bp->ratifyrecvmask & masks[besti]) == masks[besti] )
            bp->ratifybestmask = masks[besti], bp->ratifybestk = bestks[besti];
        //printf("numdiff.%d besti.%d numbest.%d (%d %llx) vs (%d %llx)\n",numdiff,besti,best,besti>=0?bestks[besti]:-1,(long long)(besti>=0?masks[besti]:0),bestk,(long long)bestmask);
        if ( bp->ratifybestmask == 0 || (time(NULL) / 100) != bp->lastepoch )
        {
            bp->ratifybestmask = dpow_ratifybest(bp->ratifyrecvmask,bp,&bp->ratifybestk);
            if ( (time(NULL) / 100) != bp->lastepoch )
            {
                bp->lastepoch = (uint32_t)(time(NULL) / 100);
                printf("epoch %u\n",bp->lastepoch % bp->numnotaries);
                sleep(2 + (rand() % 7));
            }
        }
        bp->notaries[bp->myind].ratifybestk = bp->ratifybestk;
        bp->notaries[bp->myind].ratifybestmask = bp->ratifybestmask;
        bp->notaries[bp->myind].ratifyrecvmask = bp->ratifyrecvmask;
        if ( bp->ratifybestk >= 0 )
        {
            for (matchesmask=i=0; i<bp->numnotaries; i++)
            {
                if ( bp->ratifybestk >= 0 && bp->notaries[i].ratifybestk == bp->ratifybestk && bp->notaries[i].ratifybestmask == bp->ratifybestmask )
                {
                    matches++;
                    if ( ((1LL << i) & bp->ratifybestmask) != 0 )
                    {
                        matchesmask |= (1LL << i);
                        bestmatches++;
                    }
                }
            }
            crcval = 0;
            numcrcs = 0;
            for (i=0; i<bp->numnotaries; i++)
            {
                if ( ((1LL << i) & matchesmask) != 0 )
                {
                    if ( numcrcs == 0 )
                        numcrcs++, crcval = bp->notaries[i].pendingcrcs[bp->state < 1000];
                    else if ( numcrcs > 0 && crcval == bp->notaries[i].pendingcrcs[bp->state < 1000] )
                        numcrcs++;
                }
            }
            //printf("crcval.%x numcrcs.%d bestmatches.%d matchesmask.%llx\n",crcval,numcrcs,bestmatches,(long long)matchesmask);
            if ( bestmatches >= bp->minsigs )
            {
                if ( bp->pendingratifybestk != bp->ratifybestk || bp->pendingratifybestmask != bp->ratifybestmask )
                {
                    printf("new PENDING RATIFY BESTK (%d %llx)\n",bp->ratifybestk,(long long)bp->ratifybestmask);
                    bp->pendingratifybestk = bp->ratifybestk;
                    bp->pendingratifybestmask = bp->ratifybestmask;
                    memset(bp->notaries[bp->myind].ratifysigs,0,sizeof(bp->notaries[bp->myind].ratifysigs));
                    memset(bp->notaries[bp->myind].ratifysiglens,0,sizeof(bp->notaries[bp->myind].ratifysiglens));
                    memset(bp->ratifysigmasks,0,sizeof(bp->ratifysigmasks));
                    dpow_signedtxgen(myinfo,dp,bp->destcoin,bp,bp->ratifybestk,bp->ratifybestmask,bp->myind,DPOW_SIGBTCCHANNEL,1,1);
                    for (i=0; i<bp->numnotaries; i++)
                    {
                        if ( i != bp->myind )
                        {
                            memset(&bp->notaries[i].ratifysrcutxo,0,sizeof(bp->notaries[i].ratifysrcutxo));
                            memset(&bp->notaries[i].ratifydestutxo,0,sizeof(bp->notaries[i].ratifydestutxo));
                            bp->notaries[i].ratifybestmask = bp->notaries[i].ratifyrecvmask = 0;
                        }
                        else if ( bp->require0 == 0 )
                        {
                            bitcoin_address(srcaddr,bp->srccoin->chain->pubtype,dp->minerkey33,33);
                            bitcoin_address(destaddr,bp->destcoin->chain->pubtype,dp->minerkey33,33);
                            if ( dpow_checkutxo(myinfo,dp,bp,bp->destcoin,&bp->notaries[i].dest.prev_hash,&bp->notaries[i].dest.prev_vout,destaddr) < 0 )
                            {
                                printf("dont have %s %s utxo, please send funds\n",dp->dest,destaddr);
                            }
                            if ( dpow_checkutxo(myinfo,dp,bp,bp->srccoin,&bp->notaries[i].src.prev_hash,&bp->notaries[i].src.prev_vout,srcaddr) < 0 )
                            {
                                printf("dont have %s %s utxo, please send funds\n",dp->symbol,srcaddr);
                            }
                        }
                    }
                }
                if ( bp->ratifysigmasks[1] == bp->pendingratifybestmask ) // have all sigs
                {
                    if ( bp->state < 1000 )
                    {
                        dpow_sigscheck(myinfo,dp,bp,bp->myind,1,bp->pendingratifybestk,bp->pendingratifybestmask,bp->ratified_pubkeys,bp->numratified);
                    }
                    if ( bp->ratifysigmasks[0] == bp->pendingratifybestmask ) // have all sigs
                    {
                        if ( bp->state != 0xffffffff )
                            dpow_sigscheck(myinfo,dp,bp,bp->myind,0,bp->pendingratifybestk,bp->pendingratifybestmask,bp->ratified_pubkeys,bp->numratified);
                    }
                    else if ( ((1LL << bp->myind) & bp->ratifybestmask) != 0 && (rand() % 100) == 0 )
                    {
                        dpow_signedtxgen(myinfo,dp,bp->srccoin,bp,bp->ratifybestk,bp->ratifybestmask,bp->myind,DPOW_SIGCHANNEL,0,1);
                    }
                    //else printf("ratify srcmask.%llx != bestmask.%llx\n",(long long)bp->ratifysigmasks[0],(long long)bp->bestmask);
                }
                else if ( ((1LL << bp->myind) & bp->ratifybestmask) != 0 && (rand() % 100) == 0 )
                {
                    dpow_signedtxgen(myinfo,dp,bp->destcoin,bp,bp->ratifybestk,bp->ratifybestmask,bp->myind,DPOW_SIGBTCCHANNEL,1,1);
                }
                //else printf("ratify destmask.%llx != bestmask.%llx\n",(long long)bp->ratifysigmasks[1],(long long)bp->bestmask);
            }
        }
        if ( (rand() % 100) == 0 )
            printf("[%d] numips.%d %s RATIFY.%d matches.%d bestmatches.%d bestk.%d %llx recv.%llx %llx sigmasks.(%llx %llx) crcval.%x num.%d\n",bp->myind,dp->numipbits,dp->symbol,bp->minsigs,matches,bestmatches,bp->ratifybestk,(long long)bp->ratifybestmask,(long long)bp->ratifyrecvmask,(long long)matchesmask,(long long)bp->ratifysigmasks[1],(long long)bp->ratifysigmasks[0],crcval,numcrcs);
    }
}

void dpow_notarize_update(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,uint8_t senderind,int8_t bestk,uint64_t bestmask,uint64_t recvmask,bits256 srcutxo,uint16_t srcvout,bits256 destutxo,uint16_t destvout,uint8_t siglens[2],uint8_t sigs[2][DPOW_MAXSIGLEN],uint32_t paxwdcrc)
{
    int32_t i,bestmatches = 0,matches = 0,paxmatches = 0,paxbestmatches = 0;
    if ( bp->myind < 0 )
        return;
    if ( bp->isratify == 0 && bp->state != 0xffffffff && senderind >= 0 && senderind < bp->numnotaries && bits256_nonz(srcutxo) != 0 && bits256_nonz(destutxo) != 0 )
    {
        bp->notaries[senderind].src.prev_hash = srcutxo;
        bp->notaries[senderind].src.prev_vout = srcvout;
        bp->notaries[senderind].dest.prev_hash = destutxo;
        bp->notaries[senderind].dest.prev_vout = destvout;
        if ( bestmask != 0 )
            bp->notaries[senderind].bestmask = bestmask;
        if ( recvmask != 0 )
            bp->notaries[senderind].recvmask = recvmask;
        if ( (bp->notaries[senderind].paxwdcrc= paxwdcrc) != 0 )
        {
            //fprintf(stderr,"{%d %x} ",senderind,paxwdcrc);
        }
        if ( bestk >= 0 && (bp->notaries[senderind].bestk= bestk) >= 0 )
        {
            if ( (bp->notaries[senderind].src.siglens[bestk]= siglens[0]) != 0 )
            {
                memcpy(bp->notaries[senderind].src.sigs[bestk],sigs[0],siglens[0]);
                if ( bestk == bp->bestk && bestmask == bp->bestmask )
                    bp->srcsigsmasks[bestk] |= (1LL << senderind);
                else bp->srcsigsmasks[bestk] &= ~(1LL << senderind);
            }
            if ( (bp->notaries[senderind].dest.siglens[bestk]= siglens[1]) != 0 )
            {
                memcpy(bp->notaries[senderind].dest.sigs[bestk],sigs[1],siglens[1]);
                if ( bestk == bp->bestk && bestmask == bp->bestmask )
                    bp->destsigsmasks[bestk] |= (1LL << senderind);
                else bp->destsigsmasks[bestk] &= ~(1LL << senderind);
            }
        }
        dpow_bestconsensus(bp);
        //bp->recvmask |= (1LL << senderind) | (1LL << bp->myind);
        //bp->bestmask = dpow_maskmin(bp->recvmask,bp,&bp->bestk);
        //if ( bp->paxwdcrc != 0 )
            bp->notaries[bp->myind].paxwdcrc = bp->paxwdcrc;
        if ( bp->bestk >= 0 )
            bp->notaries[bp->myind].bestk = bp->bestk;
        if ( bp->bestmask != 0 )
            bp->notaries[bp->myind].bestmask = bp->bestmask;
        if ( bp->recvmask != 0 )
            bp->notaries[bp->myind].recvmask = bp->recvmask;
        if ( bp->bestk >= 0 )
        {
            for (i=0; i<bp->numnotaries; i++)
            {
                if ( bp->paxwdcrc == bp->notaries[i].paxwdcrc )
                    paxmatches++;
                if ( bp->bestk >= 0 && bp->notaries[i].bestk == bp->bestk && bp->notaries[i].bestmask == bp->bestmask )
                {
                    matches++;
                    if ( ((1LL << i) & bp->bestmask) != 0 )
                    {
                        if ( bp->paxwdcrc == bp->notaries[i].paxwdcrc )
                        {
                            bestmatches++;
                            paxbestmatches++;
                        } //else printf("?%x ",bp->notaries[i].paxwdcrc);
                    }
                }
                if ( 1 && bp->myind <= 1 && bp->notaries[i].paxwdcrc != 0 )
                    printf("%d.(%x %d %llx r%llx) ",i,bp->notaries[i].paxwdcrc,bp->notaries[i].bestk,(long long)bp->notaries[i].bestmask,(long long)bp->notaries[i].recvmask);
            }
            if ( 1 && bp->myind <= 1 )
                printf("recv.%llx best.(%d %llx) m.%d p.%d:%d b.%d\n",(long long)bp->recvmask,bp->bestk,(long long)bp->bestmask,matches,paxmatches,paxbestmatches,bestmatches);
            if ( bestmatches >= bp->minsigs && paxbestmatches >= bp->minsigs )
            {
                if ( bp->pendingbestk != bp->bestk || bp->pendingbestmask != bp->bestmask )
                {
                    printf("new PENDING BESTK (%d %llx) state.%d\n",bp->bestk,(long long)bp->bestmask,bp->state);
                    bp->pendingbestk = bp->bestk;
                    bp->pendingbestmask = bp->bestmask;
                    dpow_signedtxgen(myinfo,dp,bp->destcoin,bp,bp->bestk,bp->bestmask,bp->myind,DPOW_SIGBTCCHANNEL,1,0);
                    printf("finished signing\n");
                }
                if ( bp->destsigsmasks[bp->bestk] == bp->bestmask ) // have all sigs
                {
                    if ( bp->state < 1000 )
                        dpow_sigscheck(myinfo,dp,bp,bp->myind,1,bp->bestk,bp->bestmask,0,0);
                    if ( bp->srcsigsmasks[bp->bestk] == bp->bestmask ) // have all sigs
                    {
                        if ( bp->state != 0xffffffff )
                            dpow_sigscheck(myinfo,dp,bp,bp->myind,0,bp->bestk,bp->bestmask,0,0);
                    } //else printf("srcmask.%llx != bestmask.%llx\n",(long long)bp->srcsigsmasks[bp->bestk],(long long)bp->bestmask);
                } //else printf("destmask.%llx != bestmask.%llx\n",(long long)bp->destsigsmasks[bp->bestk],(long long)bp->bestmask);
            }
        }
        if ( (rand() % 100) == 0 )
            printf("[%d] ips.%d %s NOTARIZE.%d matches.%d paxmatches.%d bestmatches.%d bestk.%d %llx recv.%llx sigmasks.(%llx %llx) senderind.%d state.%x (%x %x %x) pax.%x\n",bp->myind,dp->numipbits,dp->symbol,bp->minsigs,matches,paxmatches,bestmatches,bp->bestk,(long long)bp->bestmask,(long long)bp->recvmask,(long long)(bp->bestk>=0?bp->destsigsmasks[bp->bestk]:0),(long long)(bp->bestk>=0?bp->srcsigsmasks[bp->bestk]:0),senderind,bp->state,bp->hashmsg.uints[0],bp->desttxid.uints[0],bp->srctxid.uints[0],bp->paxwdcrc);
    }
}

void dpow_nanoutxoget(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,struct dpow_nanoutxo *np,int32_t isratify,int8_t senderind,uint32_t channel)
{
    if ( isratify != 0 )
    {
        dpow_ratify_update(myinfo,dp,bp,senderind,(int8_t)np->bestk,np->bestmask,np->recvmask,np->srcutxo,np->srcvout,np->destutxo,np->destvout,np->siglens,np->sigs,np->pendingcrcs);
    }
    else
    {
        dpow_notarize_update(myinfo,dp,bp,senderind,(int8_t)np->bestk,np->bestmask,np->recvmask,np->srcutxo,np->srcvout,np->destutxo,np->destvout,np->siglens,np->sigs,np->paxwdcrc);
        if ( 0 && bp->myind <= 2 )
            printf("lag.[%d] RECV.%d r%llx (%d %llx) %llx/%llx\n",(int32_t)(time(NULL)-channel),senderind,(long long)np->recvmask,(int8_t)np->bestk,(long long)np->bestmask,(long long)np->srcutxo.txid,(long long)np->destutxo.txid);
    }
    //dpow_bestmask_update(myinfo,dp,bp,nn_senderind,nn_bestk,nn_bestmask,nn_recvmask);
}

void dpow_send(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgbits,uint8_t *data,int32_t datalen)
{
    struct dpow_nanomsghdr *np; int32_t i,size,extralen=0,sentbytes = 0; uint32_t crc32,paxwdcrc; uint8_t extras[10000];
    if ( bp->myind < 0 )
        return;
    if ( time(NULL) < myinfo->nanoinit+5 )
        return;
    crc32 = calc_crc32(0,data,datalen);
     //dp->crcs[firstz] = crc32;
    size = (int32_t)(sizeof(*np) + datalen);
    np = calloc(1,size); // endian dependent!
    if ( (np->numipbits= dp->numipbits) == 0 )
    {
        dp->ipbits[0] = myinfo->myaddr.myipbits;
        np->numipbits = dp->numipbits = 1;
    }
    np->senderind = bp->myind;
    memcpy(np->ipbits,dp->ipbits,dp->numipbits * sizeof(*dp->ipbits));
    //for (i=0; i<np->numipbits; i++)
    //    printf("%08x ",np->ipbits[i]);
    //printf(" dpow_send.(%d) size.%d numipbits.%d myind.%d\n",datalen,size,np->numipbits,bp->myind);
    if ( bp->isratify == 0 )
    {
        extralen = dpow_paxpending(extras,&paxwdcrc);
        bp->paxwdcrc = bp->notaries[bp->myind].paxwdcrc = np->notarize.paxwdcrc = paxwdcrc;
        //dpow_bestconsensus(bp);
        dpow_nanoutxoset(&np->notarize,bp,0);
    }
    else
    {
        bp->paxwdcrc = bp->notaries[bp->myind].paxwdcrc = np->notarize.paxwdcrc = 0;
        dpow_nanoutxoset(&np->ratify,bp,1);
    }
    np->size = size;
    np->datalen = datalen;
    np->crc32 = crc32;
    for (i=0; i<2; i++)
        np->ratify.pendingcrcs[i] = bp->pendingcrcs[i];
    for (i=0; i<32; i++)
        np->srchash.bytes[i] = dp->minerkey33[i+1];
    np->desthash = desthash;
    if ( (np->channel= channel) == 0 )
        np->channel = (uint32_t)time(NULL);
    np->height = msgbits;
    np->myipbits = myinfo->myaddr.myipbits;
    strcpy(np->symbol,dp->symbol);
    np->version0 = DPOW_VERSION & 0xff;
    np->version1 = (DPOW_VERSION >> 8) & 0xff;
    memcpy(np->packet,data,datalen);
    sentbytes = -1;
    // deadlocks! portable_mutex_lock(&myinfo->dpowmutex);
    for (i=0; i<100; i++)
    {
        struct nn_pollfd pfd;
        pfd.fd = myinfo->dpowsock;
        pfd.events = NN_POLLOUT;
        if ( nn_poll(&pfd,1,100) > 0 )
        {
            sentbytes = nn_send(myinfo->dpowsock,np,size,0);
            break;
        }
        usleep(1000);
    }
    //portable_mutex_unlock(&myinfo->dpowmutex);
    free(np);
    if ( 0 && bp->myind <= 2 )
        printf("%d NANOSEND.%d ht.%d channel.%08x (%d) pax.%08x datalen.%d (%d %llx) (%d %llx) recv.%llx\n",i,sentbytes,np->height,np->channel,size,np->notarize.paxwdcrc,datalen,(int8_t)np->notarize.bestk,(long long)np->notarize.bestmask,bp->notaries[bp->myind].bestk,(long long)bp->notaries[bp->myind].bestmask,(long long)bp->recvmask);
}

void dpow_ipbitsadd(struct supernet_info *myinfo,struct dpow_info *dp,uint32_t *ipbits,int32_t numipbits,int32_t fromid,uint32_t senderipbits)
{
    int32_t i,j,matched,missing,n; char ipaddr[64];
    if ( numipbits >= 64 )
    {
        printf("dpow_ipbitsadd reject from.%d numipbits.%d\n",fromid,numipbits);
        return;
    }
    n = dp->numipbits;
    matched = missing = 0;
    //for (i=0; i<numipbits; i++)
    //    printf("%08x ",ipbits[i]);
    for (i=0; i<numipbits; i++)
    {
        for (j=0; j<n; j++)
            if ( ipbits[i] == dp->ipbits[j] )
            {
                matched++;
                ipbits[i] = 0;
                break;
            }
        if ( j == n )
            missing++;
    }
    if ( (numipbits == 1 || missing < matched || matched > 0) && missing > 0 )
    {
        for (i=0; i<numipbits; i++)
            if ( ipbits[i] != 0 )
            {
                expand_ipbits(ipaddr,ipbits[i]);
                //printf("ADD NOTARY.(%s) %08x\n",ipaddr,ipbits[i]);
                dpow_addnotary(myinfo,dp,ipaddr);
            }
    } else if ( missing > 0 )
        printf("IGNORE from.%d RECV numips.%d numipbits.%d matched.%d missing.%d\n",fromid,numipbits,n,matched,missing);
    expand_ipbits(ipaddr,senderipbits);
    dpow_addnotary(myinfo,dp,ipaddr);
    expand_ipbits(ipaddr,myinfo->myaddr.myipbits);
    dpow_addnotary(myinfo,dp,ipaddr);
    //printf("recv numips.(%d %d)\n",myinfo->numdpowipbits,dp->numipbits);
}

int32_t dpow_nanomsg_update(struct supernet_info *myinfo)
{
    int32_t i,n=0,num=0,size,firstz = -1; uint32_t crc32,r,m; struct dpow_nanomsghdr *np=0; struct dpow_info *dp; struct dpow_block *bp; struct dex_nanomsghdr *dexp = 0;
    if ( time(NULL) < myinfo->nanoinit+5 || myinfo->dpowsock < 0 )
        return(-1);
    portable_mutex_lock(&myinfo->dpowmutex);
    for (i=0; i<100; i++)
    {
        struct nn_pollfd pfd;
        pfd.fd = myinfo->dpowsock;
        pfd.events = NN_POLLIN;
        if ( nn_poll(&pfd,1,100) > 0 )
            break;
        usleep(1000);
    }
    if ( i < 100 && (size= nn_recv(myinfo->dpowsock,&np,NN_MSG,0)) >= 0 )
    {
        num++;
        if ( size >= 0 )
        {
            if ( np->version0 == (DPOW_VERSION & 0xff) && np->version1 == ((DPOW_VERSION >> 8) & 0xff) )
            {
                //printf("v.%02x %02x datalen.%d size.%d %d vs %d\n",np->version0,np->version1,np->datalen,size,np->datalen,(int32_t)(size - sizeof(*np)));
                if ( np->datalen == (size - sizeof(*np)) )
                {
                    crc32 = calc_crc32(0,np->packet,np->datalen);
                    dp = 0;
                    for (i=0; i<myinfo->numdpows; i++)
                    {
                        if ( strcmp(np->symbol,myinfo->DPOWS[i].symbol) == 0 )
                        {
                            dp = &myinfo->DPOWS[i];
                            break;
                        }
                    }
                    if ( dp != 0 && crc32 == np->crc32 )
                    {
                        //char str[65]; printf("%s RECV ht.%d ch.%08x (%d) crc32.%08x:%08x datalen.%d:%d firstz.%d\n",bits256_str(str,np->srchash),np->height,np->channel,size,np->crc32,crc32,np->datalen,(int32_t)(size - sizeof(*np)),firstz);
                         if ( i == myinfo->numdpows )
                            printf("received nnpacket for (%s)\n",np->symbol);
                        else
                        {
                            dpow_ipbitsadd(myinfo,dp,np->ipbits,np->numipbits,np->senderind,np->myipbits);
                            if ( (bp= dpow_heightfind(myinfo,dp,np->height)) != 0 && bp->state != 0xffffffff && bp->myind >= 0 )
                            {
                                if ( np->senderind >= 0 && np->senderind < bp->numnotaries )
                                {
                                    if ( memcmp(bp->notaries[np->senderind].pubkey+1,np->srchash.bytes,32) == 0 && bits256_nonz(np->srchash) != 0 )
                                    {
                                        if ( bp->isratify == 0 )
                                            dpow_nanoutxoget(myinfo,dp,bp,&np->notarize,0,np->senderind,np->channel);
                                        else dpow_nanoutxoget(myinfo,dp,bp,&np->ratify,1,np->senderind,np->channel);
                                        dpow_datahandler(myinfo,dp,bp,np->senderind,np->channel,np->height,np->packet,np->datalen);
                                    } else printf("wrong senderind.%d\n",np->senderind);
                                }
                            }
                            //dp->crcs[firstz] = crc32;
                        }
                    } //else printf("crc error from.%d %x vs %x or no dp.%p [%s]\n",np->senderind,crc32,np->crc32,dp,np->symbol);
                } //else printf("ignore.%d np->datalen.%d %d (size %d - %ld) [%s]\n",np->senderind,np->datalen,(int32_t)(size-sizeof(*np)),size,sizeof(*np),np->symbol);
            } //else printf("wrong version from.%d %02x %02x size.%d [%s]\n",np->senderind,np->version0,np->version1,size,np->symbol);
        } else printf("illegal size.%d\n",size);
        if ( np != 0 )
            nn_freemsg(np), np = 0;
    } //else printf("no packets\n");
    n = 0;
    if ( myinfo->dexsock >= 0 )
    {
        if ( (size= nn_recv(myinfo->dexsock,&dexp,NN_MSG,0)) >= 0 )
        {
            num++;
            if ( dex_packetcheck(myinfo,dexp,size) == 0 )
            {
                printf("FROM BUS.%08x -> pub\n",dexp->crc32);
                nn_send(myinfo->pubsock,dexp,size,0);
                dex_packet(myinfo,dexp,size);
            }
            //printf("GOT DEX bus PACKET.%d\n",size);
            if ( dexp != 0 )
                nn_freemsg(dexp), dexp = 0;
        }
    }
    if ( myinfo->repsock >= 0 )
    {
        if ( (size= nn_recv(myinfo->repsock,&dexp,NN_MSG,0)) >= 0 )
        {
            num++;
            if ( dex_packetcheck(myinfo,dexp,size) == 0 )
            {
                nn_send(myinfo->dexsock,dexp,size,0);
                if ( (m= myinfo->numdpowipbits) > 0 )
                {
                    r = myinfo->dpowipbits[rand() % m];
                    nn_send(myinfo->repsock,&r,sizeof(r),0);
                    printf("REP.%08x -> dexbus, rep.%08x",dexp->crc32,r);
                }
                dex_packet(myinfo,dexp,size);
            }
            printf("GOT DEX rep PACKET.%d\n",size);
            if ( dexp != 0 )
                nn_freemsg(dexp), dexp = 0;
        }
    }
    portable_mutex_unlock(&myinfo->dpowmutex);
    return(num);
}
#else

void dpow_nanomsginit(struct supernet_info *myinfo,char *ipaddr) { }

uint32_t dpow_send(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgbits,uint8_t *data,int32_t datalen)
{
    return(0);
}

int32_t dpow_nanomsg_update(struct supernet_info *myinfo) { return(0); }

#endif

int32_t dpow_opreturnscript(uint8_t *script,uint8_t *opret,int32_t opretlen)
{
    int32_t offset = 0;
    script[offset++] = 0x6a;
    if ( opretlen >= 0x4c )
    {
        if ( opretlen > 0xff )
        {
            script[offset++] = 0x4d;
            script[offset++] = opretlen & 0xff;
            script[offset++] = (opretlen >> 8) & 0xff;
        }
        else
        {
            script[offset++] = 0x4c;
            script[offset++] = opretlen;
        }
    } else script[offset++] = opretlen;
    memcpy(&script[offset],opret,opretlen);
    return(opretlen + offset);
}

int32_t dpow_rwopret(int32_t rwflag,uint8_t *opret,bits256 *hashmsg,int32_t *heightmsgp,char *src,uint8_t *extras,int32_t extralen,struct dpow_block *bp,int32_t src_or_dest)
{
    int32_t i,opretlen = 0; //bits256 beacon,beacons[DPOW_MAXRELAYS];
    opretlen += iguana_rwbignum(rwflag,&opret[opretlen],sizeof(*hashmsg),hashmsg->bytes);
    opretlen += iguana_rwnum(rwflag,&opret[opretlen],sizeof(*heightmsgp),(uint32_t *)heightmsgp);
    if ( src_or_dest == 0 )
    {
        //char str[65]; printf("src_or_dest.%d opreturn add %s\n",src_or_dest,bits256_str(str,bp->desttxid));
        if ( bits256_nonz(bp->desttxid) == 0 )
        {
            printf("no desttxid\n");
            return(-1);
        }
        opretlen += iguana_rwbignum(rwflag,&opret[opretlen],sizeof(bp->desttxid),bp->desttxid.bytes);
    }
    /*else if ( 0 )
    {
        memset(beacons,0,sizeof(beacons));
        for (i=0; i<bp->numnotaries; i++)
        {
            if ( ((1LL << i) & bp->bestmask) != 0 )
                beacons[i] = bp->notaries[i].beacon;
        }
        vcalc_sha256(0,beacon.bytes,beacons[0].bytes,sizeof(*beacons) * bp->numnotaries);
        opretlen += iguana_rwbignum(rwflag,&opret[opretlen],sizeof(beacon),beacon.bytes);
    }*/
    if ( rwflag != 0 )
    {
        if ( src != 0 )
        {
            for (i=0; src[i]!=0; i++)
                opret[opretlen++] = src[i];
        }
        opret[opretlen++] = 0;
        if ( extras != 0 && extralen > 0 )
        {
            memcpy(&opret[opretlen],extras,extralen);
            opretlen += extralen;
            printf("added extra.%d opreturn for withdraws paxwdcrc.%08x\n",extralen,calc_crc32(0,extras,extralen));
        }
    }
    else
    {
        if ( src != 0 )
        {
            for (i=0; opret[opretlen]!=0; i++)
                src[i] = opret[opretlen++];
            src[i] = 0;
        }
        opretlen++;
    }
    return(opretlen);
}

int32_t dpow_rwsigentry(int32_t rwflag,uint8_t *data,struct dpow_sigentry *dsig)
{
    int32_t i,len = 0;
    if ( rwflag != 0 )
    {
        data[len++] = dsig->senderind;
        data[len++] = dsig->lastk;
        len += iguana_rwnum(rwflag,&data[len],sizeof(dsig->mask),(uint8_t *)&dsig->mask);
        data[len++] = dsig->siglen;
        memcpy(&data[len],dsig->sig,dsig->siglen), len += dsig->siglen;
        for (i=0; i<sizeof(dsig->beacon); i++)
            data[len++] = dsig->beacon.bytes[i];
        for (i=0; i<33; i++)
            data[len++] = dsig->senderpub[i];
    }
    else
    {
        memset(dsig,0,sizeof(*dsig));
        dsig->senderind = data[len++];
        if ( dsig->senderind < 0 || dsig->senderind >= DPOW_MAXRELAYS )
            return(-1);
        dsig->lastk = data[len++];
        len += iguana_rwnum(rwflag,&data[len],sizeof(dsig->mask),(uint8_t *)&dsig->mask);
        dsig->siglen = data[len++];
        memcpy(dsig->sig,&data[len],dsig->siglen), len += dsig->siglen;
        for (i=0; i<sizeof(dsig->beacon); i++)
            dsig->beacon.bytes[i] = data[len++];
        for (i=0; i<33; i++)
            dsig->senderpub[i] = data[len++];
    }
    return(len);
}

void dpow_sigsend(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,int32_t myind,int8_t bestk,uint64_t bestmask,bits256 srchash,uint32_t sigchannel)
{
    struct dpow_sigentry dsig; int32_t i,len; uint8_t data[4096]; struct dpow_entry *ep;
    if ( bp->myind < 0 )
        return;
    if ( ((1LL << myind) & bestmask) == 0 )
        return;
    ep = &bp->notaries[myind];
    if ( bestk >= 0 )
    {
        if ( sigchannel == DPOW_SIGCHANNEL )
            bp->srcsigsmasks[bestk] |= (1LL << myind);
        else bp->destsigsmasks[bestk] |= (1LL << myind);
    }
    //printf("ht.%d sigsend.%s: myind.%d bestk.%d %llx >>>>>> best.(%d %llx) recv.%llx sigs.%llx\n",bp->height,sigchannel == DPOW_SIGCHANNEL ? bp->srccoin->symbol : bp->destcoin->symbol,myind,bestk,(long long)bestmask,bestk,(long long)(bestk>=0?bestmask:0),(long long)bp->recvmask,(long long)(bestk>=0?bp->destsigsmasks[bestk]:0));
    memset(&dsig,0,sizeof(dsig));
    for (i=0; i<33; i++)
        dsig.senderpub[i] = dp->minerkey33[i];
    dsig.lastk = bestk;
    dsig.mask = bestmask;
    dsig.senderind = myind;
    dsig.beacon = bp->beacon;
    if ( sigchannel == DPOW_SIGBTCCHANNEL )
    {
        dsig.siglen = ep->dest.siglens[bestk];
        memcpy(dsig.sig,ep->dest.sigs[bestk],ep->dest.siglens[bestk]);
    }
    else
    {
        dsig.siglen = ep->src.siglens[bestk];
        memcpy(dsig.sig,ep->src.sigs[bestk],ep->src.siglens[bestk]);
    }
    memcpy(dsig.senderpub,dp->minerkey33,33);
    len = dpow_rwsigentry(1,data,&dsig);
    dpow_send(myinfo,dp,bp,srchash,bp->hashmsg,sigchannel,bp->height,data,len);
}

uint32_t komodo_assetmagic(char *symbol,uint64_t supply)
{
    uint8_t buf[512]; int32_t len = 0;
    len = iguana_rwnum(1,&buf[len],sizeof(supply),(void *)&supply);
    strcpy((char *)&buf[len],symbol);
    len += strlen(symbol);
    return(calc_crc32(0,buf,len));
}

/*int32_t komodo_shortflag(char *symbol)
{
    int32_t i,shortflag = 0;
    if ( symbol[0] == '-' )
    {
        shortflag = 1;
        for (i=0; symbol[i+1]!=0; i++)
            symbol[i] = symbol[i+1];
        symbol[i] = 0;
    }
    return(shortflag);
}*/

uint16_t komodo_assetport(uint32_t magic)
{
    return(8000 + (magic % 7777));
}

uint16_t komodo_port(char *symbol,uint64_t supply,uint32_t *magicp)
{
    *magicp = komodo_assetmagic(symbol,supply);
    return(komodo_assetport(*magicp));
}

#define MAX_CURRENCIES 32
extern char CURRENCIES[][8];

void komodo_assetcoins()
{
    uint16_t extract_userpass(char *serverport,char *userpass,char *coinstr,char *userhome,char *coindir,char *confname);
    int32_t i,j; uint32_t magic; cJSON *json; uint16_t port; long filesize; char *userhome,confstr[16],jsonstr[512],magicstr[9],path[512]; struct iguana_info *coin;
    if ( (userhome= OS_filestr(&filesize,"userhome.txt")) == 0 )
        userhome = "root";
    else
    {
        while ( userhome[strlen(userhome)-1] == '\r' || userhome[strlen(userhome)-1] == '\n' )
            userhome[strlen(userhome)-1] = 0;
    }
    for (i=0; i<MAX_CURRENCIES; i++)
    {
        port = komodo_port(CURRENCIES[i],10,&magic);
        for (j=0; j<4; j++)
            sprintf(&magicstr[j*2],"%02x",((uint8_t *)&magic)[j]);
        magicstr[j*2] = 0;
        sprintf(jsonstr,"{\"newcoin\":\"%s\",\"RELAY\":-1,\"VALIDATE\":0,\"portp2p\":%u,\"rpcport\":%u,\"netmagic\":\"%s\"}",CURRENCIES[i],port,port+1,magicstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (coin= iguana_coinadd(CURRENCIES[i],CURRENCIES[i],json,0)) == 0 )
            {
                printf("Cant create (%s)\n",CURRENCIES[i]);
                return;
            }
            free_json(json);
            coin->FULLNODE = -1;
            coin->chain->rpcport = port + 1;
            coin->chain->pubtype = 60;
            coin->chain->p2shtype = 85;
            coin->chain->wiftype = 188;
            sprintf(confstr,"%s.conf",CURRENCIES[i]);
            sprintf(path,"%s/.komodo/%s",userhome,CURRENCIES[i]);
            extract_userpass(coin->chain->serverport,coin->chain->userpass,CURRENCIES[i],coin->chain->userhome,path,confstr);
        }
        printf("(%s %u) ",CURRENCIES[i],port);
    }
    printf("ports\n");
}
