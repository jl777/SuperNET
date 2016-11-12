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


#if ISNOTARYNODE

struct dpow_nanoutxo
{
    bits256 srcutxo,destutxo;
    uint64_t bestmask,recvmask;
    uint16_t srcvout,destvout;
    uint8_t sigs[2][76],siglens[2],bestk,pad;
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
int32_t dpow_signedtxgen(struct supernet_info *myinfo,struct dpow_info *dp,struct iguana_info *coin,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t myind,uint32_t sigchannel,int32_t src_or_dest,int32_t useratified);

char *nanomsg_tcpname(char *str,char *ipaddr)
{
    sprintf(str,"tcp://%s:7775",ipaddr);
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

int32_t dpow_addnotary(struct supernet_info *myinfo,struct dpow_info *dp,char *ipaddr)
{
    char str[512]; uint32_t ipbits,*ptr; int32_t i,iter,n,retval = -1;
    if ( myinfo->dpowsock >= 0 )
    {
        portable_mutex_lock(&myinfo->dpowmutex);
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
                    retval = nn_connect(myinfo->dpowsock,nanomsg_tcpname(str,ipaddr));
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
        portable_mutex_unlock(&myinfo->dpowmutex);
    }
    return(retval);
}

void dpow_nanomsginit(struct supernet_info *myinfo,char *ipaddr)
{
    char str[512]; int32_t timeout,retval;
    if ( myinfo->ipaddr[0] == 0 )
    {
        printf("need to set ipaddr before nanomsg\n");
        return;
    }
    if ( myinfo->dpowsock < 0 && (myinfo->dpowsock= nn_socket(AF_SP,NN_BUS)) >= 0 )
    {
        if ( nn_bind(myinfo->dpowsock,nanomsg_tcpname(str,myinfo->ipaddr)) < 0 )
        {
            printf("error binding to (%s)\n",nanomsg_tcpname(str,myinfo->ipaddr));
            nn_close(myinfo->dpowsock);
            myinfo->dpowsock = -1;
        }
        timeout = 1000;
        nn_setsockopt(myinfo->dpowsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
        myinfo->dpowipbits[0] = (uint32_t)calc_ipbits(myinfo->ipaddr);
        myinfo->numdpowipbits = 1;
    }
    dpow_addnotary(myinfo,0,ipaddr);
}

int32_t dpow_crc32find(struct supernet_info *myinfo,struct dpow_info *dp,uint32_t crc32,uint32_t channel)
{
    int32_t i,firstz = -1;
    for (i=0; i<sizeof(dp->crcs)/sizeof(*dp->crcs); i++)
    {
        if ( dp->crcs[i] == crc32 )
        {
            //printf("NANODUPLICATE.%08x\n",crc32);
            return(-1);
        }
        else if ( firstz < 0 && dp->crcs[i] == 0 )
            firstz = i;
    }
    if ( firstz < 0 )
        firstz = (rand() % (sizeof(dp->crcs)/sizeof(*dp->crcs)));
    return(firstz);
}

void dpow_nanoutxoset(struct dpow_nanoutxo *np,struct dpow_block *bp,int32_t isratify)
{
    int32_t i;
    if ( isratify != 0 )
    {
        np->srcutxo = bp->notaries[bp->myind].ratifysrcutxo;
        np->srcvout = bp->notaries[bp->myind].ratifysrcvout;
        np->destutxo = bp->notaries[bp->myind].ratifydestutxo;
        np->destvout = bp->notaries[bp->myind].ratifydestvout;
        np->bestmask = bp->ratifybestmask;
        np->recvmask = bp->ratifyrecvmask;
        np->bestk = bp->ratifybestk;
        for (i=0; i<2; i++)
        {
            if ( (np->siglens[i]= bp->ratifysiglens[i]) > 0 )
                memcpy(np->sigs[i],bp->ratifysigs[i],np->siglens[i]);
        }
    }
    else
    {
        np->srcutxo = bp->notaries[bp->myind].src.prev_hash;
        np->srcvout = bp->notaries[bp->myind].src.prev_vout;
        np->destutxo = bp->notaries[bp->myind].dest.prev_hash;
        np->destvout = bp->notaries[bp->myind].dest.prev_vout;
        np->bestmask = bp->bestmask;
        np->recvmask = bp->recvmask;
        if ( (np->bestk= bp->bestk) >= 0 )
        {
            if ( (np->siglens[0]= bp->notaries[bp->myind].src.siglens[bp->bestk]) > 0 )
                memcpy(np->sigs[0],bp->notaries[bp->myind].src.sigs[bp->bestk],np->siglens[0]);
            if ( (np->siglens[1]= bp->notaries[bp->myind].dest.siglens[bp->bestk]) > 0 )
                memcpy(np->sigs[1],bp->notaries[bp->myind].dest.sigs[bp->bestk],np->siglens[1]);
        }
    }
}

void dpow_ratify_update(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,uint8_t senderind,int8_t bestk,uint64_t bestmask,uint64_t recvmask,bits256 srcutxo,uint16_t srcvout,bits256 destutxo,uint16_t destvout,uint8_t siglens[2],uint8_t sigs[2][76])
{
    int32_t i,bestmatches = 0,matches = 0;
    //char str[65],str2[65];
    //printf("senderind.%d num.%d %s %s\n",senderind,bp->numnotaries,bits256_str(str,srcutxo),bits256_str(str2,destutxo));
    if ( senderind >= 0 && senderind < bp->numnotaries && bits256_nonz(srcutxo) != 0 && bits256_nonz(destutxo) != 0 )
    {
        bp->notaries[senderind].ratifysrcutxo = srcutxo;
        bp->notaries[senderind].ratifysrcvout = srcvout;
        bp->notaries[senderind].ratifydestutxo = destutxo;
        bp->notaries[senderind].ratifydestvout = destvout;
        bp->notaries[senderind].ratifybestmask = bestmask;
        bp->notaries[senderind].ratifyrecvmask = recvmask;
        bp->notaries[senderind].ratifybestk = bestk;
        for (i=0; i<2; i++)
        {
            if ( (bp->notaries[senderind].ratifysiglens[i]= siglens[i]) != 0 )
            {
                memcpy(bp->notaries[senderind].ratifysigs[i],sigs[i],siglens[i]);
                if ( bestk == bp->pendingbestk && bestmask == bp->pendingbestmask )
                    bp->ratifysigmasks[i] |= (1LL << senderind);
                else bp->ratifysigmasks[i] &= ~(1LL << senderind);
            }
        }
        bp->ratifyrecvmask |= (1LL << senderind) | (1LL << bp->myind);
        bp->ratifybestmask = dpow_ratifybest(bp->ratifyrecvmask,bp,&bp->ratifybestk);
        if ( bp->ratifybestk >= 0 )
        {
            bp->notaries[bp->myind].ratifybestmask = bp->ratifybestmask;
            bp->notaries[bp->myind].ratifyrecvmask = bp->ratifyrecvmask;
            bp->notaries[bp->myind].ratifybestk = bp->ratifybestk;
            for (i=0; i<bp->numnotaries; i++)
            {
                if ( bp->ratifybestk >= 0 && bp->notaries[i].ratifybestk == bp->ratifybestk && bp->notaries[i].ratifybestmask == bp->ratifybestmask )
                {
                    matches++;
                    if ( ((1LL << i) & bp->ratifybestmask) != 0 )
                        bestmatches++;
                }
            }
            if ( bestmatches >= bp->minsigs )
            {
                if ( bp->pendingratifybestk != bp->ratifybestk || bp->pendingratifybestmask != bp->ratifybestmask )
                {
                    printf("new PENDING BESTK (%d %llx)\n",bp->ratifybestk,(long long)bp->ratifybestmask);
                    bp->pendingratifybestk = bp->ratifybestk;
                    bp->pendingratifybestmask = bp->ratifybestmask;
                    dpow_signedtxgen(myinfo,dp,bp->destcoin,bp,bp->ratifybestk,bp->ratifybestmask,bp->myind,DPOW_SIGBTCCHANNEL,1,1);
                    dpow_signedtxgen(myinfo,dp,bp->srccoin,bp,bp->ratifybestk,bp->ratifybestmask,bp->myind,DPOW_SIGCHANNEL,0,1);
                }
            }
        }
        printf("numips.%d RATIFY.%d matches.%d bestmatches.%d bestk.%d %llx recv.%llx sigmasks.(%llx %llx)\n",dp->numipbits,bp->minsigs,matches,bestmatches,bp->ratifybestk,(long long)bp->ratifybestmask,(long long)bp->ratifyrecvmask,(long long)bp->ratifysigmasks[1],(long long)bp->ratifysigmasks[0]);
    }
}

void dpow_notarize_update(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,uint8_t senderind,int8_t bestk,uint64_t bestmask,uint64_t recvmask,bits256 srcutxo,uint16_t srcvout,bits256 destutxo,uint16_t destvout,uint8_t siglens[2],uint8_t sigs[2][76])
{
    int32_t i,bestmatches = 0,matches = 0;
    if ( senderind >= 0 && senderind < bp->numnotaries && bits256_nonz(srcutxo) != 0 && bits256_nonz(destutxo) != 0 )
    {
        bp->notaries[senderind].src.prev_hash = srcutxo;
        bp->notaries[senderind].src.prev_vout = srcvout;
        bp->notaries[senderind].dest.prev_hash = destutxo;
        bp->notaries[senderind].dest.prev_vout = destvout;
        bp->notaries[senderind].bestmask = bestmask;
        bp->notaries[senderind].recvmask = recvmask;
        if ( (bp->notaries[senderind].bestk= bestk) >= 0 )
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
        bp->recvmask |= (1LL << senderind) | (1LL << bp->myind);
        bp->bestmask = dpow_maskmin(bp->recvmask,bp,&bp->bestk);
        bp->notaries[bp->myind].bestk = bp->bestk;
        bp->notaries[bp->myind].bestmask = bp->bestmask;
        bp->notaries[bp->myind].recvmask = bp->recvmask;
        if ( bp->bestk >= 0 )
        {
            for (i=0; i<bp->numnotaries; i++)
            {
                if ( bp->bestk >= 0 && bp->notaries[i].bestk == bp->bestk && bp->notaries[i].bestmask == bp->bestmask )
                {
                    matches++;
                    if ( ((1LL << i) & bp->bestmask) != 0 )
                        bestmatches++;
                } else printf("mismatch.%d (%d %llx) ",i,bp->notaries[i].bestk,(long long)bp->notaries[i].bestmask);
            }
            if ( bestmatches >= bp->minsigs )
            {
                if ( bp->pendingbestk != bp->bestk || bp->pendingbestmask != bp->bestmask )
                {
                    printf("new PENDING BESTK (%d %llx)\n",bp->bestk,(long long)bp->bestmask);
                    bp->pendingbestk = bp->bestk;
                    bp->pendingbestmask = bp->bestmask;
                    dpow_signedtxgen(myinfo,dp,bp->destcoin,bp,bp->bestk,bp->bestmask,bp->myind,DPOW_SIGBTCCHANNEL,1,0);
                    dpow_signedtxgen(myinfo,dp,bp->srccoin,bp,bp->bestk,bp->bestmask,bp->myind,DPOW_SIGCHANNEL,0,0);
                }
            }
        }
        printf("ips.%d NOTARIZE.%d matches.%d bestmatches.%d bestk.%d %llx recv.%llx sigmasks.(%llx %llx) senderind.%d\n",dp->numipbits,bp->minsigs,matches,bestmatches,bp->bestk,(long long)bp->bestmask,(long long)bp->recvmask,(long long)(bp->bestk>=0?bp->destsigsmasks[bp->bestk]:0),(long long)(bp->bestk>=0?bp->srcsigsmasks[bp->bestk]:0),senderind);
    }
}

void dpow_nanoutxoget(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,struct dpow_nanoutxo *np,int32_t isratify,int8_t senderind)
{
    if ( isratify != 0 )
    {
        dpow_ratify_update(myinfo,dp,bp,senderind,np->bestk,np->bestmask,np->recvmask,np->srcutxo,np->srcvout,np->destutxo,np->destvout,np->siglens,np->sigs);
    }
    else
    {
        dpow_notarize_update(myinfo,dp,bp,senderind,np->bestk,np->bestmask,np->recvmask,np->srcutxo,np->srcvout,np->destutxo,np->destvout,np->siglens,np->sigs);
    }
    //dpow_bestmask_update(myinfo,dp,bp,nn_senderind,nn_bestk,nn_bestmask,nn_recvmask);
}

void dpow_send(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgbits,uint8_t *data,int32_t datalen)
{
    struct dpow_nanomsghdr *np; int32_t i,size,sentbytes = 0; uint32_t crc32;
    crc32 = calc_crc32(0,data,datalen);
    //if ( (firstz= dpow_crc32find(myinfo,crc32,channel)) >= 0 )
    {
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
        dpow_nanoutxoset(&np->notarize,bp,0);
        dpow_nanoutxoset(&np->ratify,bp,1);
        np->size = size;
        np->datalen = datalen;
        np->crc32 = crc32;
        np->srchash = srchash;
        np->desthash = desthash;
        np->channel = channel;
        np->height = msgbits;
        np->myipbits = myinfo->myaddr.myipbits;
        strcpy(np->symbol,dp->symbol);
        np->version0 = DPOW_VERSION & 0xff;
        np->version1 = (DPOW_VERSION >> 8) & 0xff;
        memcpy(np->packet,data,datalen);
        sentbytes = nn_send(myinfo->dpowsock,np,size,0);
        free(np);
        //printf("NANOSEND ht.%d channel.%08x (%d) crc32.%08x datalen.%d\n",np->height,np->channel,size,np->crc32,datalen);
    }
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
}

void dpow_nanomsg_update(struct supernet_info *myinfo)
{
    int32_t i,n=0,size,firstz = -1; uint32_t crc32; struct dpow_nanomsghdr *np; struct dpow_info *dp; struct dpow_block *bp;
    while ( (size= nn_recv(myinfo->dpowsock,&np,NN_MSG,0)) >= 0 )
    {
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
                    if ( dp != 0 && crc32 == np->crc32 )//&& (firstz= dpow_crc32find(myinfo,dp,crc32,np->channel)) >= 0 )
                    {
                        //char str[65]; printf("%s RECV ht.%d ch.%08x (%d) crc32.%08x:%08x datalen.%d:%d firstz.%d\n",bits256_str(str,np->srchash),np->height,np->channel,size,np->crc32,crc32,np->datalen,(int32_t)(size - sizeof(*np)),firstz);
                         if ( i == myinfo->numdpows )
                            printf("received nnpacket for (%s)\n",np->symbol);
                        else
                        {
                            dpow_ipbitsadd(myinfo,dp,np->ipbits,np->numipbits,np->senderind,np->myipbits);
                            if ( (bp= dpow_heightfind(myinfo,dp,np->height)) != 0 )
                            {
                                if ( np->senderind >= 0 && np->senderind < bp->numnotaries )
                                {
                                    dpow_nanoutxoget(myinfo,dp,bp,&np->notarize,0,np->senderind);
                                    dpow_nanoutxoget(myinfo,dp,bp,&np->ratify,1,np->senderind);
                                    dpow_datahandler(myinfo,dp,bp,np->senderind,np->channel,np->height,np->packet,np->datalen);
                                }
                            }
                            //dp->crcs[firstz] = crc32;
                        }
                    }
                } //else printf("ignore np->datalen.%d %d (size %d - %ld)\n",np->datalen,(int32_t)(size-sizeof(*np)),size,sizeof(*np));
            }
            if ( np != 0 )
                nn_freemsg(np);
        }
        if ( size == 0 || n++ > 100 )
            break;
    }
    if ( 0 && n != 0 )
        printf("nanoupdates.%d\n",n);
}
#else

void dpow_nanomsginit(struct supernet_info *myinfo,char *ipaddr) { }

uint32_t dpow_send(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgbits,uint8_t *data,int32_t datalen)
{
    return(0);
}

void dpow_nanomsg_update(struct supernet_info *myinfo) { }

#endif

int32_t dpow_rwcoinentry(int32_t rwflag,uint8_t *serialized,struct dpow_coinentry *src,struct dpow_coinentry *dest,int8_t *bestkp)
{
    int8_t bestk; struct dpow_coinentry *ptr; int32_t siglen,iter,len = 0;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(src->prev_hash),src->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(src->prev_vout),(uint32_t *)&src->prev_vout);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(dest->prev_hash),dest->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(dest->prev_vout),(uint32_t *)&dest->prev_vout);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(*bestkp),(uint32_t *)bestkp);
    if ( (bestk= *bestkp) >= 0 )
    {
        for (iter=0; iter<2; iter++)
        {
            ptr = (iter == 0) ? src : dest;
            len += iguana_rwnum(rwflag,&serialized[len],sizeof(ptr->siglens[bestk]),(uint32_t *)&ptr->siglens[bestk]);
            if ( (siglen= ptr->siglens[bestk]) > 0 )
            {
                if ( rwflag != 0 )
                    memcpy(&serialized[len],ptr->sigs[bestk],siglen);
                else memcpy(ptr->sigs[bestk],&serialized[len],siglen);
                len += siglen;
            }
        }
    }
    return(len);
}

int32_t dpow_rwcoinentrys(int32_t rwflag,uint8_t *serialized,struct dpow_entry notaries[DPOW_MAXRELAYS],uint8_t numnotaries,int8_t bestk)
{
    int32_t i,len = 0;
    for (i=0; i<numnotaries; i++)
    {
        if ( rwflag != 0 )
            notaries[i].bestk = bestk;
        len += dpow_rwcoinentry(rwflag,&serialized[len],&notaries[i].src,&notaries[i].dest,&notaries[i].bestk);
    }
    return(len);
}

int32_t dpow_sendcoinentrys(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp)
{
    uint8_t data[sizeof(struct dpow_coinentry)*64 + 4096]; bits256 zero; int32_t len = 0;
    memset(zero.bytes,0,sizeof(zero));
    //printf("ht.%d >>>>>>>>>>>>> dpow_sendcoinentrys (%d %llx) <- %llx\n",bp->height,bp->bestk,(long long)bp->bestmask,(long long)bp->recvmask);
    data[len++] = bp->bestk;
    data[len++] = bp->numnotaries;
    len += iguana_rwbignum(1,&data[len],sizeof(bp->hashmsg),bp->hashmsg.bytes);
    len += dpow_rwcoinentrys(1,&data[len],bp->notaries,bp->numnotaries,bp->bestk);
    dpow_send(myinfo,dp,bp,zero,bp->hashmsg,DPOW_ENTRIESCHANNEL,bp->height,data,len);
    return(len);
}

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

int32_t dpow_rwopret(int32_t rwflag,uint8_t *opret,bits256 *hashmsg,int32_t *heightmsgp,char *src,struct dpow_block *bp,int32_t src_or_dest)
{
    int32_t i,opretlen = 0; bits256 beacon,beacons[DPOW_MAXRELAYS];
    opretlen += iguana_rwbignum(rwflag,&opret[opretlen],sizeof(*hashmsg),hashmsg->bytes);
    opretlen += iguana_rwnum(rwflag,&opret[opretlen],sizeof(*heightmsgp),(uint32_t *)heightmsgp);
    if ( src_or_dest == 0 )
    {
        //char str[65]; printf("src_or_dest.%d opreturn add %s\n",src_or_dest,bits256_str(str,bp->desttxid));
        if ( bits256_nonz(bp->desttxid) == 0 )
            return(-1);
        opretlen += iguana_rwbignum(rwflag,&opret[opretlen],sizeof(bp->desttxid),bp->desttxid.bytes);
        if ( rwflag != 0 )
        {
            if ( src != 0 )
            {
                for (i=0; src[i]!=0; i++)
                    opret[opretlen++] = src[i];
            }
            opret[opretlen++] = 0;
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
    }
    else if ( 0 )
    {
        memset(beacons,0,sizeof(beacons));
        for (i=0; i<bp->numnotaries; i++)
        {
            if ( ((1LL << i) & bp->bestmask) != 0 )
                beacons[i] = bp->notaries[i].beacon;
        }
        vcalc_sha256(0,beacon.bytes,beacons[0].bytes,sizeof(*beacons) * bp->numnotaries);
        opretlen += iguana_rwbignum(rwflag,&opret[opretlen],sizeof(beacon),beacon.bytes);
    }
    return(opretlen);
}

int32_t dpow_rwutxobuf(int32_t rwflag,uint8_t *data,struct dpow_utxoentry *up,struct dpow_block *bp)
{
    uint8_t numnotaries; uint64_t othermask; int32_t i,len = 0;
    len += iguana_rwbignum(rwflag,&data[len],sizeof(up->hashmsg),up->hashmsg.bytes);
    len += iguana_rwbignum(rwflag,&data[len],sizeof(up->srchash),up->srchash.bytes);
    len += iguana_rwbignum(rwflag,&data[len],sizeof(up->desthash),up->desthash.bytes);
    if ( bits256_nonz(up->srchash) == 0 || bits256_nonz(up->desthash) == 0 )
    {
        printf("dpow_rwutxobuf null src.%d or dest.%d\n",bits256_nonz(up->srchash),bits256_nonz(up->desthash));
        return(-1);
    }
    len += iguana_rwbignum(rwflag,&data[len],sizeof(up->commit),up->commit.bytes);
    len += iguana_rwnum(rwflag,&data[len],sizeof(up->recvmask),(uint8_t *)&up->recvmask);
    len += iguana_rwnum(rwflag,&data[len],sizeof(up->height),(uint8_t *)&up->height);
    len += iguana_rwnum(rwflag,&data[len],sizeof(up->srcvout),&up->srcvout);
    len += iguana_rwnum(rwflag,&data[len],sizeof(up->destvout),&up->destvout);
    len += iguana_rwnum(rwflag,&data[len],sizeof(up->bestk),&up->bestk);
    if ( rwflag != 0 )
    {
        for (i=0; i<33; i++)
            data[len++] = up->pubkey[i];
        data[len++] = bp->numnotaries;
        for (i=0; i<bp->numnotaries; i++)
            len += iguana_rwnum(rwflag,&data[len],sizeof(*up->othermasks),(uint8_t *)&up->othermasks[(int32_t)i]);
    }
    else
    {
        for (i=0; i<33; i++)
            up->pubkey[i] = data[len++];
        numnotaries = data[len++];
        if ( numnotaries <= bp->numnotaries )
        {
            for (i=0; i<numnotaries; i++)
            {
                len += iguana_rwnum(rwflag,&data[len],sizeof(othermask),(uint8_t *)&othermask);
                bp->notaries[(int32_t)i].othermask |= othermask;
            }
        } else return(-1);
    }
    return(len);
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

int32_t komodo_shortflag(char *symbol)
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
}

uint16_t komodo_assetport(uint32_t magic,int32_t shortflag)
{
    return(8000 + shortflag*7777 + (magic % 7777));
}

uint16_t komodo_port(char *symbol,uint64_t supply,uint32_t *magicp,int32_t *shortflagp)
{
    *magicp = komodo_assetmagic(symbol,supply);
    *shortflagp = komodo_shortflag(symbol);
    return(komodo_assetport(*magicp,*shortflagp));
}

#define MAX_CURRENCIES 32
extern char CURRENCIES[][8];

void komodo_assetcoins()
{
    uint16_t extract_userpass(char *serverport,char *userpass,char *coinstr,char *userhome,char *coindir,char *confname);
    int32_t i,j,shortflag; uint32_t magic; cJSON *json; uint16_t port; long filesize; char *userhome,confstr[16],jsonstr[512],magicstr[9],path[512]; struct iguana_info *coin;
    if ( (userhome= OS_filestr(&filesize,"userhome.txt")) == 0 )
        userhome = "root";
    else
    {
        while ( userhome[strlen(userhome)-1] == '\r' || userhome[strlen(userhome)-1] == '\n' )
            userhome[strlen(userhome)-1] = 0;
    }
    for (i=0; i<MAX_CURRENCIES; i++)
    {
        port = komodo_port(CURRENCIES[i],10,&magic,&shortflag);
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
