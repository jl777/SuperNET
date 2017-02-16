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

// included from basilisk.c

#ifdef ENABLE_VIRTPING
int32_t basilisk_blocksend(struct supernet_info *myinfo,struct iguana_info *notary,struct iguana_info *virt,struct iguana_peer *addr,int32_t height)
{
    int32_t blocklen; bits256 hash2; uint8_t *data = 0; char str[65],strbuf[4096],*blockstr,*allocptr = 0; struct iguana_block *block;
    hash2 = iguana_blockhash(virt,height);
    if ( (block= iguana_blockfind("bsend",virt,hash2)) != 0 )
    {
        if ( block->height != height )
        {
            printf("basilisk_blocksend: height.%d mismatch %d\n",block->height,height);
            return(-1);
        }
        else if ( block->queued != 0 && block->req != 0 )
        {
            memcpy(&blocklen,block->req,sizeof(blocklen));
            data = (uint8_t *)(void *)((long)block->req + sizeof(blocklen));
        }
    }
    if ( data == 0 )
    {
        if ( (blocklen= iguana_peerblockrequest(virt,virt->blockspace,IGUANA_MAXPACKETSIZE,0,hash2,0)) > 0 )
            data = &virt->blockspace[sizeof(struct iguana_msghdr)];
    }
    if ( data != 0 )
    {
        blockstr = basilisk_addhexstr(&allocptr,0,strbuf,sizeof(strbuf),data,blocklen);
        printf("RELAYID.%d send block.%d %s -> (%s) %s\n",myinfo->RELAYID,height,blockstr,addr->ipaddr,bits256_str(str,hash2));
        basilisk_blocksubmit(myinfo,notary,virt,addr,blockstr,hash2,height);
        if ( allocptr != 0 )
            free(allocptr);
        return(0);
    } else printf("blocklen.%d for hwm.%d height.%d %s\n",blocklen,virt->blocks.hwmchain.height,height,bits256_str(str,hash2));
    return(-1);
}

int32_t basilisk_ping_processvirts(struct supernet_info *myinfo,struct iguana_info *notary,struct iguana_peer *addr,uint8_t *data,int32_t datalen)
{
    int32_t diff,i,j,len = 0; struct iguana_info *virt; char symbol[7]; uint32_t numvirts,height;
    len += iguana_rwvarint32(0,&data[len],&numvirts);
    symbol[6] = 0;
    for (i=0; i<numvirts; i++)
    {
        memcpy(symbol,&data[len],6), len += 6;
        len += iguana_rwvarint32(0,&data[len],&height);
        //printf("(%s %d).%p ",symbol,height,addr);
        if ( NUMRELAYS > 0 && addr != 0 && (virt= iguana_coinfind(symbol)) != 0 )
        {
            if ( height > virt->longestchain )
                virt->longestchain = height;
            if ( NUMRELAYS > 0 && virt->blocks.hwmchain.height > height )
            {
                diff = ((height % NUMRELAYS) - myinfo->RELAYID);
                diff *= diff;
                diff++;
                if ( (rand() % diff) == 0 )
                {
                    for (j=1; height+j<virt->blocks.hwmchain.height && j<3; j++)
                        basilisk_blocksend(myinfo,notary,virt,addr,height+j);
                }
            }
        }
    }
    return(len);
}

int32_t basilisk_ping_genvirts(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen)
{
    struct iguana_info *virt,*tmpcoin; int32_t iter,datalen = 0; uint32_t n;
    for (iter=n=0; iter<2; iter++)
    {
        HASH_ITER(hh,myinfo->allcoins,virt,tmpcoin)
        {
            if ( virt != 0 && virt->virtualchain != 0 )
            {
                if ( iter == 0 )
                    n++;
                else
                {
                    memcpy(&data[datalen],virt->symbol,6), datalen += 6;
                    datalen += iguana_rwvarint32(1,&data[datalen],(uint32_t *)&virt->blocks.hwmchain.height);
                }
            }
        }
        if ( iter == 0 )
            datalen += iguana_rwvarint32(1,&data[datalen],&n);
    }
    return(datalen);
}
#endif

int32_t basilisk_ping_processMSG(struct supernet_info *myinfo,uint32_t senderipbits,uint8_t *data,int32_t datalen)
{
    int32_t i,msglen=0,len=0; uint8_t num,keylen,*message,*key; uint32_t duration;
    if ( (num= data[len++]) > 0 )
    {
        //printf("processMSG num.%d datalen.%d\n",num,datalen);
        for (i=0; i<num; i++)
        {
            keylen = data[len++];
            if ( keylen != BASILISK_KEYSIZE )
            {
                printf("invalid keylen.%d != %d\n",keylen,BASILISK_KEYSIZE);
                return(0);
            }
            key = &data[len], len += keylen;
            if ( len+sizeof(msglen) > datalen )
            {
                printf("processMSG overflow len.%d msglen.%d %d > %d\n",len,msglen,(int32_t)(len+sizeof(msglen)),datalen);
                return(0);
            }
            len += iguana_rwnum(0,&data[len],sizeof(msglen),&msglen);
            len += iguana_rwnum(0,&data[len],sizeof(duration),&duration);
            message = &data[len], len += msglen;
            if ( msglen <= 0 || len > datalen )
            {
                printf("illegal msglen.%d or len.%d > %d\n",msglen,len,datalen);
                return(0);
            }
            //printf("i.%d: keylen.%d msglen.%d\n",i,keylen,msglen);
            basilisk_respond_addmessage(myinfo,key,keylen,message,msglen,0,duration);
        }
    }
    return(len);
}

int32_t basilisk_ping_genMSG(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen)
{
    struct basilisk_message *msg; int32_t datalen = 0;
    if ( maxlen > sizeof(msg->key) && (msg= queue_dequeue(&myinfo->msgQ)) != 0 ) // oneshot ping
    {
        data[datalen++] = 1;
        data[datalen++] = msg->keylen;
        memcpy(&data[datalen],msg->key,msg->keylen), datalen += msg->keylen;
        datalen += iguana_rwnum(1,&data[datalen],sizeof(msg->datalen),&msg->datalen);
        datalen += iguana_rwnum(1,&data[datalen],sizeof(msg->duration),&msg->duration);
        if ( maxlen > datalen+msg->datalen )
        {
            //printf("SEND keylen.%d msglen.%d\n",msg->keylen,msg->datalen);
            memcpy(&data[datalen],msg->data,msg->datalen), datalen += msg->datalen;
        }
        else
        {
            printf("basilisk_ping_genMSG message doesnt fit %d vs %d\n",maxlen,datalen+msg->datalen);
            datalen = 0;
        }
        //printf("\n-> ");
        //int32_t i;
        //for (i=0; i<datalen; i++)
        //    printf("%02x",data[i]);
        //printf(" <- genMSG\n");
    } else data[datalen++] = 0;
    return(datalen);
}

int32_t basilisk_ping_genrelay(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen,struct basilisk_relay *rp)
{
    int32_t datalen = 0;
    datalen = iguana_rwnum(1,&data[datalen],sizeof(rp->ipbits),&rp->ipbits);
    data[datalen++] = rp->direct.pingdelay;
    return(datalen);
}

int32_t baslisk_relay_report(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen,struct basilisk_relaystatus *reported,uint8_t pingdelay)
{
    if ( reported != 0 )
    {
        reported->pingdelay = pingdelay;
    }
    return(0);
}

int32_t basilisk_ping_processrelay(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen,struct basilisk_relay *rp,int32_t i)
{
    uint8_t pingdelay; int32_t j,datalen = 0; uint32_t ipbits; char ipaddr[64];
    ipbits = rp->ipbits;
    if ( maxlen < sizeof(ipbits)+1 )
    {
        printf("unping error maxlen.%d is too small\n",maxlen);
        return(-1);
    }
    datalen = iguana_rwnum(1,&data[datalen],sizeof(ipbits),&ipbits);
    pingdelay = data[datalen++];
    if ( (j= basilisk_relayid(myinfo,ipbits)) >= 0 )
    {
        datalen += baslisk_relay_report(myinfo,&data[datalen],maxlen-datalen,&rp->reported[j],pingdelay);
        return(datalen);
    }
    datalen += baslisk_relay_report(myinfo,&data[datalen],maxlen-datalen,0,pingdelay);
    expand_ipbits(ipaddr,ipbits);
    printf("notified about unknown relay (%s)\n",ipaddr); // parse it to match bytes sent
    basilisk_addrelay_info(myinfo,0,ipbits,GENESIS_PUBKEY);
    return(datalen);
}

void basilisk_ping_process(struct supernet_info *myinfo,struct iguana_peer *addr,uint32_t senderipbits,uint8_t *data,int32_t datalen)
{
    int32_t diff,i,n,len = 0; struct iguana_info *notary; char ipbuf[64]; struct basilisk_relay *rp; uint8_t numrelays; uint16_t sn; uint32_t now = (uint32_t)time(NULL);
    expand_ipbits(ipbuf,senderipbits);
    notary = iguana_coinfind("RELAY");
    for (i=0; i<myinfo->NOTARY.NUMRELAYS; i++)
    {
        rp = &myinfo->NOTARY.RELAYS[i];
        rp->direct.pingdelay = 0;
        if ( rp->ipbits == senderipbits )
            rp->lastping = now;
        if ( rp->lastping == now )
            rp->direct.pingdelay = 1;
        else
        {
            diff = (now - rp->lastping);
            if ( diff < 0xff )
                rp->direct.pingdelay = diff;
        }
    }
    numrelays = data[len++];
    //len += basilisk_ping_processvirts(myinfo,notary,addr,&data[len],datalen - len);
    for (i=0; i<numrelays; i++)
    {
        rp = &myinfo->NOTARY.RELAYS[i];
        if ( len > datalen )
            break;
        if ( (n= basilisk_ping_processrelay(myinfo,&data[len],datalen-len,rp,i)) < 0 )
            break;
        len += n;
    }
    if ( len <= datalen-sizeof(sn) )
    {
        //len += basilisk_ping_processDEX(myinfo,senderipbits,&data[len],datalen-len);
        len += basilisk_ping_processMSG(myinfo,senderipbits,&data[len],datalen-len);
    }
    //printf("PING got %d, processed.%d from (%s)\n",datalen,len,ipbuf);
    //else printf("\n");
    //for (i=0; i<datalen; i++)
    //    printf("%02x",data[i]);
    //printf("<<<<<<<<<<< input ping from.(%s) rel.%d numrelays.%d datalen.%d relay.%d Q.%d\n",ipbuf,basilisk_relayid(myinfo,(uint32_t)calc_ipbits(ipbuf)),numrelays,datalen,myinfo->NOTARY.RELAYID,QUEUEITEMS);
    //basilisk_addrelay_info(myinfo,0,(uint32_t)calc_ipbits(ipbuf),GENESIS_PUBKEY);
}

int32_t basilisk_ping_gen(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen = 0;
    data[datalen++] = myinfo->NOTARY.NUMRELAYS;
    //datalen += basilisk_ping_genvirts(myinfo,&data[datalen],maxlen - datalen);
    for (i=0; i<myinfo->NOTARY.NUMRELAYS; i++)
        datalen += basilisk_ping_genrelay(myinfo,&data[datalen],maxlen - datalen,&myinfo->NOTARY.RELAYS[i]);
    //datalen += basilisk_ping_genDEX(myinfo,&data[datalen],maxlen - datalen);
    datalen += basilisk_ping_genMSG(myinfo,&data[datalen],maxlen - datalen);
    //for (i=0; i<datalen; i++)
    //    printf("%02x",data[i]);
    //printf(" output ping datalen.%d relay.%d >>>>>>>>>> Q.%d\n",datalen,myinfo->NOTARY.RELAYID,QUEUEITEMS);
    return(datalen);
}

// encapsulate other messages inside msgQ for onetime ping
// filter out duplicates

void basilisk_ping_send(struct supernet_info *myinfo,struct iguana_info *notary)
{
    struct iguana_peer *addr; char ipaddr[64]; struct basilisk_relay *rp; uint32_t r; int32_t i,j,incr,datalen=0; uint64_t alreadysent;
    if ( notary == 0 || myinfo->NOTARY.NUMRELAYS <= 0 || myinfo->IAMNOTARY == 0 )
    {
        printf("skip ping send %p %d %d\n",notary,myinfo->NOTARY.NUMRELAYS,myinfo->IAMNOTARY);
        return;
    }
    if ( myinfo->pingbuf == 0 )
        myinfo->pingbuf = malloc(IGUANA_MAXPACKETSIZE);
    datalen = basilisk_ping_gen(myinfo,&myinfo->pingbuf[sizeof(struct iguana_msghdr)],IGUANA_MAXPACKETSIZE-sizeof(struct iguana_msghdr));
    incr = sqrt(myinfo->NOTARY.NUMRELAYS) + 1;
    OS_randombytes((void *)&r,sizeof(r));
    for (alreadysent=j=0; j<=incr; j++)
    {
        i = (j == 0) ? myinfo->NOTARY.RELAYID : ((r+j) % myinfo->NOTARY.NUMRELAYS);
        if ( j != 0 && i == myinfo->NOTARY.RELAYID )
            i = (myinfo->NOTARY.RELAYID + 1) % myinfo->NOTARY.NUMRELAYS;
        if ( (((uint64_t)1 << i) & alreadysent) != 0 )
        {
            j--;
            break;
        }
        alreadysent |= ((uint64_t)1 << i);
        rp = &myinfo->NOTARY.RELAYS[i];
        addr = 0;
        expand_ipbits(ipaddr,rp->ipbits);
        if ( rp->ipbits == myinfo->myaddr.myipbits )
            basilisk_ping_process(myinfo,0,myinfo->myaddr.myipbits,&myinfo->pingbuf[sizeof(struct iguana_msghdr)],datalen);
        else if ( (addr= iguana_peerfindipbits(notary,rp->ipbits,1)) != 0 && addr->usock >= 0 )
        {
            if ( iguana_queue_send(addr,0,myinfo->pingbuf,"SuperNETPIN",datalen) <= 0 )
                printf("error sending %d to (%s)\n",datalen,addr->ipaddr);
            else if ( 0 && datalen > 200 )
                fprintf(stderr,"+(%s).%d ",ipaddr,i);
        } //else fprintf(stderr,"-(%s).%d ",ipaddr,i);
    }
    if ( 0 && datalen > 200 )
        printf("my RELAYID.%d of %d\n",myinfo->NOTARY.RELAYID,myinfo->NOTARY.NUMRELAYS);
}

