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

// included from basilisk.c

int32_t baslisk_relay_report(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen,struct basilisk_relaystatus *reported,uint8_t pingdelay)
{
    if ( reported != 0 )
    {
        reported->pingdelay = pingdelay;
    }
    return(0);
}

int32_t basilisk_blocksend(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_info *virt,struct iguana_peer *addr,int32_t height)
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
        basilisk_blocksubmit(myinfo,btcd,virt,addr,blockstr,hash2,height);
        if ( allocptr != 0 )
            free(allocptr);
        return(0);
    } else printf("blocklen.%d for hwm.%d height.%d %s\n",blocklen,virt->blocks.hwmchain.height,height,bits256_str(str,hash2));
    return(-1);
}

int32_t basilisk_ping_processvirts(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_peer *addr,uint8_t *data,int32_t datalen)
{
    int32_t diff,i,j,len = 0; struct iguana_info *virt; char symbol[7]; uint32_t numvirts,height;
    len += iguana_rwvarint32(0,&data[len],&numvirts);
    symbol[6] = 0;
    for (i=0; i<numvirts; i++)
    {
        memcpy(symbol,&data[len],6), len += 6;
        len += iguana_rwvarint32(0,&data[len],&height);
        //printf("(%s %d).%p ",symbol,height,addr);
        if ( myinfo->numrelays > 0 && addr != 0 && (virt= iguana_coinfind(symbol)) != 0 )
        {
            if ( height > virt->longestchain )
                virt->longestchain = height;
            if ( myinfo->numrelays > 0 && virt->blocks.hwmchain.height > height )
            {
                diff = ((height % myinfo->numrelays) - myinfo->RELAYID);
                diff *= diff;
                diff++;
                if ( (rand() % diff) == 0 )
                {
                    for (j=1; height+j<virt->blocks.hwmchain.height && j<3; j++)
                        basilisk_blocksend(myinfo,btcd,virt,addr,height+j);
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

int32_t basilisk_ping_genrelay(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen,struct basilisk_relay *rp)
{
    int32_t datalen = 0;
    datalen = iguana_rwnum(1,&data[datalen],sizeof(rp->ipbits),&rp->ipbits);
    data[datalen++] = rp->direct.pingdelay;
    return(datalen);
}

int32_t basilisk_ping_processrelay(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen,struct basilisk_relay *rp,int32_t i)
{
    uint8_t pingdelay; int32_t j,datalen = 0; uint32_t ipbits;
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
    printf("notified about unknown relay\n"); // parse it to match bytes sent
    datalen += baslisk_relay_report(myinfo,&data[datalen],maxlen-datalen,0,pingdelay);
    return(datalen);
}

void basilisk_ping_process(struct supernet_info *myinfo,struct iguana_peer *addr,uint32_t senderipbits,uint8_t *data,int32_t datalen)
{
    int32_t diff,i,n,len = 0; struct iguana_info *btcd; char ipbuf[64]; struct basilisk_relay *rp; uint8_t numrelays; uint16_t sn; uint32_t now = (uint32_t)time(NULL);
    expand_ipbits(ipbuf,senderipbits);
    btcd = iguana_coinfind("BTCD");
    for (i=0; i<myinfo->numrelays; i++)
    {
        rp = &myinfo->relays[i];
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
    len += basilisk_ping_processvirts(myinfo,btcd,addr,&data[len],datalen - len);
    for (i=0; i<numrelays; i++)
    {
        if ( len > datalen )
            break;
        if ( (n= basilisk_ping_processrelay(myinfo,&data[len],datalen-len,rp,i)) < 0 )
            break;
        len += n;
    }
    if ( len <= datalen-sizeof(sn) )
    {
        len += basilisk_ping_processDEX(myinfo,senderipbits,&data[len],datalen-len);
        len += basilisk_ping_processMSG(myinfo,senderipbits,&data[len],datalen-len);
    }
    if ( len != datalen )
        printf("PING got %d, processed.%d from (%s)\n",datalen,len,ipbuf);
    //else printf("\n");
    //for (i=0; i<datalen; i++)
    //    printf("%02x",data[i]);
    //printf(" <- input ping from.(%s) numrelays.%d datalen.%d\n",ipbuf,numrelays,datalen);
}

int32_t basilisk_ping_gen(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen = 0;
    data[datalen++] = myinfo->numrelays;
    datalen += basilisk_ping_genvirts(myinfo,&data[datalen],maxlen - datalen);
    for (i=0; i<myinfo->numrelays; i++)
        datalen += basilisk_ping_genrelay(myinfo,&data[datalen],maxlen - datalen,&myinfo->relays[i]);
    datalen += basilisk_ping_genDEX(myinfo,&data[datalen],maxlen - datalen);
    datalen += basilisk_ping_genMSG(myinfo,&data[datalen],maxlen - datalen);
    //for (i=0; i<datalen; i++)
    //    printf("%02x",data[i]);
    //printf(" <- output ping datalen.%d\n",datalen);
    return(datalen);
}

void basilisk_ping_send(struct supernet_info *myinfo,struct iguana_info *btcd)
{
    struct iguana_peer *addr; struct basilisk_relay *rp; int32_t i,datalen=0;
    if ( myinfo->pingbuf == 0 )
        myinfo->pingbuf = malloc(IGUANA_MAXPACKETSIZE);
    datalen = basilisk_ping_gen(myinfo,&myinfo->pingbuf[sizeof(struct iguana_msghdr)],IGUANA_MAXPACKETSIZE-sizeof(struct iguana_msghdr));
    for (i=0; i<myinfo->numrelays; i++)
    {
        rp = &myinfo->relays[i];
        addr = 0;
        if ( rp->ipbits == myinfo->myaddr.myipbits )
            basilisk_ping_process(myinfo,0,myinfo->myaddr.myipbits,&myinfo->pingbuf[sizeof(struct iguana_msghdr)],datalen);
        else if ( (addr= iguana_peerfindipbits(btcd,rp->ipbits,1)) != 0 && addr->usock >= 0 )
        {
            if ( iguana_queue_send(addr,0,myinfo->pingbuf,"SuperNETPIN",datalen) <= 0 )
                printf("error sending %d to (%s)\n",datalen,addr->ipaddr);
            //else printf("sent %d to (%s)\n",datalen,addr->ipaddr);
        }
    }
}

