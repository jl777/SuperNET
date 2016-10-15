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

struct dpow_nanomsghdr
{
    bits256 srchash,desthash;
    uint32_t channel,height,size,datalen,crc32;
    uint8_t packet[];
} PACKED;

char *nanomsg_tcpname(char *str,char *ipaddr)
{
    sprintf(str,"tcp://%s:7775",ipaddr);
    return(str);
}

void dpow_nanomsginit(struct supernet_info *myinfo,char *ipaddr)
{
    char str[512]; int32_t timeout,retval;
    if ( myinfo->ipaddr[0] == 0 )
    {
        printf("need to set ipaddr before nanomsg\n");
        return;
    }
    if ( myinfo->DPOW.sock < 0 && (myinfo->DPOW.sock= nn_socket(AF_SP,NN_BUS)) >= 0 )
    {
        if ( nn_bind(myinfo->DPOW.sock,nanomsg_tcpname(str,myinfo->ipaddr)) < 0 )
        {
            printf("error binding to (%s)\n",nanomsg_tcpname(str,myinfo->ipaddr));
            nn_close(myinfo->DPOW.sock);
            myinfo->DPOW.sock = -1;
        }
        timeout = 1000;
        nn_setsockopt(myinfo->DPOW.sock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
    }
    if ( myinfo->DPOW.sock >= 0 && strcmp(ipaddr,myinfo->ipaddr) != 0 )
    {
        retval = nn_connect(myinfo->DPOW.sock,nanomsg_tcpname(str,ipaddr));
        printf("addnotary (%s) retval.%d\n",ipaddr,retval);
    }
}

int32_t dpow_crc32find(struct supernet_info *myinfo,uint32_t crc32,uint32_t channel)
{
    int32_t i,firstz = -1;
    for (i=0; i<sizeof(myinfo->DPOW.crcs)/sizeof(*myinfo->DPOW.crcs); i++)
    {
        if ( myinfo->DPOW.crcs[i] == crc32 )
        {
            //printf("NANODUPLICATE.%08x\n",crc32);
            return(-1);
        }
        else if ( myinfo->DPOW.crcs[i] == 0 )
            firstz = i;
    }
    if ( firstz < 0 )
        firstz = (rand() % (sizeof(myinfo->DPOW.crcs)/sizeof(*myinfo->DPOW.crcs)));
    return(firstz);
}

void dpow_send(struct supernet_info *myinfo,struct dpow_block *bp,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t crcs[2])
{
    struct dpow_nanomsghdr *np; int32_t size,firstz,sentbytes = 0; uint32_t crc32;
    crc32 = calc_crc32(0,data,datalen);
    //if ( (firstz= dpow_crc32find(myinfo,crc32,channel)) >= 0 )
    {
        //myinfo->DPOW.crcs[firstz] = crc32;
        size = (int32_t)(sizeof(*np) + datalen);
        np = calloc(1,size);
        //printf("dpow_send.(%d) size.%d\n",datalen,size);
        np->size = size;
        np->datalen = datalen;
        np->crc32 = crc32;
        np->srchash = srchash;
        np->desthash = desthash;
        np->channel = channel;
        np->height = msgbits;
        memcpy(np->packet,data,datalen);
        sentbytes = nn_send(myinfo->DPOW.sock,np,size,0);
        free(np);
        printf("NANOSEND ht.%d channel.%08x (%d) crc32.%08x datalen.%d\n",np->height,np->channel,size,np->crc32,datalen);
    }
}

void dpow_nanomsg_update(struct supernet_info *myinfo)
{
    int32_t n=0,size,firstz = -1; uint32_t crc32; struct dpow_nanomsghdr *np;
    while ( (size= nn_recv(myinfo->DPOW.sock,&np,NN_MSG,0)) >= 0 )
    {
        n++;
        if ( size >= 0 )
        {
            if ( np->datalen == (size - sizeof(*np)) )
            {
                crc32 = calc_crc32(0,np->packet,np->datalen);
                if ( crc32 == np->crc32 && (firstz= dpow_crc32find(myinfo,crc32,np->channel)) >= 0 )
                {
                    myinfo->DPOW.crcs[firstz] = crc32;
                    printf("NANORECV ht.%d channel.%08x (%d) crc32.%08x:%08x datalen.%d:%d\n",np->height,np->channel,size,np->crc32,crc32,np->datalen,(int32_t)(size - sizeof(*np)));
                    dpow_datahandler(myinfo,np->channel,np->height,np->packet,np->datalen);
                }
            } else printf("np->datalen.%d (size %d - %ld)\n",np->datalen,size,sizeof(*np));
            if ( np != 0 )
                nn_freemsg(np);
        }
        if ( size == 0 )
            break;
    }
    if ( n != 0 )
        printf("nanoupdates.%d\n",n);
}
#else

void dpow_nanomsginit(struct supernet_info *myinfo,char *ipaddr) { }

uint32_t dpow_send(struct supernet_info *myinfo,struct dpow_block *bp,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t crcs[2])
{
    return(0);
}

void dpow_nanomsg_update(struct supernet_info *myinfo) { }

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

int32_t dpow_rwopret(int32_t rwflag,uint8_t *opret,bits256 *hashmsg,int32_t *heightmsgp,bits256 *btctxid,char *src)
{
    int32_t i,opretlen = 0;
    opretlen += iguana_rwbignum(rwflag,&opret[opretlen],sizeof(*hashmsg),hashmsg->bytes);
    opretlen += iguana_rwnum(rwflag,&opret[opretlen],sizeof(*heightmsgp),(uint32_t *)heightmsgp);
    if ( bits256_nonz(*btctxid) != 0 )
    {
        opretlen += iguana_rwbignum(rwflag,&opret[opretlen],sizeof(*btctxid),btctxid->bytes);
        if ( rwflag != 0 )
        {
            for (i=0; src[i]!=0; i++)
                opret[opretlen++] = src[i];
            opret[opretlen++] = 0;
        }
        else
        {
            for (i=0; opret[opretlen]!=0; i++)
                src[i] = opret[opretlen++];
            src[i] = 0;
            opretlen++;
        }
    }
    return(opretlen);
}

int32_t dpow_rwutxobuf(int32_t rwflag,uint8_t *data,bits256 *hashmsg,struct dpow_entry *ep)
{
    int32_t i,len = 0;
    if ( rwflag != 0 )
    {
        data[0] = DPOW_VERSION & 0xff;
        data[1] = (DPOW_VERSION >> 8) & 0xff;
    }
    else if ( (data[0]+((int32_t)data[1]<<8)) != DPOW_VERSION )
        return(-1);
    len = 2;
    len += iguana_rwbignum(rwflag,&data[len],sizeof(*hashmsg),hashmsg->bytes);
    len += iguana_rwbignum(rwflag,&data[len],sizeof(ep->prev_hash),ep->prev_hash.bytes);
    if ( bits256_nonz(ep->prev_hash) == 0 )
        return(-1);
    len += iguana_rwbignum(rwflag,&data[len],sizeof(ep->commit),ep->commit.bytes);
    if ( rwflag != 0 )
    {
        data[len++] = ep->prev_vout;
        for (i=0; i<33; i++)
            data[len++] = ep->pubkey[i];
        data[len++] = ep->bestk;
    }
    else
    {
        ep->prev_vout = data[len++];
        for (i=0; i<33; i++)
            ep->pubkey[i] = data[len++];
        ep->bestk = data[len++];
    }
    len += iguana_rwbignum(rwflag,&data[len],sizeof(ep->recvmask),(uint8_t *)&ep->recvmask);
    return(len);
}

int32_t dpow_rwsigentry(int32_t rwflag,uint8_t *data,struct dpow_sigentry *dsig)
{
    int32_t i,len = 0;
    if ( rwflag != 0 )
    {
        data[len++] = DPOW_VERSION & 0xff;
        data[len++] = (DPOW_VERSION >> 8) & 0xff;
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
        if ( (data[0]+((int32_t)data[1]<<8)) != DPOW_VERSION )
            return(-1);
        len = 2;
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

void dpow_sigsend(struct supernet_info *myinfo,struct dpow_block *bp,int32_t myind,int8_t bestk,uint64_t bestmask,bits256 srchash,uint32_t sigchannel)
{
    struct dpow_sigentry dsig; int32_t i,len; uint8_t data[4096]; struct dpow_entry *ep;
    ep = &bp->notaries[myind];
    //printf("myind.%d bestk.%d %llx >>>>>> broadcast sig\n",myind,bestk,(long long)bestmask);
    memset(&dsig,0,sizeof(dsig));
    for (i=0; i<33; i++)
        dsig.senderpub[i] = myinfo->DPOW.minerkey33[i];
    dsig.lastk = bestk;
    dsig.mask = bestmask;
    dsig.senderind = myind;
    dsig.beacon = bp->beacon;
    dsig.siglen = ep->siglens[bestk];
    memcpy(dsig.sig,ep->sigs[bestk],ep->siglens[bestk]);
    memcpy(dsig.senderpub,myinfo->DPOW.minerkey33,33);
    len = dpow_rwsigentry(1,data,&dsig);
    dpow_send(myinfo,bp,srchash,bp->hashmsg,sigchannel,bp->height,data,len,bp->sigcrcs);
}
