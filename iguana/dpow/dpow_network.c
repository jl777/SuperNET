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
    char symbol[16];
    uint8_t version0,version1,packet[];
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
    }
    if ( myinfo->dpowsock >= 0 && strcmp(ipaddr,myinfo->ipaddr) != 0 )
    {
        retval = nn_connect(myinfo->dpowsock,nanomsg_tcpname(str,ipaddr));
        printf("addnotary (%s) retval.%d\n",ipaddr,retval);
    }
}

int32_t dpow_crc32find(struct supernet_info *myinfo,struct dpow_info *dp,uint32_t crc32,uint32_t channel)
{
    int32_t i,firstz = -1;
    //return(0);
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

void dpow_send(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t crcs[2])
{
    struct dpow_nanomsghdr *np; int32_t size,sentbytes = 0; uint32_t crc32;
    crc32 = calc_crc32(0,data,datalen);
    //if ( (firstz= dpow_crc32find(myinfo,crc32,channel)) >= 0 )
    {
        //dp->crcs[firstz] = crc32;
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
        strcpy(np->symbol,dp->symbol);
        np->version0 = DPOW_VERSION & 0xff;
        np->version1 = (DPOW_VERSION >> 8) & 0xff;
        memcpy(np->packet,data,datalen);
        sentbytes = nn_send(myinfo->dpowsock,np,size,0);
        free(np);
        //printf("NANOSEND ht.%d channel.%08x (%d) crc32.%08x datalen.%d\n",np->height,np->channel,size,np->crc32,datalen);
    }
}

void dpow_nanomsg_update(struct supernet_info *myinfo)
{
    int32_t i,n=0,size,firstz = -1; uint32_t crc32; struct dpow_nanomsghdr *np; struct dpow_info *dp;
    while ( (size= nn_recv(myinfo->dpowsock,&np,NN_MSG,0)) >= 0 )
    {
        if ( size >= 0 )
        {
            if ( np->version0 == (DPOW_VERSION & 0xff) && np->version1 == ((DPOW_VERSION >> 8) & 0xff) )
            {
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
                    if ( dp != 0 && crc32 == np->crc32 && (firstz= dpow_crc32find(myinfo,dp,crc32,np->channel)) >= 0 )
                    {
                        //char str[65]; printf("%s RECV ht.%d ch.%08x (%d) crc32.%08x:%08x datalen.%d:%d firstz.%d\n",bits256_str(str,np->srchash),np->height,np->channel,size,np->crc32,crc32,np->datalen,(int32_t)(size - sizeof(*np)),firstz);
                         if ( i == myinfo->numdpows )
                            printf("received nnpacket for (%s)\n",np->symbol);
                        else if ( dpow_datahandler(myinfo,dp,np->channel,np->height,np->packet,np->datalen) >= 0 )
                            dp->crcs[firstz] = crc32;
                    }
                } else printf("np->datalen.%d %d (size %d - %ld)\n",np->datalen,(int32_t)(size-sizeof(*np)),size,sizeof(*np));
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

uint32_t dpow_send(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t crcs[2])
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
    ep = &bp->notaries[myind];
    printf("sigsend.%s: myind.%d bestk.%d %llx >>>>>> broadcast channel.%x\n",sigchannel == DPOW_SIGCHANNEL ? bp->srccoin->symbol : bp->destcoin->symbol,myind,bestk,(long long)bestmask,sigchannel);
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
    dpow_send(myinfo,dp,bp,srchash,bp->hashmsg,sigchannel,bp->height,data,len,bp->sigcrcs);
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
