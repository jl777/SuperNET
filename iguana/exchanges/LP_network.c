
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
//
//  LP_network.c
//  marketmaker
//

void basilisk_psockinit(struct basilisk_swap *swap,int32_t amlp)
{
/*    char keystr[64],databuf[1024],pubkeystr[128],*retstr,*retstr2,*datastr,*pushaddr=0,*subaddr=0; cJSON *retjson,*addrjson; uint8_t data[512]; int32_t datalen,timeout,pushsock = -1,subsock = -1;
    if ( swap->connected == 1 )
        return;
    if ( swap->pushsock < 0 && swap->subsock < 0 && (pushsock= nn_socket(AF_SP,NN_PUSH)) >= 0 && (subsock= nn_socket(AF_SP,NN_SUB)) >= 0 )
    {
        timeout = 1000;
        nn_setsockopt(pushsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
        timeout = 1;
        nn_setsockopt(subsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
        nn_setsockopt(subsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
        swap->pushsock = pushsock;
        swap->subsock = subsock;
    }
    if ( (subsock= swap->subsock) < 0 || (pushsock= swap->pushsock) < 0 )
    {
        printf("error getting nn_sockets\n");
        return;
    }
    sprintf(keystr,"%08x-%08x",swap->I.req.requestid,swap->I.req.quoteid);
    if ( swap->connected == 0 && (retstr= _dex_kvsearch("KV",keystr)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (datastr= jstr(retjson,"value")) != 0 )
            {
                datalen = (int32_t)strlen(datastr) >> 1;
                decode_hex((uint8_t *)databuf,datalen,datastr);
                if ( (addrjson= cJSON_Parse(databuf)) != 0 )
                {
                    pushaddr = jstr(addrjson,"push");
                    subaddr = jstr(addrjson,"sub");
                    if ( pushaddr != 0 && subaddr != 0 )
                    {
                        printf("KV decoded (%s and %s) %d %d\n",pushaddr,subaddr,swap->pushsock,swap->subsock);
                        if ( nn_connect(swap->pushsock,pushaddr) >= 0 && nn_connect(swap->subsock,subaddr) >= 0 )
                            swap->connected = 1;
                    }
                    free_json(addrjson);
                }
            }
            free_json(retjson);
        }
        printf("KVsearch.(%s) -> (%s) connected.%d socks.(%d %d) amlp.%d\n",keystr,retstr,swap->connected,swap->pushsock,swap->subsock,amlp);
        free(retstr);
    }
    printf("connected.%d amlp.%d subsock.%d pushsock.%d\n",swap->connected,amlp,subsock,pushsock);
    if ( swap->connected <= 0 && amlp != 0 && subsock >= 0 && pushsock >= 0 )
    {
        if ( (retstr= _dex_psock("{}")) != 0 )
        {
            printf("psock returns.(%s)\n",retstr);
            // {"result":"success","pushaddr":"tcp://5.9.102.210:30002","subaddr":"tcp://5.9.102.210:30003","randipbits":3606291758,"coin":"KMD","tag":"6952562460568228137"}
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                pushaddr = jstr(retjson,"pushaddr");
                subaddr = jstr(retjson,"subaddr");
                if ( pushaddr != 0 && subaddr != 0 )
                {
                    if ( nn_connect(pushsock,pushaddr) >= 0 )
                    {
                        printf("connected to %d pushaddr.(%s)\n",pushsock,pushaddr);
                        if ( nn_connect(subsock,subaddr) >= 0 )
                        {
                            swap->connected = 1;
                            init_hexbytes_noT(pubkeystr,myinfo->persistent_pubkey33,33);
                            sprintf((char *)data,"{\"push\":\"%s\",\"sub\":\"%s\",\"trade\":[\"%s\", %.8f, \"%s\", %.8f],\"pub\":\"%s\"}",pushaddr,subaddr,swap->I.req.src,dstr(swap->I.req.srcamount),swap->I.req.dest,dstr(swap->I.req.destamount),pubkeystr);
                            datalen = (int32_t)strlen((char *)data) + 1;
                            printf("datalen.%d (%s)\n",datalen,(char *)data);
                            init_hexbytes_noT(databuf,data,datalen);
                            printf("%s -> %s\n",keystr,databuf);
                            if ( (retstr2= _dex_kvupdate("KV",keystr,databuf,1)) != 0 )
                            {
                                printf("KVupdate.(%s)\n",retstr2);
                                free(retstr2);
                            }
                        } else printf("nn_connect error to %d subaddr.(%s)\n",subsock,subaddr);
                    } else printf("nn_connect error to %d pushaddr.(%s)\n",pushsock,pushaddr);
                }
                else printf("missing addr (%p) (%p) (%s)\n",pushaddr,subaddr,jprint(retjson,0));
                free_json(retjson);
            } else printf("Error parsing psock.(%s)\n",retstr);
            free(retstr);
        } else printf("error issuing _dex_psock\n");
    }*/
}

char *nanomsg_tcpname(char *str,char *ipaddr,uint16_t port)
{
    sprintf(str,"tcp://%s:%u",ipaddr,port);
    return(str);
}

int32_t LP_send(int32_t sock,char *msg,int32_t freeflag)
{
    int32_t sentbytes,len,i; struct nn_pollfd pfd;
    for (i=0; i<100; i++)
    {
        pfd.fd = sock;
        pfd.events = NN_POLLOUT;
        if ( nn_poll(&pfd,1,100) > 0 )
        {
            len = (int32_t)strlen(msg) + 1;
            if ( (sentbytes= nn_send(sock,msg,len,0)) != len )
                printf("LP_send sent %d instead of %d\n",sentbytes,len);
            else printf("SENT.(%s)\n",msg);
            if ( freeflag != 0 )
                free(msg);
            return(sentbytes);
        }
        usleep(1000);
    }
    printf("error LP_send\n");
    return(-1);
}

uint32_t LP_swapsend(struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t nextbits,uint32_t crcs[2])
{
    uint8_t *buf; int32_t sentbytes,offset=0,i;
    buf = malloc(datalen + sizeof(msgbits) + sizeof(swap->I.req.quoteid) + sizeof(bits256)*2);
    for (i=0; i<32; i++)
        buf[offset++] = swap->I.myhash.bytes[i];
    for (i=0; i<32; i++)
        buf[offset++] = swap->I.otherhash.bytes[i];
    offset += iguana_rwnum(1,&buf[offset],sizeof(swap->I.req.quoteid),&swap->I.req.quoteid);
    offset += iguana_rwnum(1,&buf[offset],sizeof(msgbits),&msgbits);
    if ( datalen > 0 )
        memcpy(&buf[offset],data,datalen), offset += datalen;
    if ( (sentbytes= nn_send(swap->pushsock,buf,offset,0)) != offset )
    {
        printf("sentbytes.%d vs offset.%d\n",sentbytes,offset);
        if ( sentbytes < 0 )
        {
            if ( swap->pushsock >= 0 )
                nn_close(swap->pushsock), swap->pushsock = -1; //,
            if ( swap->subsock >= 0 ) //
                nn_close(swap->subsock), swap->subsock = -1;
            swap->connected = swap->I.iambob != 0 ? -1 : 0;
            swap->aborted = (uint32_t)time(NULL);
        }
    }
    //else printf("send.[%d] %x offset.%d datalen.%d [%llx]\n",sentbytes,msgbits,offset,datalen,*(long long *)data);
    free(buf);
    return(nextbits);
}

void basilisk_swap_sendabort(struct basilisk_swap *swap)
{
    uint32_t msgbits = 0; uint8_t buf[sizeof(msgbits) + sizeof(swap->I.req.quoteid) + sizeof(bits256)*2]; int32_t sentbytes,offset=0;
    memset(buf,0,sizeof(buf));
    offset += iguana_rwnum(1,&buf[offset],sizeof(swap->I.req.quoteid),&swap->I.req.quoteid);
    offset += iguana_rwnum(1,&buf[offset],sizeof(msgbits),&msgbits);
    if ( (sentbytes= nn_send(swap->pushsock,buf,offset,0)) != offset )
    {
        if ( sentbytes < 0 )
        {
            if ( swap->pushsock >= 0 ) //
                nn_close(swap->pushsock), swap->pushsock = -1;
            if ( swap->subsock >= 0 ) //
                nn_close(swap->subsock), swap->subsock = -1;
            swap->connected = 0;
        }
    } else printf("basilisk_swap_sendabort\n");
}

void basilisk_psockinit(struct basilisk_swap *swap,int32_t amlp);

void basilisk_swapgotdata(struct basilisk_swap *swap,uint32_t crc32,bits256 srchash,bits256 desthash,uint32_t quoteid,uint32_t msgbits,uint8_t *data,int32_t datalen,int32_t reinit)
{
    int32_t i; struct basilisk_swapmessage *mp;
    for (i=0; i<swap->nummessages; i++)
        if ( crc32 == swap->messages[i].crc32 && msgbits == swap->messages[i].msgbits && bits256_cmp(srchash,swap->messages[i].srchash) == 0 && bits256_cmp(desthash,swap->messages[i].desthash) == 0 )
            return;
    //printf(" new message.[%d] datalen.%d Q.%x msg.%x [%llx]\n",swap->nummessages,datalen,quoteid,msgbits,*(long long *)data);
    swap->messages = realloc(swap->messages,sizeof(*swap->messages) * (swap->nummessages + 1));
    mp = &swap->messages[swap->nummessages++];
    mp->crc32 = crc32;
    mp->srchash = srchash;
    mp->desthash = desthash;
    mp->msgbits = msgbits;
    mp->quoteid = quoteid;
    mp->data = malloc(datalen);
    mp->datalen = datalen;
    memcpy(mp->data,data,datalen);
    if ( reinit == 0 && swap->fp != 0 )
    {
        fwrite(mp,1,sizeof(*mp),swap->fp);
        fwrite(data,1,datalen,swap->fp);
        fflush(swap->fp);
    }
}

int32_t basilisk_swapget(struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,int32_t (*basilisk_verify_func)(void *ptr,uint8_t *data,int32_t datalen))
{
    uint8_t *ptr; bits256 srchash,desthash; uint32_t crc32,_msgbits,quoteid; int32_t i,size,offset,retval = -1; struct basilisk_swapmessage *mp = 0;
    while ( (size= nn_recv(swap->subsock,&ptr,NN_MSG,0)) >= 0 )
    {
        swap->lasttime = (uint32_t)time(NULL);
        memset(srchash.bytes,0,sizeof(srchash));
        memset(desthash.bytes,0,sizeof(desthash));
        //printf("gotmsg.[%d] crc.%x\n",size,crc32);
        offset = 0;
        for (i=0; i<32; i++)
            srchash.bytes[i] = ptr[offset++];
        for (i=0; i<32; i++)
            desthash.bytes[i] = ptr[offset++];
        offset += iguana_rwnum(0,&ptr[offset],sizeof(uint32_t),&quoteid);
        offset += iguana_rwnum(0,&ptr[offset],sizeof(uint32_t),&_msgbits);
        if ( size > offset )
        {
            crc32 = calc_crc32(0,&ptr[offset],size-offset);
            if ( size > offset )
            {
                //printf("size.%d offset.%d datalen.%d\n",size,offset,size-offset);
                basilisk_swapgotdata(swap,crc32,srchash,desthash,quoteid,_msgbits,&ptr[offset],size-offset,0);
            }
        }
        else if ( bits256_nonz(srchash) == 0 && bits256_nonz(desthash) == 0 )
        {
            if ( swap->aborted == 0 )
            {
                swap->aborted = (uint32_t)time(NULL);
                printf("got abort signal from other side\n");
            }
        } else printf("basilisk_swapget: got strange packet\n");
        if ( ptr != 0 )
            nn_freemsg(ptr), ptr = 0;
    }
    //char str[65],str2[65];
    for (i=0; i<swap->nummessages; i++)
    {
        //printf("%d: %s vs %s\n",i,bits256_str(str,swap->messages[i].srchash),bits256_str(str2,swap->messages[i].desthash));
        if ( bits256_cmp(swap->messages[i].desthash,swap->I.myhash) == 0 )
        {
            if ( swap->messages[i].msgbits == msgbits )
            {
                if ( swap->I.iambob == 0 && swap->lasttime != 0 && time(NULL) > swap->lasttime+360 )
                {
                    printf("nothing received for a while from Bob, try new sockets\n");
                    if ( swap->pushsock >= 0 ) //
                        nn_close(swap->pushsock), swap->pushsock = -1;
                    if ( swap->subsock >= 0 ) //
                        nn_close(swap->subsock), swap->subsock = -1;
                    swap->connected = 0;
                    basilisk_psockinit(swap,swap->I.iambob != 0);
                }
                mp = &swap->messages[i];
                if ( msgbits != 0x80000000 )
                    break;
            }
        }
    }
    if ( mp != 0 )
        retval = (*basilisk_verify_func)(swap,mp->data,mp->datalen);
    //printf("mine/other %s vs %s\n",bits256_str(str,swap->I.myhash),bits256_str(str2,swap->I.otherhash));
    return(retval);
}

int32_t basilisk_messagekeyread(uint8_t *key,uint32_t *channelp,uint32_t *msgidp,bits256 *srchashp,bits256 *desthashp)
{
    int32_t keylen = 0;
    keylen += iguana_rwnum(0,&key[keylen],sizeof(uint32_t),channelp);
    keylen += iguana_rwnum(0,&key[keylen],sizeof(uint32_t),msgidp);
    keylen += iguana_rwbignum(0,&key[keylen],sizeof(*srchashp),srchashp->bytes);
    keylen += iguana_rwbignum(0,&key[keylen],sizeof(*desthashp),desthashp->bytes);
    return(keylen);
}

int32_t basilisk_messagekey(uint8_t *key,uint32_t channel,uint32_t msgid,bits256 srchash,bits256 desthash)
{
    int32_t keylen = 0;
    keylen += iguana_rwnum(1,&key[keylen],sizeof(uint32_t),&channel);
    keylen += iguana_rwnum(1,&key[keylen],sizeof(uint32_t),&msgid);
    keylen += iguana_rwbignum(1,&key[keylen],sizeof(srchash),srchash.bytes);
    keylen += iguana_rwbignum(1,&key[keylen],sizeof(desthash),desthash.bytes);
    return(keylen);
}

void LP_channelsend(bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgid,uint8_t *data,int32_t datalen)
{
    int32_t keylen; uint8_t key[BASILISK_KEYSIZE]; //char *retstr;
    keylen = basilisk_messagekey(key,channel,msgid,srchash,desthash);
    //if ( (retstr= _dex_reqsend(myinfo,"DEX",key,keylen,data,datalen)) != 0 )
    //    free(retstr);
}

