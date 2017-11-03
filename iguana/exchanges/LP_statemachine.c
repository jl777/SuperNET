
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
//  LP_statemachine.c
//  marketmaker
//

else
{
    CTransaction tx; uint256 hashBlock; int32_t numvouts,len; uint8_t *ptr;
    if ( GetTransaction(NOTARIZED_DESTTXID,tx,hashBlock,true) == 0 )
    {
        fprintf(stderr,"error finding")
        return(-1);
    }
    if ( (numvouts= tx.vout.size()) > 0 )
    {
        ptr = (uint8_t *)tx.vout[numvouts - 1].scriptPubKey.data();
        len = tx.vout[numvouts - 1].scriptPubKey.size();
        retval = komodo_verifynotarizedscript(height,ptr,len,NOTARIZED_HASH);
        printf("direct verify ht.%d -> %d\n",height,retval);
        return(retval);
    }
}

/*struct LP_cacheinfo *ptr,*tmp;
 HASH_ITER(hh,LP_cacheinfos,ptr,tmp)
 {
 if ( ptr->timestamp < now-3600*2 || ptr->price == 0. )
 continue;
 if ( strcmp(ptr->Q.srccoin,base) == 0 && strcmp(ptr->Q.destcoin,rel) == 0 )
 {
 asks = realloc(asks,sizeof(*asks) * (numasks+1));
 if ( (op= LP_orderbookentry(base,rel,ptr->Q.txid,ptr->Q.vout,ptr->Q.txid2,ptr->Q.vout2,ptr->price,ptr->Q.satoshis,ptr->Q.srchash)) != 0 )
 asks[numasks++] = op;
 }
 else if ( strcmp(ptr->Q.srccoin,rel) == 0 && strcmp(ptr->Q.destcoin,base) == 0 )
 {
 bids = realloc(bids,sizeof(*bids) * (numbids+1));
 if ( (op= LP_orderbookentry(base,rel,ptr->Q.txid,ptr->Q.vout,ptr->Q.txid2,ptr->Q.vout2,1./ptr->price,ptr->Q.satoshis,ptr->Q.srchash)) != 0 )
 bids[numbids++] = op;
 }
 }*/

/*void basilisk_swaps_init(struct supernet_info *myinfo)
 {
 char fname[512]; uint32_t iter,swapcompleted,requestid,quoteid,optionduration,statebits; FILE *fp; bits256 privkey;struct basilisk_request R; struct basilisk_swapmessage M; struct basilisk_swap *swap = 0;
 sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
 if ( (myinfo->swapsfp= fopen(fname,"rb+")) != 0 )
 {
 while ( fread(&requestid,1,sizeof(requestid),myinfo->swapsfp) == sizeof(requestid) && fread(&quoteid,1,sizeof(quoteid),myinfo->swapsfp) == sizeof(quoteid) )
 {
 sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
 printf("%s\n",fname);
 if ( (fp= fopen(fname,"rb+")) != 0 ) // check to see if completed
 {
 memset(&M,0,sizeof(M));
 swapcompleted = 1;
 for (iter=0; iter<2; iter++)
 {
 if ( fread(privkey.bytes,1,sizeof(privkey),fp) == sizeof(privkey) &&
 fread(&R,1,sizeof(R),fp) == sizeof(R) &&
 fread(&statebits,1,sizeof(statebits),fp) == sizeof(statebits) &&
 fread(&optionduration,1,sizeof(optionduration),fp) == sizeof(optionduration) )
 {
 while ( 0 && fread(&M,1,sizeof(M),fp) == sizeof(M) )
 {
 M.data = 0;
 //printf("entry iter.%d crc32.%x datalen.%d\n",iter,M.crc32,M.datalen);
 if ( M.datalen < 100000 )
 {
 M.data = malloc(M.datalen);
 if ( fread(M.data,1,M.datalen,fp) == M.datalen )
 {
 if ( calc_crc32(0,M.data,M.datalen) == M.crc32 )
 {
 if ( iter == 1 )
 {
 if ( swap == 0 )
 {
 swap = basilisk_thread_start(privkey,&R,statebits,optionduration,1);
 swap->I.choosei = swap->I.otherchoosei = -1;
 }
 if ( swap != 0 )
 basilisk_swapgotdata(swap,M.crc32,M.srchash,M.desthash,M.quoteid,M.msgbits,M.data,M.datalen,1);
 }
 } else printf("crc mismatch %x vs %x\n",calc_crc32(0,M.data,M.datalen),M.crc32);
 } else printf("error reading M.datalen %d\n",M.datalen);
 free(M.data), M.data = 0;
 }
 }
 }
 if ( swapcompleted != 0 )
 break;
 rewind(fp);
 }
 }
 }
 } else myinfo->swapsfp = fopen(fname,"wb+");
 }*/

FILE *basilisk_swap_save(struct basilisk_swap *swap,bits256 privkey,struct basilisk_request *rp,uint32_t statebits,int32_t optionduration,int32_t reinit)
{
    FILE *fp=0; /*char fname[512];
                 sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,rp->requestid,rp->quoteid), OS_compatible_path(fname);
                 if ( (fp= fopen(fname,"rb+")) == 0 )
                 {
                 if ( (fp= fopen(fname,"wb+")) != 0 )
                 {
                 fwrite(privkey.bytes,1,sizeof(privkey),fp);
                 fwrite(rp,1,sizeof(*rp),fp);
                 fwrite(&statebits,1,sizeof(statebits),fp);
                 fwrite(&optionduration,1,sizeof(optionduration),fp);
                 fflush(fp);
                 }
                 }
                 else if ( reinit != 0 )
                 {
                 }*/
    return(fp);
}
/*char *issue_LP_notifyutxo(char *destip,uint16_t destport,struct LP_utxoinfo *utxo)
 {
 char url[4096],str[65],str2[65],str3[65],*retstr; struct _LP_utxoinfo u; uint64_t val,val2;
 if ( (retstr= LP_isitme(destip,destport)) != 0 )
 return(retstr);
 if ( utxo->iambob == 0 )
 {
 printf("issue_LP_notifyutxo trying to send Alice %s/v%d\n",bits256_str(str,utxo->payment.txid),utxo->payment.vout);
 return(0);
 }
 u = (utxo->iambob != 0) ? utxo->deposit : utxo->fee;
 if ( LP_iseligible(&val,&val2,utxo->iambob,utxo->coin,utxo->payment.txid,utxo->payment.vout,utxo->S.satoshis,u.txid,u.vout) > 0 )
 {
 sprintf(url,"http://%s:%u/api/stats/notified?iambob=%d&pubkey=%s&coin=%s&txid=%s&vout=%d&value=%llu&txid2=%s&vout2=%d&value2=%llu&script=%s&address=%s&timestamp=%u&gui=%s",destip,destport,utxo->iambob,bits256_str(str3,utxo->pubkey),utxo->coin,bits256_str(str,utxo->payment.txid),utxo->payment.vout,(long long)utxo->payment.value,bits256_str(str2,utxo->deposit.txid),utxo->deposit.vout,(long long)utxo->deposit.value,utxo->spendscript,utxo->coinaddr,(uint32_t)time(NULL),utxo->gui);
 if ( strlen(url) > 1024 )
 printf("WARNING long url.(%s)\n",url);
 return(LP_issue_curl("notifyutxo",destip,destport,url));
 //return(issue_curlt(url,LP_HTTP_TIMEOUT));
 }
 else
 {
 printf("issue_LP_notifyutxo: ineligible utxo iambob.%d %.8f %.8f\n",utxo->iambob,dstr(val),dstr(val2));
 if ( utxo->T.spentflag == 0 )
 utxo->T.spentflag = (uint32_t)time(NULL);
 return(0);
 }
 }*/

/*char *issue_LP_lookup(char *destip,uint16_t destport,bits256 pubkey)
 {
 char url[512],str[65];
 sprintf(url,"http://%s:%u/api/stats/lookup?client=%s",destip,destport,bits256_str(str,pubkey));
 //printf("getutxo.(%s)\n",url);
 return(LP_issue_curl("lookup",destip,destport,url));
 //return(issue_curlt(url,LP_HTTP_TIMEOUT));
 }*/


/*if ( LP_canbind == 0 )
 {
 //printf("check deadman %u vs %u\n",LP_deadman_switch,(uint32_t)time(NULL));
 if ( LP_deadman_switch < time(NULL)-PSOCK_KEEPALIVE )
 {
 printf("DEAD man's switch %u activated at %u lag.%d, register forwarding again\n",LP_deadman_switch,(uint32_t)time(NULL),(uint32_t)(time(NULL) - LP_deadman_switch));
 if ( pullsock >= 0 )
 nn_close(pullsock);
 pullsock = LP_initpublicaddr(ctx,&mypullport,pushaddr,myipaddr,mypullport,0);
 LP_deadman_switch = (uint32_t)time(NULL);
 strcpy(LP_publicaddr,pushaddr);
 LP_publicport = mypullport;
 LP_forwarding_register(LP_mypubkey,pushaddr,mypullport,MAX_PSOCK_PORT);
 }
 }*/
/*if ( lastforward < now-3600 )
 {
 if ( (retstr= LP_registerall(0)) != 0 )
 free(retstr);
 //LP_forwarding_register(LP_mypubkey,pushaddr,pushport,10);
 lastforward = now;
 }*/
//if ( IAMLP != 0 && (counter % 600) == 42 )
//    LP_hellos();
/*if ( 0 && LP_canbind == 0 && (counter % (PSOCK_KEEPALIVE*MAINLOOP_PERSEC/2)) == 13 )
 {
 char keepalive[128];
 sprintf(keepalive,"{\"method\":\"keepalive\"}");
 //printf("send keepalive to %s pullsock.%d\n",pushaddr,pullsock);
 if ( /LP_send(pullsock,keepalive,(int32_t)strlen(keepalive)+1,0) < 0 )
 {
 //LP_deadman_switch = 0;
 }
 }*/

/*int32_t nn_tests(void *ctx,int32_t pullsock,char *pushaddr,int32_t nnother)
 {
 int32_t sock,n,m,timeout,retval = -1; char msg[512],*retstr;
 printf("nn_tests.(%s)\n",pushaddr);
 if ( (sock= nn_socket(AF_SP,nnother)) >= 0 )
 {
 if ( nn_connect(sock,pushaddr) < 0 )
 printf("connect error %s\n",nn_strerror(nn_errno()));
 else
 {
 sleep(3);
 timeout = 1;
 nn_setsockopt(sock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
 sprintf(msg,"{\"method\":\"nn_tests\",\"ipaddr\":\"%s\"}",pushaddr);
 n = /LP_send(sock,msg,(int32_t)strlen(msg)+1,0);
 sleep(3);
 LP_pullsock_check(ctx,&retstr,"127.0.0.1",-1,pullsock,0.);
 sprintf(msg,"{\"method\":\"nn_tests2\",\"ipaddr\":\"%s\"}",pushaddr);
 m = /LP_send(pullsock,msg,(int32_t)strlen(msg)+1,0);
 printf(">>>>>>>>>>>>>>>>>>>>>> sent %d+%d bytes -> pullsock.%d retstr.(%s)\n",n,m,pullsock,retstr!=0?retstr:"");
 if ( retstr != 0 )
 {
 free(retstr);
 retval = 0;
 }
 }
 nn_close(sock);
 }
 return(retval);
 }*/

int32_t basilisk_swap_load(uint32_t requestid,uint32_t quoteid,bits256 *privkeyp,struct basilisk_request *rp,uint32_t *statebitsp,int32_t *optiondurationp)
{
    FILE *fp=0; char fname[512]; int32_t retval = -1;
    sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"rb+")) != 0 )
    {
        if ( fread(privkeyp,1,sizeof(*privkeyp),fp) == sizeof(*privkeyp) &&
            fread(rp,1,sizeof(*rp),fp) == sizeof(*rp) &&
            fread(statebitsp,1,sizeof(*statebitsp),fp) == sizeof(*statebitsp) &&
            fread(optiondurationp,1,sizeof(*optiondurationp),fp) == sizeof(*optiondurationp) )
            retval = 0;
        fclose(fp);
    }
    return(retval);
}

void basilisk_swap_saveupdate(struct basilisk_swap *swap)
{
    FILE *fp; char fname[512];
    sprintf(fname,"%s/SWAPS/%u-%u.swap",GLOBAL_DBDIR,swap->I.req.requestid,swap->I.req.quoteid), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        fwrite(&swap->I,1,sizeof(swap->I),fp);
        /*fwrite(&swap->bobdeposit,1,sizeof(swap->bobdeposit),fp);
         fwrite(&swap->bobpayment,1,sizeof(swap->bobpayment),fp);
         fwrite(&swap->alicepayment,1,sizeof(swap->alicepayment),fp);
         fwrite(&swap->myfee,1,sizeof(swap->myfee),fp);
         fwrite(&swap->otherfee,1,sizeof(swap->otherfee),fp);
         fwrite(&swap->aliceclaim,1,sizeof(swap->aliceclaim),fp);
         fwrite(&swap->alicespend,1,sizeof(swap->alicespend),fp);
         fwrite(&swap->bobreclaim,1,sizeof(swap->bobreclaim),fp);
         fwrite(&swap->bobspend,1,sizeof(swap->bobspend),fp);
         fwrite(&swap->bobrefund,1,sizeof(swap->bobrefund),fp);
         fwrite(&swap->alicereclaim,1,sizeof(swap->alicereclaim),fp);*/
        fwrite(swap->privkeys,1,sizeof(swap->privkeys),fp);
        fwrite(swap->otherdeck,1,sizeof(swap->otherdeck),fp);
        fwrite(swap->deck,1,sizeof(swap->deck),fp);
        fclose(fp);
    }
}

/*int32_t basilisk_swap_loadtx(struct basilisk_rawtx *rawtx,FILE *fp,char *bobcoinstr,char *alicecoinstr)
 {
 if ( fread(rawtx,1,sizeof(*rawtx),fp) == sizeof(*rawtx) )
 {
 rawtx->coin = 0;
 rawtx->vins = 0;
 if ( strcmp(rawtx->I.coinstr,bobcoinstr) == 0 || strcmp(rawtx->I.coinstr,alicecoinstr) == 0 )
 {
 rawtx->coin = LP_coinfind(rawtx->I.coinstr);
 if ( rawtx->vinstr[0] != 0 )
 rawtx->vins = cJSON_Parse(rawtx->vinstr);
 printf("loaded.%s len.%d\n",rawtx->name,rawtx->I.datalen);
 return(0);
 }
 }
 return(-1);
 }*/

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
    while ( (size= nn_recv(swap->subsock,&ptr,NN_MSG,NN_DONTWAIT)) >= 0 )
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


#ifdef adfafds
void iguana_ensure_privkey(struct iguana_info *coin,bits256 privkey)
{
    uint8_t pubkey33[33]; struct iguana_waccount *wacct; struct iguana_waddress *waddr,addr; char coinaddr[128];
    bitcoin_pubkey33(swap->ctx,pubkey33,privkey);
    bitcoin_address(coinaddr,coin->pubtype,pubkey33,33);
    //printf("privkey for (%s)\n",coinaddr);
    if ( myinfo->expiration != 0 && ((waddr= iguana_waddresssearch(&wacct,coinaddr)) == 0 || bits256_nonz(waddr->privkey) == 0) )
    {
        if ( waddr == 0 )
        {
            memset(&addr,0,sizeof(addr));
            iguana_waddresscalc(coin->pubtype,coin->wiftype,&addr,privkey);
            if ( (wacct= iguana_waccountfind("default")) != 0 )
                waddr = iguana_waddressadd(coin,wacct,&addr,0);
        }
        if ( waddr != 0 )
        {
            waddr->privkey = privkey;
            if ( bitcoin_priv2wif(waddr->wifstr,waddr->privkey,coin->wiftype) > 0 )
            {
                if ( (0) && waddr->wiftype != coin->wiftype )
                    printf("ensurepriv warning: mismatched wiftype %02x != %02x\n",waddr->wiftype,coin->wiftype);
                if ( (0) && waddr->addrtype != coin->pubtype )
                    printf("ensurepriv warning: mismatched addrtype %02x != %02x\n",waddr->addrtype,coin->pubtype);
            }
        }
    }
}


int32_t basilisk_rawtx_return(struct basilisk_rawtx *rawtx,cJSON *item,int32_t lockinputs,struct vin_info *V)
{
    char *signedtx,*txbytes; cJSON *vins,*privkeyarray; int32_t i,n,retval = -1;
    if ( (txbytes= jstr(item,"rawtx")) != 0 && (vins= jobj(item,"vins")) != 0 )
    {
        privkeyarray = cJSON_CreateArray();
        jaddistr(privkeyarray,wifstr);
        if ( (signedtx= LP_signrawtx(rawtx->coin->symbol,&rawtx->I.signedtxid,&rawtx->I.completed,vins,txbytes,privkeyarray,V)) != 0 )
        {
            if ( lockinputs != 0 )
            {
                //printf("lockinputs\n");
                LP_unspentslock(rawtx->coin->symbol,vins);
                if ( (n= cJSON_GetArraySize(vins)) != 0 )
                {
                    bits256 txid; int32_t vout;
                    for (i=0; i<n; i++)
                    {
                        item = jitem(vins,i);
                        txid = jbits256(item,"txid");
                        vout = jint(item,"vout");
                    }
                }
            }
            rawtx->I.datalen = (int32_t)strlen(signedtx) >> 1;
            //rawtx->txbytes = calloc(1,rawtx->I.datalen);
            decode_hex(rawtx->txbytes,rawtx->I.datalen,signedtx);
            //printf("%s SIGNEDTX.(%s)\n",rawtx->name,signedtx);
            free(signedtx);
            retval = 0;
        } else printf("error signrawtx\n"); //do a very short timeout so it finishes via local poll
        free_json(privkeyarray);
    }
    return(retval);
}
#endif

cJSON *LP_createvins(struct basilisk_rawtx *dest,struct vin_info *V,struct basilisk_rawtx *rawtx,uint8_t *userdata,int32_t userdatalen,uint32_t sequenceid)
{
    cJSON *vins,*item,*sobj; char hexstr[8192];
    vins = cJSON_CreateArray();
    item = cJSON_CreateObject();
    if ( userdata != 0 && userdatalen > 0 )
    {
        memcpy(V[0].userdata,userdata,userdatalen);
        V[0].userdatalen = userdatalen;
        init_hexbytes_noT(hexstr,userdata,userdatalen);
        jaddstr(item,"userdata",hexstr);
#ifdef DISABLE_CHECKSIG
        needsig = 0;
#endif
    }
    //printf("rawtx B\n");
    if ( bits256_nonz(rawtx->I.actualtxid) != 0 )
        jaddbits256(item,"txid",rawtx->I.actualtxid);
    else jaddbits256(item,"txid",rawtx->I.signedtxid);
    jaddnum(item,"vout",0);
    //sobj = cJSON_CreateObject();
    init_hexbytes_noT(hexstr,rawtx->spendscript,rawtx->I.spendlen);
    //jaddstr(sobj,"hex",hexstr);
    //jadd(item,"scriptPubKey",sobj);
    jaddstr(item,"scriptPubKey",hexstr);
    jaddnum(item,"suppress",dest->I.suppress_pubkeys);
    jaddnum(item,"sequence",sequenceid);
    if ( (dest->I.redeemlen= rawtx->I.redeemlen) != 0 )
    {
        init_hexbytes_noT(hexstr,rawtx->redeemscript,rawtx->I.redeemlen);
        memcpy(dest->redeemscript,rawtx->redeemscript,rawtx->I.redeemlen);
        jaddstr(item,"redeemScript",hexstr);
    }
    jaddi(vins,item);
    return(vins);
}

int32_t _basilisk_rawtx_gen(char *str,uint32_t swapstarted,uint8_t *pubkey33,int32_t iambob,int32_t lockinputs,struct basilisk_rawtx *rawtx,uint32_t locktime,uint8_t *script,int32_t scriptlen,int64_t txfee,int32_t minconf,int32_t delay,bits256 privkey)
{
    char scriptstr[1024],wifstr[256],coinaddr[64],*signedtx,*rawtxbytes; uint32_t basilisktag; int32_t retval = -1; cJSON *vins,*privkeys,*addresses,*valsobj; struct vin_info *V;
    init_hexbytes_noT(scriptstr,script,scriptlen);
    basilisktag = (uint32_t)rand();
    valsobj = cJSON_CreateObject();
    jaddstr(valsobj,"coin",rawtx->coin->symbol);
    jaddstr(valsobj,"spendscript",scriptstr);
    jaddstr(valsobj,"changeaddr",rawtx->coin->smartaddr);
    jadd64bits(valsobj,"satoshis",rawtx->I.amount);
    if ( strcmp(rawtx->coin->symbol,"BTC") == 0 && txfee > 0 && txfee < 50000 )
        txfee = 50000;
    jadd64bits(valsobj,"txfee",txfee);
    jaddnum(valsobj,"minconf",minconf);
    if ( locktime == 0 )
        locktime = (uint32_t)time(NULL) - 777;
    jaddnum(valsobj,"locktime",locktime);
    jaddnum(valsobj,"timeout",30000);
    jaddnum(valsobj,"timestamp",swapstarted+delay);
    addresses = cJSON_CreateArray();
    bitcoin_address(coinaddr,rawtx->coin->pubtype,pubkey33,33);
    jaddistr(addresses,coinaddr);
    jadd(valsobj,"addresses",addresses);
    rawtx->I.locktime = locktime;
    printf("%s locktime.%u\n",rawtx->name,locktime);
    V = calloc(256,sizeof(*V));
    privkeys = cJSON_CreateArray();
    bitcoin_priv2wif(wifstr,privkey,rawtx->coin->wiftype);
    jaddistr(privkeys,wifstr);
    vins = LP_createvins(rawtx,V,rawtx,0,0,0xffffffff);
    rawtx->vins = jduplicate(vins);
    jdelete(valsobj,"vin");
    jadd(valsobj,"vin",vins);
    if ( (rawtxbytes= bitcoin_json2hex(rawtx->coin->isPoS,&rawtx->I.txid,valsobj,V)) != 0 )
    {
        //printf("rawtx.(%s) vins.%p\n",rawtxbytes,vins);
        if ( (signedtx= LP_signrawtx(rawtx->coin->symbol,&rawtx->I.signedtxid,&rawtx->I.completed,vins,rawtxbytes,privkeys,V)) != 0 )
        {
            rawtx->I.datalen = (int32_t)strlen(signedtx) >> 1;
            if ( rawtx->I.datalen <= sizeof(rawtx->txbytes) )
                decode_hex(rawtx->txbytes,rawtx->I.datalen,signedtx);
            else printf("DEX tx is too big %d vs %d\n",rawtx->I.datalen,(int32_t)sizeof(rawtx->txbytes));
            if ( signedtx != rawtxbytes )
                free(signedtx);
            if ( rawtx->I.completed != 0 )
                retval = 0;
            else printf("couldnt complete sign transaction %s\n",rawtx->name);
        } else printf("error signing\n");
        free(rawtxbytes);
    } else printf("error making rawtx\n");
    free_json(privkeys);
    free_json(valsobj);
    free(V);
    return(retval);
}

int32_t _basilisk_rawtx_sign(char *symbol,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,uint8_t wiftype,struct basilisk_swap *swap,uint32_t timestamp,uint32_t locktime,uint32_t sequenceid,struct basilisk_rawtx *dest,struct basilisk_rawtx *rawtx,bits256 privkey,bits256 *privkey2,uint8_t *userdata,int32_t userdatalen,int32_t ignore_cltverr)
{
    char *rawtxbytes=0,*signedtx=0,wifstr[128]; cJSON *txobj,*vins,*privkeys; int32_t needsig=1,retval = -1; struct vin_info *V;
    V = calloc(256,sizeof(*V));
    V[0].signers[0].privkey = privkey;
    bitcoin_pubkey33(swap->ctx,V[0].signers[0].pubkey,privkey);
    privkeys = cJSON_CreateArray();
    bitcoin_priv2wif(wifstr,privkey,wiftype);
    jaddistr(privkeys,wifstr);
    if ( privkey2 != 0 )
    {
        V[0].signers[1].privkey = *privkey2;
        bitcoin_pubkey33(swap->ctx,V[0].signers[1].pubkey,*privkey2);
        bitcoin_priv2wif(wifstr,*privkey2,wiftype);
        jaddistr(privkeys,wifstr);
        V[0].N = V[0].M = 2;
        //char str[65]; printf("add second privkey.(%s) %s\n",jprint(privkeys,0),bits256_str(str,*privkey2));
    } else V[0].N = V[0].M = 1;
    V[0].suppress_pubkeys = dest->I.suppress_pubkeys;
    V[0].ignore_cltverr = ignore_cltverr;
    if ( dest->I.redeemlen != 0 )
        memcpy(V[0].p2shscript,dest->redeemscript,dest->I.redeemlen), V[0].p2shlen = dest->I.redeemlen;
    txobj = bitcoin_txcreate(symbol,isPoS,locktime,userdata == 0 ? 1 : 1,timestamp);//rawtx->coin->locktime_txversion);
    vins = LP_createvins(dest,V,rawtx,userdata,userdatalen,sequenceid);
    jdelete(txobj,"vin");
    jadd(txobj,"vin",vins);
    //printf("basilisk_rawtx_sign locktime.%u/%u for %s spendscript.%s -> %s, suppress.%d\n",rawtx->I.locktime,dest->I.locktime,rawtx->name,hexstr,dest->name,dest->I.suppress_pubkeys);
    txobj = bitcoin_txoutput(txobj,dest->spendscript,dest->I.spendlen,dest->I.amount);
    if ( (rawtxbytes= bitcoin_json2hex(isPoS,&dest->I.txid,txobj,V)) != 0 )
    {
        //printf("rawtx.(%s) vins.%p\n",rawtxbytes,vins);
        if ( needsig == 0 )
            signedtx = rawtxbytes;
        if ( signedtx != 0 || (signedtx= LP_signrawtx(symbol,&dest->I.signedtxid,&dest->I.completed,vins,rawtxbytes,privkeys,V)) != 0 )
        {
            dest->I.datalen = (int32_t)strlen(signedtx) >> 1;
            if ( dest->I.datalen <= sizeof(dest->txbytes) )
                decode_hex(dest->txbytes,dest->I.datalen,signedtx);
            else printf("DEX tx is too big %d vs %d\n",dest->I.datalen,(int32_t)sizeof(dest->txbytes));
            if ( signedtx != rawtxbytes )
                free(signedtx);
            if ( dest->I.completed != 0 )
                retval = 0;
            else printf("couldnt complete sign transaction %s\n",rawtx->name);
        } else printf("error signing\n");
        free(rawtxbytes);
    } else printf("error making rawtx\n");
    free_json(privkeys);
    free_json(txobj);
    free(V);
    return(retval);
}

int32_t basilisk_process_swapverify(void *ptr,int32_t (*internal_func)(void *ptr,uint8_t *data,int32_t datalen),uint32_t channel,uint32_t msgid,uint8_t *data,int32_t datalen,uint32_t expiration,uint32_t duration)
{
    struct basilisk_swap *swap = ptr;
    if ( internal_func != 0 )
        return((*internal_func)(swap,data,datalen));
    else return(0);
}

int32_t basilisk_priviextract(struct iguana_info *coin,char *name,bits256 *destp,uint8_t secret160[20],bits256 srctxid,int32_t srcvout)
{
    /*bits256 txid; char str[65]; int32_t i,vini,scriptlen; uint8_t rmd160[20],scriptsig[IGUANA_MAXSCRIPTSIZE];
    memset(privkey.bytes,0,sizeof(privkey));
    // use dex_listtransactions!
    if ( (vini= iguana_vinifind(coin,&txid,srctxid,srcvout)) >= 0 )
    {
        if ( (scriptlen= iguana_scriptsigextract(coin,scriptsig,sizeof(scriptsig),txid,vini)) > 32 )
        {
            for (i=0; i<32; i++)
                privkey.bytes[i] = scriptsig[scriptlen - 33 + i];
            revcalc_rmd160_sha256(rmd160,privkey);//.bytes,sizeof(privkey));
            if ( memcmp(secret160,rmd160,sizeof(rmd160)) == sizeof(rmd160) )
            {
                *destp = privkey;
                printf("basilisk_priviextract found privi %s (%s)\n",name,bits256_str(str,privkey));
                return(0);
            }
        }
    }*/
    return(-1);
}
int32_t basilisk_verify_privi(void *ptr,uint8_t *data,int32_t datalen);

int32_t basilisk_privBn_extract(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    if ( basilisk_priviextract(&swap->bobcoin,"privBn",&swap->I.privBn,swap->I.secretBn,swap->bobrefund.I.actualtxid,0) == 0 )
    {
        printf("extracted privBn from blockchain\n");
    }
    else if ( basilisk_swapget(swap,0x40000000,data,maxlen,basilisk_verify_privi) == 0 )
    {
    }
    if ( bits256_nonz(swap->I.privBn) != 0 && swap->alicereclaim.I.datalen == 0 )
    {
        char str[65]; printf("got privBn.%s\n",bits256_str(str,swap->I.privBn));
        return(basilisk_alicepayment_spend(swap,&swap->alicereclaim));
    }
    return(-1);
}

int32_t basilisk_privAm_extract(struct basilisk_swap *swap)
{
    if ( basilisk_priviextract(&swap->bobcoin,"privAm",&swap->I.privAm,swap->I.secretAm,swap->bobpayment.I.actualtxid,0) == 0 )
    {
        printf("extracted privAm from blockchain\n");
    }
    if ( bits256_nonz(swap->I.privAm) != 0 && swap->bobspend.I.datalen == 0 )
    {
        char str[65]; printf("got privAm.%s\n",bits256_str(str,swap->I.privAm));
        return(basilisk_alicepayment_spend(swap,&swap->bobspend));
    }
    return(-1);
}

int32_t basilisk_verify_otherstatebits(void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t retval; struct basilisk_swap *swap = ptr;
    if ( datalen == sizeof(swap->I.otherstatebits) )
    {
        retval = iguana_rwnum(0,data,sizeof(swap->I.otherstatebits),&swap->I.otherstatebits);
        return(retval);
    } else return(-1);
}

int32_t basilisk_verify_statebits(void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t retval = -1; uint32_t statebits; struct basilisk_swap *swap = ptr;
    if ( datalen == sizeof(swap->I.statebits) )
    {
        retval = iguana_rwnum(0,data,sizeof(swap->I.statebits),&statebits);
        if ( statebits != swap->I.statebits )
        {
            printf("statebits.%x != %x\n",statebits,swap->I.statebits);
            return(-1);
        }
    }
    return(retval);
}

void basilisk_sendstate(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t datalen=0;
    datalen = iguana_rwnum(1,data,sizeof(swap->I.statebits),&swap->I.statebits);
    LP_swapsend(swap,0x80000000,data,datalen,0,0);
}

int32_t basilisk_swapiteration(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t j,datalen,retval = 0; uint32_t savestatebits=0,saveotherbits=0;
    if ( swap->I.iambob != 0 )
        swap->I.statebits |= 0x80;
    while ( swap->aborted == 0 && ((swap->I.otherstatebits & 0x80) == 0 || (swap->I.statebits & 0x80) == 0) && retval == 0 && time(NULL) < swap->I.expiration )
    {
        if ( swap->connected == 0 )
            basilisk_psockinit(swap,swap->I.iambob != 0);
        printf("D r%u/q%u swapstate.%x otherstate.%x remaining %d\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits,swap->I.otherstatebits,(int32_t)(swap->I.expiration-time(NULL)));
        if ( swap->I.iambob != 0 && (swap->I.statebits & 0x80) == 0 ) // wait for fee
        {
            if ( basilisk_swapget(swap,0x80,data,maxlen,basilisk_verify_otherfee) == 0 )
            {
                // verify and submit otherfee
                swap->I.statebits |= 0x80;
                basilisk_sendstate(swap,data,maxlen);
            }
        }
        else if ( swap->I.iambob == 0 )
            swap->I.statebits |= 0x80;
        basilisk_sendstate(swap,data,maxlen);
        basilisk_swapget(swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        if ( (swap->I.otherstatebits & 0x80) != 0 && (swap->I.statebits & 0x80) != 0 )
            break;
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
        basilisk_swapget(swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        basilisk_sendstate(swap,data,maxlen);
        if ( (swap->I.otherstatebits & 0x80) == 0 )
            LP_swapdata_rawtxsend(swap,0x80,data,maxlen,&swap->myfee,0x40,0);
    }
    basilisk_swap_saveupdate(swap);
    while ( swap->aborted == 0 && retval == 0 && time(NULL) < swap->I.expiration )  // both sides have setup required data and paid txfee
    {
        basilisk_swap_saveupdate(swap);
        if ( swap->connected == 0 )
            basilisk_psockinit(swap,swap->I.iambob != 0);
        //if ( (rand() % 30) == 0 )
        printf("E r%u/q%u swapstate.%x otherstate.%x remaining %d\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits,swap->I.otherstatebits,(int32_t)(swap->I.expiration-time(NULL)));
        if ( swap->I.iambob != 0 )
        {
            //printf("BOB\n");
            if ( (swap->I.statebits & 0x100) == 0 )
            {
                printf("send bobdeposit\n");
                swap->I.statebits |= LP_swapdata_rawtxsend(swap,0x200,data,maxlen,&swap->bobdeposit,0x100,0);
            }
            // [BLOCKING: altfound] make sure altpayment is confirmed and send payment
            else if ( (swap->I.statebits & 0x1000) == 0 )
            {
                printf("check alicepayment\n");
                if ( basilisk_swapget(swap,0x1000,data,maxlen,basilisk_verify_alicepaid) == 0 )
                {
                    swap->I.statebits |= 0x1000;
                    printf("got alicepayment aliceconfirms.%d\n",swap->I.aliceconfirms);
                }
            }
            else if ( (swap->I.statebits & 0x2000) == 0 )
            {
                if ( (swap->I.aliceconfirms == 0 && swap->aliceunconf != 0) || LP_numconfirms(swap,&swap->alicepayment,1) >= swap->I.aliceconfirms )
                {
                    swap->I.statebits |= 0x2000;
                    printf("alicepayment confirmed\n");
                }
            }
            else if ( (swap->I.statebits & 0x4000) == 0 )
            {
                basilisk_bobscripts_set(swap,0,1);
                printf("send bobpayment\n");
                swap->I.statebits |= LP_swapdata_rawtxsend(swap,0x8000,data,maxlen,&swap->bobpayment,0x4000,0);
            }
            // [BLOCKING: privM] Bob waits for privAm either from Alice or alice blockchain
            else if ( (swap->I.statebits & 0xc0000) != 0xc0000 )
            {
                if ( basilisk_swapget(swap,0x40000,data,maxlen,basilisk_verify_privi) == 0 || basilisk_privAm_extract(swap) == 0 ) // divulges privAm
                {
                    //printf("got privi spend alicepayment, dont divulge privBn until bobspend propagated\n");
                    basilisk_alicepayment_spend(swap,&swap->bobspend);
                    if ( LP_swapdata_rawtxsend(swap,0,data,maxlen,&swap->bobspend,0x40000,1) == 0 )
                        printf("Bob error spending alice payment\n");
                    else
                    {
                        tradebot_swap_balancingtrade(swap,1);
                        printf("Bob spends alicepayment aliceconfirms.%d\n",swap->I.aliceconfirms);
                        swap->I.statebits |= 0x40000;
                        if ( LP_numconfirms(swap,&swap->bobspend,1) >= swap->I.aliceconfirms )
                        {
                            printf("bobspend confirmed\n");
                            swap->I.statebits |= 0x80000;
                            printf("Bob confirming spend of Alice's payment\n");
                            sleep(DEX_SLEEP);
                        }
                        retval = 1;
                    }
                }
            }
            if ( swap->bobpayment.I.locktime != 0 && time(NULL) > swap->bobpayment.I.locktime )
            {
                // submit reclaim of payment
                printf("bob reclaims bobpayment\n");
                swap->I.statebits |= (0x40000 | 0x80000);
                if ( LP_swapdata_rawtxsend(swap,0,data,maxlen,&swap->bobreclaim,0,0) == 0 )
                    printf("Bob error reclaiming own payment after alice timed out\n");
                else
                {
                    printf("Bob reclaimed own payment\n");
                    while ( 0 && (swap->I.statebits & 0x100000) == 0 ) // why wait for own tx?
                    {
                        if ( LP_numconfirms(swap,&swap->bobreclaim,1) >= 1 )
                        {
                            printf("bobreclaim confirmed\n");
                            swap->I.statebits |= 0x100000;
                            printf("Bob confirms reclain of payment\n");
                            break;
                        }
                    }
                    retval = 1;
                }
            }
        }
        else
        {
            //printf("ALICE\n");
            // [BLOCKING: depfound] Alice waits for deposit to confirm and sends altpayment
            if ( (swap->I.statebits & 0x200) == 0 )
            {
                printf("checkfor deposit\n");
                if ( basilisk_swapget(swap,0x200,data,maxlen,basilisk_verify_bobdeposit) == 0 )
                {
                    // verify deposit and submit, set confirmed height
                    printf("got bobdeposit\n");
                    swap->I.statebits |= 0x200;
                } else printf("no valid deposit\n");
            }
            else if ( (swap->I.statebits & 0x400) == 0 )
            {
                if ( basilisk_istrustedbob(swap) != 0 || (swap->I.bobconfirms == 0 && swap->depositunconf != 0) || LP_numconfirms(swap,&swap->bobdeposit,1) >= swap->I.bobconfirms )
                {
                    printf("bobdeposit confirmed\n");
                    swap->I.statebits |= 0x400;
                }
            }
            else if ( (swap->I.statebits & 0x800) == 0 )
            {
                printf("send alicepayment\n");
                swap->I.statebits |= LP_swapdata_rawtxsend(swap,0x1000,data,maxlen,&swap->alicepayment,0x800,0);
            }
            // [BLOCKING: payfound] make sure payment is confrmed and send in spend or see bob's reclaim and claim
            else if ( (swap->I.statebits & 0x8000) == 0 )
            {
                if ( basilisk_swapget(swap,0x8000,data,maxlen,basilisk_verify_bobpaid) == 0 )
                {
                    printf("got bobpayment\n");
                    tradebot_swap_balancingtrade(swap,0);
                    // verify payment and submit, set confirmed height
                    swap->I.statebits |= 0x8000;
                }
            }
            else if ( (swap->I.statebits & 0x10000) == 0 )
            {
                if ( basilisk_istrustedbob(swap) != 0 || (swap->I.bobconfirms == 0 && swap->paymentunconf != 0) || LP_numconfirms(swap,&swap->bobpayment,1) >= swap->I.bobconfirms )
                {
                    printf("bobpayment confirmed\n");
                    swap->I.statebits |= 0x10000;
                }
            }
            else if ( (swap->I.statebits & 0x20000) == 0 )
            {
                printf("alicespend bobpayment\n");
                if ( LP_swapdata_rawtxsend(swap,0,data,maxlen,&swap->alicespend,0x20000,0) != 0 )//&& (swap->aliceunconf != 0 || basilisk_numconfirms(swap,&swap->alicespend) > 0) )
                {
                    swap->I.statebits |= 0x20000;
                }
            }
            else if ( (swap->I.statebits & 0x40000) == 0 )
            {
                int32_t numconfs;
                if ( (numconfs= LP_numconfirms(swap,&swap->alicespend,1)) >= swap->I.bobconfirms )
                {
                    for (j=datalen=0; j<32; j++)
                        data[datalen++] = swap->I.privAm.bytes[j];
                    printf("send privAm %x\n",swap->I.statebits);
                    swap->I.statebits |= LP_swapsend(swap,0x40000,data,datalen,0x20000,swap->I.crcs_mypriv);
                    printf("Alice confirms spend of Bob's payment\n");
                    retval = 1;
                } else printf("alicespend numconfs.%d < %d\n",numconfs,swap->I.bobconfirms);
            }
            if ( swap->bobdeposit.I.locktime != 0 && time(NULL) > swap->bobdeposit.I.locktime )
            {
                printf("Alice claims deposit\n");
                if ( LP_swapdata_rawtxsend(swap,0,data,maxlen,&swap->aliceclaim,0,0) == 0 )
                    printf("Alice couldnt claim deposit\n");
                else
                {
                    printf("Alice claimed deposit\n");
                    retval = 1;
                }
            }
            else if ( swap->aborted != 0 || basilisk_privBn_extract(swap,data,maxlen) == 0 )
            {
                printf("Alice reclaims her payment\n");
                swap->I.statebits |= 0x40000000;
                if ( LP_swapdata_rawtxsend(swap,0,data,maxlen,&swap->alicereclaim,0x40000000,0) == 0 )
                    printf("Alice error sending alicereclaim\n");
                else
                {
                    printf("Alice reclaimed her payment\n");
                    retval = 1;
                }
            }
        }
        if ( (rand() % 30) == 0 )
            printf("finished swapstate.%x other.%x\n",swap->I.statebits,swap->I.otherstatebits);
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
        basilisk_sendstate(swap,data,maxlen);
        basilisk_swapget(swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
    }
    return(retval);
}

int32_t swapcompleted(struct basilisk_swap *swap)
{
    if ( swap->I.iambob != 0 )
        return(swap->I.bobspent);
    else return(swap->I.alicespent);
}

cJSON *swapjson(struct basilisk_swap *swap)
{
    cJSON *retjson = cJSON_CreateObject();
    return(retjson);
}

int32_t basilisk_rwDEXquote(int32_t rwflag,uint8_t *serialized,struct basilisk_request *rp)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->requestid),&rp->requestid);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->timestamp),&rp->timestamp); // must be 2nd
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->quoteid),&rp->quoteid);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->quotetime),&rp->quotetime);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->optionhours),&rp->optionhours);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->srcamount),&rp->srcamount);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->unused),&rp->unused);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(rp->srchash),rp->srchash.bytes);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(rp->desthash),rp->desthash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->destamount),&rp->destamount);
    if ( rwflag != 0 )
    {
        memcpy(&serialized[len],rp->src,sizeof(rp->src)), len += sizeof(rp->src);
        memcpy(&serialized[len],rp->dest,sizeof(rp->dest)), len += sizeof(rp->dest);
    }
    else
    {
        memcpy(rp->src,&serialized[len],sizeof(rp->src)), len += sizeof(rp->src);
        memcpy(rp->dest,&serialized[len],sizeof(rp->dest)), len += sizeof(rp->dest);
    }
    //len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->DEXselector),&rp->DEXselector);
    //len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->extraspace),&rp->extraspace);
    if ( rp->quoteid != 0 && basilisk_quoteid(rp) != rp->quoteid )
        printf(" basilisk_rwDEXquote.%d: quoteid.%u mismatch calc %u rp.%p\n",rwflag,rp->quoteid,basilisk_quoteid(rp),rp);
    if ( basilisk_requestid(rp) != rp->requestid )
        printf(" basilisk_rwDEXquote.%d: requestid.%u mismatch calc %u rp.%p\n",rwflag,rp->requestid,basilisk_requestid(rp),rp);
    return(len);
}

struct basilisk_request *basilisk_parsejson(struct basilisk_request *rp,cJSON *reqjson)
{
    uint32_t requestid,quoteid;
    memset(rp,0,sizeof(*rp));
    rp->srchash = jbits256(reqjson,"srchash");
    rp->desthash = jbits256(reqjson,"desthash");
    rp->srcamount = j64bits(reqjson,"srcamount");
    //rp->minamount = j64bits(reqjson,"minamount");
    //rp->destamount = j64bits(reqjson,"destamount");
    rp->destamount = j64bits(reqjson,"destsatoshis");
    //printf("parse DESTSATOSHIS.%llu (%s)\n",(long long)rp->destamount,jprint(reqjson,0));
    requestid = juint(reqjson,"requestid");
    quoteid = juint(reqjson,"quoteid");
    //if ( jstr(reqjson,"relay") != 0 )
    //    rp->relaybits = (uint32_t)calc_ipbits(jstr(reqjson,"relay"));
    rp->timestamp = juint(reqjson,"timestamp");
    rp->quotetime = juint(reqjson,"quotetime");
    safecopy(rp->src,jstr(reqjson,"src"),sizeof(rp->src));
    safecopy(rp->dest,jstr(reqjson,"dest"),sizeof(rp->dest));
    if ( quoteid != 0 )
    {
        rp->quoteid = basilisk_quoteid(rp);
        if ( quoteid != rp->quoteid )
            printf("basilisk_parsejson quoteid.%u != %u error\n",quoteid,rp->quoteid);
    }
    rp->requestid = basilisk_requestid(rp);
    if ( requestid != rp->requestid )
    {
        int32_t i; for (i=0; i<sizeof(*rp); i++)
            printf("%02x",((uint8_t *)rp)[i]);
        printf(" basilisk_parsejson.(%s) requestid.%u != %u error\n",jprint(reqjson,0),requestid,rp->requestid);
    }
    return(rp);
}

cJSON *basilisk_requestjson(struct basilisk_request *rp)
{
    cJSON *item = cJSON_CreateObject();
    /*if ( rp->relaybits != 0 )
     {
     expand_ipbits(ipaddr,rp->relaybits);
     jaddstr(item,"relay",ipaddr);
     }*/
    jaddbits256(item,"srchash",rp->srchash);
    if ( bits256_nonz(rp->desthash) != 0 )
        jaddbits256(item,"desthash",rp->desthash);
    jaddstr(item,"src",rp->src);
    if ( rp->srcamount != 0 )
        jadd64bits(item,"srcamount",rp->srcamount);
    //if ( rp->minamount != 0 )
    //    jadd64bits(item,"minamount",rp->minamount);
    jaddstr(item,"dest",rp->dest);
    if ( rp->destamount != 0 )
    {
        //jadd64bits(item,"destamount",rp->destamount);
        jadd64bits(item,"destsatoshis",rp->destamount);
        //printf("DESTSATOSHIS.%llu\n",(long long)rp->destamount);
    }
    jaddnum(item,"quotetime",rp->quotetime);
    jaddnum(item,"timestamp",rp->timestamp);
    jaddnum(item,"requestid",rp->requestid);
    jaddnum(item,"quoteid",rp->quoteid);
    //jaddnum(item,"DEXselector",rp->DEXselector);
    jaddnum(item,"optionhours",rp->optionhours);
    //jaddnum(item,"profit",(double)rp->profitmargin / 1000000.);
    if ( rp->quoteid != 0 && basilisk_quoteid(rp) != rp->quoteid )
        printf("quoteid mismatch %u vs %u\n",basilisk_quoteid(rp),rp->quoteid);
    if ( basilisk_requestid(rp) != rp->requestid )
        printf("requestid mismatch %u vs calc %u\n",rp->requestid,basilisk_requestid(rp));
    {
        int32_t i; struct basilisk_request R;
        if ( basilisk_parsejson(&R,item) != 0 )
        {
            if ( memcmp(&R,rp,sizeof(*rp)-sizeof(uint32_t)) != 0 )
            {
                for (i=0; i<sizeof(*rp); i++)
                    printf("%02x",((uint8_t *)rp)[i]);
                printf(" <- rp.%p\n",rp);
                for (i=0; i<sizeof(R); i++)
                    printf("%02x",((uint8_t *)&R)[i]);
                printf(" <- R mismatch\n");
                for (i=0; i<sizeof(R); i++)
                    if ( ((uint8_t *)rp)[i] != ((uint8_t *)&R)[i] )
                        printf("(%02x %02x).%d ",((uint8_t *)rp)[i],((uint8_t *)&R)[i],i);
                printf("mismatches\n");
            } //else printf("matched JSON conv %u %u\n",basilisk_requestid(&R),basilisk_requestid(rp));
        }
    }
    return(item);
}

cJSON *basilisk_swapjson(struct basilisk_swap *swap)
{
    cJSON *item = cJSON_CreateObject();
    jaddnum(item,"requestid",swap->I.req.requestid);
    jaddnum(item,"quoteid",swap->I.req.quoteid);
    jaddnum(item,"state",swap->I.statebits);
    jaddnum(item,"otherstate",swap->I.otherstatebits);
    jadd(item,"request",basilisk_requestjson(&swap->I.req));
    return(item);
}

#ifdef later

cJSON *basilisk_privkeyarray(struct iguana_info *coin,cJSON *vins)
{
    cJSON *privkeyarray,*item,*sobj; struct iguana_waddress *waddr; struct iguana_waccount *wacct; char coinaddr[64],account[128],wifstr[64],str[65],typestr[64],*hexstr; uint8_t script[1024]; int32_t i,n,len,vout; bits256 txid,privkey; double bidasks[2];
    privkeyarray = cJSON_CreateArray();
    if ( (n= cJSON_GetArraySize(vins)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(vins,i);
            txid = jbits256(item,"txid");
            vout = jint(item,"vout");
            if ( bits256_nonz(txid) != 0 && vout >= 0 )
            {
                iguana_txidcategory(coin,account,coinaddr,txid,vout);
                if ( coinaddr[0] == 0 && (sobj= jobj(item,"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 && is_hexstr(hexstr,0) > 0 )
                {
                    len = (int32_t)strlen(hexstr) >> 1;
                    if ( len < (sizeof(script) << 1) )
                    {
                        decode_hex(script,len,hexstr);
                        if ( len == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 )
                            bitcoin_address(coinaddr,coin->chain->pubtype,script+3,20);
                    }
                }
                if ( coinaddr[0] != 0 )
                {
                    if ( (waddr= iguana_waddresssearch(&wacct,coinaddr)) != 0 )
                    {
                        bitcoin_priv2wif(wifstr,waddr->privkey,coin->chain->wiftype);
                        jaddistr(privkeyarray,waddr->wifstr);
                    }
                    else if ( smartaddress(typestr,bidasks,&privkey,coin->symbol,coinaddr) >= 0 )
                    {
                        bitcoin_priv2wif(wifstr,privkey,coin->chain->wiftype);
                        jaddistr(privkeyarray,wifstr);
                    }
                    else printf("cant find (%s) in wallet\n",coinaddr);
                } else printf("cant coinaddr from (%s).v%d\n",bits256_str(str,txid),vout);
            } else printf("invalid txid/vout %d of %d\n",i,n);
        }
    }
    return(privkeyarray);
}


#endif


#ifdef old
void basilisk_swaploop(void *_utxo)
{
    uint8_t *data; uint32_t expiration,savestatebits=0,saveotherbits=0; uint32_t channel; int32_t iters,retval=0,j,datalen,maxlen; struct basilisk_swap *swap; struct LP_utxoinfo *utxo = _utxo;
    swap = utxo->swap;
    fprintf(stderr,"start swap iambob.%d\n",swap->I.iambob);
    maxlen = 1024*1024 + sizeof(*swap);
    data = malloc(maxlen);
    expiration = (uint32_t)time(NULL) + 300;
    //myinfo->DEXactive = expiration;
    channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
    while ( swap->aborted == 0 && (swap->I.statebits & (0x08|0x02)) != (0x08|0x02) && time(NULL) < expiration )
    {
        LP_channelsend(swap->I.req.srchash,swap->I.req.desthash,channel,0x4000000,(void *)&swap->I.req.requestid,sizeof(swap->I.req.requestid)); //,60);
        if ( swap->connected == 0 )
            basilisk_psockinit(swap,swap->I.iambob != 0);
        if ( swap->connected > 0 )
        {
            printf("A r%u/q%u swapstate.%x\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits);
            basilisk_sendstate(swap,data,maxlen);
            basilisk_sendpubkeys(swap,data,maxlen); // send pubkeys
            if ( basilisk_checkdeck(swap,data,maxlen) == 0) // check for other deck 0x02
                basilisk_sendchoosei(swap,data,maxlen);
            basilisk_waitchoosei(swap,data,maxlen); // wait for choosei 0x08
            if ( (swap->I.statebits & (0x08|0x02)) == (0x08|0x02) )
                break;
        }
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
    }
    if ( swap->connected == 0 )
    {
        printf("couldnt establish connection\n");
        retval = -1;
    }
    while ( swap->aborted == 0 && retval == 0 && (swap->I.statebits & 0x20) == 0 )
    {
        if ( swap->connected == 0 )
            basilisk_psockinit(swap,swap->I.iambob != 0);
        printf("B r%u/q%u swapstate.%x\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits);
        basilisk_sendstate(swap,data,maxlen);
        basilisk_sendchoosei(swap,data,maxlen);
        basilisk_sendmostprivs(swap,data,maxlen);
        if ( basilisk_swapget(swap,0x20,data,maxlen,basilisk_verify_privkeys) == 0 )
        {
            swap->I.statebits |= 0x20;
            break;
        }
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
        if ( time(NULL) > expiration )
            break;
    }
    //myinfo->DEXactive = swap->I.expiration;
    if ( time(NULL) >= expiration )
    {
        retval = -1;
        //myinfo->DEXactive = 0;
    }
    if ( swap->aborted != 0 )
    {
        printf("swap aborted before tx sent\n");
        retval = -1;
    }
    printf("C r%u/q%u swapstate.%x retval.%d\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits,retval);
    iters = 0;
    while ( swap->aborted == 0 && retval == 0 && (swap->I.statebits & 0x40) == 0 && iters++ < 10 ) // send fee
    {
        if ( swap->connected == 0 )
            basilisk_psockinit(swap,swap->I.iambob != 0);
        //printf("sendstate.%x\n",swap->I.statebits);
        basilisk_sendstate(swap,data,maxlen);
        //printf("swapget\n");
        basilisk_swapget(swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        //printf("after swapget\n");
        if ( swap->I.iambob != 0 && swap->bobdeposit.I.datalen == 0 )
        {
            printf("bobscripts set\n");
            if ( basilisk_bobscripts_set(swap,1,1) < 0 )
            {
                sleep(DEX_SLEEP);
                printf("bobscripts set error\n");
                continue;
            }
        }
        if ( swap->I.iambob == 0 )
        {
            /*for (i=0; i<20; i++)
             printf("%02x",swap->secretAm[i]);
             printf(" <- secretAm\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->secretAm256[i]);
             printf(" <- secretAm256\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->pubAm.bytes[i]);
             printf(" <- pubAm\n");
             for (i=0; i<20; i++)
             printf("%02x",swap->secretBn[i]);
             printf(" <- secretBn\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->secretBn256[i]);
             printf(" <- secretBn256\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->pubBn.bytes[i]);
             printf(" <- pubBn\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->pubA0.bytes[i]);
             printf(" <- pubA0\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->pubA1.bytes[i]);
             printf(" <- pubA1\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->pubB0.bytes[i]);
             printf(" <- pubB0\n");
             for (i=0; i<32; i++)
             printf("%02x",swap->pubB1.bytes[i]);
             printf(" <- pubB1\n");*/
            if ( (retval= basilisk_alicetxs(swap,data,maxlen)) != 0 )
            {
                printf("basilisk_alicetxs error\n");
                break;
            }
        }
    }
    if ( swap->I.iambob == 0 && (swap->I.statebits & 0x40) == 0 )
    {
        printf("couldnt send fee\n");
        retval = -8;
    }
    if ( retval == 0 )
    {
        if ( swap->I.iambob == 0 && (swap->myfee.I.datalen == 0 || swap->alicepayment.I.datalen == 0 || swap->alicepayment.I.datalen == 0) )
        {
            printf("ALICE's error %d %d %d\n",swap->myfee.I.datalen,swap->alicepayment.I.datalen,swap->alicepayment.I.datalen);
            retval = -7;
        }
        else if ( swap->I.iambob != 0 && swap->bobdeposit.I.datalen == 0 ) //swap->bobpayment.I.datalen == 0
        {
            printf("BOB's error %d %d %d\n",swap->myfee.I.datalen,swap->bobpayment.I.datalen,swap->bobdeposit.I.datalen);
            retval = -7;
        }
    }
    while ( swap->aborted == 0 && retval == 0 && basilisk_swapiteration(swap,data,maxlen) == 0 )
    {
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
        basilisk_sendstate(swap,data,maxlen);
        basilisk_swapget(swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        basilisk_swap_saveupdate(swap);
        if ( time(NULL) > swap->I.expiration )
            break;
    }
    if ( swap->I.iambob != 0 && swap->bobdeposit.I.datalen != 0 && bits256_nonz(swap->bobdeposit.I.actualtxid) != 0 )
    {
        printf("BOB waiting for confirm state.%x\n",swap->I.statebits);
        sleep(60); // wait for confirm/propagation of msig
        printf("BOB reclaims refund\n");
        basilisk_bobdeposit_refund(swap,0);
        if ( LP_swapdata_rawtxsend(swap,0,data,maxlen,&swap->bobrefund,0x40000000,0) == 0 ) // use secretBn
        {
            printf("Bob submit error getting refund of deposit\n");
        }
        else
        {
            // maybe wait for bobrefund to be confirmed
            for (j=datalen=0; j<32; j++)
                data[datalen++] = swap->I.privBn.bytes[j];
            LP_swapsend(swap,0x40000000,data,datalen,0x40000000,swap->I.crcs_mypriv);
        }
        basilisk_swap_saveupdate(swap);
    }
    if ( retval != 0 )
        basilisk_swap_sendabort(swap);
    printf("end of atomic swap\n");
    if ( swapcompleted(swap) > 0 ) // only if swap completed
    {
        if ( swap->I.iambob != 0 )
            tradebot_pendingadd(swapjson(swap),swap->I.req.src,dstr(swap->I.req.srcamount),swap->I.req.dest,dstr(swap->I.req.destamount));
        else tradebot_pendingadd(swapjson(swap),swap->I.req.dest,dstr(swap->I.req.destamount),swap->I.req.src,dstr(swap->I.req.srcamount));
    }
    printf("%s swap finished statebits %x\n",swap->I.iambob!=0?"BOB":"ALICE",swap->I.statebits);
    //basilisk_swap_purge(swap);
    free(data);
}
#endif

int32_t bitcoin_coinptrs(bits256 pubkey,struct iguana_info **bobcoinp,struct iguana_info **alicecoinp,char *src,char *dest,bits256 srchash,bits256 desthash)
{
    struct iguana_info *coin = LP_coinfind(src);
    if ( coin == 0 || LP_coinfind(dest) == 0 )
        return(0);
    *bobcoinp = *alicecoinp = 0;
    *bobcoinp = LP_coinfind(dest);
    *alicecoinp = LP_coinfind(src);
    if ( bits256_cmp(pubkey,srchash) == 0 )
    {
        if ( strcmp(src,(*bobcoinp)->symbol) == 0 )
            return(1);
        else if ( strcmp(dest,(*alicecoinp)->symbol) == 0 )
            return(-1);
        else return(0);
    }
    else if ( bits256_cmp(pubkey,desthash) == 0 )
    {
        if ( strcmp(src,(*bobcoinp)->symbol) == 0 )
            return(-1);
        else if ( strcmp(dest,(*alicecoinp)->symbol) == 0 )
            return(1);
        else return(0);
    }
    return(0);
}

/*void basilisk_swap_purge(struct basilisk_swap *swap)
 {
 int32_t i,n;
 // while still in orderbook, wait
 //return;
 portable_mutex_lock(&myinfo->DEX_swapmutex);
 n = myinfo->numswaps;
 for (i=0; i<n; i++)
 if ( myinfo->swaps[i] == swap )
 {
 myinfo->swaps[i] = myinfo->swaps[--myinfo->numswaps];
 myinfo->swaps[myinfo->numswaps] = 0;
 basilisk_swap_finished(swap);
 break;
 }
 portable_mutex_unlock(&myinfo->DEX_swapmutex);
 }*/

/*int32_t LP_priceping(int32_t pubsock,struct LP_utxoinfo *utxo,char *rel,double origprice)
 {
 double price,bid,ask; uint32_t now; cJSON *retjson; struct LP_quoteinfo Q; char *retstr;
 if ( (now= (uint32_t)time(NULL)) > utxo->T.swappending && utxo->S.swap == 0 )
 utxo->T.swappending = 0;
 if ( now > utxo->T.published+60 && LP_isavailable(utxo) && (price= LP_myprice(&bid,&ask,utxo->coin,rel)) != 0. )
 {
 if ( origprice < price )
 price = origprice;
 if ( LP_quoteinfoinit(&Q,utxo,rel,price) < 0 )
 return(-1);
 Q.timestamp = (uint32_t)time(NULL);
 retjson = LP_quotejson(&Q);
 jaddstr(retjson,"method","quote");
 retstr = jprint(retjson,1);
 //printf("PING.(%s)\n",retstr);
 if ( pubsock >= 0 )
 LP_send(pubsock,retstr,1);
 else
 {
 // verify it is in list
 // push if it isnt
 }
 utxo->T.published = now;
 return(0);
 }
 return(-1);
 }*/
/*if ( (butxo= LP_utxopairfind(1,Q.txid,Q.vout,Q.txid2,Q.vout2)) == 0 )
 {
 value = LP_txvalue(Q.coinaddr,Q.srccoin,Q.txid,Q.vout);
 value2 = LP_txvalue(Q.coinaddr,Q.srccoin,Q.txid2,Q.vout2);
 if ( value == 0 || value2 == 0 )
 {
 printf("zero value %.8f or value2 %.8f\n",dstr(value),dstr(value2));
 return(clonestr("{\"error\":\"spent txid or txid2 for bob?\"}"));
 }
 if ( (butxo= LP_utxoadd(1,Q.srccoin,Q.txid,Q.vout,value,Q.txid2,Q.vout2,value2,Q.coinaddr,Q.srchash,LP_gui,0)) == 0 )
 {
 printf("cant find or create butxo\n");
 return(clonestr("{\"error\":\"cant find or create butxo\"}"));
 }
 if ( value < Q.satoshis )
 {
 printf("butxo value %.8f less satoshis %.8f\n",dstr(value),dstr(Q.satoshis));
 return(clonestr("{\"error\":\"butxo value less than satoshis\"}"));
 }
 }*/

/*if ( addflag != 0 && LP_utxofind(1,Q.txid,Q.vout) == 0 )
 {
 LP_utxoadd(1,-1,Q.srccoin,Q.txid,Q.vout,Q.value,Q.txid2,Q.vout2,Q.value2,"",Q.srcaddr,Q.srchash,0.);
 LP_utxoadd(0,-1,Q.destcoin,Q.desttxid,Q.destvout,Q.destvalue,Q.feetxid,Q.feevout,Q.feevalu,"",Q.destaddr,Q.desthash,0.);
 }*/

/*struct LP_utxoinfo *utxo,*tmp;
 HASH_ITER(hh,LP_utxoinfos[1],utxo,tmp)
 {
 if ( LP_ismine(utxo) > 0 && strcmp(utxo->coin,base) == 0 )
 LP_priceping(LP_mypubsock,utxo,rel,price * LP_profitratio);
 }*/
/*
bestprice = 0.;
if ( (array= LP_tradecandidates(base)) != 0 )
{
    printf("candidates.(%s)\nn.%d\n",jprint(array,0),cJSON_GetArraySize(array));
    if ( (n= cJSON_GetArraySize(array)) > 0 )
    {
        memset(prices,0,sizeof(prices));
        memset(Q,0,sizeof(Q));
        for (i=0; i<n && i<sizeof(prices)/sizeof(*prices); i++)
        {
            item = jitem(array,i);
            LP_quoteparse(&Q[i],item);
            if ( (price= jdouble(item,"price")) == 0. )
            {
                price = LP_query("price",&Q[i],base,myutxo->coin,zero);
                Q[i].destsatoshis = price * Q[i].satoshis;
            }
            if ( (prices[i]= price) > SMALLVAL && (bestprice == 0. || price < bestprice) )
                bestprice = price;
            char str[65]; printf("i.%d of %d: (%s) -> txid.%s price %.8f best %.8f dest %.8f\n",i,n,jprint(item,0),bits256_str(str,Q[i].txid),price,bestprice,dstr(Q[i].destsatoshis));
        }
        if ( bestprice > SMALLVAL )
        {
            bestmetric = 0.;
            besti = -1;
            for (i=0; i<n && i<sizeof(prices)/sizeof(*prices); i++)
            {
                if ( (price= prices[i]) > SMALLVAL && myutxo->S.satoshis >= Q[i].destsatoshis+Q[i].desttxfee )
                {
                    metric = price / bestprice;
                    printf("%f %f %f %f ",price,metric,dstr(Q[i].destsatoshis),metric * metric * metric);
                    if ( metric < 1.1 )
                    {
                        metric = dstr(Q[i].destsatoshis) * metric * metric * metric;
                        printf("%f\n",metric);
                        if ( bestmetric == 0. || metric < bestmetric )
                        {
                            besti = i;
                            bestmetric = metric;
                        }
                    }
                } else printf("(%f %f) ",dstr(myutxo->S.satoshis),dstr(Q[i].destsatoshis));
            }
            printf("metrics, best %f\n",bestmetric);
*/

int32_t LP_utxosquery(struct LP_peerinfo *mypeer,int32_t mypubsock,char *destipaddr,uint16_t destport,char *coin,int32_t lastn,char *myipaddr,uint16_t myport,int32_t maxentries)
{
    char *retstr; struct LP_peerinfo *peer; uint32_t now; int32_t retval = -1;
    printf("deprecated LP_utxosquery\n");
    return(-1);
    peer = LP_peerfind((uint32_t)calc_ipbits(destipaddr),destport);
    if ( coin == 0 )
        coin = "";
    //printf("utxo query.(%s)\n",destipaddr);
    if ( IAMLP != 0 )
        retstr = issue_LP_getutxos(destipaddr,destport,coin,lastn,myipaddr,myport,mypeer != 0 ? mypeer->numpeers : 0,maxentries);
    else retstr = issue_LP_clientgetutxos(destipaddr,destport,coin,maxentries);
    if ( retstr != 0 )
    {
        now = (uint32_t)time(NULL);
        retval = LP_utxosparse(destipaddr,destport,retstr,now);
        //printf("got.(%s)\n",retstr);
        free(retstr);
    }
    return(retval);
}

char *issue_LP_numutxos(char *destip,uint16_t destport,char *ipaddr,uint16_t port,int32_t numpeers,int32_t numutxos)
{
    char url[512],*retstr;
    printf("deprecated issue_LP_numutxos\n");
    return(0);
    sprintf(url,"http://%s:%u/api/stats/numutxos?ipaddr=%s&port=%u&numpeers=%d&numutxos=%d",destip,destport,ipaddr,port,numpeers,numutxos);
    retstr = LP_issue_curl("numutxos",destip,port,url);
    //printf("%s -> getpeers.(%s)\n",destip,retstr);
    return(retstr);
}

char *issue_LP_getutxos(char *destip,uint16_t destport,char *coin,int32_t lastn,char *ipaddr,uint16_t port,int32_t numpeers,int32_t numutxos)
{
    char url[512];
    printf("deprecated issue_LP_getutxos\n");
    return(0);
    sprintf(url,"http://%s:%u/api/stats/getutxos?coin=%s&lastn=%d&ipaddr=%s&port=%u&numpeers=%d&numutxos=%d",destip,destport,coin,lastn,ipaddr,port,numpeers,numutxos);
    return(LP_issue_curl("getutxos",destip,destport,url));
    //return(issue_curlt(url,LP_HTTP_TIMEOUT));
}

char *issue_LP_clientgetutxos(char *destip,uint16_t destport,char *coin,int32_t lastn)
{
    char url[512];//,*retstr;
    printf("deprecated issue_LP_clientgetutxos\n");
    return(0);
    sprintf(url,"http://%s:%u/api/stats/getutxos?coin=%s&lastn=%d&ipaddr=127.0.0.1&port=0",destip,destport,coin,lastn);
    return(LP_issue_curl("clientgetutxos",destip,destport,url));
    //retstr = issue_curlt(url,LP_HTTP_TIMEOUT);
    //printf("%s clientgetutxos.(%s)\n",url,retstr);
    //return(retstr);
}
void LP_address_monitor(struct LP_pubkeyinfo *pubp)
{
    struct iguana_info *coin,*tmp; char coinaddr[64]; cJSON *retjson; struct LP_address *ap;
    return;
    HASH_ITER(hh,LP_coins,coin,tmp)
    {
        bitcoin_address(coinaddr,coin->taddr,coin->pubtype,pubp->rmd160,sizeof(pubp->rmd160));
        portable_mutex_lock(&coin->addrmutex);
        if ( (ap= _LP_address(coin,coinaddr)) != 0 )
        {
            ap->monitor = (uint32_t)time(NULL);
        }
        portable_mutex_unlock(&coin->addrmutex);
        if ( coin->electrum != 0 )
        {
            if ( (retjson= electrum_address_subscribe(coin->symbol,coin->electrum,&retjson,coinaddr)) != 0 )
            {
                printf("%s MONITOR.(%s) -> %s\n",coin->symbol,coinaddr,jprint(retjson,0));
                free_json(retjson);
            }
        }
    }
}

/*else if ( strcmp(method,"ordermatch") == 0 )
 {
 if ( price > SMALLVAL )
 return(LP_ordermatch(base,j64bits(argjson,"txfee"),price,jdouble(argjson,"relvolume"),rel,jbits256(argjson,"txid"),jint(argjson,"vout"),jbits256(argjson,"feetxid"),jint(argjson,"feevout"),j64bits(argjson,"desttxfee"),jint(argjson,"duration")));
 else return(clonestr("{\"error\":\"no price set\"}"));
 }
 else if ( strcmp(method,"trade") == 0 )
 {
 struct LP_quoteinfo Q;
 if ( price > SMALLVAL || jobj(argjson,"quote") != 0 )
 {
 LP_quoteparse(&Q,jobj(argjson,"quote"));
 return(LP_trade(ctx,myipaddr,pubsock,&Q,price,jint(argjson,"timeout"),jint(argjson,"duration")));
 } else return(clonestr("{\"error\":\"no price set or no quote object\"}"));
 }
 else if ( strcmp(method,"autotrade") == 0 )
 {
 if ( price > SMALLVAL )
 {
 return(LP_autotrade(ctx,myipaddr,pubsock,base,rel,price,jdouble(argjson,"relvolume"),jint(argjson,"timeout"),jint(argjson,"duration")));
 } else return(clonestr("{\"error\":\"no price set\"}"));
 }*/
if ( flag != 0 )
{
    // need to find the requestid/quoteid for aliceid
    if ( (retstr= basilisk_swapentries(bot->base,bot->rel,0)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(retjson)) != 0 )
            {
                for (flag=j=0; j<n; j++)
                {
                    item = jitem(retjson,j);
                    aliceid = j64bits(item,"aliceid");
                    for (i=0; i<bot->numtrades; i++)
                    {
                        if ( (tp= bot->trades[i]) != 0 && tp->finished == 0 && tp->requestid == 0 && tp->quoteid == 0 )
                        {
                            if ( tp->aliceid == aliceid )
                            {
                                tp->requestid = juint(item,"requestid");
                                tp->quoteid = juint(item,"quoteid");
                                printf("found aliceid.%llx to set requestid.%u quoteid.%u\n",(long long)aliceid,tp->requestid,tp->quoteid);
                                flag = 1;
                                break;
                            }
                        }
                    }
                }
            }
            free_json(retjson);
        }
        free(retstr);
    }
}
// check for finished pending swap
for (i=0; i<bot->numtrades; i++)
{
    if ( (tp= bot->trades[i]) != 0 && tp->finished == 0 && tp->requestid != 0 && tp->quoteid != 0 )
    {
        if ( (retstr= basilisk_swapentry(tp->requestid,tp->quoteid)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( (status= jstr(retjson,"status")) != 0 && strcmp(status,"finished") == 0 )
                {
                    bot->pendbasesum -= tp->basevol, bot->basesum += tp->basevol;
                    bot->pendrelsum -= tp->relvol, bot->relsum += tp->relvol;
                    bot->numpending--, bot->completed++;
                    printf("detected completion aliceid.%llx r.%u q.%u\n",(long long)tp->aliceid,tp->requestid,tp->quoteid);
                    tp->finished = (uint32_t)time(NULL);
                }
                free_json(retjson);
            }
            free(retstr);
        }
    }
}
}

int32_t LP_utxopurge(int32_t allutxos)
{
    char str[65]; struct LP_utxoinfo *utxo,*tmp; int32_t iambob,n = 0;
    printf("LP_utxopurge mypub.(%s)\n",bits256_str(str,LP_mypub25519));
    portable_mutex_lock(&LP_utxomutex);
    for (iambob=0; iambob<=1; iambob++)
    {
        HASH_ITER(hh,LP_utxoinfos[iambob],utxo,tmp)
        {
            if ( LP_isavailable(utxo) > 0 )
            {
                if ( allutxos != 0 || LP_ismine(utxo) > 0 )
                {
                    printf("iambob.%d delete.(%s)\n",iambob,bits256_str(str,utxo->payment.txid));
                    HASH_DELETE(hh,LP_utxoinfos[iambob],utxo);
                    //free(utxo); let the LP_utxoinfos2 free the utxo, should be 1:1
                } else n++;
            } else n++;
        }
        HASH_ITER(hh,LP_utxoinfos2[iambob],utxo,tmp)
        {
            if ( LP_isavailable(utxo) > 0 )
            {
                if ( allutxos != 0 || LP_ismine(utxo) > 0 )
                {
                    printf("iambob.%d delete2.(%s)\n",iambob,bits256_str(str,utxo->payment.txid));
                    HASH_DELETE(hh2,LP_utxoinfos2[iambob],utxo);
                    free(utxo);
                } else n++;
            } else n++;
        }
    }
    portable_mutex_unlock(&LP_utxomutex);
    return(n);
}
/*struct LP_utxoinfo *_LP_butxo_find(struct LP_utxoinfo *butxo)
 {
 int32_t i; struct LP_utxoinfo *utxo=0; uint32_t now = (uint32_t)time(NULL);
 //portable_mutex_lock(&LP_butxomutex);
 for (i=0; i<sizeof(BUTXOS)/sizeof(*BUTXOS); i++)
 {
 utxo = &BUTXOS[i];
 if ( butxo->payment.vout == utxo->payment.vout && butxo->deposit.vout == utxo->deposit.vout && bits256_nonz(butxo->payment.txid) != 0 && bits256_nonz(butxo->deposit.txid) != 0 && bits256_cmp(butxo->payment.txid,utxo->payment.txid) == 0 && bits256_cmp(butxo->deposit.txid,utxo->deposit.txid) == 0 )
 break;
 if ( utxo->S.swap == 0 && now > utxo->T.swappending )
 memset(utxo,0,sizeof(*utxo));
 utxo = 0;
 }
 //portable_mutex_unlock(&LP_butxomutex);
 return(utxo);
 }
 
 struct LP_utxoinfo *LP_butxo_add(struct LP_utxoinfo *butxo)
 {
 static struct LP_utxoinfo zeroes;
 int32_t i; struct LP_utxoinfo *utxo=0;
 portable_mutex_lock(&LP_butxomutex);
 if ( (utxo= _LP_butxo_find(butxo)) == 0 )
 {
 for (i=0; i<sizeof(BUTXOS)/sizeof(*BUTXOS); i++)
 {
 utxo = &BUTXOS[i];
 if ( memcmp(&zeroes,utxo,sizeof(*utxo)) == 0 )
 {
 *utxo = *butxo;
 break;
 }
 utxo = 0;
 }
 }
 portable_mutex_unlock(&LP_butxomutex);
 return(utxo);
 }
 
 void LP_butxo_swapfields_copy(struct LP_utxoinfo *destutxo,struct LP_utxoinfo *srcutxo)
 {
 destutxo->S = srcutxo->S;
 destutxo->T = srcutxo->T;
 }
 
 void LP_butxo_swapfields(struct LP_utxoinfo *butxo)
 {
 struct LP_utxoinfo *getutxo=0;
 portable_mutex_lock(&LP_butxomutex);
 if ( (getutxo= _LP_butxo_find(butxo)) != 0 )
 LP_butxo_swapfields_copy(butxo,getutxo);
 portable_mutex_unlock(&LP_butxomutex);
 }
 
 void LP_butxo_swapfields_set(struct LP_utxoinfo *butxo)
 {
 struct LP_utxoinfo *setutxo;
 if ( (setutxo= LP_butxo_add(butxo)) != 0 )
 {
 LP_butxo_swapfields_copy(setutxo,butxo);
 }
 }*/
/*struct LP_utxoinfo BUTXOS[100];
 
 int32_t LP_butxo_findeither(bits256 txid,int32_t vout)
 {
 struct LP_utxoinfo *utxo; int32_t i,retval = 0;
 portable_mutex_lock(&LP_butxomutex);
 for (i=0; i<sizeof(BUTXOS)/sizeof(*BUTXOS); i++)
 {
 utxo = &BUTXOS[i];
 if ( (vout == utxo->payment.vout && bits256_cmp(txid,utxo->payment.txid)) == 0 || (vout == utxo->deposit.vout && bits256_cmp(txid,utxo->deposit.txid) == 0) )
 {
 retval = 1;
 break;
 }
 }
 portable_mutex_unlock(&LP_butxomutex);
 return(retval);
 }*/

struct LP_utxoinfo *LP_utxoaddjson(int32_t iambob,int32_t pubsock,cJSON *argjson)
{
    struct LP_utxoinfo *utxo;
    if ( jobj(argjson,"iambob") == 0 || iambob != jint(argjson,"iambob") )
    {
        printf("LP_utxoaddjson: iambob.%d != arg.%d obj.%p (%s)\n",iambob,jint(argjson,"iambob"),jobj(argjson,"iambob"),jprint(argjson,0));
        return(0);
    }
    portable_mutex_lock(&LP_UTXOmutex);
    utxo = LP_utxoadd(iambob,pubsock,jstr(argjson,"coin"),jbits256(argjson,"txid"),jint(argjson,"vout"),j64bits(argjson,"value"),jbits256(argjson,"txid2"),jint(argjson,"vout2"),j64bits(argjson,"value2"),jstr(argjson,"script"),jstr(argjson,"address"),jbits256(argjson,"pubkey"),jstr(argjson,"gui"),juint(argjson,"session"));
    if ( LP_ismine(utxo) > 0 && utxo->T.lasttime == 0 )
    {
        utxo->T.lasttime = (uint32_t)time(NULL);
        printf("set lasttime!\n");
    }
    portable_mutex_unlock(&LP_UTXOmutex);
    return(utxo);
}


int32_t LP_utxosparse(char *destipaddr,uint16_t destport,char *retstr,uint32_t now)
{
    struct LP_peerinfo *peer; uint32_t argipbits; char *argipaddr; uint16_t argport,pushport,subport; cJSON *array,*item; int32_t i,n=0; bits256 txid; struct LP_utxoinfo *utxo;
    //printf("parse.(%s)\n",retstr);
    if ( (array= cJSON_Parse(retstr)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                if ( (argipaddr= jstr(item,"ipaddr")) != 0 && (argport= juint(item,"port")) != 0 )
                {
                    if ( (pushport= juint(item,"push")) == 0 )
                        pushport = argport + 1;
                    if ( (subport= juint(item,"sub")) == 0 )
                        subport = argport + 2;
                    argipbits = (uint32_t)calc_ipbits(argipaddr);
                    if ( (peer= LP_peerfind(argipbits,argport)) == 0 )
                        peer = LP_addpeer(0,-1,argipaddr,argport,pushport,subport,jint(item,"numpeers"),jint(item,"numutxos"),juint(item,"session"));
                }
                if ( jobj(item,"txid") != 0 )
                {
                    txid = jbits256(item,"txid");
                    //printf("parse.(%s)\n",jprint(item,0));
                    if ( (utxo= LP_utxoaddjson(1,-1,item)) != 0 )
                        utxo->T.lasttime = now;
                }
            }
            if ( (destpeer= LP_peerfind((uint32_t)calc_ipbits(destipaddr),destport)) != 0 )
            {
                destpeer->numutxos = n;
            }
        }
        free_json(array);
    }
    return(n);
}
void LP_spentnotify(struct LP_utxoinfo *utxo,int32_t selector)
{
    //cJSON *argjson; struct _LP_utxoinfo u; char *msg;
    if ( utxo == 0 )
        return;
    utxo->T.spentflag = (uint32_t)time(NULL);
    /*if ( LP_mypeer != 0 && LP_mypeer->numutxos > 0 )
     LP_mypeer->numutxos--;
     if ( LP_mypubsock >= 0 )
     {
     argjson = cJSON_CreateObject();
     jaddstr(argjson,"method","checktxid");
     jaddbits256(argjson,"txid",utxo->payment.txid);
     jaddnum(argjson,"vout",utxo->payment.vout);
     if ( selector != 0 )
     {
     if ( bits256_nonz(utxo->deposit.txid) != 0 )
     u = utxo->deposit;
     else u = utxo->fee;
     jaddbits256(argjson,"checktxid",u.txid);
     jaddnum(argjson,"checkvout",u.vout);
     }
     msg = jprint(argjson,1);
     /LP_send(LP_mypubsock,msg,(int32_t)strlen(msg)+1,1);
     }*/
}
char *LP_utxos(int32_t iambob,struct LP_peerinfo *mypeer,char *symbol,int32_t lastn)
{
    int32_t i,n,m; uint64_t val,val2; struct _LP_utxoinfo u; struct LP_utxoinfo *utxo,*tmp; cJSON *utxosjson = cJSON_CreateArray();
    printf("deprecated! LP_utxos\n");
    //n = mypeer != 0 ? mypeer->numutxos : 0;
    if ( lastn <= 0 )
        lastn = LP_PROPAGATION_SLACK * 2;
    HASH_ITER(hh,LP_utxoinfos[iambob],utxo,tmp)
    {
        //char str[65]; printf("check %s.%s\n",utxo->coin,bits256_str(str,utxo->payment.txid));
        if ( (symbol == 0 || symbol[0] == 0 || strcmp(symbol,utxo->coin) == 0) && utxo->T.spentflag == 0 )
        {
            u = (iambob != 0) ? utxo->deposit : utxo->fee;
            if ( LP_iseligible(&val,&val2,utxo->iambob,utxo->coin,utxo->payment.txid,utxo->payment.vout,utxo->S.satoshis,u.txid,u.vout) == 0 )
            {
                char str[65]; printf("iambob.%d not eligible (%.8f %.8f) %s %s/v%d\n",iambob,dstr(val),dstr(val2),utxo->coin,bits256_str(str,utxo->payment.txid),utxo->payment.vout);
                continue;
            } else jaddi(utxosjson,LP_utxojson(utxo));
        }
    }
    if ( (n= cJSON_GetArraySize(utxosjson)) > lastn )
    {
        m = n - lastn;
        for (i=0; i<m; i++)
            cJSON_DeleteItemFromArray(utxosjson,0);
    }
    return(jprint(utxosjson,1));
}
void LP_utxo_clientpublish(struct LP_utxoinfo *utxo)
{
    bits256 zero; char *msg;
    if ( 0 && LP_isunspent(utxo) > 0 )
    {
        memset(zero.bytes,0,sizeof(zero));
        msg = jprint(LP_utxojson(utxo),1);
        LP_broadcast_message(LP_mypubsock,utxo->coin,"",zero,msg);
    }
}

/*char *LP_spentcheck(cJSON *argjson)
 {
 bits256 txid,checktxid; int32_t vout,checkvout; struct LP_utxoinfo *utxo; int32_t iambob,retval = 0;
 txid = jbits256(argjson,"txid");
 vout = jint(argjson,"vout");
 for (iambob=0; iambob<=1; iambob++)
 {
 if ( (utxo= LP_utxofind(iambob,txid,vout)) != 0 && utxo->T.spentflag == 0 )
 {
 if ( jobj(argjson,"check") == 0 )
 checktxid = txid, checkvout = vout;
 else
 {
 checktxid = jbits256(argjson,"checktxid");
 checkvout = jint(argjson,"checkvout");
 }
 if ( LP_txvalue(0,utxo->coin,checktxid,checkvout) == 0 )
 {
 //if ( LP_mypeer != 0 && LP_mypeer->numutxos > 0 )
 //    LP_mypeer->numutxos--;
 utxo->T.spentflag = (uint32_t)time(NULL);
 retval++;
 printf("indeed txid was spent\n");
 }
 }
 }
 if ( retval > 0 )
 return(clonestr("{\"result\":\"marked as spent\"}"));
 return(clonestr("{\"error\":\"cant find txid to check spent status\"}"));
 }*/


/*char *LP_pricestr(char *base,char *rel,double origprice)
 {
 cJSON *retjson; double price = 0.;
 if ( base != 0 && base[0] != 0 && rel != 0 && rel[0] != 0 )
 {
 price = LP_price(base,rel);
 if ( origprice > SMALLVAL && origprice < price )
 price = origprice;
 }
 if ( LP_pricevalid(price) > 0 )
 {
 retjson = cJSON_CreateObject();
 jaddstr(retjson,"result","success");
 jaddstr(retjson,"method","postprice");
 jaddbits256(retjson,"pubkey",G.LP_mypub25519);
 jaddstr(retjson,"base",base);
 jaddstr(retjson,"rel",rel);
 jaddnum(retjson,"price",price);
 jadd(retjson,"theoretical",LP_priceinfomatrix(0));
 jadd(retjson,"quotes",LP_priceinfomatrix(1));
 return(jprint(retjson,1));
 } else return(clonestr("{\"error\":\"cant find baserel pair\"}"));
 }*/
void LP_utxo_spentcheck(int32_t pubsock,struct LP_utxoinfo *utxo)
{
    struct _LP_utxoinfo u; struct iguana_info *coin; char str[65]; uint32_t now = (uint32_t)time(NULL);
    if ( IAMLP != 0 && (coin= LP_coinfind(utxo->coin)) != 0 && coin->inactive != 0 )
        return;
    //printf("%s lag.%d\n",bits256_str(str,utxo->txid),now-utxo->lastspentcheck);
    if ( utxo->T.spentflag == 0 && now > utxo->T.lastspentcheck+60 )
    {
        u = (utxo->iambob != 0) ? utxo->deposit : utxo->fee;
        utxo->T.lastspentcheck = now;
        if ( LP_txvalue(0,utxo->coin,utxo->payment.txid,utxo->payment.vout) == 0 )
        {
            printf("txid.%s %s/v%d %.8f has been spent\n",utxo->coin,bits256_str(str,utxo->payment.txid),utxo->payment.vout,dstr(utxo->payment.value));
            LP_spentnotify(utxo,0);
        }
        else if ( LP_txvalue(0,utxo->coin,u.txid,u.vout) == 0 )
        {
            printf("txid2.%s %s/v%d %.8f has been spent\n",utxo->coin,bits256_str(str,u.txid),u.vout,dstr(u.value));
            LP_spentnotify(utxo,1);
        }
    }
}

int32_t LP_peer_utxosquery(struct LP_peerinfo *mypeer,uint16_t myport,int32_t pubsock,struct LP_peerinfo *peer,uint32_t now,int32_t interval,int32_t maxentries)
{
    int32_t lastn,n = -1;
    if ( peer->lastutxos < now-interval )
    {
        //lastn = peer->numutxos - mypeer->numutxos + LP_PROPAGATION_SLACK;
        //if ( lastn < LP_PROPAGATION_SLACK * 2 )
        lastn = LP_PROPAGATION_SLACK * 2;
        if ( mypeer == 0 || strcmp(peer->ipaddr,mypeer->ipaddr) != 0 )
        {
            peer->lastutxos = now;
            //printf("query utxos from %s\n",peer->ipaddr);
            n = LP_utxosquery(mypeer,pubsock,peer->ipaddr,peer->port,"",lastn,mypeer != 0 ? mypeer->ipaddr : "127.0.0.1",myport,maxentries);
        }
    } //else printf("LP_peer_utxosquery skip.(%s) %u\n",peer->ipaddr,peer->lastutxos);
    return(n);
}
bestitem = LP_quotejson(qp);
if ( LP_pricevalid(price) > 0 )
{
    if ( price <= maxprice )
    {
        LP_query(ctx,myipaddr,mypubsock,"connect",qp);
        //price = LP_pricecache(qp,qp->srccoin,qp->destcoin,qp->txid,qp->vout);
        LP_requestinit(&qp->R,qp->srchash,qp->desthash,qp->srccoin,qp->satoshis-2*qp->txfee,qp->destcoin,qp->destsatoshis-2*qp->desttxfee,qp->timestamp,qp->quotetime,DEXselector);
        while ( time(NULL) < expiration )
        {
            if ( aliceutxo->S.swap != 0 )
                break;
            sleep(3);
        }
        jaddnum(bestitem,"quotedprice",price);
        jaddnum(bestitem,"maxprice",maxprice);
        if ( (swap= aliceutxo->S.swap) == 0 )
        {
            if ( (pubp= LP_pubkeyadd(qp->srchash)) != 0 )
                pubp->numerrors++;
            jaddstr(bestitem,"status","couldnt establish connection");
        }
        else
        {
            jaddstr(bestitem,"status","connected");
            jaddnum(bestitem,"requestid",swap->I.req.requestid);
            jaddnum(bestitem,"quoteid",swap->I.req.quoteid);
            printf("Alice r.%u qp->%u\n",swap->I.req.requestid,swap->I.req.quoteid);
        }
    }
    else
    {
        jaddnum(bestitem,"quotedprice",price);
        jaddnum(bestitem,"maxprice",maxprice);
        jaddstr(bestitem,"status","too expensive");
    }
}
else
{
    printf("invalid price %.8f\n",price);
    jaddnum(bestitem,"maxprice",maxprice);
    jaddstr(bestitem,"status","no response to request");
}
/*while ( time(NULL) < expiration )
 {
 if ( (price= LP_pricecache(qp,qp->srccoin,qp->destcoin,qp->txid,qp->vout)) > SMALLVAL )
 {
 printf("break out of price %.8f %s/%s\n",price,qp->srccoin,qp->destcoin);
 break;
 }
 sleep(1);
 }*/

if ( aliceutxo->S.swap == 0 )
LP_availableset(aliceutxo);
return(jprint(bestitem,0));
}
if ( 0 && (retstr= issue_LP_listunspent(peer->ipaddr,peer->port,coin->symbol,"")) != 0 )
{
    if ( (array2= cJSON_Parse(retstr)) != 0 )
    {
        if ( (m= cJSON_GetArraySize(array2)) > 0 )
        {
            for (j=0; j<m; j++)
            {
                item = jitem(array2,j);
                if ( (coinaddr= jfieldname(item)) != 0 )
                {
                    metric = j64bits(item,coinaddr);
                    //printf("(%s) -> %.8f n.%d\n",coinaddr,dstr(metric>>16),(uint16_t)metric);
                    if ( (ap= LP_addressfind(coin,coinaddr)) == 0 || _LP_unspents_metric(ap->total,ap->n) != metric )
                    {
                        if ( ap == 0 || ap->n < (metric & 0xffff) )
                        {
                            if ( (retstr2= issue_LP_listunspent(peer->ipaddr,peer->port,coin->symbol,coinaddr)) != 0 )
                            {
                                if ( (array3= cJSON_Parse(retstr2)) != 0 )
                                {
                                    LP_unspents_array(coin,coinaddr,array3);
                                    //printf("pulled.(%s)\n",retstr2);
                                    free_json(array3);
                                }
                                free(retstr2);
                            }
                        } //else printf("wait for %s to pull %d vs %d\n",peer->ipaddr,ap!=0?ap->n:-1,(uint16_t)metric);
                    }
                }
            }
        }
        free_json(array2);
    }
    //printf("processed.(%s)\n",retstr);
    free(retstr);
}
/*if ( time(NULL) > coin->lastmonitor+60 )
 {
 //portable_mutex_lock(&coin->addrmutex);
 HASH_ITER(hh,coin->addresses,ap,atmp)
 {
 if ( coin->electrum == 0 )
 {
 LP_listunspent_issue(coin->symbol,ap->coinaddr);
 DL_FOREACH_SAFE(ap->utxos,up,utmp)
 {
 if ( up->spendheight <= 0 )
 {
 if ( LP_txvalue(0,coin->symbol,up->U.txid,up->U.vout) == 0 )
 up->spendheight = 1;
 }
 }
 }
 }
 //portable_mutex_unlock(&coin->addrmutex);
 coin->lastmonitor = (uint32_t)time(NULL);
 }*/

/*cJSON *LP_tradecandidates(char *base)
 {
 struct LP_peerinfo *peer,*tmp; struct LP_quoteinfo Q; char *utxostr,coinstr[16]; cJSON *array,*retarray=0,*item; int32_t i,n,totaladded,added;
 totaladded = 0;
 HASH_ITER(hh,LP_peerinfos,peer,tmp)
 {
 printf("%s:%u %s\n",peer->ipaddr,peer->port,base);
 n = added = 0;
 if ( (utxostr= issue_LP_clientgetutxos(peer->ipaddr,peer->port,base,100)) != 0 )
 {
 printf("%s:%u %s %s\n",peer->ipaddr,peer->port,base,utxostr);
 if ( (array= cJSON_Parse(utxostr)) != 0 )
 {
 if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
 {
 retarray = cJSON_CreateArray();
 for (i=0; i<n; i++)
 {
 item = jitem(array,i);
 LP_quoteparse(&Q,item);
 safecopy(coinstr,jstr(item,"base"),sizeof(coinstr));
 if ( strcmp(coinstr,base) == 0 )
 {
 if ( LP_iseligible(1,Q.srccoin,Q.txid,Q.vout,Q.satoshis,Q.txid2,Q.vout2) != 0 )
 {
 if ( LP_arrayfind(retarray,Q.txid,Q.vout) < 0 )
 {
 jaddi(retarray,jduplicate(item));
 added++;
 totaladded++;
 }
 } else printf("ineligible.(%s)\n",jprint(item,0));
 }
 }
 }
 free_json(array);
 }
 free(utxostr);
 }
 if ( n == totaladded && added == 0 )
 {
 printf("n.%d totaladded.%d vs added.%d\n",n,totaladded,added);
 break;
 }
 }
 return(retarray);
 }
 
 void LP_quotesinit(char *base,char *rel)
 {
 cJSON *array,*item; struct LP_quoteinfo Q; bits256 zero; int32_t i,n,iter;
 memset(&zero,0,sizeof(zero));
 for (iter=0; iter<2; iter++)
 if ( (array= LP_tradecandidates(iter == 0 ? base : rel)) != 0 )
 {
 //printf("candidates.(%s)\nn.%d\n",jprint(array,0),cJSON_GetArraySize(array));
 if ( (n= cJSON_GetArraySize(array)) > 0 )
 {
 memset(&Q,0,sizeof(Q));
 for (i=0; i<n; i++)
 {
 item = jitem(array,i);
 LP_quoteparse(&Q,item);
 if ( iter == 0 )
 LP_query("price",&Q,base,rel,zero);
 else LP_query("price",&Q,rel,base,zero);
 }
 }
 free_json(array);
 }
 }*/

/*else if ( LP_ismine(utxo) > 0 )
 {
 printf("iterate through all locally generated quotes and update, or change to price feed\n");
 // jl777: iterated Q's
 if ( strcmp(utxo->coin,"KMD") == 0 )
 LP_priceping(pubsock,utxo,"BTC",profitmargin);
 else LP_priceping(pubsock,utxo,"KMD",profitmargin);
 }*/
/*if ( LP_txvalue(destaddr,symbol,searchtxid,searchvout) > 0 )
 return(0);
 if ( (txobj= LP_gettx(symbol,searchtxid)) == 0 )
 return(0);
 hash = jbits256(txobj,"blockhash");
 free_json(txobj);
 if ( bits256_nonz(hash) == 0 )
 return(0);
 if ( (blockjson= LP_getblock(symbol,hash)) == 0 )
 return(0);
 loadheight = jint(blockjson,"height");
 free_json(blockjson);
 if ( loadheight <= 0 )
 return(0);
 while ( errs == 0 && *indp < 0 )
 {
 //printf("search %s ht.%d\n",symbol,loadheight);
 if ( (blockjson= LP_blockjson(&h,symbol,0,loadheight)) != 0 && h == loadheight )
 {
 if ( (txids= jarray(&numtxids,blockjson,"tx")) != 0 )
 {
 for (i=0; i<numtxids; i++)
 {
 txid = jbits256(jitem(txids,i),0);
 if ( (j= LP_vinscan(spendtxidp,indp,symbol,txid,searchtxid,searchvout,searchtxid,searchvout)) >= 0 )
 break;
 }
 }
 free_json(blockjson);
 } else errs++;
 loadheight++;
 }
 char str[65]; printf("reached %s ht.%d %s/v%d\n",symbol,loadheight,bits256_str(str,*spendtxidp),*indp);
 if ( bits256_nonz(*spendtxidp) != 0 && *indp >= 0 )
 return(loadheight);
 else return(0);*/

/*if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
 {
 for (i=0; i<n; i++)
 {
 mempooltxid = jbits256i(array,i);
 if ( (selector= LP_vinscan(spendtxidp,spendvinp,symbol,mempooltxid,searchtxid,searchvout,searchtxid2,searchvout2)) >= 0 )
 return(selector);
 }
 }*/

/*int32_t LP_orderbookfind(struct LP_orderbookentry **array,int32_t num,bits256 txid,int32_t vout)
 {
 int32_t i;
 for (i=0; i<num; i++)
 if ( (array[i]->vout == vout && bits256_cmp(array[i]->txid,txid) == 0) || (array[i]->vout2 == vout && bits256_cmp(array[i]->txid2,txid) == 0) )
 return(i);
 return(-1);
 }*/
//char str[65],str2[65]; printf("check utxo.%s/v%d from %s\n",bits256_str(str,utxo->payment.txid),utxo->payment.vout,bits256_str(str2,utxo->pubkey));
//if ( strcmp(base,utxo->coin) == 0 && LP_isavailable(utxo) > 0 && pubp != 0 && (price= pubp->matrix[baseid][relid]) > SMALLVAL )
//if ( polarity > 0 )
//    minsatoshis = utxo->S.satoshis;
//else minsatoshis = utxo->S.satoshis * price;
/*if ( LP_orderbookfind(*arrayp,cachednum,utxo->payment.txid,utxo->payment.vout) < 0 )
 {
 if ( LP_iseligible(&val,&val2,utxo->iambob,utxo->coin,utxo->payment.txid,utxo->payment.vout,utxo->S.satoshis,utxo->deposit.txid,utxo->deposit.vout) == 0 )
 continue;
 if ( polarity > 0 )
 basesatoshis = utxo->S.satoshis;
 else basesatoshis = utxo->S.satoshis * price;
 //char str[65]; printf("found utxo not in orderbook %s/v%d %.8f %.8f\n",bits256_str(str,utxo->payment.txid),utxo->payment.vout,dstr(basesatoshis),polarity > 0 ? price : 1./price);
 if ( (op= LP_orderbookentry(base,rel,utxo->payment.txid,utxo->payment.vout,utxo->deposit.txid,utxo->deposit.vout,polarity > 0 ? price : 1./price,basesatoshis,utxo->pubkey,now - pubp->timestamp)) != 0 )
 {
 *arrayp = realloc(*arrayp,sizeof(*(*arrayp)) * (num+1));
 (*arrayp)[num++] = op;
 if ( LP_ismine(utxo) > 0 && utxo->T.lasttime == 0 )
 LP_utxo_clientpublish(utxo);
 }
 }*/
void LP_price_broadcastloop(void *ctx)
{
    struct LP_priceinfo *basepp,*relpp; double price; int32_t baseind,relind;
    sleep(30);
    while ( 1 )
    {
        for (baseind=0; baseind<LP_MAXPRICEINFOS; baseind++)
        {
            basepp = LP_priceinfo(baseind);
            if ( basepp->symbol[0] == 0 )
                continue;
            for (relind=0; relind<LP_MAXPRICEINFOS; relind++)
            {
                relpp = LP_priceinfo(relind);
                if ( relpp->symbol[0] == 0 )
                    continue;
                if ( basepp != 0 && relpp != 0 && (price= relpp->myprices[basepp->ind]) > SMALLVAL)
                {
                    //printf("automated price broadcast %s/%s %.8f\n",relpp->symbol,basepp->symbol,price);
                    LP_pricepings(ctx,LP_myipaddr,LP_mypubsock,relpp->symbol,basepp->symbol,price);
                }
            }
        }
        sleep(LP_ORDERBOOK_DURATION * .9);
    }
}
//else if ( strcmp(method,"checktxid") == 0 )
//    retstr = LP_spentcheck(argjson);
//else if ( IAMLP == 0 && LP_isdisabled(base,rel) != 0 )
//    return(clonestr("{\"result\":\"at least one of coins disabled\"}"));
//else if ( IAMLP == 0 && LP_isdisabled(jstr(argjson,"coin"),0) != 0 )
//    retstr = clonestr("{\"result\":\"coin is disabled\"}");
/*if ( strcmp(method,"broadcast") == 0 )
 {
 bits256 zero; char *cipherstr; int32_t cipherlen; uint8_t cipher[LP_ENCRYPTED_MAXSIZE];
 if ( (reqjson= LP_dereference(argjson,"broadcast")) != 0 )
 {
 Broadcaststr = jprint(reqjson,0);
 if ( (cipherstr= jstr(reqjson,"cipher")) != 0 )
 {
 cipherlen = (int32_t)strlen(cipherstr) >> 1;
 if ( cipherlen <= sizeof(cipher) )
 {
 decode_hex(cipher,cipherlen,cipherstr);
 LP_queuesend(calc_crc32(0,&cipher[2],cipherlen-2),LP_mypubsock,base,rel,cipher,cipherlen);
 } else retstr = clonestr("{\"error\":\"cipher too big\"}");
 }
 else
 {
 memset(zero.bytes,0,sizeof(zero));
 //printf("broadcast.(%s)\n",Broadcaststr);
 LP_reserved_msg(base!=0?base:jstr(argjson,"coin"),rel,zero,jprint(reqjson,0));
 }
 retstr = clonestr("{\"result\":\"success\"}");
 } else retstr = clonestr("{\"error\":\"couldnt dereference sendmessage\"}");
 }
 else*/

/*relvol = bot->totalrelvolume * .1;
 p = LP_pricevol_invert(&v,bot->maxprice,relvol);
 if ( bot->dispdir > 0 )
 {
 printf("simulated trade buy %s/%s maxprice %.8f volume %.8f, %.8f %s -> %s, price %.8f relvol %.8f\n",bot->base,bot->rel,bot->maxprice,bot->totalrelvolume - bot->relsum,relvol,bot->rel,bot->base,bot->maxprice,relvol);
 }
 else
 {
 minprice = LP_pricevol_invert(&basevol,bot->maxprice,bot->totalrelvolume - bot->relsum);
 printf("simulated trade sell %s/%s minprice %.8f volume %.8f, %.8f %s -> %s price %.8f relvol %.8f\n",bot->rel,bot->base,minprice,basevol,v,bot->base,bot->rel,p,relvol);
 }
 if ( (rand() % 2) == 0 )
 {
 bot->relsum += relvol;
 bot->basesum += v;
 bot->completed++;
 }
 else
 {
 bot->pendrelsum += relvol;
 bot->pendbasesum += v;
 bot->numpending++;
 }
 bot->numtrades++;
 */
#ifdef FROM_JS
int32_t sentbytes,sock,peerind,maxind;
if ( (maxind= LP_numpeers()) > 0 )
peerind = (rand() % maxind) + 1;
else peerind = 1;
sock = LP_peerindsock(&peerind);
if ( sock >= 0 )
{
    if ( (sentbytes= nn_send(sock,msg,msglen,0)) != msglen )
        printf("LP_send sent %d instead of %d\n",sentbytes,msglen);
        else printf("sent %d bytes of %d to sock.%d\n",sentbytes,msglen,sock);
            } else printf("couldnt get valid sock\n");
#else

void _LP_queuesend(uint32_t crc32,int32_t sock0,int32_t sock1,uint8_t *msg,int32_t msglen,int32_t needack)
{
    int32_t maxind,peerind = 0; //sentbytes,
    if ( sock0 >= 0 || sock1 >= 0 )
    {
        /*        if ( sock0 >= 0 && LP_sockcheck(sock0) > 0 )
         {
         if ( (sentbytes= nn_send(sock0,msg,msglen,0)) != msglen )
         printf("_LP_queuesend0 sent %d instead of %d\n",sentbytes,msglen);
         else
         {
         printf("Q sent %u msglen.%d (%s)\n",crc32,msglen,msg);
         sock0 = -1;
         }
         }
         if ( sock1 >= 0 && LP_sockcheck(sock1) > 0 )
         {
         if ( (sentbytes= nn_send(sock1,msg,msglen,0)) != msglen )
         printf("_LP_queuesend1 sent %d instead of %d\n",sentbytes,msglen);
         else
         {
         printf("Q sent1 %u msglen.%d (%s)\n",crc32,msglen,msg);
         sock1 = -1;
         }
         }
         if ( sock0 < 0 && sock1 < 0 )
         return;*/
    }
    else
    {
        if ( (maxind= LP_numpeers()) > 0 )
            peerind = (rand() % maxind) + 1;
        else peerind = 1;
        sock0 = LP_peerindsock(&peerind);
        if ( (maxind= LP_numpeers()) > 0 )
            peerind = (rand() % maxind) + 1;
        else peerind = 1;
        sock1 = LP_peerindsock(&peerind);
    }
    if ( sock0 >= 0 )
        _LP_sendqueueadd(crc32,sock0,msg,msglen,needack * peerind);
    if ( sock1 >= 0 )
        _LP_sendqueueadd(crc32,sock1,msg,msglen,needack);
}

if ( 0 && OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_price_broadcastloop,(void *)ctx) != 0 )
{
    printf("error launching LP_swapsloop for port.%u\n",myport);
    exit(-1);
}
void LP_queuesend(uint32_t crc32,int32_t pubsock,char *base,char *rel,uint8_t *msg,int32_t msglen)
{
    //struct iguana_info *coin; int32_t flag=0,socks[2];
    portable_mutex_lock(&LP_networkmutex);
    if ( pubsock >= 0 )
    {
        //socks[0] = socks[1] = -1;
        //if ( rel != 0 && rel[0] != 0 && (coin= LP_coinfind(rel)) != 0 && coin->bussock >= 0 )
        //    socks[flag++] = coin->bussock;
        //if ( base != 0 && base[0] != 0 && (coin= LP_coinfind(base)) != 0 && coin->bussock >= 0 )
        //    socks[flag++] = coin->bussock;
        //if ( flag == 0 && pubsock >= 0 )
        _LP_queuesend(crc32,pubsock,-1,msg,msglen,0);
        //else _LP_queuesend(socks[0],socks[1],msg,msglen,0);
    } else _LP_queuesend(crc32,-1,-1,msg,msglen,1);
    portable_mutex_unlock(&LP_networkmutex);
}
#ifdef oldway
struct LP_utxoinfo *LP_bestutxo(double *ordermatchpricep,int64_t *bestsatoshisp,int64_t *bestdestsatoshisp,struct LP_utxoinfo *autxo,char *base,double maxprice,int32_t duration,uint64_t txfee,uint64_t desttxfee,uint64_t maxdestsatoshis)
{
    int64_t satoshis,destsatoshis; uint64_t val,val2; bits256 txid,pubkey; char *obookstr; cJSON *orderbook,*asks,*item; struct LP_utxoinfo *butxo,*bestutxo = 0; int32_t i,n,j,vout,numasks; double bestmetric=0.,metric,vol,price,qprice,bestprice = 0.; struct LP_pubkeyinfo *pubp;
    *ordermatchpricep = 0.;
    *bestsatoshisp = *bestdestsatoshisp = 0;
    if ( duration <= 0 )
        duration = LP_ORDERBOOK_DURATION;
    if ( maxprice <= 0. || LP_priceinfofind(base) == 0 )
        return(0);
    LP_txfees(&txfee,&desttxfee,base,autxo->coin);
    if ( (obookstr= LP_orderbook(base,autxo->coin,duration)) != 0 )
    {
        if ( (orderbook= cJSON_Parse(obookstr)) != 0 )
        {
            if ( (asks= jarray(&numasks,orderbook,"asks")) != 0 )
            {
                for (i=0; i<numasks; i++)
                {
                    item = jitem(asks,i);
                    price = jdouble(item,"price");
                    if ( LP_pricevalid(price) > 0 && price <= maxprice )
                    {
                        //price *= 1.0001;
                        //if ( price > maxprice )
                        //    price = maxprice;
                        pubkey = jbits256(item,"pubkey");
                        if ( bits256_cmp(pubkey,LP_mypub25519) != 0 && (pubp= LP_pubkeyadd(pubkey)) != 0 && pubp->numerrors < LP_MAXPUBKEY_ERRORS )
                        {
                            if ( bestprice == 0. ) // assumes price ordered asks
                                bestprice = price;
                            printf("item.[%d] %s\n",i,jprint(item,0));
                            txid = jbits256(item,"txid");
                            vout = jint(item,"vout");
                            vol = jdouble(item,"volume");
                            metric = price / bestprice;
                            printf("maxdest %.8f metric %f vol %f add pings numutxos.%d min %.8f max %.8f\n",dstr(maxdestsatoshis),metric,vol,jint(item,"numutxos"),jdouble(item,"minvolume"),jdouble(item,"maxvolume"));
                            // check utxos > 1 for pubkey, SPV validate recv'ed
                            /*if ( (butxo= LP_utxofind(1,txid,vout)) != 0 && (long long)(vol*SATOSHIDEN) == butxo->S.satoshis && LP_isavailable(butxo) > 0 && LP_ismine(butxo) == 0 && butxo->T.bestflag == 0 )
                             {
                             printf("got butxo? %p\n",butxo);
                             if ( LP_iseligible(&val,&val2,butxo->iambob,butxo->coin,butxo->payment.txid,butxo->payment.vout,butxo->S.satoshis,butxo->deposit.txid,butxo->deposit.vout) > 0 )
                             {
                             destsatoshis = ((butxo->S.satoshis - txfee) * price);
                             satoshis = (destsatoshis / price + 0.49) - txfee;
                             if ( satoshis <= 0 )
                             continue;
                             qprice = (double)destsatoshis / satoshis;
                             n = (int32_t)((double)destsatoshis / desttxfee);
                             if ( n < 10 )
                             n = 10;
                             else n = 3;
                             for (j=0; j<n; j++)
                             {
                             if ( (qprice= LP_qprice_calc(&destsatoshis,&satoshis,(price*(100.+j))/100.,butxo->S.satoshis,txfee,autxo->payment.value,maxdestsatoshis,desttxfee)) > price+SMALLVAL )
                             break;
                             }
                             //printf("j.%d/%d qprice %.8f vs price %.8f best.(%.8f %.8f)\n",j,n,qprice,price,dstr(satoshis),dstr(destsatoshis));
                             if ( metric < 1.2 && destsatoshis > desttxfee && destsatoshis-desttxfee > (autxo->payment.value / LP_MINCLIENTVOL) && satoshis-txfee > (butxo->S.satoshis / LP_MINVOL) && satoshis <= butxo->payment.value-txfee )
                             {
                             printf("value %.8f price %.8f/%.8f best %.8f destsatoshis %.8f * metric %.8f -> (%f)\n",dstr(autxo->payment.value),price,bestprice,bestmetric,dstr(destsatoshis),metric,dstr(destsatoshis) * metric * metric * metric);
                             metric = dstr(destsatoshis) * metric * metric * metric;
                             if ( bestmetric == 0. || metric < bestmetric )
                             {
                             bestutxo = butxo;
                             *ordermatchpricep = price;
                             *bestdestsatoshisp = destsatoshis;
                             *bestsatoshisp = satoshis;
                             bestmetric = metric;
                             printf("set best!\n");
                             }
                             } // else printf("skip.(%d %d %d %d %d) metric %f destsatoshis %.8f value %.8f destvalue %.8f txfees %.8f %.8f sats %.8f\n",metric < 1.2,destsatoshis > desttxfee,destsatoshis-desttxfee > (autxo->payment.value / LP_MINCLIENTVOL),satoshis-txfee > (butxo->S.satoshis / LP_MINVOL),satoshis < butxo->payment.value-txfee,metric,dstr(destsatoshis),dstr(butxo->S.satoshis),dstr(autxo->payment.value),dstr(txfee),dstr(desttxfee),dstr(satoshis));
                             }
                             else
                             {
                             printf("ineligible.(%.8f %.8f)\n",price,dstr(butxo->S.satoshis));
                             //if ( butxo->T.spentflag == 0 )
                             //    butxo->T.spentflag = (uint32_t)time(NULL);
                             }
                             }
                             else
                             {
                             if ( butxo != 0 )
                             printf("%llu %llu %d %d %d: ",(long long)(vol*SATOSHIDEN),(long long)butxo->S.satoshis,vol*SATOSHIDEN == butxo->S.satoshis,LP_isavailable(butxo) > 0,LP_ismine(butxo) == 0);
                             printf("cant find butxo.%p or value mismatch %.8f != %.8f or bestflag.%d\n",butxo,vol,butxo!=0?dstr(butxo->S.satoshis):0,butxo->T.bestflag);
                             }*/
                        } else printf("self trading or blacklisted peer\n");
                    }
                    else
                    {
                        if ( i == 0 )
                            printf("maxprice %.8f vs %.8f\n",maxprice,price);
                        break;
                    }
                }
                if ( bestutxo == 0 )
                {
                    int32_t numrestraints;
                    for (i=numrestraints=0; i<numasks; i++)
                    {
                        item = jitem(asks,i);
                        pubkey = jbits256(item,"pubkey");
                        if ( bits256_cmp(pubkey,LP_mypub25519) != 0 && (pubp= LP_pubkeyadd(pubkey)) != 0 )
                        {
                            txid = jbits256(item,"txid");
                            vout = jint(item,"vout");
                            if ( (butxo= LP_utxofind(1,txid,vout)) != 0 )
                            {
                                numrestraints++;
                                butxo->T.bestflag = 0;
                                //pubp->numerrors = 0;
                            }
                        }
                    }
                    printf("no bob utxo found -> cleared %d restraints\n",numrestraints);
                }
            }
            free_json(orderbook);
        }
        free(obookstr);
    }
    printf("bestutxo.%p %.8f %.8f\n",bestutxo,*ordermatchpricep,dstr(*bestdestsatoshisp));
    if ( bestutxo == 0 || *ordermatchpricep == 0. || *bestdestsatoshisp == 0 )
        return(0);
    bestutxo->T.bestflag = 1;
    int32_t changed;
    LP_mypriceset(&changed,autxo->coin,base,1. / *ordermatchpricep);
    return(bestutxo);
}
if ( (0) )
{
    ep = LP_electrum_info(&already,"BTC","88.198.241.196",50001,IGUANA_MAXPACKETSIZE * 10);
    if ( ep != 0 && OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_dedicatedloop,(void *)ep) != 0 )
    {
        printf("error launching LP_dedicatedloop (%s:%u)\n",ep->ipaddr,ep->port);
        exit(-1);
    } else printf("launched.(%s:%u)\n",ep->ipaddr,ep->port);
        electrum_test();
        }

/*static int _LP_metric_eval(const void *a,const void *b)
 {
 #define aptr (*(struct LP_metricinfo **)a)
 #define bptr (*(struct LP_metricinfo **)b)
 if ( bptr->metric > aptr->metric )
 return(1);
 else if ( bptr->metric < aptr->metric )
 return(-1);
 return(0);
 #undef aptr
 #undef bptr
 }*/

/*portable_mutex_lock(&ep->pendingQ.mutex);
 if ( ep->pendingQ.list != 0 )
 {
 printf("list %p\n",ep->pendingQ.list);
 DL_FOREACH_SAFE(ep->pendingQ.list,item,tmp)
 {
 printf("item.%p\n",item);
 if ( item->type == 0xffffffff )
 {
 printf("%p purge %s",item,((struct stritem *)item)->str);
 DL_DELETE(ep->pendingQ.list,item);
 free(item);
 }
 }
 }
 DL_APPEND(ep->pendingQ.list,&sitem->DL);
 portable_mutex_unlock(&ep->pendingQ.mutex);*/
//printf("%p SENT.(%s) to %s:%u\n",sitem,sitem->str,ep->ipaddr,ep->port);

char *LP_ordermatch(char *base,int64_t txfee,double maxprice,double maxvolume,char *rel,bits256 txid,int32_t vout,bits256 feetxid,int32_t feevout,int64_t desttxfee,int32_t duration)
{
    struct LP_quoteinfo Q; int64_t bestsatoshis=0,bestdestsatoshis = 0; double ordermatchprice = 0.; struct LP_utxoinfo *autxo,*bestutxo;
    txfee = LP_txfeecalc(LP_coinfind(base),txfee);
    desttxfee = LP_txfeecalc(LP_coinfind(rel),desttxfee);
    if ( (autxo= LP_utxopairfind(0,txid,vout,feetxid,feevout)) == 0 )
        return(clonestr("{\"error\":\"cant find alice utxopair\"}"));
    if ( (bestutxo= LP_bestutxo(&ordermatchprice,&bestsatoshis,&bestdestsatoshis,autxo,base,maxprice,duration,txfee,desttxfee,SATOSHIDEN*maxvolume)) == 0 || ordermatchprice == 0. || bestdestsatoshis == 0 )
        return(clonestr("{\"error\":\"cant find ordermatch utxo\"}"));
    if ( LP_quoteinfoinit(&Q,bestutxo,rel,ordermatchprice,bestsatoshis,bestdestsatoshis) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote\"}"));
    if ( LP_quotedestinfo(&Q,autxo->payment.txid,autxo->payment.vout,autxo->fee.txid,autxo->fee.vout,LP_mypub25519,autxo->coinaddr) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote info\"}"));
    return(jprint(LP_quotejson(&Q),1));
}

char *LP_autotrade(void *ctx,char *myipaddr,int32_t mypubsock,char *base,char *rel,double maxprice,double relvolume,int32_t timeout,int32_t duration)
{
    uint64_t desttxfee,txfee; int64_t bestsatoshis=0,bestdestsatoshis=0; struct LP_utxoinfo *autxo,*butxo,*bestutxo = 0; double qprice,ordermatchprice=0.; struct LP_quoteinfo Q;
    if ( duration <= 0 )
        duration = LP_ORDERBOOK_DURATION;
    if ( timeout <= 0 )
        timeout = LP_AUTOTRADE_TIMEOUT;
    if ( maxprice <= 0. || relvolume <= 0. || LP_priceinfofind(base) == 0 || LP_priceinfofind(rel) == 0 )
        return(clonestr("{\"error\":\"invalid parameter\"}"));
    if ( (autxo= LP_utxo_bestfit(rel,SATOSHIDEN * relvolume)) == 0 )
        return(clonestr("{\"error\":\"cant find utxo that is big enough\"}"));
    LP_txfees(&txfee,&desttxfee,base,rel);
    if ( (bestutxo= LP_bestutxo(&ordermatchprice,&bestsatoshis,&bestdestsatoshis,autxo,base,maxprice,duration,txfee,desttxfee,SATOSHIDEN*relvolume)) == 0 || ordermatchprice == 0. || bestdestsatoshis == 0 )
    {
        printf("bestutxo.%p ordermatchprice %.8f bestdestsatoshis %.8f\n",bestutxo,ordermatchprice,dstr(bestdestsatoshis));
        return(clonestr("{\"error\":\"cant find ordermatch utxo\"}"));
    }
    if ( LP_quoteinfoinit(&Q,bestutxo,rel,ordermatchprice,bestsatoshis,bestdestsatoshis) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote\"}"));
    if ( LP_quotedestinfo(&Q,autxo->payment.txid,autxo->payment.vout,autxo->fee.txid,autxo->fee.vout,LP_mypub25519,autxo->coinaddr) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote info\"}"));
    if ( (qprice= LP_quote_validate(&autxo,&butxo,&Q,0)) <= SMALLVAL )
    {
        printf("quote validate error %.0f\n",qprice);
        return(clonestr("{\"error\":\"quote validation error\"}"));
    }
    printf("do quote.(%s)\n",jprint(LP_quotejson(&Q),1));
    return(LP_trade(ctx,myipaddr,mypubsock,&Q,maxprice,timeout,duration));
}
#endif


