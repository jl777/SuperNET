
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
#endif


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
    //bitcoin_address(coinaddr,rawtx->coin->chain->pubtype,myinfo->persistent_pubkey33,33);
    if ( rawtx->coin->changeaddr[0] == 0 )
    {
        bitcoin_address(rawtx->coin->changeaddr,rawtx->coin->pubtype,pubkey33,33);
        printf("set change address.(%s)\n",rawtx->coin->changeaddr);
    }
    init_hexbytes_noT(scriptstr,script,scriptlen);
    basilisktag = (uint32_t)rand();
    valsobj = cJSON_CreateObject();
    jaddstr(valsobj,"coin",rawtx->coin->symbol);
    jaddstr(valsobj,"spendscript",scriptstr);
    jaddstr(valsobj,"changeaddr",rawtx->coin->changeaddr);
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
                if ( (swap->I.aliceconfirms == 0 && swap->aliceunconf != 0) || LP_numconfirms(swap,&swap->alicepayment) >= swap->I.aliceconfirms )
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
                        if ( LP_numconfirms(swap,&swap->bobspend) >= swap->I.aliceconfirms )
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
                        if ( LP_numconfirms(swap,&swap->bobreclaim) >= 1 )
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
                if ( basilisk_istrustedbob(swap) != 0 || (swap->I.bobconfirms == 0 && swap->depositunconf != 0) || LP_numconfirms(swap,&swap->bobdeposit) >= swap->I.bobconfirms )
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
                if ( basilisk_istrustedbob(swap) != 0 || (swap->I.bobconfirms == 0 && swap->paymentunconf != 0) || LP_numconfirms(swap,&swap->bobpayment) >= swap->I.bobconfirms )
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
                if ( (numconfs= LP_numconfirms(swap,&swap->alicespend)) >= swap->I.bobconfirms )
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
    //printf("%s persistent.(%s) (%s) change.(%s) scriptstr.(%s)\n",coin->symbol,myinfo->myaddr.BTC,coinaddr,coin->changeaddr,scriptstr);
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
