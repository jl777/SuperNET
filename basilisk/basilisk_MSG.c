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

cJSON *basilisk_msgjson(struct basilisk_message *msg,uint8_t *key,int32_t keylen)
{
    cJSON *msgjson=0; char *str = 0,strbuf[32768],keystr[BASILISK_KEYSIZE*2+1];
    msgjson = cJSON_CreateObject();
    if ( basilisk_addhexstr(&str,msgjson,strbuf,sizeof(strbuf),msg->data,msg->datalen) != 0 )
    {
        init_hexbytes_noT(keystr,key,keylen);
        jaddstr(msgjson,"key",keystr);
        jaddnum(msgjson,"expiration",msg->expiration);
        jaddnum(msgjson,"duration",msg->duration);
        if ( str != 0 )
            free(str);
    }
    else
    {
        printf("basilisk_respond_getmessage: couldnt basilisk_addhexstr data.[%d]\n",msg->datalen);
        free_json(msgjson);
        msgjson = 0;
    }
    return(msgjson);
}

cJSON *_basilisk_respond_getmessage(struct supernet_info *myinfo,uint8_t *key,int32_t keylen)
{
    cJSON *msgjson = 0; struct basilisk_message *msg;
    HASH_FIND(hh,myinfo->messagetable,key,keylen,msg);
    if ( msg != 0 && msg->broadcast == 0 )
        msgjson = basilisk_msgjson(msg,key,keylen);
    return(msgjson);
}

int32_t basilisk_msgcmp(struct basilisk_message *msg,int32_t width,uint32_t channel,uint32_t msgid,bits256 srchash,bits256 desthash)
{
    uint32_t keychannel,keymsgid,n=0; bits256 keysrc,keydest;
    basilisk_messagekeyread(msg->key,&keychannel,&keymsgid,&keysrc,&keydest);
    if ( bits256_nonz(srchash) == 0 || bits256_cmp(srchash,keysrc) == 0 )
    {
        if ( bits256_nonz(desthash) == 0 || bits256_cmp(desthash,keydest) == 0 )
        {
            while ( width >= 0 && n < 60 )
            {
                if ( msgid == keymsgid && keychannel == channel )
                    return(0);
                msgid--;
                n++;
            }
            return(-1);
        } else return(-2);
    } else return(-3);
}

char *basilisk_iterate_MSG(struct supernet_info *myinfo,uint32_t channel,uint32_t msgid,bits256 srchash,bits256 desthash,int32_t origwidth)
{
    uint8_t key[BASILISK_KEYSIZE]; int32_t i,keylen,width; cJSON *msgjson,*item,*retjson,*array; bits256 zero; struct basilisk_message *msg,*tmpmsg; uint32_t origmsgid,now = (uint32_t)time(NULL);
    origmsgid = msgid;
    memset(zero.bytes,0,sizeof(zero));
    if ( (width= origwidth) > 3600 )
        width = 3600;
    else if ( width < 1 )
        width = 1;
   // char str[65],str2[65]; printf("MSGiterate (%s) -> (%s)\n",bits256_str(str,srchash),bits256_str(str2,desthash));
    array = cJSON_CreateArray();
    portable_mutex_lock(&myinfo->messagemutex);
    //printf("iterate_MSG allflag.%d width.%d channel.%d msgid.%d src.%llx -> %llx\n",allflag,origwidth,channel,msgid,(long long)srchash.txid,(long long)desthash.txid);
    for (i=0; i<width; i++)
    {
        keylen = basilisk_messagekey(key,channel,msgid,srchash,desthash);
        if ( (item= _basilisk_respond_getmessage(myinfo,key,keylen)) != 0 )
            jaddi(array,item);//, printf("gotmsg0.(%s)\n",jprint(item,0));
        //keylen = basilisk_messagekey(key,channel,msgid,desthash,srchash);
        //if ( (item= _basilisk_respond_getmessage(myinfo,key,keylen)) != 0 )
        //    jaddi(array,item);//, printf("gotmsg0.(%s)\n",jprint(item,0));
        if ( origwidth > 0 )
        {
            if ( bits256_nonz(srchash) != 0 )
            {
                keylen = basilisk_messagekey(key,channel,msgid,zero,desthash);
                if ( (item= _basilisk_respond_getmessage(myinfo,key,keylen)) != 0 )
                    jaddi(array,item);//, printf("gotmsg1.(%s)\n",jprint(item,0));
                //keylen = basilisk_messagekey(key,channel,msgid,desthash,zero);
                //if ( (item= _basilisk_respond_getmessage(myinfo,key,keylen)) != 0 )
                //    jaddi(array,item);//, printf("gotmsg1.(%s)\n",jprint(item,0));
            }
            if ( bits256_nonz(desthash) != 0 )
            {
                keylen = basilisk_messagekey(key,channel,msgid,srchash,zero);
                if ( (item= _basilisk_respond_getmessage(myinfo,key,keylen)) != 0 )
                    jaddi(array,item);//, printf("gotmsg2.(%s)\n",jprint(item,0));
                //keylen = basilisk_messagekey(key,channel,msgid,zero,srchash);
                //if ( (item= _basilisk_respond_getmessage(myinfo,key,keylen)) != 0 )
                //    jaddi(array,item);//, printf("gotmsg2.(%s)\n",jprint(item,0));
            }
            if ( bits256_nonz(srchash) != 0 && bits256_nonz(desthash) != 0 )
            {
                keylen = basilisk_messagekey(key,channel,msgid,zero,zero);
                if ( (item= _basilisk_respond_getmessage(myinfo,key,keylen)) != 0 )
                    jaddi(array,item);//, printf("gotmsg3.(%s)\n",jprint(item,0));
            }
        }
        msgid--;
    }
    if ( bits256_nonz(srchash) == 0 )
    {
        HASH_ITER(hh,myinfo->messagetable,msg,tmpmsg)
        {
            if ( basilisk_msgcmp(msg,origwidth,channel,origmsgid,zero,zero) == 0 )
            {
                if ( (msgjson= basilisk_msgjson(msg,msg->key,msg->keylen)) != 0 )
                    jaddi(array,msgjson);
            }
        }
    }
    HASH_ITER(hh,myinfo->messagetable,msg,tmpmsg)
    {
        if ( now > msg->expiration+60 )
        {
            printf("delete expired message.%p QUEUEITEMS.%d\n",msg,QUEUEITEMS);
            HASH_DELETE(hh,myinfo->messagetable,msg);
            QUEUEITEMS--;
            free(msg);
        }
    }
    portable_mutex_unlock(&myinfo->messagemutex);
    if ( cJSON_GetArraySize(array) > 0 )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","success");
        jadd(retjson,"messages",array);
        //printf("MESSAGES.(%s)\n",jprint(array,0));
        return(jprint(retjson,1));
    }
    //printf("no matching messages\n");
    return(clonestr("{\"error\":\"no messages\"}"));
}

char *basilisk_respond_addmessage(struct supernet_info *myinfo,uint8_t *key,int32_t keylen,uint8_t *data,int32_t datalen,int32_t sendping,uint32_t duration)
{
    struct basilisk_message *msg; bits256 desthash;
    if ( keylen != BASILISK_KEYSIZE )
    {
        printf("basilisk_respond_addmessage keylen.%d != %d\n",keylen,BASILISK_KEYSIZE);
        return(0);
    }
    if ( duration == 0 )
        duration = BASILISK_MSGDURATION;
    else if ( duration > INSTANTDEX_LOCKTIME*2 )
        duration = INSTANTDEX_LOCKTIME*2;
    portable_mutex_lock(&myinfo->messagemutex);
    HASH_FIND(hh,myinfo->messagetable,key,keylen,msg);
    if ( msg != 0 )
    {
        if ( msg->datalen != datalen )
        {
            //printf("overwrite delete of msg.[%d]\n",msg->datalen);
            HASH_DELETE(hh,myinfo->messagetable,msg);
            QUEUEITEMS--;
            free(msg);
            msg = 0;
        }
        else
        {
            if ( memcmp(msg->data,data,datalen) != 0 )
            {
                //printf("overwrite update of msg.[%d] <- datalen.%d\n",msg->datalen,datalen);
                memcpy(msg->data,data,datalen);
                if ( sendping != 0 )
                    queue_enqueue("basilisk_message",&myinfo->msgQ,&msg->DL,0);
            }
            portable_mutex_unlock(&myinfo->messagemutex);
            return(clonestr("{\"result\":\"message updated\"}"));
        }
    }
    msg = calloc(1,sizeof(*msg) + datalen + 16);
    msg->keylen = keylen;
    memcpy(msg->key,key,keylen);
    msg->datalen = datalen;
    memcpy(msg->data,data,datalen);
    memcpy(desthash.bytes,&key[BASILISK_KEYSIZE - sizeof(desthash)],sizeof(desthash));
    if ( bits256_nonz(desthash) == 0 )
        msg->broadcast = 1;
    msg->duration = duration;
    msg->expiration = (uint32_t)time(NULL) + duration;
    HASH_ADD_KEYPTR(hh,myinfo->messagetable,msg->key,msg->keylen,msg);
    QUEUEITEMS++;
    //int32_t i; for (i=0; i<BASILISK_KEYSIZE; i++)
    //    printf("%02x",key[i]);
    //printf(" <- ADDMSG.[%d] exp %u %p (%p %p)\n",QUEUEITEMS,msg->expiration,msg,msg->hh.next,msg->hh.prev);
    portable_mutex_unlock(&myinfo->messagemutex);
    if ( sendping != 0 )
        queue_enqueue("basilisk_message",&myinfo->msgQ,&msg->DL,0);
    return(clonestr("{\"result\":\"message added to hashtable\"}"));
}

// respond to incoming OUT, MSG

char *basilisk_respond_OUT(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    int32_t keylen,duration; uint8_t key[BASILISK_KEYSIZE]; bits256 desthash,senderhash; char *retstr;
    senderhash = jbits256(valsobj,"srchash");
    desthash = jbits256(valsobj,"desthash");
    duration = juint(valsobj,"duration");
    keylen = basilisk_messagekey(key,juint(valsobj,"channel"),juint(valsobj,"msgid"),senderhash,desthash);
    if ( bits256_nonz(hash) == 0 )
    {
        if ( duration > BASILISK_MSGDURATION )
            duration = BASILISK_MSGDURATION;
    }
    //char str[65]; printf("add message.[%d] %s from.%s\n",datalen,bits256_str(str,hash),remoteaddr);
    retstr = basilisk_respond_addmessage(myinfo,key,keylen,data,datalen,0,duration);
    // printf("OUT keylen.%d datalen.%d\n",keylen,datalen);
    return(retstr);
}

char *basilisk_respond_MSG(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    int32_t width; uint32_t msgid,channel; char *retstr=0;
    if ( valsobj != 0 )
    {
        width = juint(valsobj,"width");
        msgid = juint(valsobj,"msgid");
        channel = juint(valsobj,"channel");
        //char str[65],str2[65]; printf("%s -> %s channel.%u msgid.%x width.%d from.%s\n",bits256_str(str,jbits256(valsobj,"sender")),bits256_str(str2,jbits256(valsobj,"desthash")),juint(valsobj,"channel"),msgid,width,remoteaddr);
        retstr = basilisk_iterate_MSG(myinfo,channel,msgid,jbits256(valsobj,"srchash"),jbits256(valsobj,"desthash"),width);
    }
    return(retstr);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

HASH_ARRAY_STRING(basilisk,getmessage,hash,vals,hexstr)
{
    uint32_t msgid,width,channel; char *retstr;
    if ( bits256_cmp(GENESIS_PUBKEY,jbits256(vals,"srchash")) == 0 )
        jaddbits256(vals,"srchash",hash);
    if ( bits256_cmp(GENESIS_PUBKEY,jbits256(vals,"desthash")) == 0 )
        jaddbits256(vals,"desthash",myinfo->myaddr.persistent);
    if ( (msgid= juint(vals,"msgid")) == 0 )
    {
        msgid = (uint32_t)time(NULL);
        jdelete(vals,"msgid");
        jaddnum(vals,"msgid",msgid);
    }
    if ( myinfo->NOTARY.RELAYID >= 0 )
    {
        channel = juint(vals,"channel");
        width = juint(vals,"width");
        retstr = basilisk_iterate_MSG(myinfo,channel,msgid,jbits256(vals,"srchash"),jbits256(vals,"desthash"),width);
        return(retstr);
    }
    //printf("getmessage not relay.%d\n",myinfo->NOTARY.RELAYID);
    return(basilisk_standardservice("MSG",myinfo,0,jbits256(vals,"desthash"),vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,sendmessage,hash,vals,hexstr)
{
    int32_t keylen,datalen; uint8_t key[BASILISK_KEYSIZE],space[16384],*data,*ptr = 0; char *retstr=0;
    if ( myinfo->IAMNOTARY != 0 && myinfo->NOTARY.RELAYID >= 0 )
    {
        keylen = basilisk_messagekey(key,juint(vals,"channel"),juint(vals,"msgid"),jbits256(vals,"srchash"),jbits256(vals,"desthash"));
        if ( (data= get_dataptr(BASILISK_HDROFFSET,&ptr,&datalen,space,sizeof(space),hexstr)) != 0 )
        {
            retstr = basilisk_respond_addmessage(myinfo,key,keylen,data,datalen,0,juint(vals,"duration"));
        } else printf("no get_dataptr\n");
        if ( ptr != 0 )
            free(ptr);
        if ( retstr != 0 )
            free(retstr);
    } else printf("not notary.%d relayid.%d\n",myinfo->IAMNOTARY,myinfo->NOTARY.RELAYID);
    if ( vals != 0 && juint(vals,"fanout") == 0 )
        jaddnum(vals,"fanout",MAX(8,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)+2));
    return(basilisk_standardservice("OUT",myinfo,0,jbits256(vals,"desthash"),vals,hexstr,0));
}
#include "../includes/iguana_apiundefs.h"

int32_t basilisk_channelsend(struct supernet_info *myinfo,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgid,uint8_t *data,int32_t datalen,uint32_t duration)
{
    char *retstr,*hexstr,strbuf[4096],*ptr = 0; int32_t retval = -1; cJSON *valsobj;
    if ( (hexstr= basilisk_addhexstr(&ptr,0,strbuf,sizeof(strbuf),data,datalen)) != 0 )
    {
        valsobj = cJSON_CreateObject();
        jaddnum(valsobj,"channel",channel);
        if ( msgid == 0 )
            msgid = (uint32_t)time(NULL);
        jaddnum(valsobj,"fanout",MAX(8,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)+2));
        jaddnum(valsobj,"msgid",msgid);
        jaddnum(valsobj,"duration",duration);
        jaddbits256(valsobj,"srchash",srchash);
        jaddbits256(valsobj,"desthash",desthash);
        //char str[65]; printf("sendmessage.[%d] channel.%u msgid.%x -> %s numrelays.%d\n",datalen,channel,msgid,bits256_str(str,desthash),myinfo->NOTARY.NUMRELAYS);
        if ( (retstr= basilisk_sendmessage(myinfo,0,0,0,desthash,valsobj,hexstr)) != 0 )
            free(retstr);
        free_json(valsobj);
        if ( ptr != 0 )
            free(ptr);
        retval = 0;
    } else printf("error adding hexstr datalen.%d\n",datalen);
    return(retval);
}

int32_t basilisk_message_returned(uint8_t *key,uint8_t *data,int32_t maxlen,cJSON *json)
{
    char *keystr=0,*hexstr=0; int32_t i,n,datalen=0,retval = -1; cJSON *item,*msgobj;
    if ( (msgobj= jarray(&n,json,"messages")) != 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(msgobj,i);
            if ( (keystr= jstr(item,"key")) != 0 && is_hexstr(keystr,0) == BASILISK_KEYSIZE*2 && (hexstr= jstr(item,"data")) != 0 && (datalen= is_hexstr(hexstr,0)) > 0 )
            {
                decode_hex(key,BASILISK_KEYSIZE,keystr);
                datalen >>= 1;
                if ( datalen <= maxlen )
                {
                    decode_hex(data,datalen,hexstr);
                    //printf("decoded hexstr.[%d]\n",datalen);
                    retval = datalen;
                } else printf("datalen.%d >= maxlen.%d\n",datalen,maxlen);
            }
        }
    } //else printf("no hexstr.%p or datalen.%d (%s)\n",hexstr,datalen,jprint(json,0));
    return(retval);
}

cJSON *basilisk_channelget(struct supernet_info *myinfo,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgid,int32_t width)
{
    char *retstr; cJSON *valsobj,*retarray=0,*item;
    valsobj = cJSON_CreateObject();
    jaddnum(valsobj,"channel",channel);
    if ( msgid == 0 )
        msgid = (uint32_t)time(NULL);
    jaddnum(valsobj,"msgid",msgid);
    jaddnum(valsobj,"width",width);
    jaddnum(valsobj,"timeout",BASILISK_TIMEOUT);
    jaddnum(valsobj,"fanout",MAX(8,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)+1));
    jaddnum(valsobj,"numrequired",1);
    jaddbits256(valsobj,"srchash",srchash);
    jaddbits256(valsobj,"desthash",desthash);
    if ( (retstr= basilisk_getmessage(myinfo,0,0,0,desthash,valsobj,0)) != 0 )
    {
        //printf("channel.%u msgid.%u gotmessage.(%d)\n",channel,msgid,(int32_t)strlen(retstr));
        if ( (retarray= cJSON_Parse(retstr)) != 0 )
        {
            if ( is_cJSON_Array(retarray) == 0 )
            {
                item = cJSON_CreateArray();
                jaddi(item,retarray);
                retarray = item;
            }
        }
        free(retstr);
    }
    free_json(valsobj);
    return(retarray);
}

int32_t basilisk_process_retarray(struct supernet_info *myinfo,void *ptr,int32_t (*process_func)(struct supernet_info *myinfo,void *ptr,int32_t (*internal_func)(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen),uint32_t channel,uint32_t msgid,uint8_t *data,int32_t datalen,uint32_t expiration,uint32_t duration),uint8_t *data,int32_t maxlen,uint32_t channel,uint32_t msgid,cJSON *retarray,int32_t (*internal_func)(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen))
{
    cJSON *item; uint32_t duration,expiration; char *retstr; uint8_t key[BASILISK_KEYSIZE]; int32_t i,n,datalen,havedata = 0,errs = 0;
    if ( (n= cJSON_GetArraySize(retarray)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(retarray,i);
            if ( jobj(item,"error") != 0 )
                continue;
            //printf("(%s).%d ",jprint(item,0),i);
            if ( (datalen= basilisk_message_returned(key,data,maxlen,item)) > 0 )
            {
                duration = juint(item,"duration");
                expiration = juint(item,"expiration");
                if ( (retstr= basilisk_respond_addmessage(myinfo,key,BASILISK_KEYSIZE,data,datalen,0,duration)) != 0 )
                {
                     if ( (*process_func)(myinfo,ptr,internal_func,channel,msgid,data,datalen,expiration,duration) < 0 )
                        errs++;
                     else havedata++;
                     free(retstr);
                } // else printf("duplicate.%d skipped\n",datalen);
            }
        }
        //printf("n.%d maxlen.%d\n",n,maxlen);
    }
    if ( havedata == 0 )
        return(-1);
    else if ( errs > 0 )
        return(-errs);
    else return(havedata);
}
