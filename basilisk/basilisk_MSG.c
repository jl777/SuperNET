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

char *basilisk_respond_sendmessage(struct supernet_info *myinfo,uint8_t *key,int32_t keylen,uint8_t *data,int32_t datalen,int32_t sendping)
{
    struct basilisk_message *msg;
    if ( keylen == sizeof(bits256)+sizeof(uint32_t)*2 )
    {
        msg = calloc(1,sizeof(*msg) + datalen);
        msg->expiration = (uint32_t)time(NULL) + INSTANTDEX_LOCKTIME*2;
        msg->keylen = keylen;
        memcpy(msg->key,key,keylen);
        msg->datalen = datalen;
        memcpy(msg->data,data,datalen);
        portable_mutex_lock(&myinfo->messagemutex);
        HASH_ADD_KEYPTR(hh,myinfo->messagetable,msg->key,msg->keylen,msg);
        portable_mutex_unlock(&myinfo->messagemutex);
        if ( sendping != 0 )
        {
            queue_enqueue("basilisk_message",&myinfo->msgQ,&msg->DL,0);
            return(clonestr("{\"result\":\"message added to hashtable\"}"));
        } else return(0);
    } else return(0);
}

int32_t basilisk_ping_processMSG(struct supernet_info *myinfo,uint32_t senderipbits,uint8_t *data,int32_t datalen)
{
    int32_t i,msglen,len=0; uint8_t num,keylen,*msg,*key;
    if ( (num= data[len++]) > 0 )
    {
        printf("processMSG num.%d datalen.%d\n",num,datalen);
        for (i=0; i<num; i++)
        {
            keylen = data[len++];
            if ( keylen != sizeof(bits256)+sizeof(uint32_t)*2 )
                return(0);
            key = &data[len], len += keylen;
            if ( len+sizeof(msglen) > datalen )
                return(0);
            len += iguana_rwnum(0,&data[len],sizeof(msglen),&msglen);
            msg = &data[len], len += msglen;
            if ( msglen <= 0 || len > datalen )
                return(0);
            printf("i.%d: keylen.%d msglen.%d\n",i,keylen,msglen);
            basilisk_respond_sendmessage(myinfo,key,keylen,msg,msglen,0);
        }
    }
    return(len);
}

int32_t basilisk_ping_genMSG(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen)
{
    struct basilisk_message *msg; int32_t datalen = 0;
    if ( maxlen > sizeof(msg->key) && (msg= queue_dequeue(&myinfo->msgQ,0)) != 0 ) // oneshot ping
    {
        data[datalen++] = 1;
        data[datalen++] = msg->keylen;
        memcpy(&data[datalen],msg->key,msg->keylen), datalen += msg->keylen;
        datalen += iguana_rwnum(1,&data[datalen],sizeof(msg->datalen),&msg->datalen);
        if ( maxlen > datalen+msg->datalen )
        {
            printf("SEND keylen.%d msglen.%d\n",msg->keylen,msg->datalen);
            memcpy(&data[datalen],msg->data,msg->datalen), datalen += msg->datalen;
        }
        else
        {
            printf("basilisk_ping_genMSG message doesnt fit %d vs %d\n",maxlen,datalen+msg->datalen);
            datalen = 0;
        }
        printf("\n-> ");
        int32_t i;
        for (i=0; i<datalen; i++)
            printf("%02x",data[i]);
        printf(" <- genMSG\n");
    } else data[datalen++] = 0;
    return(datalen);
}

char *basilisk_respond_getmessage(struct supernet_info *myinfo,uint8_t *key,int32_t keylen)
{
    cJSON *retjson,*msgjson; struct basilisk_message *msg; char *ptr = 0,strbuf[16384];
    retjson = cJSON_CreateObject();
    portable_mutex_lock(&myinfo->messagemutex);
    HASH_FIND(hh,myinfo->messagetable,key,keylen,msg);
    if ( msg != 0 )
    {
        msgjson = cJSON_CreateObject();
        if ( basilisk_addhexstr(&ptr,msgjson,strbuf,sizeof(strbuf),msg->data,msg->datalen) != 0 )
        {
            jadd(retjson,"message",msgjson);
            jaddstr(retjson,"result","success");
            printf("getmessage.(%s)\n",jprint(retjson,0));
        }
        else jaddstr(retjson,"error","couldnt add message");
    } else jaddstr(retjson,"error","no message");
    portable_mutex_unlock(&myinfo->messagemutex);
    return(jprint(retjson,1));
}

// respond to incoming OUT, MSG

int32_t basilisk_messagekey(uint8_t *key,bits256 hash,cJSON *valsobj)
{
    uint32_t channel,msgid; int32_t keylen = 0;
    channel = juint(valsobj,"channel");
    msgid = juint(valsobj,"msgid");
    keylen += iguana_rwbignum(1,&key[keylen],sizeof(hash),hash.bytes);
    keylen += iguana_rwnum(1,&key[keylen],sizeof(uint32_t),&channel);
    keylen += iguana_rwnum(1,&key[keylen],sizeof(uint32_t),&msgid);
    return(keylen);
}

char *basilisk_respond_OUT(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    int32_t keylen; uint8_t key[64];
    keylen = basilisk_messagekey(key,hash,valsobj);
    printf("keylen.%d datalen.%d\n",keylen,datalen);
    return(basilisk_respond_sendmessage(myinfo,key,keylen,data,datalen,1));
}

char *basilisk_respond_MSG(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    int32_t keylen; uint8_t key[64];
    keylen = basilisk_messagekey(key,hash,valsobj);
    return(basilisk_respond_getmessage(myinfo,key,keylen));
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"
HASH_ARRAY_STRING(basilisk,getmessage,hash,vals,hexstr)
{
    return(basilisk_standardservice("MSG",myinfo,0,myinfo->myaddr.persistent,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,sendmessage,hash,vals,hexstr)
{
    return(basilisk_standardservice("OUT",myinfo,0,myinfo->myaddr.persistent,vals,hexstr,1));
}
#include "../includes/iguana_apiundefs.h"

int32_t basilisk_channelsend(struct supernet_info *myinfo,bits256 hash,uint32_t channel,uint32_t msgid,uint8_t *data,int32_t datalen)
{
    char *retstr,*hexstr,strbuf[16384],*ptr = 0; int32_t retval = -1; cJSON *retjson,*valsobj;
    if ( (hexstr= basilisk_addhexstr(&ptr,0,strbuf,sizeof(strbuf),data,datalen)) != 0 )
    {
        valsobj = cJSON_CreateObject();
        jaddnum(valsobj,"channel",channel);
        jaddnum(valsobj,"msgid",msgid);
        if ( (retstr= basilisk_sendmessage(myinfo,0,0,0,hash,valsobj,hexstr)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( jobj(retjson,"error") == 0 )
                    retval = 0;
                free_json(retjson);
            }
            free(retstr);
        }
        free_json(valsobj);
        if ( ptr != 0 )
            free(ptr);
    }
    return(retval);
}

int32_t basilisk_channelget(struct supernet_info *myinfo,bits256 hash,uint32_t channel,uint32_t msgid,uint8_t *data,int32_t maxlen)
{
    char *retstr,*hexstr; cJSON *valsobj,*retjson; int32_t datalen,retval = -1;
    valsobj = cJSON_CreateObject();
    jaddnum(valsobj,"channel",channel);
    jaddnum(valsobj,"msgid",msgid);
    if ( (retstr= basilisk_getmessage(myinfo,0,0,0,hash,valsobj,0)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (hexstr= jstr(retjson,"data")) != 0 && (datalen= is_hexstr(hexstr,0)) > 0 )
            {
                if ( datalen < maxlen )
                {
                    decode_hex(data,datalen,hexstr);
                    retval = datalen;
                }
            }
            free_json(retjson);
        }
        free(retstr);
    }
    free_json(valsobj);
    return(retval);
}
