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

#include "../iguana/iguana777.h"

char *basilisk_respond_goodbye(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    printf("(%s) sends goodbye\n",remoteaddr);
    addr->dead = (uint32_t)time(NULL);
    addr->rank = 0;
    return(0);
}

void basilisk_request_goodbye(struct supernet_info *myinfo)
{
    struct basilisk_item Lptr; cJSON *valsobj = cJSON_CreateObject();
    jaddnum(valsobj,"timeout",-1);
    basilisk_requestservice(&Lptr,myinfo,"BYE",0,valsobj,GENESIS_PUBKEY);
    free_json(valsobj);
}

char *basilisk_respond_publish(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    printf("from.(%s) PUB.(%s) datalen.%d\n",remoteaddr,jprint(valsobj,0),datalen);
    return(retstr);
}

struct basilisk_item *basilisk_request_publish(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"PUB",0,valsobj,pubkey));
}

char *basilisk_respond_subscribe(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    return(retstr);
}
struct basilisk_item *basilisk_request_subscribe(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"SUB",0,valsobj,pubkey));
}

char *basilisk_respond_setfield(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    printf("from.(%s) SET.(%s) datalen.%d\n",remoteaddr,jprint(valsobj,0),datalen);
    return(retstr);
}

struct basilisk_item *basilisk_request_setfield(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"SET",0,valsobj,pubkey));
}

char *basilisk_respond_getfield(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    printf("from.(%s) GET.(%s) datalen.%d\n",remoteaddr,jprint(valsobj,0),datalen);
    return(retstr);
}

struct basilisk_item *basilisk_request_getfield(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"GET",0,valsobj,pubkey));
}

char *basilisk_respond_dispatch(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_dispatch(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"RUN",0,valsobj,pubkey));
}

char *basilisk_respond_addrelay(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_addrelay(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"ADD",0,valsobj,pubkey));
}

char *basilisk_respond_forward(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_forward(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"HOP",0,valsobj,pubkey));
}

char *basilisk_respond_mailbox(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_mailbox(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"BOX",0,valsobj,pubkey));
}

char *basilisk_respond_VPNcreate(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_VPNcreate(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"HUB",0,valsobj,pubkey));
}

char *basilisk_respond_VPNjoin(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_VPNjoin(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"ARC",0,valsobj,pubkey));
}

char *basilisk_respond_VPNlogout(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_VPNlogout(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"END",0,valsobj,pubkey));
}

char *basilisk_respond_VPNbroadcast(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_VPNbroadcast(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"SAY",0,valsobj,pubkey));
}

char *basilisk_respond_VPNreceive(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_VPNreceive(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"EAR",0,valsobj,pubkey));
}

char *basilisk_respond_VPNmessage(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_VPNmessage(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"GAP",0,valsobj,pubkey));
}


