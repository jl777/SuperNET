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

char *basilisk_respond_goodbye(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
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
    basilisk_requestservice(&Lptr,myinfo,"BYE",0,valsobj,GENESIS_PUBKEY,0x1efffff0);
    free_json(valsobj);
}

char *basilisk_respond_setfield(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk)
{
    bits256 hash,cathash; struct category_info *rootcat,*cat,*prevcat=0; char *category; char str[65];
    printf("from.(%s) SET.(%s) datalen.%d\n",remoteaddr,jprint(valsobj,0),datalen);
    if ( datalen <= 0 || (category= jstr(valsobj,"category")) == 0 )
        return(0);
    vcalc_sha256(0,cathash.bytes,(uint8_t *)category,(int32_t)strlen(category));
    vcalc_sha256(0,hash.bytes,data,datalen);
    category_subscribe(myinfo,cathash,hash,data,datalen);
    if ( bits256_cmp(prevhash,GENESIS_PUBKEY) != 0 && bits256_nonz(prevhash) != 0 )
    {
        if ( (prevcat= category_find(cathash,prevhash)) == 0 )
        {
            printf("basilisk_respond_publish: cant find prevhash.%s\n",bits256_str(str,prevhash));
        }
    } else memset(prevhash.bytes,0,sizeof(prevhash));
    if ( (rootcat= category_find(cathash,GENESIS_PUBKEY)) == 0 )
        printf("error finding category.(%s)\n",category);
    else if ( (cat= category_find(cathash,hash)) == 0 )
        printf("error finding just added category\n");
    else
    {
        rootcat->lasthash = hash;
        cat->prevhash = prevhash;
        if ( prevcat != 0 )
            prevcat->next = cat;
    }
    return(0);
}

struct basilisk_item *basilisk_request_setfield(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"SET",0,valsobj,pubkey,0x1efffff0));
}

char *basilisk_respond_getfield(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk)
{
    bits256 cathash; struct category_info *cat; char *category,*hexstr; cJSON *retjson;
    if ( (category= jstr(valsobj,"category")) == 0 )
        return(0);
    vcalc_sha256(0,cathash.bytes,(uint8_t *)category,(int32_t)strlen(category));
    char str[65]; printf("from.(%s) GET.(%s) datalen.%d %s\n",remoteaddr,jprint(valsobj,0),datalen,bits256_str(str,cathash));
    retjson = cJSON_CreateObject();
    if ( bits256_nonz(prevhash) == 0 || bits256_cmp(GENESIS_PUBKEY,prevhash) == 0 )
    {
        if ( (cat= category_find(cathash,GENESIS_PUBKEY)) == 0 )
            jaddstr(retjson,"error","cant find category");
        else
        {
            jaddbits256(retjson,"genesis",cat->hash);
            jaddbits256(retjson,"last",cat->lasthash);
        }
    }
    else
    {
        if ( (cat= category_find(cathash,prevhash)) == 0 )
            printf("error finding just added category\n");
        if ( cat->datalen > 0 )
        {
            hexstr = calloc(1,(cat->datalen << 1) + 1);
            init_hexbytes_noT(hexstr,cat->data,cat->datalen);
            jaddstr(retjson,"data",hexstr);
        }
    }
    return(jprint(retjson,1));
}

struct basilisk_item *basilisk_request_getfield(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 prevhash,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    bits256 cathash; char *category;
    if ( (category= jstr(valsobj,"category")) == 0 )
        return(0);
    vcalc_sha256(0,cathash.bytes,(uint8_t *)category,(int32_t)strlen(category));
    return(basilisk_requestservice(Lptr,myinfo,"GET",0,valsobj,prevhash,0x1efffff0));
}

char *basilisk_respond_publish(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    printf("from.(%s) PUB.(%s) datalen.%d\n",remoteaddr,jprint(valsobj,0),datalen);
    return(retstr);
}

struct basilisk_item *basilisk_request_publish(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"PUB",0,valsobj,pubkey,0x1efffff0));
}

char *basilisk_respond_subscribe(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    printf("from.(%s) SUB.(%s) datalen.%d\n",remoteaddr,jprint(valsobj,0),datalen);
    return(retstr);
}

struct basilisk_item *basilisk_request_subscribe(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"SUB",0,valsobj,pubkey,0x1efffff0));
}

char *basilisk_respond_dispatch(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_dispatch(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"RUN",0,valsobj,pubkey,0x1efffff0));
}

char *basilisk_respond_addrelay(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_addrelay(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"ADD",0,valsobj,pubkey,0x1efffff0));
}

char *basilisk_respond_forward(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_forward(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"HOP",0,valsobj,pubkey,0x1efffff0));
}

char *basilisk_respond_mailbox(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_mailbox(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"BOX",0,valsobj,pubkey,0x1efffff0));
}

char *basilisk_respond_VPNcreate(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_VPNcreate(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"HUB",0,valsobj,pubkey,0x1efffff0));
}

char *basilisk_respond_VPNjoin(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_VPNjoin(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"ARC",0,valsobj,pubkey,0x1efffff0));
}

char *basilisk_respond_VPNlogout(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_VPNlogout(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"END",0,valsobj,pubkey,0x1efffff0));
}

char *basilisk_respond_VPNbroadcast(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_VPNbroadcast(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"SAY",0,valsobj,pubkey,0x1efffff0));
}

char *basilisk_respond_VPNreceive(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_VPNreceive(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"EAR",0,valsobj,pubkey,0x1efffff0));
}

char *basilisk_respond_VPNmessage(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

struct basilisk_item *basilisk_request_VPNmessage(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 pubkey,cJSON *valsobj,uint8_t *data,int32_t datalen)
{
    return(basilisk_requestservice(Lptr,myinfo,"GAP",0,valsobj,pubkey,0x1efffff0));
}


