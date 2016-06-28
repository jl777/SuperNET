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

int32_t basilisk_rwDEXquote(int32_t rwflag,uint8_t *serialized,struct basilisk_request *rp)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->crc),&rp->crc); // must be 1st
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->timestamp),&rp->timestamp); // must be 2nd
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->requestid),&rp->requestid);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->quoteid),&rp->quoteid);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->srcamount),&rp->srcamount);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->destamount),&rp->destamount);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(rp->hash),rp->hash.bytes);
    len += iguana_rwvarstr(rwflag,&serialized[len],sizeof(rp->src)-1,rp->src);
    len += iguana_rwvarstr(rwflag,&serialized[len],sizeof(rp->src)-1,rp->dest);
    len += iguana_rwvarstr(rwflag,&serialized[len],128,rp->message);
    return(len);
}

int32_t basilisk_request_enqueue(struct supernet_info *myinfo,bits256 hash,char *src,uint64_t srcamount,char *dest,uint64_t destamount,char *message,uint32_t requestid,uint32_t quoteid)
{
    uint8_t serialized[256]; int32_t len; struct queueitem *item; struct basilisk_request R;
    memset(&R,0,sizeof(R));
    R.timestamp = (uint32_t)time(NULL);
    R.hash = hash;
    R.srcamount = srcamount;
    R.destamount = destamount;
    R.requestid = requestid;
    R.quoteid = quoteid;
    strncpy(R.src,src,sizeof(R.src)-1);
    strncpy(R.dest,dest,sizeof(R.dest)-1);
    if ( message != 0 )
        strncpy(R.message,message,sizeof(R.message)-1);
    R.crc = calc_crc32(0,(void *)((long)&R + sizeof(R.crc)),sizeof(R) - sizeof(R.crc));
    len = basilisk_rwDEXquote(1,serialized+1,&R);
    serialized[0] = len;
    if ( (item= calloc(1,sizeof(*item) + len + 1)) != 0 )
    {
        memcpy(&item[1],serialized,len + 1);
        portable_mutex_lock(&myinfo->DEX_mutex);
        DL_APPEND(myinfo->DEX_quotes,item);
        portable_mutex_unlock(&myinfo->DEX_mutex);
        return(0);
    }
    return(-1);
}

cJSON *basilisk_requestjson(uint32_t relaybits,struct basilisk_request *rp)
{
    char ipaddr[64]; cJSON *item = cJSON_CreateObject();
    expand_ipbits(ipaddr,relaybits);
    jaddstr(item,"relay",ipaddr);
    jaddbits256(item,"hash",rp->hash);
    jaddstr(item,"src",rp->src);
    if ( rp->srcamount != 0 )
        jaddnum(item,"srcamount",dstr(rp->srcamount));
    jaddstr(item,"dest",rp->dest);
    if ( rp->destamount != 0 )
        jaddnum(item,"destamount",dstr(rp->destamount));
    jaddnum(item,"timestamp",rp->timestamp);
    jaddnum(item,"requestid",rp->requestid);
    jaddnum(item,"quoteid",rp->quoteid);
    if ( rp->message[0] != 0 )
        jaddstr(item,"message",rp->message);
    return(item);
}

struct basilisk_request *basilisk_parsejson(struct basilisk_request *rp,cJSON *reqjson)
{
    memset(rp,0,sizeof(*rp));
    rp->hash = jbits256(reqjson,"hash");
    rp->srcamount = j64bits(reqjson,"srcamount");
    rp->destamount = j64bits(reqjson,"destamount");
    rp->requestid = juint(reqjson,"requestid");
    rp->quoteid = juint(reqjson,"quoteid");
    rp->timestamp = juint(reqjson,"timestamp");
    safecopy(rp->src,jstr(reqjson,"src"),sizeof(rp->src));
    safecopy(rp->dest,jstr(reqjson,"dest"),sizeof(rp->dest));
    safecopy(rp->message,jstr(reqjson,"message"),sizeof(rp->message));
    rp->crc = calc_crc32(0,(void *)((long)rp + sizeof(rp->crc)),sizeof(*rp) - sizeof(rp->crc));
    return(rp);
}

char *basilisk_choose(struct supernet_info *myinfo,bits256 hash,struct basilisk_request *other,uint64_t destamount,uint32_t quoteid)
{
    cJSON *retjson;
    if ( basilisk_request_enqueue(myinfo,hash,other->src,other->srcamount,other->dest,destamount,"start",other->requestid,quoteid) == 0 )
    {
        if ( bits256_cmp(hash,myinfo->myaddr.persistent) == 0 )
        {
            printf("START thread to complete %u/%u for (%s %.8f) <- (%s %.8f)\n",other->requestid,quoteid,other->src,dstr(other->srcamount),other->dest,dstr(other->destamount));
            // other, myinfo->myaddr.persistent, destamount, quoteid
            return(clonestr("{\"result\":\"started atomic thread\"}"));
        }
        else
        {
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"result","need to start atomic thread");
            jadd(retjson,"other",basilisk_requestjson(myinfo->myaddr.myipbits,other));
            return(jprint(retjson,1));
        }
    } else return(clonestr("{\"error\":\"couldnt enqueue chosen\"}"));
}

struct basilisk_relay *basilisk_request_ensure(struct supernet_info *myinfo,uint32_t senderipbits,int32_t numrequests)
{
    int32_t j; struct basilisk_relay *relay = 0;
    if ( (j= basilisk_relayid(myinfo,senderipbits)) >= 0 )
    {
        relay = &myinfo->relays[j];
        if ( numrequests > relay->maxrequests )
        {
            relay->maxrequests = numrequests;
            relay->requests = realloc(relay->requests,sizeof(*relay->requests) * numrequests);
        }
        relay->numrequests = 0;
    }
    return(relay);
}

int32_t basilisk_ping_processDEX(struct supernet_info *myinfo,uint32_t senderipbits,uint8_t *data,int32_t datalen)
{
    int32_t i,len=0; struct basilisk_relay *relay; struct basilisk_request R; uint8_t clen,serialized[256]; uint16_t sn; uint32_t crc;
    portable_mutex_lock(&myinfo->DEX_reqmutex);
    len += iguana_rwnum(0,&data[len],sizeof(sn),&sn);
    if ( (relay= basilisk_request_ensure(myinfo,senderipbits,sn)) != 0 )
    {
        for (i=0; i<sn; i++)
        {
            clen = data[len++];
            if ( len+clen <= datalen )
            {
                if ( relay->numrequests < relay->maxrequests )
                {
                    memcpy(serialized,&data[len],clen);
                    len += basilisk_rwDEXquote(0,serialized,&R);
                    crc = calc_crc32(0,(void *)((long)&R + sizeof(R.crc)),sizeof(R) - sizeof(R.crc));
                    if ( crc == R.crc )
                    {
                        relay->requests[relay->numrequests++] = R;
                        printf("(%s (%s %.8f) -> (%s %.8f) r.%u q.%u) ",R.message,R.src,dstr(R.srcamount),R.dest,dstr(R.destamount),R.requestid,R.quoteid);
                    } else printf("crc.%08x error vs %08x\n",crc,R.crc);
                } else printf("relay num.%d >= max.%d\n",relay->numrequests,relay->maxrequests);
            } else len += clen;
        }
    }
    else
    {
        for (i=0; i<sn; i++)
        {
            if ( len+clen <= datalen )
            {
                clen = data[len++];
                len += clen;
            }
        }
    }
    portable_mutex_unlock(&myinfo->DEX_reqmutex);
    return(len);
}

int32_t basilisk_ping_genDEX(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen)
{
    struct queueitem *item,*tmp; uint8_t clen; int32_t i,datalen = 0; uint16_t sn; uint32_t timestamp,now;
    datalen += sizeof(uint16_t);
    i = 0;
    now = (uint32_t)time(NULL);
    portable_mutex_lock(&myinfo->DEX_mutex);
    DL_FOREACH_SAFE(myinfo->DEX_quotes,item,tmp)
    {
        memcpy(&clen,&item[1],sizeof(clen));
        if ( datalen+clen < maxlen )
        {
            memcpy(&data[datalen],&item[1],clen+1), datalen += (clen + 1);
            i++;
        }
        iguana_rwnum(0,(void *)((long)&item[1] + 1),sizeof(timestamp),&timestamp);
        if ( now > timestamp + BASILISK_DEXDURATION )
        {
            DL_DELETE(myinfo->DEX_quotes,item);
            free(item);
        }
    }
    portable_mutex_unlock(&myinfo->DEX_mutex);
    sn = i;
    iguana_rwnum(1,data,sizeof(sn),&sn); // fill in at beginning
    return(datalen);
}

char *basilisk_respond_incoming(struct supernet_info *myinfo,bits256 hash,uint32_t requestid,uint32_t quoteid)
{
    int32_t i,j,n,k,m; struct basilisk_relay *relay; cJSON *retjson,*array; struct basilisk_request requests[BASILISK_MAXRELAYS],*rp;
    array = cJSON_CreateArray();
    portable_mutex_lock(&myinfo->DEX_reqmutex);
    for (j=m=0; j<myinfo->numrelays; j++)
    {
        relay = &myinfo->relays[j];
        if ( (n= relay->numrequests) > 0 )
        {
            for (i=0; i<n; i++)
            {
                rp = &relay->requests[i];
                if ( (requestid == 0 || rp->requestid == requestid) && ((quoteid == 0 && rp->quoteid != 0) || quoteid == rp->quoteid) )
                {
                    for (k=0; k<m; k++)
                        if ( memcmp(&requests[k],rp,sizeof(requests[k])) == 0 )
                            break;
                    if ( k == m )
                    {
                        requests[m++] = *rp;
                        jaddi(array,basilisk_requestjson(relay->ipbits,rp));
                    }
                }
            }
        }
    }
    portable_mutex_unlock(&myinfo->DEX_reqmutex);
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

char *basilisk_respond_choose(struct supernet_info *myinfo,bits256 hash,uint32_t requestid,uint64_t destamount)
{
    int32_t i,n,j,alreadythere = 0; uint32_t quoteid; char *retstr; struct basilisk_relay *relay; struct basilisk_request *rp=0;
    quoteid = (requestid ^ hash.uints[0]);
    portable_mutex_lock(&myinfo->DEX_reqmutex);
    for (j=0; j<myinfo->numrelays; j++)
    {
        relay = &myinfo->relays[j];
        if ( (n= relay->numrequests) > 0 )
        {
            for (i=0; i<n; i++)
            {
                if ( relay->requests[i].requestid == requestid )
                {
                    if ( relay->requests[i].quoteid == 0 )
                        rp = &relay->requests[i];
                    else if ( relay->requests[i].quoteid == quoteid )
                    {
                        alreadythere = 1;
                        break;
                    }
                }
            }
        }
        if ( alreadythere != 0 )
            break;
    }
    if ( alreadythere == 0 )
    {
        if ( rp == 0 )
            retstr = clonestr("{\"error\":\"couldnt find to requestid to choose\"}");
        else retstr = basilisk_choose(myinfo,hash,rp,destamount,quoteid);
    } else retstr = clonestr("{\"result\":\"quoteid already there\"}");
    portable_mutex_unlock(&myinfo->DEX_reqmutex);
    return(retstr);
}

// respond to incoming RID, CHS, DEX, QST

char *basilisk_respond_RID(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    return(basilisk_respond_incoming(myinfo,hash,juint(valsobj,"requestid"),0));
}

char *basilisk_respond_QID(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    return(basilisk_respond_incoming(myinfo,hash,juint(valsobj,"requestid"),juint(valsobj,"quoteid")));
}

char *basilisk_respond_CHS(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    uint32_t requestid; uint64_t destamount;
    if ( (requestid= juint(valsobj,"requestid")) != 0 && (destamount= j64bits(valsobj,"destamount")) != 0 )
        return(basilisk_respond_choose(myinfo,hash,requestid,destamount));
    return(clonestr("{\"error\":\"need nonzero requestid and quoteid\"}"));
}

char *basilisk_respond_DEX(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *dest,*src,*retstr=0,buf[256]; uint32_t zero=0; uint64_t satoshis;
    if ( (dest= jstr(valsobj,"dest")) != 0 && (src= jstr(valsobj,"src")) != 0 && (satoshis= j64bits(valsobj,"satoshis")) != 0 )
    {
        char str[65]; printf("DEX.(%s %.8f) -> %s %s\n",src,dstr(satoshis),dest,bits256_str(str,hash));
        if ( basilisk_request_enqueue(myinfo,hash,src,satoshis,dest,0,jstr(valsobj,"msg"),basilisktag,zero) == 0 )
        {
            sprintf(buf,"{\"result\":\"DEX request added\",\"request\":%u}",basilisktag);
            retstr = clonestr(buf);
        } else retstr = clonestr("{\"error\":\"DEX quote couldnt be created\"}");
    }
    return(retstr);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

ZERO_ARGS(InstantDEX,allcoins)
{
    struct iguana_info *tmp; cJSON *array,*retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    HASH_ITER(hh,myinfo->allcoins,coin,tmp)
    {
        jaddistr(array,coin->symbol);
    }
    jadd(retjson,"coins",array);
    return(jprint(retjson,1));
}

STRING_ARG(InstantDEX,available,source)
{
    if ( (coin= iguana_coinfind(source)) != 0 )
    {
        if ( myinfo->expiration != 0 )
            return(bitcoinrpc_getbalance(myinfo,coin,json,remoteaddr,"*",coin->chain->minconfirms,1,1<<30));
        else return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    } else return(clonestr("{\"error\":\"specified coin is not active\"}"));
}

THREE_STRINGS_AND_DOUBLE(InstantDEX,request,message,dest,source,amount)
{
    struct basilisk_request R; char *retstr; cJSON *vals = cJSON_CreateObject();
    jaddstr(vals,"dest",dest);
    jaddstr(vals,"src",source);
    if ( strlen(message) < sizeof(R.message) )
        jaddstr(vals,"msg",message);
    jadd64bits(vals,"satoshis",amount * SATOSHIDEN);
    retstr = basilisk_standardservice("DEX",myinfo,0,myinfo->myaddr.persistent,vals,"",1);
    free_json(vals);
    return(retstr);
}

INT_ARG(InstantDEX,incoming,requestid)
{
    cJSON *vals; char *retstr;
    if ( myinfo->RELAYID >= 0 )
        return(basilisk_respond_incoming(myinfo,myinfo->myaddr.persistent,requestid,0));
    else
    {
        vals = cJSON_CreateObject();
        jaddnum(vals,"requestid",requestid);
        jaddbits256(vals,"hash",myinfo->myaddr.persistent);
        retstr = basilisk_standardservice("RID",myinfo,0,myinfo->myaddr.persistent,vals,"",1);
        free_json(vals);
        return(retstr);
    }
}

TWO_INTS(InstantDEX,qstatus,requestid,quoteid)
{
    cJSON *vals; char *retstr;
    if ( myinfo->RELAYID >= 0 )
        return(basilisk_respond_incoming(myinfo,myinfo->myaddr.persistent,requestid,quoteid));
    else
    {
        vals = cJSON_CreateObject();
        jaddnum(vals,"quoteid",quoteid);
        jaddbits256(vals,"hash",myinfo->myaddr.persistent);
        retstr = basilisk_standardservice("QST",myinfo,0,myinfo->myaddr.persistent,vals,"",1);
        free_json(vals);
        return(retstr);
    }
}

INT_AND_DOUBLE(InstantDEX,choose,requestid,destamount)
{
    cJSON *vals,*retjson; char *retstr; struct basilisk_request R,*other; uint32_t quoteid;
    if ( myinfo->RELAYID >= 0 )
        return(basilisk_respond_choose(myinfo,myinfo->myaddr.persistent,requestid,destamount*SATOSHIDEN));
    else
    {
        quoteid = (requestid ^ myinfo->myaddr.persistent.uints[0]);
        vals = cJSON_CreateObject();
        jaddnum(vals,"requestid",requestid);
        jaddnum(vals,"quoteid",quoteid);
        jadd64bits(vals,"destamount",destamount*SATOSHIDEN);
        jaddbits256(vals,"hash",myinfo->myaddr.persistent);
        if ( (retstr= basilisk_standardservice("CHS",myinfo,0,myinfo->myaddr.persistent,vals,"",1)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                other = basilisk_parsejson(&R,jobj(retjson,"other"));
                // other, myinfo->myaddr.persistent, destamount, quoteid
                printf("START thread to complete %u/%u for (%s %.8f) <- (%s %.8f)\n",other->requestid,quoteid,other->src,dstr(other->srcamount),other->dest,dstr(other->destamount));
                free(retjson);
            }
        }
        free_json(vals);
        return(retstr);
    }
}

#include "../includes/iguana_apiundefs.h"


int32_t basilisk_request_pending(struct supernet_info *myinfo,struct basilisk_request *rp,uint32_t requestid)
{
    int32_t i,j,n,alreadystarted = 0; struct basilisk_relay *relay; uint32_t quoteid;
    quoteid = (requestid ^ myinfo->myaddr.persistent.uints[0]);
    portable_mutex_lock(&myinfo->DEX_reqmutex);
    for (j=0; j<myinfo->numrelays; j++)
    {
        relay = &myinfo->relays[j];
        if ( (n= relay->numrequests) > 0 )
        {
            for (i=0; i<n; i++)
            {
                if ( relay->requests[i].requestid == requestid && relay->requests[i].quoteid == quoteid )
                {
                    alreadystarted = 1;
                    break;
                }
            }
        }
    }
    portable_mutex_unlock(&myinfo->DEX_reqmutex);
    return(alreadystarted);
}

void basilisk_request_check(struct supernet_info *myinfo,struct basilisk_request *rp)
{
    double retvals[4],aveprice; struct basilisk_request R; struct iguana_info *src,*dest; char message[128]; uint32_t quoteid;
    if ( (src= iguana_coinfind(rp->src)) != 0 && (dest= iguana_coinfind(rp->dest)) != 0 )
    {
        if ( basilisk_request_pending(myinfo,&R,rp->requestid) == 0 )
        {
            aveprice = instantdex_avehbla(myinfo,retvals,rp->src,rp->dest,dstr(rp->srcamount));
            quoteid = rp->requestid ^ myinfo->myaddr.persistent.uints[0];
            sprintf(message,"{\"price\":%.8f,\"requestid\":%u,\"quoteid\":%u}",aveprice,rp->requestid,quoteid);
            if ( basilisk_request_enqueue(myinfo,myinfo->myaddr.persistent,rp->src,rp->srcamount*aveprice,rp->dest,rp->srcamount*aveprice,message,rp->requestid,quoteid) < 0 )
                printf("error creating quoteid\n");
        }
    }
}

