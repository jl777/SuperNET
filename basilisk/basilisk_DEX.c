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
// requestid is invariant for a specific request
// quoteid is invariant for a specific request after dest fields are set

uint32_t basilisk_requestid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.requestid = R.quoteid = R.pad = 0;
    R.volatile_start = 0;
    memset(R.message,0,sizeof(R.message));
    R.destamount = 0;
    R.relaybits = 0;
    memset(R.desthash.bytes,0,sizeof(R.desthash.bytes));
    if ( 0 )
    {
        int32_t i;
        for (i=0; i<sizeof(R); i++)
            printf("%02x",((uint8_t *)&R)[i]);
        printf(" <- crc.%u\n",calc_crc32(0,(void *)&R,sizeof(R)));
        char str[65],str2[65]; printf("B REQUESTID: t.%u r.%u q.%u %s %.8f %s -> %s %.8f %s (%s) crc.%u\n",R.timestamp,R.requestid,R.quoteid,R.src,dstr(R.srcamount),bits256_str(str,R.hash),R.dest,dstr(R.destamount),bits256_str(str2,R.desthash),R.message,calc_crc32(0,(void *)&R,sizeof(R)));
    }
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

uint32_t basilisk_quoteid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.requestid = R.quoteid = R.relaybits = R.pad = R.volatile_start = 0;
    memset(R.message,0,sizeof(R.message));
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

int32_t basilisk_rwDEXquote(int32_t rwflag,uint8_t *serialized,struct basilisk_request *rp)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->requestid),&rp->requestid);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->timestamp),&rp->timestamp); // must be 2nd
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->quoteid),&rp->quoteid);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->relaybits),&rp->relaybits);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->srcamount),&rp->srcamount);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->minamount),&rp->minamount);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(rp->hash),rp->hash.bytes);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(rp->desthash),rp->desthash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->destamount),&rp->destamount);
    if ( rwflag != 0 )
    {
        memcpy(&serialized[len],rp->src,sizeof(rp->src)), len += sizeof(rp->src);
        memcpy(&serialized[len],rp->dest,sizeof(rp->dest)), len += sizeof(rp->dest);
    }
    else
    {
        rp->pad = rp->volatile_start = 0;
        memcpy(rp->src,&serialized[len],sizeof(rp->src)), len += sizeof(rp->src);
        memcpy(rp->dest,&serialized[len],sizeof(rp->dest)), len += sizeof(rp->dest);
    }
    len += iguana_rwvarstr(rwflag,&serialized[len],sizeof(rp->message)-1,rp->message);
    if ( rp->quoteid != 0 && basilisk_quoteid(rp) != rp->quoteid )
        printf("basilisk_rwDEXquote.%d: quoteid.%u mismatch calc %u\n",rwflag,rp->quoteid,basilisk_quoteid(rp));
    if ( basilisk_requestid(rp) != rp->requestid )
        printf("basilisk_rwDEXquote.%d: requestid.%u mismatch calc %u\n",rwflag,rp->requestid,basilisk_requestid(rp));
    return(len);
}

uint32_t basilisk_request_enqueue(struct supernet_info *myinfo,struct basilisk_request *rp,char *message)
{
    uint8_t serialized[256]; int32_t len; struct queueitem *item;
    printf("ENQUEUE.%u calc.%u\n",rp->requestid,basilisk_requestid(rp));
    strcpy(rp->message,message);
    len = basilisk_rwDEXquote(1,serialized+1,rp);
    printf("ENQUEUE.%u calc.%u\n",rp->requestid,basilisk_requestid(rp));
    if ( (item= calloc(1,sizeof(*item) + len + 1)) != 0 )
    {
        serialized[0] = len;
        memcpy(&item[1],serialized,len + 1);
        portable_mutex_lock(&myinfo->DEX_mutex);
        DL_APPEND(myinfo->DEX_quotes,item);
        portable_mutex_unlock(&myinfo->DEX_mutex);
        return(rp->requestid);
    }
    return(0);
}

struct basilisk_request *basilisk_parsejson(struct basilisk_request *rp,cJSON *reqjson)
{
    uint32_t requestid,quoteid; char *msgstr;
    memset(rp,0,sizeof(*rp));
    rp->hash = jbits256(reqjson,"hash");
    rp->desthash = jbits256(reqjson,"desthash");
    rp->srcamount = j64bits(reqjson,"srcamount");
    rp->minamount = j64bits(reqjson,"minamount");
    rp->destamount = j64bits(reqjson,"destamount");
    requestid = juint(reqjson,"requestid");
    quoteid = juint(reqjson,"quoteid");
    if ( jstr(reqjson,"relay") != 0 )
        rp->relaybits = (uint32_t)calc_ipbits(jstr(reqjson,"relay"));
    rp->timestamp = juint(reqjson,"timestamp");
    safecopy(rp->src,jstr(reqjson,"src"),sizeof(rp->src));
    safecopy(rp->dest,jstr(reqjson,"dest"),sizeof(rp->dest));
    if ( jobj(reqjson,"message") != 0 )
    {
        msgstr = jprint(jobj(reqjson,"message"),0);
        if ( strlen(msgstr) > sizeof(rp->message)-1 )
            printf("basilisk_parsejson msgstr.(%s) too long\n",msgstr);
        safecopy(rp->message,msgstr,sizeof(rp->message));
        free(msgstr);
    }
    if ( quoteid != 0 )
    {
        rp->quoteid = basilisk_quoteid(rp);
        if ( quoteid != rp->quoteid )
            printf("basilisk_parsejson quoteid.%u != %u error\n",quoteid,rp->quoteid);
    }
    rp->requestid = basilisk_requestid(rp);
    if ( requestid != rp->requestid )
        printf("basilisk_parsejson requestid.%u != %u error\n",requestid,rp->requestid);
    return(rp);
}

cJSON *basilisk_requestjson(uint32_t relaybits,struct basilisk_request *rp)
{
    /*uint32_t requestid,timestamp,quoteid;
    uint64_t srcamount,minamount;
    bits256 hash;
    char src[8],dest[8];
    char volatile_start,message[43];
    uint32_t relaybits;
    uint64_t destamount;
    bits256 desthash;*/
    char ipaddr[64]; cJSON *msgobj,*item = cJSON_CreateObject();
    expand_ipbits(ipaddr,relaybits);
    jaddstr(item,"relay",ipaddr);
    jaddbits256(item,"hash",rp->hash);
    if ( bits256_nonz(rp->desthash) != 0 )
        jaddbits256(item,"desthash",rp->desthash);
    jaddstr(item,"src",rp->src);
    if ( rp->srcamount != 0 )
        jadd64bits(item,"srcamount",rp->srcamount);
    if ( rp->minamount != 0 )
        jadd64bits(item,"min",rp->minamount);
    jaddstr(item,"dest",rp->dest);
    if ( rp->destamount != 0 )
        jadd64bits(item,"destamount",rp->destamount);
    jaddnum(item,"timestamp",rp->timestamp);
    jaddnum(item,"requestid",rp->requestid);
    jaddnum(item,"quoteid",rp->quoteid);
    if ( rp->message[0] != 0 && (msgobj= cJSON_Parse(rp->message)) != 0 )
        jadd(item,"message",msgobj);
    if ( rp->quoteid != 0 && basilisk_quoteid(rp) != rp->quoteid )
        printf("quoteid mismatch %u vs %u\n",basilisk_quoteid(rp),rp->quoteid);
    if ( basilisk_requestid(rp) != rp->requestid )
        printf("requestid mismatch %u vs calc %u\n",rp->requestid,basilisk_requestid(rp));
    {
        int32_t i; struct basilisk_request R;
        if ( basilisk_parsejson(&R,item) != 0 )
        {
            memset(R.message,0,sizeof(R.message));
            strcpy(R.message,rp->message);
            if ( memcmp(&R,rp,sizeof(*rp)) != 0 )
            {
                for (i=0; i<sizeof(*rp); i++)
                    printf("%02x",((uint8_t *)rp)[i]);
                printf(" <- rp\n");
                for (i=0; i<sizeof(R); i++)
                    printf("%02x",((uint8_t *)&R)[i]);
                printf(" <- R mismatch\n");
                for (i=0; i<sizeof(R); i++)
                    if ( ((uint8_t *)rp)[i] != ((uint8_t *)&R)[i] )
                        printf("%d ",i);
                printf("mismatches\n");
            } else printf("matched JSON conv %u %u\n",basilisk_requestid(&R),basilisk_requestid(rp));
        }
    }
    return(item);
}

int32_t basilisk_request_create(struct basilisk_request *rp,cJSON *valsobj,bits256 hash,uint32_t timestamp)
{
    char *dest,*src,*msgstr=0; uint32_t i;
    memset(rp,0,sizeof(*rp));
    if ( (dest= jstr(valsobj,"dest")) != 0 && (src= jstr(valsobj,"source")) != 0 && (rp->srcamount= j64bits(valsobj,"satoshis")) != 0 )
    {
        if ( (rp->destamount= j64bits(valsobj,"destsatoshis")) != 0 )
        {
            rp->desthash = jbits256(valsobj,"desthash");
            for (i=0; i<4; i++)
                if ( rp->desthash.ulongs[i] != 0 )
                    break;
            if ( i != 4 )
                rp->destamount = 0;
        }
        rp->minamount = j64bits(valsobj,"min");
        rp->timestamp = timestamp;
        rp->hash = hash;
        strncpy(rp->src,src,sizeof(rp->src)-1);
        strncpy(rp->dest,dest,sizeof(rp->dest)-1);
        if ( jobj(valsobj,"message") != 0 )
        {
            msgstr = jprint(jobj(valsobj,"message"),0);
            if ( strlen(msgstr) > sizeof(rp->message)-1 )
                printf("message.(%s) too long\n",rp->message);
            strncpy(rp->message,msgstr,sizeof(rp->message)-1);
            free(msgstr);
        }
        rp->requestid = basilisk_requestid(rp);
        if ( rp->destamount != 0 && bits256_nonz(rp->desthash) != 0 )
        {
            rp->quoteid = basilisk_quoteid(rp);
            printf("set quoteid.%u\n",rp->quoteid);
        }
        //printf("create.%u calc.%u\n",rp->requestid,basilisk_requestid(rp));
        return(0);
    }
    return(-1);
}

char *basilisk_start(struct supernet_info *myinfo,struct basilisk_request *rp,uint32_t statebits)
{
    cJSON *retjson; char msgjsonstr[64];
    sprintf(rp->message,"{\"state\":%u\"}",statebits);
    if ( basilisk_request_enqueue(myinfo,rp,msgjsonstr) == rp->requestid )
    {
        if ( myinfo->RELAYID >= 0 && (bits256_cmp(rp->hash,myinfo->myaddr.persistent) == 0 || bits256_cmp(rp->desthash,myinfo->myaddr.persistent) == 0) )
        {
            printf("START thread to complete %u/%u for (%s %.8f) <- (%s %.8f)\n",rp->requestid,rp->quoteid,rp->src,dstr(rp->srcamount),rp->dest,dstr(rp->destamount));
            if ( basilisk_thread_start(myinfo,rp) != 0 )
            {
                basilisk_request_enqueue(myinfo,rp,msgjsonstr);
                return(clonestr("{\"result\":\"started atomic swap thread\"}"));
            }
            else return(clonestr("{\"error\":\"couldnt atomic swap thread\"}"));
        }
        else if ( myinfo->RELAYID < 0 )
        {
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"result","basilisk node needs to start atomic thread locally");
            jadd(retjson,"req",basilisk_requestjson(myinfo->myaddr.myipbits,rp));
            return(jprint(retjson,1));
        } else return(clonestr("{\"error\":\"unexpected basilisk_start not mine and amrelay\"}"));
    } else return(clonestr("{\"error\":\"couldnt enqueue chosen\"}"));
}
// end of swap code

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
    }
    return(relay);
}

int32_t basilisk_ping_processDEX(struct supernet_info *myinfo,uint32_t senderipbits,uint8_t *data,int32_t datalen)
{
    int32_t i,n,len=0; struct basilisk_relay *relay; struct basilisk_request R; uint8_t clen,serialized[256]; uint16_t sn; uint32_t crc;
    portable_mutex_lock(&myinfo->DEX_reqmutex);
    len += iguana_rwnum(0,&data[len],sizeof(sn),&sn);
    if ( (relay= basilisk_request_ensure(myinfo,senderipbits,sn)) != 0 )
    {
        relay->numrequests = 0;
        for (i=0; i<sn; i++)
        {
            clen = data[len++];
            if ( len+clen <= datalen )
            {
                if ( relay->numrequests < relay->maxrequests )
                {
                    memcpy(serialized,&data[len],clen);
                    printf("ping processDEX\n");
                    n = basilisk_rwDEXquote(0,serialized,&R);
                    if ( n != clen )
                        printf("n.%d clen.%d\n",n,clen);
                    len += clen;
                    crc = basilisk_requestid(&R);
                    if ( crc == R.requestid )
                    {
                        relay->requests[relay->numrequests++] = R;
                        printf("(%s (%s %.8f) -> (%s %.8f) r.%u q.%u) ",R.message,R.src,dstr(R.srcamount),R.dest,dstr(R.destamount),R.requestid,R.quoteid);
                    } else printf("crc.%u error vs %u\n",crc,R.requestid);
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
        iguana_rwnum(0,(void *)((long)&item[1] + 1 + sizeof(uint32_t)),sizeof(timestamp),&timestamp);
        if ( now > timestamp + BASILISK_DEXDURATION )
        {
            DL_DELETE(myinfo->DEX_quotes,item);
            free(item);
        } else printf("now.%u vs timestamp.%u, lag.%d\n",now,timestamp,now-timestamp);
    }
    portable_mutex_unlock(&myinfo->DEX_mutex);
    sn = i;
    iguana_rwnum(1,data,sizeof(sn),&sn); // fill in at beginning
    return(datalen);
}

static int _cmp_requests(const void *a,const void *b)
{
#define uint32_a (*(struct basilisk_request *)a).requestid
#define uint32_b (*(struct basilisk_request *)b).requestid
	if ( uint32_b > uint32_a )
		return(1);
	else if ( uint32_b < uint32_a )
		return(-1);
    else
    {
#undef uint32_a
#undef uint32_b
#define uint32_a (*(struct basilisk_request *)a).quoteid
#define uint32_b (*(struct basilisk_request *)b).quoteid
        if ( uint32_b > uint32_a )
            return(1);
        else if ( uint32_b < uint32_a )
            return(-1);
    }
	return(0);
#undef uint32_a
#undef uint32_b
}

struct basilisk_request *_basilisk_requests_uniq(struct supernet_info *myinfo,int32_t *nump,uint8_t *space,int32_t spacesize)
{
    int32_t i,j,n,k,m; struct basilisk_relay *relay; struct basilisk_request *requests,*rp;
    for (j=m=0; j<myinfo->numrelays; j++)
        m += myinfo->relays[j].numrequests;
    if ( m*sizeof(*requests) <= spacesize )
        requests = (void *)space;
    else requests = calloc(m,sizeof(*requests));
    for (j=m=0; j<myinfo->numrelays; j++)
    {
        relay = &myinfo->relays[j];
        if ( (n= relay->numrequests) > 0 )
        {
            for (i=0; i<n; i++)
            {
                rp = &relay->requests[i];
                for (k=0; k<m; k++)
                    if ( memcmp(&requests[k],rp,sizeof(requests[k])) == 0 )
                        break;
                if ( k == m )
                {
                    requests[m].relaybits = relay->ipbits;
                    requests[m++] = *rp;
                }
            }
        }
    }
    qsort(requests,m,sizeof(*requests),_cmp_requests);
    *nump = m;
    return(requests);
}

char *basilisk_respond_swapstatus(struct supernet_info *myinfo,bits256 hash,uint32_t requestid,uint32_t quoteid)
{
    cJSON *array,*retjson;
    array = cJSON_CreateArray();
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

char *basilisk_respond_requests(struct supernet_info *myinfo,bits256 hash,uint32_t requestid,uint32_t quoteid)
{
    int32_t i,qflag,num=0; cJSON *retjson,*array; struct basilisk_request *requests,*rp; uint8_t space[16384];
    array = cJSON_CreateArray();
    portable_mutex_lock(&myinfo->DEX_reqmutex);
    if ( (requests= _basilisk_requests_uniq(myinfo,&num,space,sizeof(space))) != 0 )
    {
        for (i=0; i<num; i++)
        {
            rp = &requests[i];
            if ( quoteid == 0 || (quoteid == rp->quoteid && (bits256_cmp(hash,rp->hash) == 0 || bits256_cmp(hash,rp->desthash) == 0)) )
                qflag = 1;
            else qflag = 0;
            if ( requestid == 0 || (rp->requestid == requestid && qflag != 0) )
                jaddi(array,basilisk_requestjson(rp->relaybits,rp));
        }
    }
    portable_mutex_unlock(&myinfo->DEX_reqmutex);
    if ( requests != (void *)space )
        free(requests);
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

char *basilisk_respond_accept(struct supernet_info *myinfo,uint32_t requestid,uint32_t quoteid,char *msgjsonstr)
{
    int32_t i,num=0; char *retstr=0; struct basilisk_request *requests,*rp; uint8_t space[16384];
    portable_mutex_lock(&myinfo->DEX_reqmutex);
    if ( (requests= _basilisk_requests_uniq(myinfo,&num,space,sizeof(space))) != 0 )
    {
        for (i=0; i<num; i++)
        {
            rp = &requests[i];
            if ( rp->requestid == requestid && rp->quoteid == quoteid )
            {
                retstr = basilisk_start(myinfo,rp,1);
                break;
            }
        }
    }
    portable_mutex_unlock(&myinfo->DEX_reqmutex);
    if ( requests != (void *)space )
        free(requests);
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"couldnt find to requestid to choose\"}");
    return(retstr);
}

// respond to incoming RID, ACC, DEX, QST

char *basilisk_respond_RID(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    return(basilisk_respond_requests(myinfo,hash,juint(valsobj,"requestid"),0));
}

char *basilisk_respond_SWP(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    return(basilisk_respond_swapstatus(myinfo,hash,juint(valsobj,"requestid"),juint(valsobj,"quoteid")));
}

char *basilisk_respond_ACC(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    uint32_t requestid,quoteid; char *retstr,*msgstr=0;
    if ( (requestid= juint(valsobj,"requestid")) != 0 && (quoteid= juint(valsobj,"quoteid")) != 0 )
    {
        if ( jobj(valsobj,"message") != 0 )
            msgstr = jprint(jobj(valsobj,"message"),0);
        retstr = basilisk_respond_accept(myinfo,requestid,quoteid,msgstr);
        if ( msgstr != 0 )
            free(msgstr);
        return(retstr);
    }
    return(clonestr("{\"error\":\"need nonzero requestid and quoteid\"}"));
}

char *basilisk_respond_DEX(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk)
{
    char *retstr=0,buf[256]; struct basilisk_request R;
    if ( basilisk_request_create(&R,valsobj,hash,juint(valsobj,"timestamp")) == 0 )
    {
        char str[65]; printf("DEX.(%s %.8f) -> %s %s\n",R.src,dstr(R.srcamount),R.dest,bits256_str(str,hash));
        if ( basilisk_request_enqueue(myinfo,&R,R.message) != 0 )
        {
            sprintf(buf,"{\"result\":\"DEX request added\",\"requestid\":%u}",R.requestid);
            retstr = clonestr(buf);
        } else retstr = clonestr("{\"error\":\"DEX quote couldnt be created\"}");
    } else retstr = clonestr("{\"error\":\"missing or invalid fields\"}");
    return(retstr);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

THREE_STRINGS_AND_DOUBLE(tradebot,aveprice,comment,base,rel,basevolume)
{
    double retvals[4],aveprice; cJSON *retjson = cJSON_CreateObject();
    aveprice = instantdex_avehbla(myinfo,retvals,base,rel,basevolume);
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"aveprice",aveprice);
    jaddnum(retjson,"avebid",retvals[0]);
    jaddnum(retjson,"bidvol",retvals[1]);
    jaddnum(retjson,"aveask",retvals[2]);
    jaddnum(retjson,"askvol",retvals[3]);
    return(jprint(retjson,1));
}

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
    if ( source != 0 && source[0] != 0 && (coin= iguana_coinfind(source)) != 0 )
    {
        if ( myinfo->expiration != 0 )
            return(bitcoinrpc_getbalance(myinfo,coin,json,remoteaddr,"*",coin->chain->minconfirms,1,1<<30));
        else return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    } else return(clonestr("{\"error\":\"specified coin is not active\"}"));
}

HASH_ARRAY_STRING(InstantDEX,request,hash,vals,hexstr)
{
    cJSON *msgobj = cJSON_CreateObject();
    myinfo->DEXactive = (uint32_t)time(NULL) + INSTANTDEX_LOCKTIME;
    jadd64bits(msgobj,"min",jdouble(vals,"minprice") * jdouble(vals,"amount") * SATOSHIDEN);
    jaddnum(msgobj,"auto",juint(vals,"autoflag"));
    jadd(vals,"message",msgobj);
    if ( jobj(vals,"desthash") == 0 )
        jaddbits256(vals,"desthash",hash);
    jadd64bits(vals,"satoshis",jdouble(vals,"amount") * SATOSHIDEN);
    jadd64bits(vals,"destsatoshis",jdouble(vals,"destamount") * SATOSHIDEN);
    jaddnum(vals,"timestamp",time(NULL));
    hash = myinfo->myaddr.persistent;
    printf("service.(%s)\n",jprint(vals,0));
    {
        uint8_t serialized[522]; struct basilisk_request R; cJSON *reqjson;
        memset(&R,0,sizeof(R));
        if ( basilisk_request_create(&R,vals,hash,juint(vals,"timestamp")) == 0 )
        {
            printf("R.requestid.%u vs calc %u, q.%u\n",R.requestid,basilisk_requestid(&R),R.quoteid);
            if ( (reqjson= basilisk_requestjson(R.relaybits,&R)) != 0 )
                free_json(reqjson);
            printf("R.requestid.%u vs calc %u, q.%u\n",R.requestid,basilisk_requestid(&R),R.quoteid);
            basilisk_rwDEXquote(1,serialized,&R);
            basilisk_rwDEXquote(0,serialized,&R);
        } else printf("error creating request\n");
    }
    return(basilisk_standardservice("DEX",myinfo,0,myinfo->myaddr.persistent,vals,"",1));
}

INT_ARG(InstantDEX,automatched,requestid)
{
    // return quoteid
    myinfo->DEXactive = (uint32_t)time(NULL) + INSTANTDEX_LOCKTIME;
    return(clonestr("{\"result\":\"automatched not yet\"}"));
}

INT_ARG(InstantDEX,incoming,requestid)
{
    cJSON *vals; char *retstr;
    myinfo->DEXactive = (uint32_t)time(NULL) + INSTANTDEX_LOCKTIME;
    if ( myinfo->RELAYID >= 0 )
        return(basilisk_respond_requests(myinfo,myinfo->myaddr.persistent,requestid,0));
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

TWO_INTS(InstantDEX,swapstatus,requestid,quoteid)
{
    cJSON *vals; char *retstr;
    myinfo->DEXactive = (uint32_t)time(NULL) + INSTANTDEX_LOCKTIME;
    if ( myinfo->RELAYID >= 0 )
        return(basilisk_respond_swapstatus(myinfo,myinfo->myaddr.persistent,requestid,quoteid));
    else
    {
        vals = cJSON_CreateObject();
        jaddnum(vals,"requestid",requestid);
        jaddnum(vals,"quoteid",quoteid);
        jaddbits256(vals,"hash",myinfo->myaddr.persistent);
        retstr = basilisk_standardservice("SWP",myinfo,0,myinfo->myaddr.persistent,vals,"",1);
        free_json(vals);
        return(retstr);
    }
}

TWO_INTS(InstantDEX,accept,requestid,quoteid)
{
    struct basilisk_request R,*other; cJSON *vals,*retjson; char *retstr,*msgjsonstr = "{\"state\":1}";
    myinfo->DEXactive = (uint32_t)time(NULL) + INSTANTDEX_LOCKTIME;
    if ( myinfo->RELAYID >= 0 )
        return(basilisk_respond_accept(myinfo,requestid,quoteid,msgjsonstr));
    else
    {
        vals = cJSON_CreateObject();
        jaddnum(vals,"quoteid",quoteid);
        jaddnum(vals,"requestid",requestid);
        jadd(vals,"message",cJSON_Parse(msgjsonstr));
        if ( (retstr= basilisk_standardservice("ACC",myinfo,0,myinfo->myaddr.persistent,vals,"",1)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                other = basilisk_parsejson(&R,jobj(retjson,"req"));
                if ( basilisk_thread_start(myinfo,other) != 0 )
                    printf("START thread to complete %u/%u for %s %.8f) <- (%s %.8f)\n",other->requestid,R.quoteid,other->src,dstr(other->srcamount),other->dest,dstr(other->destamount));
                else printf("ERROR starting atomic swap thread\n");
                free(retjson);
            }
        }
        free_json(vals);
        return(retstr);
    }
}
#include "../includes/iguana_apiundefs.h"

int32_t basilisk_request_cmpref(struct basilisk_request *ref,struct basilisk_request *rp)
{
    if ( bits256_cmp(rp->hash,ref->hash) != 0 || memcmp(rp->src,ref->src,sizeof(ref->src)) != 0 || memcmp(rp->dest,ref->dest,sizeof(ref->dest)) != 0 || rp->srcamount != ref->srcamount || rp->timestamp != ref->timestamp )
    {
        printf("basilisk_request_listprocess mismatched hash\n");
        return(-1);
    } else return(0);
}

double basilisk_request_listprocess(struct supernet_info *myinfo,struct basilisk_request *issueR,struct basilisk_request *list,int32_t n)
{
    int32_t i,noquoteflag=0,havequoteflag=0,myrequest=0,maxi=-1,autoflag=0; cJSON *statejson,*msgobj=0; uint64_t destamount,minamount = 0,maxamount = 0; uint32_t pendingid=0,statebits; struct basilisk_swap *active; double metric = 0.;
    memset(issueR,0,sizeof(*issueR));
    printf("need to verify null quoteid is list[0] requestid.%u quoteid.%u\n",list[0].requestid,list[0].quoteid);
    if ( (active= basilisk_request_started(myinfo,list[0].requestid)) != 0 )
        pendingid = active->req.quoteid;
    if ( bits256_cmp(myinfo->myaddr.persistent,list[0].hash) == 0 ) // my request
        myrequest = 1;
    if ( list[0].message[0] != 0 && (msgobj= cJSON_Parse(list[0].message)) != 0 )
    {
        autoflag = juint(msgobj,"auto");
        minamount = j64bits(msgobj,"min");
    }
    for (i=0; i<n; i++)
    {
        if ( basilisk_request_cmpref(&list[0],&list[i]) != 0 )
            return(-1);
        if ( list[i].quoteid != 0 )
        {
            if ( bits256_cmp(myinfo->myaddr.persistent,list[i].desthash) == 0 ) // my quoteid
                myrequest |= 2;
            havequoteflag++;
            if ( pendingid == 0 )
            {
                if ( list[i].destamount > maxamount )
                {
                    maxamount = list[i].destamount;
                    maxi = i;
                }
            }
            else if ( active != 0 && pendingid == list[i].quoteid )
            {
                if ( (statejson= cJSON_Parse(list[i].message)) != 0 )
                {
                    statebits = juint(statejson,"state");
                    if ( bitweight(statebits) > bitweight(active->statebits) )
                    {
                        // advance statemachine
                        //active->statebits = statebits;
                        printf("req statbits.%x -> %x\n",active->statebits,statebits);
                    }
                    free(statejson);
                }
            }
        } else noquoteflag++;
    }
    printf("myrequest.%d pendingid.%u noquoteflag.%d havequoteflag.%d\n",myrequest,pendingid,noquoteflag,havequoteflag);
    if ( myrequest == 0 && pendingid == 0 && noquoteflag != 0 )
    {
        double retvals[4],aveprice;
        aveprice = instantdex_avehbla(myinfo,retvals,list[0].src,list[0].dest,dstr(list[0].srcamount));
        destamount = 0.99 * aveprice * list[0].srcamount;
        printf("destamount %.8f aveprice %.8f minamount %.8f\n",dstr(destamount),aveprice,dstr(minamount));
        if ( destamount >= maxamount && destamount >= minamount )
        {
            metric = 1.;
            *issueR = list[0];
            issueR->desthash = myinfo->myaddr.persistent;
            issueR->destamount = destamount;
        }
    }
    else if ( myrequest != 0 && pendingid == 0 && maxi >= 0 ) // automatch best quote
    {
        if ( maxamount > minamount && autoflag != 0 && time(NULL) > BASILISK_DEXDURATION/2 )
        {
            printf("automatch quoteid.%u triggered %.8f > %.8f\n",list[maxi].quoteid,dstr(maxamount),dstr(minamount));
            *issueR = list[maxi];
            if ( minamount > 0 )
                metric = (dstr(maxamount) / dstr(minamount)) - 1.;
            else metric = 1.;
        }
    }
    if ( msgobj != 0 )
        free_json(msgobj);
    return(metric);
}

void basilisk_requests_poll(struct supernet_info *myinfo)
{
    char *retstr; cJSON *retjson,*array,*item; int32_t i,n,m; struct basilisk_request tmpR,R,issueR,refR,list[BASILISK_MAXRELAYS*10]; double metric=0.,hwm = 0.;
    memset(&issueR,0,sizeof(issueR));
    /*{
        double retvals[4],aveprice; uint64_t destamount;
        aveprice = instantdex_avehbla(myinfo,retvals,"BTCD","BTC",1);
        destamount = 0.99 * aveprice * 1 * SATOSHIDEN;
        printf("destamount %.8f aveprice %.8f\n",dstr(destamount),aveprice);
    }*/
    if ( (retstr= InstantDEX_incoming(myinfo,0,0,0,0)) != 0 )
    {
        //printf("poll.(%s)\n",retstr);
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (array= jarray(&n,retjson,"result")) != 0 )
            {
                for (i=m=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( i != 0 )
                    {
                        basilisk_parsejson(&R,item);
                        if ( refR.requestid == R.requestid )
                            list[m++] = R;
                        else
                        {
                            if ( (metric= basilisk_request_listprocess(myinfo,&tmpR,list,m)) > hwm )
                                issueR = tmpR, hwm = metric;
                            m = 0;
                        }
                    }
                    if ( m < sizeof(list)/sizeof(*list) )
                        basilisk_parsejson(&list[m++],item);
                }
                if ( m > 0 && m < sizeof(list)/sizeof(*list) )
                    if ( (metric= basilisk_request_listprocess(myinfo,&tmpR,list,m)) > hwm )
                        issueR = tmpR, hwm = metric;
            }
            free_json(retjson);
        }
        free(retstr);
    }
    printf("hwm %f\n",hwm);
    if ( hwm > 0. )
    {
        if ( bits256_cmp(myinfo->myaddr.persistent,issueR.hash) == 0 ) // my request
        {
            if ( (retstr= InstantDEX_accept(myinfo,0,0,0,issueR.requestid,issueR.quoteid)) != 0 )
                free(retstr);
        }
        else if ( issueR.quoteid == 0 )
        {
            if ( (retstr= basilisk_start(myinfo,&issueR,0)) != 0 )
                free(retstr);
        } else printf("basilisk_requests_poll unexpected hwm issueR\n");
    }
}
