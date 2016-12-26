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

#ifdef ENABLE_DEXPING
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
                        //printf("[(%s %.8f) -> (%s %.8f) r.%u q.%u] ",R.src,dstr(R.srcamount),R.dest,dstr(R.destamount),R.requestid,R.quoteid);
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
        } //else printf("now.%u vs timestamp.%u, lag.%d\n",now,timestamp,now-timestamp);
    }
    portable_mutex_unlock(&myinfo->DEX_mutex);
    sn = i;
    iguana_rwnum(1,data,sizeof(sn),&sn); // fill in at beginning
    return(datalen);
}
#endif

int32_t basilisk_rwDEXquote(int32_t rwflag,uint8_t *serialized,struct basilisk_request *rp)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->requestid),&rp->requestid);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->timestamp),&rp->timestamp); // must be 2nd
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->quoteid),&rp->quoteid);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->quotetime),&rp->quotetime);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->optionhours),&rp->optionhours);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->srcamount),&rp->srcamount);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->minamount),&rp->minamount);
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
    if ( rp->quoteid != 0 && basilisk_quoteid(rp) != rp->quoteid )
        printf(" basilisk_rwDEXquote.%d: quoteid.%u mismatch calc %u\n",rwflag,rp->quoteid,basilisk_quoteid(rp));
    if ( basilisk_requestid(rp) != rp->requestid )
        printf(" basilisk_rwDEXquote.%d: requestid.%u mismatch calc %u\n",rwflag,rp->requestid,basilisk_requestid(rp));
    return(len);
}

uint32_t basilisk_request_enqueue(struct supernet_info *myinfo,struct basilisk_request *rp)
{
    uint8_t serialized[256]; int32_t len; struct queueitem *item;
    printf("basilisk_request_enqueue\n");
    len = basilisk_rwDEXquote(1,serialized+1,rp);
    if ( (item= calloc(1,sizeof(*item) + len + 1)) != 0 )
    {
        serialized[0] = len;
        memcpy(&item[1],serialized,len + 1);
        portable_mutex_lock(&myinfo->DEX_mutex);
        DL_APPEND(myinfo->DEX_quotes,item);
        portable_mutex_unlock(&myinfo->DEX_mutex);
        printf("ENQUEUE.%u calc.%u\n",rp->requestid,basilisk_requestid(rp));
        return(rp->requestid);
    }
    return(0);
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
    if ( rp->minamount != 0 )
        jadd64bits(item,"minamount",rp->minamount);
    jaddstr(item,"dest",rp->dest);
    if ( rp->destamount != 0 )
        jadd64bits(item,"destamount",rp->destamount);
    jaddnum(item,"quotetime",rp->quotetime);
    jaddnum(item,"timestamp",rp->timestamp);
    jaddnum(item,"requestid",rp->requestid);
    jaddnum(item,"quoteid",rp->quoteid);
    jaddnum(item,"optionhours",rp->optionhours);
    jaddnum(item,"profit",(double)rp->profitmargin / 1000000.);
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
                printf(" <- rp\n");
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

int32_t basilisk_request_create(struct basilisk_request *rp,cJSON *valsobj,bits256 desthash,uint32_t timestamp)
{
    char *dest,*src; uint32_t i;
    memset(rp,0,sizeof(*rp));
    if ( (dest= jstr(valsobj,"dest")) != 0 && (src= jstr(valsobj,"source")) != 0 && (rp->srcamount= j64bits(valsobj,"satoshis")) != 0 )
    {
        if ( (rp->destamount= j64bits(valsobj,"destsatoshis")) != 0 )
        {
            rp->desthash = desthash;
            for (i=0; i<4; i++)
                if ( rp->desthash.ulongs[i] != 0 )
                    break;
            if ( i != 4 )
                rp->destamount = 0;
        }
        rp->minamount = j64bits(valsobj,"minamount");
        rp->timestamp = timestamp;
        rp->srchash = jbits256(valsobj,"srchash");
        rp->optionhours = jint(valsobj,"optionhours");
        rp->profitmargin = jdouble(valsobj,"profit") * 1000000;
        strncpy(rp->src,src,sizeof(rp->src)-1);
        strncpy(rp->dest,dest,sizeof(rp->dest)-1);
        //if ( jstr(valsobj,"relay") != 0 )
        //    rp->relaybits = (uint32_t)calc_ipbits(jstr(valsobj,"relay"));
        rp->requestid = basilisk_requestid(rp);
        //printf("set requestid <- %u\n",rp->requestid);
        if ( rp->destamount != 0 && bits256_nonz(rp->desthash) != 0 )
        {
            rp->quoteid = basilisk_quoteid(rp);
            //printf("set quoteid.%u\n",rp->quoteid);
        }
        //printf("create.%u calc.%u\n",rp->requestid,basilisk_requestid(rp));
        return(0);
    }
    return(-1);
}

char *basilisk_start(struct supernet_info *myinfo,struct basilisk_request *_rp,uint32_t statebits,int32_t optionduration)
{
    cJSON *retjson; struct basilisk_request *rp;
    if ( (bits256_cmp(_rp->srchash,myinfo->myaddr.persistent) == 0 || bits256_cmp(_rp->desthash,myinfo->myaddr.persistent) == 0) )
    {
        rp = calloc(1,sizeof(*rp));
        *rp = *_rp;
        printf("START thread to complete %u/%u for (%s %.8f) <-> (%s %.8f) q.%u\n",rp->requestid,rp->quoteid,rp->src,dstr(rp->srcamount),rp->dest,dstr(rp->destamount),rp->quoteid);
        if ( basilisk_thread_start(myinfo,rp,statebits,optionduration) != 0 )
        {
            basilisk_request_enqueue(myinfo,rp);
            return(clonestr("{\"result\":\"started atomic swap thread\"}"));
        }
        else return(clonestr("{\"error\":\"couldnt atomic swap thread\"}"));
    }
    else if ( myinfo->IAMLP != 0 )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","basilisk node needs to start atomic thread locally");
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"unexpected basilisk_start not mine and amrelay\"}"));
}

void basilisk_requests_poll(struct supernet_info *myinfo)
{
    static uint32_t lastpoll;
    char *retstr; uint8_t data[32768],buf[4096]; cJSON *outerarray,*retjson; uint32_t msgid,crcs[2],crc,channel; int32_t datalen,i,n,numiters; struct basilisk_request issueR; double hwm = 0.;
    if ( time(NULL) < lastpoll+3 )
        return;
    lastpoll = (uint32_t)time(NULL);
    memset(&issueR,0,sizeof(issueR));
    memset(&myinfo->DEXaccept,0,sizeof(myinfo->DEXaccept));
    //printf("Call incoming\n");
    if ( (retstr= InstantDEX_incoming(myinfo,0,0,0,0)) != 0 )
    {
        //printf("poll.(%s)\n",retstr);
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (outerarray= jarray(&n,retjson,"responses")) != 0 )
            {
                for (i=0; i<n; i++)
                    hwm = basilisk_process_results(myinfo,&issueR,jitem(outerarray,i),hwm);
            } //else hwm = basilisk_process_results(myinfo,&issueR,outerarray,hwm);
            free_json(retjson);
        }
        free(retstr);
    } else printf("null incoming\n");
    channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
    if ( hwm > 0. )
    {
        //printf("hwm %f\n",hwm);
        //for (i=0; i<sizeof(issueR); i++)
        //    printf("%02x",((uint8_t *)&issueR)[i]);
        //printf("\n");
        myinfo->DEXaccept = issueR;
        /*issueR.quoteid = basilisk_quoteid(&issueR);
        datalen = basilisk_rwDEXquote(1,data,&issueR);
        msgid = (uint32_t)time(NULL);
        keylen = basilisk_messagekey(key,0,msgid,issueR.srchash,issueR.desthash);
        if ( (retstr= basilisk_respond_addmessage(myinfo,key,keylen,data,datalen,0,BASILISK_DEXDURATION)) != 0 )
            free(retstr);*/
        if ( bits256_cmp(myinfo->myaddr.persistent,issueR.srchash) == 0 ) // my request
        {
            printf("my req hwm %f\n",hwm);
            if ( (retstr= InstantDEX_accept(myinfo,0,0,0,issueR.requestid,issueR.quoteid)) != 0 )
                free(retstr);
            basilisk_channelsend(myinfo,issueR.srchash,issueR.desthash,channel,0x4000000,(void *)&issueR.requestid,sizeof(issueR.requestid),60);
            numiters = 0;
            while ( numiters < 10 && (crc= basilisk_crcsend(myinfo,0,buf,sizeof(buf),issueR.srchash,issueR.desthash,channel,0x4000000,(void *)&issueR.requestid,sizeof(issueR.requestid),crcs)) == 0 )
            {
                printf("didnt get back what was sent\n");
                sleep(3);
                basilisk_channelsend(myinfo,issueR.srchash,issueR.desthash,channel,0x4000000,(void *)&issueR.requestid,sizeof(issueR.requestid),60);
                numiters++;
            }
            if ( crc != 0 )
            {
                printf("crc.%08x -> basilisk_starta\n",crc);
                if ( (retstr= basilisk_start(myinfo,&issueR,1,issueR.optionhours * 3600)) != 0 )
                    free(retstr);
            } else printf("couldnt accept offer\n");
        }
        else //if ( issueR.quoteid == 0 )
        {
            printf("other req hwm %f >>>>>>>>>>> send response (%llx -> %llx)\n",hwm,(long long)issueR.desthash.txid,(long long)issueR.srchash.txid);
            issueR.quoteid = basilisk_quoteid(&issueR);
            issueR.desthash = myinfo->myaddr.persistent;
            datalen = basilisk_rwDEXquote(1,data,&issueR);
            msgid = (uint32_t)time(NULL);
            crcs[0] = crcs[1] = 0;
            numiters = 0;
            basilisk_channelsend(myinfo,issueR.desthash,issueR.srchash,channel,msgid,data,datalen,INSTANTDEX_LOCKTIME*2);
            while ( numiters < 10 && (crc= basilisk_crcsend(myinfo,0,buf,sizeof(buf),issueR.desthash,issueR.srchash,channel,msgid,data,datalen,crcs)) == 0 )
            {
                //printf("didnt get back what was sent\n");
                sleep(3);
                basilisk_channelsend(myinfo,issueR.desthash,issueR.srchash,channel,msgid,data,datalen,INSTANTDEX_LOCKTIME*2);
                numiters++;
            }
            if ( crc != 0 )
            {
                printf("crc.%08x -> basilisk_start\n",crc);
                if ( (retstr= basilisk_start(myinfo,&issueR,0,issueR.optionhours * 3600)) != 0 )
                    free(retstr);
            }
        } //else printf("basilisk_requests_poll unexpected hwm issueR\n");
    }
}

struct basilisk_relay *basilisk_request_ensure(struct supernet_info *myinfo,uint32_t senderipbits,int32_t numrequests)
{
    int32_t j; struct basilisk_relay *relay = 0;
    if ( (j= basilisk_relayid(myinfo,senderipbits)) >= 0 )
    {
        relay = &myinfo->NOTARY.RELAYS[j];
        if ( numrequests > relay->maxrequests )
        {
            relay->maxrequests = numrequests;
            relay->requests = realloc(relay->requests,sizeof(*relay->requests) * numrequests);
        }
    }
    return(relay);
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

struct basilisk_request *_basilisk_requests_uniq(struct supernet_info *myinfo,int32_t *nump,uint8_t *space,int32_t spacesize,struct basilisk_request *refrp)
{
    int32_t i,j,n,k,m; struct basilisk_relay *relay; struct basilisk_request *requests,*rp;
    m = 0;
    if ( refrp != 0 )
        m = 1;
    for (j=0; j<myinfo->NOTARY.NUMRELAYS; j++)
        m += myinfo->NOTARY.RELAYS[j].numrequests;
    if ( m*sizeof(*requests) <= spacesize )
        requests = (void *)space;
    else requests = calloc(m,sizeof(*requests));
    if ( refrp != 0 )
    {
        requests[0] = *refrp;
        for (i=0; i<sizeof(*refrp); i++)
            printf("%02x",((uint8_t *)refrp)[i]);
        printf(" uniq\n");
    }
    if ( refrp != 0 )
        m = 1;
    else m = 0;
    for (j=0; j<myinfo->NOTARY.NUMRELAYS; j++)
    {
        relay = &myinfo->NOTARY.RELAYS[j];
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
                    //requests[m].relaybits = relay->ipbits;
                    requests[m++] = *rp;
                }
            }
        }
    }
    qsort(requests,m,sizeof(*requests),_cmp_requests);
    *nump = m;
    return(requests);
}

/*char *basilisk_respond_swapstatus(struct supernet_info *myinfo,bits256 hash,uint32_t requestid,uint32_t quoteid)
{
    cJSON *array,*retjson;
    array = cJSON_CreateArray();
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}*/

char *basilisk_respond_requests(struct supernet_info *myinfo,bits256 hash,uint32_t requestid,uint32_t quoteid,struct basilisk_request *refrp)
{
    int32_t i,qflag,num=0; cJSON *retjson,*array; struct basilisk_request *requests,*rp; uint8_t space[4096];
    array = cJSON_CreateArray();
    portable_mutex_lock(&myinfo->DEX_reqmutex);
    if ( (requests= _basilisk_requests_uniq(myinfo,&num,space,sizeof(space),refrp)) != 0 )
    {
        for (i=0; i<num; i++)
        {
            rp = &requests[i];
            if ( quoteid == 0 || (quoteid == rp->quoteid && (bits256_cmp(hash,rp->srchash) == 0 || bits256_cmp(hash,rp->desthash) == 0)) )
                qflag = 1;
            else qflag = 0;
            //int32_t j; for (j=0; j<sizeof(*rp); j++)
            //    printf("%02x",((uint8_t *)rp)[j]);
            //printf(" rp[%d] of %d qflag.%d\n",i,num,qflag);
            if ( requestid == 0 || (rp->requestid == requestid && qflag != 0) )
                jaddi(array,basilisk_requestjson(rp));
        }
    }
    portable_mutex_unlock(&myinfo->DEX_reqmutex);
    if ( requests != (void *)space )
        free(requests);
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

char *basilisk_respond_accept(struct supernet_info *myinfo,uint32_t requestid,uint32_t quoteid,struct basilisk_request *refrp)
{
    int32_t i,num=0; char *retstr=0; struct basilisk_request *requests,*rp; uint8_t space[4096];
    portable_mutex_lock(&myinfo->DEX_reqmutex);
    if ( (requests= _basilisk_requests_uniq(myinfo,&num,space,sizeof(space),refrp)) != 0 )
    {
        for (i=0; i<num; i++)
        {
            rp = &requests[i];
            if ( rp->requestid == requestid && rp->quoteid == quoteid )
            {
                printf("start from accept\n");
                retstr = basilisk_start(myinfo,rp,1,0);
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
    struct iguana_info *tmp; cJSON *basilisk,*virtual,*full,*retjson = cJSON_CreateObject();
    full = cJSON_CreateArray();
    basilisk = cJSON_CreateArray();
    virtual = cJSON_CreateArray();
    HASH_ITER(hh,myinfo->allcoins,coin,tmp)
    {
        if ( coin->virtualchain != 0 )
            jaddistr(virtual,coin->symbol);
        if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
            jaddistr(full,coin->symbol);
        else jaddistr(basilisk,coin->symbol);
    }
    jadd(retjson,"basilisk",basilisk);
    jadd(retjson,"full",full);
    jadd(retjson,"virtual",virtual);
    return(jprint(retjson,1));
}

STRING_ARG(InstantDEX,available,source)
{
    uint64_t total = 0; int32_t i,n=0; cJSON *item,*unspents,*retjson = 0;
    if ( source != 0 && source[0] != 0 && (coin= iguana_coinfind(source)) != 0 )
    {
        if ( myinfo->expiration != 0 )
        {
            if ( (unspents= iguana_listunspents(myinfo,coin,0,0,0,remoteaddr)) != 0 )
            {
                //printf("available.(%s)\n",jprint(unspents,0));
                if ( (n= cJSON_GetArraySize(unspents)) > 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        item = jitem(unspents,i);
                        //if ( jobj(item,"unspent") != 0 )
                        {
                            total += jdouble(item,"amount") * SATOSHIDEN;
                        }
                        //printf("(%s) -> %.8f\n",jprint(item,0),dstr(total));
                    }
                }
                free_json(unspents);
            }
            retjson = cJSON_CreateObject();
            jaddnum(retjson,"result",dstr(total));
            printf(" n.%d total %.8f (%s)\n",n,dstr(total),jprint(retjson,0));
            return(jprint(retjson,1));
        }
        printf("InstantDEX_available: need to unlock wallet\n");
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    }
    printf("InstantDEX_available: %s is not active\n",source!=0?source:"");
    return(clonestr("{\"error\":\"specified coin is not active\"}"));
}

HASH_ARRAY_STRING(InstantDEX,request,hash,vals,hexstr)
{
    uint8_t serialized[512]; char buf[512]; struct basilisk_request R; int32_t iambob,optionhours; cJSON *reqjson; uint32_t datalen=0,DEX_channel; struct iguana_info *bobcoin,*alicecoin;
    myinfo->DEXactive = (uint32_t)time(NULL) + 3*BASILISK_TIMEOUT + 60;
    jadd64bits(vals,"minamount",jdouble(vals,"minprice") * jdouble(vals,"amount") * SATOSHIDEN);
    if ( jobj(vals,"srchash") == 0 )
        jaddbits256(vals,"srchash",myinfo->myaddr.persistent);
    if ( jobj(vals,"desthash") == 0 )
        jaddbits256(vals,"desthash",hash);
    jadd64bits(vals,"satoshis",jdouble(vals,"amount") * SATOSHIDEN);
    jadd64bits(vals,"destsatoshis",jdouble(vals,"destamount") * SATOSHIDEN);
    jaddnum(vals,"timestamp",time(NULL));
    hash = myinfo->myaddr.persistent;
    printf("service.(%s)\n",jprint(vals,0));
    memset(&R,0,sizeof(R));
    if ( basilisk_request_create(&R,vals,hash,juint(vals,"timestamp")) == 0 )
    {
        iambob = bitcoin_coinptrs(myinfo,&bobcoin,&alicecoin,R.src,R.dest,myinfo->myaddr.persistent,GENESIS_PUBKEY);
        if ( (optionhours= jint(vals,"optionhours")) != 0 )
        {
            printf("iambob.%d optionhours.%d R.requestid.%u vs calc %u, q.%u\n",iambob,R.optionhours,R.requestid,basilisk_requestid(&R),R.quoteid);
            if ( iambob != 0 && optionhours > 0 )
            {
                sprintf(buf,"{\"error\":\"illegal call option request hours.%d when iambob.%d\"}",optionhours,iambob);
                printf("ERROR.(%s)\n",buf);
                return(clonestr(buf));
            }
            else if ( iambob == 0 && optionhours < 0 )
            {
                sprintf(buf,"{\"error\":\"illegal put option request hours.%d when iambob.%d\"}",optionhours,iambob);
                printf("ERROR.(%s)\n",buf);
                return(clonestr(buf));
            }
        }
        //if ( myinfo->IAMNOTARY != 0 || myinfo->NOTARY.RELAYID >= 0 )
        //    R.relaybits = myinfo->myaddr.myipbits;
        if ( (reqjson= basilisk_requestjson(&R)) != 0 )
            free_json(reqjson);
        datalen = basilisk_rwDEXquote(1,serialized,&R);
        int32_t i; for (i=0; i<sizeof(R); i++)
            printf("%02x",((uint8_t *)&R)[i]);
        printf(" R.requestid.%u vs calc %u, q.%u datalen.%d\n",R.requestid,basilisk_requestid(&R),R.quoteid,datalen);
        basilisk_rwDEXquote(0,serialized,&R);
    } else printf("error creating request\n");
    if ( datalen > 0 )
    {
        uint32_t msgid,crc,crcs[2],numiters = 0; uint8_t buf[4096];
        memset(hash.bytes,0,sizeof(hash));
        msgid = (uint32_t)time(NULL);
        DEX_channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
        basilisk_channelsend(myinfo,myinfo->myaddr.persistent,hash,DEX_channel,msgid,serialized,datalen,60);
        sleep(3);
        while ( numiters < 10 && (crc= basilisk_crcsend(myinfo,0,buf,sizeof(buf),hash,myinfo->myaddr.persistent,DEX_channel,msgid,serialized,datalen,crcs)) == 0 )
        {
            //printf("didnt get back what was sent\n");
            sleep(3);
            basilisk_channelsend(myinfo,myinfo->myaddr.persistent,hash,DEX_channel,msgid,serialized,datalen,60);
            numiters++;
        }
        if ( crc != 0 )//basilisk_channelsend(myinfo,R.srchash,R.desthash,DEX_channel,(uint32_t)time(NULL),serialized,datalen,30) == 0 )
            return(clonestr("{\"result\":\"DEX message sent\"}"));
        else return(clonestr("{\"error\":\"DEX message couldnt be sent\"}"));
    }
    return(clonestr("{\"error\":\"DEX message not sent\"}"));
}

INT_ARG(InstantDEX,automatched,requestid)
{
    // return quoteid
    myinfo->DEXactive = (uint32_t)time(NULL) + INSTANTDEX_LOCKTIME;
    return(clonestr("{\"result\":\"automatched not yet\"}"));
}

int32_t InstantDEX_incoming_func(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    //int32_t i;
    //for (i=0; i<datalen; i++)
    //    printf("%02x",data[i]);
    //printf(" <- incoming\n");
    return(0);
}

int32_t InstantDEX_process_channelget(struct supernet_info *myinfo,void *ptr,int32_t (*internal_func)(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen),uint32_t channel,uint32_t msgid,uint8_t *data,int32_t datalen,uint32_t expiration,uint32_t duration)
{
    return((*internal_func)(myinfo,ptr,data,datalen));
}

INT_ARG(InstantDEX,incoming,requestid)
{
    cJSON *retjson,*retarray; bits256 zero; uint32_t DEX_channel,msgid,now; int32_t retval,width,drift=3; uint8_t data[32768];
    now = (uint32_t)time(NULL);
    memset(&zero,0,sizeof(zero));
    width = (now - myinfo->DEXpoll) + 2*drift;
    if ( width < (drift+1) )
        width = 2*drift+1;
    else if ( width > 64 )
        width = 64;
    myinfo->DEXpoll = now;
    retjson = cJSON_CreateObject();
    DEX_channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
    msgid = (uint32_t)time(NULL) + drift;
    if ( (retarray= basilisk_channelget(myinfo,zero,myinfo->myaddr.persistent,DEX_channel,msgid,width)) != 0 ) 
    {
        //printf("GOT.(%s)\n",jprint(retarray,0));
        if ( (retval= basilisk_process_retarray(myinfo,0,InstantDEX_process_channelget,data,sizeof(data),DEX_channel,msgid,retarray,InstantDEX_incoming_func)) > 0 )
        {
            jaddstr(retjson,"result","success");
        } else jaddstr(retjson,"error","cant process InstantDEX retarray");
        jadd(retjson,"responses",retarray);
    }
    else
    {
        jaddstr(retjson,"error","cant do InstantDEX channelget");
        printf("error channelget\n");
    }
    return(jprint(retjson,1));
}

/*TWO_INTS(InstantDEX,swapstatus,requestid,quoteid)
{
    cJSON *vals; char *retstr;
    myinfo->DEXactive = (uint32_t)time(NULL) + INSTANTDEX_LOCKTIME;
    //if ( myinfo->IAMLP != 0 )
    //    return(basilisk_respond_swapstatus(myinfo,myinfo->myaddr.persistent,requestid,quoteid));
    //else
    {
        vals = cJSON_CreateObject();
        jaddnum(vals,"requestid",(uint32_t)requestid);
        jaddnum(vals,"quoteid",(uint32_t)quoteid);
        jaddbits256(vals,"hash",myinfo->myaddr.persistent);
        retstr = basilisk_standardservice("SWP",myinfo,0,myinfo->myaddr.persistent,vals,"",1);
        free_json(vals);
        return(retstr);
    }
}*/

TWO_INTS(InstantDEX,accept,requestid,quoteid)
{
    cJSON *vals; char *retstr;
    myinfo->DEXactive = (uint32_t)time(NULL) + INSTANTDEX_LOCKTIME;
    if ( myinfo->IAMLP != 0 || myinfo->dexsock >= 0 || myinfo->subsock >= 0 )
        return(basilisk_respond_accept(myinfo,requestid,quoteid,&myinfo->DEXaccept));
    else
    {
        vals = cJSON_CreateObject();
        jaddnum(vals,"quoteid",(uint32_t)quoteid);
        jaddnum(vals,"requestid",(uint32_t)requestid);
        retstr = basilisk_standardservice("ACC",myinfo,0,myinfo->myaddr.persistent,vals,"",1);
        free_json(vals);
        return(retstr);
    }
}
#include "../includes/iguana_apiundefs.h"
