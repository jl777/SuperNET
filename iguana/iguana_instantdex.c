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

// selftest supports against allpairs list

#include "exchanges777.h"

#define INSTANTDEX_HOPS 2
#define INSTANTDEX_DURATION 60

#define INSTANTDEX_INSURANCERATE (1. / 777.)
#define INSTANTDEX_PUBEY "03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06"
#define INSTANTDEX_RMD160 "ca1e04745e8ca0c60d8c5881531d51bec470743f"
#define TIERNOLAN_RMD160 "daedddd8dbe7a2439841ced40ba9c3d375f98146"
#define INSTANTDEX_BTC "1KRhTPvoxyJmVALwHFXZdeeWFbcJSbkFPu"
#define INSTANTDEX_BTCD "RThtXup6Zo7LZAi8kRWgjAyi1s4u6U9Cpf"
#define INSTANTDEX_MINPERC 50.

struct instantdex_event { char cmdstr[24],sendcmd[16]; struct instantdex_stateinfo *nextstate; };

struct instantdex_stateinfo
{
    char name[24];
    cJSON *(*process)(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,cJSON *argjson,uint8_t **serdatap,int32_t *serdatalenp);
    cJSON *(*timeout)(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,cJSON *argjson,uint8_t **serdatap,int32_t *serdatalenp);
    struct instantdex_stateinfo *timeoutevent,*errorevent;
    struct instantdex_event *events; int32_t numevents;
};

struct bitcoin_swapinfo
{
    bits256 privkeys[777],mypubs[2],otherpubs[2],privAm,pubAm,privBn,pubBn;
    bits256 orderhash,dtxid,ptxid,aptxid,astxid,stxid,ftxid,othertrader;
    uint64_t otherscut[777][2],deck[777][2],satoshis[2],insurance,bidid,askid;
    int32_t isbob,choosei,otherschoosei,cutverified,otherverifiedcut;
    double minperc;
    char altmsigaddr[64],*deposit,*payment,*altpayment,*altspend,*spendtx,*feetx;
    struct instantdex_stateinfo *state; uint32_t expiration;
};
struct instantdex_stateinfo *BTC_states; int32_t BTC_numstates;

cJSON *instantdex_defaultprocess(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,cJSON *argjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    cJSON *newjson=0; uint8_t *serdata = *serdatap; int32_t serdatalen = *serdatalenp;
    *serdatap = 0, *serdatalenp = 0;
    if ( serdata != 0 && serdatalen > 0 )
    {
        serdata[serdatalen-1] = 0;
    }
    return(newjson);
}

cJSON *instantdex_defaulttimeout(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,cJSON *argjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    cJSON *newjson=0; uint8_t *serdata = *serdatap; int32_t serdatalen = *serdatalenp;
    *serdatap = 0, *serdatalenp = 0;
    if ( serdata != 0 && serdatalen > 0 )
    {
        serdata[serdatalen-1] = 0;
    }
    return(newjson);
}

struct instantdex_stateinfo instantdex_errorstate = { "error", instantdex_defaultprocess, instantdex_defaulttimeout };
struct instantdex_stateinfo instantdex_timeoutstate = { "timeout", instantdex_defaultprocess, instantdex_defaulttimeout };

struct instantdex_stateinfo *instantdex_statefind(struct instantdex_stateinfo *states,int32_t numstates,char *statename)
{
    int32_t i; struct instantdex_stateinfo *state = 0;
    if ( states != 0 && statename != 0 && numstates > 0 )
    {
        for (i=0; i<numstates; i++)
        {
            if ( (state= &states[i]) != 0 && strcmp(state->name,statename) == 0 )
                return(state);
        }
    }
    return(0);
}

struct instantdex_stateinfo *instantdex_statecreate(struct instantdex_stateinfo *states,int32_t *numstatesp,char *name,cJSON *(*process_func)(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,cJSON *argjson,uint8_t **serdatap,int32_t *serdatalenp),cJSON *(*timeout_func)(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,cJSON *argjson,uint8_t **serdatap,int32_t *serdatalenp),char *timeoutstr,char *errorstr)
{
    struct instantdex_stateinfo *timeoutstate,*errorstate,*state = 0;
    if ( (state= instantdex_statefind(states,*numstatesp,name)) == 0 )
    {
        states = realloc(states,sizeof(*states) * (*numstatesp + 1));
        state = &states[*numstatesp];
        strcpy(state->name,name);
        if ( (errorstate= instantdex_statefind(states,*numstatesp,errorstr)) == 0 )
            errorstate = &instantdex_errorstate;
        state->errorevent = errorstate;
        if ( (timeoutstate= instantdex_statefind(states,*numstatesp,timeoutstr)) == 0 )
            timeoutstate = &instantdex_timeoutstate;
        state->timeoutevent = timeoutstate;
        if ( (state->process= process_func) == 0 )
            state->process = instantdex_defaultprocess;
        if ( (state->timeout= timeout_func) == 0 )
            state->timeout = instantdex_defaulttimeout;
        (*numstatesp)++;
    } else printf("statecreate error!!! (%s) already exists\n",name);
    return(state);
}

struct instantdex_event *instantdex_addevent(struct instantdex_stateinfo *states,int32_t numstates,char *statename,char *cmdstr,char *sendcmd,char *nextstatename)
{
    struct instantdex_stateinfo *nextstate,*state;
    if ( (state= instantdex_statefind(states,numstates,statename)) != 0 && (nextstate= instantdex_statefind(states,numstates,nextstatename)) != 0 )
    {
        if ( (state->events= realloc(state->events,(state->numevents + 1) * sizeof(*state->events))) != 0 )
        {
            strcpy(state->events[state->numevents].cmdstr,cmdstr);
            strcpy(state->events[state->numevents].sendcmd,sendcmd);
            state->events[state->numevents].nextstate = nextstate;
            state->numevents++;
        }
        return(state->events);
    }
    else
    {
        printf("cant add event (%s -> %s) without existing state and nextstate\n",statename,nextstatename);
        return(0);
    }
}

cJSON *InstantDEX_argjson(char *reference,char *message,char *othercoinaddr,char *otherNXTaddr,int32_t iter,int32_t val,int32_t val2)
{
    cJSON *argjson = cJSON_CreateObject();
    if ( reference != 0 )
        jaddstr(argjson,"refstr",reference);
    if ( message != 0 && message[0] != 0 )
        jaddstr(argjson,"message",message);
    if ( othercoinaddr != 0 && othercoinaddr[0] != 0 )
        jaddstr(argjson,"othercoinaddr",othercoinaddr);
    if ( otherNXTaddr != 0 && otherNXTaddr[0] != 0 )
        jaddstr(argjson,"otherNXTaddr",otherNXTaddr);
    //jaddbits256(argjson,"basetxid",basetxid);
    //jaddbits256(argjson,"reltxid",reltxid);
    if ( iter != 3 )
    {
        if ( val == 0 )
            val = INSTANTDEX_DURATION;
        jaddnum(argjson,"duration",val);
        jaddnum(argjson,"flags",val2);
    }
    else
    {
        if ( val > 0 )
            jaddnum(argjson,"baseheight",val);
        if ( val2 > 0 )
            jaddnum(argjson,"relheight",val2);
    }
    return(argjson);
}

struct instantdex_msghdr *instantdex_msgcreate(struct supernet_info *myinfo,struct instantdex_msghdr *msg,int32_t datalen)
{
    bits256 otherpubkey; uint64_t signerbits; uint32_t timestamp; uint8_t buf[sizeof(msg->sig)],*data;
    memset(&msg->sig,0,sizeof(msg->sig));
    datalen += (int32_t)(sizeof(*msg) - sizeof(msg->sig));
    data = (void *)((long)msg + sizeof(msg->sig));
    otherpubkey = acct777_msgpubkey(data,datalen);
    timestamp = (uint32_t)time(NULL);
    acct777_sign(&msg->sig,myinfo->privkey,otherpubkey,timestamp,data,datalen);
    //printf("signed datalen.%d allocsize.%d crc.%x\n",datalen,msg->sig.allocsize,calc_crc32(0,data,datalen));
    if ( (signerbits= acct777_validate(&msg->sig,acct777_msgprivkey(data,datalen),msg->sig.pubkey)) != 0 )
    {
        //int32_t i;
        //char str[65],str2[65];
        //for (i=0; i<datalen; i++)
        //    printf("%02x",data[i]);
        //printf(">>>>>>>>>>>>>>>> validated [%ld] len.%d (%s + %s)\n",(long)data-(long)msg,datalen,bits256_str(str,acct777_msgprivkey(data,datalen)),bits256_str(str2,msg->sig.pubkey));
        memset(buf,0,sizeof(buf));
        acct777_rwsig(1,buf,&msg->sig);
        memcpy(&msg->sig,buf,sizeof(buf));
        return(msg);
    } else printf("error validating instantdex msg\n");
    return(0);
}

bits256 instantdex_rwoffer(int32_t rwflag,int32_t *lenp,uint8_t *serialized,struct instantdex_offer *offer)
{
    bits256 orderhash; int32_t len = 0;
    if ( rwflag == 1 )
    {
        vcalc_sha256(0,orderhash.bytes,(void *)offer,sizeof(*offer));
        /*int32_t i;
        for (i=0; i<sizeof(*offer); i++)
            printf("%02x ",((uint8_t *)offer)[i]);
        printf("rwoffer offer\n");*/
    }
    else
    {
        memset(offer,0,sizeof(*offer));
    }
    len += iguana_rwstr(rwflag,&serialized[len],sizeof(offer->base),offer->base);
    len += iguana_rwstr(rwflag,&serialized[len],sizeof(offer->rel),offer->rel);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(offer->price64),&offer->price64);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(offer->basevolume64),&offer->basevolume64);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(offer->offer64),&offer->offer64);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(offer->expiration),&offer->expiration);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(offer->nonce),&offer->nonce);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(offer->myside),&offer->myside);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(offer->acceptdir),&offer->acceptdir);
    if ( rwflag == 0 )
    {
        vcalc_sha256(0,orderhash.bytes,(void *)offer,sizeof(*offer));
        /*int32_t i;
        for (i=0; i<len; i++)
            printf("%02x ",serialized[i]);
        printf("read rwoffer serialized\n");
        for (i=0; i<sizeof(*offer); i++)
            printf("%02x ",((uint8_t *)offer)[i]);
        printf("rwoffer offer\n");*/
    }
    /*else
    {
        int32_t i;
        for (i=0; i<len; i++)
            printf("%02x ",serialized[i]);
        printf("wrote rwoffer serialized\n");
    }*/
    *lenp = len;
    return(orderhash);
}

char *instantdex_sendcmd(struct supernet_info *myinfo,struct instantdex_offer *offer,cJSON *argjson,char *cmdstr,bits256 desthash,int32_t hops,void *extraser,int32_t extralen)
{
    char *reqstr,*hexstr,*retstr; struct instantdex_msghdr *msg; bits256 instantdexhash,orderhash;
    int32_t i,olen,slen,datalen; uint8_t serialized[sizeof(*offer) + 2]; uint64_t nxt64bits;
    instantdexhash = calc_categoryhashes(0,"InstantDEX",0);
    category_subscribe(myinfo,instantdexhash,GENESIS_PUBKEY);
    jaddstr(argjson,"cmd",cmdstr);
    jaddstr(argjson,"agent","SuperNET");
    jaddstr(argjson,"method","DHT");
    jaddstr(argjson,"handle",myinfo->handle);
    jaddbits256(argjson,"categoryhash",instantdexhash);
    jaddbits256(argjson,"traderpub",myinfo->myaddr.persistent);
    orderhash = instantdex_rwoffer(1,&olen,serialized,offer);
    if ( 1 )
    {
        struct instantdex_offer checkoffer; bits256 checkhash; int32_t checklen;
        checkhash = instantdex_rwoffer(0,&checklen,serialized,&checkoffer);
        if ( checkhash.txid != orderhash.txid )
        {
            for (i=0; i<sizeof(checkoffer); i++)
                printf("%02x ",((uint8_t *)&checkoffer)[i]);
            printf("checklen.%d checktxid.%llu\n",checklen,(long long)checkhash.txid);
        }
    }
    jadd64bits(argjson,"id",orderhash.txid);
    nxt64bits = acct777_nxt64bits(myinfo->myaddr.persistent);
    reqstr = jprint(argjson,0);
    slen = (int32_t)(strlen(reqstr) + 1);
    datalen = (int32_t)slen + extralen + olen;
    msg = calloc(1,datalen + sizeof(*msg));
    for (i=0; i<sizeof(msg->cmd); i++)
        if ( (msg->cmd[i]= cmdstr[i]) == 0 )
            break;
    memcpy(msg->serialized,reqstr,slen);
    memcpy(&msg->serialized[slen],serialized,olen);
    //printf("extralen.%d datalen.%d slen.%d olen.%d\n",extralen,datalen,slen,olen);
    if ( extralen > 0 )
        memcpy(&msg->serialized[slen + olen],extraser,extralen);
    free(reqstr);
    if ( instantdex_msgcreate(myinfo,msg,datalen) != 0 )
    {
        printf(">>>>>>>>>>>> instantdex send.(%s) datalen.%d allocsize.%d crc.%x\n",cmdstr,datalen,msg->sig.allocsize,calc_crc32(0,(void *)((long)msg + 8),datalen-8));
        hexstr = malloc(msg->sig.allocsize*2 + 1);
        init_hexbytes_noT(hexstr,(uint8_t *)msg,msg->sig.allocsize);
        retstr = SuperNET_categorymulticast(myinfo,0,instantdexhash,desthash,hexstr,0,hops,1,argjson,0);
        free_json(argjson), free(hexstr), free(msg);
        return(retstr);
    }
    else
    {
        free_json(argjson), free(msg);
        printf("cant msgcreate datalen.%d\n",datalen);
        return(clonestr("{\"error\":\"couldnt create instantdex message\"}"));
    }
}

int32_t instantdex_updatesources(struct exchange_info *exchange,struct exchange_quote *sortbuf,int32_t n,int32_t max,int32_t ind,int32_t dir,struct exchange_quote *quotes,int32_t numquotes)
{
    int32_t i; struct exchange_quote *quote;
    //printf("instantdex_updatesources update dir.%d numquotes.%d\n",dir,numquotes);
    for (i=0; i<numquotes; i++)
    {
        quote = &quotes[i << 1];
        //printf("n.%d ind.%d i.%d dir.%d price %.8f vol %.8f\n",n,ind,i,dir,quote->price,quote->volume);
        if ( quote->price > SMALLVAL )
        {
            sortbuf[n] = *quote;
            sortbuf[n].val = ind;
            sortbuf[n].exchangebits = exchange->exchangebits;
            //printf("sortbuf[%d] <-\n",n*2);
            if ( ++n >= max )
                break;
        }
    }
    return(n);
}

double instantdex_aveprice(struct supernet_info *myinfo,struct exchange_quote *sortbuf,int32_t max,double *totalvolp,char *base,char *rel,double basevolume,cJSON *argjson)
{
    char *str; double totalvol,pricesum; uint32_t timestamp;
    struct exchange_quote quote; int32_t i,n,dir,num,depth = 100;
    struct exchange_info *exchange; struct exchange_request *req,*active[64];
    timestamp = (uint32_t)time(NULL);
    if ( basevolume < 0. )
        basevolume = -basevolume, dir = -1;
    else dir = 1;
    memset(sortbuf,0,sizeof(*sortbuf) * max);
    if ( base != 0 && rel != 0 && basevolume > SMALLVAL )
    {
        for (i=num=0; i<myinfo->numexchanges && num < sizeof(active)/sizeof(*active); i++)
        {
            if ( (exchange= myinfo->tradingexchanges[i]) != 0 )
            {
                if ( (req= exchanges777_baserelfind(exchange,base,rel,'M')) == 0 )
                {
                    if ( (str= exchanges777_Qprices(exchange,base,rel,30,1,depth,argjson,1,exchange->commission)) != 0 )
                        free(str);
                    req = exchanges777_baserelfind(exchange,base,rel,'M');
                }
                if ( req == 0 )
                {
                    if ( (*exchange->issue.supports)(exchange,base,rel,argjson) != 0 )
                        printf("unexpected null req.(%s %s) %s\n",base,rel,exchange->name);
                }
                else
                {
                    //printf("active.%s\n",exchange->name);
                    active[num++] = req;
                }
            }
        }
        for (i=n=0; i<num; i++)
        {
            if ( dir < 0 && active[i]->numbids > 0 )
                n = instantdex_updatesources(active[i]->exchange,sortbuf,n,max,i,1,active[i]->bidasks,active[i]->numbids);
            else if ( dir > 0 && active[i]->numasks > 0 )
                n = instantdex_updatesources(active[i]->exchange,sortbuf,n,max,i,-1,&active[i]->bidasks[1],active[i]->numasks);
        }
        //printf("dir.%d %s/%s numX.%d n.%d\n",dir,base,rel,num,n);
        if ( dir < 0 )
            revsort64s(&sortbuf[0].satoshis,n,sizeof(*sortbuf));
        else sort64s(&sortbuf[0].satoshis,n,sizeof(*sortbuf));
        for (totalvol=pricesum=i=0; i<n && totalvol < basevolume; i++)
        {
            quote = sortbuf[i];
            //printf("n.%d i.%d price %.8f %.8f %.8f\n",n,i,dstr(sortbuf[i].satoshis),sortbuf[i].price,quote.volume);
            if ( quote.satoshis != 0 )
            {
                pricesum += (quote.price * quote.volume);
                totalvol += quote.volume;
                printf("i.%d of %d %12.8f vol %.8f %s | aveprice %.8f total vol %.8f\n",i,n,sortbuf[i].price,quote.volume,active[quote.val]->exchange->name,pricesum/totalvol,totalvol);
            }
        }
        if ( totalvol > 0. )
        {
            *totalvolp = totalvol;
            return(pricesum / totalvol);
        }
    }
    *totalvolp = 0;
    return(0);
}

double instantdex_avehbla(struct supernet_info *myinfo,double retvals[4],char *base,char *rel,double basevolume)
{
    double avebid,aveask,bidvol,askvol; struct exchange_quote sortbuf[256]; cJSON *argjson;
    argjson = cJSON_CreateObject();
    aveask = instantdex_aveprice(myinfo,sortbuf,sizeof(sortbuf)/sizeof(*sortbuf),&askvol,base,rel,basevolume,argjson);
    avebid = instantdex_aveprice(myinfo,sortbuf,sizeof(sortbuf)/sizeof(*sortbuf),&bidvol,base,rel,-basevolume,argjson);
    free_json(argjson);
    retvals[0] = avebid, retvals[1] = bidvol, retvals[2] = aveask, retvals[3] = askvol;
    if ( avebid > SMALLVAL && aveask > SMALLVAL )
        return((avebid + aveask) * .5);
    else return(0);
}

int32_t instantdex_bidaskdir(struct instantdex_accept *ap)
{
    if ( ap->offer.myside == 0 && ap->offer.acceptdir > 0 ) // base
        return(-1);
    else if ( ap->offer.myside == 1 && ap->offer.acceptdir < 0 ) // rel
        return(1);
    else return(0);
}

cJSON *instantdex_acceptjson(struct instantdex_accept *ap)
{
    int32_t dir;
    cJSON *item = cJSON_CreateObject();
    jadd64bits(item,"orderid",ap->orderid);
    jadd64bits(item,"offerer",ap->offer.offer64);
    if ( ap->dead != 0 )
        jadd64bits(item,"dead",ap->dead);
    if ( (dir= instantdex_bidaskdir(ap)) > 0 )
        jaddstr(item,"type","bid");
    else if ( dir < 0 )
        jaddstr(item,"type","ask");
    else
    {
        jaddstr(item,"type","strange");
        jaddnum(item,"acceptdir",ap->offer.acceptdir);
        jaddnum(item,"myside",ap->offer.myside);
    }
    jaddstr(item,"base",ap->offer.base);
    jaddstr(item,"rel",ap->offer.rel);
    jaddnum(item,"timestamp",ap->offer.expiration);
    jaddnum(item,"price",dstr(ap->offer.price64));
    jaddnum(item,"volume",dstr(ap->offer.basevolume64));
    jaddnum(item,"nonce",ap->offer.nonce);
    jaddnum(item,"pendingvolume",dstr(ap->pendingvolume64));
    jaddnum(item,"expiresin",ap->offer.expiration - time(NULL));
    return(item);
}

struct instantdex_accept *instantdex_pendingfind(struct supernet_info *myinfo,struct exchange_info *exchange,uint64_t orderid)
{
    struct instantdex_accept PAD,*ap,*retap = 0; uint32_t now;
    now = (uint32_t)time(NULL);
    memset(&PAD,0,sizeof(PAD));
    queue_enqueue("pendingQ",&exchange->pendingQ,&PAD.DL,0);
    while ( (ap= queue_dequeue(&exchange->pendingQ,0)) != 0 && ap != &PAD )
    {
        if ( now < ap->offer.expiration && ap->dead == 0 )
        {
            if ( orderid == ap->orderid )
                retap = ap;
        }
        else
        {
            printf("expired pending, need to take action\n");
        }
        queue_enqueue("pendingQ",&exchange->pendingQ,&PAD.DL,0);
    }
    return(retap);
}

struct instantdex_accept *instantdex_offerfind(struct supernet_info *myinfo,struct exchange_info *exchange,cJSON *bids,cJSON *asks,uint64_t orderid,char *base,char *rel,int32_t requeue)
{
    struct instantdex_accept PAD,*ap,*retap = 0; uint32_t now; cJSON *item; char *type;
    now = (uint32_t)time(NULL);
    memset(&PAD,0,sizeof(PAD));
    queue_enqueue("acceptableQ",&exchange->acceptableQ,&PAD.DL,0);
    while ( (ap= queue_dequeue(&exchange->acceptableQ,0)) != 0 && ap != &PAD )
    {
        if ( now < ap->offer.expiration && ap->dead == 0 )
        {
            //printf("find cmps %d %d %d %d %d %d\n",strcmp(base,"*") == 0,strcmp(base,ap->offer.base) == 0,strcmp(rel,"*") == 0,strcmp(rel,ap->offer.rel) == 0,orderid == 0,orderid == ap->orderid);
            if ( (strcmp(base,"*") == 0 || strcmp(base,ap->offer.base) == 0) && (strcmp(rel,"*") == 0 || strcmp(rel,ap->offer.rel) == 0) && (orderid == 0 || orderid == ap->orderid) )
            {
                printf("found match.%p\n",ap);
                if ( requeue == 0 && retap != 0 )
                    queue_enqueue("acceptableQ",&exchange->acceptableQ,&retap->DL,0);
                retap = ap;
            }
            if ( (item= instantdex_acceptjson(ap)) != 0 )
            {
                //printf("item.(%s)\n",jprint(item,0));
                if ( (type= jstr(item,"type")) != 0 )
                {
                    if ( strcmp(type,"bid") == 0 && bids != 0 )
                        jaddi(bids,item);
                    else if ( strcmp(type,"ask") == 0 && asks != 0 )
                        jaddi(asks,item);
                }
            }
            if ( ap != retap || requeue != 0 )
            {
                printf("requeue.%p\n",ap);
                queue_enqueue("acceptableQ",&exchange->acceptableQ,&ap->DL,0);
            }
        } else free(ap);
    }
    return(retap);
}

struct instantdex_accept *instantdex_acceptable(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,uint64_t offerbits,double minperc)
{
    struct instantdex_accept PAD,*ap,*retap = 0; double aveprice,retvals[4];
    uint64_t minvol,bestprice64 = 0; uint32_t now; int32_t offerdir;
    aveprice = instantdex_avehbla(myinfo,retvals,A->offer.base,A->offer.rel,dstr(A->offer.basevolume64));
    now = (uint32_t)time(NULL);
    memset(&PAD,0,sizeof(PAD));
    queue_enqueue("acceptableQ",&exchange->acceptableQ,&PAD.DL,0);
    offerdir = instantdex_bidaskdir(A);
    minvol = A->offer.basevolume64 * minperc * .01;
    while ( (ap= queue_dequeue(&exchange->acceptableQ,0)) != 0 && ap != &PAD )
    {
        if ( now < ap->offer.expiration && ap->dead == 0 && (offerbits == 0 || offerbits != ap->offer.offer64) )
        {
            //printf("check offerbits.%llu vs %llu: %d %d %d %d %d %d %d %d\n",(long long)offerbits,(long long)ap->offer.offer64,A->offer.basevolume64 > 0.,strcmp(A->offer.base,"*") == 0 ,strcmp(A->offer.base,ap->offer.base) == 0, strcmp(A->offer.rel,"*") == 0 ,strcmp(A->offer.rel,ap->offer.rel) == 0,A->offer.basevolume64 <= (ap->offer.basevolume64 - ap->pendingvolume64),offerdir,instantdex_bidaskdir(ap));
            if ( A->offer.basevolume64 > 0. && (strcmp(A->offer.base,"*") == 0 || strcmp(A->offer.base,ap->offer.base) == 0) && (strcmp(A->offer.rel,"*") == 0 || strcmp(A->offer.rel,ap->offer.rel) == 0) && minvol <= (ap->offer.basevolume64 - ap->pendingvolume64) && offerdir*instantdex_bidaskdir(ap) < 0 )
            {
                //printf("aveprice %.8f %.8f offerdir.%d first cmp: %d %d %d\n",aveprice,dstr(ap->offer.price64),offerdir,A->offer.price64 == 0,(offerdir > 0 && ap->offer.price64 >= A->offer.price64),(offerdir < 0 && ap->offer.price64 <= A->offer.price64));
                if ( offerdir == 0 || A->offer.price64 == 0 || ((offerdir < 0 && ap->offer.price64 >= A->offer.price64) || (offerdir > 0 && ap->offer.price64 <= A->offer.price64)) )
                {
                    //printf("passed second cmp: offerdir.%d best %.8f ap %.8f\n",offerdir,dstr(bestprice64),dstr(ap->offer.price64));
                    if ( bestprice64 == 0 || (offerdir < 0 && ap->offer.price64 < bestprice64) || (offerdir > 0 && ap->offer.price64 > bestprice64) )
                    {
                        //printf("found better price %f vs %f\n",dstr(ap->offer.price64),dstr(bestprice64));
                        bestprice64 = ap->offer.price64;
                        if ( retap != 0 )
                            queue_enqueue("acceptableQ",&exchange->acceptableQ,&retap->DL,0);
                        retap = ap;
                    }
                }
            }
            if ( ap != retap)
                queue_enqueue("acceptableQ",&exchange->acceptableQ,&ap->DL,0);
        } else free(ap);
    }
    return(retap);
}

// NXTrequest:
// sends NXT assetid, volume and desired
// request:
// other node sends (othercoin, othercoinaddr, otherNXT and reftx that expires well before phasedtx)
// proposal:
// NXT node submits phasedtx that refers to it, but it wont confirm
// approve:
// other node verifies unconfirmed has phasedtx and broadcasts cltv, also to NXT node, releases trigger
// confirm:
// NXT node verifies bitcoin txbytes has proper payment and cashes in with onetimepubkey
// BTC* node approves phased tx with onetimepubkey

bits256 instantdex_acceptset(struct instantdex_accept *ap,char *base,char *rel,int32_t duration,int32_t myside,int32_t acceptdir,double price,double volume,uint64_t offerbits,uint32_t nonce)
{
    bits256 hash;
    memset(ap,0,sizeof(*ap));
    safecopy(ap->offer.base,base,sizeof(ap->offer.base));
    safecopy(ap->offer.rel,rel,sizeof(ap->offer.rel));
    if ( nonce == 0 )
        OS_randombytes((uint8_t *)&ap->offer.nonce,sizeof(ap->offer.nonce));
    else ap->offer.nonce = nonce;
    if ( duration < 1000000000 )
        ap->offer.expiration = (uint32_t)time(NULL) + duration;
    else ap->offer.expiration = duration;
    ap->offer.offer64 = offerbits;
    ap->offer.myside = myside;
    ap->offer.acceptdir = acceptdir;
    ap->offer.price64 = price * SATOSHIDEN;
    ap->offer.basevolume64 = volume * SATOSHIDEN;
    vcalc_sha256(0,hash.bytes,(void *)&ap->offer,sizeof(ap->offer));
    ap->orderid = hash.txid;
    //int32_t i;
    //for (i=0; i<sizeof(ap->offer); i++)
    //    printf("%02x ",((uint8_t *)&ap->offer)[i]);
    //printf("\n(%s/%s) %.8f %.8f acceptdir.%d myside.%d\n",base,rel,price,volume,acceptdir,myside);
    return(hash);
}

int32_t instantdex_acceptextract(struct instantdex_accept *ap,cJSON *argjson)
{
    char *base,*rel; bits256 hash,traderpub; double price,volume; int32_t baserel,acceptdir;
    memset(ap,0,sizeof(*ap));
    if ( (base= jstr(argjson,"base")) != 0 )
    {
        volume = jdouble(argjson,"volume");
        if ( (rel= jstr(argjson,"rel")) != 0 )
            safecopy(ap->offer.rel,rel,sizeof(ap->offer.rel));
        if ( (price= jdouble(argjson,"maxprice")) > SMALLVAL )
        {
            baserel = 1;
            acceptdir = -1;
        }
        else if ( (price= jdouble(argjson,"minprice")) > SMALLVAL )
        {
            baserel = 0;
            acceptdir = 1;
        } else return(-1);
        //printf("price %f vol %f baserel.%d acceptdir.%d\n",price,volume,baserel,acceptdir);
        traderpub = jbits256(argjson,"traderpub");
        hash = instantdex_acceptset(ap,base,rel,INSTANTDEX_LOCKTIME*2,baserel,acceptdir,price,volume,traderpub.txid,0);
    }
    else
    {
        if ( (base= jstr(argjson,"b")) != 0 )
            safecopy(ap->offer.base,base,sizeof(ap->offer.base));
        if ( (rel= jstr(argjson,"r")) != 0 )
            safecopy(ap->offer.rel,rel,sizeof(ap->offer.rel));
        ap->offer.nonce = juint(argjson,"n");
        ap->offer.expiration = juint(argjson,"e");
        ap->offer.myside = juint(argjson,"s");
        ap->offer.acceptdir = jint(argjson,"d");
        ap->offer.offer64 = j64bits(argjson,"o");
        ap->offer.price64 = j64bits(argjson,"p");
        ap->offer.basevolume64 = j64bits(argjson,"v");
        vcalc_sha256(0,hash.bytes,(void *)&ap->offer,sizeof(ap->offer));
        ap->orderid = j64bits(argjson,"id");
    }
    if ( hash.txid != ap->orderid )
    {
        int32_t i;
        for (i=0; i<sizeof(*ap); i++)
            printf("%02x ",((uint8_t *)ap)[i]);
        printf("instantdex_acceptextract warning %llu != %llu\n",(long long)hash.txid,(long long)ap->orderid);
        return(-1);
    }
    return(0);
}

#include "swaps/iguana_BTCswap.c"
#include "swaps/iguana_ALTswap.c"
#include "swaps/iguana_NXTswap.c"
#include "swaps/iguana_PAXswap.c"

char *instantdex_swapset(struct supernet_info *myinfo,struct instantdex_accept *A,cJSON *argjson)
{
    uint64_t satoshis[2]; int32_t offerdir = 0; double minperc; uint64_t insurance,relsatoshis;
    struct bitcoin_swapinfo *swap; bits256 orderhash,traderpub; struct iguana_info *coinbtc;
    if ( (swap= A->info) == 0 )
        return(clonestr("{\"error\":\"no swapinfo set\"}"));
    relsatoshis = instantdex_relsatoshis(A->offer.price64,A->offer.basevolume64);
    traderpub = jbits256(argjson,"traderpub");
    if ( (minperc= jdouble(argjson,"p")) < INSTANTDEX_MINPERC )
        minperc = INSTANTDEX_MINPERC;
    if ( (coinbtc= iguana_coinfind("BTC")) == 0 )
        return(clonestr("{\"error\":\"no BTC found\"}"));
    insurance = (satoshis[1] * INSTANTDEX_INSURANCERATE + coinbtc->chain->txfee); // txfee prevents papercut attack
    offerdir = instantdex_bidaskdir(A);
    vcalc_sha256(0,orderhash.bytes,(void *)&A->offer,sizeof(A->offer));
    if ( offerdir > 0 )
        swap->bidid = A->orderid;
    else swap->askid = A->orderid;
    if ( bits256_nonz(swap->othertrader) == 0 )
        swap->othertrader = traderpub;
    else if ( bits256_cmp(traderpub,swap->othertrader) != 0 )
    {
        printf("competing offer received for (%s/%s) %.8f %.8f\n",A->offer.base,A->offer.rel,dstr(A->offer.price64),dstr(A->offer.basevolume64));
        return(clonestr("{\"error\":\"no competing offers for now\"}"));
    }
    if ( bits256_nonz(swap->orderhash) == 0 )
        swap->orderhash = orderhash;
    else if ( bits256_cmp(orderhash,swap->orderhash) != 0 )
    {
        printf("orderhash %llx mismatch %llx\n",(long long)swap->orderhash.txid,(long long)orderhash.txid);
        return(clonestr("{\"error\":\"orderhash mismatch???\"}"));
    }
    swap->satoshis[0] = A->offer.basevolume64;
    swap->satoshis[1] = relsatoshis;
    swap->insurance = (relsatoshis * INSTANTDEX_INSURANCERATE + coinbtc->chain->txfee); // txfee
    if ( swap->minperc < minperc )
        swap->minperc = minperc;
    return(0);
}

char *instantdex_btcoffer(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,cJSON *argjson) // Bob sending to network (Alice)
{
    struct iguana_info *other; struct bitcoin_swapinfo *swap; int32_t isbob; cJSON *newjson; char *retstr;
    if ( strcmp(A->offer.rel,"BTC") != 0 )
    {
        printf("rel not BTC?!\n");
        return(clonestr("{\"error\":\"invalid othercoin\"}"));
    }
    else if ( (other= iguana_coinfind(A->offer.base)) == 0 )
        return(clonestr("{\"error\":\"invalid othercoin\"}"));
    else if ( A->offer.price64 <= 0 || A->offer.basevolume64 <= 0 )
    {
        printf("illegal price %.8f or volume %.8f\n",dstr(A->offer.price64),dstr(A->offer.basevolume64));
        return(clonestr("{\"error\":\"illegal price or volume\"}"));
    }
    isbob = (A->offer.myside == 1);
    swap = calloc(1,sizeof(struct bitcoin_swapinfo)), swap->isbob = isbob, swap->choosei = swap->otherschoosei = -1;
    A->info = swap;
    if ( (retstr= instantdex_swapset(myinfo,A,argjson)) != 0 )
        return(retstr);
    A->orderid = swap->orderhash.txid;
    if ( (newjson= instantdex_newjson(myinfo,swap,argjson,swap->orderhash,A,1)) == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap offer null newjson\"}"));
    if ( instantdex_pubkeyargs(swap,newjson,777+2,myinfo->persistent_priv,swap->orderhash,0x02+isbob) != 777+2 )
    {
        printf("error from pubkeyargs\n");
        free(swap), free(A);
        return(clonestr("{\"error\":\"highly unlikely run of 02 pubkeys\"}"));
    }
    else
    {
        queue_enqueue("pendingQ",&exchange->pendingQ,&A->DL,0);
        swap->state = instantdex_statefind(BTC_states,BTC_numstates,swap->isbob != 0 ? "BOB_sentoffer" : "ALICE_sentoffer");
        return(instantdex_sendcmd(myinfo,&A->offer,newjson,"BTCoffer",GENESIS_PUBKEY,INSTANTDEX_HOPS,swap->deck,sizeof(swap->deck)));
    }
}

char *instantdex_gotoffer(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *serdata,int32_t serdatalen) // receiving side
{
    struct bitcoin_swapinfo *swap = 0; bits256 orderhash,traderpub;
    struct iguana_info *coinbtc,*altcoin; cJSON *newjson=0; char *retstr=0;
    swap = A->info;
    coinbtc = iguana_coinfind("BTC");
    traderpub = jbits256(argjson,"traderpub");
    if ( bits256_cmp(traderpub,myinfo->myaddr.persistent) == 0 )
    {
        printf("got my own packet\n");
        return(clonestr("{\"result\":\"got my own packet\"}"));
    }
    printf("T.%d got (%s/%s) %.8f vol %.8f %llu offerside.%d offerdir.%d swap.%p decksize.%ld/datalen.%d\n",bits256_cmp(traderpub,myinfo->myaddr.persistent),A->offer.base,A->offer.rel,dstr(A->offer.price64),dstr(A->offer.basevolume64),(long long)A->orderid,A->offer.myside,A->offer.acceptdir,A->info,sizeof(swap->deck),serdatalen);
    if ( exchange == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap null exchange ptr\"}"));
    if ( (altcoin= iguana_coinfind(A->offer.base)) == 0 || coinbtc == 0 )
    {
        printf("other.%p coinbtc.%p (%s/%s)\n",altcoin,coinbtc,A->offer.base,A->offer.rel);
        return(clonestr("{\"error\":\"instantdex_BTCswap cant find btc or other coin info\"}"));
    }
    if ( strcmp(A->offer.rel,"BTC") != 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap offer non BTC rel\"}"));
    if ( A->offer.expiration < (time(NULL) + INSTANTDEX_DURATION) )
        return(clonestr("{\"error\":\"instantdex_BTCswap offer too close to expiration\"}"));
    if ( A->info == 0 )
    {
        A->info = swap = calloc(1,sizeof(struct bitcoin_swapinfo));
        swap->choosei = swap->otherschoosei = -1;
        swap->isbob = (A->offer.myside ^ 1);
        if ( (retstr= instantdex_swapset(myinfo,A,argjson)) != 0 )
            return(retstr);
        if ( instantdex_pubkeyargs(swap,newjson,2+777,myinfo->persistent_priv,swap->orderhash,0x02 + swap->isbob) != 2+777 )
        {
            printf("error generating pubkeyargs\n");
            return(0);
        }
        char str[65]; printf("GOT OFFER! %p (%s/%s) other.%s myside.%d\n",A->info,A->offer.base,A->offer.rel,bits256_str(str,traderpub),swap->isbob);
        if ( (newjson= instantdex_newjson(myinfo,swap,argjson,orderhash,A,1)) == 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap offer null newjson\"}"));
        else
        {
            // verify feetx
            instantdex_pendingnotice(myinfo,exchange,A,A->offer.basevolume64);
            if ( (retstr= instantdex_choosei(swap,newjson,argjson,serdata,serdatalen)) != 0 )
                return(retstr);
            else
            {
                // generate feetx to send
                swap->state = instantdex_statefind(BTC_states,BTC_numstates,swap->isbob != 0 ? "BOB_gotoffer" : "ALICE_gotoffer");
                return(instantdex_sendcmd(myinfo,&A->offer,newjson,"BTCchose",traderpub,INSTANTDEX_HOPS,swap->deck,sizeof(swap->deck)));
            }
        }
    } else return(clonestr("{\"error\":\"couldnt allocate swap info\"}"));
}

char *instantdex_parse(struct supernet_info *myinfo,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,struct instantdex_offer *offer,bits256 orderhash,uint8_t *serdata,int32_t serdatalen)
{
    char cmdstr[16]; struct exchange_info *exchange; double minperc;
    struct instantdex_accept A,*ap = 0; bits256 traderpub;
    if ( BTC_states == 0 )
        BTC_states = BTC_initFSM(&BTC_numstates);
    exchange = exchanges777_find("bitcoin");
    memset(cmdstr,0,sizeof(cmdstr)), memcpy(cmdstr,msg->cmd,sizeof(msg->cmd));
    if ( argjson != 0 )
    {
        traderpub = jbits256(argjson,"traderpub");
        memset(&A,0,sizeof(A));
        if ( j64bits(argjson,"id") != orderhash.txid )
        {
            printf("orderhash %llu mismatch id.%llu\n",(long long)orderhash.txid,(long long)j64bits(argjson,"id"));
            return(clonestr("{\"error\":\"orderhash mismatch\"}"));
        }
        A.offer = *offer;
        A.orderid = orderhash.txid;
        if ( strcmp(cmdstr,"BTCoffer") == 0 )
        {
            if ( (minperc= jdouble(argjson,"p")) < INSTANTDEX_MINPERC )
                minperc = INSTANTDEX_MINPERC;
            if ( (ap= instantdex_acceptable(myinfo,exchange,&A,acct777_nxt64bits(traderpub),minperc)) != 0 )
            {
                return(instantdex_gotoffer(myinfo,exchange,ap,msg,argjson,remoteaddr,signerbits,serdata,serdatalen));
            }
            else
            {
                printf("no matching trade for %llu -> InstantDEX_minaccept isbob.%d\n",(long long)A.orderid,A.offer.myside);
                if ( instantdex_offerfind(myinfo,exchange,0,0,A.orderid,"*","*",1) == 0 )
                {
                    ap = calloc(1,sizeof(*ap));
                    *ap = A;
                    queue_enqueue("acceptableQ",&exchange->acceptableQ,&ap->DL,0);
                    return(clonestr("{\"result\":\"added new order to orderbook\"}"));
                } else return(clonestr("{\"result\":\"order was already in orderbook\"}"));
            }
        }
        else if ( (ap= instantdex_pendingfind(myinfo,exchange,A.orderid)) != 0 )
        {
            if ( ap->info == 0 )
            {
                printf("null swap for orderid.%llu\n",(long long)ap->orderid);
                return(clonestr("{\"error\":\"no swap for orderid\"}"));
            }
            return(instantdex_statemachine(myinfo,exchange,ap,cmdstr,argjson,serdata,serdatalen));
        }
        else
        {
            printf("cant find existing order.%llu that matches\n",(long long)A.orderid);
            return(clonestr("{\"error\":\"cant find matching order\"}"));
        }
    }
    return(clonestr("{\"error\":\"request needs argjson\"}"));
}

char *InstantDEX_hexmsg(struct supernet_info *myinfo,void *ptr,int32_t len,char *remoteaddr)
{
    struct instantdex_msghdr *msg = ptr; int32_t i,olen,slen,num,datalen,newlen,flag = 0;
    uint8_t *serdata; struct supernet_info *myinfos[64]; struct instantdex_offer rawoffer;
    bits256 orderhash; uint64_t signerbits; uint8_t tmp[sizeof(msg->sig)]; char *retstr = 0;
    cJSON *retjson,*item,*argjson = 0;
    if ( BTC_states == 0 )
        BTC_states = BTC_initFSM(&BTC_numstates);
    datalen = len  - (int32_t)sizeof(msg->sig);
    serdata = (void *)((long)msg + sizeof(msg->sig));
    //printf("a signed datalen.%d allocsize.%d crc.%x\n",datalen,msg->sig.allocsize,calc_crc32(0,serdata,datalen));
    acct777_rwsig(0,(void *)&msg->sig,(void *)tmp);
    memcpy(&msg->sig,tmp,sizeof(msg->sig));
   // printf("b signed datalen.%d allocsize.%d crc.%x\n",datalen,msg->sig.allocsize,calc_crc32(0,serdata,datalen));
    if ( remoteaddr != 0 && remoteaddr[0] == 0 && strcmp("127.0.0.1",remoteaddr) == 0 && ((uint8_t *)msg)[len-1] == 0 && (argjson= cJSON_Parse((char *)msg)) != 0 )
    {
        printf("string instantdex_hexmsg RESULT.(%s)\n",jprint(argjson,0));
        free_json(argjson);
        return(clonestr("{\"error\":\"string base packets deprecated\"}"));
    }
    //printf("msg.%p len.%d data.%p datalen.%d crc.%u %s\n",msg,len,data,datalen,calc_crc32(0,(void *)msg,len),bits256_str(str,msg->sig.pubkey));
    //return(0);
    else if ( (signerbits= acct777_validate(&msg->sig,acct777_msgprivkey(serdata,datalen),msg->sig.pubkey)) != 0 || 1 )
    {
        flag++;
        //printf("InstantDEX_hexmsg <<<<<<<<<<<<< sigsize.%ld VALIDATED [%ld] len.%d t%u allocsize.%d (%s) [%d]\n",sizeof(msg->sig),(long)serdata-(long)msg,datalen,msg->sig.timestamp,msg->sig.allocsize,(char *)msg->serialized,serdata[datalen-1]);
        newlen = (int32_t)(msg->sig.allocsize - ((long)msg->serialized - (long)msg));
        serdata = msg->serialized;
        //printf("newlen.%d diff.%ld alloc.%d datalen.%d\n",newlen,((long)msg->serialized - (long)msg),msg->sig.allocsize,datalen);
        if ( (argjson= cJSON_Parse((char *)serdata)) != 0 )
        {
            slen = (int32_t)strlen((char *)serdata) + 1;
            serdata = &serdata[slen];
            newlen -= slen;
        }
        if ( newlen > 0 )
        {
            orderhash = instantdex_rwoffer(0,&olen,serdata,&rawoffer);
            newlen -= olen;
            //newlen -= ((long)msg->serialized - (long)msg);
            serdata = &serdata[olen];
            //printf("received orderhash.%llu olen.%d slen.%d newlen.%d\n",(long long)orderhash.txid,olen,slen,newlen);
        } else olen = 0;
        if ( newlen <= 0 )
            serdata = 0, newlen = 0;
        if ( serdata != 0 || argjson != 0 )
        {
            //printf("CALL instantdex_parse.(%s)\n",argjson!=0?jprint(argjson,0):"");
            retjson = cJSON_CreateArray();
            if ( (num= SuperNET_MYINFOS(myinfos,sizeof(myinfos)/sizeof(*myinfos))) == 0 )
            {
                myinfos[0] = myinfo;
                num = 1;
            }
            for (i=0; i<num; i++)
            {
                myinfo = myinfos[i];
                //char str[65]; printf("i.%d of %d: %s\n",i,num,bits256_str(str,myinfo->myaddr.persistent));
                if ( (retstr= instantdex_parse(myinfo,msg,argjson,remoteaddr,signerbits,&rawoffer,orderhash,serdata,newlen)) != 0 )
                {
                    item = cJSON_CreateObject();
                    jaddstr(item,"result",retstr);
                    if ( myinfo->handle[0] != 0 )
                        jaddstr(item,"handle",myinfo->handle);
                    jaddbits256(item,"traderpub",myinfo->myaddr.persistent);
                    jaddi(retjson,item);
                }
            }
            retstr = jprint(retjson,1);
        }
    } else printf("sig err datalen.%d\n",datalen);
    if ( argjson != 0 )
        free_json(argjson);
    return(retstr);
}

char *instantdex_queueaccept(struct supernet_info *myinfo,struct instantdex_accept **aptrp,struct exchange_info *exchange,char *base,char *rel,double price,double basevolume,int32_t acceptdir,char *mysidestr,int32_t duration,uint64_t offerer,int32_t queueflag)
{
    struct instantdex_accept *ap; int32_t myside; char *retstr;
    *aptrp = 0;
    if ( exchange != 0 )
    {
        *aptrp = ap = calloc(1,sizeof(*ap));
        if ( strcmp(mysidestr,base) == 0 )
            myside = 0;
        else if ( strcmp(mysidestr,rel) == 0 )
            myside = 1;
        else
        {
            myside = -1;
            printf("myside.(%s) != base.%s or rel.%s\n",mysidestr,base,rel);
        }
        instantdex_acceptset(ap,base,rel,duration,myside,acceptdir,price,basevolume,offerer,0);
        if ( queueflag != 0 )
            queue_enqueue("acceptableQ",&exchange->acceptableQ,&ap->DL,0);
        retstr = jprint(instantdex_acceptjson(ap),1);
        //printf("acceptableQ %llu (%s)\n",(long long)ap->orderid,retstr);
        return(retstr);
    } else return(clonestr("{\"error\":\"invalid exchange\"}"));
}

void instantdex_update(struct supernet_info *myinfo)
{
    struct instantdex_msghdr *pm; struct category_msg *m; int32_t iter; bits256 instantdexhash; char *str,remote[64];
    instantdexhash = calc_categoryhashes(0,"InstantDEX",0);
    for (iter=0; iter<2; iter++)
    {
        while ( (m= category_gethexmsg(myinfo,instantdexhash,iter == 0 ? GENESIS_PUBKEY : myinfo->myaddr.persistent)) != 0 )
        {
            //printf("gothexmsg len.%d\n",m->len);
            pm = (struct instantdex_msghdr *)m->msg;
            if ( m->remoteipbits != 0 )
                expand_ipbits(remote,m->remoteipbits);
            else remote[0] = 0;
            if ( (str= InstantDEX_hexmsg(myinfo,pm,m->len,remote)) != 0 )
                free(str);
            free(m);
        }
    }
}

#include "../includes/iguana_apidefs.h"

TWO_STRINGS_AND_TWO_DOUBLES(InstantDEX,maxaccept,base,rel,maxprice,basevolume)
{
    struct instantdex_accept *ap;
    myinfo = SuperNET_accountfind(json);
    if ( remoteaddr == 0 )
        return(instantdex_queueaccept(myinfo,&ap,exchanges777_find("bitcoin"),base,rel,maxprice,basevolume,-1,rel,INSTANTDEX_OFFERDURATION,myinfo->myaddr.nxt64bits,1));
    else return(clonestr("{\"error\":\"InstantDEX API request only local usage!\"}"));
}

TWO_STRINGS_AND_TWO_DOUBLES(InstantDEX,minaccept,base,rel,minprice,basevolume)
{
    struct instantdex_accept *ap;
    myinfo = SuperNET_accountfind(json);
    if ( remoteaddr == 0 )
        return(instantdex_queueaccept(myinfo,&ap,exchanges777_find("bitcoin"),base,rel,minprice,basevolume,1,base,INSTANTDEX_OFFERDURATION,myinfo->myaddr.nxt64bits,1));
    else return(clonestr("{\"error\":\"InstantDEX API request only local usage!\"}"));
}
#include "../includes/iguana_apiundefs.h"

