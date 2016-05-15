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

struct instantdex_stateinfo *BTC_states; int32_t BTC_numstates;

int64_t instantdex_BTCsatoshis(int64_t price,int64_t volume)
{
    if ( volume > price )
        return(price * dstr(volume));
    else return(dstr(price) * volume);
}

int64_t instantdex_insurance(struct iguana_info *coin,int64_t amount)
{
    return(amount * INSTANTDEX_INSURANCERATE + coin->chain->txfee); // insurance prevents attack
}

void instantdex_swapfree(struct instantdex_accept *A,struct bitcoin_swapinfo *swap)
{
    if ( A != 0 )
        free(A);
    if ( swap != 0 )
    {
        if ( swap->deposit != 0 )
            free(swap->deposit);
        if ( swap->payment != 0 )
            free(swap->payment);
        if ( swap->altpayment != 0 )
            free(swap->altpayment);
        if ( swap->myfee != 0 )
            free(swap->myfee);
        if ( swap->otherfee != 0 )
            free(swap->otherfee);
    }
}

int32_t instantdex_unbasebits(char *base,uint64_t basebits)
{
    char tmp[9];
    unstringbits(tmp,basebits);
    if ( iguana_coinfind(tmp) == 0 )
    {
        sprintf(base,"%lld",(long long)basebits);
        return(1);
    }
    else
    {
        strcmp(base,tmp);
        return(0);
    }
}

uint64_t instantdex_basebits(char *base)
{
    if ( is_decimalstr(base) != 0 )
        return(calc_nxt64bits(base));
    else return(stringbits(base));
}

uint64_t instantdex_decodehash(char *base,char *rel,int64_t *pricep,uint64_t *accountp,bits256 encodedhash)
{
    int32_t i; uint64_t offerid;
    base[4] = rel[4] = 0;
    for (i=0; i<4; i++)
    {
        base[i] = encodedhash.bytes[8 + i];
        rel[i] = encodedhash.bytes[12 + i];
    }
    iguana_rwnum(0,(void *)&encodedhash.ulongs[2],sizeof(uint64_t),pricep);
    iguana_rwnum(0,(void *)&encodedhash.ulongs[3],sizeof(uint64_t),accountp);
    iguana_rwnum(0,(void *)&encodedhash.ulongs[0],sizeof(uint64_t),&offerid);
    return(encodedhash.ulongs[0]);
}

bits256 instantdex_encodehash(char *base,char *rel,int64_t price,uint64_t orderid,uint64_t account)
{
    bits256 encodedhash; int32_t i; char _base[4],_rel[4];
    iguana_rwnum(1,(void *)&encodedhash.ulongs[0],sizeof(uint64_t),&orderid);
    memset(_base,0,sizeof(_base));
    memset(_rel,0,sizeof(_rel));
    strncpy(_base,base,4);
    strncpy(_rel,rel,4);
    for (i=0; i<4; i++)
    {
        encodedhash.bytes[8 + i] = _base[i];
        encodedhash.bytes[12 + i] = _rel[i];
    }
    iguana_rwnum(1,(void *)&encodedhash.ulongs[2],sizeof(uint64_t),&price);
    iguana_rwnum(1,(void *)&encodedhash.ulongs[3],sizeof(uint64_t),&account);
    return(encodedhash);
}

cJSON *instantdex_defaultprocess(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    uint8_t *serdata = *serdatap; int32_t serdatalen = *serdatalenp;
    *serdatap = 0, *serdatalenp = 0;
    if ( serdata != 0 && serdatalen > 0 )
    {
        serdata[serdatalen-1] = 0;
    }
    return(newjson);
}

cJSON *instantdex_defaulttimeout(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    uint8_t *serdata = *serdatap; int32_t serdatalen = *serdatalenp;
    *serdatap = 0, *serdatalenp = 0;
    if ( serdata != 0 && serdatalen > 0 )
    {
        serdata[serdatalen-1] = 0;
    }
    return(newjson);
}

struct instantdex_stateinfo instantdex_errorstate = { "error", 0,0, instantdex_defaultprocess, instantdex_defaulttimeout };
struct instantdex_stateinfo instantdex_timeoutstate = { "timeout", 1,0, instantdex_defaultprocess, instantdex_defaulttimeout };

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

void instantdex_stateinit(struct instantdex_stateinfo *states,int32_t numstates,struct instantdex_stateinfo *state,char *name,char *errorstr,char *timeoutstr,void *process_func,void *timeout_func)
{
    struct instantdex_stateinfo *timeoutstate,*errorstate;
    memset(state,0,sizeof(*state));
    strcpy(state->name,name);
    if ( (errorstate= instantdex_statefind(states,numstates,errorstr)) == 0 )
        errorstate = &instantdex_errorstate;
    state->errorind = errorstate->ind;
    if ( (timeoutstate= instantdex_statefind(states,numstates,timeoutstr)) == 0 )
        timeoutstate = &instantdex_timeoutstate;
    else printf("TS.%s ",timeoutstr);
    state->timeoutind = timeoutstate->ind;
    if ( (state->process= process_func) == 0 )
        state->process = instantdex_defaultprocess;
    if ( (state->timeout= timeout_func) == 0 )
        state->timeout = instantdex_defaulttimeout;
}

struct instantdex_stateinfo *instantdex_statecreate(struct instantdex_stateinfo *states,int32_t *numstatesp,char *name,cJSON *(*process_func)(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp),cJSON *(*timeout_func)(struct supernet_info *myinfo,struct exchange_info *exchange,struct bitcoin_swapinfo *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp),char *timeoutstr,char *errorstr,int32_t initialstate)
{
    struct instantdex_stateinfo S,*state = 0;
    if ( (state= instantdex_statefind(states,*numstatesp,name)) == 0 )
    {
        states = realloc(states,sizeof(*states) * (*numstatesp + 1));
        state = &states[*numstatesp];
        instantdex_stateinit(states,*numstatesp,state,name,errorstr,timeoutstr,process_func,timeout_func);
        state->initialstate = initialstate;
        printf("STATES[%d] %s %p %p %d %d\n",*numstatesp,state->name,state->process,state->timeout,state->timeoutind,state->errorind);
        state->ind = (*numstatesp)++;
    }
    else
    {
        instantdex_stateinit(states,*numstatesp,&S,name,errorstr,timeoutstr,process_func,timeout_func);
        S.ind = state->ind;
        S.initialstate = initialstate;
        if ( memcmp(&S,state,sizeof(S) - sizeof(void *) - sizeof(int)) != 0 )
        {
            int32_t i;
            for (i=0; i<sizeof(S); i++)
                printf("%02x ",((uint8_t *)&S)[i]);
            printf("S\n");
            for (i=0; i<sizeof(S); i++)
                printf("%02x ",((uint8_t *)state)[i]);
            printf("state\n");
            printf("%s %p %p %d %d vs %s %p %p %d %d\n",state->name,state->process,state->timeout,state->timeoutind,state->errorind,S.name,S.process,S.timeout,S.timeoutind,S.errorind);
            printf("statecreate error!!! (%s) already exists\n",name);
        }
    }
    return(states);
}

struct instantdex_event *instantdex_addevent(struct instantdex_stateinfo *states,int32_t numstates,char *statename,char *cmdstr,char *sendcmd,char *nextstatename)
{
    struct instantdex_stateinfo *nextstate,*state;
    if ( (state= instantdex_statefind(states,numstates,statename)) != 0 && (nextstate= instantdex_statefind(states,numstates,nextstatename)) != 0 )
    {
        if ( (state->events= realloc(state->events,(state->numevents + 1) * sizeof(*state->events))) != 0 )
        {
            memset(&state->events[state->numevents],0,sizeof(state->events[state->numevents]));
            strcpy(state->events[state->numevents].cmdstr,cmdstr);
            if ( sendcmd != 0 )
                strcpy(state->events[state->numevents].sendcmd,sendcmd);
            state->events[state->numevents].nextstateind = nextstate->ind;
            state->numevents++;
        }
        return(state->events);
    }
    else
    {
        int32_t i;
        for (i=0; i<numstates; i++)
            printf("%s[%d] ",states[i].name,i);
        printf("cant add event (%s -> %s) without existing state and nextstate\n",statename,nextstatename);
        exit(-1);
        return(0);
    }
}

double instantdex_FSMtest(struct instantdex_stateinfo *states,int32_t numstates,int32_t maxiters)
{
    int32_t i,most,r,r2,n,m=0,initials[100],nextstate=-1;
    struct instantdex_stateinfo *state; struct instantdex_event *event; double sum = 0.;
    if ( maxiters < 1 )
        maxiters = 1;
    for (i=n=most=0; i<numstates; i++)
        if ( states[i].initialstate > 0 )
        {
            printf("initialstate[%d] %d %s\n",i,states[i].initialstate,states[i].name);
            initials[n++] = i;
        }
    if ( n > 0 && n < sizeof(initials)/sizeof(*initials) )
    {
        for (i=0; i<maxiters; i++)
        {
            r = rand() % n;
            state = &states[initials[r]];
            if ( state->name[0] == 0 || state->ind >= numstates )
            {
                printf("illegal state.(%s) %d? ind.%d >= numstates.%d\n",state->name,nextstate,state->ind,numstates);
                break;
            }
            m = 0;
            while ( m++ < 1000 && state->initialstate >= 0 && state->numevents != 0 )
            {
                if ( (i % 1000000) == 0 )
                    fprintf(stderr,"%s ",state->name);
                r2 = rand() % state->numevents;
                event = &state->events[r2];
                if ( (nextstate= event->nextstateind) < 0 )
                    break;
                if ( event->nextstateind >= numstates )
                {
                    printf("nextstateind overflow? %d vs %d\n",event->nextstateind,numstates);
                    break;
                }
                state = &states[event->nextstateind];
            }
            if ( m > most )
                most = m;
            sum += m;
            if ( (i % 1000000) == 0 )
                fprintf(stderr,"reached %s m.%d events most.%d ave %.2f\n",state->name,m,most,sum/(i+1));
        }
    }
    fprintf(stderr," most.%d ave %.2f\n",most,sum/(i+1));
    return(sum / maxiters);
}

void instantdex_FSMinit()
{
    if ( BTC_states == 0 )
        BTC_states = BTC_initFSM(&BTC_numstates);
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
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(offer->account),&offer->account);
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

char *instantdex_sendcmd(struct supernet_info *myinfo,struct instantdex_offer *offer,cJSON *argjson,char *cmdstr,bits256 desthash,int32_t hops,void *extraser,int32_t extralen,struct iguana_peer *addr)
{
    char *reqstr,*hexstr,*retstr; struct instantdex_msghdr *msg; bits256 orderhash; struct iguana_info *coin; int32_t i,olen,slen,datalen,max=-1; uint8_t serialized[sizeof(*offer) + sizeof(struct iguana_msghdr) + 4096 + INSTANTDEX_DECKSIZE*33]; uint64_t nxt64bits;
    category_subscribe(myinfo,myinfo->instantdex_category,GENESIS_PUBKEY);
    jaddstr(argjson,"cmd",cmdstr);
    jaddstr(argjson,"agent","SuperNET");
    jaddstr(argjson,"method","DHT");
    jaddstr(argjson,"handle",myinfo->handle);
    jaddbits256(argjson,"categoryhash",myinfo->instantdex_category);
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
        if ( addr != 0 )
        {
            memset(serialized,0,sizeof(struct iguana_msghdr));
            memcpy(&serialized[sizeof(struct iguana_msghdr)],(uint8_t *)msg,msg->sig.allocsize);
            if ( (coin= iguana_coinfind("BTCD")) != 0 )//&& (max= coin->peers.numranked) > 0 )
            {
                iguana_queue_send(coin,addr,0,serialized,"InstantDEX",msg->sig.allocsize,0,0);
                /*r = (rand() % max);
                 for (i=0; i<max; i++)
                 {
                 j = (i + r) % max;
                 if ( (addr= coin->peers.ranked[j]) != 0 && addr->supernet != 0 && addr->usock >= 0 )
                 {
                 printf("send.%d to (%s)\n",(int32_t)msg->sig.allocsize,addr->ipaddr);
                 iguana_queue_send(coin,addr,0,serialized,"InstantDEX",msg->sig.allocsize,0,0);
                 if ( --hops <= 0 )
                 break;
                 } //else printf("skip.%d addr.%p (%s) max.%d hops.%d\n",j,addr,addr!=0?addr->ipaddr:"",max,hops);
                 }*/
            } else printf("cant find coin.%p or no ranked.%d\n",coin,max);
        }
        else
        {
            if ( (hexstr= malloc(msg->sig.allocsize*2 + 1)) != 0 )
            {
                init_hexbytes_noT(hexstr,(uint8_t *)msg,msg->sig.allocsize);
                if ( (retstr= SuperNET_categorymulticast(myinfo,0,myinfo->instantdex_category,desthash,hexstr,0,hops,1,argjson,0)) != 0 )
                    free(retstr);
                free(hexstr);
            }
        }
        free(msg);
        return(jprint(argjson,1));
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

int32_t instantdex_bidaskdir(struct instantdex_offer *offer)
{
    if ( offer->myside == 0 && offer->acceptdir > 0 ) // base
        return(-1);
    else if ( offer->myside == 1 && offer->acceptdir < 0 ) // rel
        return(1);
    else return(0);
}

cJSON *instantdex_offerjson(struct instantdex_offer *offer,uint64_t orderid)
{
    int32_t dir; cJSON *item = cJSON_CreateObject();
    jadd64bits(item,"orderid",orderid);
    jadd64bits(item,"account",offer->account);
    if ( (dir= instantdex_bidaskdir(offer)) > 0 )
        jaddstr(item,"type","bid");
    else if ( dir < 0 )
        jaddstr(item,"type","ask");
    else
    {
        jaddstr(item,"type","strange");
        jaddnum(item,"acceptdir",offer->acceptdir);
        jaddnum(item,"myside",offer->myside);
    }
    jaddstr(item,"base",offer->base);
    jaddstr(item,"rel",offer->rel);
    jaddnum(item,"timestamp",offer->expiration);
    jaddnum(item,"price",dstr(offer->price64));
    jaddnum(item,"volume",dstr(offer->basevolume64));
    jaddnum(item,"minperc",offer->minperc);
    jaddnum(item,"nonce",offer->nonce);
    jaddnum(item,"expiresin",offer->expiration - time(NULL));
    return(item);
}

cJSON *instantdex_acceptjson(struct instantdex_accept *ap)
{
    cJSON *item = cJSON_CreateObject();
    jadd64bits(item,"orderid",ap->orderid);
    jaddnum(item,"pendingvolume",dstr(ap->pendingvolume64));
    if ( ap->dead != 0 )
        jadd64bits(item,"dead",ap->dead);
    jadd(item,"offer",instantdex_offerjson(&ap->offer,ap->orderid));
    return(item);
}

void instantdex_statetxjson(cJSON *array,char *name,struct bitcoin_statetx *tx)
{
    cJSON *item;
    if ( tx != 0 )
    {
        item = cJSON_CreateObject();
        jaddbits256(item,"txid",tx->txid);
        jaddnum(item,"inputsum",dstr(tx->inputsum));
        jaddnum(item,"amount",dstr(tx->amount));
        jaddnum(item,"change",dstr(tx->change));
        jaddnum(item,"txfee",dstr(tx->inputsum) - dstr(tx->amount) - dstr(tx->change));
        jaddnum(item,"confirms",dstr(tx->numconfirms));
        jaddstr(item,"destaddr",tx->destaddr);
        jaddstr(item,"txbytes",tx->txbytes);
        jadd(array,name,item);
    }
}

cJSON *instantdex_statemachinejson(struct bitcoin_swapinfo *swap)
{
    cJSON *retjson,*txs; int32_t isbob,mydir,otherdir;
    retjson = cJSON_CreateObject();
    if ( swap != 0 )
    {
        mydir = instantdex_bidaskdir(&swap->mine.offer);
        otherdir = instantdex_bidaskdir(&swap->other.offer);
        isbob = instantdex_isbob(swap);
        jaddnum(retjson,"isbob",isbob);
        jaddnum(retjson,"mydir",mydir);
        jaddnum(retjson,"otherdir",otherdir);
        jaddnum(retjson,"expiration",swap->expiration);
        jaddnum(retjson,"insurance",dstr(swap->insurance));
        jaddnum(retjson,"baseamount",dstr(swap->altsatoshis));
        jaddnum(retjson,"BTCamount",dstr(swap->BTCsatoshis));
        jaddnum(retjson,"expiration",swap->expiration);
        if ( swap->dead != 0 )
            jadd64bits(retjson,"dead",swap->dead);
        jaddbits256(retjson,"privAm",swap->privAm);
        jaddbits256(retjson,"pubAm",swap->pubAm);
        jaddbits256(retjson,"privBn",swap->privBn);
        jaddbits256(retjson,"pubBn",swap->pubBn);
        
        jaddbits256(retjson,"myorderhash",swap->myorderhash);
        jaddnum(retjson,"choosei",swap->choosei);
        jaddnum(retjson,"cutverified",swap->cutverified);
        jaddbits256(retjson,"othertrader",swap->othertrader);
        jaddbits256(retjson,"otherorderhash",swap->otherorderhash);
        jaddnum(retjson,"otherchoosei",swap->otherchoosei);
        jaddnum(retjson,"otherverifiedcut",swap->otherverifiedcut);
        if ( isbob == 0 )
        {
            jaddbits256(retjson,"pubA0",swap->mypubs[0]);
            jaddbits256(retjson,"pubA1",swap->mypubs[1]);
            jaddbits256(retjson,"pubB0",swap->otherpubs[0]);
            jaddbits256(retjson,"pubB1",swap->otherpubs[1]);
        }
        else
        {
            jaddbits256(retjson,"pubB0",swap->mypubs[0]);
            jaddbits256(retjson,"pubB1",swap->mypubs[1]);
            jaddbits256(retjson,"pubA0",swap->otherpubs[0]);
            jaddbits256(retjson,"pubA1",swap->otherpubs[1]);
        }
        if ( mydir > 0 && otherdir < 0 )
        {
            jadd64bits(retjson,"bidid",swap->mine.orderid);
            jadd64bits(retjson,"askid",swap->other.orderid);
        }
        else if ( mydir < 0 && otherdir > 0 )
        {
            jadd64bits(retjson,"askid",swap->mine.orderid);
            jadd64bits(retjson,"bidid",swap->other.orderid);
        }
        if ( swap->matched64 == swap->mine.orderid )
        {
            jadd(retjson,"initiator",instantdex_acceptjson(&swap->other));
            jadd(retjson,"matched",instantdex_acceptjson(&swap->mine));
        }
        else if ( swap->matched64 == swap->other.orderid )
        {
            jadd(retjson,"initiator",instantdex_acceptjson(&swap->mine));
            jadd(retjson,"matched",instantdex_acceptjson(&swap->other));
        }
        else jaddstr(retjson,"initiator","illegal initiator missing");
        if ( swap->state != 0 )
            jaddstr(retjson,"state",swap->state->name);
        txs = cJSON_CreateObject();
        instantdex_statetxjson(txs,"deposit",swap->deposit);
        instantdex_statetxjson(txs,"payment",swap->payment);
        instantdex_statetxjson(txs,"altpayment",swap->altpayment);
        instantdex_statetxjson(txs,"myfee",swap->myfee);
        instantdex_statetxjson(txs,"otherfee",swap->otherfee);
        jadd(retjson,"txs",txs);
        jaddstr(retjson,"status",swap->status);
    }
    return(retjson);
}

cJSON *instantdex_historyjson(struct bitcoin_swapinfo *swap)
{
    // need to make sure accepts are put onto history queue when they are completed or deaded
    // also to make permanent copy (somewhere)
    return(instantdex_statemachinejson(swap));
}

void instantdex_historyadd(struct exchange_info *exchange,struct bitcoin_swapinfo *swap)
{
    portable_mutex_lock(&exchange->mutexH);
    DL_APPEND(exchange->history,swap);
    portable_mutex_unlock(&exchange->mutexH);
}

void instantdex_statemachineadd(struct exchange_info *exchange,struct bitcoin_swapinfo *swap)
{
    portable_mutex_lock(&exchange->mutexS);
    DL_APPEND(exchange->statemachines,swap);
    portable_mutex_unlock(&exchange->mutexS);
}

void instantdex_offeradd(struct exchange_info *exchange,struct instantdex_accept *ap)
{
    portable_mutex_lock(&exchange->mutex);
    DL_APPEND(exchange->offers,ap);
    portable_mutex_unlock(&exchange->mutex);
}

struct bitcoin_swapinfo *instantdex_historyfind(struct supernet_info *myinfo,struct exchange_info *exchange,uint64_t orderid)
{
    struct bitcoin_swapinfo *swap,*tmp,*retswap = 0;
    portable_mutex_lock(&exchange->mutexH);
    DL_FOREACH_SAFE(exchange->history,swap,tmp)
    {
        if ( orderid == swap->mine.orderid )
        {
            retswap = swap;
            break;
        }
    }
    portable_mutex_unlock(&exchange->mutexH);
    return(retswap);
}

struct bitcoin_swapinfo *instantdex_statemachinefind(struct supernet_info *myinfo,struct exchange_info *exchange,uint64_t orderid)
{
    struct bitcoin_swapinfo *tmp,*swap,*retswap = 0; uint32_t now;
    now = (uint32_t)time(NULL);
    portable_mutex_lock(&exchange->mutexS);
    DL_FOREACH_SAFE(exchange->statemachines,swap,tmp)
    {
        if ( now < swap->expiration && swap->mine.dead == 0 && swap->other.dead == 0 )
        {
            if ( orderid == swap->mine.orderid || orderid == swap->other.orderid )
            {
                retswap = swap;
                break;
            }
        }
        else
        {
            strcpy(swap->status,"expired");
            printf("expired pending, need to take action, send timeout event\n");
            DL_DELETE(exchange->statemachines,swap);
            instantdex_historyadd(exchange,swap);
            continue;
        }
    }
    //printf("found statemachine.%p\n",retswap);
    portable_mutex_unlock(&exchange->mutexS);
    return(retswap);
}

struct instantdex_accept *instantdex_offerfind(struct supernet_info *ignore,struct exchange_info *exchange,cJSON *bids,cJSON *asks,uint64_t orderid,char *base,char *rel,int32_t report)
{
    struct instantdex_accept *tmp,*ap,*retap = 0; uint32_t now; cJSON *item,*offerobj; char *type;
    if ( exchange == 0 )
        return(0);
    now = (uint32_t)time(NULL);
    portable_mutex_lock(&exchange->mutex);
    DL_FOREACH_SAFE(exchange->offers,ap,tmp)
    {
        if ( now < ap->offer.expiration && ap->dead == 0 )
        {
            //printf("%d %d find cmps %d %d %d %d %d %d me.%llu vs %llu o.%llu | vs %llu\n",instantdex_bidaskdir(&ap->offer),ap->offer.expiration-now,strcmp(base,"*") == 0,strcmp(base,ap->offer.base) == 0,strcmp(rel,"*") == 0,strcmp(rel,ap->offer.rel) == 0,orderid == 0,orderid == ap->orderid,(long long)myinfo->myaddr.nxt64bits,(long long)ap->offer.account,(long long)ap->orderid,(long long)orderid);
            if ( (report == 0 || ap->reported == 0) && (strcmp(base,"*") == 0 || strcmp(base,ap->offer.base) == 0) && (strcmp(rel,"*") == 0 || strcmp(rel,ap->offer.rel) == 0) && (orderid == 0 || orderid == ap->orderid) )
            {
                if ( report != 0 && ap->reported == 0 )
                {
                    ap->reported = 1;
                    printf("MARK as reported %llu\n",(long long)ap->orderid);
                }
                retap = ap;
                if ( (item= instantdex_acceptjson(ap)) != 0 )
                {
                    //printf("item.(%s)\n",jprint(item,0));
                    if ( (offerobj= jobj(item,"offer")) != 0 && (type= jstr(offerobj,"type")) != 0 )
                    {
                        if ( bids != 0 && strcmp(type,"bid") == 0 )
                            jaddi(bids,jduplicate(offerobj));
                        else if ( asks != 0 && strcmp(type,"ask") == 0 )
                            jaddi(asks,jduplicate(offerobj));
                    }
                    free_json(item);
                } else printf("error generating acceptjson.%llu\n",(long long)ap->orderid);
            }
        }
        else
        {
            DL_DELETE(exchange->offers,ap);
            free(ap);
        }
    }
    portable_mutex_unlock(&exchange->mutex);
    //printf("offerfind -> retap.%p Qsize.%d\n",retap,queue_size(&exchange->acceptableQ));
    return(retap);
}

int32_t instantdex_peerhas_clear(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct instantdex_accept *tmp,*ap; struct exchange_info *exchange; int32_t ind,num = 0;
    if ( addr != 0 && (exchange= exchanges777_find("bitcoin")) != 0 )
    {
        //printf("clear all bits for addrind.%d\n",addr->addrind);
        ind = addr->addrind;
        portable_mutex_lock(&exchange->mutex);
        DL_FOREACH_SAFE(exchange->offers,ap,tmp)
        {
            CLEARBIT(ap->peerhas,ind);
        }
        portable_mutex_unlock(&exchange->mutex);
    }
    return(num);
}

struct instantdex_accept *instantdex_acceptable(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *A,double minperc)
{
    struct instantdex_accept *tmp,*ap,*retap = 0; double aveprice;
    uint64_t minvol,bestprice64 = 0; uint32_t now; int32_t offerdir;
    if ( exchange == 0 )
    {
        printf("instantdex_acceptable null exchange\n");
        return(0);
    }
    aveprice = 0;//instantdex_avehbla(myinfo,retvals,A->offer.base,A->offer.rel,dstr(A->offer.basevolume64));
    now = (uint32_t)time(NULL);
    offerdir = instantdex_bidaskdir(&A->offer);
    minvol = (A->offer.basevolume64 * minperc * .01);
    printf("instantdex_acceptable offerdir.%d (%s/%s) minperc %.3f minvol %.8f vs %.8f\n",offerdir,A->offer.base,A->offer.rel,minperc,dstr(minvol),dstr(A->offer.basevolume64));
    portable_mutex_lock(&exchange->mutex);
    DL_FOREACH_SAFE(exchange->offers,ap,tmp)
    {
        //printf("ap.%p account.%llu dir.%d\n",ap,(long long)ap->offer.account,offerdir);
        if ( now > ap->offer.expiration || ap->dead != 0 || A->offer.account == ap->offer.account )
        {
            //printf("now.%u skip expired %u/dead.%u or my order orderid.%llu from %llu\n",now,ap->offer.expiration,ap->dead,(long long)ap->orderid,(long long)ap->offer.account);
        }
        else if ( A->offer.account != myinfo->myaddr.nxt64bits && ap->offer.account != myinfo->myaddr.nxt64bits )
        {
            
        }
        else if ( strcmp(ap->offer.base,A->offer.base) != 0 || strcmp(ap->offer.rel,A->offer.rel) != 0 )
        {
            //printf("skip mismatched.(%s/%s) orderid.%llu from %llu\n",ap->offer.base,ap->offer.rel,(long long)ap->orderid,(long long)ap->offer.account);
        }
        else if ( offerdir*instantdex_bidaskdir(&ap->offer) > 0 )
        {
            //printf("skip same direction %d orderid.%llu from %llu\n",instantdex_bidaskdir(&ap->offer),(long long)ap->orderid,(long long)ap->offer.account);
        }
        else if ( minvol > ap->offer.basevolume64 - ap->pendingvolume64 )
        {
            //printf("skip too small order %.8f vs %.8f orderid.%llu from %llu\n",dstr(minvol),dstr(ap->offer.basevolume64)-dstr(ap->pendingvolume64),(long long)ap->orderid,(long long)ap->offer.account);
        }
        else if ( (offerdir > 0 && ap->offer.price64 > A->offer.price64) || (offerdir < 0 && ap->offer.price64 < A->offer.price64) )
        {
            //printf("skip out of band dir.%d offer %.8f vs %.8f orderid.%llu from %llu\n",offerdir,dstr(ap->offer.price64),dstr(A->offer.price64),(long long)ap->orderid,(long long)ap->offer.account);
        }
        else
        {
            if ( bestprice64 == 0 || (offerdir > 0 && ap->offer.price64 < bestprice64) || (offerdir < 0 && ap->offer.price64 > bestprice64) )
            {
                printf(">>>> MATCHED better price dir.%d offer %.8f vs %.8f orderid.%llu from %llu\n",offerdir,dstr(ap->offer.price64),dstr(A->offer.price64),(long long)ap->orderid,(long long)ap->offer.account);
                bestprice64 = ap->offer.price64;
                retap = ap;
            }
        }
    }
    portable_mutex_unlock(&exchange->mutex);
    //printf("after acceptable Qsize.%d retap.%p\n",queue_size(&exchange->acceptableQ),retap);
    return(retap);
}

int32_t instantdex_inv2data(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,struct exchange_info *exchange)
{
    struct instantdex_accept *tmp,*ap; uint32_t now,n=0,len; bits256 encodedhash,hashes[100]; uint8_t serialized[100*36 + 1024];
    //printf("instantdex_inv2data exchange.%p (%s)\n",exchange,addr->ipaddr);
    if ( exchange == 0 )
        return(0);
    portable_mutex_lock(&exchange->mutex);
    now = (uint32_t)time(NULL);
    DL_FOREACH_SAFE(exchange->offers,ap,tmp)
    {
        if ( now < ap->offer.expiration && ap->dead == 0 )
        {
            encodedhash = instantdex_encodehash(ap->offer.base,ap->offer.rel,ap->offer.price64*instantdex_bidaskdir(&ap->offer),ap->orderid,ap->offer.account);
            if ( n < sizeof(hashes)/sizeof(*hashes) )//&& GETBIT(ap->peerhas,addr->addrind) == 0 )
            {
                hashes[n++] = encodedhash;
                printf("%llu ",(long long)ap->orderid);
            }
        }
        else
        {
            DL_DELETE(exchange->offers,ap);
            free(ap);
        }
    }
    portable_mutex_unlock(&exchange->mutex);
    if ( n > 0 )
    {
        len = iguana_inv2packet(serialized,sizeof(serialized),MSG_QUOTE,hashes,n);
        //printf("Send inv2[%d] -> (%s)\n",n,addr->ipaddr);
        return(iguana_queue_send(coin,addr,0,serialized,"inv2",len,0,0));
    }
    return(-1);
}

struct instantdex_accept *instantdex_quotefind(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,bits256 encodedhash)
{
    char base[9],rel[9]; int64_t pricetoshis; uint64_t orderid,account;
    orderid = instantdex_decodehash(base,rel,&pricetoshis,&account,encodedhash);
    //printf("search for orderid.%llu (%s/%s) %.8f from %llu\n",(long long)orderid,base,rel,dstr(pricetoshis),(long long)account);
    return(instantdex_offerfind(myinfo,exchanges777_find("bitcoin"),0,0,orderid,base,rel,0));
}

struct iguana_bundlereq *instantdex_recvquotes(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *quotes,int32_t n)
{
    int32_t i,len,m = 0; uint8_t serialized[10000];
    if ( req->addr == 0 )
        return(0);
    //printf("received quotehashes.%d from (%s)\n",n,req->addr->ipaddr);
    for (i=1; i<n; i++)
    {
        if ( instantdex_quotefind(0,coin,req->addr,quotes[i]) != 0 )
            continue;
        quotes[m++] = quotes[i];
    }
    if ( m > 0 )
    {
        len = iguana_getdata(coin,serialized,MSG_QUOTE,quotes,m);
        printf("send getdata for %d of %d quotes to %s\n",m,n,req->addr->ipaddr);
        iguana_send(coin,req->addr,serialized,len);
    }
    return(req);
}

int32_t instantdex_quoterequest(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *serialized,int32_t maxlen,struct iguana_peer *addr,bits256 encodedhash)
{
    struct instantdex_accept *ap; int32_t olen,checklen; struct instantdex_offer checkoffer; bits256 orderhash,checkhash;
    if ( (ap= instantdex_quotefind(myinfo,coin,addr,encodedhash)) != 0 )
    {
        orderhash = instantdex_rwoffer(1,&olen,serialized,&ap->offer);
        if ( orderhash.ulongs[0] == ap->orderid )
        {
            checkhash = instantdex_rwoffer(0,&checklen,serialized,&checkoffer);
            if ( bits256_cmp(checkhash,orderhash) != 0 )
                printf("%llu vs %llu, %d vs %d\n",(long long)checkhash.txid,(long long)orderhash.txid,checklen,olen);
            return(olen);
        }
        else return(-1);
    }
    return(0);
}

int32_t instantdex_quotep2p(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,uint8_t *serialized,int32_t recvlen)
{
    bits256 orderhash,encodedhash; int32_t added,checklen; struct instantdex_accept A,*ap; struct exchange_info *exchange; char *retstr; cJSON *argjson; uint64_t txid;
    exchange = exchanges777_find("bitcoin");
    memset(&A,0,sizeof(A));
    orderhash = instantdex_rwoffer(0,&checklen,serialized,&A.offer), A.orderid = orderhash.txid;
    if ( checklen == recvlen )
    {
        encodedhash = instantdex_encodehash(A.offer.base,A.offer.rel,A.offer.price64 * instantdex_bidaskdir(&A.offer),A.orderid,A.offer.account);
        //printf("before quotefind.%d\n",queue_size(&exchange->acceptableQ));
        if ( (ap= instantdex_quotefind(myinfo,coin,addr,encodedhash)) == 0 )
        {
            //printf("add quote here! Qsize.%d\n",queue_size(&exchange->acceptableQ));
            if ( exchange != 0 )
            {
                if ( instantdex_statemachinefind(myinfo,exchange,A.orderid) == 0 && instantdex_historyfind(myinfo,exchange,A.orderid) == 0 )
                {
                    ap = calloc(1,sizeof(*ap));
                    *ap = A;
                    SETBIT(ap->peerhas,addr->addrind);
                    argjson = cJSON_Parse("{}");
                    //printf("before checkoffer Qsize.%d\n",queue_size(&exchange->acceptableQ));
                    if ( (retstr= instantdex_checkoffer(myinfo,&added,&txid,exchange,ap,argjson)) != 0 )
                        free(retstr);
                    if ( added == 0 )
                        free(ap);
                    free_json(argjson);
                }
            }
        }
        else
        {
            printf("instantdex_quote: got %llu which was already there (%p %p)\n",(long long)encodedhash.txid,ap,addr);
            SETBIT(ap->peerhas,addr->addrind);
        }
    } else printf("instantdex_quote: checklen.%d != recvlen.%d\n",checklen,recvlen);
    return(checklen);
}

void instantdex_propagate(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *ap)
{
    bits256 orderhash; uint8_t serialized[8192]; int32_t i,len; struct iguana_peer *addr; struct iguana_info *coin;
    orderhash = instantdex_rwoffer(1,&len,&serialized[sizeof(struct iguana_msghdr)],&ap->offer);
    if ( (coin= iguana_coinfind("BTCD")) != 0 && coin->peers.numranked > 0 )
    {
        for (i=0; i<coin->peers.numranked; i++)
            if ( (addr= coin->peers.ranked[i]) != 0 && addr->supernet != 0 && addr->usock >= 0 && GETBIT(ap->peerhas,addr->addrind) == 0 && strcmp("0.0.0.0",addr->ipaddr) != 0 && strcmp("127.0.0.1",addr->ipaddr) != 0 )
            {
                //SETBIT(ap->peerhas,addr->addrind);
                char str[65]; printf("send quote.(%s) <- [%d] %s %llu\n",addr->ipaddr,len,bits256_str(str,orderhash),(long long)orderhash.txid);
                iguana_queue_send(coin,addr,0,serialized,"quote",len,0,0);
            }
    }
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

bits256 instantdex_acceptset(struct instantdex_accept *ap,char *base,char *rel,int32_t duration,int32_t myside,int32_t acceptdir,double price,double volume,uint64_t account,uint32_t nonce,uint8_t minperc)
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
    ap->offer.account = account;
    ap->offer.myside = myside;
    ap->offer.acceptdir = acceptdir;
    ap->offer.minperc = minperc;
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
    char *base,*rel; bits256 hash,traderpub; double price,volume; int32_t baserel,acceptdir,minperc;
    memset(ap,0,sizeof(*ap));
    if ( (base= jstr(argjson,"base")) != 0 )
    {
        volume = jdouble(argjson,"volume");
        if ( (minperc= juint(argjson,"minperc")) < INSTANTDEX_MINPERC )
            minperc = INSTANTDEX_MINPERC;
        else if ( minperc > 100 )
            minperc = 100;
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
        hash = instantdex_acceptset(ap,base,rel,INSTANTDEX_LOCKTIME*2,baserel,acceptdir,price,volume,traderpub.txid,0,minperc);
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
        ap->offer.account = j64bits(argjson,"o");
        ap->offer.price64 = j64bits(argjson,"p");
        ap->offer.basevolume64 = j64bits(argjson,"v");
        if ( (ap->offer.minperc= juint(argjson,"m")) < INSTANTDEX_MINPERC )
            ap->offer.minperc = INSTANTDEX_MINPERC;
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

struct bitcoin_swapinfo *bitcoin_swapinit(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *myap,struct instantdex_accept *otherap,int32_t aminitiator,cJSON *argjson,char *statename)
{
    struct bitcoin_swapinfo *swap = 0; struct iguana_info *coinbtc,*altcoin;
    swap = calloc(1,sizeof(struct bitcoin_swapinfo));
    swap->state = instantdex_statefind(BTC_states,BTC_numstates,statename);
    swap->mine = *myap, swap->other = *otherap;
    if ( (swap->isinitiator= aminitiator) != 0 )
    {
        swap->matched64 = otherap->orderid;
        swap->expiration = otherap->offer.expiration;
    }
    else
    {
        swap->matched64 = myap->orderid;
        swap->expiration = myap->offer.expiration;
    }
    swap->choosei = swap->otherchoosei = -1;
    strcpy(swap->status,"pending");
    vcalc_sha256(0,swap->myorderhash.bytes,(void *)&swap->mine.offer,sizeof(swap->mine.offer));
    vcalc_sha256(0,swap->otherorderhash.bytes,(void *)&swap->other.offer,sizeof(swap->other.offer));
    swap->mypubkey = myinfo->myaddr.persistent;
    swap->othertrader = jbits256(argjson,"traderpub");
    swap->altsatoshis = myap->offer.basevolume64;
    swap->BTCsatoshis = instantdex_BTCsatoshis(myap->offer.price64,myap->offer.basevolume64);
    if ( (coinbtc= iguana_coinfind("BTC")) == 0 || (altcoin= iguana_coinfind(swap->mine.offer.base)) == 0 )
    {
        printf("cant find BTC or %s\n",swap->mine.offer.base);
        return(0);
    }
    swap->insurance = (swap->BTCsatoshis * INSTANTDEX_INSURANCERATE + coinbtc->chain->txfee);
    swap->altpremium = (swap->altsatoshis * INSTANTDEX_INSURANCERATE + altcoin->chain->txfee);
    if ( myap->offer.myside != instantdex_isbob(swap) || otherap->offer.myside == instantdex_isbob(swap) )
    {
        printf("isbob error.(%d %d) %d\n",myap->offer.myside,otherap->offer.myside,instantdex_isbob(swap));
        return(0);
    }
    return(swap);
}

char *instantdex_checkoffer(struct supernet_info *myinfo,int32_t *addedp,uint64_t *txidp,struct exchange_info *exchange,struct instantdex_accept *ap,cJSON *argjson)
{
    struct instantdex_accept *otherap,*tmp; struct bitcoin_swapinfo *swap; cJSON *newjson; int32_t isbob = 0;
    *addedp = 0;
    if ( exchange == 0 )
    {
        printf("instantdex_checkoffer null exchange\n");
        return(0);
    }
    if ( instantdex_statemachinefind(myinfo,exchange,ap->orderid) != 0 || instantdex_historyfind(myinfo,exchange,ap->orderid) != 0 )
    {
        printf("instantdex_checkoffer already have statemachine or history\n");
        return(0);
    }
    *txidp = ap->orderid;
    if ( (otherap= instantdex_acceptable(myinfo,exchange,ap,ap->offer.minperc)) == 0 )
    {
        if ( instantdex_offerfind(myinfo,exchange,0,0,ap->orderid,ap->offer.base,ap->offer.rel,0) == 0 )
        {
            printf("instantdex_checkoffer add.%llu from.%llu to acceptableQ\n",(long long)ap->orderid,(long long)ap->offer.account);
            instantdex_offeradd(exchange,ap);
            *addedp = 1;
            if ( instantdex_offerfind(myinfo,exchange,0,0,ap->orderid,ap->offer.base,ap->offer.rel,0) == 0 )
                printf("cant find just added to acceptableQ\n");
        }
        return(jprint(instantdex_offerjson(&ap->offer,ap->orderid),1));
    }
    else
    {
        if ( otherap->offer.account == myinfo->myaddr.nxt64bits )
        {
            tmp = otherap;
            otherap = ap;
            ap = tmp;
            printf("SWAP otherap\n");
        }
        else if ( ap->offer.account != myinfo->myaddr.nxt64bits )
        {
            printf("checkoffer unexpected account missing\n");
            return(0);
        }
        isbob = ap->offer.myside;
        swap = bitcoin_swapinit(myinfo,exchange,ap,otherap,1,argjson,isbob != 0 ? "BOB_sentoffer" : "ALICE_sentoffer");
        printf("ISBOB.%d vs %d\n",isbob,instantdex_isbob(swap));
        if ( swap != 0 )
        {
            printf("STATEMACHINEQ.(%llu / %llu)\n",(long long)swap->mine.orderid,(long long)swap->other.orderid);
            //queue_enqueue("acceptableQ",&exchange->acceptableQ,&swap->DL,0);
            instantdex_statemachineadd(exchange,swap);
            *addedp = 1;
            if ( (newjson= instantdex_parseargjson(myinfo,exchange,swap,argjson,1)) == 0 )
                return(clonestr("{\"error\":\"instantdex_checkoffer null newjson\"}"));
            return(instantdex_sendcmd(myinfo,&swap->mine.offer,newjson,"BTCoffer",GENESIS_PUBKEY,INSTANTDEX_HOPS,swap->deck,sizeof(swap->deck),0));
        } else printf("error creating statemachine\n");
    }
    return(0);
}

char *instantdex_gotoffer(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *myap,struct instantdex_accept *otherap,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *serdata,int32_t serdatalen) // receiving side
{
    struct bitcoin_swapinfo *swap = 0; bits256 traderpub; struct iguana_info *coinbtc,*altcoin; cJSON *newjson=0; char *retstr=0; int32_t isbob;
    coinbtc = iguana_coinfind("BTC");
    traderpub = jbits256(argjson,"traderpub");
    if ( bits256_cmp(traderpub,myinfo->myaddr.persistent) == 0 )
    {
        printf("got my own gotoffer packet orderid.%llu/%llu\n",(long long)myap->orderid,(long long)otherap->orderid);
        return(clonestr("{\"result\":\"got my own packet\"}"));
    }
    if ( 0 )
    {
        int32_t i;
        for (i=0; i<sizeof(otherap->offer); i++)
            printf("%02x ",((uint8_t *)&otherap->offer)[i]);
        printf("gotoffer.%llu\n",(long long)otherap->orderid);
    }
    printf(">>>>>>>>> GOTOFFER T.%d got (%s/%s) %.8f vol %.8f %llu offerside.%d offerdir.%d decksize.%d/datalen.%d\n",bits256_cmp(traderpub,myinfo->myaddr.persistent),myap->offer.base,myap->offer.rel,dstr(myap->offer.price64),dstr(myap->offer.basevolume64),(long long)myap->orderid,myap->offer.myside,myap->offer.acceptdir,(int32_t)sizeof(swap->deck),serdatalen);
    if ( exchange == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap null exchange ptr\"}"));
    if ( (altcoin= iguana_coinfind(myap->offer.base)) == 0 || coinbtc == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap cant find btc or other coin info\"}"));
    if ( strcmp(myap->offer.rel,"BTC") != 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap offer non BTC rel\"}"));
    if ( myap->offer.expiration < (time(NULL) + INSTANTDEX_DURATION) || otherap->offer.expiration < (time(NULL) + INSTANTDEX_DURATION) )
        return(clonestr("{\"error\":\"instantdex_BTCswap offer too close to expiration\"}"));
    isbob = myap->offer.myside;
    if ( (swap= bitcoin_swapinit(myinfo,exchange,myap,otherap,0,argjson,isbob != 0 ? "BOB_gotoffer" : "ALICE_gotoffer")) == 0 )
        return(clonestr("{\"error\":\"couldnt allocate statemachine\"}"));
    printf("ISBOB.%d vs %d\n",isbob,instantdex_isbob(swap));
    if ( (newjson= instantdex_parseargjson(myinfo,exchange,swap,argjson,1)) == 0 )
    {
        printf("error parsing argjson\n");
        return(clonestr("{\"error\":\"instantdex_BTCswap offer null newjson\"}"));
    }
    else //if ( (retstr= instantdex_addfeetx(myinfo,newjson,ap,swap,"BOB_gotoffer","ALICE_gotoffer")) == 0 )
    {
        printf("create statemachine\n");
        //queue_enqueue("acceptableQ",&exchange->acceptableQ,&swap->DL,0);
        instantdex_statemachineadd(exchange,swap);
        if ( (retstr= instantdex_choosei(swap,newjson,argjson,serdata,serdatalen)) != 0 )
            return(retstr);
        else
        {
            return(instantdex_sendcmd(myinfo,&swap->mine.offer,newjson,"BTCdeckC",traderpub,INSTANTDEX_HOPS,swap->deck,sizeof(swap->deck),0));
        }
    }
    return(retstr);
}

char *instantdex_parse(struct supernet_info *myinfo,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,struct instantdex_offer *offer,bits256 orderhash,uint8_t *serdata,int32_t serdatalen)
{
    char cmdstr[16],*retstr; struct exchange_info *exchange; struct instantdex_accept A,*ap = 0; bits256 traderpub; cJSON *newjson; struct bitcoin_swapinfo *swap;
    exchange = exchanges777_find("bitcoin");
    memset(cmdstr,0,sizeof(cmdstr)), memcpy(cmdstr,msg->cmd,sizeof(msg->cmd));
    if ( argjson != 0 )
    {
        traderpub = jbits256(argjson,"traderpub");
        memset(&A,0,sizeof(A));
        if ( j64bits(argjson,"id") != orderhash.txid )
        {
            printf("orderhash %llu (%s)\n",(long long)orderhash.txid,jprint(argjson,0));
            return(clonestr("{\"error\":\"orderhash mismatch\"}"));
        }
        A.offer = *offer;
        A.orderid = orderhash.txid;
        printf("got.(%s) for %llu account.%llu serdatalen.%d\n",cmdstr,(long long)A.orderid,(long long)A.offer.account,serdatalen);
        if ( (A.offer.minperc= jdouble(argjson,"p")) < INSTANTDEX_MINPERC )
            A.offer.minperc = INSTANTDEX_MINPERC;
        else if ( A.offer.minperc > 100 )
            A.offer.minperc = 100;
        if ( (swap= instantdex_statemachinefind(myinfo,exchange,A.orderid)) != 0 )
        {
            printf("found existing state machine %llu\n",(long long)A.orderid);
            newjson = instantdex_parseargjson(myinfo,exchange,swap,argjson,0);
            if ( serdatalen == sizeof(swap->otherdeck) && swap->choosei < 0 && (retstr= instantdex_choosei(swap,newjson,argjson,serdata,serdatalen)) != 0 )
            {
                printf("error choosei\n");
                return(retstr);
            }
            return(instantdex_statemachine(BTC_states,BTC_numstates,myinfo,exchange,swap,cmdstr,argjson,newjson,serdata,serdatalen));
        }
        else if ( strcmp(cmdstr,"BTCoffer") == 0 ) // incoming
        {
            printf("BTCoffer state exchange.%p serdatalen.%d\n",exchange,serdatalen);
            if ( (ap= instantdex_acceptable(myinfo,exchange,&A,A.offer.minperc)) != 0 )
            {
                if ( (retstr= instantdex_gotoffer(myinfo,exchange,ap,&A,msg,argjson,remoteaddr,signerbits,serdata,serdatalen)) != 0 ) // adds to statemachine if no error
                {
                    printf("from GOTOFFER.(%s)\n",retstr);
                    return(retstr);
                } else return(clonestr("{\"error\":\"gotoffer error\"}"));
            }
            else
            {
                printf("no matching trade for %s %llu -> InstantDEX_minaccept isbob.%d\n",cmdstr,(long long)A.orderid,A.offer.myside);
                if ( instantdex_offerfind(myinfo,exchange,0,0,A.orderid,"*","*",0) == 0 )
                {
                    ap = calloc(1,sizeof(*ap));
                    *ap = A;
                    printf("acceptableQ <- %llu\n",(long long)ap->orderid);
                    instantdex_offeradd(exchange,ap);
                    return(clonestr("{\"result\":\"added new order to orderbook\"}"));
                } else return(clonestr("{\"result\":\"order was already in orderbook\"}"));
            }
        }
        else
        {
            printf("cant find existing order.%llu that matches\n",(long long)A.orderid);
            return(clonestr("{\"error\":\"cant find matching order\"}"));
        }
    }
    return(clonestr("{\"error\":\"request needs argjson\"}"));
}

char *InstantDEX_hexmsg(struct supernet_info *myinfo,struct category_info *cat,void *ptr,int32_t len,char *remoteaddr)
{
    struct instantdex_msghdr *msg = ptr; int32_t i,olen,slen,num,datalen,newlen,flag = 0;
    uint8_t *serdata; struct supernet_info *myinfos[64]; struct instantdex_offer rawoffer;
    uint64_t signerbits; uint8_t tmp[sizeof(msg->sig)]; char *retstr = 0;
    bits256 orderhash,traderpub; cJSON *retjson,*item,*argjson = 0;
    datalen = len  - (int32_t)sizeof(msg->sig);
    serdata = (void *)((long)msg + sizeof(msg->sig));
    //printf("a signed datalen.%d allocsize.%d crc.%x\n",datalen,msg->sig.allocsize,calc_crc32(0,serdata,datalen));
    acct777_rwsig(0,(void *)&msg->sig,(void *)tmp);
    memcpy(&msg->sig,tmp,sizeof(msg->sig));
    // printf("b signed datalen.%d allocsize.%d crc.%x\n",datalen,msg->sig.allocsize,calc_crc32(0,serdata,datalen));
    if ( (remoteaddr == 0 || remoteaddr[0] == 0 || strcmp("127.0.0.1",remoteaddr) == 0) && ((uint8_t *)msg)[len-1] == 0 && (argjson= cJSON_Parse((char *)msg)) != 0 )
    {
        printf("string instantdex_hexmsg RESULT.(%s)\n",jprint(argjson,0));
        free_json(argjson);
        return(clonestr("{\"error\":\"string base packets deprecated\"}"));
    }
    else if ( (signerbits= acct777_validate(&msg->sig,acct777_msgprivkey(serdata,datalen),msg->sig.pubkey)) != 0 )//|| 1 )
    {
        flag++;
        printf("InstantDEX_hexmsg <<<<<<<<<<<<< sigsize.%d VALIDATED [%ld] len.%d t%u allocsize.%d (%s) [%d]\n",(int32_t)sizeof(msg->sig),(long)serdata-(long)msg,datalen,msg->sig.timestamp,msg->sig.allocsize,(char *)msg->serialized,serdata[datalen-1]);
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
            printf("received orderhash.%llu olen.%d slen.%d newlen.%d\n",(long long)orderhash.txid,olen,slen,newlen);
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
                traderpub = jbits256(argjson,"traderpub");
                if ( bits256_cmp(traderpub,myinfo->myaddr.persistent) == 0 )
                    continue;
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

char *instantdex_createaccept(struct supernet_info *myinfo,struct instantdex_accept **aptrp,struct exchange_info *exchange,char *base,char *rel,double price,double basevolume,int32_t acceptdir,char *mysidestr,int32_t duration,uint64_t account,uint8_t minperc)
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
        instantdex_acceptset(ap,base,rel,duration,myside,acceptdir,price,basevolume,account,0,minperc);
        if ( instantdex_offerfind(myinfo,exchange,0,0,ap->orderid,ap->offer.base,ap->offer.rel,0) == 0 )
        {
            instantdex_propagate(myinfo,exchange,ap);
            /*if ( queueflag != 0 )
            {
                printf("acceptableQ <- %llu\n",(long long)ap->orderid);
                instantdex_offeradd(exchange,ap);
                *addedp = 1;
            }*/
            retstr = jprint(instantdex_acceptjson(ap),1);
            //printf("acceptableQ %llu (%s)\n",(long long)ap->orderid,retstr);
            return(retstr);
        } else return(0);
    } else return(clonestr("{\"error\":\"invalid exchange\"}"));
}

void instantdex_update(struct supernet_info *myinfo)
{
    struct instantdex_msghdr *pm; struct category_msg *m; char *str,remote[64]; queue_t *Q; struct queueitem *item; struct category_info *cat;
    //char str2[65]; printf("myinfo->instantdex_category.(%s)\n",bits256_str(str2,myinfo->instantdex_category));
    if ( (Q= category_Q(&cat,myinfo->instantdex_category,myinfo->myaddr.persistent)) != 0 && queue_size(Q) > 0 && (item= Q->list) != 0 )
    {
        m = queue_dequeue(Q,0);
        pm = (struct instantdex_msghdr *)m->msg;
        if ( m->remoteipbits != 0 )
            expand_ipbits(remote,m->remoteipbits);
        else remote[0] = 0;
        {
            char hexstr[3000];
            init_hexbytes_noT(hexstr,(uint8_t *)pm,m->len);
            printf("instantdex_update.(%s) len.%d remote.(%s) %p\n",hexstr,m->len,remote,remote);
        }
        if ( (str= InstantDEX_hexmsg(myinfo,cat,pm,m->len,remote)) != 0 )
            free(str);
        free(m);
    }
}

#include "../includes/iguana_apidefs.h"

TWO_STRINGS_AND_TWO_DOUBLES(InstantDEX,maxaccept,base,rel,maxprice,basevolume)
{
    struct instantdex_accept *ap; int32_t added; char *retstr; struct exchange_info *exchange; uint64_t txid;
    myinfo = SuperNET_accountfind(json);
    if ( remoteaddr == 0 && (exchange= exchanges777_find("bitcoin")) != 0 )
    {
        if ( (retstr= instantdex_createaccept(myinfo,&ap,exchange,base,rel,maxprice,basevolume,-1,rel,INSTANTDEX_OFFERDURATION,myinfo->myaddr.nxt64bits,juint(json,"minperc"))) != 0 )
            free(retstr);
        retstr = instantdex_checkoffer(myinfo,&added,&txid,exchange,ap,json);
        if ( added == 0 )
            free(ap);
        return(retstr);
        
    } else return(clonestr("{\"error\":\"InstantDEX API request only local usage!\"}"));
}

TWO_STRINGS_AND_TWO_DOUBLES(InstantDEX,minaccept,base,rel,minprice,basevolume)
{
    struct instantdex_accept *ap; int32_t added; char *retstr; struct exchange_info *exchange; uint64_t txid;
    myinfo = SuperNET_accountfind(json);
    if ( remoteaddr == 0 && (exchange= exchanges777_find("bitcoin")) != 0 )
    {
        if ( (retstr= instantdex_createaccept(myinfo,&ap,exchanges777_find("bitcoin"),base,rel,minprice,basevolume,1,base,INSTANTDEX_OFFERDURATION,myinfo->myaddr.nxt64bits,juint(json,"minperc"))) != 0 )
            free(retstr);
        retstr = instantdex_checkoffer(myinfo,&added,&txid,exchange,ap,json);
        if ( added == 0 )
            free(ap);
        return(retstr);
    } else return(clonestr("{\"error\":\"InstantDEX API request only local usage!\"}"));
}

char *instantdex_statemachineget(struct supernet_info *myinfo,struct bitcoin_swapinfo **swapp,cJSON *argjson,char *remoteaddr)
{
    struct bitcoin_swapinfo *swap; uint64_t orderid,otherorderid; struct exchange_info *exchange;
    *swapp = 0;
    if ( remoteaddr == 0 && (exchange= exchanges777_find("bitcoin")) != 0 )
    {
        orderid = j64bits(argjson,"myorderid");
        otherorderid = j64bits(argjson,"otherid");
        if ( (swap= instantdex_statemachinefind(myinfo,exchange,orderid)) != 0 )
        {
            if ( swap->other.orderid != otherorderid )
                return(clonestr("{\"error\":\"statemachine otherid mismatch\"}"));
            else
            {
                *swapp = swap;
                return(0);
            }
        } else return(clonestr("{\"error\":\"statemachine not found\"}"));
    } else return(clonestr("{\"error\":\"atomic API request only local usage!\"}"));
}

THREE_STRINGS(atomic,approve,myorderid,otherid,txname)
{
    char *retstr,virtualevent[16]; cJSON *newjson; struct bitcoin_statetx *tx; struct bitcoin_swapinfo *swap = 0;
    if ( (retstr= instantdex_statemachineget(myinfo,&swap,json,remoteaddr)) != 0 )
        return(retstr);
    else if ( (tx= instantdex_getstatetx(swap,txname)) == 0 )
        return(clonestr("{\"error\":\"cant find txname\"}"));
    else
    {
        strcpy(virtualevent,txname);
        strcat(virtualevent,"found");
        newjson = cJSON_CreateObject();
        if ( (retstr= instantdex_sendcmd(myinfo,&swap->mine.offer,newjson,virtualevent,myinfo->myaddr.persistent,0,0,0,0)) != 0 )
            return(retstr);
        else return(clonestr("{\"result\":\"statemachine sent found event\"}"));
    }
}

THREE_STRINGS(atomic,claim,myorderid,otherid,txname)
{
    char *retstr; struct bitcoin_statetx *tx; struct bitcoin_swapinfo *swap = 0;
    if ( (retstr= instantdex_statemachineget(myinfo,&swap,json,remoteaddr)) != 0 )
        return(retstr);
    else if ( (tx= instantdex_getstatetx(swap,txname)) == 0 )
        return(clonestr("{\"error\":\"cant find txname\"}"));
    else
    {
        return(clonestr("{\"result\":\"statemachine should claim tx\"}"));
    }
}

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

cJSON *instantdex_reportjson(cJSON *item,char *name)
{
    cJSON *newjson = cJSON_CreateObject(); uint64_t dateval;
    dateval = juint(item,"timestamp"), dateval *= 1000;
    newjson = cJSON_CreateObject();
    jadd(newjson,name,jduplicate(jobj(item,"price")));
    jadd(newjson,"volume",jduplicate(jobj(item,"volume")));
    jadd(newjson,"orderid",jduplicate(jobj(item,"orderid")));
    jadd(newjson,"account",jduplicate(jobj(item,"account")));
    jaddnum(newjson,"date",dateval);
    jaddnum(newjson,"s",dateval % 60);
    jaddnum(newjson,"m",(dateval / 60) % 60);
    jaddnum(newjson,"h",(dateval / 3600) % 24);
    return(newjson);
}

TWO_STRINGS(InstantDEX,events,base,rel)
{
    cJSON *bids,*asks,*array,*item; int32_t i,n; struct exchange_info *exchange;
    array = cJSON_CreateArray();
    if ( (exchange= exchanges777_find("bitcoin")) != 0 )
    {
        bids = cJSON_CreateArray();
        asks = cJSON_CreateArray();
        instantdex_offerfind(myinfo,exchange,bids,asks,0,base,rel,1);
        if ( (n= cJSON_GetArraySize(bids)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(bids,i);
                jaddi(array,instantdex_reportjson(item,"bid"));
            }
        }
        if ( (n= cJSON_GetArraySize(asks)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(asks,i);
                jaddi(array,instantdex_reportjson(item,"ask"));
            }
        }
        free_json(bids);
        free_json(asks);
    }
    return(jprint(array,1));
    
    //return(clonestr("[{\"h\":14,\"m\":44,\"s\":32,\"date\":1407877200000,\"bid\":30,\"ask\":35},{\"date\":1407877200000,\"bid\":40,\"ask\":44},{\"date\":1407877200000,\"bid\":49,\"ask\":45},{\"date\":1407877200000,\"ask\":28},{\"date\":1407877200000,\"ask\":52}]"));
}

#include "../includes/iguana_apiundefs.h"

