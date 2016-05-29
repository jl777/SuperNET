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

char *basilisk_finish(struct basilisk_item *ptr,int32_t besti,char *errstr)
{
    char *retstr = 0; struct basilisk_item *parent;
    if ( ptr->retstr != 0 )
        return(ptr->retstr);
    if ( besti >= 0 && besti < ptr->numresults )
    {
        retstr = ptr->results[besti];
        ptr->results[besti] = 0;
    } else printf("besti.%d vs numresults.%d retstr.%p\n",besti,ptr->numresults,retstr);
    if ( retstr == 0 )
        retstr = clonestr(errstr);
    ptr->retstr = retstr;
    ptr->finished = (uint32_t)time(NULL);
    if ( (parent= ptr->parent) != 0 )
    {
        ptr->parent = 0;
        parent->childrendone++;
    }
    return(retstr);
}

cJSON *basilisk_json(struct supernet_info *myinfo,cJSON *hexjson,uint32_t basilisktag,int32_t timeout)
{
    char *str,*buf; cJSON *retjson;
    if ( jobj(hexjson,"basilisktag") != 0 )
        jdelete(hexjson,"basilisktag");
    jaddnum(hexjson,"basilisktag",basilisktag);
    str = jprint(hexjson,0);
    buf = malloc(strlen(str)*2 + 1);
    init_hexbytes_noT(buf,(uint8_t *)str,(int32_t)strlen(str));
    free(str);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"hexmsg",buf);
    free(buf);
    jaddstr(retjson,"agent","SuperNET");
    jaddstr(retjson,"method","DHT");
    jaddnum(retjson,"request",1);
    jaddnum(retjson,"plaintext",1);
    jaddbits256(retjson,"categoryhash",myinfo->basilisk_category);
    jaddnum(retjson,"timeout",timeout);
    return(retjson);
}

/*char *basilisk_results(uint32_t basilisktag,cJSON *valsobj)
{
    cJSON *resultobj = cJSON_CreateObject();
    jadd(resultobj,"vals",valsobj);
    jaddstr(resultobj,"agent","basilisk");
    jaddstr(resultobj,"method","result");
    jaddnum(resultobj,"plaintext",1);
    if ( jobj(resultobj,"basilisktag") != 0 )
        jdelete(resultobj,"basilisktag");
    jaddnum(resultobj,"basilisktag",basilisktag);
    return(jprint(resultobj,1));
}

cJSON *basilisk_resultsjson(struct supernet_info *myinfo,char *symbol,char *remoteaddr,uint32_t basilisktag,int32_t timeoutmillis,char *retstr)
{
    cJSON *hexjson=0,*retjson=0;
    if ( retstr != 0 )
    {
        if ( remoteaddr != 0 && remoteaddr[0] != 0 )
        {
            hexjson = cJSON_CreateObject();
            jaddstr(hexjson,"agent","basilisk");
            jaddstr(hexjson,"method","result");
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
                jadd(hexjson,"vals",retjson);
            retjson = basilisk_json(myinfo,hexjson,basilisktag,timeoutmillis);
            free_json(hexjson);
            printf("resultsjson.(%s)\n",jprint(retjson,0));
        }
        else // local request
            retjson = cJSON_Parse(retstr);
    }
    return(retjson);
}*/

struct basilisk_item *basilisk_itemcreate(struct supernet_info *myinfo,uint32_t basilisktag,int32_t minresults,cJSON *vals,int32_t timeoutmillis,void *metricfunc,char *symbol)
{
    struct basilisk_item *ptr;
    ptr = calloc(1,sizeof(*ptr));
    ptr->basilisktag = basilisktag;
    if ( (ptr->numrequired= minresults) == 0 )
        ptr->numrequired = 1;
    if ( (ptr->metricfunc= metricfunc) != 0 )
        ptr->vals = jduplicate(vals);
    strcpy(ptr->symbol,symbol);
    ptr->expiration = OS_milliseconds() + timeoutmillis;
    queue_enqueue("submitQ",&myinfo->basilisks.submitQ,&ptr->DL,0);
    return(ptr);
}

#include "basilisk_bitcoin.c"
#include "basilisk_nxt.c"
#include "basilisk_ether.c"
#include "basilisk_waves.c"
#include "basilisk_lisk.c"

int32_t basilisk_submit(struct supernet_info *myinfo,cJSON *reqjson,int32_t timeout,int32_t fanout,struct basilisk_item *ptr)
{
    int32_t i,j,k,l,r2,r,n; struct iguana_peer *addr; struct iguana_info *coin; char *reqstr; cJSON *tmpjson;
    tmpjson = basilisk_json(myinfo,reqjson,ptr->basilisktag,timeout);
    reqstr = jprint(tmpjson,1);
    //printf("basilisk_submit.(%s)\n",reqstr);
    if ( fanout <= 0 )
        fanout = BASILISK_MINFANOUT;
    else if ( fanout > BASILISK_MAXFANOUT )
        fanout = BASILISK_MAXFANOUT;
    r2 = rand();
    for (l=n=0; l<IGUANA_MAXCOINS; l++)
    {
        i = (l + r2) % IGUANA_MAXCOINS;
        if ( (coin= Coins[i]) != 0 )
        {
            r = rand();
            for (k=0; k<IGUANA_MAXPEERS; k++)
            {
                j = (k + r) % IGUANA_MAXPEERS;
                if ( (addr= &coin->peers.active[j]) != 0 && addr->supernet != 0 && addr->usock >= 0 )
                {
                    ptr->submit = (uint32_t)time(NULL);
                    printf("submit to (%s)\n",addr->ipaddr);
                    iguana_send_supernet(addr,reqstr,0);
                    if ( n++ > fanout )
                        break;
                }
            }
        }
    }
    free(reqstr);
    return(n);
}

struct basilisk_item *basilisk_issueremote(struct supernet_info *myinfo,char *methodstr,char *symbol,cJSON *vals,int32_t timeoutmillis,int32_t fanout,int32_t minresults,uint32_t basilisktag,void *_metricfunc,char *retstr)
{
    struct basilisk_item *ptr; cJSON *hexjson; basilisk_metricfunc metricfunc = _metricfunc;
    if ( basilisktag == 0 )
        basilisktag = rand();
    ptr = basilisk_itemcreate(myinfo,basilisktag,minresults,vals,timeoutmillis,metricfunc,symbol);
    if ( retstr != 0 )
    {
        ptr->retstr = retstr;
        ptr->results[0] = retstr;
        ptr->numresults = ptr->numrequired;
        ptr->metrics[0] = (*metricfunc)(myinfo,ptr,retstr);
        ptr->finished = (uint32_t)time(NULL);
    }
    else
    {
        hexjson = cJSON_CreateObject();
        jaddstr(hexjson,"agent","basilisk");
        jaddnum(hexjson,"basilisktag",basilisktag);
        jaddstr(hexjson,"method",methodstr);
        jaddstr(hexjson,"activecoin",symbol);
        jaddnum(hexjson,"timeout",timeoutmillis);
        if ( vals != 0 )
            jadd(hexjson,"vals",jduplicate(vals));
        printf("issue.(%s) timeout.%d\n",jprint(hexjson,0),timeoutmillis);
        if ( basilisk_submit(myinfo,hexjson,timeoutmillis,fanout,ptr) > 0 )
        {
            /*if ( timeoutmillis > 0 )
             {
             printf("unexpected blocking\n");
             expiration = OS_milliseconds() + ((timeoutmillis == 0) ? BASILISK_TIMEOUT : timeoutmillis);
             while ( OS_milliseconds() < expiration && ptr->finished == 0 && ptr->numresults < ptr->numrequired )
             usleep(timeoutmillis/100 + 1);
             }*/
        }
        free_json(hexjson);
    }
    return(ptr);
}

void basilisk_functions(struct iguana_info *coin)
{
    switch ( coin->protocol )
    {
        case IGUANA_PROTOCOL_BITCOIN:
            coin->basilisk_balances = basilisk_bitcoinbalances;
            coin->basilisk_rawtx = basilisk_bitcoinrawtx;
            coin->basilisk_rawtxmetric = basilisk_bitcoin_rawtxmetric;
            coin->basilisk_value = basilisk_bitcoinvalue;
            coin->basilisk_valuemetric = basilisk_bitcoin_valuemetric;
            break;
        /*case IGUANA_PROTOCOL_IOTA:
            coin->basilisk_balances = basilisk_iotabalances;
            coin->basilisk_rawtx = basilisk_iotarawtx;
            break;
        case IGUANA_PROTOCOL_NXT:
            coin->basilisk_balances = basilisk_nxtbalances;
            coin->basilisk_rawtx = basilisk_nxtrawtx;
            break;
        case IGUANA_PROTOCOL_ETHER:
            coin->basilisk_balances = basilisk_etherbalances;
            coin->basilisk_rawtx = basilisk_etherrawtx;
            break;
        case IGUANA_PROTOCOL_WAVES:
            coin->basilisk_balances = basilisk_wavesbalances;
            coin->basilisk_rawtx = basilisk_wavesrawtx;
            break;
        case IGUANA_PROTOCOL_LISK:
            coin->basilisk_balances = basilisk_liskbalances;
            coin->basilisk_rawtx = basilisk_liskrawtx;
            break;*/
    }
}

int32_t basilisk_besti(struct basilisk_item *ptr)
{
    int32_t i,besti = -1; double metric,bestmetric=-1.;
    for (i=0; i<ptr->numresults; i++)
    {
        if ( (metric= ptr->metrics[i]) > 0. )
        {
            if ( (ptr->metricdir < 0 && (bestmetric < 0. || metric < bestmetric)) || (ptr->metricdir > 0 && (bestmetric < 0. || metric > bestmetric)) || (ptr->metricdir == 0 && bestmetric < 0.) )
            {
                bestmetric = metric;
                besti = i;
            }
        }
    }
    if ( besti >= 0 )
    {
        for (ptr->numexact=i=0; i<ptr->numresults; i++)
            if ( fabs(ptr->metrics[i] - bestmetric) < SMALLVAL )
                ptr->numexact++;
    }
    return(besti);
}

char *basilisk_iscomplete(struct basilisk_item *ptr)
{
    int32_t i,numvalid,besti=-1; char *errstr = 0,*retstr = 0;
    if ( ptr->childrendone < ptr->numchildren )
        return(0);
    if ( ptr->retstr != 0 || ptr->finished != 0 )
        return(ptr->retstr);
    if ( (numvalid= ptr->numresults) >= ptr->numrequired )
    {
        for (i=numvalid=0; i<ptr->numresults; i++)
        {
            if ( ptr->metrics[i] != 0. )
                numvalid++;
        }
    }
    if ( numvalid < ptr->numrequired )
    {
        //printf("%u: numvalid.%d < required.%d m %f\n",ptr->basilisktag,numvalid,ptr->numrequired,ptr->metrics[0]);
        return(0);
    }
    if ( ptr->uniqueflag == 0 && ptr->numexact != ptr->numresults && ptr->numexact < (ptr->numresults >> 1) )
        besti = -1, errstr = "{\"error\":\"basilisk non-consensus results\"}";
    else besti = basilisk_besti(ptr), errstr = "{\"error\":\"basilisk no valid results\"}";
    //printf("%u complete besti.%d\n",ptr->basilisktag,besti);
    retstr = basilisk_finish(ptr,besti,errstr);
    //printf("%u besti.%d numexact.%d numresults.%d -> (%s)\n",ptr->basilisktag,besti,ptr->numexact,ptr->numresults,retstr);
    return(retstr);
}

int32_t basilisk_sendcmd(char *ipaddr,char *msgstr)
{
    int32_t i,j,r,r2,k,l; struct iguana_info *coin; struct iguana_peer *addr;
    r = rand(), r2 = rand();
    for (k=0; k<IGUANA_MAXCOINS; k++)
    {
        j = (r2 + k) % IGUANA_MAXCOINS;
        if ( (coin= Coins[j]) == 0 )
            continue;
        for (l=0; l<IGUANA_MAXPEERS; l++)
        {
            i = (l + r) % IGUANA_MAXPEERS;
            if ( (addr= &coin->peers.active[i]) != 0 && addr->usock >= 0 )
            {
                if ( addr->supernet != 0 && (ipaddr == 0 || ipaddr[0] == 0 || strcmp(addr->ipaddr,ipaddr) == 0) )
                {
                    //printf("send back.%s basilisk_result addr->supernet.%u to (%s).%d\n",retstr,addr->supernet,addr->ipaddr,addr->A.port);
                    return(iguana_send_supernet(addr,msgstr,0));
                }
            }
        }
    }
    return(-1);
}

char *basilisk_block(struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,struct basilisk_item *Lptr,struct basilisk_item *ptr)
{
    char *retstr = 0; cJSON *hexobj,*retjson,*valsobj;
    if ( ptr == Lptr )
    {
        if ( (retstr= Lptr->retstr) == 0 )
            retstr = clonestr("{\"result\":\"null return from local basilisk_issuecmd\"}");
        ptr = basilisk_itemcreate(myinfo,Lptr->basilisktag,Lptr->numrequired,Lptr->vals,OS_milliseconds() - Lptr->expiration,Lptr->metricfunc,Lptr->symbol);
        //printf("block got local.(%s)\n",retstr);
    }
    else
    {
        while ( OS_milliseconds() < ptr->expiration )
        {
            //if ( (retstr= basilisk_iscomplete(ptr)) != 0 )
            if ( (retstr= ptr->retstr) != 0 )
                break;
            usleep(1000000);
        }
        if ( retstr == 0 )
            retstr = basilisk_finish(ptr,-1,"{\"error\":\"basilisk timeout\"}");
    }
    if ( retstr != 0 && remoteaddr != 0 && remoteaddr[0] != 0 && strcmp(remoteaddr,"127.0.0.1") != 0 )
    {
        hexobj = cJSON_CreateObject();
        jaddstr(hexobj,"agent","basilisk");
        jaddstr(hexobj,"method","result");
        jaddnum(hexobj,"basilisktag",ptr->basilisktag);
        if ( (valsobj= cJSON_Parse(retstr)) != 0 )
        {
            if ( jobj(valsobj,"coin") == 0 )
                jaddstr(valsobj,"coin",ptr->symbol);
            jadd(hexobj,"vals",valsobj);
        }
        retjson = basilisk_json(myinfo,hexobj,ptr->basilisktag,0);
        free_json(hexobj);
        free(retstr);
        retstr = jprint(retjson,1);
        basilisk_sendcmd(remoteaddr,retstr);
    }
    return(retstr);
}

struct basilisk_item *basilisk_issuecmd(struct basilisk_item *Lptr,basilisk_func func,basilisk_metricfunc metricfunc,struct supernet_info *myinfo,char *remoteaddr,uint32_t basilisktag,char *symbol,int32_t timeoutmillis,cJSON *vals)
{
    struct iguana_info *coin; struct basilisk_item *ptr;
    memset(Lptr,0,sizeof(*Lptr));
    if ( (coin= iguana_coinfind(symbol)) != 0 )
    {
        if ( func != 0 )
        {
            if ( (ptr= (*func)(Lptr,myinfo,coin,remoteaddr,basilisktag,timeoutmillis,vals)) != 0 )
            {
                if ( (ptr->metricfunc= metricfunc) != 0 )
                    ptr->vals = jduplicate(vals);
                strcpy(ptr->symbol,symbol);
                ptr->basilisktag = basilisktag;
                ptr->expiration = OS_milliseconds() + timeoutmillis;
                return(ptr);
            }
            else Lptr->retstr = clonestr("{\"error\":\"error issuing basilisk command\"}");
        } else Lptr->retstr = clonestr("{\"error\":\"null basilisk function\"}");
    } else Lptr->retstr = clonestr("{\"error\":\"error missing coin\"}");
    return(Lptr);
}

char *basilisk_check(int32_t *timeoutmillisp,uint32_t *basilisktagp,char *symbol,cJSON *vals)
{
    if ( symbol != 0 && symbol[0] != 0 && vals != 0 )
    {
        if ( *basilisktagp == 0 )
            *basilisktagp = rand();
        if ( (*timeoutmillisp= jint(vals,"timeout")) < 0 )
            *timeoutmillisp = BASILISK_TIMEOUT;
        return(0);
    } else return(clonestr("{\"error\":\"missing activecoin or vals\"}"));
}

char *basilisk_standardcmd(struct supernet_info *myinfo,char *activecoin,char *remoteaddr,uint32_t basilisktag,cJSON *vals,basilisk_func func,basilisk_metricfunc metric)
{
    char *retstr; struct basilisk_item *ptr,Lptr; int32_t timeoutmillis; struct iguana_info *coin;
    if ( (retstr= basilisk_check(&timeoutmillis,&basilisktag,activecoin,vals)) == 0 )
    {
        if ( (coin= iguana_coinfind(activecoin)) != 0 )
        {
            if ( (ptr= basilisk_issuecmd(&Lptr,func,metric,myinfo,remoteaddr,basilisktag,activecoin,timeoutmillis,vals)) != 0 )
                return(basilisk_block(myinfo,coin,remoteaddr,&Lptr,ptr));
            else return(clonestr("{\"error\":\"null return from basilisk_issuecmd\"}"));
        } else return(clonestr("{\"error\":\"couldnt get coin\"}"));
    } else return(retstr);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

INT_ARRAY_STRING(basilisk,balances,basilisktag,vals,activecoin)
{
    if ( (coin= iguana_coinfind(activecoin)) != 0 )
        return(basilisk_standardcmd(myinfo,activecoin,remoteaddr,basilisktag,vals,coin->basilisk_balances,coin->basilisk_balancesmetric));
    else return(clonestr("{\"error\":\"cant find missing coin\"}"));
}

INT_ARRAY_STRING(basilisk,value,basilisktag,vals,activecoin)
{
    if ( (coin= iguana_coinfind(activecoin)) != 0 )
        return(basilisk_standardcmd(myinfo,activecoin,remoteaddr,basilisktag,vals,coin->basilisk_value,coin->basilisk_valuemetric));
    else return(clonestr("{\"error\":\"cant find missing coin\"}"));
}

char *basilisk_checkrawtx(int32_t *timeoutmillisp,uint32_t *basilisktagp,char *symbol,cJSON *vals)
{
    cJSON *addresses=0; char *changeaddr,*spendscriptstr; int32_t i,n;
    *timeoutmillisp = -1;
    changeaddr = jstr(vals,"changeaddr");
    spendscriptstr = jstr(vals,"spendscript");
    addresses = jarray(&n,vals,"addresses");
    if ( addresses == 0 || changeaddr == 0 || changeaddr[0] == 0 )
        return(clonestr("{\"error\":\"invalid addresses[] or changeaddr\"}"));
    else
    {
        for (i=0; i<n; i++)
            if ( strcmp(jstri(addresses,i),changeaddr) == 0 )
                return(clonestr("{\"error\":\"changeaddr cant be in addresses[]\"}"));
    }
    if ( spendscriptstr != 0 && spendscriptstr[0] != 0 )
        return(basilisk_check(timeoutmillisp,basilisktagp,symbol,vals));
    else
    {
        printf("vals.(%s)\n",jprint(vals,0));
        return(clonestr("{\"error\":\"missing spendscript\"}"));
    }
}

INT_ARRAY_STRING(basilisk,rawtx,basilisktag,vals,activecoin)
{
    char *retstr; struct basilisk_item *ptr,Lptr; int32_t timeoutmillis;
    if ( (retstr= basilisk_checkrawtx(&timeoutmillis,(uint32_t *)&basilisktag,activecoin,vals)) == 0 )
    {
        if ( (ptr= basilisk_issuecmd(&Lptr,coin->basilisk_rawtx,coin->basilisk_rawtxmetric,myinfo,remoteaddr,basilisktag,activecoin,timeoutmillis,vals)) != 0 )
        {
            if ( (ptr->numrequired= juint(vals,"numrequired")) == 0 )
                ptr->numrequired = 1;
            ptr->uniqueflag = 1;
            ptr->metricdir = -1;
            return(basilisk_block(myinfo,coin,remoteaddr,&Lptr,ptr));
        } else return(clonestr("{\"error\":\"error issuing basilisk rawtx\"}"));
    } else return(retstr);
}

INT_AND_ARRAY(basilisk,result,basilisktag,vals)
{
    struct basilisk_item *ptr;
    if ( vals != 0 )
    {
        ptr = calloc(1,sizeof(*ptr));
        ptr->retstr = jprint(vals,0);
        ptr->basilisktag = basilisktag;
        //printf("Q.%u results vals.(%s)\n",basilisktag,ptr->retstr);
        queue_enqueue("resultsQ",&myinfo->basilisks.resultsQ,&ptr->DL,0);
        return(clonestr("{\"result\":\"queued basilisk return\"}"));
    } else printf("null vals.(%s) or no hexmsg.%p\n",jprint(vals,0),vals);
    return(clonestr("{\"error\":\"no hexmsg to return\"}"));
}
#include "../includes/iguana_apiundefs.h"

char *basilisk_hexmsg(struct supernet_info *myinfo,struct category_info *cat,void *ptr,int32_t len,char *remoteaddr) // incoming
{
    char *method="",*agent="",*retstr = 0,*tmpstr,*hexmsg; int32_t n; cJSON *array,*remotejson,*valsobj; struct iguana_info *coin=0; uint32_t basilisktag;
    array = 0;
    if ( (remotejson= cJSON_Parse(ptr)) != 0 )
    {
        //printf("basilisk.(%s)\n",jprint(remotejson,0));
        agent = jstr(remotejson,"agent");
        method = jstr(remotejson,"method");
        if ( agent != 0 && method != 0 && strcmp(agent,"SuperNET") == 0 && strcmp(method,"DHT") == 0 && (hexmsg= jstr(remotejson,"hexmsg")) != 0 )
        {
            n = (int32_t)(strlen(hexmsg) >> 1);
            tmpstr = calloc(1,n + 1);
            decode_hex((void *)tmpstr,n,hexmsg);
            free_json(remotejson);
            printf("NESTED.(%s)\n",tmpstr);
            if ( (remotejson= cJSON_Parse(tmpstr)) == 0 )
            {
                printf("couldnt parse decoded hexmsg.(%s)\n",tmpstr);
                free(tmpstr);
                return(0);
            }
            free(tmpstr);
            agent = jstr(remotejson,"agent");
            method = jstr(remotejson,"method");
        }
        basilisktag = juint(remotejson,"basilisktag");
        if ( strcmp(agent,"basilisk") == 0 && (valsobj= jobj(remotejson,"vals")) != 0 )
        {
            if ( jobj(valsobj,"coin") != 0 )
                coin = iguana_coinfind(jstr(valsobj,"coin"));
            else if ( jstr(remotejson,"activecoin") != 0 )
                coin = iguana_coinfind(jstr(remotejson,"activecoin"));
            //printf("coin.%p agent.%s method.%s vals.%p\n",coin,agent,method,valsobj);
            if ( coin != 0 )
            {
                if ( coin->RELAYNODE != 0 || coin->VALIDATENODE != 0 )
                {
                    if ( strcmp(method,"rawtx") == 0 )
                        retstr = basilisk_rawtx(myinfo,coin,0,remoteaddr,basilisktag,valsobj,coin->symbol);
                    else if ( strcmp(method,"balances") == 0 )
                        retstr = basilisk_balances(myinfo,coin,0,remoteaddr,basilisktag,valsobj,coin->symbol);
                    else if ( strcmp(method,"value") == 0 )
                        retstr = basilisk_value(myinfo,coin,0,remoteaddr,basilisktag,valsobj,coin->symbol);
                    if ( retstr != 0 )
                        free(retstr);
                    return(0);
                    // should automatically send to remote requester
                }
                else
                {
                    if ( strcmp(method,"result") == 0 )
                        return(basilisk_result(myinfo,coin,0,remoteaddr,basilisktag,valsobj));
                }
            }
        }
        free_json(remotejson);
    }
    printf("unhandled bitcoin_hexmsg.(%d) from %s (%s)\n",len,remoteaddr,(char *)ptr);
    return(retstr);
}

void basilisks_loop(void *arg)
{
    basilisk_metricfunc metricfunc; struct basilisk_item *ptr,*tmp,*pending,*parent; int32_t i,iter,flag,n; struct supernet_info *myinfo = arg;
    //uint8_t *blockspace; struct OS_memspace RAWMEM;
    //memset(&RAWMEM,0,sizeof(RAWMEM));
    //blockspace = calloc(1,IGUANA_MAXPACKETSIZE);
    iter = 0;
    while ( 1 )
    {
        iter++;
        //for (i=0; i<IGUANA_MAXCOINS; i++)
        //    if ( (coin= Coins[i]) != 0 && coin->RELAYNODE == 0 && coin->VALIDATENODE == 0 && coin->active != 0 && coin->chain->userpass[0] != 0 && coin->MAXPEERS == 1 )
        //        basilisk_bitcoinscan(coin,blockspace,&RAWMEM);
        if ( (ptr= queue_dequeue(&myinfo->basilisks.submitQ,0)) != 0 )
        {
            if ( ptr->finished == 0 )
                HASH_ADD(hh,myinfo->basilisks.issued,basilisktag,sizeof(ptr->basilisktag),ptr);
            else free(ptr);
            continue;
        }
        if ( (ptr= queue_dequeue(&myinfo->basilisks.resultsQ,0)) != 0 )
        {
            HASH_FIND(hh,myinfo->basilisks.issued,&ptr->basilisktag,sizeof(ptr->basilisktag),pending);
            if ( pending != 0 )
            {
                if ( (n= pending->numresults) < sizeof(pending->results)/sizeof(*pending->results) )
                {
                    pending->numresults++;
                    if ( (metricfunc= pending->metricfunc) == 0 )
                        pending->metrics[n] = n + 1;
                    else if ( (pending->metrics[n]= (*metricfunc)(myinfo,pending,ptr->retstr)) != 0. )
                        pending->childrendone++;
                    printf("%u Add results[%d] <- (%s) metric %f\n",pending->basilisktag,n,ptr->retstr,pending->metrics[n]);
                    pending->results[n] = ptr->retstr;
                }
            }
            free(ptr);
            continue;
        }
        flag = 0;
        HASH_ITER(hh,myinfo->basilisks.issued,pending,tmp)
        {
            //printf("pending.%u numresults.%d m %f func.%p\n",pending->basilisktag,pending->numresults,pending->metrics[0],pending->metricfunc);
            if ( (metricfunc= pending->metricfunc) != 0 )
            {
                for (i=0; i<pending->numresults; i++)
                    if ( pending->metrics[i] == 0. && pending->results[i] != 0 )
                    {
                        if ( (pending->metrics[i]= (*metricfunc)(myinfo,pending,pending->results[i])) != 0 )
                            pending->childrendone++;
                        // printf("iter.%d %p.[%d] poll metrics.%u metric %f\n",iter,pending,i,pending->basilisktag,pending->metrics[i]);
                        flag++;
                    }
            }
            basilisk_iscomplete(pending);
            if ( OS_milliseconds() > pending->expiration )
            {
                if ( pending->finished == 0 )
                {
                    if ( (parent= pending->parent) != 0 )
                    {
                        pending->parent = 0;
                        parent->childrendone++;
                    }
                    pending->finished = (uint32_t)time(NULL);
                    if ( pending->retstr == 0 )
                        pending->retstr = clonestr("{\"error\":\"basilisk timeout\"}");
                    printf("timeout call metrics.%u lag %f - %f\n",pending->basilisktag,OS_milliseconds(),pending->expiration);
                    for (i=0; i<pending->numresults; i++)
                        if ( (metricfunc= pending->metricfunc) != 0 )
                            pending->metrics[i] = (*metricfunc)(myinfo,pending,pending->results[i]);
                }
            }
            if ( pending->finished != 0 && time(NULL) > pending->finished+60 )
            {
                if ( pending->dependents == 0 || pending->childrendone >= pending->numchildren )
                {
                    HASH_DELETE(hh,myinfo->basilisks.issued,pending);
                    if ( pending->dependents != 0 )
                        free(pending->dependents);
                    printf("HASH_DELETE free ptr.%u\n",pending->basilisktag);
                    for (i=0; i<pending->numresults; i++)
                        if ( pending->results[i] != 0 )
                            free(pending->results[i]);
                    if ( pending->vals != 0 )
                        free_json(pending->vals);
                    free(pending);
                    flag++;
                }
            }
        }
        if ( flag == 0 )
            usleep(50000);
        else usleep(10000);
    }
}

void basilisks_init(struct supernet_info *myinfo)
{
    bits256 basiliskhash;
    iguana_initQ(&myinfo->basilisks.submitQ,"submitQ");
    iguana_initQ(&myinfo->basilisks.resultsQ,"resultsQ");
    basiliskhash = calc_categoryhashes(0,"basilisk",0);
    myinfo->basilisk_category = basiliskhash;
    category_subscribe(myinfo,basiliskhash,GENESIS_PUBKEY);
    category_processfunc(basiliskhash,GENESIS_PUBKEY,basilisk_hexmsg);
    category_processfunc(basiliskhash,myinfo->myaddr.persistent,basilisk_hexmsg);
    myinfo->basilisks.launched = iguana_launch(iguana_coinfind("BTCD"),"basilisks_loop",basilisks_loop,myinfo,IGUANA_PERMTHREAD);
}
