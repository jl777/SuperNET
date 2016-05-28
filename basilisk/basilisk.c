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

char *basilisk_finish(struct basilisk_item *ptr,int32_t besti)
{
    int32_t i; char *retstr = 0;
    for (i=0; i<ptr->numresults; i++)
    {
        if ( besti >= 0 && i != besti )
        {
            if ( ptr->results[i] != 0 )
                free(ptr->results[i]);
        }
        else retstr = ptr->results[i];
        ptr->results[i] = 0;
    }
    ptr->finished = (uint32_t)time(NULL);
    return(retstr);
}

cJSON *basilisk_json(struct supernet_info *myinfo,cJSON *hexjson,uint32_t basilisktag,int32_t timeout)
{
    char *str,*buf; cJSON *retjson;
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
            jadd(hexjson,"vals",retstr);
            retjson = basilisk_json(myinfo,hexjson,basilisktag,timeoutmillis);
            free_json(hexjson);
            printf("resultsjson.(%s)\n",jprint(retjson,0));
        }
        else // local request
            retjson = cJSON_Parse(retstr);
    }
    return(retjson);
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
    printf("basilisk_submit.(%s)\n",reqstr);
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

struct basilisk_item *basilisk_issue(struct supernet_info *myinfo,cJSON *hexjson,int32_t timeoutmillis,int32_t fanout,int32_t minresults,uint32_t basilisktag)
{
    double expiration; struct basilisk_item *ptr;
    ptr = calloc(1,sizeof(*ptr));
    if ( basilisktag == 0 )
        basilisktag = rand();
    ptr->basilisktag = basilisktag;
    queue_enqueue("submitQ",&myinfo->basilisks.submitQ,&ptr->DL,0);
    if ( basilisk_submit(myinfo,hexjson,timeoutmillis,fanout,ptr) > 0 )
    {
        if ( timeoutmillis >= 0 )
        {
            expiration = OS_milliseconds() + ((timeoutmillis == 0) ? BASILISK_TIMEOUT : timeoutmillis);
            while ( OS_milliseconds() < expiration && ptr->finished == 0 && ptr->numresults < minresults )
                usleep(timeoutmillis/100 + 1);
        }
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
            coin->basilisk_value = basilisk_bitcoinvalue;
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

char *basilisk_issuecmd(basilisk_func func,struct supernet_info *myinfo,char *remoteaddr,uint32_t basilisktag,char *symbol,int32_t timeoutmillis,cJSON *vals)
{
    struct iguana_info *coin; char *retstr=0; cJSON *retjson;
    if ( basilisktag == 0 )
        OS_randombytes((uint8_t *)&basilisktag,sizeof(basilisktag));
    if ( (coin= iguana_coinfind(symbol)) != 0 )
    {
        if ( func != 0 )
        {
            if ( (retstr= (*func)(myinfo,coin,remoteaddr,basilisktag,timeoutmillis,vals)) != 0 )
            {
                retjson = basilisk_resultsjson(myinfo,symbol,remoteaddr,basilisktag,timeoutmillis,retstr);
                free(retstr);
                retstr = jprint(retjson,1);
            }
        }
    }
    return(retstr);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

INT_ARRAY_STRING(basilisk,balances,lastheight,addresses,activecoin)
{
    /*uint64_t amount,total = 0; cJSON *item,*result,*array,*retjson,*hexjson; int32_t i,n,minconf=0; char *retstr,*balancestr,*coinaddr;
    retjson = cJSON_CreateObject();
    if ( activecoin != 0 && activecoin[0] != 0 && (coin= iguana_coinfind(activecoin)) != 0 )
    {
xxx
        jadd(retjson,"balances",array);
            jaddnum(retjson,"total",dstr(total));
            if ( lastheight != 0 )
                jaddnum(retjson,"lastheight",lastheight);
            if ( remoteaddr != 0 && remoteaddr[0] != 0 && strcmp(remoteaddr,"127.0.0.1") != 0 )
            {
                //printf("remote req.(%s)\n",jprint(retjson,0));
                hexjson = cJSON_CreateObject();
                jaddstr(hexjson,"rawtx",jprint(retjson,1));
                jaddstr(hexjson,"agent","iguana");
                jaddstr(hexjson,"method","rawtx_result");
                jaddstr(hexjson,"activecoin",activecoin);
                jaddnum(hexjson,"basilisktag",lastheight);
                retjson = iguana_json(myinfo,hexjson);
            } else jaddstr(retjson,"result","success");
            return(jprint(retjson,1));
        }
        else if ( remoteaddr == 0 || remoteaddr[0] == 0 || strcmp(remoteaddr,"127.0.0.1") == 0 )
        {
            if ( (retstr= basilisk_request_andwait(myinfo,&myinfo->basiliskQ,0,json,lastheight,juint(json,"timeout"))) == 0 )
                return(clonestr("{\"error\":\"timeout waiting for remote request\"}"));
            else return(retstr);
        } else return(clonestr("{\"error\":\"invalid remoterequest when not relaynode\"}"));
    } else */return(clonestr("{\"error\":\"invalid request for inactive coin\"}"));
}

INT_ARRAY_STRING(basilisk,rawtx,basilisktag,vals,activecoin)
{
    cJSON *addresses=0; char *changeaddr,*spendscriptstr; int32_t i,n,timeoutmillis;
    changeaddr = jstr(vals,"changeaddr");
    spendscriptstr = jstr(vals,"spendscript");
    addresses = jarray(&n,vals,"addresses");
    timeoutmillis = jint(vals,"timeout");
    if ( addresses == 0 || changeaddr == 0 || changeaddr[0] == 0 )
        return(clonestr("{\"error\":\"invalid addresses[] or changeaddr\"}"));
    else
    {
        for (i=0; i<n; i++)
            if ( strcmp(jstri(addresses,i),changeaddr) == 0 )
                return(clonestr("{\"error\":\"changeaddr cant be in addresses[]\"}"));
    }
    if ( spendscriptstr != 0 && spendscriptstr[0] != 0 && activecoin != 0 && activecoin[0] != 0 )
    {
        return(basilisk_issuecmd(coin->basilisk_rawtx,myinfo,remoteaddr,basilisktag,activecoin,timeoutmillis,vals));
    }
    return(clonestr("{\"error\":\"missing activecoin or spendscript\"}"));
}

INT_ARRAY_STRING(basilisk,value,basilisktag,vals,activecoin)
{
    int32_t timeoutmillis;
    if ( activecoin != 0 && activecoin[0] != 0 && vals != 0 )
    {
        timeoutmillis = jint(vals,"timeout");
        return(basilisk_issuecmd(coin->basilisk_value,myinfo,remoteaddr,basilisktag,activecoin,timeoutmillis,vals));
    }
    return(clonestr("{\"error\":\"missing activecoin\"}"));
}

INT_AND_ARRAY(basilisk,result,basilisktag,vals)
{
    struct basilisk_item *ptr; char *hexmsg=0;
    if ( vals != 0 && (hexmsg= jstr(vals,"hexmsg")) != 0 )
    {
        ptr = calloc(1,sizeof(*ptr));
        ptr->results[0] = jprint(vals,0);
        ptr->basilisktag = basilisktag;
        ptr->numresults = 1;
        //printf("Q results hexmsg.(%s) args.(%s)\n",hexmsg,jprint(args,0));
        queue_enqueue("resultsQ",&myinfo->basilisks.resultsQ,&ptr->DL,0);
        return(clonestr("{\"result\":\"queued basilisk return\"}"));
    } else printf("null vals.(%s) or no hexmsg.%p\n",jprint(vals,0),hexmsg);
    return(clonestr("{\"error\":\"no hexmsg to return\"}"));
}

#include "../includes/iguana_apiundefs.h"


char *basilisk_hexmsg(struct supernet_info *myinfo,struct category_info *cat,void *ptr,int32_t len,char *remoteaddr)
{
    char *method="",*agent="",*retstr = 0,*tmpstr,*hexmsg; int32_t i,j,n,timeoutmillis; cJSON *array,*json,*valsobj; struct iguana_info *coin=0; struct iguana_peer *addr; uint32_t basilisktag;
    array = 0;
    if ( (json= cJSON_Parse(ptr)) != 0 )
    {
        printf("basilisk.(%s)\n",jprint(json,0));
        //basilisk.({"basilisktag":2955372280,"agent":"basilisk","method":"rawtx","vals":{"changeaddr":"1FNhoaBYzf7safMBjoCsJYgxtah3K95sep","addresses":["1Hgzt5xsnbfc8UTWqWKSTLRm5bEYHYBoCE"],"timeout":5000,"amount":"20000","spendscript":"76a914b7128d2ee837cf03e30a2c0e3e0181f7b9669bb688ac"},"basilisktag":2955372280})
       // basilisk.({"agent":"basilisk","method":"rawtx","activecoin":"BTC","basilisktag":1398466607})

        agent = jstr(json,"agent");
        method = jstr(json,"method");
        if ( agent != 0 && method != 0 && strcmp(agent,"SuperNET") == 0 && strcmp(method,"DHT") == 0 && (hexmsg= jstr(json,"hexmsg")) != 0 )
        {
            n = (int32_t)(strlen(hexmsg) >> 1);
            tmpstr = calloc(1,n + 1);
            decode_hex((void *)tmpstr,n,hexmsg);
            free_json(json);
            if ( (json= cJSON_Parse(tmpstr)) == 0 )
            {
                printf("couldnt parse decoded hexmsg.(%s)\n",tmpstr);
                free(tmpstr);
                return(0);
            }
            free(tmpstr);
            agent = jstr(json,"agent");
            method = jstr(json,"method");
        }
        basilisktag = juint(json,"basilisktag");
        if ( strcmp(agent,"basilisk") == 0 && (valsobj= jobj(json,"vals")) != 0 )
        {
            if ( jobj(json,"timeout") != 0 )
                timeoutmillis = jint(json,"timeout");
            if ( valsobj != 0 && jobj(valsobj,"coin") != 0 )
                coin = iguana_coinfind(jstr(valsobj,"coin"));
            else if ( jstr(json,"activecoin") != 0 )
                coin = iguana_coinfind(jstr(json,"activecoin"));
            if ( coin != 0 )
            {
                if ( coin->RELAYNODE != 0 || coin->VALIDATENODE != 0 )
                {
                    if ( strcmp(method,"rawtx") == 0 )
                    {
                        retstr = basilisk_issuecmd(coin->basilisk_rawtx,myinfo,remoteaddr,basilisktag,coin->symbol,timeoutmillis,valsobj);
                    }
                    else if ( strcmp(method,"balances") == 0 )
                    {
                        retstr = basilisk_issuecmd(coin->basilisk_balances,myinfo,remoteaddr,basilisktag,coin->symbol,timeoutmillis,valsobj);
                    }
                    else if ( strcmp(method,"value") == 0 )
                    {
                        retstr = basilisk_issuecmd(coin->basilisk_value,myinfo,remoteaddr,basilisktag,coin->symbol,timeoutmillis,valsobj);
                    }
                    if ( retstr == 0 )
                        return(0);
                    //printf("basilisk will return.(%s)\n",retstr);
                    for (j=0; j<IGUANA_MAXCOINS; j++)
                    {
                        if ( (coin= Coins[j]) == 0 )
                            continue;
                        for (i=0; i<IGUANA_MAXPEERS; i++)
                        {
                            if ( (addr= &coin->peers.active[i]) != 0 && addr->usock >= 0 )
                            {
                                if ( addr->supernet != 0 && strcmp(addr->ipaddr,remoteaddr) == 0 )
                                {
                                    printf("send back.%d basilisk_result addr->supernet.%u to (%s).%d\n",(int32_t)strlen(retstr),addr->supernet,addr->ipaddr,addr->A.port);
                                    iguana_send_supernet(addr,retstr,0);
                                    free_json(json);
                                    return(retstr);
                                }
                            }
                            if ( 0 && addr->ipbits != 0 )
                                printf("i.%d (%s) vs (%s) %s\n",i,addr->ipaddr,remoteaddr,coin->symbol);
                        }
                    }
                }
                else
                {
                    if ( strcmp(method,"result") == 0 )
                    {
                        //printf("got rawtx.(%s)\n",jstr(valsobj,"hexmsg"));
                        return(basilisk_result(myinfo,coin,json,remoteaddr,basilisktag,valsobj));
                    }
                }
            }
        }
    }
    printf("unhandled bitcoin_hexmsg.(%d) from %s (%s/%s)\n",len,remoteaddr,agent,method);
    free_json(json);
    return(retstr);
}

void basilisks_loop(void *arg)
{
    struct basilisk_item *ptr,*tmp,*pending; int32_t i,flag,n; struct supernet_info *myinfo = arg;
    uint8_t *blockspace; struct OS_memspace RAWMEM; struct iguana_info *coin;
    memset(&RAWMEM,0,sizeof(RAWMEM));
    blockspace = calloc(1,IGUANA_MAXPACKETSIZE);
    while ( 1 )
    {
        for (i=0; i<IGUANA_MAXCOINS; i++)
            if ( (coin= Coins[i]) != 0 && coin->RELAYNODE == 0 && coin->VALIDATENODE == 0 && coin->active != 0 && coin->chain->userpass[0] != 0 && coin->MAXPEERS == 1 )
                basilisk_bitcoinscan(coin,blockspace,&RAWMEM);
        if ( (ptr= queue_dequeue(&myinfo->basilisks.submitQ,0)) != 0 )
        {
            if ( ptr->finished == 0 )
                HASH_ADD(hh,myinfo->basilisks.issued,basilisktag,sizeof(ptr->basilisktag),ptr);
            else free(ptr);
            continue;
        }
        else if ( (ptr= queue_dequeue(&myinfo->basilisks.resultsQ,0)) != 0 )
        {
            HASH_FIND(hh,myinfo->basilisks.issued,&ptr->basilisktag,sizeof(ptr->basilisktag),pending);
            if ( pending != 0 )
            {
                if ( (n= pending->numresults) < sizeof(pending->results)/sizeof(*pending->results) )
                {
                    pending->results[n] = ptr->results[0];
                    pending->numresults++;
                }
            }
            free(ptr);
            continue;
        }
        else
        {
            flag = 0;
            HASH_ITER(hh,myinfo->basilisks.issued,ptr,tmp)
            {
                if ( ptr->finished != 0 )
                {
                    HASH_DELETE(hh,myinfo->basilisks.issued,ptr);
                    free(ptr);
                    flag++;
                }
            }
            if ( flag == 0 )
                usleep(100000);
        }
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
