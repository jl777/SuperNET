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

char *basilisk_finish(struct basilisk_item *ptr,cJSON **argjsonp,int32_t besti)
{
    int32_t i; char *retstr = 0;
    for (i=0; i<ptr->numresults; i++)
    {
        if ( besti >= 0 && i != besti )
        {
            if ( ptr->results[i] != 0 )
                free(ptr->results[i]);
            if ( ptr->resultargs[i] != 0 )
                free_json(ptr->resultargs[i]);
        }
        else
        {
            retstr = ptr->results[i];
            if ( argjsonp != 0 )
                *argjsonp = ptr->resultargs[i];
        }
        ptr->results[i] = 0;
        ptr->resultargs[i] = 0;
    }
    ptr->finished = (uint32_t)time(NULL);
    return(retstr);
}

#include "basilisk_bitcoin.c"
#include "basilisk_nxt.c"
#include "basilisk_ether.c"
#include "basilisk_waves.c"
#include "basilisk_lisk.c"

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

int32_t basilisk_submit(struct supernet_info *myinfo,cJSON *reqjson,int32_t timeout,int32_t fanout,struct basilisk_item *ptr)
{
    int32_t i,j,k,l,r2,r,n; struct iguana_peer *addr; struct iguana_info *coin; char *reqstr; cJSON *tmpjson;
    tmpjson = basilisk_json(myinfo,reqjson,ptr->basilisktag,timeout);
    reqstr = jprint(tmpjson,1);
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

char *basilisk_issuerawtx(struct supernet_info *myinfo,char *remoteaddr,uint32_t basilisktag,char *symbol,cJSON **vinsp,uint32_t locktime,uint64_t satoshis,char *spendscriptstr,char *changeaddr,int64_t txfee,int32_t minconf,cJSON *addresses,int32_t timeout)
{
    struct iguana_info *coin; char *rawtx=0;
    *vinsp = 0;
    if ( (coin= iguana_coinfind(symbol)) != 0 )
    {
        if ( coin->basilisk_rawtx != 0 )
            rawtx = (*coin->basilisk_rawtx)(myinfo,coin,remoteaddr,basilisktag,vinsp,locktime,satoshis,changeaddr,txfee,addresses,minconf,spendscriptstr,timeout);
    }
    return(rawtx);
}

int64_t basilisk_issuebalances(struct supernet_info *myinfo,char *remoteaddr,int32_t basilisktag,char *symbol,cJSON **argsp,int32_t lastheight,int32_t minconf,cJSON *addresses,int32_t timeout)
{
    struct iguana_info *coin; int64_t balance = 0;
    *argsp = 0;
    if ( (coin= iguana_coinfind(symbol)) != 0 )
    {
        if ( coin->basilisk_balances != 0 )
            balance = (*coin->basilisk_balances)(myinfo,coin,remoteaddr,basilisktag,argsp,lastheight,minconf,addresses,timeout);
    }
    return(balance);
}

int64_t basilisk_issuevalue(struct supernet_info *myinfo,char *remoteaddr,int32_t basilisktag,char *symbol,cJSON **argsp,bits256 txid,int16_t vout,char *coinaddr,int32_t timeout)
{
    struct iguana_info *coin; int64_t value = 0;
    *argsp = 0;
    if ( (coin= iguana_coinfind(symbol)) != 0 )
    {
        if ( coin->basilisk_value != 0 )
            value = (*coin->basilisk_value)(myinfo,coin,remoteaddr,basilisktag,txid,vout,coinaddr,timeout);
    }
    return(value);
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

STRING_ARRAY_OBJ_STRING(basilisk,rawtx,changeaddr,addresses,vals,spendscriptstr)
{
    cJSON *argjson=0,*retjson,*hexjson,*valsobj; char *rawtx=0,*symbol=0; int64_t txfee,satoshis; uint32_t locktime,minconf,basilisktag; int32_t timeout;
    //printf("RAWTX changeaddr.%s (%s) remote.(%s)\n",changeaddr==0?"":changeaddr,jprint(json,0),remoteaddr);
    retjson = cJSON_CreateObject();
    if ( spendscriptstr != 0 && spendscriptstr[0] != 0 && (symbol= jstr(vals,"coin")) != 0 )
    {
        minconf = juint(vals,"minconf");
        locktime = juint(vals,"locktime");
        if ( jobj(json,"timeout") != 0 )
            timeout = jint(json,"timeout");
        else timeout = jint(vals,"timeout");
        satoshis = j64bits(vals,"amount");
        txfee = j64bits(vals,"txfee");
        if ( (basilisktag= juint(vals,"basilisktag")) == 0 )
            OS_randombytes((uint8_t *)&basilisktag,sizeof(basilisktag));
        if ( (rawtx= basilisk_issuerawtx(myinfo,remoteaddr,basilisktag,symbol,&argjson,locktime,satoshis,spendscriptstr,changeaddr,txfee,minconf,addresses,timeout)) != 0 )
        {
            //printf("return rawtx.(%s) remote.%p symbol.%s\n",rawtx,remoteaddr,symbol);
            if ( remoteaddr != 0 && remoteaddr[0] != 0 && (coin= iguana_coinfind(symbol)) != 0 )
            {
                hexjson = cJSON_CreateObject();
                jaddstr(hexjson,"rawtx",rawtx);
                jaddstr(hexjson,"agent","basilisk");
                jaddstr(hexjson,"method","result");
                if ( argjson != 0 )
                    jadd(hexjson,"args",argjson);
                valsobj = cJSON_CreateObject();
                jaddstr(valsobj,"coin",symbol);
                jadd(hexjson,"vals",valsobj);
                retjson = basilisk_json(myinfo,hexjson,basilisktag,timeout);
                free_json(hexjson);
            }
            else
            {
                jaddstr(retjson,"result",rawtx);
                if ( argjson != 0 )
                    jadd(retjson,"args",argjson);
            }
            free(rawtx);
        } else jaddstr(retjson,"error","couldnt create rawtx");
    }
    return(jprint(retjson,1));
}

INT_ARRAY_STRING(basilisk,result,basilisktag,argjson,hexmsg)
{
    struct basilisk_item *ptr = calloc(1,sizeof(*ptr) + strlen(hexmsg) + 1);
    ptr->results[0] = clonestr(hexmsg);
    ptr->basilisktag = basilisktag;
    if ( argjson != 0 )
        ptr->resultargs[0] = jduplicate(argjson);
    ptr->numresults = 1;
    queue_enqueue("resultsQ",&myinfo->basilisks.resultsQ,&ptr->DL,0);
    return(clonestr("{\"result\":\"queued basilisk return\"}"));
}

#include "../includes/iguana_apiundefs.h"


char *basilisk_hexmsg(struct supernet_info *myinfo,struct category_info *cat,void *ptr,int32_t len,char *remoteaddr)
{
    char *method="",*agent="",*retstr = 0; int32_t i,j; cJSON *vins,*json,*valsobj; struct iguana_info *coin=0; struct iguana_peer *addr;
    if ( (json= cJSON_Parse(ptr)) != 0 )
    {
        printf("basilisk.(%s)\n",jprint(json,0));
        agent = jstr(json,"agent");
        method = jstr(json,"method");
        valsobj = jobj(json,"vals");
        if ( strcmp(agent,"basilisk") == 0 )
        {
            if ( valsobj != 0 && jobj(valsobj,"coin") != 0 )
                coin = iguana_coinfind(jstr(valsobj,"coin"));
            else if ( jstr(json,"activecoin") != 0 )
                coin = iguana_coinfind(jstr(json,"activecoin"));
            if ( coin != 0 )
            {
                if ( coin->RELAYNODE != 0 || coin->VALIDATENODE != 0 )
                {
                    if ( valsobj != 0 && strcmp(method,"rawtx") == 0 )
                    {
                        uint64_t amount = j64bits(valsobj,"amount");
                        uint64_t txfee = j64bits(valsobj,"txfee");
                        int32_t minconf = juint(valsobj,"minconf");
                        int32_t timeout = juint(valsobj,"timeout");
                        uint32_t locktime = juint(valsobj,"locktime");
                        retstr = basilisk_issuerawtx(myinfo,remoteaddr,0,coin->symbol,&vins,locktime,amount,jstr(json,"spendscriptstr"),jstr(json,"changeaddr"),txfee,minconf,jobj(json,"addresses"),timeout);
                    }
                    else if ( strcmp(method,"balances") == 0 )
                    {
                        retstr = basilisk_balances(myinfo,coin,json,remoteaddr,juint(json,"lastheight"),jobj(json,"addresses"),jstr(json,"activecoin"));
                    }
                    if ( retstr == 0 )
                        return(0);
                    printf("basilisk will return.(%s)\n",retstr);
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
                        printf("got rawtx.(%s)\n",jstr(json,"hexmsg"));
                        return(basilisk_result(myinfo,coin,json,remoteaddr,juint(json,"basilisktag"),jobj(json,"args"),jstr(json,"hexmsg")));
                    }
                }
            }
        }
    }
    if ( coin->RELAYNODE != 0 || coin->VALIDATENODE != 0 )
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
                    pending->resultargs[n] = ptr->resultargs[0];
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
