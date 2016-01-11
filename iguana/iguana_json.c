/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
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

#include "iguana777.h"
#include "SuperNET.h"

cJSON *iguana_peerjson(struct iguana_info *coin,struct iguana_peer *addr)
{
    cJSON *array,*json = cJSON_CreateObject();
    jaddstr(json,"ipaddr",addr->ipaddr);
    jaddnum(json,"protover",addr->protover);
    jaddnum(json,"relay",addr->relayflag);
    jaddnum(json,"height",addr->height);
    jaddnum(json,"rank",addr->rank);
    jaddnum(json,"usock",addr->usock);
    if ( addr->dead != 0 )
        jaddnum(json,"dead",addr->dead);
    jaddnum(json,"ready",addr->ready);
    jaddnum(json,"recvblocks",addr->recvblocks);
    jaddnum(json,"recvtotal",addr->recvtotal);
    jaddnum(json,"lastcontact",addr->lastcontact);
    if ( addr->numpings > 0 )
        jaddnum(json,"aveping",addr->pingsum/addr->numpings);
    array = cJSON_CreateObject();
    jaddnum(array,"version",addr->msgcounts.version);
    jaddnum(array,"verack",addr->msgcounts.verack);
    jaddnum(array,"getaddr",addr->msgcounts.getaddr);
    jaddnum(array,"addr",addr->msgcounts.addr);
    jaddnum(array,"inv",addr->msgcounts.inv);
    jaddnum(array,"getdata",addr->msgcounts.getdata);
    jaddnum(array,"notfound",addr->msgcounts.notfound);
    jaddnum(array,"getblocks",addr->msgcounts.getblocks);
    jaddnum(array,"getheaders",addr->msgcounts.getheaders);
    jaddnum(array,"headers",addr->msgcounts.headers);
    jaddnum(array,"tx",addr->msgcounts.tx);
    jaddnum(array,"block",addr->msgcounts.block);
    jaddnum(array,"mempool",addr->msgcounts.mempool);
    jaddnum(array,"ping",addr->msgcounts.ping);
    jaddnum(array,"pong",addr->msgcounts.pong);
    jaddnum(array,"reject",addr->msgcounts.reject);
    jaddnum(array,"filterload",addr->msgcounts.filterload);
    jaddnum(array,"filteradd",addr->msgcounts.filteradd);
    jaddnum(array,"filterclear",addr->msgcounts.filterclear);
    jaddnum(array,"merkleblock",addr->msgcounts.merkleblock);
    jaddnum(array,"alert",addr->msgcounts.alert);
    jadd(json,"msgcounts",array);
    return(json);
}

cJSON *iguana_peersjson(struct iguana_info *coin,int32_t addronly)
{
    cJSON *retjson,*array; int32_t i; struct iguana_peer *addr;
    if ( coin == 0 )
        return(0);
    array = cJSON_CreateArray();
    for (i=0; i<coin->MAXPEERS; i++)
    {
        addr = &coin->peers.active[i];
        if ( addr->usock >= 0 && addr->ipbits != 0 && addr->ipaddr[0] != 0 )
        {
            if ( addronly != 0 )
                jaddistr(array,addr->ipaddr);
            else jaddi(array,iguana_peerjson(coin,addr));
        }
    }
    if ( addronly == 0 )
    {
        retjson = cJSON_CreateObject();
        jadd(retjson,"peers",array);
        jaddnum(retjson,"maxpeers",coin->MAXPEERS);
        jaddstr(retjson,"coin",coin->symbol);
        return(retjson);
    }
    else return(array);
}

char *iguana_coinjson(struct iguana_info *coin,char *method,cJSON *json)
{
    int32_t i,max,retval; struct iguana_peer *addr; char *ipaddr; cJSON *retjson = 0;
    //printf("iguana_coinjson(%s)\n",jprint(json,0));
    if ( strcmp(method,"peers") == 0 )
        return(jprint(iguana_peersjson(coin,0),1));
    else if ( strcmp(method,"addnode") == 0 )
    {
        if ( (ipaddr= jstr(json,"ipaddr")) != 0 )
        {
            iguana_possible_peer(coin,ipaddr);
            return(clonestr("{\"result\":\"addnode submitted\"}"));
        } else return(clonestr("{\"error\":\"addnode needs ipaddr\"}"));
    }
    else if ( strcmp(method,"nodestatus") == 0 )
    {
        if ( (ipaddr= jstr(json,"ipaddr")) != 0 )
        {
            for (i=0; i<coin->MAXPEERS; i++)
            {
                addr = &coin->peers.active[i];
                if ( strcmp(addr->ipaddr,ipaddr) == 0 )
                    return(jprint(iguana_peerjson(coin,addr),1));
            }
            return(clonestr("{\"result\":\"nodestatus couldnt find ipaddr\"}"));
        } else return(clonestr("{\"error\":\"nodestatus needs ipaddr\"}"));
    }
    else if ( strcmp(method,"maxpeers") == 0 )
    {
        retjson = cJSON_CreateObject();
        if ( (max= juint(json,"max")) <= 0 )
            max = 1;
        else if ( max > IGUANA_MAXPEERS )
            max = IGUANA_MAXPEERS;
        if ( max > coin->MAXPEERS )
        {
            for (i=max; i<coin->MAXPEERS; i++)
                if ( (addr= coin->peers.ranked[i]) != 0 )
                    addr->dead = 1;
        }
        coin->MAXPEERS = max;
        jaddnum(retjson,"maxpeers",coin->MAXPEERS);
        jaddstr(retjson,"coin",coin->symbol);
        return(jprint(retjson,1));
    }
    else if ( strcmp(method,"startcoin") == 0 )
    {
        coin->active = 1;
        return(clonestr("{\"result\":\"coin started\"}"));
    }
    else if ( strcmp(method,"pausecoin") == 0 )
    {
        coin->active = 0;
        return(clonestr("{\"result\":\"coin paused\"}"));
    }
    else if ( strcmp(method,"addcoin") == 0 )
    {
        if ( (retval= iguana_launchcoin(coin->symbol,json)) > 0 )
            return(clonestr("{\"result\":\"coin added\"}"));
        else if ( retval == 0 )
            return(clonestr("{\"result\":\"coin already there\"}"));
        else return(clonestr("{\"error\":\"error adding coin\"}"));
    }
    return(clonestr("{\"error\":\"unhandled request\"}"));
}

char *iguana_parser(struct supernet_info *myinfo,char *method,cJSON *json,char *remoteaddr)
{
    char *coinstr,SYM[16]; int32_t j,k,l,r,rr; struct iguana_peer *addr;
    cJSON *retjson = 0,*array; int32_t i,n; struct iguana_info *coin; char *symbol;
    printf("remoteaddr.(%s)\n",remoteaddr!=0?remoteaddr:"local");
    if ( remoteaddr == 0 || remoteaddr[0] == 0 || strcmp(remoteaddr,"127.0.0.1") == 0 ) // local (private) api
    {
        if ( strcmp(method,"list") == 0 )
        {
            retjson = cJSON_CreateObject();
            array = cJSON_CreateArray();
            for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
            {
                if ( Coins[i] != 0 && Coins[i]->symbol[0] != 0 )
                    jaddistr(array,Coins[i]->symbol);
            }
            jadd(retjson,"coins",array);
            return(jprint(retjson,1));
        }
        else if ( strcmp(method,"allpeers") == 0 )
        {
            retjson = cJSON_CreateObject();
            array = cJSON_CreateArray();
            for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
            {
                if ( Coins[i] != 0 && Coins[i]->symbol[0] != 0 )
                    jaddi(array,iguana_peersjson(Coins[i],0));
            }
            jadd(retjson,"allpeers",array);
            return(jprint(retjson,1));
        }
        else
        {
            if ( (symbol= jstr(json,"coin")) != 0 && strlen(symbol) < sizeof(SYM)-1 )
            {
                strcpy(SYM,symbol);
                touppercase(SYM);
                if ( (coin= iguana_coinfind(SYM)) == 0 )
                {
                    if ( strcmp(method,"addcoin") == 0 )
                        coin = iguana_coinadd(SYM);
                }
                if ( coin != 0 )
                    return(iguana_coinjson(coin,method,json));
                else return(clonestr("{\"error\":\"cant get coin info\"}"));
            }
        }
    }
    array = 0;
    if ( strcmp(method,"getpeers") == 0 )
    {
        if ( (coinstr= jstr(json,"coin")) != 0 )
        {
            if ( (array= iguana_peersjson(iguana_coinfind(coinstr),1)) == 0 )
                return(clonestr("{\"error\":\"coin not found\"}"));
        }
        else
        {
            n = 0;
            array = cJSON_CreateArray();
            r = rand();
            for (i=0; i<IGUANA_MAXCOINS; i++)
            {
                j = (r + i) % IGUANA_MAXCOINS;
                if ( (coin= Coins[j]) != 0 )
                {
                    rr = rand();
                    for (k=0; k<IGUANA_MAXPEERS; k++)
                    {
                        l = (rr + k) % IGUANA_MAXPEERS;
                        addr = &coin->peers.active[l];
                        if ( addr->usock >= 0 && addr->supernet != 0 )
                        {
                            jaddistr(array,addr->ipaddr);
                            if ( ++n >= 64 )
                                break;
                        }
                    }
                }
            }
        }
        if ( array != 0 )
        {
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"agent","SuperNET");
            jaddstr(retjson,"method","mypeers");
            jaddstr(retjson,"result","peers found");
            jadd(retjson,"peers",array);
            return(jprint(retjson,1));
        } else return(clonestr("{\"error\":\"no peers found\"}"));
    }
    else if ( strcmp(method,"mypeers") == 0 )
    {
        printf("mypeers from %s\n",remoteaddr!=0?remoteaddr:"local");
    }
    return(clonestr("{\"result\":\"stub processed generic json\"}"));
}

