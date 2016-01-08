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

struct iguana_agent *Agents[16];

char *pangea_parser(struct iguana_agent *agent,struct iguana_info *coin,char *method,cJSON *json);
char *InstantDEX_parser(struct iguana_agent *agent,struct iguana_info *coin,char *method,cJSON *json);
char *jumblr_parser(struct iguana_agent *agent,struct iguana_info *coin,char *method,cJSON *json);
char *ramchain_parser(struct iguana_agent *agent,struct iguana_info *coin,char *method,cJSON *json);

int32_t iguana_launchcoin(char *symbol,cJSON *json);
struct iguana_jsonitem { struct queueitem DL; uint32_t fallback,expired,allocsize; char **retjsonstrp; char remoteaddr[64]; char jsonstr[]; };

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

cJSON *iguana_agentinfojson(struct iguana_agent *agent)
{
    cJSON *json= cJSON_CreateObject();
    jaddstr(json,"name",agent->name);
    jadd(json,"methods",agent->methods);
    if ( agent->port != 0 )
        jaddnum(json,"port",agent->port);
    else jaddstr(json,"type","builtin");
    return(json);
}

char *iguana_remoteparser(struct iguana_agent *agent,struct iguana_info *coin,char *method,cJSON *json)
{
    int32_t i,n,remains,numsent; char *jsonstr = 0,*retstr = 0; uint8_t hdr[128];
    if ( agent->sock < 0 )
        agent->sock = iguana_socket(0,agent->hostname,agent->port);
    if ( agent->sock >= 0 )
    {
        i = 0;
        jsonstr = jprint(json,0);
        n = (int32_t)strlen(jsonstr) + 1;
        remains = n;
        //printf("RETBUF.(%s)\n",retbuf);
        while ( remains > 0 )
        {
            if ( (numsent= (int32_t)send(agent->sock,&jsonstr[i],remains,MSG_NOSIGNAL)) < 0 )
            {
                if ( errno != EAGAIN && errno != EWOULDBLOCK )
                {
                    printf("%s: %s numsent.%d vs remains.%d of %d errno.%d (%s) usock.%d\n",jsonstr,agent->name,numsent,remains,n,errno,strerror(errno),agent->sock);
                    break;
                }
            }
            else if ( remains > 0 )
            {
                remains -= numsent;
                i += numsent;
                if ( remains > 0 )
                    printf("iguana sent.%d remains.%d of len.%d\n",numsent,remains,n);
            }
        }
        if ( (n= (int32_t)recv(agent->sock,hdr,sizeof(hdr),0)) >= 0 )
        {
            remains = (hdr[0] + ((int32_t)hdr[1] << 8) + ((int32_t)hdr[2] << 16));
            retstr = mycalloc('p',1,remains + 1);
            i = 0;
            while ( remains > 0 )
            {
                if ( (n= (int32_t)recv(agent->sock,&retstr[i],remains,0)) < 0 )
                {
                    if ( errno == EAGAIN )
                    {
                        printf("EAGAIN for len %d, remains.%d\n",n,remains);
                        usleep(10000);
                    }
                    break;
                }
                else
                {
                    if ( n > 0 )
                    {
                        remains -= n;
                        i += n;
                    } else usleep(10000);
                }
            }
        }
        free(jsonstr);
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null return\"}");
    return(retstr);
}

char *iguana_addagent(char *name,char *(*parsefunc)(struct iguana_agent *agent,struct iguana_info *coin,char *method,cJSON *json),char *hostname,cJSON *methods,uint16_t port,char *pubkeystr,char *privkeystr)
{
    int32_t i; struct iguana_agent *agent; char retbuf[8192];
    for (i=0; i<sizeof(Agents)/sizeof(*Agents); i++)
    {
        if ( (agent= Agents[i]) != 0 && strcmp(agent->name,name) == 0 )
        {
            if ( pubkeystr != 0 && privkeystr != 0 && strlen(pubkeystr) == 64 && strlen(privkeystr) == 64 )
            {
                decode_hex(agent->pubkey.bytes,sizeof(bits256),pubkeystr);
                decode_hex(agent->privkey.bytes,sizeof(bits256),privkeystr);
            }
            if ( port != 0 && agent->port == 0 )
            {
                if ( agent->sock >= 0 )
                    close(agent->sock);
                agent->port = port;
                strcpy(agent->hostname,hostname);
                agent->sock = iguana_socket(0,agent->hostname,port);
                printf("set (%s) port.%d for %s -> sock.%d\n",hostname,port,agent->name,agent->sock);
            }
            if ( agent->port > 0 && agent->sock < 0 && agent->hostname[0] != 0 && (agent->sock= iguana_socket(0,agent->hostname,agent->port)) < 0 )
                return(clonestr("{\"result\":\"existing agent couldnt connect to remote agent\"}"));
            else return(clonestr("{\"result\":\"agent already there\"}"));
        }
    }
    for (i=0; i<sizeof(Agents)/sizeof(*Agents); i++)
    {
        if ( Agents[i] == 0 )
        {
            agent = mycalloc('G',1,sizeof(*Agents[i]));
            Agents[i] = agent;
            strncpy(agent->name,name,sizeof(agent->name)-1);
            strncpy(agent->hostname,hostname,sizeof(agent->hostname)-1);
            agent->methods = methods, agent->nummethods = cJSON_GetArraySize(methods);
            agent->sock = -1;
            agent->port = port;
            agent->parsefunc = (void *)parsefunc;
            if ( pubkeystr != 0 && privkeystr != 0 && strlen(pubkeystr) == 64 && strlen(privkeystr) == 64 )
            {
                decode_hex(agent->pubkey.bytes,sizeof(bits256),pubkeystr);
                decode_hex(agent->privkey.bytes,sizeof(bits256),privkeystr);
            }
            if ( port > 0 )
            {
                if ( (agent->sock= iguana_socket(0,hostname,port)) < 0 )
                    return(clonestr("{\"result\":\"agent added, but couldnt connect to remote agent\"}"));
            }
            sprintf(retbuf,"{\"result\":\"agent added\",\"name\"\"%s\",\"methods\":%s,\"hostname\":\"%s\",\"port\":%u,\"sock\":%d}",agent->name,jprint(agent->methods,0),agent->hostname,agent->port,agent->sock);
            return(clonestr(retbuf));
        }
    }
    return(clonestr("{\"error\":\"no more agent slots available\"}"));
}

char *iguana_agentjson(char *name,struct iguana_info *coin,char *method,cJSON *json,char *remoteaddr)
{
    cJSON *retjson = 0,*array,*methods,*obj; int32_t i,n,j; struct iguana_agent *agent;
    if ( strcmp(name,"SuperNET") != 0 )
    {
        for (i=0; i<sizeof(Agents)/sizeof(*Agents); i++)
        {
            if ( (agent= Agents[i]) != 0 && strcmp(agent->name,name) == 0 )
            {
                if ( agent->parsefunc != 0 )
                {
                    for (j=0; j<agent->nummethods; j++)
                    {
                        if ( (obj= jitem(agent->methods,j)) != 0 )
                        {
                            if ( strcmp(method,jstr(obj,0)) == 0 )
                                return((*agent->parsefunc)(agent,method,json,remoteaddr));
                        }
                    }
                    return(clonestr("{\"result\":\"agent doesnt have method\"}"));
                } else return(clonestr("{\"result\":\"agent doesnt have parsefunc\"}"));
            }
        }
    }
    else if ( remoteaddr == 0 || strcmp(remoteaddr,"127.0.0.1") != 0 ) // public api
    {
        char *coinstr; int32_t j,k,l,r,rr; struct iguana_peer *addr;
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
                jaddstr(retjson,"result","peers found");
                jadd(retjson,"peers",array);
                return(jprint(retjson,1));
            } else return(clonestr("{\"error\":\"no peers found\"}"));
        }
    }
    else // local api
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
            array = cJSON_CreateArray();
            for (i=0; i<sizeof(Agents)/sizeof(*Agents); i++)
            {
                if ( Agents[i] != 0 && Agents[i]->name[0] != 0 )
                    jaddi(array,iguana_agentinfojson(Agents[i]));
            }
            jadd(retjson,"agents",array);
            return(jprint(retjson,1));
        }
        else if ( strcmp(method,"peers") == 0 )
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
        else if ( strcmp(method,"addagent") == 0 )
        {
            char *hostname = "127.0.0.1",*name; uint16_t port;
            if ( (name= jstr(json,"name")) != 0 && (methods= jarray(&n,json,"methods")) != 0 )
            {
                if ( (port= juint(json,"port")) != 0 )
                {
                    if ( (hostname= jstr(json,"host")) == 0 )
                    {
                        if ( (hostname= jstr(json,"ipaddr")) == 0 )
                            hostname = "127.0.0.1";
                    }
                    if ( hostname == 0 )
                        return(clonestr("{\"error\":\"no host specified for remote agent\"}"));
                }
                else if ( strcmp(name,"pangea") != 0 && strcmp(name,"InstantDEX") != 0 && strcmp(name,"jumblr") != 0 )
                    return(clonestr("{\"error\":\"no port specified for remote agent\"}"));
                return(iguana_addagent(name,iguana_remoteparser,hostname,methods,port,jstr(json,"pubkey"),jstr(json,"privkey")));
            } else return(clonestr("{\"error\":\"cant addagent without name and methods\"}"));
        }
    }
    return(clonestr("{\"result\":\"stub processed generic json\"}"));
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

char *iguana_jsonstr(struct iguana_info *coin,char *jsonstr,char *remoteaddr)
{
    cJSON *json; char *retjsonstr,*methodstr,*agentstr;
    //printf("iguana_jsonstr.(%s)\n",jsonstr);
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (methodstr= jstr(json,"method")) != 0 )
        {
            if ( (agentstr= jstr(json,"agent")) == 0 || strcmp(agentstr,"iguana") == 0 )
                retjsonstr = iguana_coinjson(coin,methodstr,json);
            else retjsonstr = iguana_agentjson(agentstr,coin,methodstr,json,remoteaddr);
        } else retjsonstr = clonestr("{\"error\":\"no method in JSON\"}");
        free_json(json);
    } else retjsonstr = clonestr("{\"error\":\"cant parse JSON\"}");
    printf("iguana_jsonstr.(%s)\n",retjsonstr);
    return(retjsonstr);
}

/*char *iguana_genericjsonstr(char *jsonstr,char *remoteaddr)
{
    cJSON *json; char *retjsonstr,*methodstr,*agentstr;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (agentstr= jstr(json,"agent")) == 0 )
            agentstr = "SuperNET";
        if ( (methodstr= jstr(json,"method")) != 0 )
            retjsonstr = iguana_agentjson(agentstr,0,methodstr,json,remoteaddr);
        else retjsonstr = clonestr("{\"error\":\"no method in generic JSON\"}");
        free_json(json);
    } else retjsonstr = clonestr("{\"error\":\"cant parse generic JSON\"}");
    return(retjsonstr);
}*/

int32_t iguana_processjsonQ(struct iguana_info *coin) // reentrant, can be called during any idletime
{
    struct iguana_jsonitem *ptr;
    if ( (ptr= queue_dequeue(&coin->finishedQ,0)) != 0 )
    {
        if ( ptr->expired != 0 )
        {
            *ptr->retjsonstrp = clonestr("{\"error\":\"request timeout\"}");
            printf("garbage collection: expired.(%s)\n",ptr->jsonstr);
            myfree(ptr,ptr->allocsize);
        } else queue_enqueue("finishedQ",&coin->finishedQ,&ptr->DL,0);
    }
    if ( (ptr= queue_dequeue(&coin->jsonQ,0)) != 0 )
    {
        //printf("process.(%s)\n",ptr->jsonstr);
        if ( (*ptr->retjsonstrp= iguana_jsonstr(ptr->fallback==0?coin:0,ptr->jsonstr,ptr->remoteaddr)) == 0 )
            *ptr->retjsonstrp = clonestr("{\"error\":\"null return from iguana_jsonstr\"}");
        queue_enqueue("finishedQ",&coin->finishedQ,&ptr->DL,0);
        return(1);
    }
    return(0);
}

char *iguana_blockingjsonstr(struct iguana_info *coin,char *jsonstr,uint64_t tag,int32_t maxmillis,char *remoteaddr)
{
    struct iguana_jsonitem *ptr; char *retjsonstr = 0; int32_t fallback = 0,len,allocsize; double expiration = OS_milliseconds() + maxmillis;
    if ( coin == 0 )
        coin = iguana_coinfind("BTCD"), fallback = 1;
    if ( coin != 0 )
    {
        //printf("blocking case.(%s)\n",jsonstr);
        len = (int32_t)strlen(jsonstr);
        allocsize = sizeof(*ptr) + len + 1;
        ptr = mycalloc('J',1,allocsize);
        ptr->allocsize = allocsize;
        ptr->fallback = fallback;
        ptr->retjsonstrp = &retjsonstr;
        safecopy(ptr->remoteaddr,remoteaddr,sizeof(ptr->remoteaddr));
        memcpy(ptr->jsonstr,jsonstr,len+1);
        queue_enqueue("jsonQ",&coin->jsonQ,&ptr->DL,0);
        while ( OS_milliseconds() < expiration )
        {
            usleep(100);
            if ( retjsonstr != 0 )
            {
                //printf("blocking retjsonstr.(%s)\n",retjsonstr);
                queue_delete(&coin->finishedQ,&ptr->DL,allocsize,1);
                return(retjsonstr);
            }
            usleep(1000);
        }
        printf("(%s) expired\n",jsonstr);
        ptr->expired = (uint32_t)time(NULL);
        return(clonestr("{\"error\":\"iguana jsonstr expired\"}"));
    }
    return(clonestr("{\"error\":\"iguana blockingjsonstr cant get coin_info\"}"));
}

char *iguana_JSON(struct iguana_info *coin,char *jsonstr,char *remoteaddr)
{
    cJSON *json,*retjson; uint64_t tag; uint32_t timeout; int32_t retval,localaccess = 0;
    char *method,*retjsonstr,*symbol,*retstr = 0;
    if ( remoteaddr == 0 || strcmp(remoteaddr,"127.0.0.1") == 0 ) // || strcmp(remoteaddr,myipaddr) == 0 )
        localaccess = 1;
    printf("iguana_JSON.(%s) from %s\n",jsonstr,localaccess==0?remoteaddr:"local access");
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( localaccess != 0 && (method= jstr(json,"method")) != 0 && strcmp(method,"addcoin") == 0 )
        {
            if ( (retval= iguana_launchcoin(jstr(json,"coin"),json)) > 0 )
                return(clonestr("{\"result\":\"launched coin\"}"));
            else if ( retval == 0 ) return(clonestr("{\"result\":\"coin already launched\"}"));
            else return(clonestr("{\"error\":\"error launching coin\"}"));
        }
        if ( (tag= j64bits(json,"tag")) == 0 )
            OS_randombytes((uint8_t *)&tag,sizeof(tag));
        if ( (symbol= jstr(json,"coin")) != 0 )
        {
            coin = iguana_coinfind(symbol);
            if ( coin != 0 && localaccess != 0 && coin->launched == 0 )
                iguana_launchcoin(symbol,json);
        }
        if ( (timeout= juint(json,"timeout")) == 0 )
            timeout = IGUANA_JSONTIMEOUT;
        if ( (retjsonstr= iguana_blockingjsonstr(coin,jsonstr,tag,timeout,remoteaddr)) != 0 )
        {
            //printf("retjsonstr.(%s)\n",retjsonstr);
            if ( (retjson= cJSON_Parse(retjsonstr)) == 0 )
            {
                retjson = cJSON_Parse("{\"error\":\"cant parse retjsonstr\"}");
            }
            jdelete(retjson,"tag");
            jadd64bits(retjson,"tag",tag);
            retstr = jprint(retjson,1);
            //printf("retstr.(%s) retjsonstr.%p retjson.%p\n",retstr,retjsonstr,retjson);
            free(retjsonstr);//,strlen(retjsonstr)+1);
        }
        free_json(json);
    } else retstr = clonestr("{\"error\":\"cant parse JSON\"}");
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null return\"}");
    return(retstr);
}

/*void iguana_issuejsonstrM(void *arg)
{
    cJSON *json; int32_t fd; char *retjsonstr,*jsonstr = arg;
    retjsonstr = iguana_JSON(jsonstr);
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (fd= juint(json,"retdest")) > 0 )
        {
            send(fd,jsonstr,(int32_t)strlen(jsonstr)+1,MSG_NOSIGNAL);
        }
        free_json(json);
        return;
    }
    printf("%s\n",retjsonstr);
    free(retjsonstr);//,strlen(retjsonstr)+1);
    free(jsonstr);//,strlen(jsonstr)+1);
}*/

void iguana_main(void *arg)
{
    char helperstr[64],*helperargs,*coinargs=0,*retstr,*secret,*jsonstr = arg;
    int32_t i,len,flag; cJSON *json; uint8_t secretbuf[512];
    //  portable_OS_init()?
    mycalloc(0,0,0);
    if ( (retstr= iguana_addagent("ramchain",ramchain_parser,"127.0.0.1",cJSON_Parse("[\"block\", \"tx\", \"txs\", \"rawtx\", \"balance\", \"totalreceived\", \"totalsent\", \"utxo\", \"status\"]"),0,0,0)) != 0 )
        printf("%s\n",retstr), free(retstr);
    if ( (retstr= iguana_addagent("pangea",pangea_parser,"127.0.0.1",cJSON_Parse("[\"test\"]"),0,0,0)) != 0 )
        printf("%s\n",retstr), free(retstr);
    if ( (retstr= iguana_addagent("InstantDEX",InstantDEX_parser,"127.0.0.1",cJSON_Parse("[\"test\"]"),0,0,0)) != 0 )
        printf("%s\n",retstr), free(retstr);
    if ( (retstr= iguana_addagent("jumblr",jumblr_parser,"127.0.0.1",cJSON_Parse("[\"test\"]"),0,0,0)) != 0 )
        printf("%s\n",retstr), free(retstr);
    iguana_initQ(&helperQ,"helperQ");
    OS_ensure_directory("confs");
    OS_ensure_directory("DB");
    OS_ensure_directory("tmp");
    if ( jsonstr != 0 && (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( jobj(json,"numhelpers") != 0 )
            IGUANA_NUMHELPERS = juint(json,"numhelpers");
        if ( (secret= jstr(json,"secret")) != 0 )
        {
            len = (int32_t)strlen(secret);
            if ( is_hexstr(secret,0) != 0 && len <= (sizeof(secretbuf)<<1) )
            {
                len >>= 1;
                decode_hex(secretbuf,len,secret);
            } else vcalc_sha256(0,secretbuf,(void *)secret,len), len = sizeof(bits256);
        }
        if ( jobj(json,"coins") != 0 )
            coinargs = jsonstr;
    }
    if ( IGUANA_NUMHELPERS == 0 )
        IGUANA_NUMHELPERS = 1;
    for (i=0; i<IGUANA_NUMHELPERS; i++)
    {
        sprintf(helperstr,"{\"name\":\"helper.%d\"}",i);
        helperargs = clonestr(helperstr);
        iguana_launch(iguana_coinadd("BTCD"),"iguana_helper",iguana_helper,helperargs,IGUANA_PERMTHREAD);
    }
    iguana_launch(iguana_coinadd("BTCD"),"rpcloop",iguana_rpcloop,iguana_coinadd("BTCD"),IGUANA_PERMTHREAD);
    if ( coinargs != 0 )
        iguana_launch(iguana_coinadd("BTCD"),"iguana_coins",iguana_coins,coinargs,IGUANA_PERMTHREAD);
    else if ( 1 )
    {
#ifdef __APPLE__
        sleep(1);
        iguana_JSON(iguana_coinfind("BTCD"),"{\"agent\":\"iguana\",\"method\":\"addcoin\",\"services\":128,\"maxpeers\":16,\"coin\":\"BTCD\",\"active\":1}",0);
#endif
    }
    if ( arg != 0 )
        iguana_JSON(0,arg,0);
    //init_InstantDEX();
    while ( 1 )
    {
        flag = 0;
        for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
            if ( Coins[i] != 0 && Coins[i]->symbol[0] != 0 )
                flag += iguana_processjsonQ(Coins[i]);
        if ( flag == 0 )
            usleep(100000);
    }
}
