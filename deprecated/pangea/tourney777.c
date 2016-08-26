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
#ifdef later

#ifdef DEFINES_ONLY
#ifndef tourney777_h
#define tourney777_h

// nonplaying nodeA

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include "../iguana777.h"

struct tourney777_table { uint64_t tableid; union hostnet777 *hn[CARDS777_MAXPLAYERS]; int32_t N,numactive; };

struct tourney777
{
    struct tourney777_table tables[1024]; char transport[16],ipaddr[64],name[128]; uint32_t started,finished,numtables; uint16_t port;
    union hostnet777 hn[];
} *Tournament;

#define TOURNEY777_TABLESIZE 9
#define TOURNEY777_MINPLAYERS (TOURNEY777_TABLESIZE - 2)

#endif
#else
#ifndef tourney777_c
#define tourney777_c

#ifndef tourney777_h
#define DEFINES_ONLY
#include "tourney777.c"
#undef DEFINES_ONLY
#endif

void tourney777_jointable(struct tourney777 *tp,struct tourney777_table *table,union hostnet777 *player)
{
    player->client->tableid = table->tableid;
    printf("jointable.%llu tableid.%llu\n",(long long)player->client->H.nxt64bits,(long long)table->tableid);
}

void tourney777_leavetable(struct tourney777 *tp,struct tourney777_table *table,union hostnet777 *player)
{
    printf("leavetable.%llu tableid.%llu\n",(long long)player->client->H.nxt64bits,(long long)table->tableid);
    player->client->tableid = 0;
}

void tourney777_createtable(struct tourney777 *tp,union hostnet777 *players[],int32_t num)
{
    int32_t i; uint64_t tableid = rand();
    for (i=0; i<num; i++)
        players[i]->client->tableid = tableid;
    printf("createtable.%llu numplayers.%d\n",(long long)tableid,num);
}

void tourney777_freetable(struct tourney777 *tp,struct tourney777_table *table)
{
    printf("freetable.%llu numplayers.%d numactives.%d\n",(long long)table->tableid,table->N,table->numactive);
}

struct tourney777_table *tourney777_findtable(struct tourney777 *tp,uint64_t tableid,struct tourney777_table *avoid)
{
    struct tourney777_table *mintable = 0; int32_t i,minplayers = CARDS777_MAXPLAYERS + 1;
    if ( tp->numtables >  0 )
    {
        for (i=0; i<tp->numtables; i++)
        {
            if ( tableid == 0 )
            {
                if ( (avoid == 0 || avoid != &tp->tables[i]) && tp->tables[i].numactive != TOURNEY777_TABLESIZE && tp->tables[i].numactive < minplayers )
                {
                    minplayers = tp->tables[i].numactive;
                    mintable = &tp->tables[i];
                }
            }
            else if ( tp->tables[i].tableid == tableid )
                return(&tp->tables[i]);
        }
    }
    return(mintable);
}

union hostnet777 *tourney777_nextblind(struct tourney777_table *table)
{
    int32_t i,ind,j = (rand() % table->N);
    for (i=0; i<table->N; i++)
    {
        ind = (j + i) % table->N;
        if ( table->hn[ind] != 0 && table->hn[ind]->client->balance != 0 )
            return(table->hn[ind]);
    }
    return(0);
}

void tourney777_rebalance(struct tourney777 *tp,int32_t delta)
{
    int32_t i,j,num,n,pertable,flag,threshold,needs_table = 0; struct hostnet777_server *srv;
    union hostnet777 *player,*newtable[TOURNEY777_TABLESIZE]; struct tourney777_table *table,*t;
    srv = tp->hn[0].server;
    if ( delta < 0 )
    {
        if ( (table= tourney777_findtable(tp,0,0)) != 0 )
        {
            if ( table->numactive < TOURNEY777_MINPLAYERS )
            {
                if ( tp->numtables >= table->numactive )
                {
                    for (j=0; j<table->N; j++)
                        tourney777_leavetable(tp,table,table->hn[j]);
                    for (j=0; j<table->N; j++)
                    {
                        if ( (t= tourney777_findtable(tp,0,table)) != 0 )
                            tourney777_jointable(tp,t,table->hn[j]);
                        else printf("tourney777_rebalance: cant find table with slot\n");
                    }
                    tourney777_freetable(tp,table);
                }
                else
                {
                    printf("tourney777_rebalance: imbalance tableid.%llu numactive.%d vs total tables.%d\n",(long long)table->tableid,table->numactive,tp->numtables);
                    flag = 0;
                    for (threshold=TOURNEY777_TABLESIZE; threshold>=TOURNEY777_MINPLAYERS+1; threshold--)
                    {
                        for (i=0; i<tp->numtables; i++)
                        {
                            if ( tp->tables[i].numactive == threshold )
                            {
                                if ( (player= tourney777_nextblind(&tp->tables[i])) != 0 )
                                {
                                    tourney777_leavetable(tp,&tp->tables[i],player);
                                    tourney777_jointable(tp,table,player);
                                    flag = 1;
                                    break;
                                }
                                else printf("tourney777_nextblind: cant find nextblind\n");
                            }
                        }
                        if ( flag != 0 )
                            break;
                    }
                    if ( flag == 0 )
                    {
                        printf("tourney777_rebalance: couldnt find donor tableid.%llu numactive.%d vs total tables.%d\n",(long long)table->tableid,table->numactive,tp->numtables);
                    }
                }
            }
        }
    }
    else
    {
        for (i=1; i<srv->num; i++)
        {
            player = &tp->hn[i];
            if ( player != 0 && player->client->tableid == 0 && player->client->balance != 0 )
            {
                if ( (table= tourney777_findtable(tp,0,0)) != 0 )
                    tourney777_jointable(tp,table,player);
                else needs_table++;
            }
        }
        if ( needs_table >= TOURNEY777_TABLESIZE )
        {
            num = (needs_table / TOURNEY777_TABLESIZE);
            if ( (needs_table % TOURNEY777_TABLESIZE) != 0 )
                num++;
            pertable = (needs_table / num);
            printf("needs_table.%d pertable.%d num.%d\n",needs_table,pertable,num);
            for (j=0; j<num; j++)
            {
                memset(newtable,0,sizeof(newtable));
                // find nodes with endpoints and verify connections
                for (i=1,n=0; i<srv->num; i++)
                {
                    player = &tp->hn[i];
                    if ( player != 0 && player->client->tableid == 0 && player->client->balance != 0 )
                    {
                        newtable[n++] = player;
                        if ( n >= pertable )
                            break;
                    }
                }
                tourney777_createtable(tp,newtable,n);
            }
        }
    }
}

void tourney777_newhand(union hostnet777 *hn,uint64_t tableid,cJSON *json,uint8_t *data,int32_t datalen)
{
    struct pangea_info *pangea_find(uint64_t tableid,int32_t threadid);
    char *pangea_dispsummary(struct pangea_info *sp,int32_t verbose,uint8_t *summary,int32_t summarysize,uint64_t tableid,int32_t handid,int32_t numplayers);
    char *handhist; int32_t i,j,handid,numplayers,n,m,busted,rebuy; cJSON *handjson,*array,*balances,*item; struct tourney777_table *table;
    handid = juint(json,"handid");
    numplayers = juint(json,"numplayers");
    if ( (handhist= pangea_dispsummary(pangea_find(tableid,0),1,data,datalen,tableid,handid,numplayers)) != 0 )
    {
        printf("GOT HANDHIST.(%s)\n",handhist);
        if ( (handjson= cJSON_Parse(handhist)) != 0 )
        {
            if ( (array= jarray(&n,handjson,"hand")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    rebuy = juint(item,"rebuy");
                    busted = juint(item,"busted");
                    if ( (balances= jarray(&m,item,"balances")) != 0 && (table= tourney777_findtable(Tournament,tableid,0)) != 0 )
                    {
                        for (j=0; j<m; j++)
                            table->hn[j]->client->balance = j64bits(jitem(balances,j),0);
                    }
                    if ( busted != 0 )
                        tourney777_rebalance(Tournament,-1);
                }
            }
            free_json(handjson);
        }
        free(handhist);
    }
}

void tourney777_poll(union hostnet777 *hn)
{
    char *jsonstr; uint64_t senderbits,tableid; uint8_t *buf=0; int32_t maxlen,len,senderind; uint32_t timestamp; char *cmdstr,*hexstr; cJSON *json;
    maxlen = 65536;
    if ( (buf= malloc(maxlen)) == 0 )
    {
        printf("tourney777_poll: cant allocate buf\n");
        return;
    }
    if ( (jsonstr= queue_dequeue(&hn->server->H.Q,1)) != 0 )
    {
        printf("tourney slot.%d GOT.(%s)\n",hn->client->H.slot,jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            tableid = j64bits(json,"tableid");
            if ( tourney777_findtable(Tournament,tableid,0) == 0 )
            {
                free(buf);
                return;
            }
            senderbits = j64bits(json,"sender");
            if ( (senderind= juint(json,"myind")) < 0 || senderind >= hn->server->num )
            {
                printf("pangea_poll: illegal senderind.%d cardi.%d turni.%d\n",senderind,juint(json,"cardi"),juint(json,"turni"));
                goto cleanup;
            }
            timestamp = juint(json,"timestamp");
            hn->client->H.state = juint(json,"state");
            len = juint(json,"n");
            cmdstr = jstr(json,"cmd");
            if ( (hexstr= jstr(json,"data")) != 0 && strlen(hexstr) == (len<<1) )
            {
                if ( len > maxlen )
                {
                    printf("len too big for tourney777_poll\n");
                    goto cleanup;
                }
                decode_hex(buf,len,hexstr);
            } else if ( hexstr != 0 )
                printf("len.%d vs hexlen.%d (%s)\n",len,(int32_t)strlen(hexstr)>>1,hexstr);
            if ( cmdstr != 0 )
            {
                if ( strcmp(cmdstr,"newhand") == 0 )
                    tourney777_newhand(hn,tableid,json,buf,len);
            }
cleanup:
            free_json(json);
        }
        free_queueitem(jsonstr);
    }
    free(buf);
}

char *tourney777_start(char *name,cJSON *json)
{
    if ( Tournament != 0 && strcmp(Tournament->name,name) == 0 )
    {
        Tournament->started = (uint32_t)time(NULL);
        tourney777_rebalance(Tournament,1);
        return(clonestr("{\"result\":\"tournament started\"}"));
    } else return(clonestr("{\"error\":\"no matching tournament\"}"));
}

char *tourney777_register(char *name,bits256 pubkey,cJSON *json)
{
    int32_t i; struct hostnet777_server *srv;
    if ( Tournament != 0 && strcmp(Tournament->name,name) == 0 && (srv= Tournament->hn[0].server) != 0 )
    {
        if ( Tournament->started != 0 )
            return(clonestr("{\"error\":\"tournament already started\"}"));
        else
        {
            for (i=0; i<srv->num; i++)
                if ( memcmp(pubkey.bytes,srv->clients[i].pubkey.bytes,sizeof(bits256)) == 0 )
                    return(clonestr("{\"error\":\"already registered in tournament\"}"));
            srv->clients[srv->num].lastcontact = (uint32_t)time(NULL);
            // get endpoint
            srv->num++;
            return(clonestr("{\"result\":\"registered in tournament\"}"));
        }
    } else return(clonestr("{\"error\":\"no matching tournament\"}"));
}

char *tourney777_deregister(char *name,bits256 pubkey,cJSON *json)
{
    int32_t i; struct hostnet777_server *srv;
    if ( Tournament != 0 && strcmp(Tournament->name,name) == 0 && (srv= Tournament->hn[0].server) != 0 )
    {
        if ( Tournament->started != 0 )
            return(clonestr("{\"error\":\"tournament already started\"}"));
        else
        {
            for (i=0; i<srv->num; i++)
                if ( memcmp(pubkey.bytes,srv->clients[i].pubkey.bytes,sizeof(bits256)) == 0 )
                {
                    memset(&srv->clients[i],0,sizeof(srv->clients[i]));
                    if ( i == srv->num-1 )
                        srv->num--;
                    return(clonestr("{\"result\":\"deregistered from tournament\"}"));
                }
            return(clonestr("{\"error\":\"not registered in tournament\"}"));
        }
    } else return(clonestr("{\"error\":\"no matching tournament\"}"));
}

struct tourney777 *tourney777_init(char *name,bits256 privkey,char *transport,char *ipaddr,uint16_t port,int32_t maxplayers,cJSON *json)
{
    struct hostnet777_server *srv; bits256 pubkey; struct tourney777 *tourney; int32_t i; char endpoint[128];
    tourney = calloc(1,sizeof(*tourney) + sizeof(*tourney->hn)*maxplayers);
    pubkey = acct777_pubkey(privkey);
    safecopy(tourney->name,name,sizeof(tourney->name)-1);
    if ( transport == 0 || transport[0] == 0 )
        transport = "tcp";
    strcpy(tourney->transport,transport);
    if ( ipaddr == 0 || ipaddr[0] == 0 )
        ipaddr = "127.0.0.1";
    strcpy(tourney->ipaddr,ipaddr);
    if ( port == 0 )
        port = 8897;
    tourney->port = port;
    if ( (srv= hostnet777_server(privkey,pubkey,tourney->transport,tourney->ipaddr,tourney->port,maxplayers)) == 0 )
    {
        printf("tourney777_init: cant create hostnet777 server\n");
        return(0);
    }
    srv->H.privkey = privkey, srv->H.pubkey = pubkey;
    for (i=0; i<maxplayers; i++)
    {
        sprintf(endpoint,"%s://%s:%u",srv->ep.transport,srv->ep.ipaddr,srv->ep.port + i + 1);
        srv->clients[i].pmsock = nn_createsocket(endpoint,1,"NN_PULL",NN_PULL,srv->ep.port + i + 1,10,10);
    }
    srv->H.pollfunc = tourney777_poll;
    tourney->hn[0].server = srv;
    // set tournament parameters
    if ( portable_thread_create((void *)hostnet777_idler,&tourney->hn[0]) == 0 )
        printf("error launching server thread\n");
    Tournament = tourney;
    return(tourney);
}


#endif
#endif

#endif
