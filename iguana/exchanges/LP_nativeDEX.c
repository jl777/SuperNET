
/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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
//
//  LP_nativeDEX.c
//  marketmaker
//
// jl777: profitmargin per coin, ignore peers with errors

#include <stdio.h>
#include "LP_include.h"
#include "LP_network.c"

struct LP_utxoinfo  *LP_utxoinfos[2],*LP_utxoinfos2[2];
struct LP_peerinfo  *LP_peerinfos,*LP_mypeer;

char *activecoins[] = { "BTC", "KMD" };
char GLOBAL_DBDIR[] = { "DB" };
char USERPASS[65],USERPASS_WIFSTR[64],USERHOME[512] = { "/root" };

char *default_LPnodes[] = { "5.9.253.195", "5.9.253.196" , };//'"5.9.253.197", "5.9.253.198", "5.9.253.199", "5.9.253.200", "5.9.253.201", "5.9.253.202", "5.9.253.203", "5.9.253.204" }; //

portable_mutex_t LP_peermutex,LP_utxomutex,LP_commandmutex,LP_cachemutex,LP_swaplistmutex,LP_forwardmutex,LP_pubkeymutex;
int32_t LP_mypubsock = -1;
int32_t USERPASS_COUNTER,IAMLP = 0;
double LP_profitratio = 1.;
bits256 LP_mypubkey;

// stubs
int32_t basilisk_istrustedbob(struct basilisk_swap *swap)
{
    // for BTC and if trusted LP
    return(0);
}

void tradebot_swap_balancingtrade(struct basilisk_swap *swap,int32_t iambob)
{
    
}

void tradebot_pendingadd(cJSON *tradejson,char *base,double basevolume,char *rel,double relvolume)
{
    // add to trades
}

char *LP_getdatadir()
{
    return(USERHOME);
}

char *blocktrail_listtransactions(char *symbol,char *coinaddr,int32_t num,int32_t skip)
{
    return(0);
}

#include "LP_secp.c"
#include "LP_bitcoin.c"
#include "LP_coins.c"
#include "LP_rpc.c"
#include "LP_prices.c"
#include "LP_transaction.c"
#include "LP_remember.c"
#include "LP_swap.c"
#include "LP_peers.c"
#include "LP_utxos.c"
#include "LP_quotes.c"
#include "LP_forwarding.c"
#include "LP_commands.c"

int32_t LP_pullsock_check(char *myipaddr,int32_t pubsock,int32_t pullsock,double profitmargin)
{
    int32_t recvsize,len,datalen=0,nonz = 0; void *ptr; char *retstr,*jsonstr=0; cJSON *argjson,*reqjson;
    while ( (recvsize= nn_recv(pullsock,&ptr,NN_MSG,0)) >= 0 )
    {
        nonz++;
        if ( (datalen= is_hexstr((char *)ptr,0)) > 0 )
        {
            datalen >>= 1;
            jsonstr = malloc(datalen + 1);
            decode_hex((void *)jsonstr,datalen,(char *)ptr);
            jsonstr[datalen] = 0;
        } else jsonstr = (char *)ptr;
        //printf("PULLED %d, datalen.%d (%s)\n",recvsize,datalen,jsonstr);
        if ( (argjson= cJSON_Parse(jsonstr)) != 0 )
        {
            len = (int32_t)strlen(jsonstr) + 1;
            portable_mutex_lock(&LP_commandmutex);
            if ( jstr(argjson,"method") != 0 && strcmp(jstr(argjson,"method"),"forwardhex") == 0 )
            {
                if ( (retstr= LP_forwardhex(jbits256(argjson,"pubkey"),jstr(argjson,"hex"))) != 0 )
                    free(retstr);
            }
            else if ( jstr(argjson,"method") != 0 && strcmp(jstr(argjson,"method"),"publish") == 0 )
            {
                if ( jobj(argjson,"method2") != 0 )
                    jdelete(argjson,"method2");
                jaddstr(argjson,"method2","broadcast");
                if ( pubsock >= 0 && (reqjson= LP_dereference(argjson,"publish")) != 0 )
                    LP_send(pubsock,jprint(reqjson,1),1);
            }
            else if ( LP_tradecommand(myipaddr,pubsock,argjson,&((uint8_t *)ptr)[len],recvsize - len,profitmargin) <= 0 )
            {
                if ( (retstr= stats_JSON(argjson,"127.0.0.1",0)) != 0 )
                {
                    printf("%s PULL.[%d] %s -> (%s)\n",myipaddr != 0 ? myipaddr : "127.0.0.1",recvsize,jsonstr,retstr);
                    if ( pubsock >= 0 )
                        LP_send(pubsock,retstr,1);
                    else free(retstr);
                }
            }
            portable_mutex_unlock(&LP_commandmutex);
            free_json(argjson);
        } else printf("error parsing(%s)\n",jsonstr);
        if ( (void *)jsonstr != ptr )
            free(jsonstr);
        if ( ptr != 0 )
            nn_freemsg(ptr), ptr = 0;
    }
    return(nonz);
}

int32_t LP_subsock_check(struct LP_peerinfo *peer)
{
    int32_t recvsize,nonz = 0; char *retstr; void *ptr; cJSON *argjson;
    while ( peer->subsock >= 0 && (recvsize= nn_recv(peer->subsock,&ptr,NN_MSG,0)) >= 0 )
    {
        nonz++;
        if ( (argjson= cJSON_Parse((char *)ptr)) != 0 )
        {
            portable_mutex_lock(&LP_commandmutex);
            if ( (retstr= stats_JSON(argjson,"127.0.0.1",0)) != 0 )
            {
                //printf("%s SUB.[%d] %s\n",peer->ipaddr,recvsize,(char *)ptr);
                free(retstr);
            }
            portable_mutex_unlock(&LP_commandmutex);
            free_json(argjson);
        } else printf("error parsing.(%s)\n",(char *)ptr);
        if ( ptr != 0 )
            nn_freemsg(ptr), ptr = 0;
    }
    return(nonz);
}

void LP_utxo_spentcheck(int32_t pubsock,struct LP_utxoinfo *utxo,double profitmargin)
{
    struct _LP_utxoinfo u; char str[65],destaddr[64]; uint32_t now = (uint32_t)time(NULL);
    //printf("%s lag.%d\n",bits256_str(str,utxo->txid),now-utxo->lastspentcheck);
    if ( utxo->T.spentflag == 0 && now > utxo->T.lastspentcheck+60 )
    {
        u = (utxo->iambob != 0) ? utxo->deposit : utxo->fee;
        utxo->T.lastspentcheck = now;
        if ( LP_txvalue(destaddr,utxo->coin,utxo->payment.txid,utxo->payment.vout) == 0 )
        {
            printf("txid.%s %s/v%d %.8f has been spent\n",utxo->coin,bits256_str(str,utxo->payment.txid),utxo->payment.vout,dstr(utxo->payment.value));
            LP_spentnotify(utxo,0);
        }
        else if ( LP_txvalue(destaddr,utxo->coin,u.txid,u.vout) == 0 )
        {
            printf("txid2.%s %s/v%d %.8f has been spent\n",utxo->coin,bits256_str(str,u.txid),u.vout,dstr(u.value));
            LP_spentnotify(utxo,1);
        }
        /*else if ( LP_ismine(utxo) > 0 )
        {
            printf("iterate through all locally generated quotes and update, or change to price feed\n");
            // jl777: iterated Q's
            if ( strcmp(utxo->coin,"KMD") == 0 )
                LP_priceping(pubsock,utxo,"BTC",profitmargin);
            else LP_priceping(pubsock,utxo,"KMD",profitmargin);
        }*/
    }
}

void LP_utxo_updates(int32_t pubsock,char *passphrase,double profitmargin)
{
    //LP_utxopurge(0);
    LP_privkey_updates(pubsock,passphrase);
}

void LP_peer_utxosquery(struct LP_peerinfo *mypeer,uint16_t myport,int32_t pubsock,struct LP_peerinfo *peer,uint32_t now,double profitmargin,int32_t interval)
{
    int32_t lastn;
    if ( peer->lastutxos < now-interval )
    {
        //lastn = peer->numutxos - mypeer->numutxos + LP_PROPAGATION_SLACK;
        //if ( lastn < LP_PROPAGATION_SLACK * 2 )
        lastn = LP_PROPAGATION_SLACK * 2;
        if ( mypeer == 0 || strcmp(peer->ipaddr,mypeer->ipaddr) != 0 )
        {
            peer->lastutxos = now;
            LP_utxosquery(mypeer,pubsock,peer->ipaddr,peer->port,"",lastn,mypeer != 0 ? mypeer->ipaddr : "127.0.0.1",myport,profitmargin);
        }
    }
}

void LP_mainloop(char *myipaddr,struct LP_peerinfo *mypeer,uint16_t mypubport,int32_t pubsock,char *pushaddr,int32_t pullsock,uint16_t myport,char *passphrase,double profitmargin,cJSON *coins,char *seednode)
{
    char *retstr; uint8_t r; int32_t i,n,j,counter=0,nonz; struct LP_peerinfo *peer,*tmp; uint32_t now,lastforward = 0; cJSON *item; struct LP_utxoinfo *utxo,*utmp;
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)stats_rpcloop,(void *)&myport) != 0 )
    {
        printf("error launching stats rpcloop for port.%u\n",myport);
        exit(-1);
    }
    if ( IAMLP != 0 )
    {
        if ( seednode == 0 || seednode[0] == 0 )
        {
            for (i=0; i<sizeof(default_LPnodes)/sizeof(*default_LPnodes); i++)
            {
                if ( (rand() % 100) > 25 )
                    continue;
                LP_peersquery(mypeer,pubsock,default_LPnodes[i],myport,mypeer->ipaddr,myport,profitmargin);
            }
        } else LP_peersquery(mypeer,pubsock,seednode,myport,mypeer->ipaddr,myport,profitmargin);
    }
    else
    {
        if ( seednode == 0 || seednode[0] == 0 )
        {
            OS_randombytes((void *)&r,sizeof(r));
            for (j=0; j<sizeof(default_LPnodes)/sizeof(*default_LPnodes); j++)
            {
                i = (r + j) % (sizeof(default_LPnodes)/sizeof(*default_LPnodes));
                LP_peersquery(mypeer,pubsock,default_LPnodes[i],myport,"127.0.0.1",myport,profitmargin);
            }
        } else LP_peersquery(mypeer,pubsock,seednode,myport,"127.0.0.1",myport,profitmargin);
    }
    for (i=0; i<sizeof(activecoins)/sizeof(*activecoins); i++)
    {
        LP_coinfind(activecoins[i]);
        LP_priceinfoadd(activecoins[i]);
    }
    if ( (n= cJSON_GetArraySize(coins)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(coins,i);
            LP_coincreate(item);
            LP_priceinfoadd(jstr(item,"coin"));
        }
    }
    printf("update utxos\n");
    LP_privkey_updates(pubsock,passphrase);
    printf("update swaps\n");
    if ( (retstr= basilisk_swaplist()) != 0 )
        free(retstr);
    printf("update peers\n");
    printf("mainloop pushaddr.(%s)\n",pushaddr);
    if ( IAMLP == 0 )
    {
        while ( 1 )
        {
            now = (uint32_t)time(NULL);
            if ( lastforward < now-3600 )
            {
                LP_forwarding_register(LP_mypubkey,pushaddr,10);
                lastforward = now;
            }
            nonz = n = 0;
            if ( (counter % 6000) == 0 )
                LP_utxo_updates(pubsock,passphrase,profitmargin);
            HASH_ITER(hh,LP_peerinfos,peer,tmp)
            {
                nonz += LP_subsock_check(peer);
                LP_peer_utxosquery(LP_mypeer,myport,pubsock,peer,now,profitmargin,600);
            }
            if ( pullsock >= 0 )
            {
                if ( (n= LP_pullsock_check(myipaddr,pubsock,pullsock,profitmargin)) > 0 )
                {
                    nonz += n;
                    lastforward = now;
                }
            }
            if ( nonz == 0 )
                usleep(200000);
            counter++;
        }
    }
    else
    {
        HASH_ITER(hh,LP_peerinfos,peer,tmp)
        {
            if ( strcmp(peer->ipaddr,mypeer != 0 ? mypeer->ipaddr : "127.0.0.1") != 0 )
            {
                //printf("query utxo from %s\n",peer->ipaddr);
                LP_utxosquery(mypeer,pubsock,peer->ipaddr,peer->port,"",100,mypeer != 0 ? mypeer->ipaddr : "127.0.0.1",myport,profitmargin);
            }
        }
        while ( 1 )
        {
            nonz = 0;
            if ( (counter % 600) == 0 )
                LP_utxo_updates(pubsock,passphrase,profitmargin);
            now = (uint32_t)time(NULL);
            if ( lastforward < now-3600 )
            {
                LP_forwarding_register(LP_mypubkey,pushaddr,10);
                lastforward = now;
            }
            //printf("start peers updates\n");
            HASH_ITER(hh,LP_peerinfos,peer,tmp)
            {
                //printf("updatepeer.%s lag.%d\n",peer->ipaddr,now-peer->lastpeers);
                if ( now > peer->lastpeers+60 && peer->numpeers > 0 && (peer->numpeers != mypeer->numpeers || (rand() % 10000) == 0) )
                {
                    peer->lastpeers = now;
                    if ( peer->numpeers != mypeer->numpeers )
                        printf("%s num.%d vs %d\n",peer->ipaddr,peer->numpeers,mypeer->numpeers);
                    if ( strcmp(peer->ipaddr,mypeer->ipaddr) != 0 )
                        LP_peersquery(mypeer,pubsock,peer->ipaddr,peer->port,mypeer->ipaddr,myport,profitmargin);
                }
                nonz += LP_subsock_check(peer);
                LP_peer_utxosquery(LP_mypeer,myport,pubsock,peer,now,profitmargin,60);
            }
            if ( (counter % 100) == 0 )
            {
                HASH_ITER(hh,LP_utxoinfos[0],utxo,utmp)
                {
                    LP_utxo_spentcheck(pubsock,utxo,profitmargin);
                }
                HASH_ITER(hh,LP_utxoinfos[1],utxo,utmp)
                {
                    LP_utxo_spentcheck(pubsock,utxo,profitmargin);
                }
            }
            if ( pullsock >= 0 )
                nonz += LP_pullsock_check(myipaddr,pubsock,pullsock,profitmargin);
            if ( nonz == 0 )
                usleep(100000);
            counter++;
            //printf("nonz.%d in mainloop\n",nonz);
        }
    }
}

void LPinit(uint16_t myport,uint16_t mypullport,uint16_t mypubport,double profitmargin,char *passphrase,int32_t amclient,char *userhome,cJSON *argjson)
{
    char *myipaddr=0; long filesize,n; int32_t timeout,maxsize,pullsock=-1,pubsock=-1; struct LP_peerinfo *mypeer=0; char pushaddr[128],subaddr[128];
    IAMLP = !amclient;
    LP_profitratio += profitmargin;
    OS_randombytes((void *)&n,sizeof(n));
    srand((int32_t)n);
    if ( userhome != 0 && userhome[0] != 0 )
        safecopy(USERHOME,userhome,sizeof(USERHOME));
    portable_mutex_init(&LP_peermutex);
    portable_mutex_init(&LP_utxomutex);
    portable_mutex_init(&LP_commandmutex);
    portable_mutex_init(&LP_swaplistmutex);
    portable_mutex_init(&LP_cachemutex);
    portable_mutex_init(&LP_forwardmutex);
    portable_mutex_init(&LP_pubkeymutex);
    if ( profitmargin == 0. || profitmargin == 0.01 )
    {
        profitmargin = 0.01 + (double)(rand() % 100)/100000;
        printf("default profit margin %f\n",profitmargin);
    }
    if ( system("curl -s4 checkip.amazonaws.com > /tmp/myipaddr") == 0 )
    {
        if ( (myipaddr= OS_filestr(&filesize,"/tmp/myipaddr")) != 0 && myipaddr[0] != 0 )
        {
            n = strlen(myipaddr);
            if ( myipaddr[n-1] == '\n' )
                myipaddr[--n] = 0;
        } else printf("error getting myipaddr\n");
    } else printf("error issuing curl\n");
    nanomsg_tcpname(pushaddr,myipaddr,mypullport);
    if ( (pullsock= nn_socket(AF_SP,NN_PULL)) >= 0 )
    {
        if ( nn_bind(pullsock,pushaddr) >= 0 )
        {
            timeout = 1;
            nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
            timeout = 1;
            maxsize = 1024 * 1024;
            nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVBUF,&maxsize,sizeof(maxsize));
        }
    }
    if ( IAMLP != 0 )
    {
        if ( myipaddr != 0 )
        {
            pubsock = -1;
            nanomsg_tcpname(subaddr,myipaddr,mypubport);
            printf(">>>>>>>>> myipaddr.%s (%s %s)\n",myipaddr,pushaddr,subaddr);
            if ( (pubsock= nn_socket(AF_SP,NN_PUB)) >= 0 )
            {
                if ( nn_bind(pubsock,subaddr) >= 0 )
                {
                    timeout = 10;
                    nn_setsockopt(pubsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                }
                else
                {
                    printf("error binding to (%s).%d (%s).%d\n",pushaddr,pullsock,subaddr,pubsock);
                     if ( pubsock >= 0 )
                        nn_close(pubsock), pubsock = -1;
                }
            } else printf("error getting sockets %d %d\n",pullsock,pubsock);
            LP_mypubsock = pubsock;
            LP_mypeer = mypeer = LP_addpeer(mypeer,pubsock,myipaddr,myport,0,0,profitmargin,0,0);
        }
        if ( myipaddr == 0 || mypeer == 0 )
        {
            printf("couldnt get myipaddr or null mypeer.%p\n",mypeer);
            exit(-1);
        }
    }
    else if ( myipaddr == 0 )
    {
        printf("couldnt get myipaddr\n");
        exit(-1);
    }
LP_mainloop(myipaddr,mypeer,mypubport,pubsock,pushaddr,pullsock,myport,passphrase,profitmargin,jobj(argjson,"coins"),jstr(argjson,"seednode"));
}


// splitfunds cant trade?
// timeout on bad peers


