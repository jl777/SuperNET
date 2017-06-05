
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
// jl777: fix price calcs based on specific txfees

#include <stdio.h>
#include "LP_include.h"
#include "LP_network.c"

struct LP_utxoinfo  *LP_utxoinfos;
struct LP_peerinfo  *LP_peerinfos,*LP_mypeer;

char *activecoins[] = { "BTC", "KMD", "REVS", "JUMBLR" };//"LTC", "USD",   };
char GLOBAL_DBDIR[] = { "DB" };
char USERPASS[65],USERPASS_WIFSTR[64],USERHOME[512] = { "/root" };

char *default_LPnodes[] = { "5.9.253.196", "5.9.253.197", "5.9.253.198", "5.9.253.199", "5.9.253.200", "5.9.253.201", "5.9.253.202", "5.9.253.203", "5.9.253.204" }; //"5.9.253.195",

portable_mutex_t LP_peermutex,LP_utxomutex,LP_commandmutex,LP_cachemutex;
int32_t LP_mypubsock = -1;
int32_t Client_connections;
int32_t USERPASS_COUNTER,IAMCLIENT = 0;
double LP_profitratio = 1.;

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
#include "LP_commands.c"

void LP_mainloop(struct LP_peerinfo *mypeer,uint16_t mypubport,int32_t pubsock,int32_t pullsock,uint16_t myport,int32_t amclient,char *passphrase,double profitmargin)
{
    //static uint16_t tmpport;
    char *retstr; uint8_t r; int32_t i,n,j,len,recvsize,counter=0,nonz,lastn; struct LP_peerinfo *peer,*tmp; uint32_t now; struct LP_utxoinfo *utxo,*utmp; void *ptr; cJSON *argjson;
    if ( amclient == 0 )
    {
        for (i=0; i<sizeof(default_LPnodes)/sizeof(*default_LPnodes); i++)
        {
            if ( (rand() % 100) > 25 )
                continue;
            LP_peersquery(amclient,mypeer,pubsock,default_LPnodes[i],myport,mypeer->ipaddr,myport,profitmargin);
        }
    }
    else
    {
        OS_randombytes((void *)&r,sizeof(r));
        for (j=0; j<sizeof(default_LPnodes)/sizeof(*default_LPnodes); j++)
        {
            i = (r + j) % (sizeof(default_LPnodes)/sizeof(*default_LPnodes));
            LP_peersquery(amclient,mypeer,pubsock,default_LPnodes[i],myport,"127.0.0.1",myport,profitmargin);
        }
    }
    //if ( amclient != 0 )
    //    tmpport = myport + 10;
    //else tmpport = myport;
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)stats_rpcloop,(void *)&myport) != 0 )
    {
        printf("error launching stats rpcloop for port.%u\n",myport);
        exit(-1);
    }
    for (i=0; i<sizeof(activecoins)/sizeof(*activecoins); i++)
    {
        LP_coinfind(activecoins[i]);
        LP_priceinfoadd(activecoins[i]);
    }
    LP_privkey_updates(mypeer,pubsock,passphrase,amclient);
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        if ( strcmp(peer->ipaddr,mypeer != 0 ? mypeer->ipaddr : "127.0.0.1") != 0 )
            LP_utxosquery(0,mypeer,pubsock,peer->ipaddr,peer->port,"",100,mypeer != 0 ? mypeer->ipaddr : "127.0.0.1",myport,profitmargin);
    }
    if ( amclient != 0 )
    {
        while ( 1 )
        {
            nonz = n = 0;
            if ( (++counter % 3600) == 0 )
                LP_privkey_updates(mypeer,pubsock,passphrase,amclient);
            HASH_ITER(hh,LP_peerinfos,peer,tmp)
            {
                n++;
                while ( peer->subsock >= 0 && (recvsize= nn_recv(peer->subsock,&ptr,NN_MSG,0)) >= 0 )
                {
                    nonz++;
                    if ( (argjson= cJSON_Parse((char *)ptr)) != 0 )
                    {
                        portable_mutex_lock(&LP_commandmutex);
                        if ( (retstr= stats_JSON(argjson,"127.0.0.1",0)) != 0 )
                        {
                            //printf("%s RECV.[%d] %s\n",peer->ipaddr,recvsize,(char *)ptr);
                            free(retstr);
                        }
                        portable_mutex_unlock(&LP_commandmutex);
                        //printf("subloop.(%s)\n",jprint(argjson,0));
                        free_json(argjson);
                    } else printf("error parsing.(%s)\n",(char *)ptr);
                    if ( ptr != 0 )
                        nn_freemsg(ptr), ptr = 0;
                }
            }
            if ( nonz == 0 )
                usleep(100000);
        }
    }
    else
    {
        while ( 1 )
        {
            nonz = 0;
            if ( (++counter % 2000) == 0 )
                LP_privkey_updates(mypeer,pubsock,passphrase,amclient);
            if ( (counter % 500) == 0 )
            {
                HASH_ITER(hh,LP_utxoinfos,utxo,utmp)
                {
                    if ( LP_txvalue(utxo->coin,utxo->txid,utxo->vout) == 0 )
                    {
                        printf("txid %s %.8f has been spent\n",utxo->coin,dstr(utxo->value));
                        LP_spentnotify(utxo,0);
                    }
                    else if ( LP_txvalue(utxo->coin,utxo->txid2,utxo->vout2) == 0 )
                    {
                        printf("txid2 %s %.8f has been spent\n",utxo->coin,dstr(utxo->value2));
                        LP_spentnotify(utxo,1);
                    }
                    else if ( LP_ismine(utxo) != 0 )
                    {
                        if ( strcmp(utxo->coin,"KMD") == 0 )
                            LP_priceping(pubsock,utxo,"BTC",profitmargin);
                        else LP_priceping(pubsock,utxo,"KMD",profitmargin);
                    }
                }
            }
            now = (uint32_t)time(NULL);
            HASH_ITER(hh,LP_peerinfos,peer,tmp)
            {
                if ( peer->numpeers > 0 && (peer->numpeers != mypeer->numpeers || (rand() % 10000) == 0) )
                {
                    if ( peer->numpeers != mypeer->numpeers )
                        printf("%s num.%d vs %d\n",peer->ipaddr,peer->numpeers,mypeer->numpeers);
                    if ( strcmp(peer->ipaddr,mypeer->ipaddr) != 0 )
                        LP_peersquery(amclient,mypeer,pubsock,peer->ipaddr,peer->port,mypeer->ipaddr,myport,profitmargin);
                }
                if ( peer->numutxos != mypeer->numutxos && now > peer->lastutxos+60 )
                {
                    peer->lastutxos = now;
                    lastn = peer->numutxos - mypeer->numutxos + LP_PROPAGATION_SLACK;
                    if ( lastn < LP_PROPAGATION_SLACK * 2 )
                        lastn = LP_PROPAGATION_SLACK * 2;
                    printf("%s numutxos.%d vs %d lastn.%d\n",peer->ipaddr,peer->numutxos,mypeer->numutxos,lastn);
                    if ( strcmp(peer->ipaddr,mypeer->ipaddr) != 0 )
                        LP_utxosquery(0,mypeer,pubsock,peer->ipaddr,peer->port,"",lastn,mypeer->ipaddr,myport,profitmargin);
                }
                while ( peer->subsock >= 0 && (recvsize= nn_recv(peer->subsock,&ptr,NN_MSG,0)) >= 0 )
                {
                    nonz++;
                    if ( (argjson= cJSON_Parse((char *)ptr)) != 0 )
                    {
                        portable_mutex_lock(&LP_commandmutex);
                        if ( (retstr= stats_JSON(argjson,"127.0.0.1",0)) != 0 )
                        {
                            //printf("%s RECV.[%d] %s\n",peer->ipaddr,recvsize,(char *)ptr);
                            free(retstr);
                        }
                        portable_mutex_unlock(&LP_commandmutex);
                        free_json(argjson);
                    } else printf("error parsing.(%s)\n",(char *)ptr);
                    if ( ptr != 0 )
                        nn_freemsg(ptr), ptr = 0;
                }
            }
            while ( pullsock >= 0 && (recvsize= nn_recv(pullsock,&ptr,NN_MSG,0)) >= 0 )
            {
                nonz++;
                if ( (argjson= cJSON_Parse((char *)ptr)) != 0 )
                {
                    len = (int32_t)strlen((char *)ptr) + 1;
                    portable_mutex_lock(&LP_commandmutex);
                    if ( LP_command(mypeer,pubsock,argjson,&((uint8_t *)ptr)[len],recvsize - len,profitmargin) == 0 )
                    {
                        if ( (retstr= stats_JSON(argjson,"127.0.0.1",0)) != 0 )
                        {
                            //printf("%s RECV.[%d] %s\n",peer->ipaddr,recvsize,(char *)ptr);
                            free(retstr);
                        }
                    }
                    portable_mutex_unlock(&LP_commandmutex);
                    free_json(argjson);
                }
                if ( ptr != 0 )
                    nn_freemsg(ptr), ptr = 0;
            }
            if ( nonz == 0 )
                usleep(50000);
        }
    }
}

void LPinit(uint16_t myport,uint16_t mypullport,uint16_t mypubport,double profitmargin,char *passphrase,int32_t amclient,char *userhome)
{
    char *myipaddr=0; long filesize,n; int32_t timeout,maxsize,pullsock=-1,pubsock=-1; struct LP_peerinfo *mypeer=0; char pushaddr[128],subaddr[128];
    IAMCLIENT = amclient;
    LP_profitratio += profitmargin;
    OS_randombytes((void *)&n,sizeof(n));
    srand((int32_t)n);
    if ( userhome != 0 && userhome[0] != 0 )
        safecopy(USERHOME,userhome,sizeof(USERHOME));
    portable_mutex_init(&LP_peermutex);
    portable_mutex_init(&LP_utxomutex);
    portable_mutex_init(&LP_commandmutex);
    portable_mutex_init(&LP_cachemutex);
    if ( amclient == 0 )
    {
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
                pullsock = pubsock = -1;
                nanomsg_tcpname(pushaddr,myipaddr,mypullport);
                nanomsg_tcpname(subaddr,myipaddr,mypubport);
                printf(">>>>>>>>> myipaddr.%s (%s %s)\n",myipaddr,pushaddr,subaddr);
                if ( (pullsock= nn_socket(AF_SP,NN_PULL)) >= 0 && (pubsock= nn_socket(AF_SP,NN_PUB)) >= 0 )
                {
                    if ( nn_bind(pullsock,pushaddr) >= 0 && nn_bind(pubsock,subaddr) >= 0 )
                    {
                        timeout = 10;
                        nn_setsockopt(pubsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                        timeout = 1;
                        nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                        timeout = 1;
                        maxsize = 1024 * 1024;
                        nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVBUF,&maxsize,sizeof(maxsize));
                    }
                    else
                    {
                        printf("error binding to (%s).%d (%s).%d\n",pushaddr,pullsock,subaddr,pubsock);
                        if ( pullsock >= 0 )
                            nn_close(pullsock), pullsock = -1;
                        if ( pubsock >= 0 )
                            nn_close(pubsock), pubsock = -1;
                    }
                } else printf("error getting sockets %d %d\n",pullsock,pubsock);
                LP_mypubsock = pubsock;
                LP_mypeer = mypeer = LP_addpeer(amclient,mypeer,pubsock,myipaddr,myport,0,0,profitmargin,0,0);
                //printf("my ipaddr.(%s) peers.(%s)\n",ipaddr,retstr!=0?retstr:"");
            } else printf("error getting myipaddr\n");
        } else printf("error issuing curl\n");
        if ( myipaddr == 0 || mypeer == 0 )
        {
            printf("couldnt get myipaddr or null mypeer.%p\n",mypeer);
            exit(-1);
        }
        printf("utxos.(%s)\n",LP_utxos(mypeer,"",10000));
    }
    LP_mainloop(mypeer,mypubport,pubsock,pullsock,myport,amclient,passphrase,profitmargin);
}


