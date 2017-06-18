
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

#include <stdio.h>
#include "LP_include.h"
portable_mutex_t LP_peermutex,LP_UTXOmutex,LP_utxomutex,LP_commandmutex,LP_cachemutex,LP_swaplistmutex,LP_forwardmutex,LP_pubkeymutex,LP_networkmutex;

#include "LP_network.c"

struct LP_utxoinfo  *LP_utxoinfos[2],*LP_utxoinfos2[2];
struct LP_peerinfo  *LP_peerinfos,*LP_mypeer;

char *activecoins[] = { "BTC", "KMD" };
char GLOBAL_DBDIR[] = { "DB" };
char USERPASS[65],USERPASS_WIFSTR[64],USERHOME[512] = { "/root" };

char *default_LPnodes[] = { "5.9.253.195", "5.9.253.196", "5.9.253.197", "5.9.253.198", "5.9.253.199", "5.9.253.200", "5.9.253.201", "5.9.253.202", "5.9.253.203", "5.9.253.204" }; //

int32_t LP_mypubsock = -1;
int32_t USERPASS_COUNTER,IAMLP = 0;
double LP_profitratio = 1.;
bits256 LP_mypubkey;

// stubs

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
#include "LP_ordermatch.c"
#include "LP_forwarding.c"
#include "LP_commands.c"

char *LP_command_process(char *myipaddr,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen,double profitmargin)
{
    char *retstr=0;
    if ( jobj(argjson,"result") != 0 || jobj(argjson,"error") != 0 )
        return(0);
    if ( LP_tradecommand(myipaddr,pubsock,argjson,data,datalen,profitmargin) <= 0 )
    {
        if ( (retstr= stats_JSON(myipaddr,pubsock,profitmargin,argjson,"127.0.0.1",0)) != 0 )
        {
            //printf("%s PULL.[%d]-> (%s)\n",myipaddr != 0 ? myipaddr : "127.0.0.1",datalen,retstr);
            if ( pubsock >= 0 ) //strncmp("{\"error\":",retstr,strlen("{\"error\":")) != 0 && 
                LP_send(pubsock,retstr,0);
        }
    }
    return(retstr);
}

void LP_process_message(char *typestr,char *myipaddr,int32_t pubsock,double profitmargin,void *ptr,int32_t recvlen)
{
    int32_t len,datalen=0; char *retstr,*jsonstr=0; cJSON *argjson,*reqjson;
    if ( (datalen= is_hexstr((char *)ptr,0)) > 0 )
    {
        datalen >>= 1;
        jsonstr = malloc(datalen + 1);
        decode_hex((void *)jsonstr,datalen,(char *)ptr);
        jsonstr[datalen] = 0;
    } else jsonstr = (char *)ptr;
    if ( 0 && IAMLP == 0 )
        printf("%s %d, datalen.%d (%s)\n",typestr,recvlen,datalen,jsonstr);
    if ( (argjson= cJSON_Parse(jsonstr)) != 0 )
    {
        len = (int32_t)strlen(jsonstr) + 1;
        portable_mutex_lock(&LP_commandmutex);
        if ( jstr(argjson,"method") != 0 && strcmp(jstr(argjson,"method"),"forwardhex") == 0 )
        {
            //printf("got forwardhex\n");
            if ( (retstr= LP_forwardhex(pubsock,jbits256(argjson,"pubkey"),jstr(argjson,"hex"))) != 0 )
                free(retstr);
        }
        else if ( jstr(argjson,"method") != 0 && strcmp(jstr(argjson,"method"),"publish") == 0 )
        {
            printf("got publish\n");
            if ( jobj(argjson,"method2") != 0 )
                jdelete(argjson,"method2");
            jaddstr(argjson,"method2","broadcast");
            if ( pubsock >= 0 && (reqjson= LP_dereference(argjson,"publish")) != 0 )
                LP_send(pubsock,jprint(reqjson,1),1);
        }
        else if ( (retstr= LP_command_process(myipaddr,pubsock,argjson,&((uint8_t *)ptr)[len],recvlen - len,profitmargin)) != 0 )
            free(retstr);
        portable_mutex_unlock(&LP_commandmutex);
        free_json(argjson);
    } else printf("error parsing(%s)\n",jsonstr);
    if ( (void *)jsonstr != ptr )
        free(jsonstr);
    if ( ptr != 0 )
        nn_freemsg(ptr), ptr = 0;
}

int32_t LP_pullsock_check(char *myipaddr,int32_t pubsock,int32_t pullsock,double profitmargin)
{
    void *ptr; int32_t recvlen,nonz = 0;
    while ( pullsock >= 0 && (recvlen= nn_recv(pullsock,&ptr,NN_MSG,NN_DONTWAIT)) >= 0 )
    {
        nonz++;
        LP_process_message("PULL",myipaddr,pubsock,profitmargin,ptr,recvlen);
    }
    return(nonz);
}

int32_t LP_subsock_check(char *myipaddr,int32_t pubsock,int32_t sock,double profitmargin)
{
    int32_t recvlen,nonz = 0; void *ptr;
    while ( sock >= 0 && (recvlen= nn_recv(sock,&ptr,NN_MSG,NN_DONTWAIT)) >= 0 )
    {
        nonz++;
        LP_process_message("SUB",myipaddr,pubsock,profitmargin,ptr,recvlen);
        /*if ( (argjson= cJSON_Parse((char *)ptr)) != 0 )
        {
            printf("%s SUB.[%d] %s\n",myipaddr,recvsize,jprint(argjson,0));
            portable_mutex_lock(&LP_commandmutex);
            if ( (retstr= LP_command_process(myipaddr,-1,argjson,0,0,profitmargin)) != 0 )
            {
                free(retstr);
            }
            portable_mutex_unlock(&LP_commandmutex);
            free_json(argjson);
        } else printf("error parsing.(%s)\n",(char *)ptr);
        if ( ptr != 0 )
            nn_freemsg(ptr), ptr = 0;*/
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
    }
}

void LP_myutxo_updates(int32_t pubsock,char *passphrase,double profitmargin)
{
    //LP_utxopurge(0); not good to disrupt existing pointers
    LP_privkey_updates(pubsock,passphrase,0);
}

int32_t LP_peer_utxosquery(struct LP_peerinfo *mypeer,uint16_t myport,int32_t pubsock,struct LP_peerinfo *peer,uint32_t now,double profitmargin,int32_t interval)
{
    int32_t lastn,n = -1;
    if ( peer->lastutxos < now-interval )
    {
        //lastn = peer->numutxos - mypeer->numutxos + LP_PROPAGATION_SLACK;
        //if ( lastn < LP_PROPAGATION_SLACK * 2 )
        lastn = LP_PROPAGATION_SLACK * 2;
        if ( mypeer == 0 || strcmp(peer->ipaddr,mypeer->ipaddr) != 0 )
        {
            peer->lastutxos = now;
            printf("query utxos from %s\n",peer->ipaddr);
            n = LP_utxosquery(mypeer,pubsock,peer->ipaddr,peer->port,"",lastn,mypeer != 0 ? mypeer->ipaddr : "127.0.0.1",myport,profitmargin);
        }
    } //else printf("LP_peer_utxosquery skip.(%s) %u\n",peer->ipaddr,peer->lastutxos);
    return(n);
}

int32_t LP_mainloop_iter(char *myipaddr,struct LP_peerinfo *mypeer,int32_t pubsock,char *pushaddr,int32_t pullsock,uint16_t myport,char *passphrase,double profitmargin)
{
    static uint32_t counter,lastforward,numpeers;
    struct LP_utxoinfo *utxo,*utmp; char *retstr; struct LP_peerinfo *peer,*tmp; uint32_t now; int32_t nonz = 0,n=0,lastn=-1;
    now = (uint32_t)time(NULL);
    if ( mypeer == 0 )
        myipaddr = "127.0.0.1";
    numpeers = 0;
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        numpeers++;
    }
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        if ( now > peer->lastpeers+60 && peer->numpeers > 0 && (peer->numpeers != numpeers || (rand() % 10000) == 0) )
        {
            printf("numpeers.%d updatepeer.%s lag.%d\n",numpeers,peer->ipaddr,now-peer->lastpeers);
            peer->lastpeers = now;
            if ( peer->numpeers != numpeers )
                printf("%s num.%d vs %d\n",peer->ipaddr,peer->numpeers,numpeers);
            if ( strcmp(peer->ipaddr,myipaddr) != 0 )
                LP_peersquery(mypeer,pubsock,peer->ipaddr,peer->port,myipaddr,myport,profitmargin);
        }
        if ( peer->diduquery == 0 )
        {
            if ( lastn != n || n < 20 )
            {
                lastn = n;
                n = LP_peer_utxosquery(mypeer,myport,pubsock,peer,now,profitmargin,60);
            }
            LP_peer_pricesquery(peer->ipaddr,peer->port);
            peer->diduquery = now;
        }
        nonz += LP_subsock_check(myipaddr,pubsock,peer->subsock,profitmargin);
    }
    if ( (counter % 600) == 60 )
    {
        LP_myutxo_updates(pubsock,passphrase,profitmargin);
        if ( lastforward < now-3600 )
        {
            LP_forwarding_register(LP_mypubkey,pushaddr,10);
            lastforward = now;
        }
    }
    if ( (counter % 600) == 0 )
    {
        HASH_ITER(hh,LP_utxoinfos[0],utxo,utmp)
        {
            LP_utxo_spentcheck(pubsock,utxo,profitmargin);
        }
        HASH_ITER(hh,LP_utxoinfos[1],utxo,utmp)
        {
            LP_utxo_spentcheck(pubsock,utxo,profitmargin);
            if ( utxo->T.lasttime == 0 )
                LP_utxo_clientpublish(utxo);
        }
    }
    if ( (counter % 600) == 599 )
    {
        if ( (retstr= basilisk_swapentry(0,0)) != 0 )
        {
            //printf("SWAPS.(%s)\n",retstr);
            free(retstr);
        }
    }
    nonz += LP_pullsock_check(myipaddr,pubsock,pullsock,profitmargin);
    if ( IAMLP != 0 && (counter % 600) == 42 )
        LP_hellos();
    counter++;
    return(nonz);
}

void LP_mainloop(char *myipaddr,struct LP_peerinfo *mypeer,uint16_t mypubport,int32_t pubsock,char *pushaddr,int32_t pullsock,uint16_t myport,char *passphrase,double profitmargin,cJSON *coins,char *seednode)
{
    uint8_t r; int32_t i,n,j; cJSON *item;
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
        fprintf(stderr,"%s ",activecoins[i]);
        LP_coinfind(activecoins[i]);
        LP_priceinfoadd(activecoins[i]);
    }
    if ( (n= cJSON_GetArraySize(coins)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(coins,i);
            fprintf(stderr,"%s ",jstr(item,"coin"));
            LP_coincreate(item);
            LP_priceinfoadd(jstr(item,"coin"));
        }
    }
    fprintf(stderr,"privkey updates\n");
    LP_privkey_updates(pubsock,passphrase,1);
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)stats_rpcloop,(void *)&myport) != 0 )
    {
        printf("error launching stats rpcloop for port.%u\n",myport);
        exit(-1);
    }
    while ( 1 )
    {
        if ( 0 && (rand() % 100) == 0 )
            printf("mainloop\n");
        if ( LP_mainloop_iter(myipaddr,mypeer,pubsock,pushaddr,pullsock,myport,passphrase,profitmargin) == 0 )
            usleep(100000);
    }
}

void nn_tests(int32_t pullsock,char *pushaddr)
{
    int32_t sock,n,timeout;
    if ( (sock= nn_socket(AF_SP,NN_BUS)) >= 0 )
    {
        if ( nn_connect(sock,pushaddr) < 0 )
            printf("connect error %s\n",nn_strerror(nn_errno()));
        else
        {
            timeout = 1000;
            nn_setsockopt(sock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
            n = nn_send(sock,"nn_tests",(int32_t)strlen("nn_tests")+1,0*NN_DONTWAIT);
            LP_pullsock_check("127.0.0.1",-1,pullsock,0.);
            // n = LP_send(sock,"nn_tests",0);
            printf("sent %d bytes\n",n);
        }
    }
}

void LPinit(uint16_t myport,uint16_t mypullport,uint16_t mypubport,double profitmargin,char *passphrase,int32_t amclient,char *userhome,cJSON *argjson)
{
    char *myipaddr=0; long filesize,n; int32_t maxsize,timeout,pullsock=-1,pubsock=-1; struct LP_peerinfo *mypeer=0; char pushaddr[128],subaddr[128],bindaddr[128];
    IAMLP = !amclient;
    LP_profitratio += profitmargin;
    OS_randombytes((void *)&n,sizeof(n));
    srand((int32_t)n);
    if ( userhome != 0 && userhome[0] != 0 )
    {
        safecopy(USERHOME,userhome,sizeof(USERHOME));
#ifdef __APPLE__
        strcat(USERHOME,"/Library/Application Support");
#endif
    }
    portable_mutex_init(&LP_peermutex);
    portable_mutex_init(&LP_utxomutex);
    portable_mutex_init(&LP_UTXOmutex);
    portable_mutex_init(&LP_commandmutex);
    portable_mutex_init(&LP_swaplistmutex);
    portable_mutex_init(&LP_cachemutex);
    portable_mutex_init(&LP_networkmutex);
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
    if ( (pullsock= nn_socket(AF_SP,NN_BUS)) >= 0 )
    {
        timeout = 1;
        nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
#ifdef __APPLE__
        nanomsg_tcpname(bindaddr,"*",mypullport);
#else
        nanomsg_tcpname(bindaddr,myipaddr,mypullport);
#endif
        if ( nn_bind(pullsock,bindaddr) >= 0 )
        {
            maxsize = 2 * 1024 * 1024;
            nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVBUF,&maxsize,sizeof(maxsize));
            LP_pullsock_check(myipaddr,-1,pullsock,0.);
        } else printf("bind to %s error for %s: %s\n",bindaddr,pushaddr,nn_strerror(nn_errno()));
    }
    nn_tests(pullsock,pushaddr);
    printf("my command address is (%s) pullsock.%d\n",pushaddr,pullsock);
    if ( IAMLP != 0 )
    {
        if ( myipaddr != 0 )
        {
            pubsock = -1;
            nanomsg_tcpname(subaddr,myipaddr,mypubport);
            nanomsg_tcpname(bindaddr,myipaddr,mypubport);
            if ( (pubsock= nn_socket(AF_SP,NN_PUB)) >= 0 )
            {
                if ( nn_bind(pubsock,bindaddr) >= 0 )
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
            printf(">>>>>>>>> myipaddr.%s (%s %s) pubsock.%d pullsock.%d\n",myipaddr,pushaddr,subaddr,pubsock,pullsock);
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



