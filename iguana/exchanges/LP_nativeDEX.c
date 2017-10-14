
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
//alice only coins GAME UNO BTM ANC: GAME BTCD PPC RDD XZC POT EAC FTC BASH SPR WDC UNO XPM XCN BELA CHC DIME MEC NAUT MED AUR MAX DGC RIC EB3 DOT BTM GEO ANC CANN ICASH WBB SRC PTC ADZ TIPS EQT START EFL FST FJC NYC GCN

//
//  LP_nativeDEX.c
//  marketmaker
//

// -SPV at tx level and limit SPV proofing
// withdraw
// stats, fix pricearray
// sign packets
// electrum peers
// dPoW security and zeroconf
// verify portfolio
// bittrex balancing


#include <stdio.h>
#include "LP_include.h"
portable_mutex_t LP_peermutex,LP_UTXOmutex,LP_utxomutex,LP_commandmutex,LP_cachemutex,LP_swaplistmutex,LP_forwardmutex,LP_pubkeymutex,LP_networkmutex,LP_psockmutex,LP_coinmutex,LP_messagemutex,LP_portfoliomutex,LP_electrummutex,LP_butxomutex,LP_reservedmutex,LP_nanorecvsmutex;
int32_t LP_canbind;
char *Broadcaststr,*Reserved_msgs[1000];
int32_t num_Reserved_msgs,max_Reserved_msgs;
struct LP_peerinfo  *LP_peerinfos,*LP_mypeer;
struct LP_forwardinfo *LP_forwardinfos;
struct iguana_info *LP_coins;
#include "LP_network.c"

char *activecoins[] = { "BTC", "KMD" };
char GLOBAL_DBDIR[] = { "DB" };
char LP_myipaddr[64],LP_publicaddr[64],USERHOME[512] = { "/root" };
char LP_gui[16] = { "cli" };

char *default_LPnodes[] = { "5.9.253.195", "5.9.253.196", "5.9.253.197", "5.9.253.198", "5.9.253.199", "5.9.253.200", "5.9.253.201", "5.9.253.202", "5.9.253.203", };//"5.9.253.204" }; //

//uint32_t LP_deadman_switch;
uint16_t LP_fixed_pairport,LP_publicport;
int32_t LP_mybussock = -1;
int32_t LP_mypubsock = -1;
int32_t LP_mypullsock = -1;
int32_t LP_showwif,IAMLP = 0;
double LP_profitratio = 1.;

struct LP_privkey { bits256 privkey; uint8_t rmd160[20]; };

struct LP_globals
{
    struct LP_utxoinfo  *LP_utxoinfos[2],*LP_utxoinfos2[2];
    bits256 LP_mypub25519,LP_mypriv25519;
    uint64_t LP_skipstatus[10000];
    uint8_t LP_myrmd160[20],LP_pubsecp[33];
    uint32_t LP_sessionid,counter;
    int32_t LP_pendingswaps,USERPASS_COUNTER,LP_numprivkeys,initializing,waiting,LP_numskips;
    char USERPASS[65],USERPASS_WIFSTR[64],LP_myrmd160str[41],gui[16];
    struct LP_privkey LP_privkeys[100];
} G;

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

#include "LP_socket.c"
#include "LP_secp.c"
#include "LP_bitcoin.c"
#include "LP_coins.c"
#include "LP_rpc.c"
#include "LP_utxo.c"
#include "LP_prices.c"
#include "LP_scan.c"
#include "LP_transaction.c"
#include "LP_remember.c"
#include "LP_swap.c"
#include "LP_peers.c"
#include "LP_utxos.c"
#include "LP_forwarding.c"
#include "LP_ordermatch.c"
#include "LP_portfolio.c"
#include "LP_messages.c"
#include "LP_commands.c"

char *LP_command_process(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen)
{
    char *retstr=0;
    if ( jobj(argjson,"result") != 0 || jobj(argjson,"error") != 0 )
        return(0);
    if ( LP_tradecommand(ctx,myipaddr,pubsock,argjson,data,datalen) <= 0 )
    {
        if ( (retstr= stats_JSON(ctx,myipaddr,pubsock,argjson,"127.0.0.1",0)) != 0 )
        {
            //printf("%s PULL.[%d]-> (%s)\n",myipaddr != 0 ? myipaddr : "127.0.0.1",datalen,retstr);
            //if ( pubsock >= 0 ) //strncmp("{\"error\":",retstr,strlen("{\"error\":")) != 0 &&
                //LP_send(pubsock,retstr,(int32_t)strlen(retstr)+1,0);
        }
    } //else printf("finished tradecommand (%s)\n",jprint(argjson,0));
    return(retstr);
}

char *LP_decrypt(uint8_t *ptr,int32_t *recvlenp)
{
    uint8_t decoded[LP_ENCRYPTED_MAXSIZE + crypto_box_ZEROBYTES],*nonce,*cipher; int32_t recvlen,cipherlen; char *jsonstr = 0;
    recvlen = *recvlenp;
    nonce = &ptr[2];
    cipher = &ptr[2 + crypto_box_NONCEBYTES];
    cipherlen = recvlen - (2 + crypto_box_NONCEBYTES);
    if ( cipherlen > 0 && cipherlen <= sizeof(decoded) )
    {
        if ( (jsonstr= (char *)_SuperNET_decipher(nonce,cipher,decoded,cipherlen,GENESIS_PUBKEY,G.LP_mypriv25519)) != 0 )
        {
            recvlen = (cipherlen - crypto_box_ZEROBYTES);
            if ( strlen(jsonstr)+1 != recvlen )
            {
                printf("unexpected len %d vs recvlen.%d\n",(int32_t)strlen(jsonstr)+1,recvlen);
                jsonstr = 0;
            } else printf("decrypted (%s)\n",jsonstr);
        }
    } else printf("cipher.%d too big for %d\n",cipherlen,(int32_t)sizeof(decoded));
    *recvlenp = recvlen;
    return(jsonstr);
}

char *LP_process_message(void *ctx,char *typestr,char *myipaddr,int32_t pubsock,uint8_t *ptr,int32_t recvlen,int32_t recvsock)
{
    static uint32_t dup,uniq;
    int32_t i,len,cipherlen,datalen=0,duplicate=0,encrypted=0; char *method,*method2,*tmp,*cipherstr,*retstr=0,*jsonstr=0; cJSON *argjson; uint32_t crc32;
    crc32 = calc_crc32(0,&ptr[2],recvlen-2);
    if ( (crc32 & 0xff) == ptr[0] && ((crc32>>8) & 0xff) == ptr[1] )
        encrypted = 1;
    portable_mutex_lock(&LP_commandmutex);
    i = LP_crc32find(&duplicate,-1,crc32);
    if ( duplicate != 0 )
        dup++;
    else uniq++;
    if ( (rand() % 1000) == 0 )
        printf("%s dup.%d (%u / %u) %.1f%% encrypted.%d recv.%u [%02x %02x] vs %02x %02x\n",typestr,duplicate,dup,dup+uniq,(double)100*dup/(dup+uniq),encrypted,crc32,ptr[0],ptr[1],crc32&0xff,(crc32>>8)&0xff);
    if ( duplicate == 0 )
    {
        if ( i >= 0 )
            LP_crc32find(&duplicate,i,crc32);
        if ( encrypted != 0 )
            jsonstr = LP_decrypt(ptr,&recvlen);
        else if ( (datalen= is_hexstr((char *)ptr,0)) > 0 )
        {
            datalen >>= 1;
            jsonstr = malloc(datalen + 1);
            decode_hex((void *)jsonstr,datalen,(char *)ptr);
            jsonstr[datalen] = 0;
        } else jsonstr = (char *)ptr;
        if ( jsonstr != 0 && (argjson= cJSON_Parse(jsonstr)) != 0 )
        {
            uint8_t decoded[LP_ENCRYPTED_MAXSIZE + crypto_box_ZEROBYTES];
            //printf("[%s]\n",jsonstr);
            cipherlen = 0;
            if ( (cipherstr= jstr(argjson,"cipher")) != 0 && (cipherlen= is_hexstr(cipherstr,0)) > 32 && cipherlen <= sizeof(decoded)*2 )
            {
                method2 = jstr(argjson,"method2");
                if ( (method= jstr(argjson,"method")) != 0 && (strcmp(method,"encrypted") == 0 ||(method2 != 0 && strcmp(method2,"encrypted") == 0)) )
                {
                    cipherlen >>= 1;
                    decode_hex(decoded,cipherlen,cipherstr);
                    crc32 = calc_crc32(0,&decoded[2],cipherlen-2);
                    if ( (tmp= LP_decrypt(decoded,&cipherlen)) != 0 )
                    {
                        jsonstr = tmp;
                        free_json(argjson);
                        argjson = cJSON_Parse(jsonstr);
                        recvlen = cipherlen;
                        encrypted = 1;
                        if ( (crc32 & 0xff) == decoded[0] && ((crc32>>8) & 0xff) == decoded[1] )
                        {
                            i = LP_crc32find(&duplicate,-1,crc32);
                            if ( duplicate == 0 && i >= 0 )
                                LP_crc32find(&duplicate,i,crc32);
                        }
                        printf("%02x %02x %08x duplicate.%d decrypted.(%s)\n",decoded[0],decoded[1],crc32,duplicate,jsonstr);
                    }
                    else
                    {
                        printf("packet not for this node %u\n",crc32);
                    }
                } else printf("error (%s) method is %s\n",jsonstr,method);
            }
            if ( jsonstr != 0 && argjson != 0 )
            {
                len = (int32_t)strlen(jsonstr) + 1;
                if ( (retstr= LP_command_process(ctx,myipaddr,pubsock,argjson,&((uint8_t *)ptr)[len],recvlen - len)) != 0 )
                {
                }
                free_json(argjson);
            }
        }
    } //else printf("DUPLICATE.(%s)\n",(char *)ptr);
    portable_mutex_unlock(&LP_commandmutex);
    if ( jsonstr != 0 && (void *)jsonstr != (void *)ptr && encrypted == 0 )
        free(jsonstr);
    if ( ptr != 0 )
        nn_freemsg(ptr), ptr = 0;
    return(retstr);
}

int32_t LP_sock_check(char *typestr,void *ctx,char *myipaddr,int32_t pubsock,int32_t sock,char *remoteaddr)
{
    int32_t recvlen=1,nonz = 0; cJSON *argjson; void *ptr; char *retstr,*str; struct nn_pollfd pfd;
    if ( sock >= 0 )
    {
        while ( nonz < 100 && recvlen > 0 )
        {
            memset(&pfd,0,sizeof(pfd));
            pfd.fd = sock;
            pfd.events = NN_POLLIN;
            if ( nn_poll(&pfd,1,1) != 1 )
                break;
            if ( (recvlen= nn_recv(sock,&ptr,NN_MSG,0)) > 0 )
            {
//printf("RECV.(%s)\n",(char *)ptr);
                nonz++;
                if ( (retstr= LP_process_message(ctx,typestr,myipaddr,pubsock,ptr,recvlen,sock)) != 0 )
                    free(retstr);
                if ( Broadcaststr != 0 )
                {
                    //printf("self broadcast.(%s)\n",Broadcaststr);
                    str = Broadcaststr;
                    Broadcaststr = 0;
                    if ( (argjson= cJSON_Parse(str)) != 0 )
                    {
                        if ( jobj(argjson,"method") != 0 && strcmp("connect",jstr(argjson,"method")) == 0 )
                            printf("self.(%s)\n",str);
                        if ( LP_tradecommand(ctx,myipaddr,pubsock,argjson,0,0) <= 0 )
                        {
                            portable_mutex_lock(&LP_commandmutex);
                            if ( (retstr= stats_JSON(ctx,myipaddr,pubsock,argjson,remoteaddr,0)) != 0 )
                            free(retstr);
                            portable_mutex_unlock(&LP_commandmutex);
                        }
                        free_json(argjson);
                    }
                    free(str);
                }
            }
        }
    }
    return(nonz);
}

int32_t LP_nanomsg_recvs(void *ctx)
{
    static double lastmilli;
    int32_t nonz = 0; char *origipaddr; struct LP_peerinfo *peer,*tmp; double milli;
    if ( (origipaddr= LP_myipaddr) == 0 )
        origipaddr = "127.0.0.1";
    milli = OS_milliseconds();
    if ( lastmilli > 0. && milli > lastmilli+100 )
        fprintf(stderr,">>>>>>>>>>>>>>>>> BIG latency lag %.3f milliseconds\n",milli-lastmilli);
    lastmilli = milli;
    //portable_mutex_lock(&LP_nanorecvsmutex);
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        if ( peer->errors >= LP_MAXPEER_ERRORS )
        {
            if ( (rand() % 10000) == 0 )
                peer->errors--;
            else
            {
                //printf("skip %s\n",peer->ipaddr);
                continue;
            }
        }
        //printf("check %s pubsock.%d\n",peer->ipaddr,peer->subsock);
        nonz += LP_sock_check("PULL",ctx,origipaddr,LP_mypubsock,peer->subsock,peer->ipaddr);
    }
    /*HASH_ITER(hh,LP_coins,coin,ctmp) // firstrefht,firstscanht,lastscanht
     {
     if ( coin->inactive != 0 )
     continue;
     if ( coin->bussock >= 0 )
     nonz += LP_sock_check(coin->symbol,ctx,origipaddr,-1,coin->bussock,LP_profitratio - 1.);
     }*/
    if ( LP_mypullsock >= 0 )
        nonz += LP_sock_check("SUB",ctx,origipaddr,-1,LP_mypullsock,"127.0.0.1");
    //portable_mutex_unlock(&LP_nanorecvsmutex);
    return(nonz);
}

void command_rpcloop(void *myipaddr)
{
    int32_t nonz = 0; void *ctx;
    ctx = bitcoin_ctx();
    while ( 1 )
    {
        nonz = LP_nanomsg_recvs(ctx);
        //if ( LP_mybussock >= 0 )
        //    nonz += LP_sock_check("BUS",ctx,origipaddr,-1,LP_mybussock);
        if ( nonz == 0 )
        {
            if ( IAMLP != 0 )
                usleep(1000);
            else usleep(10000);
        }
    }
}

void LP_smartutxos_push(struct iguana_info *coin)
{
    struct LP_peerinfo *peer,*tmp; uint64_t value; bits256 zero,txid; int32_t i,vout,height,n; char *retstr; cJSON *array,*item,*req;
    if ( coin->smartaddr[0] == 0 )
        return;
    if ( (array= LP_address_utxos(coin,coin->smartaddr,1)) != 0 )
    {
        memset(zero.bytes,0,sizeof(zero));
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            printf("PUSH %s %s\n",coin->symbol,coin->smartaddr);
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                txid = jbits256(item,"tx_hash");
                vout = jint(item,"tx_pos");
                value = j64bits(item,"value");
                height = jint(item,"height");
                if ( 0 )
                {
                HASH_ITER(hh,LP_peerinfos,peer,tmp)
                {
                    if ( (retstr= issue_LP_uitem(peer->ipaddr,peer->port,coin->symbol,coin->smartaddr,txid,vout,height,value)) != 0 )
                        free(retstr);
                }
                }
                else
                {
                    req = cJSON_CreateObject();
                    jaddstr(req,"method","uitem");
                    jaddstr(req,"coin",coin->symbol);
                    jaddstr(req,"coinaddr",coin->smartaddr);
                    jaddbits256(req,"txid",txid);
                    jaddnum(req,"vout",vout);
                    jaddnum(req,"ht",height);
                    jadd64bits(req,"value",value);
                    //printf("ADDR_UNSPENTS[] <- %s\n",jprint(req,0));
                    LP_reserved_msg("","",zero,jprint(req,1));
                }
            }
        }
        free_json(array);
    }
}

int32_t LP_utxos_sync(struct LP_peerinfo *peer)
{
    int32_t i,j,n=0,m,v,posted=0; bits256 txid; cJSON *array,*item,*item2,*array2,*array3; uint64_t total,total2,metric; struct iguana_info *coin,*ctmp; struct LP_address *ap; char *retstr,*retstr2,*coinaddr;
    if ( strcmp(peer->ipaddr,LP_myipaddr) == 0 )
        return(0);
    HASH_ITER(hh,LP_coins,coin,ctmp)
    {
        if ( IAMLP == 0 && coin->inactive != 0 )//|| (coin->electrum != 0 && coin->obooktime == 0) )
            continue;
        if ( coin->smartaddr[0] == 0 )
            continue;
        total = 0;
        if ( (j= LP_listunspent_both(coin->symbol,coin->smartaddr,0)) == 0 )
            continue;
        if ( (array= LP_address_utxos(coin,coin->smartaddr,1)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    total += j64bits(item,"value");
                }
            }
            if ( n > 0 && total > 0 && (retstr= issue_LP_listunspent(peer->ipaddr,peer->port,coin->symbol,coin->smartaddr)) != 0 )
            {
                //printf("UTXO sync.%d %s n.%d total %.8f -> %s (%s)\n",j,coin->symbol,n,dstr(total),peer->ipaddr,retstr);
                total2 = 0;
                if ( (array2= cJSON_Parse(retstr)) != 0 )
                {
                    if ( (m= cJSON_GetArraySize(array2)) > 0 )
                    {
                        for (i=0; i<m; i++)
                        {
                            item2 = jitem(array2,i);
                            total2 += j64bits(item2,"value");
                        }
                    }
                    if ( total != total2 || n != m )
                    {
                        for (i=0; i<n; i++)
                        {
                            item = jitem(array,i);
                            txid = jbits256(item,"tx_hash");
                            v = jint(item,"tx_pos");
                            for (j=0; j<m; j++)
                            {
                                if ( v == jint(jitem(array2,i),"tx_pos") && bits256_cmp(txid,jbits256(jitem(array2,i),"tx_hash")) == 0 )
                                    break;
                            }
                            if ( j == m )
                            {
                                //printf("%s missing %s %s\n",peer->ipaddr,coin->symbol,jprint(item,0));
                                if ( (retstr2= issue_LP_uitem(peer->ipaddr,peer->port,coin->symbol,coin->smartaddr,txid,v,jint(item,"height"),j64bits(item,"value"))) != 0 )
                                    free(retstr2);
                                posted++;
                            }
                        }
                        if ( 0 && posted != 0 )
                            printf(">>>>>>>> %s compare %s %s (%.8f n%d) (%.8f m%d)\n",peer->ipaddr,coin->symbol,coin->smartaddr,dstr(total),n,dstr(total2),m);
                    } //else printf("%s matches %s\n",peer->ipaddr,coin->symbol);
                    free_json(array2);
                } else printf("parse error (%s)\n",retstr);
                free(retstr);
            }
            else if ( n != 0 && total != 0 )
            {
                //printf("no response from %s for %s %s\n",peer->ipaddr,coin->symbol,coin->smartaddr);
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    txid = jbits256(item,"tx_hash");
                    v = jint(item,"tx_pos");
                    if ( (retstr2= issue_LP_uitem(peer->ipaddr,peer->port,coin->symbol,coin->smartaddr,txid,v,jint(item,"height"),j64bits(item,"value"))) != 0 )
                        free(retstr2);
                }
            }
            free_json(array);
        }
        if ( 0 && (retstr= issue_LP_listunspent(peer->ipaddr,peer->port,coin->symbol,"")) != 0 )
        {
            if ( (array2= cJSON_Parse(retstr)) != 0 )
            {
                if ( (m= cJSON_GetArraySize(array2)) > 0 )
                {
                    for (j=0; j<m; j++)
                    {
                        item = jitem(array2,j);
                        if ( (coinaddr= jfieldname(item)) != 0 )
                        {
                            metric = j64bits(item,coinaddr);
                            //printf("(%s) -> %.8f n.%d\n",coinaddr,dstr(metric>>16),(uint16_t)metric);
                            if ( (ap= LP_addressfind(coin,coinaddr)) == 0 || _LP_unspents_metric(ap->total,ap->n) != metric )
                            {
                                if ( ap == 0 || ap->n < (metric & 0xffff) )
                                {
                                    if ( (retstr2= issue_LP_listunspent(peer->ipaddr,peer->port,coin->symbol,coinaddr)) != 0 )
                                    {
                                        if ( (array3= cJSON_Parse(retstr2)) != 0 )
                                        {
                                            LP_unspents_array(coin,coinaddr,array3);
                                            //printf("pulled.(%s)\n",retstr2);
                                            free_json(array3);
                                        }
                                        free(retstr2);
                                    }
                                } //else printf("wait for %s to pull %d vs %d\n",peer->ipaddr,ap!=0?ap->n:-1,(uint16_t)metric);
                            }
                        }
                    }
                }
                free_json(array2);
            }
            //printf("processed.(%s)\n",retstr);
            free(retstr);
        }
    }
    return(posted);
}

int32_t LP_mainloop_iter(void *ctx,char *myipaddr,struct LP_peerinfo *mypeer,int32_t pubsock,char *pushaddr,uint16_t myport)
{
    static uint32_t counter,numpeers;
    struct iguana_info *coin,*ctmp; char *retstr,*origipaddr; struct LP_peerinfo *peer,*tmp; uint32_t now; bits256 zero; int32_t needpings,j,height,nonz = 0;
    now = (uint32_t)time(NULL);
    if ( (origipaddr= myipaddr) == 0 )
        origipaddr = "127.0.0.1";
    if ( mypeer == 0 )
        myipaddr = "127.0.0.1";
    numpeers = LP_numpeers();
    needpings = 0;
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        if ( peer->errors >= LP_MAXPEER_ERRORS )
        {
            if ( (rand() % 10000) == 0 )
            {
                peer->errors--;
                if ( peer->errors < LP_MAXPEER_ERRORS )
                    peer->diduquery = 0;
            }
            if ( IAMLP == 0 )
                continue;
        }
        if ( now > peer->lastpeers+60 || (rand() % 10000) == 0 )
        {
            if ( strcmp(peer->ipaddr,myipaddr) != 0 )
            {
                nonz++;
                LP_peersquery(mypeer,pubsock,peer->ipaddr,peer->port,myipaddr,myport);
                peer->diduquery = 0;
                LP_utxos_sync(peer);
            }
            peer->lastpeers = now;
        }
        if ( peer->diduquery == 0 )
        {
            nonz++;
            needpings++;
            LP_peer_pricesquery(peer);
            LP_utxos_sync(peer);
            peer->diduquery = now;
        }
        if ( peer->needping != 0 )
        {
            nonz++;
            needpings++;
            if ( (retstr= issue_LP_notify(peer->ipaddr,peer->port,"127.0.0.1",0,numpeers,G.LP_sessionid,G.LP_myrmd160str,G.LP_mypub25519)) != 0 )
                free(retstr);
            peer->needping = 0;
        }
    }
    if ( needpings != 0 || (counter % 6000) == 5 )
    {
        nonz++;
        //printf("needpings.%d send notify\n",needpings);
        LP_notify_pubkeys(ctx,pubsock);
    }
    if ( (counter % 6000) == 10 )
    {
        nonz++;
        LP_privkey_updates(ctx,pubsock,0);
    }
    HASH_ITER(hh,LP_coins,coin,ctmp) // firstrefht,firstscanht,lastscanht
    {
        memset(&zero,0,sizeof(zero));
        if ( coin->addr_listunspent_requested != 0 )
        {
            //printf("addr_listunspent_requested %u\n",coin->addr_listunspent_requested);
            LP_smartutxos_push(coin);
            coin->addr_listunspent_requested = 0;
        }
        if ( coin->inactive != 0 )
            continue;
        if ( coin->electrum != 0 )
            continue;
        //if ( coin->obooktime == 0 )
        //    continue;
        if ( time(NULL) > coin->lastgetinfo+LP_GETINFO_INCR )
        {
            nonz++;
            if ( (height= LP_getheight(coin)) > coin->longestchain )
            {
                coin->longestchain = height;
                if ( coin->firstrefht != 0 )
                    printf(">>>>>>>>>> set %s longestchain %d (ref.%d [%d, %d])\n",coin->symbol,height,coin->firstrefht,coin->firstscanht,coin->lastscanht);
            } else LP_mempoolscan(coin->symbol,zero);
            coin->lastgetinfo = (uint32_t)time(NULL);
        }
        if ( coin->firstrefht == 0 )
            continue;
        else if ( coin->firstscanht == 0 )
            coin->lastscanht = coin->firstscanht = coin->firstrefht;
        else if ( coin->firstrefht < coin->firstscanht )
        {
            printf("detected %s firstrefht.%d < firstscanht.%d\n",coin->symbol,coin->firstrefht,coin->firstscanht);
            coin->lastscanht = coin->firstscanht = coin->firstrefht;
        }
        if ( coin->lastscanht == coin->longestchain+1 )
            continue;
        else if ( coin->lastscanht > coin->longestchain+1 )
        {
            printf("detected chain rewind lastscanht.%d vs longestchain.%d, first.%d ref.%d\n",coin->lastscanht,coin->longestchain,coin->firstscanht,coin->firstrefht);
            LP_undospends(coin,coin->longestchain-1);
            LP_mempoolscan(coin->symbol,zero);
            coin->lastscanht = coin->longestchain - 1;
            if ( coin->firstscanht < coin->lastscanht )
                coin->lastscanht = coin->firstscanht;
            continue;
        }
        if ( (coin->lastscanht % 1000) == 0 )
            printf("%s ref.%d scan.%d to %d, longest.%d\n",coin->symbol,coin->firstrefht,coin->firstscanht,coin->lastscanht,coin->longestchain);
        for (j=0; j<100; j++)
        {
            if ( LP_blockinit(coin,coin->lastscanht) < 0 )
            {
                printf("blockinit.%s %d error\n",coin->symbol,coin->lastscanht);
                break;
            }
            coin->lastscanht++;
            if ( coin->lastscanht == coin->longestchain+1 )
                break;
        }
        if ( j < 100 )
            continue;
        nonz++;
        //LP_getestimatedrate(coin);
        break;
    }
    if ( (counter % 6000) == 60 )
    {
        if ( (retstr= basilisk_swapentry(0,0)) != 0 )
        {
            //printf("SWAPS.(%s)\n",retstr);
            nonz++;
            free(retstr);
        }
    }
    counter++;
    return(nonz);
}

void LP_initcoins(void *ctx,int32_t pubsock,cJSON *coins)
{
    int32_t i,n; cJSON *item;
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
}

void LP_initpeers(int32_t pubsock,struct LP_peerinfo *mypeer,char *myipaddr,uint16_t myport,char *seednode)
{
    int32_t i,j; uint32_t r;
    if ( IAMLP != 0 )
    {
        LP_mypeer = mypeer = LP_addpeer(mypeer,pubsock,myipaddr,myport,0,0,0,0,G.LP_sessionid);
        if ( myipaddr == 0 || mypeer == 0 )
        {
            printf("couldnt get myipaddr or null mypeer.%p\n",mypeer);
            exit(-1);
        }
        if ( seednode == 0 || seednode[0] == 0 )
        {
            for (i=0; i<sizeof(default_LPnodes)/sizeof(*default_LPnodes); i++)
            {
                //if ( (rand() % 100) > 25 )
                //    continue;
                LP_peersquery(mypeer,pubsock,default_LPnodes[i],myport,mypeer->ipaddr,myport);
            }
        } else LP_peersquery(mypeer,pubsock,seednode,myport,mypeer->ipaddr,myport);
    }
    else
    {
        if ( myipaddr == 0 )
        {
            printf("couldnt get myipaddr\n");
            exit(-1);
        }
        if ( seednode == 0 || seednode[0] == 0 )
        {
            OS_randombytes((void *)&r,sizeof(r));
            for (j=0; j<sizeof(default_LPnodes)/sizeof(*default_LPnodes); j++)
            {
                i = (r + j) % (sizeof(default_LPnodes)/sizeof(*default_LPnodes));
                LP_peersquery(mypeer,pubsock,default_LPnodes[i],myport,"127.0.0.1",myport);
            }
        } else LP_peersquery(mypeer,pubsock,seednode,myport,"127.0.0.1",myport);
    }
}

int32_t LP_reserved_msgs()
{
    bits256 zero; int32_t n = 0;
    memset(zero.bytes,0,sizeof(zero));
    portable_mutex_lock(&LP_reservedmutex);
    while ( num_Reserved_msgs > 0 )
    {
        num_Reserved_msgs--;
        //printf("BROADCASTING RESERVED.(%s)\n",Reserved_msgs[num_Reserved_msgs]);
        LP_broadcast_message(LP_mypubsock,"","",zero,Reserved_msgs[num_Reserved_msgs]);
        Reserved_msgs[num_Reserved_msgs] = 0;
        n++;
    }
    portable_mutex_unlock(&LP_reservedmutex);
    return(n);
}

int32_t LP_reserved_msg(char *base,char *rel,bits256 pubkey,char *msg)
{
    int32_t n = 0;
    portable_mutex_lock(&LP_reservedmutex);
    if ( num_Reserved_msgs < sizeof(Reserved_msgs)/sizeof(*Reserved_msgs) )
    {
        Reserved_msgs[num_Reserved_msgs++] = msg;
        n = num_Reserved_msgs;
    } else LP_broadcast_message(LP_mypubsock,base,rel,pubkey,msg);
    portable_mutex_unlock(&LP_reservedmutex);
    if ( num_Reserved_msgs > max_Reserved_msgs )
    {
        max_Reserved_msgs = num_Reserved_msgs;
        printf("New max_Reserved_msgs.%d\n",max_Reserved_msgs);
    }
    return(n);
}

void LPinit(uint16_t myport,uint16_t mypullport,uint16_t mypubport,uint16_t mybusport,char *passphrase,int32_t amclient,char *userhome,cJSON *argjson)
{
    char *myipaddr=0; long filesize,n; int32_t timeout,pubsock=-1; struct LP_peerinfo *mypeer=0; char pushaddr[128],subaddr[128],bindaddr[128],*coins_str=0; cJSON *coinsjson=0; void *ctx = bitcoin_ctx();
    LP_showwif = juint(argjson,"wif");
    if ( passphrase == 0 || passphrase[0] == 0 )
    {
        printf("jeezy says we cant use the nullstring as passphrase and I agree\n");
        exit(-1);
    }
    IAMLP = !amclient;
#ifndef __linux__
    if ( IAMLP != 0 )
    {
        printf("must run a unix node for LP node\n");
        exit(-1);
    }
#endif
    OS_randombytes((void *)&n,sizeof(n));
    if ( jobj(argjson,"gui") != 0 )
        safecopy(LP_gui,jstr(argjson,"gui"),sizeof(LP_gui));
    if ( jobj(argjson,"canbind") == 0 )
    {
#ifndef __linux__
        LP_canbind = IAMLP;
#else
        LP_canbind = IAMLP;
#endif
    }
    else
    {
        LP_canbind = jint(argjson,"canbind");
        printf(">>>>>>>>>>> set LP_canbind.%d\n",LP_canbind);
    }
    if ( LP_canbind > 1000 && LP_canbind < 65536 )
        LP_fixed_pairport = LP_canbind;
    if ( LP_canbind != 0 )
        LP_canbind = 1;
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
    portable_mutex_init(&LP_psockmutex);
    portable_mutex_init(&LP_coinmutex);
    portable_mutex_init(&LP_pubkeymutex);
    portable_mutex_init(&LP_electrummutex);
    portable_mutex_init(&LP_messagemutex);
    portable_mutex_init(&LP_portfoliomutex);
    portable_mutex_init(&LP_butxomutex);
    portable_mutex_init(&LP_reservedmutex);
    portable_mutex_init(&LP_nanorecvsmutex);
#ifndef _WIN32
    if ( system("curl -s4 checkip.amazonaws.com > DB/myipaddr") == 0 )
    {
        char ipfname[64];
        strcpy(ipfname,"DB/myipaddr");
        if ( (myipaddr= OS_filestr(&filesize,ipfname)) != 0 && myipaddr[0] != 0 )
        {
            n = strlen(myipaddr);
            if ( myipaddr[n-1] == '\n' )
                myipaddr[--n] = 0;
            strcpy(LP_myipaddr,myipaddr);
        } else printf("error getting myipaddr\n");
    } else printf("error issuing curl\n");
#else
    myipaddr = clonestr("127.0.0.1");
#endif
    if ( IAMLP != 0 )
    {
        pubsock = -1;
        nanomsg_transportname(0,subaddr,myipaddr,mypubport);
        nanomsg_transportname(1,bindaddr,myipaddr,mypubport);
        if ( (pubsock= nn_socket(AF_SP,NN_PUB)) >= 0 )
        {
            if ( nn_bind(pubsock,bindaddr) >= 0 )
            {
                timeout = 1;
                nn_setsockopt(pubsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
            }
            else
            {
                printf("error binding to (%s).%d\n",subaddr,pubsock);
                if ( pubsock >= 0 )
                    nn_close(pubsock), pubsock = -1;
            }
        } else printf("error getting pubsock %d\n",pubsock);
        printf(">>>>>>>>> myipaddr.%s (%s) pullsock.%d\n",myipaddr,subaddr,pubsock);
        LP_mypubsock = pubsock;
    }
    printf("got %s, initpeers\n",myipaddr);
    LP_initpeers(pubsock,mypeer,myipaddr,myport,jstr(argjson,"seednode"));
    printf("get public socket\n");
    LP_mypullsock = LP_initpublicaddr(ctx,&mypullport,pushaddr,myipaddr,mypullport,0);
    strcpy(LP_publicaddr,pushaddr);
    LP_publicport = mypullport;
    LP_mybussock = LP_coinbus(mybusport);
    //LP_deadman_switch = (uint32_t)time(NULL);
    printf("canbind.%d my command address is (%s) pullsock.%d pullport.%u\n",LP_canbind,pushaddr,LP_mypullsock,mypullport);
    if ( (coinsjson= jobj(argjson,"coins")) == 0 )
    {
        if ( (coins_str= OS_filestr(&filesize,"coins.json")) != 0 )
        {
            unstringify(coins_str);
            printf("UNSTRINGIFIED.(%s)\n",coins_str);
            coinsjson = cJSON_Parse(coins_str);
            free(coins_str);
            // yes I know this coinsjson is not freed, not sure about if it is referenced
        }
    }
    if ( coinsjson == 0 )
    {
        printf("no coins object or coins file, must abort\n");
        exit(-1);
    }
    LP_initcoins(ctx,pubsock,coinsjson);
    G.waiting = 1;
    LP_passphrase_init(passphrase,jstr(argjson,"gui"));
    if ( IAMLP != 0 && OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_psockloop,(void *)&myipaddr) != 0 )
    {
        printf("error launching LP_psockloop for (%s)\n",myipaddr);
        exit(-1);
    }
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)stats_rpcloop,(void *)&myport) != 0 )
    {
        printf("error launching stats rpcloop for port.%u\n",myport);
        exit(-1);
    }
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)command_rpcloop,(void *)&myipaddr) != 0 )
    {
        printf("error launching stats rpcloop for port.%u\n",myport);
        exit(-1);
    }
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)queue_loop,(void *)&myipaddr) != 0 )
    {
        printf("error launching stats rpcloop for port.%u\n",myport);
        exit(-1);
    }
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)prices_loop,(void *)&myipaddr) != 0 )
    {
        printf("error launching stats rpcloop for port.%u\n",myport);
        exit(-1);
    }
    //if ( (retstr= basilisk_swapentry(0,0)) != 0 )
    //    free(retstr);
    int32_t nonz;
    printf("start mainloop\n");
    while ( 1 )
    {
        nonz = 0;
        G.waiting = 1;
        while ( G.initializing != 0 )
        {
            fprintf(stderr,".");
            sleep(3);
        }
        if ( LP_mainloop_iter(ctx,myipaddr,mypeer,pubsock,pushaddr,myport) != 0 )
            nonz++;
        if ( nonz == 0 )
            usleep(10000);
        else if ( IAMLP != 0 )
            usleep(1000);
        else usleep(10000);
    }
}



