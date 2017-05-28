
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
//  LP_commands.c
//  marketmaker
//

struct basilisk_request *LP_requestinit(struct basilisk_request *rp,bits256 srchash,bits256 desthash,char *src,uint64_t srcsatoshis,char *dest,uint64_t destsatoshis,uint32_t timestamp,uint32_t quotetime,int32_t DEXselector)
{
    memset(rp,0,sizeof(*rp));
    rp->srchash = srchash;
    rp->desthash = desthash;
    rp->srcamount = srcsatoshis;
    rp->destamount = destsatoshis;
    rp->timestamp = timestamp;
    rp->quotetime = quotetime;
    rp->DEXselector = DEXselector;
    safecopy(rp->src,src,sizeof(rp->src));
    safecopy(rp->dest,dest,sizeof(rp->dest));
    rp->quoteid = basilisk_quoteid(rp);
    rp->requestid = basilisk_requestid(rp);
    return(rp);
}

void LP_command(struct LP_peerinfo *mypeer,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen,double profitmargin)
{
    char *method,*base,*rel,*retstr,*pairstr; cJSON *retjson; double price; bits256 srchash,desthash,pubkey,privkey,txid,desttxid; struct LP_utxoinfo *utxo; uint32_t timestamp,quotetime; int32_t destvout,DEXselector = 0; uint64_t txfee,satoshis,desttxfee,destsatoshis,value; struct basilisk_request R;
    if ( (method= jstr(argjson,"method")) != 0 )
    {
        txid = jbits256(argjson,"txid");
        if ( (utxo= LP_utxofind(txid,jint(argjson,"vout"))) != 0 && strcmp(utxo->ipaddr,mypeer->ipaddr) == 0 && utxo->port == mypeer->port && (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 && strcmp(base,utxo->coin) == 0 )
        {
            if ( time(NULL) > utxo->swappending )
                utxo->swappending = 0;
            if ( strcmp(method,"price") == 0 || strcmp(method,"request") == 0 )
            {
                if ( utxo->swappending == 0 && utxo->pair < 0 )
                {
                    if ( utxo->pair >= 0 )
                        nn_close(utxo->pair), utxo->pair = -1;
                    if ( (price= LP_price(base,rel)) != 0. )
                    {
                        price *= (1. + profitmargin);
                        retjson = cJSON_CreateObject();
                        jaddstr(retjson,"base",base);
                        jaddstr(retjson,"rel",rel);
                        jaddnum(retjson,"timestamp",time(NULL));
                        jaddnum(retjson,"price",price);
                        jaddbits256(retjson,"txid",txid);
                        pubkey = LP_pubkey(LP_privkey(utxo->coinaddr));
                        jaddbits256(retjson,"srchash",pubkey);
                        txfee = LP_txfee(base);
                        jadd64bits(retjson,"txfee",txfee);
                        jadd64bits(retjson,"satoshis",utxo->satoshis - txfee);
                        jadd64bits(retjson,"destsatoshis",price * (utxo->satoshis-txfee));
                        if ( strcmp(method,"request") == 0 )
                        {
                            utxo->swappending = (uint32_t)(time(NULL) + 60);
                            utxo->otherpubkey = jbits256(argjson,"pubkey");
                            jaddstr(retjson,"result","reserved");
                            jaddnum(retjson,"pending",utxo->swappending);
                        }
                        retstr = jprint(retjson,1);
                        LP_send(pubsock,retstr,1);
                    }
                }
            }
            else if ( strcmp(method,"connect") == 0 )
            {
                if ( utxo->pair < 0 )
                {
                    if ( (price= LP_price(base,rel)) != 0. )
                    {
                        price *= (1. + profitmargin);
                        txfee = LP_txfee(base);
                        satoshis = j64bits(argjson,"satoshis");
                        desttxfee = LP_txfee(rel);
                        desttxid = jbits256(argjson,"desttxid");
                        destvout = jint(argjson,"destvout");
                        timestamp = juint(argjson,"timestamp");
                        quotetime = juint(argjson,"quotetime");
                        privkey = LP_privkey(utxo->coinaddr);
                        pubkey = LP_pubkey(privkey);
                        srchash = jbits256(argjson,"srchash");
                        value = j64bits(argjson,"destsatoshis");
                        if ( timestamp == utxo->swappending-60 && quotetime >= timestamp && quotetime < utxo->swappending && bits256_cmp(pubkey,srchash) == 0 && (destsatoshis= LP_txvalue(rel,desttxid,destvout)) > price*(utxo->satoshis-txfee)+desttxfee && value <= destsatoshis-desttxfee )
                        {
                            destsatoshis = value;
                            if ( (utxo->pair= nn_socket(AF_SP,NN_PAIR)) < 0 )
                                printf("error creating utxo->pair\n");
                            else if ( (pairstr= jstr(argjson,"pair")) != 0 && nn_connect(utxo->pair,pairstr) >= 0 )
                            {
                                desthash = jbits256(argjson,"desthash");
                                LP_requestinit(&R,srchash,desthash,base,satoshis,rel,destsatoshis,timestamp,quotetime,DEXselector);
                                if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_bobloop,(void *)utxo) != 0 )
                                {
                                    retjson = cJSON_CreateObject();
                                    jaddstr(retjson,"result","connected");
                                    jaddnum(retjson,"requestid",R.requestid);
                                    jaddnum(retjson,"quoteid",R.quoteid);
                                    retstr = jprint(retjson,1);
                                    LP_send(pubsock,retstr,1);
                                    utxo->swap = LP_swapinit(1,0,privkey,&R);
                                }
                                else
                                {
                                    printf("error launching swaploop\n");
                                    free(utxo->swap);
                                    utxo->swap = 0;
                                    nn_close(utxo->pair);
                                    utxo->pair = -1;
                                }
                            }
                            else
                            {
                                if ( pairstr != 0 )
                                    printf("printf error nn_connect to %s\n",pairstr);
                                else printf("(%s) missing pair\n",jprint(argjson,0));
                                nn_close(utxo->pair);
                                utxo->pair = -1;
                            }
                        } else printf("dest %.8f < required %.8f\n",dstr(value),dstr(price*(utxo->satoshis-txfee)));
                    } else printf("no price for %s/%s\n",base,rel);
                } else printf("utxo->pair.%d when connect came in (%s)\n",utxo->pair,jprint(argjson,0));
            }
        }
    }
}

char *stats_JSON(cJSON *argjson,char *remoteaddr,uint16_t port) // from rpc port
{
    char *method,*ipaddr,*coin,*retstr = 0; uint16_t argport,pushport,subport; int32_t otherpeers,othernumutxos; struct LP_peerinfo *peer; cJSON *retjson;
    if ( (method= jstr(argjson,"method")) == 0 )
        return(clonestr("{\"error\":\"need method in request\"}"));
    else
    {
        if ( (ipaddr= jstr(argjson,"ipaddr")) != 0 && (argport= juint(argjson,"port")) != 0 )
        {
            if ( (pushport= juint(argjson,"push")) == 0 )
                pushport = argport + 1;
            if ( (subport= juint(argjson,"sub")) == 0 )
                subport = argport + 2;
            if ( (peer= LP_peerfind((uint32_t)calc_ipbits(ipaddr),argport)) != 0 )
            {
                if ( (otherpeers= jint(argjson,"numpeers")) > peer->numpeers )
                    peer->numpeers = otherpeers;
                if ( (othernumutxos= jint(argjson,"numutxos")) > peer->numutxos )
                {
                    printf("change.(%s) numutxos.%d -> %d mynumutxos.%d\n",peer->ipaddr,peer->numutxos,othernumutxos,LP_mypeer->numutxos);
                    peer->numutxos = othernumutxos;
                }
                //printf("peer.(%s) found (%d %d) (%d %d) (%s)\n",peer->ipaddr,peer->numpeers,peer->numutxos,otherpeers,othernumutxos,jprint(argjson,0));
            } else LP_addpeer(LP_mypeer,LP_mypubsock,ipaddr,argport,pushport,subport,jdouble(argjson,"profit"),jint(argjson,"numpeers"),jint(argjson,"numutxos"));
            if ( strcmp(method,"getpeers") == 0 )
                retstr = LP_peers();
            else if ( strcmp(method,"getutxos") == 0 && (coin= jstr(argjson,"coin")) != 0 )
                retstr = LP_utxos(LP_mypeer,coin,jint(argjson,"lastn"));
            else if ( strcmp(method,"notify") == 0 )
                retstr = clonestr("{\"result\":\"success\",\"notify\":\"received\"}");
            else if ( strcmp(method,"notifyutxo") == 0 )
            {
                printf("utxonotify.(%s)\n",jprint(argjson,0));
                LP_addutxo(LP_mypeer,LP_mypubsock,jstr(argjson,"coin"),jbits256(argjson,"txid"),jint(argjson,"vout"),SATOSHIDEN * jdouble(argjson,"value"),jbits256(argjson,"deposit"),jint(argjson,"dvout"),SATOSHIDEN * jdouble(argjson,"dvalue"),jstr(argjson,"script"),jstr(argjson,"address"),ipaddr,argport,jdouble(argjson,"profit"));
                retstr = clonestr("{\"result\":\"success\",\"notifyutxo\":\"received\"}");
            }
        } else printf("malformed request.(%s)\n",jprint(argjson,0));
    }
    if ( retstr != 0 )
        return(retstr);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"error","unrecognized command");
    return(clonestr(jprint(retjson,1)));
}
