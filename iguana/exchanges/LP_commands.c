
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

void LP_command(struct LP_peerinfo *mypeer,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen,double profitmargin)
{
    char *method,*base,*rel,*retstr; cJSON *retjson; double price; bits256 txid; struct LP_utxoinfo *utxo;
    if ( (method= jstr(argjson,"method")) != 0 )
    {
        if ( strcmp(method,"price") == 0 || strcmp(method,"request") == 0 )
        {
            txid = jbits256(argjson,"txid");
            if ( (utxo= LP_utxofind(txid)) != 0 && strcmp(utxo->ipaddr,mypeer->ipaddr) == 0 && utxo->port == mypeer->port && utxo->swappending == 0 )
            {
                if ( (base= jstr(argjson,"base")) != 0 && (rel= jstr(argjson,"rel")) != 0 && strcmp(base,utxo->coin) == 0 )
                {
                    if ( (price= LP_price(base,rel)) != 0. )
                    {
                        price *= (1. + profitmargin);
                        retjson = cJSON_CreateObject();
                        jaddstr(retjson,"base",base);
                        jaddstr(retjson,"rel",rel);
                        jaddnum(retjson,"timestamp",time(NULL));
                        jaddnum(retjson,"price",price);
                        jaddbits256(retjson,"txid",txid);
                        jadd64bits(retjson,"destsatoshis",price * utxo->satoshis);
                        if ( strcmp(method,"request") == 0 )
                        {
                            utxo->swappending = (uint32_t)(time(NULL) + 60);
                            utxo->otherpubkey = jbits256(argjson,"pubkey");
                            jaddnum(retjson,"pending",utxo->swappending);
                        }
                        retstr = jprint(retjson,1);
                        LP_send(pubsock,retstr,1);
                    }
                }
            }
        }
        else if (  )
        {
            
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
