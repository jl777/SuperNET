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

#include "iguana777.h"

char *iguana_APIrequest(struct iguana_info *coin,bits256 blockhash,bits256 txid,int32_t seconds)
{
    int32_t i,len; char *retstr = 0; uint8_t serialized[1024]; char str[65];
    coin->APIblockhash = blockhash;
    coin->APItxid = txid;
    printf("request block.(%s) txid.%llx\n",bits256_str(str,blockhash),(long long)txid.txid);
    if ( (len= iguana_getdata(coin,serialized,MSG_BLOCK,&blockhash,1)) > 0 )
    {
        for (i=0; i<seconds; i++)
        {
            if ( i == 0 )
                iguana_send(coin,0,serialized,len);
            if ( coin->APIblockstr != 0 )
            {
                retstr = coin->APIblockstr;
                coin->APIblockstr = 0;
                memset(&coin->APIblockhash,0,sizeof(coin->APIblockhash));
                memset(&coin->APItxid,0,sizeof(coin->APItxid));
                return(retstr);
            }
            sleep(1);
        }
    }
    return(0);
}

bits256 iguana_str2priv(struct supernet_info *myinfo,struct iguana_info *coin,char *str)
{
    bits256 privkey; int32_t n; uint8_t addrtype; struct iguana_waccount *wacct=0; struct iguana_waddress *waddr;
    memset(&privkey,0,sizeof(privkey));
    if ( str != 0 )
    {
        n = (int32_t)strlen(str) >> 1;
        if ( n == sizeof(bits256) && is_hexstr(str,sizeof(bits256)) > 0 )
            decode_hex(privkey.bytes,sizeof(privkey),str);
        else if ( bitcoin_wif2priv(&addrtype,&privkey,str) != sizeof(bits256) )
        {
            if ( (waddr= iguana_waddresssearch(myinfo,coin,&wacct,str)) != 0 )
                privkey = waddr->privkey;
            else memset(privkey.bytes,0,sizeof(privkey));
        }
    }
    return(privkey);
}

int32_t iguana_pubkeyget(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *pubkey33,char *str)
{
    bits256 privkey,pubkey; uint8_t pubkeydata[128]; int32_t len,plen= -1; struct iguana_waccount *wacct; struct iguana_waddress *waddr;
    len = (int32_t)strlen(str);
    if ( is_hexstr(str,len) == 0 )
    {
        if ( (waddr= iguana_waddresssearch(myinfo,coin,&wacct,str)) != 0 )
        {
            if ( (plen= bitcoin_pubkeylen(waddr->pubkey)) > 0 )
                memcpy(pubkeydata,waddr->pubkey,plen);
        }
    }
    else
    {
        decode_hex(pubkeydata,len,str);
        plen = bitcoin_pubkeylen(pubkeydata);
    }
    if ( plen <= 0 )
    {
        privkey = iguana_str2priv(myinfo,coin,str);
        if ( bits256_nonz(privkey) == 0 )
            return(-1);
        else
        {
            pubkey = bitcoin_pubkey33(myinfo->ctx,pubkeydata,privkey);
            if ( bits256_nonz(pubkey) == 0 )
                return(-1);
        }
    }
    if ( (plen= bitcoin_pubkeylen(pubkeydata)) > 0 )
        memcpy(pubkey33,pubkeydata,plen);
    return(0);
}

cJSON *iguana_p2shjson(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *retjson,struct iguana_waddress *waddr)
{
    char str[4096]; uint8_t type; struct iguana_waccount *wacct; bits256 debugtxid; struct vin_info V; cJSON *privkeys,*pubkeys,*addresses; int32_t i,plen;
    if ( retjson == 0 )
        retjson = cJSON_CreateObject();
    init_hexbytes_noT(str,waddr->redeemScript,waddr->scriptlen);
    jaddstr(retjson,"redeemScript",str);
    memset(debugtxid.bytes,0,sizeof(debugtxid));
    if ( (type= iguana_calcrmd160(coin,0,&V,waddr->redeemScript,waddr->scriptlen, debugtxid,-1,0xffffffff)) >= 0 )
    {
        privkeys = cJSON_CreateArray();
        pubkeys = cJSON_CreateArray();
        addresses = cJSON_CreateArray();
        for (i=0; i<V.N; i++)
        {
            if ( V.signers[i].coinaddr[0] != 0 && (waddr= iguana_waddresssearch(myinfo,coin,&wacct,V.signers[i].coinaddr)) != 0 && waddr->wifstr[0] != 0 )
                jaddistr(privkeys,waddr->wifstr);
            else jaddistr(privkeys,"");
            if ( (plen= bitcoin_pubkeylen(V.signers[i].pubkey)) > 0 )
            {
                init_hexbytes_noT(str,V.signers[i].pubkey,plen);
                jaddistr(pubkeys,str);
            } else jaddistr(pubkeys,"");
            jaddistr(addresses,V.signers[i].coinaddr);
        }
        jaddstr(retjson,"result",V.coinaddr);
        jaddnum(retjson,"M",V.M);
        jaddnum(retjson,"N",V.N);
        jadd(retjson,"pubkeys",pubkeys);
        jadd(retjson,"privkeys",privkeys);
        jadd(retjson,"addresses",addresses);
    }
    return(retjson);
}

cJSON *iguana_scriptobj(struct iguana_info *coin,uint8_t rmd160[20],char *coinaddr,char *asmstr,uint8_t *script,int32_t scriptlen)
{
    struct vin_info V; int32_t i,plen,asmtype; char pubkeystr[130],rmdstr[41]; cJSON *addrobj,*scriptobj=cJSON_CreateObject();
    if ( (asmtype= iguana_calcrmd160(coin,asmstr,&V,script,scriptlen,rand256(0),1,0xffffffff)) >= 0 )
    {
        if ( asmstr != 0 && asmstr[0] != 0 )
            jaddstr(scriptobj,"asm",asmstr);
        jaddnum(scriptobj,"iguanatype",asmtype);
        jaddnum(scriptobj,"scriptlen",scriptlen);
        jaddnum(scriptobj,"reqSigs",V.M);
        if ( (plen= bitcoin_pubkeylen(V.signers[0].pubkey)) > 0 )
        {
            init_hexbytes_noT(pubkeystr,V.signers[0].pubkey,plen);
            jaddstr(scriptobj,"pubkey",pubkeystr);
            init_hexbytes_noT(rmdstr,V.signers[0].rmd160,20);
            jaddstr(scriptobj,"rmd160",rmdstr);
        }
        addrobj = cJSON_CreateArray();
        for (i=0; i<V.N; i++)
            jaddistr(addrobj,V.signers[i].coinaddr);
        jadd(scriptobj,"addresses",addrobj);
        if ( V.p2shlen != 0 )
            jaddstr(scriptobj,"p2sh",V.coinaddr);
        strcpy(coinaddr,V.coinaddr);
        memcpy(rmd160,V.rmd160,20);
    }
    return(scriptobj);
}

int32_t iguana_bestunspent(struct iguana_info *coin,int32_t *aboveip,int64_t *abovep,int32_t *belowip,int64_t *belowp,uint64_t *unspents,int32_t numunspents,uint64_t value)
{
    int32_t i,abovei,belowi; int64_t above,below,gap,atx_value;
    abovei = belowi = -1;
    for (above=below=i=0; i<numunspents; i++)
    {
        if ( (atx_value= unspents[(i << 1) + 1]) <= 0 )
            continue;
        //printf("(%.8f vs %.8f)\n",dstr(atx_value),dstr(value));
        if ( atx_value == value )
        {
            *aboveip = *belowip = i;
            *abovep = *belowp = 0;
            return(i);
        }
        else if ( atx_value > value )
        {
            gap = (atx_value - value);
            if ( above == 0 || gap < above )
            {
                above = gap;
                abovei = i;
            }
        }
        gap = (value - atx_value);
        if ( below == 0 || gap < below )
        {
            below = gap;
            belowi = i;
        }
    }
    *aboveip = abovei;
    *abovep = above;
    *belowip = belowi;
    *belowp = below;
    return(abovei >= 0 ? abovei : belowi);
}

cJSON *iguana_inputsjson(struct supernet_info *myinfo,struct iguana_info *coin,int64_t *totalp,uint64_t amount,uint64_t *unspents,int32_t num)
{
    cJSON *item,*vins; uint8_t spendscript[IGUANA_MAXSCRIPTSIZE]; struct iguana_txid *T; struct iguana_unspent *U,*u; struct iguana_bundle *bp; struct iguana_ramchain *ramchain; char coinaddr[64],hexstr[IGUANA_MAXSCRIPTSIZE*2+1]; int32_t height,abovei,belowi,i,spendlen,ind,hdrsi; uint32_t txidind,unspentind; int64_t value,above,below,total = 0; int64_t remains = amount;
    *totalp = 0;
    vins = cJSON_CreateArray();
    for (i=0; i<num; i++)
    {
        below = above = 0;
        if ( iguana_bestunspent(coin,&abovei,&above,&belowi,&below,unspents,num,remains) < 0 )
        {
            printf("error finding unspent i.%d of %d, %.8f vs %.8f\n",i,num,dstr(remains),dstr(amount));
            free_json(vins);
            return(0);
        }
        if ( belowi < 0 || (num == 0 && abovei >= 0) )
            ind = abovei;
        else ind = belowi;
        hdrsi = (int16_t)(unspents[(ind << 1)] >> 32);
        unspentind = (uint32_t)unspents[(ind << 1)];
        value = unspents[(ind << 1) + 1];
        unspents[(ind << 1) + 1] = -1;
        if ( (bp= coin->bundles[hdrsi]) == 0 )
        {
            printf("no bundle.[%d]\n",hdrsi);
            free_json(vins);
            return(0);
        }
        ramchain = &bp->ramchain;
        U = RAMCHAIN_PTR(ramchain->H.data,Uoffset);
        T = RAMCHAIN_PTR(ramchain->H.data,Toffset);
        if ( unspentind > 0 && unspentind < ramchain->H.data->numunspents )
        {
            u = &U[unspentind];
            if ( (txidind= u->txidind) > 0 && txidind < ramchain->H.data->numtxids )
            {
                if ( iguana_unspentindfind(coin,coinaddr,spendscript,&spendlen,&amount,&height,T[txidind].txid,u->vout,coin->bundlescount-1) == unspentind && spendlen > 0 )
                {
                    init_hexbytes_noT(hexstr,spendscript,spendlen);
                    item = cJSON_CreateObject();
                    jaddbits256(item,"txid",T[txidind].txid);
                    jaddnum(item,"vout",u->vout);
                    jaddstr(item,"scriptPubKey",hexstr);
                    jaddi(vins,item);
                    total += value;
                    remains -= value;
                    printf("value %.8f -> remains %.8f\n",dstr(value),dstr(remains));
                    if ( remains <= 0 )
                        break;
                }
                else
                {
                    char str[65];printf("couldnt get script for %s.%d\n",bits256_str(str,T[txidind].txid),u->vout);
                    free_json(vins);
                    return(0);
                }
            }
            else
            {
                printf("illegal txidind.%d [%d]\n",txidind,hdrsi);
                free_json(vins);
                return(0);
            }
        }
        else
        {
            printf("illegal unspentind.u%d [%d]\n",unspentind,hdrsi);
            free_json(vins);
            return(0);
        }
    }
    *totalp = total;
    return(vins);
}

char *iguana_signunspents(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *completedp,char *coinaddr,uint64_t satoshis,char *changeaddr,uint64_t txfee,uint64_t *unspents,int32_t num)
{
    uint8_t addrtype,rmd160[20],spendscript[IGUANA_MAXSCRIPTSIZE]; uint32_t locktime = 0; int32_t spendlen,numinputs,i,RTspentflag; struct iguana_msgtx msgtx; char *rawtx=0,*signedtx = 0; bits256 txid,signedtxid; cJSON *txobj,*vins=0,*privkeys=0; struct vin_info *V; int64_t value,total,change; char changeaddress[64]; struct iguana_waddress *waddr;
    *completedp = 0;
    if ( (vins= iguana_inputsjson(myinfo,coin,&total,satoshis + txfee,unspents,num)) != 0 )
    {
        if ( total < (satoshis + txfee) )
        {
            free_json(vins);
            printf("insufficient total %.8f vs (%.8f + %.8f)\n",dstr(total),dstr(satoshis),dstr(txfee));
            return(0);
        }
        if ( (change= (total - (satoshis + txfee))) > 0 )
        {
            if ( changeaddr == 0 || changeaddr[0] == 0 )
            {
                if ( (waddr= iguana_getaccountaddress(myinfo,coin,0,0,changeaddress,"change")) == 0 )
                {
                    free_json(vins);
                    return(0);
                }
                strcpy(changeaddress,waddr->coinaddr);
                changeaddr = changeaddress;
            }
        }
        if ( (privkeys= iguana_privkeysjson(myinfo,coin,vins)) != 0 )
        {
            if ( (txobj= bitcoin_txcreate(coin,locktime)) != 0 )
            {
                iguana_createvins(myinfo,coin,txobj,vins);
                if ( iguana_addressvalidate(coin,&addrtype,rmd160,coinaddr) < 0 )
                {
                    free_json(vins), free_json(privkeys), free_json(txobj);
                    printf("illegal destination address.(%s)\n",coinaddr);
                    return(0);
                }
                spendlen = bitcoin_standardspend(spendscript,0,rmd160);
                bitcoin_txoutput(coin,txobj,spendscript,spendlen,satoshis);
                if ( change > 0 )
                {
                    if ( iguana_addressvalidate(coin,&addrtype,rmd160,changeaddr) < 0 )
                    {
                        free_json(vins), free_json(privkeys), free_json(txobj);
                        printf("illegal destination address.(%s)\n",changeaddr);
                        return(0);
                    }
                    spendlen = bitcoin_standardspend(spendscript,0,rmd160);
                    bitcoin_txoutput(coin,txobj,spendscript,spendlen,change);
                }
                if ( (rawtx= bitcoin_json2hex(myinfo,coin,&txid,txobj,0)) != 0 )
                {
                    if ( (numinputs= cJSON_GetArraySize(vins)) > 0 && (V= calloc(numinputs,sizeof(*V))) != 0 )
                    {
                        memset(&msgtx,0,sizeof(msgtx));
                        if ( iguana_signrawtransaction(myinfo,coin,&msgtx,&signedtx,&signedtxid,V,numinputs,rawtx,vins,privkeys) > 0 )
                        {
                            for (i=0; i<num; i++)
                            {
                                value = unspents[(i << 1) + 1];
                                if ( value == -1 )
                                    iguana_utxofind(coin,(int32_t)(unspents[i << 1] >> 32),(uint32_t)unspents[i << 1],&RTspentflag,1);
                            }
                            *completedp = 1;
                        }
                        else printf("signrawtransaction incomplete\n");
                        free(V);
                    }
                    free(rawtx);
                }
                free_json(txobj);
            }
            free_json(privkeys);
        }
        free_json(vins);
    }
    return(signedtx);
}

char *sendtoaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,uint64_t satoshis,uint64_t txfee,char *comment,char *comment2,int32_t minconf,char *account)
{
    uint8_t addrtype,rmd160[20]; int32_t i,j,num,completed,numwaddrs; struct iguana_waddress **waddrs,*waddr; uint64_t *unspents,value,avail=0; char *signedtx = 0; cJSON *retjson;
    //sendtoaddress	<bitcoinaddress> <amount> [comment] [comment-to]	<amount> is a real and is rounded to 8 decimal places. Returns the transaction ID <txid> if successful.	Y
    if ( coinaddr != 0 && coinaddr[0] != 0 && satoshis != 0 )
    {
        if ( iguana_addressvalidate(coin,&addrtype,rmd160,coinaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        waddrs = (struct iguana_waddress **)coin->blockspace;
        numwaddrs = iguana_unspentslists(myinfo,coin,waddrs,(int32_t)(sizeof(coin->blockspace)/sizeof(*waddrs)),(uint64_t)1 << 62,minconf,account);
        if ( numwaddrs > 0 )
        {
            unspents = (uint64_t *)((long)coin->blockspace + sizeof(*waddrs)*numwaddrs);
            for (i=num=0; i<numwaddrs; i++)
            {
                if ( (waddr= waddrs[i]) != 0 && waddr->numunspents > 0 )
                {
                    for (j=0; j<waddr->numunspents; j++)
                    {
                        if ( (value= iguana_unspentavail(coin,waddr->unspents[j],minconf,coin->longestchain)) != 0 )
                        {
                            unspents[num << 1] = waddr->unspents[j];
                            unspents[(num << 1) + 1] = value;
                            num++;
                            avail += value;
                            printf("([%d].u%u) ",(uint32_t)(waddr->unspents[j]>>32),(uint32_t)waddr->unspents[j]);
                        }
                    }
                    printf("(%s %.8f)\n",waddr->coinaddr,dstr(waddr->balance));
                }
            }
            if ( avail < satoshis+txfee )
                return(clonestr("{\"error\":\"not enough funds\"}"));
            else if ( (signedtx= iguana_signunspents(myinfo,coin,&completed,coinaddr,satoshis,coin->changeaddr,txfee,unspents,num)) != 0 )
            {
                retjson = cJSON_CreateObject();
                jaddstr(retjson,"result",signedtx);
                jadd(retjson,"complete",completed != 0 ? jtrue() : jfalse());
                free(signedtx);
                return(jprint(retjson,1));
            } else return(clonestr("{\"error\":\"couldnt create signedtx\"}"));
        } else return(clonestr("{\"error\":\"no funded wallet addresses\"}"));
    }
    return(clonestr("{\"error\":\"need address and amount\"}"));
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

STRING_AND_INT(bitcoinrpc,sendrawtransaction,rawtx,allowhighfees)
{
    cJSON *retjson = cJSON_CreateObject(); char txidstr[65]; bits256 txid; uint8_t *serialized; struct iguana_peer *addr; int32_t i,len = (int32_t)strlen(rawtx) >> 1;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( coin->peers.numranked >= 8 )
    {
        serialized = calloc(1,sizeof(struct iguana_msghdr) + len);
        decode_hex(&serialized[sizeof(struct iguana_msghdr)],len,rawtx);
        for (i=0; i<8; i++)
        {
            if ( (addr= coin->peers.ranked[i]) != 0 && addr->dead == 0 && addr->usock >= 0 )
                iguana_queue_send(coin,addr,0,serialized,"tx",len,0,0);
        }
        free(serialized);
        txid = bits256_doublesha256(txidstr,&serialized[sizeof(struct iguana_msghdr)],len);
        jaddstr(retjson,"result",txidstr);
    } else jaddstr(retjson,"error","no peers");
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,submitblock,rawbytes)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    cJSON *retjson = cJSON_CreateObject();
    // send to all peers
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,makekeypair)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    bits256 privkey; char str[67]; cJSON *retjson = cJSON_CreateObject();
    privkey = rand256(1);
    jaddstr(retjson,"result","success");
    jaddstr(retjson,"privkey",bits256_str(str,privkey));
    jadd(retjson,"rosetta",SuperNET_rosettajson(privkey,1));
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,validatepubkey,pubkeystr)
{
    uint8_t rmd160[20],pubkey[65],addrtype = 0; int32_t plen; char coinaddr[128],*str; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    plen = (int32_t)strlen(pubkeystr) >> 1;
    if ( plen >= 33 && plen <= 65 && coin != 0 && coin->chain != 0 )
    {
        addrtype = coin->chain->pubtype;
        decode_hex(pubkey,plen,pubkeystr);
        if ( (str= bitcoin_address(coinaddr,addrtype,pubkey,plen)) != 0 )
        {
            if ( iguana_addressvalidate(coin,&addrtype,rmd160,coinaddr) < 0 )
                return(clonestr("{\"error\":\"invalid coin address\"}"));
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"result","success");
            jaddstr(retjson,"pubkey",pubkeystr);
            jaddstr(retjson,"address",coinaddr);
            jaddstr(retjson,"coin",coin->symbol);
            return(jprint(retjson,1));
        }
    }
    return(clonestr("{\"error\":\"invalid pubkey\"}"));
}

STRING_ARG(bitcoinrpc,decodescript,scriptstr)
{
    int32_t scriptlen; uint8_t script[IGUANA_MAXSCRIPTSIZE],rmd160[20]; char coinaddr[128],asmstr[IGUANA_MAXSCRIPTSIZE*2+1]; cJSON *scriptobj,*retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( scriptstr != 0 && coin != 0 && (scriptlen= (int32_t)strlen(scriptstr)>>1) < sizeof(script) )
    {
        decode_hex(script,scriptlen,scriptstr);
        if ( (scriptobj= iguana_scriptobj(coin,rmd160,coinaddr,asmstr,script,scriptlen)) != 0 )
            jadd(retjson,"result",scriptobj);
    }
    return(jprint(retjson,1));
}

INT_ARRAY_STRING(bitcoinrpc,createmultisig,M,pubkeys,ignore)
{
    cJSON *retjson,*pkjson,*addresses; uint8_t script[2048],p2sh_rmd160[20]; char pubkeystr[256],msigaddr[64],*pkstr,scriptstr[sizeof(script)*2+1]; struct vin_info V; int32_t i,plen,len,n = cJSON_GetArraySize(pubkeys);
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( n < 0 || n > 16 || M < 0 || M > n )
        return(clonestr("{\"error\":\"illegal number of pubkeys\"}"));
    memset(&V,0,sizeof(V));
    V.M = M, V.N = n;
    pkjson = cJSON_CreateArray();
    addresses = cJSON_CreateArray();
    for (i=0; i<n; i++)
    {
        if ( (pkstr= jstr(jitem(pubkeys,i),0)) != 0 )
        {
            if ( iguana_pubkeyget(myinfo,coin,V.signers[i].pubkey,pkstr) < 0 )
                break;
            if ( (plen= bitcoin_pubkeylen(V.signers[i].pubkey)) <= 0 )
                break;
            bitcoin_address(V.signers[i].coinaddr,coin->chain->pubtype,V.signers[i].pubkey,plen);
            jaddistr(addresses,V.signers[i].coinaddr);
            init_hexbytes_noT(pubkeystr,V.signers[i].pubkey,plen);
            jaddistr(pkjson,pubkeystr);
        } else break;
    }
    retjson = cJSON_CreateObject();
    if ( i == n )
    {
        len = bitcoin_MofNspendscript(p2sh_rmd160,script,0,&V);
        bitcoin_address(msigaddr,coin->chain->p2shtype,p2sh_rmd160,sizeof(p2sh_rmd160));
        jaddstr(retjson,"result","success");
        jaddstr(retjson,"address",msigaddr);
        init_hexbytes_noT(scriptstr,script,len);
        jaddstr(retjson,"redeemScript",scriptstr);
        jaddnum(retjson,"M",M);
        jaddnum(retjson,"N",n);
        jadd(retjson,"pubkeys",pkjson);
        jadd(retjson,"addresses",addresses);
    }
    else
    {
        jaddstr(retjson,"error","couldnt get all pubkeys");
        free_json(pkjson);
    }
    return(jprint(retjson,1));
}

INT_ARRAY_STRING(bitcoinrpc,addmultisigaddress,M,pubkeys,account) //
{
    cJSON *retjson,*tmpjson,*setjson=0; char *retstr,*str=0,*msigaddr,*redeemScript;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    if ( (retstr= bitcoinrpc_createmultisig(IGUANA_CALLARGS,M,pubkeys,account)) != 0 )
    {
        //printf("CREATEMULTISIG.(%s)\n",retstr);
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (msigaddr= jstr(retjson,"address")) != 0 )
            {
                if ( (redeemScript= jstr(retjson,"redeemScript")) == 0 || (str= setaccount(myinfo,coin,0,account,msigaddr,redeemScript)) == 0 || (setjson= cJSON_Parse(str)) == 0 || jobj(setjson,"error") != 0 )
                {
                    if ( jobj(retjson,"result") != 0 )
                        jdelete(retjson,"result");
                    if ( jobj(retjson,"error") == 0 )
                        jaddstr(retjson,"error","couldnt add multisig address to account");
                }
                else
                {
                    tmpjson = cJSON_CreateObject();
                    jaddstr(tmpjson,"result",msigaddr);
                    free_json(retjson);
                    free(retstr);
                    retjson = tmpjson;
                }
            }
            if ( setjson != 0 )
                free_json(setjson);
            if ( str != 0 )
                free(str);
            return(jprint(retjson,1));
        } else return(clonestr("{\"error\":\"couldnt parse retstr from createmultisig\"}"));
    } else return(clonestr("{\"error\":\"no retstr from createmultisig\"}"));
}

HASH_AND_TWOINTS(bitcoinrpc,gettxout,txid,vout,mempool)
{
    uint8_t script[IGUANA_MAXSCRIPTSIZE],rmd160[20],pubkey33[33]; char coinaddr[128],asmstr[IGUANA_MAXSCRIPTSIZE*2+1]; struct iguana_bundle *bp; int32_t minconf,scriptlen,unspentind,height,spentheight; int64_t RTspend; struct iguana_ramchaindata *rdata; struct iguana_pkhash *P; struct iguana_txid *T; struct iguana_unspent *U; struct iguana_ramchain *ramchain; cJSON *scriptobj,*retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( coin != 0 )
    {
        minconf = (mempool != 0) ? 0 : 1;
        if ( (unspentind= iguana_unspentindfind(coin,0,0,0,0,&height,txid,vout,coin->bundlescount-1)) != 0 )
        {
            if ( height >= 0 && height < coin->longestchain && (bp= coin->bundles[height / coin->chain->bundlesize]) != 0 )
            {
                ramchain = &bp->ramchain;
                if ( (rdata= ramchain->H.data) != 0 )
                {
                    U = RAMCHAIN_PTR(rdata,Uoffset);
                    P = RAMCHAIN_PTR(rdata,Poffset);
                    T = RAMCHAIN_PTR(rdata,Toffset);
                    //U = (void *)(long)((long)rdata + rdata->Uoffset);
                    //P = (void *)(long)((long)rdata + rdata->Poffset);
                    //T = (void *)(long)((long)rdata + rdata->Toffset);
                    RTspend = 0;
                    if ( iguana_spentflag(coin,&RTspend,&spentheight,ramchain,bp->hdrsi,unspentind,height,minconf,coin->longestchain,U[unspentind].value) == 0 )
                    {
                        jaddbits256(retjson,"bestblock",coin->blocks.hwmchain.RO.hash2);
                        jaddnum(retjson,"bestheight",coin->blocks.hwmchain.height);
                        jaddnum(retjson,"height",height);
                        jaddnum(retjson,"confirmations",coin->blocks.hwmchain.height - height + 1);
                        jaddnum(retjson,"value",dstr(U[unspentind].value));
                        memset(rmd160,0,sizeof(rmd160));
                        memset(pubkey33,0,sizeof(pubkey33));
                        memset(coinaddr,0,sizeof(coinaddr));
                        if ( (scriptlen= iguana_voutscript(coin,bp,script,0,&U[unspentind],&P[U[unspentind].pkind],vout)) > 0 )
                        {
                            if ( (scriptobj= iguana_scriptobj(coin,rmd160,coinaddr,asmstr,script,scriptlen)) != 0 )
                                jadd(retjson,"scriptPubKey",scriptobj);
                        }
                        jadd(retjson,"iguana",iguana_unspentjson(myinfo,coin,bp->hdrsi,unspentind,T,&U[unspentind],rmd160,coinaddr,pubkey33));
                        if ( (height % coin->chain->bundlesize) == 0 && vout == 0 )
                            jadd(retjson,"coinbase",jtrue());
                        else jadd(retjson,"coinbase",jfalse());
                    }
                    else
                    {
                        jaddstr(retjson,"error","already spent");
                        jaddnum(retjson,"spentheight",spentheight);
                        jaddnum(retjson,"unspentind",unspentind);
                    }
                }
            }
        }
    }
    return(jprint(retjson,1));
}

bits256 iguana_messagehash2(char *message,char *messagemagic)
{
    int32_t n,len; uint8_t *messagebuf; bits256 hash2;
    n = (int32_t)strlen(message) >> 1;
    len = (int32_t)strlen(messagemagic);
    if ( message[0] == '0' && message[1] == 'x' && is_hexstr(message+2,n-2) > 0 )
    {
        messagebuf = malloc(n-2 + len);
        memcpy(messagebuf,messagemagic,len);
        decode_hex(messagebuf+len,n-2,message+2);
        n--;
    }
    else
    {
        n <<= 1;
        messagebuf = malloc(n + len + 1);
        memcpy(messagebuf,messagemagic,len);
        strcpy((void *)&messagebuf[len],message);
        //printf("MESSAGE.(%s)\n",(void *)messagebuf);
    }
    n += len;
    hash2 = bits256_doublesha256(0,messagebuf,n);
    //for (i=0; i<sizeof(hash2); i++)
    //    revhash2.bytes[i] = hash2.bytes[sizeof(hash2) - 1 - i];
    if ( messagebuf != (void *)message )
        free(messagebuf);
    return(hash2);
}

TWO_STRINGS(bitcoinrpc,signmessage,address,message)
{
    bits256 privkey,hash2; int32_t len,siglen; char sigstr[256],sig65str[256]; uint8_t sig[128]; cJSON *retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( coin != 0 )
    {
        privkey = iguana_str2priv(myinfo,coin,address);
        if ( bits256_nonz(privkey) != 0 )
        {
            hash2 = iguana_messagehash2(message,coin->chain->messagemagic);
            if ( (siglen= bitcoin_sign(coin->ctx,coin->symbol,sig,hash2,privkey,1)) > 0 )
            {
                sigstr[0] = sig65str[0] = 0;
                len = nn_base64_encode(sig,siglen,sig65str,sizeof(sig65str));
                sig65str[len] = 0;
                jaddstr(retjson,"result",sig65str);
            }
        } else jaddstr(retjson,"error","invalid address (can be wif, wallet address or privkey hex)");
    }
    return(jprint(retjson,1));
}

THREE_STRINGS(bitcoinrpc,verifymessage,address,sig,message)
{
    int32_t len,plen; uint8_t sigbuf[256],pubkey[65]; char str[4096]; bits256 hash2; cJSON *retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( strlen(sig) < sizeof(sigbuf)*8/6 )
    {
        len = (int32_t)strlen(sig);
        len = nn_base64_decode(sig,len,sigbuf,sizeof(sigbuf));
        //int32_t i; for (i=0; i<len; i++)
        //    printf("%02x",sigbuf[i]);
        //printf(" siglen.%d [%d] address.(%s) sig.(%s) message.(%s)\n",len,sigbuf[0],address,sig,message);
        hash2 = iguana_messagehash2(message,coin->chain->messagemagic);
        if ( bitcoin_recoververify(myinfo->ctx,coin->symbol,sigbuf,hash2,pubkey) == 0 )
            jadd(retjson,"result",jtrue());
        else jadd(retjson,"result",jfalse());
        jaddstr(retjson,"coin",coin->symbol);
        jaddstr(retjson,"address",address);
        jaddstr(retjson,"message",message);
        if ( (plen= bitcoin_pubkeylen(pubkey)) > 0 )
        {
            init_hexbytes_noT(str,pubkey,plen);
            jaddstr(retjson,"pubkey",str);
        }
        init_hexbytes_noT(str,sigbuf,len);
        jaddstr(retjson,"sighex",str);
        jaddbits256(retjson,"messagehash",hash2);
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"sig is too long\"}"));
}

HASH_AND_INT(bitcoinrpc,getrawtransaction,txid,verbose)
{
    struct iguana_txid *tx,T; char *txbytes; bits256 checktxid; int32_t len,height; cJSON *retjson,*txobj;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( (tx= iguana_txidfind(coin,&height,&T,txid,coin->bundlescount-1)) != 0 )
    {
        retjson = cJSON_CreateObject();
        if ( (len= iguana_ramtxbytes(coin,coin->blockspace,sizeof(coin->blockspace),&checktxid,tx,height,0,0,0)) > 0 )
        {
            txbytes = calloc(1,len*2+1);
            init_hexbytes_noT(txbytes,coin->blockspace,len);
            if ( verbose != 0 )
            {
                txobj = bitcoin_hex2json(coin,&checktxid,0,txbytes);
                free(txbytes);
                if ( txobj != 0 )
                    return(jprint(txobj,1));
            }
            jaddstr(retjson,"result",txbytes);
            printf("txbytes.(%s) len.%d (%s)\n",txbytes,len,jprint(retjson,0));
            free(txbytes);
            return(jprint(retjson,1));
        }
        else if ( height >= 0 )
        {
            if ( coin->APIblockstr != 0 )
                jaddstr(retjson,"error","already have pending request");
            else
            {
                int32_t datalen; uint8_t *data; char *blockstr; bits256 blockhash;
                blockhash = iguana_blockhash(coin,height);
                if ( (blockstr= iguana_APIrequest(coin,blockhash,txid,2)) != 0 )
                {
                    datalen = (int32_t)(strlen(blockstr) >> 1);
                    data = malloc(datalen);
                    decode_hex(data,datalen,blockstr);
                    if ( (txbytes= iguana_txscan(coin,verbose != 0 ? retjson : 0,data,datalen,txid)) != 0 )
                    {
                        jaddstr(retjson,"result",txbytes);
                        jaddbits256(retjson,"blockhash",blockhash);
                        jaddnum(retjson,"height",height);
                        free(txbytes);
                    } else jaddstr(retjson,"error","cant find txid in block");
                    free(blockstr);
                    free(data);
                } else jaddstr(retjson,"error","cant find blockhash");
                return(jprint(retjson,1));
            }
        } else printf("height.%d\n",height);
    }
    return(clonestr("{\"error\":\"cant find txid\"}"));
}

STRING_ARG(bitcoinrpc,decoderawtransaction,rawtx)
{
    cJSON *txobj = 0; bits256 txid;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( rawtx != 0 && rawtx[0] != 0 )
    {
        if ( (strlen(rawtx) & 1) != 0 )
            return(clonestr("{\"error\":\"rawtx hex has odd length\"}"));
        txobj = bitcoin_hex2json(coin,&txid,0,rawtx);
        //char str[65]; printf("got txid.(%s)\n",bits256_str(str,txid));
    }
    if ( txobj == 0 )
        txobj = cJSON_CreateObject();
    return(jprint(txobj,1));
}

HASH_ARG(bitcoinrpc,gettransaction,txid)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(bitcoinrpc_getrawtransaction(IGUANA_CALLARGS,txid,1));
}

cJSON *iguana_createvins(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *txobj,cJSON *vins)
{
    int32_t i,n,vout,p2shlen=0,spendlen=0,unspentind,height; uint64_t satoshis; char coinaddr[128],pubkeystr[256],scriptstr[IGUANA_MAXSCRIPTSIZE*2],*str,*hexstr; cJSON *pubkeys,*item,*obj,*newvin,*newvins; uint32_t sequenceid; bits256 txid; uint8_t spendscript[IGUANA_MAXSCRIPTSIZE],redeemscript[IGUANA_MAXSCRIPTSIZE]; struct iguana_waccount *wacct; struct iguana_waddress *waddr;
    newvins = cJSON_CreateArray();
    if ( (n= cJSON_GetArraySize(vins)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            pubkeys = cJSON_CreateArray();
            newvin = cJSON_CreateObject();
            item = jitem(vins,i);
            txid = jbits256(item,"txid");
            vout = jint(item,"vout");
            jaddbits256(newvin,"txid",txid);
            jaddnum(newvin,"vout",vout);
            p2shlen = spendlen = 0;
            if ( ((str= jstr(item,"scriptPub")) != 0 || (str= jstr(item,"scriptPubkey")) != 0) && is_hexstr(str,(int32_t)strlen(str)) > 0 )
            {
                spendlen = (int32_t)strlen(str) >> 1;
                decode_hex(spendscript,spendlen,str);
            }
            else if ( ((obj= jobj(item,"scriptPub")) != 0 || (obj= jobj(item,"scriptPubkey")) != 0) && (hexstr= jstr(obj,"hex")) != 0 )
            {
                spendlen = (int32_t)strlen(hexstr) >> 1;
                decode_hex(spendscript,spendlen,hexstr);
            }
            if ( (unspentind= iguana_unspentindfind(coin,coinaddr,spendscript,&spendlen,&satoshis,&height,txid,vout,coin->bundlescount-1)) > 0 )
            {
                printf("[%d] unspentind.%d (%s) spendlen.%d %.8f\n",height/coin->chain->bundlesize,unspentind,coinaddr,spendlen,dstr(satoshis));
                if ( coinaddr[0] != 0 && (waddr= iguana_waddresssearch(myinfo,coin,&wacct,coinaddr)) != 0 )
                {
                    init_hexbytes_noT(pubkeystr,waddr->pubkey,bitcoin_pubkeylen(waddr->pubkey));
                    jaddistr(pubkeys,pubkeystr);
                }
            }
            if ( spendlen > 0 )
            {
                init_hexbytes_noT(scriptstr,spendscript,spendlen);
                jaddstr(newvin,"scriptPub",scriptstr);
            }
            if ( (str= jstr(item,"redeemScript")) != 0 )
            {
                p2shlen = (int32_t)strlen(str) >> 1;
                decode_hex(redeemscript,p2shlen,str);
                init_hexbytes_noT(scriptstr,redeemscript,p2shlen);
                jaddstr(newvin,"redeemScript",scriptstr);
            }
            if ( jobj(item,"sequence") != 0 )
                sequenceid = juint(item,"sequence");
            else sequenceid = 0xffffffff;
            jaddnum(newvin,"sequence",sequenceid);
            bitcoin_txinput(coin,txobj,txid,vout,sequenceid,spendscript,spendlen,redeemscript,p2shlen,0,0);
            jadd(newvin,"pubkeys",pubkeys);
            jaddi(newvins,newvin);
        }
    }
    return(newvins);
}

ARRAY_OBJ_INT(bitcoinrpc,createrawtransaction,vins,vouts,locktime)
{
    bits256 txid; int32_t offset,spendlen=0,n; uint8_t addrtype,rmd160[20],spendscript[IGUANA_MAXSCRIPTSIZE]; uint64_t satoshis; char *hexstr,*field,*txstr; cJSON *txobj,*item,*obj,*retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( coin != 0 && (txobj= bitcoin_txcreate(coin,locktime)) != 0 )
    {
        iguana_createvins(myinfo,coin,txobj,vins);
        if ( (n= cJSON_GetArraySize(vouts)) > 0 )
        {
            if ( (item= vouts->child) != 0 && n == 1 )
                item = item->child;
            while ( item != 0 )
            {
                if ( (field= jfieldname(item)) != 0 )
                {
                    if ( strcmp(field,"data") == 0 )
                    {
                        if ( (hexstr= jstr(item,"data")) != 0 )
                        {
                            spendlen = (int32_t)strlen(hexstr) >> 1;
                            offset = 0;
                            if ( is_hexstr(hexstr,spendlen) > 0 )
                            {
                                decode_hex(spendscript+4,spendlen,hexstr);
                                spendscript[3] = SCRIPT_OPRETURN;
                                spendlen++;
                                /* 1-75	0x01-0x4b	(special)	data	The next opcode bytes is data to be pushed onto the stack
                                 OP_PUSHDATA1	76	0x4c	(special)	data	The next byte contains the number of bytes to be pushed onto the stack.
                                 OP_PUSHDATA2	77	0x4d*/
                                if ( spendlen < 76 )
                                {
                                    spendscript[2] = spendlen;
                                    offset = 2;
                                    spendlen++;
                                }
                                else if ( spendlen <= 0xff )
                                {
                                    spendscript[2] = spendlen;
                                    spendscript[1] = 0x4c;
                                    offset = 1;
                                    spendlen += 2;
                                }
                                else if ( spendlen <= 0xffff )
                                {
                                    spendscript[2] = ((spendlen >> 8) & 0xff);
                                    spendscript[1] = (spendlen & 0xff);
                                    spendscript[0] = 0x4d;
                                    offset = 0;
                                    spendlen += 3;
                                }
                                else continue;
                                if ( (obj= jobj(item,"amount")) != 0 )
                                    satoshis = jdouble(obj,0) * SATOSHIDEN;
                                else satoshis = 0;
                                bitcoin_txoutput(coin,txobj,spendscript+offset,spendlen,satoshis);
                            }
                        }
                        break;
                    }
                    else
                    {
                        if ( bitcoin_addr2rmd160(&addrtype,rmd160,field) == sizeof(rmd160) )
                        {
                            spendlen = bitcoin_standardspend(spendscript,0,rmd160);
                            satoshis = jdouble(item,0) * SATOSHIDEN;
                            bitcoin_txoutput(coin,txobj,spendscript,spendlen,satoshis);
                        }
                    }
                }
                item = item->next;
            }
        }
        if ( (txstr= bitcoin_json2hex(myinfo,coin,&txid,txobj,0)) != 0 )
        {
            jaddstr(retjson,"result",txstr);
            free(txstr);
        }
    }
    return(jprint(retjson,1));
}

TWOINTS_AND_ARRAY(bitcoinrpc,listunspent,minconf,maxconf,array)
{
    int32_t numrmds,numunspents=0; uint8_t *rmdarray; cJSON *retjson = cJSON_CreateArray();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( minconf == 0 )
        minconf = 1;
    if ( maxconf == 0 )
        maxconf = 9999999;
    rmdarray = iguana_rmdarray(coin,&numrmds,array,0);
    iguana_unspents(myinfo,coin,retjson,minconf,maxconf,rmdarray,numrmds,0,0,&numunspents);
    if ( rmdarray != 0 )
        free(rmdarray);
    return(jprint(retjson,1));
}

INT_AND_ARRAY(bitcoinrpc,lockunspent,flag,array)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,listlockunspent)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

DOUBLE_ARG(bitcoinrpc,settxfee,amount)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    coin->txfee_perkb = amount * SATOSHIDEN;
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",jtrue());
    return(jprint(retjson,1));
}

S_D_SS(bitcoinrpc,sendtoaddress,address,amount,comment,comment2)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    iguana_unspentset(myinfo,coin);
    return(sendtoaddress(myinfo,coin,address,amount * SATOSHIDEN,coin->txfee,comment,comment2,coin->minconfirms,0));
}

SS_D_I_SS(bitcoinrpc,sendfrom,fromaccount,toaddress,amount,minconf,comment,comment2)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    iguana_unspentset(myinfo,coin);
    return(sendtoaddress(myinfo,coin,toaddress,amount * SATOSHIDEN,coin->txfee,comment,comment2,minconf,fromaccount));
}

S_A_I_S(bitcoinrpc,sendmany,fromaccount,payments,minconf,comment)
{
    cJSON *retjson,*item; int32_t i,n; char *coinaddr,*str; int64_t required,val; double amount;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    iguana_unspentset(myinfo,coin);
    n = cJSON_GetArraySize(payments);
    item = payments->child;
    for (required=i=0; i<n; i++)
    {
        if ( item != 0 && (coinaddr= item->string) != 0 )
        {
            amount = jdouble(item,0);
            val = amount * SATOSHIDEN;
            printf("(%s %.8f) ",coinaddr,dstr(val));
            if ( (str= sendtoaddress(myinfo,coin,coinaddr,val,coin->txfee,comment,"",minconf,fromaccount)) != 0 )
            {
                free(str);
            }
            required += val;
        }
        item = item->next;
    }
    printf("required %.8f\n",dstr(required));
    retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

#include "../includes/iguana_apiundefs.h"
