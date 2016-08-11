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

// compare multiple rawtx returns

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
            if ( (waddr= iguana_waddresssearch(myinfo,&wacct,str)) != 0 )
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
        if ( (waddr= iguana_waddresssearch(myinfo,&wacct,str)) != 0 )
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
            if ( V.signers[i].coinaddr[0] != 0 && (waddr= iguana_waddresssearch(myinfo,&wacct,V.signers[i].coinaddr)) != 0 && waddr->wifstr[0] != 0 )
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
        if ( scriptlen != 0 )
        {
            bitcoin_address(coinaddr,coin->chain->p2shtype,script,scriptlen);
            jaddstr(scriptobj,"p2sh",coinaddr);
        }
        memcpy(rmd160,V.rmd160,20);
    }
    return(scriptobj);
}

int32_t iguana_bestunspent(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *aboveip,int64_t *abovep,int32_t *belowip,int64_t *belowp,int64_t *unspents,int32_t numunspents,uint64_t value)
{
    int32_t i,abovei,belowi; int64_t above,below,gap,atx_value;
    abovei = belowi = -1;
    for (above=below=i=0; i<numunspents; i++)
    {
        if ( (atx_value= unspents[(i << 1) + 1]) <= 0 )
            continue;
        if ( iguana_unspent_check(myinfo,coin,(uint16_t)(unspents[i << 1] >> 32),(uint32_t)unspents[i << 1]) != 0 )
        {
            printf("(%d u%d) %.8f already used\n",(uint16_t)(unspents[i << 1] >> 32),(uint32_t)unspents[i << 1],dstr(atx_value));
            continue;
        }
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
        } else gap = (value - atx_value);
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

cJSON *iguana_inputjson(bits256 txid,int32_t vout,uint8_t *spendscript,int32_t spendlen)
{
    char hexstr[IGUANA_MAXSCRIPTSIZE*2 + 1]; cJSON *sobj,*item = cJSON_CreateObject();
    jaddbits256(item,"txid",txid);
    jaddnum(item,"vout",vout);
    sobj = cJSON_CreateObject();
    init_hexbytes_noT(hexstr,spendscript,spendlen);
    jaddstr(sobj,"hex",hexstr);
    jadd(item,"scriptPubKey",sobj);
    return(item);
}

cJSON *iguana_inputsjson(struct supernet_info *myinfo,struct iguana_info *coin,int64_t *totalp,uint64_t amount,int64_t *unspents,int32_t num)
{
    cJSON *vins; uint8_t spendscript[IGUANA_MAXSCRIPTSIZE]; struct iguana_txid *T; struct iguana_unspent *U,*u; struct iguana_bundle *bp; struct iguana_ramchain *ramchain; char coinaddr[64]; int32_t vout,height,abovei,belowi,i,spendlen,ind,hdrsi; uint32_t txidind,unspentind; struct iguana_ramchaindata *rdata; bits256 txid; int64_t value,above,below,total = 0; int64_t remains = amount;
    *totalp = 0;
    vins = cJSON_CreateArray();
    for (i=0; i<num; i++)
    {
        below = above = 0;
        if ( iguana_bestunspent(myinfo,coin,&abovei,&above,&belowi,&below,unspents,num,remains) < 0 )
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
        if ( coin->RELAYNODE == 0 && coin->VALIDATENODE == 0 )
        {
            if ( (spendlen= basilisk_unspentfind(myinfo,coin,&txid,&vout,spendscript,hdrsi,unspentind,value)) > 0 )
            {
                jaddi(vins,iguana_inputjson(txid,vout,spendscript,spendlen));
                total += value;
                remains -= value;
                //printf("%s value %.8f -> remains %.8f\n",coinaddr,dstr(value),dstr(remains));
                if ( remains <= 0 )
                    break;
            }
            continue;
        }
        if ( (bp= coin->bundles[hdrsi]) == 0 )
        {
            printf("no bundle.[%d]\n",hdrsi);
            free_json(vins);
            return(0);
        }
        ramchain = &bp->ramchain;
        if ( (rdata= ramchain->H.data) == 0 )
            continue;
        U = RAMCHAIN_PTR(rdata,Uoffset);
        T = RAMCHAIN_PTR(rdata,Toffset);
        if ( unspentind > 0 && unspentind < rdata->numunspents )
        {
            u = &U[unspentind];
            if ( (txidind= u->txidind) > 0 && txidind < rdata->numtxids )
            {
                if ( iguana_unspentindfind(myinfo,coin,coinaddr,spendscript,&spendlen,&amount,&height,T[txidind].txid,u->vout,coin->bundlescount-1,0) == unspentind && spendlen > 0 )
                {
                    jaddi(vins,iguana_inputjson(T[txidind].txid,u->vout,spendscript,spendlen));
                    total += value;
                    remains -= value;
                    //printf("%s value %.8f -> remains %.8f\n",coinaddr,dstr(value),dstr(remains));
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

char *iguana_signrawtx(struct supernet_info *myinfo,struct iguana_info *coin,int32_t height,bits256 *signedtxidp,int32_t *completedp,cJSON *vins,char *rawtx,cJSON *privkeys,struct vin_info *V)
{
    char *signedtx = 0; struct iguana_msgtx msgtx; int32_t numinputs,flagV = 0,flag = 0;
    *completedp = 0;
    if ( privkeys == 0 )
        privkeys = iguana_privkeysjson(myinfo,coin,vins), flag = 1;
    if ( (numinputs= cJSON_GetArraySize(vins)) > 0 && privkeys != 0 )
    {
        memset(&msgtx,0,sizeof(msgtx));
        if ( V == 0 )
            V = calloc(numinputs,sizeof(*V)), flagV = 1;
        //printf("SIGN.(%s) priv.(%s) %llx %llx\n",jprint(vins,0),jprint(privkeys,0),(long long)V->signers[0].privkey.txid,(long long)V->signers[1].privkey.txid);
        if ( V != 0 )
        {
            if ( iguana_signrawtransaction(myinfo,coin,height,&msgtx,&signedtx,signedtxidp,V,numinputs,rawtx,vins,privkeys) > 0 )
                *completedp = 1;
            else printf("signrawtransaction incomplete\n");
            if ( flagV != 0 )
                free(V);
        }
        if ( flag != 0 )
            free_json(privkeys);
    }
    printf("signed.(%s)\n",signedtx!=0?signedtx:"");
    return(signedtx);
}

bits256 iguana_sendrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *signedtx)
{
    bits256 txid; uint8_t *serialized; int32_t i,len,n; struct iguana_peer *addr; cJSON *vals; char *str;
    len = (int32_t)strlen(signedtx) >> 1;
    serialized = calloc(1,sizeof(struct iguana_msghdr) + len);
    decode_hex(&serialized[sizeof(struct iguana_msghdr)],len,signedtx);
    txid = bits256_doublesha256(0,&serialized[sizeof(struct iguana_msghdr)],len);
    if ( coin->peers != 0 && (n= coin->peers->numranked) > 0 )
    {
        for (i=0; i<8 && i<n; i++)
        {
            if ( (addr= coin->peers->ranked[i]) != 0 && addr->dead == 0 && addr->usock >= 0 )
                iguana_queue_send(addr,0,serialized,"tx",len);
        }
    }
    else
    {
        vals = cJSON_CreateObject();
        jaddstr(vals,"symbol",coin->symbol);
        if ( (str= gecko_sendrawtransaction(myinfo,coin->symbol,serialized,len,txid,vals,signedtx)) != 0 )
            free(str);
        free_json(vals);
    }
    free(serialized);
    return(txid);
}

char *iguana_calcrawtx(struct supernet_info *myinfo,struct iguana_info *coin,cJSON **vinsp,cJSON *txobj,int64_t satoshis,char *changeaddr,int64_t txfee,cJSON *addresses,int32_t minconf,uint8_t *opreturn,int32_t oplen,int64_t burnamount,char *remoteaddr)
{
    uint8_t addrtype,rmd160[20],spendscript[IGUANA_MAXSCRIPTSIZE]; int32_t max,num,spendlen; char *rawtx=0; bits256 txid; cJSON *vins=0; int64_t avail,total,change,*unspents = 0; struct vin_info *V=0;
    *vinsp = 0;
    max = 10000;
    satoshis += burnamount;
    unspents = calloc(max,sizeof(*unspents));
    if ( (num= iguana_unspentslists(myinfo,coin,&avail,unspents,max,satoshis+txfee,minconf,addresses,remoteaddr)) <= 0 )
    {
        free(unspents);
        return(0);
    }
    if ( txobj != 0 && avail >= satoshis+txfee )
    {
        if ( (vins= iguana_inputsjson(myinfo,coin,&total,satoshis + txfee,unspents,num)) != 0 )
        {
            if ( total < (satoshis + txfee) )
            {
                free_json(vins);
                free(unspents);
                printf("insufficient total %.8f vs (%.8f + %.8f)\n",dstr(total),dstr(satoshis),dstr(txfee));
                return(0);
            }
            if ( (change= (total - (satoshis + txfee))) > 0 && (changeaddr == 0 || changeaddr[0] == 0) )
            {
                printf("no changeaddr for %.8f\n",dstr(change));
                free_json(vins);
                free(unspents);
                return(0);
            }
            iguana_createvins(myinfo,coin,txobj,vins);
            if ( change > 0 )
            {
                if ( iguana_addressvalidate(coin,&addrtype,changeaddr) < 0 )
                {
                    free_json(vins);
                    free(unspents);
                    printf("illegal destination address.(%s)\n",changeaddr);
                    return(0);
                }
                bitcoin_addr2rmd160(&addrtype,rmd160,changeaddr);
                spendlen = bitcoin_standardspend(spendscript,0,rmd160);
                bitcoin_txoutput(txobj,spendscript,spendlen,change);
                int32_t i; for (i=0; i<oplen; i++)
                    printf("%02x",spendscript[i]);
                printf(" changeaddr.%s\n",changeaddr);
                if ( opreturn != 0 )
                {
                    for (i=0; i<oplen; i++)
                        printf("%02x",opreturn[i]);
                    printf(" <- got opret\n");
                    bitcoin_txoutput(txobj,opreturn,oplen,burnamount);
                }
            }
            if ( vins != 0 )
                V = calloc(cJSON_GetArraySize(vins),sizeof(*V));
            rawtx = bitcoin_json2hex(myinfo,coin,&txid,txobj,V);
            if ( V != 0 )
                free(V);
        }
    }
    free(unspents);
    *vinsp = vins;
    return(rawtx);
}

void iguana_unspentslock(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *vins)
{
    uint32_t spent_unspentind; char coinaddr[64]; int16_t spent_hdrsi; int32_t i,RTspentflag,num;
    if ( coin->MAXPEERS == 1 || coin->RELAYNODE != 0 || coin->VALIDATENODE != 0 )
    {
        num = cJSON_GetArraySize(vins);
        for (i=0; i<num; i++)
        {
            if ( iguana_inputaddress(myinfo,coin,coinaddr,&spent_hdrsi,&spent_unspentind,jitem(vins,i)) != 0 )
                iguana_utxofind(coin,spent_hdrsi,spent_unspentind,&RTspentflag,1);
        }
    }
}

char *sendtoaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,char *coinaddr,uint64_t satoshis,uint64_t txfee,char *comment,char *comment2,int32_t minconf,char *account)
{
    uint8_t addrtype,spendscript[1024],rmd160[20]; int32_t completed; char *retstr,spendscriptstr[4096],*rawtx=0,*signedtx = 0; bits256 signedtxid,senttxid; cJSON *retjson,*vins,*addresses,*valsobj; uint32_t spendlen,locktime = 0; struct iguana_waddress *waddr; uint32_t basilisktag;
    //sendtoaddress	<bitcoinaddress> <amount> [comment] [comment-to]	<amount> is a real and is rounded to 8 decimal places. Returns the transaction ID <txid> if successful.	Y
    if ( account == 0 || account[0] == 0 )
        account = "*";
    addresses = iguana_getaddressesbyaccount(myinfo,coin,account);
    if ( coin->changeaddr[0] == 0 )
    {
        if ( (waddr= iguana_getaccountaddress(myinfo,coin,0,0,coin->changeaddr,"change")) == 0 )
            return(clonestr("{\"error\":\"no change address specified\"}"));
        strcpy(coin->changeaddr,waddr->coinaddr);
    }
    if ( coinaddr != 0 && coinaddr[0] != 0 && satoshis != 0 )
    {
        if ( iguana_addressvalidate(coin,&addrtype,coinaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
        spendlen = bitcoin_standardspend(spendscript,0,rmd160);
        init_hexbytes_noT(spendscriptstr,spendscript,spendlen);
        basilisktag = (uint32_t)rand();
        valsobj = cJSON_CreateObject();
        jadd(valsobj,"addresses",addresses);
        jaddstr(valsobj,"coin",coin->symbol);
        jaddstr(valsobj,"changeaddr",coin->changeaddr);
        jaddstr(valsobj,"spendscript",spendscriptstr);
        jadd64bits(valsobj,"satoshis",satoshis);
        jadd64bits(valsobj,"txfee",txfee);
        jaddnum(valsobj,"minconf",minconf);
        jaddnum(valsobj,"basilisktag",basilisktag);
        jaddnum(valsobj,"locktime",locktime);
        jaddnum(valsobj,"timeout",30000);
        if ( comment != 0 && is_hexstr(comment,0) > 0 )
            jaddstr(valsobj,"opreturn",comment);
        if ( (retstr= basilisk_bitcoinrawtx(myinfo,coin,remoteaddr,basilisktag,jint(valsobj,"timeout"),valsobj)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( (rawtx= jstr(retjson,"rawtx")) != 0 && (vins= jobj(retjson,"vins")) != 0 )
                {
                    if ( (signedtx= iguana_signrawtx(myinfo,coin,coin->blocks.hwmchain.height,&signedtxid,&completed,vins,rawtx,0,0)) != 0 )
                    {
                        iguana_unspentslock(myinfo,coin,vins);
                        retjson = cJSON_CreateObject();
                        jaddbits256(retjson,"result",signedtxid);
                        jaddstr(retjson,"signedtx",signedtx);
                        jadd(retjson,"complete",completed != 0 ? jtrue() : jfalse());
                        if ( completed != 0 )
                        {
                            senttxid = iguana_sendrawtransaction(myinfo,coin,signedtx);
                            if ( bits256_cmp(senttxid,signedtxid) == 0 )
                                jaddstr(retjson,"sendrawtransaction","success");
                            else jaddbits256(retjson,"senderror",senttxid);
                        }
                        free_json(vins);
                        free(signedtx);
                        return(jprint(retjson,1));
                    }
                    else
                    {
                        free_json(vins);
                        return(clonestr("{\"error\":\"couldnt sign rawtx\"}"));
                    }
                }
                free_json(retjson);
            }
            free(retstr);
            return(clonestr("{\"error\":\"couldnt create rawtx\"}"));
        } else return(clonestr("{\"error\":\"couldnt create rawtx\"}"));
    }
    return(clonestr("{\"error\":\"need address and amount\"}"));
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

STRING_AND_INT(bitcoinrpc,sendrawtransaction,rawtx,allowhighfees)
{
    cJSON *retjson = cJSON_CreateObject(); bits256 txid;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    txid = iguana_sendrawtransaction(myinfo,coin,rawtx);
    jaddbits256(retjson,"result",txid);
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

ZERO_ARGS(iguana,makekeypair)
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
    uint8_t pubkey[65],addrtype = 0; int32_t plen; char coinaddr[128],*str; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    plen = (int32_t)strlen(pubkeystr) >> 1;
    if ( plen >= 33 && plen <= 65 && coin != 0 && coin->chain != 0 )
    {
        addrtype = coin->chain->pubtype;
        decode_hex(pubkey,plen,pubkeystr);
        if ( (str= bitcoin_address(coinaddr,addrtype,pubkey,plen)) != 0 )
        {
            if ( iguana_addressvalidate(coin,&addrtype,coinaddr) < 0 )
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
        if ( (unspentind= iguana_unspentindfind(myinfo,coin,0,0,0,0,&height,txid,vout,coin->bundlescount-1,0)) != 0 )
        {
            if ( height >= 0 && height < coin->longestchain && (bp= coin->bundles[height / coin->chain->bundlesize]) != 0 )
            {
                ramchain = &bp->ramchain;
                if ( (rdata= ramchain->H.data) != 0 )
                {
                    U = RAMCHAIN_PTR(rdata,Uoffset);
                    P = RAMCHAIN_PTR(rdata,Poffset);
                    T = RAMCHAIN_PTR(rdata,Toffset);
                    RTspend = 0;
                    if ( iguana_spentflag(myinfo,coin,&RTspend,&spentheight,ramchain,bp->hdrsi,unspentind,height,minconf,coin->longestchain,U[unspentind].value) == 0 )
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
                        jadd(retjson,"iguana",iguana_unspentjson(myinfo,coin,bp->hdrsi,unspentind,T,&U[unspentind],rmd160,coinaddr,pubkey33,spentheight,remoteaddr));
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
    struct iguana_txid *tx,T; char *txbytes; bits256 checktxid; int32_t len,height,extralen=65536; cJSON *retjson,*txobj; uint8_t *extraspace; struct iguana_block *block; bits256 hash2;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( (tx= iguana_txidfind(coin,&height,&T,txid,coin->bundlescount-1)) != 0 )
    {
        retjson = cJSON_CreateObject();
        if ( (len= iguana_ramtxbytes(coin,coin->blockspace,coin->blockspacesize,&checktxid,tx,height,0,0,0)) > 0 )
        {
            txbytes = calloc(1,len*2+1);
            init_hexbytes_noT(txbytes,coin->blockspace,len);
            if ( verbose != 0 )
            {
                extraspace = calloc(1,extralen);
                txobj = bitcoin_hex2json(coin,coin->blocks.hwmchain.height,&checktxid,0,txbytes,extraspace,extralen,0,0,0);
                free(extraspace);
                free(txbytes);
                if ( txobj != 0 )
                {
                    hash2 = iguana_blockhash(coin,height);
                    jaddbits256(txobj,"blockhash",hash2);
                    if ( (block= iguana_blockfind("rawtx",coin,hash2)) != 0 )
                        jaddnum(txobj,"blocktime",block->RO.timestamp);
                    jaddnum(txobj,"height",height);
                    jaddnum(txobj,"confirmations",coin->blocks.hwmchain.height - height);
                    return(jprint(txobj,1));
                }
            }
            jaddstr(retjson,"result",txbytes);
            char str[65]; printf("txbytes.(%s) len.%d (%s) %s\n",txbytes,len,jprint(retjson,0),bits256_str(str,checktxid));
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

int64_t iguana_lockval(int32_t finalized,int64_t locktime)
{
    int64_t lockval = -1;
    if ( finalized == 0 )
        return(locktime);
    return(lockval);
}

char *iguana_validaterawtx(struct supernet_info *myinfo,struct iguana_info *coin,int32_t height,struct iguana_msgtx *msgtx,uint8_t *extraspace,int32_t extralen,char *rawtx,int32_t mempool,int32_t suppress_pubkeys)
{
    bits256 signedtxid,txid; struct iguana_msgvin vin; cJSON *log,*vins,*vouts,*txobj,*retjson; char *checkstr,*signedtx; int32_t finalized = 1,i,len,maxsize,numinputs,numoutputs,complete; struct vin_info *V; uint8_t *serialized,*serialized2; uint32_t sigsize,pubkeysize,p2shsize,suffixlen; int64_t inputsum,outputsum,lockval;
    retjson = cJSON_CreateObject();
    inputsum = outputsum = numinputs = numoutputs = 0;
    if ( rawtx != 0 && rawtx[0] != 0 && coin != 0 )
    {
        if ( (strlen(rawtx) & 1) != 0 )
            return(clonestr("{\"error\":\"rawtx hex has odd length\"}"));
        memset(msgtx,0,sizeof(*msgtx));
        if ( (txobj= bitcoin_hex2json(coin,coin->blocks.hwmchain.height,&msgtx->txid,msgtx,rawtx,extraspace,extralen,0,0,suppress_pubkeys)) != 0 )
        {
            //printf("txobj.(%s)\n",jprint(txobj,0));
            if ( (checkstr= bitcoin_json2hex(myinfo,coin,&txid,txobj,0)) != 0 )
            {
                if ( strcmp(rawtx,checkstr) != 0 )
                {
                    jaddstr(retjson,"error","converting from hex2json and json2hex mismatch");
                    jaddstr(retjson,"original",rawtx);
                    jaddstr(retjson,"checkstr",checkstr);
                    for (i=0; rawtx[i]!=0 && checkstr[i]!=0; i++)
                        if ( rawtx[i] != checkstr[i] )
                            break;
                    jaddnum(retjson,"mismatch position",i);
                    jadd(retjson,"origtx",txobj);
                    if ( (txobj= bitcoin_hex2json(coin,coin->blocks.hwmchain.height,&txid,msgtx,checkstr,extraspace,extralen,0,0,suppress_pubkeys)) != 0 )
                        jadd(retjson,"checktx",txobj);
                    free(checkstr);
                    return(jprint(retjson,1));
                }
                free(checkstr);
            }
            if ( (vouts= jarray(&numoutputs,txobj,"vout")) > 0 )
            {
                struct iguana_msgvout vout; uint8_t voutdata[IGUANA_MAXSCRIPTSIZE];
                for (i=0; i<numoutputs; i++)
                {
                    if ( iguana_parsevoutobj(coin,voutdata,sizeof(voutdata),&vout,jitem(vouts,i)) > 0 )
                        outputsum += vout.value;
                }
            }
            if ( (vins= jarray(&numinputs,txobj,"vin")) > 0 )
            {
                maxsize = (int32_t)strlen(rawtx);
                serialized = malloc(maxsize);
                serialized2 = malloc(maxsize);
                len = 0;
                V = calloc(numinputs,sizeof(*V));
                for (i=0; i<numinputs; i++)
                {
                    len += iguana_parsevinobj(myinfo,coin,&serialized[len],maxsize-len,&vin,jitem(vins,i),&V[i]);
                    if ( (V[i].unspentind= iguana_unspentindfind(myinfo,coin,V[i].coinaddr,V[i].spendscript,&V[i].spendlen,&V[i].amount,&V[i].height,msgtx->vins[i].prev_hash,msgtx->vins[i].prev_vout,coin->bundlescount-1,mempool)) > 0 )
                    {
                        inputsum += V[i].amount;
                        msgtx->vins[i].spendscript = V[i].spendscript;
                        msgtx->vins[i].spendlen = V[i].spendlen;
                        V[i].hashtype = iguana_vinscriptparse(coin,&V[i],&sigsize,&pubkeysize,&p2shsize,&suffixlen,msgtx->vins[i].vinscript,msgtx->vins[i].scriptlen);
                        V[i].userdatalen = suffixlen;
                        memcpy(V[i].spendscript,msgtx->vins[i].spendscript,msgtx->vins[i].spendlen);
                        V[i].spendlen = msgtx->vins[i].spendlen;
                        if ( msgtx->vins[i].sequence < IGUANA_SEQUENCEID_FINAL )
                            finalized = 0;
                        //printf("V %.8f (%s) spendscript.[%d] scriptlen.%d\n",dstr(V[i].amount),V[i].coinaddr,V[i].spendlen,V[i].spendlen);
                    }
                }
                V[0].suppress_pubkeys = suppress_pubkeys;
                if ( (complete= bitcoin_verifyvins(coin,height,&signedtxid,&signedtx,msgtx,serialized2,maxsize,V,1,0,suppress_pubkeys)) > 0 && signedtx != 0 )
                {
                    msgtx->txid = signedtxid;
                    log = cJSON_CreateArray();
                    lockval = iguana_lockval(finalized,jint(txobj,"locktime"));
                    if ( iguana_interpreter(coin,log,lockval,V,numinputs) < 0 )
                    {
                        jaddstr(retjson,"error","interpreter rejects tx");
                    }
                    jadd(retjson,"interpreter",log);
                }
                jaddnum(retjson,"complete",complete);
                free(serialized), free(serialized2);
            }
        }
        //char str[65]; printf("got txid.(%s)\n",bits256_str(str,txid));
    }
    msgtx->inputsum = inputsum;
    msgtx->numinputs = numinputs;
    msgtx->outputsum = outputsum;
    msgtx->numoutputs = numoutputs;
    msgtx->txfee = (inputsum - outputsum);
    return(jprint(retjson,1));
}

STRING_AND_INT(bitcoinrpc,validaterawtransaction,rawtx,suppress)
{
    uint8_t *extraspace; int32_t extralen=65536;// char *retstr; struct iguana_msgtx msgtx;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    
    //cJSON *txobj; char *teststr= "{\"version\":1,\"locktime\":0,\"vin\":[{\"userdata\":\"20fe936da3707c8c4cc7eb0352160ec3f50b9454d46425df6347b2fbc5b2ec87ea00\",\"txid\":\"ee12e50b629d5d45438570fff841d1a2ba7d27f356de4aa06900c9a5e38cf141\",\"vout\":0,\"scriptPubKey\":{\"hex\":\"a9145cc47cc123e3f9b7dce0230009b9d3013a9e0c9687\"},\"suppress\":1,\"redeemScript\":\"6304165daa57b1752102a9669e63ef1ab04913615c2f3887ea3584f81e5f08feee9535b19ab3739d8afdac67a9143805600256ed8498ca1ec426759212e5835e8dc2882103a7b696908f77d69ec89887f8c4a0423b9e80b5974dc43301bd7d8abad07e1211ac68\"}],\"vout\":[{\"satoshis\":\"21821\",\"scriptPubkey\":{\"hex\":\"76a9143ef4734c1141725c095342095f6e0e7748b6c16588ac\"}}]}";
    
    cJSON *txobj; char *teststr= "{\"version\":1,\"locktime\":0,\"vin\":[{\"userdata\":\"206efad760ee54b9b2e2a038a821ef9f950eb0e248545ac202c3e2074cd14f92cb00\",\"txid\":\"3f4759381a62154f2f0eefed1e4433342548ad7b269f912820383b715a39273c\",\"vout\":0,\"scriptPubKey\":{\"hex\":\"a91446dcccef39c1d8c6da2ccc35dce2bfa7ec0d168887\"},\"suppress\":1,\"redeemScript\":\"63041c60aa57b1752103175cf93574c31637b8c2d8acd5319e3cd23761b5e418d32c6bcb194972ba9273ac67a9142d75daf71325feaa593b8f30989e462892189914882102a9669e63ef1ab04913615c2f3887ea3584f81e5f08feee9535b19ab3739d8afdac68\"}],\"vout\":[{\"satoshis\":\"18625\",\"scriptPubkey\":{\"hex\":\"76a914b7128d2ee837cf03e30a2c0e3e0181f7b9669bb688ac\"}}]}";
    // 01000000013c27395a713b382028919f267bad48253433441eedef0e2f4f15621a3859473f00000000d147304402207ecd423b55c1aa45a994c4eb4337ff0891692fbb69954a9ba024745a99c5272d02207cea696425feb5388153ab7f2608d66a66e4c95cfda2d44e98bc56e25994d3f701206efad760ee54b9b2e2a038a821ef9f950eb0e248545ac202c3e2074cd14f92cb004c6763041c60aa57b1752103175cf93574c31637b8c2d8acd5319e3cd23761b5e418d32c6bcb194972ba9273ac67a9142d75daf71325feaa593b8f30989e462892189914882102a9669e63ef1ab04913615c2f3887ea3584f81e5f08feee9535b19ab3739d8afdac68ffffffff01c1480000000000001976a914b7128d2ee837cf03e30a2c0e3e0181f7b9669bb688ac00000000
    // 01000000013c27395a713b382028919f267bad48253433441eedef0e2f4f15621a3859473f00000000fd8b00206efad760ee54b9b2e2a038a821ef9f950eb0e248545ac202c3e2074cd14f92cb004c6763041c60aa57b1752103175cf93574c31637b8c2d8acd5319e3cd23761b5e418d32c6bcb194972ba9273ac67a9142d75daf71325feaa593b8f30989e462892189914882102a9669e63ef1ab04913615c2f3887ea3584f81e5f08feee9535b19ab3739d8afdac68ffffffff01c1480000000000001976a914b7128d2ee837cf03e30a2c0e3e0181f7b9669bb688ac00000000
    //cJSON *txobj; char *teststr= "{\"version\":1,\"locktime\":0,\"vin\":[{\"userdata\":\"20ae439d344513eab8e718d8214fe6ae8133b8b5b594afd64da21d0e40b9c37cdd00\",\"txid\":\"2c1320315f4fb519cbf2b4d7b67855013b9a09a85e515df43b41d407a0083b09\",\"vout\":0,\"scriptPubKey\":{\"hex\":\"a9142e7674400d04217f770f2222126dc7fee44b06b487\"},\"suppress\":1,\"redeemScript\":\"63041686a657b1752102a9669e63ef1ab04913615c2f3887ea3584f81e5f08feee9535b19ab3739d8afdac67a914ed74c61c27656abc6c20687c3a9212ffdc6f34cd88210398a4cb9f6ea7c52a4e27455028a95e2e4e397a110fb75f072c2c58a8bdcbf4baac68\"}],\"vout\":[{\"satoshis\":\"16733\",\"scriptPubkey\":{\"hex\":\"76a91454a752f0d71b89d7c014ed0be29ca231c9546f9f88ac\"}}]}";
    extraspace = calloc(1,extralen);
    if ( (txobj= cJSON_Parse(teststr)) != 0 )
    {
        bits256 txid;
        rawtx = bitcoin_json2hex(myinfo,coin,&txid,txobj,0);
        txobj = bitcoin_hex2json(coin,coin->blocks.hwmchain.height,&txid,0,rawtx,extraspace,extralen,0,0,suppress);
        printf("RAWTX.(%s) -> (%s)\n",rawtx,jprint(txobj,0));
    }
    //retstr = iguana_validaterawtx(myinfo,coin,coin->blocks.hwmchain.height,&msgtx,extraspace,extralen,rawtx,0,suppress);
    free(extraspace);
    return(rawtx);
}

STRING_AND_INT(bitcoinrpc,decoderawtransaction,rawtx,suppress)
{
    cJSON *txobj = 0; bits256 txid; uint8_t *extraspace; int32_t extralen = 65536;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( rawtx != 0 && rawtx[0] != 0 )
    {
        if ( (strlen(rawtx) & 1) != 0 )
            return(clonestr("{\"error\":\"rawtx hex has odd length\"}"));
        extraspace = calloc(1,extralen);
        txobj = bitcoin_hex2json(coin,coin->blocks.hwmchain.height,&txid,0,rawtx,extraspace,extralen,0,0,suppress);
        free(extraspace);
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
            if ( (unspentind= iguana_unspentindfind(myinfo,coin,coinaddr,spendscript,&spendlen,&satoshis,&height,txid,vout,coin->bundlescount-1,0)) > 0 )
            {
                //printf("[%d] unspentind.%d (%s) spendlen.%d %.8f\n",height/coin->chain->bundlesize,unspentind,coinaddr,spendlen,dstr(satoshis));
                if ( coinaddr[0] != 0 && (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 )
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
            if ( jint(txobj,"locktime") > 0 )
                sequenceid = (uint32_t)time(NULL); // any value < 0xfffffffe should be fine
            else
            {
                if ( jobj(item,"sequence") != 0 )
                    sequenceid = juint(item,"sequence");
                else sequenceid = 0xffffffff;
            }
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
    if ( coin != 0 && (txobj= bitcoin_txcreate(coin->chain->isPoS,locktime,locktime==0?coin->chain->normal_txversion:coin->chain->locktime_txversion)) != 0 )
    {
        iguana_createvins(myinfo,coin,txobj,vins);
        if ( (n= cJSON_GetArraySize(vouts)) > 0 )
        {
            if ( is_cJSON_Array(vouts) != 0 && n == 1 && (item= jitem(vouts,0)) != 0 )
                item = item->child;
            else item = vouts->child;
            while ( item != 0 )
            {
                if ( (field= jfieldname(item)) != 0 )
                {
                    if ( strcmp(field,"data") == 0 )
                    {
                        if ( (hexstr= jstr(item,0)) != 0 )
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
                                bitcoin_txoutput(txobj,spendscript+offset,spendlen,satoshis);
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
                            bitcoin_txoutput(txobj,spendscript,spendlen,satoshis);
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
        maxconf = (1 << 30);
    rmdarray = iguana_rmdarray(myinfo,coin,&numrmds,array,0);
    iguana_unspents(myinfo,coin,retjson,minconf,maxconf,rmdarray,numrmds,(1 << 30),0,&numunspents,remoteaddr);
    if ( rmdarray != 0 )
        free(rmdarray);
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,getrawchangeaddress)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",coin->changeaddr);
    return(jprint(retjson,1));
}

INT_AND_ARRAY(bitcoinrpc,lockunspent,flag,array)
{
    int32_t RTspendflag,vout,hdrsi,i,n,height; cJSON *item,*retjson; bits256 txid; uint32_t unspentind;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    if ( array != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( jobj(item,"txid") != 0 && jobj(item,"vout") != 0 )
            {
                txid = jbits256(item,"txid");
                vout = jint(item,"vout");
                if ( (unspentind= iguana_unspentindfind(myinfo,coin,0,0,0,0,&height,txid,vout,coin->bundlescount-1,0)) != 0 )
                {
                    hdrsi = height / coin->chain->bundlesize;
                    iguana_utxofind(coin,hdrsi,unspentind,&RTspendflag,!flag);
                }
            }
        }
    }
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,listlockunspent)
{
    cJSON *array,*item,*retjson; bits256 txid; struct iguana_hhutxo *hhutxo,*tmputxo; int32_t hdrsi,vout; uint32_t unspentind;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    array = cJSON_CreateArray();
    retjson = cJSON_CreateObject();
    if ( coin->utxotable != 0 )
    {
        HASH_ITER(hh,coin->utxotable,hhutxo,tmputxo)
        {
            item = cJSON_CreateObject();
            hdrsi = (int32_t)(hhutxo->uval >> 32);
            unspentind = (uint32_t)hhutxo->uval;
            if ( (vout= iguana_uvaltxid(myinfo,&txid,coin,hdrsi,unspentind)) >= 0 )
            {
                jaddbits256(item,"txid",txid);
                jaddnum(item,"vout",vout);
                jaddi(array,item);
            }
        }
    }
    jadd(retjson,"result",array);
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
    //iguana_unspentset(myinfo,coin);
    return(sendtoaddress(myinfo,coin,remoteaddr,address,amount * SATOSHIDEN,coin->txfee,comment,comment2,coin->minconfirms,0));
}

SS_D_I_SS(bitcoinrpc,sendfrom,fromaccount,toaddress,amount,minconf,comment,comment2)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    //iguana_unspentset(myinfo,coin);
    return(sendtoaddress(myinfo,coin,remoteaddr,toaddress,amount * SATOSHIDEN,coin->txfee,comment,comment2,minconf,fromaccount));
}

S_A_I_S(bitcoinrpc,sendmany,fromaccount,payments,minconf,comment)
{
    cJSON *retjson,*item; int32_t i,n; char *coinaddr,*str; int64_t required,val; double amount;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    //iguana_unspentset(myinfo,coin);
    n = cJSON_GetArraySize(payments);
    item = payments->child;
    for (required=i=0; i<n; i++)
    {
        if ( item != 0 && (coinaddr= item->string) != 0 )
        {
            amount = jdouble(item,0);
            val = amount * SATOSHIDEN;
            printf("(%s %.8f) ",coinaddr,dstr(val));
            if ( (str= sendtoaddress(myinfo,coin,remoteaddr,coinaddr,val,coin->txfee,comment,"",minconf,fromaccount)) != 0 )
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
