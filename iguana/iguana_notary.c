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

// Todo list:
// a) updating latest notarized height based on the notarized tx data
// b) prevent overwriting blocks below notarized height
// c) detection of special transactions to update list of current notaries
// d) award 5% APR for utxo older than a week when they are spent
// e) round robin mining difficulty
// f) reduce cost for splitting
// g) RBF to reduce latency


#include "iguana777.h"
#include "notaries.h"

#if ISNOTARYNODE

struct dpow_nanomsghdr
{
    bits256 srchash,desthash;
    uint32_t channel,height,size,crc32;
    uint8_t packet[];
};

char *nanomsg_tcpname(char *str,char *ipaddr)
{
    sprintf(str,"tcp://%s:7775",ipaddr);
    return(str);
}

void dpow_nanomsginit(struct supernet_info *myinfo,char *ipaddr)
{
    char str[512]; int32_t timeout,retval;
    if ( myinfo->DPOW.sock < 0 && (myinfo->DPOW.sock= nn_socket(AF_SP,NN_BUS)) >= 0 )
    {
        if ( nn_bind(myinfo->DPOW.sock,nanomsg_tcpname(str,myinfo->ipaddr)) < 0 )
        {
            printf("error binding to (%s)\n",nanomsg_tcpname(str,myinfo->ipaddr));
            nn_close(myinfo->DPOW.sock);
            myinfo->DPOW.sock = -1;
        }
        timeout = 100;
        nn_setsockopt(myinfo->DPOW.sock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
    }
    if ( myinfo->DPOW.sock >= 0 && strcmp(ipaddr,myinfo->ipaddr) != 0 )
    {
        retval = nn_connect(myinfo->DPOW.sock,ipaddr);
        printf("addnotary (%s) retval.%d\n",ipaddr,retval);
    }
}

uint32_t dpow_send(struct supernet_info *myinfo,struct dpow_block *bp,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t crcs[2])
{
    struct dpow_nanomsghdr *np; int32_t size,sentbytes;
    size = (int32_t)(sizeof(*np) + datalen);
    np = malloc(size);
    np->size = size;
    np->crc32 = calc_crc32(0,data,datalen);
    np->srchash = srchash;
    np->desthash = desthash;
    np->channel = channel;
    np->height = msgbits;
    memcpy(np->packet,data,datalen);
    sentbytes = nn_send(myinfo->DPOW.sock,np,size,0);
    free(np);
    return(sentbytes);
    //return(basilisk_channelsend(myinfo,srchash,desthash,channel,msgbits,data,datalen,120));
    //return(basilisk_crcsend(myinfo,1,bp->sendbuf,sizeof(bp->sendbuf),srchash,desthash,channel,msgbits,data,datalen,crcs));
}

void dpow_nanomsg_update(struct supernet_info *myinfo)
{
    int32_t size; struct dpow_nanomsghdr *np;
    while ( (size= nn_recv(myinfo->DPOW.sock,&np,NN_MSG,0)) >= 0 )
    {
        if ( size >= 0 )
        {
            printf("NANORECV ht.%d channel.%08x (%d) crc32.%08x\n",np->height,np->channel,size,np->crc32);
            if ( np != 0 )
                nn_freemsg(np);
        }
    }
}
#else

void dpow_nanomsginit(struct supernet_info *myinfo,char *ipaddr) { }

uint32_t dpow_send(struct supernet_info *myinfo,struct dpow_block *bp,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t crcs[2])
{
    return(0);
}

void dpow_nanomsg_update(struct supernet_info *myinfo) { }

#endif

#define CHECKSIG 0xac

int32_t dpow_opreturnscript(uint8_t *script,uint8_t *opret,int32_t opretlen)
{
    int32_t offset = 0;
    script[offset++] = 0x6a;
    if ( opretlen >= 0x4c )
    {
        if ( opretlen > 0xff )
        {
            script[offset++] = 0x4d;
            script[offset++] = opretlen & 0xff;
            script[offset++] = (opretlen >> 8) & 0xff;
        }
        else
        {
            script[offset++] = 0x4c;
            script[offset++] = opretlen;
        }
    } else script[offset++] = opretlen;
    memcpy(&script[offset],opret,opretlen);
    return(opretlen + offset);
}

int32_t dpow_rwopret(int32_t rwflag,uint8_t *opret,bits256 *hashmsg,int32_t *heightmsgp,bits256 *btctxid,char *src)
{
    int32_t i,opretlen = 0;
    opretlen += iguana_rwbignum(rwflag,&opret[opretlen],sizeof(*hashmsg),hashmsg->bytes);
    opretlen += iguana_rwnum(rwflag,&opret[opretlen],sizeof(*heightmsgp),(uint32_t *)heightmsgp);
    if ( bits256_nonz(*btctxid) != 0 )
    {
        opretlen += iguana_rwbignum(rwflag,&opret[opretlen],sizeof(*btctxid),btctxid->bytes);
        if ( rwflag != 0 )
        {
            for (i=0; src[i]!=0; i++)
                opret[opretlen++] = src[i];
            opret[opretlen++] = 0;
        }
        else
        {
            for (i=0; opret[opretlen]!=0; i++)
                src[i] = opret[opretlen++];
            src[i] = 0;
            opretlen++;
        }
    }
    return(opretlen);
}

int32_t dpow_rwutxobuf(int32_t rwflag,uint8_t *data,bits256 *hashmsg,struct dpow_entry *ep)
{
    int32_t i,len = 0;
    if ( rwflag != 0 )
    {
        data[0] = DPOW_VERSION & 0xff;
        data[1] = (DPOW_VERSION >> 8) & 0xff;
    }
    else if ( (data[0]+((int32_t)data[1]<<8)) != DPOW_VERSION )
        return(-1);
    len = 2;
    len += iguana_rwbignum(rwflag,&data[len],sizeof(*hashmsg),hashmsg->bytes);
    len += iguana_rwbignum(rwflag,&data[len],sizeof(ep->prev_hash),ep->prev_hash.bytes);
    if ( bits256_nonz(ep->prev_hash) == 0 )
        return(-1);
    len += iguana_rwbignum(rwflag,&data[len],sizeof(ep->commit),ep->commit.bytes);
    if ( rwflag != 0 )
    {
        data[len++] = ep->prev_vout;
        for (i=0; i<33; i++)
            data[len++] = ep->pubkey[i];
        data[len++] = ep->bestk;
    }
    else
    {
        ep->prev_vout = data[len++];
        for (i=0; i<33; i++)
            ep->pubkey[i] = data[len++];
        ep->bestk = data[len++];
    }
    len += iguana_rwbignum(rwflag,&data[len],sizeof(ep->recvmask),(uint8_t *)&ep->recvmask);
    return(len);
}

int32_t dpow_rwsigentry(int32_t rwflag,uint8_t *data,struct dpow_sigentry *dsig)
{
    int32_t i,len = 0;
    if ( rwflag != 0 )
    {
        data[len++] = DPOW_VERSION & 0xff;
        data[len++] = (DPOW_VERSION >> 8) & 0xff;
        data[len++] = dsig->senderind;
        data[len++] = dsig->lastk;
        len += iguana_rwnum(rwflag,&data[len],sizeof(dsig->mask),(uint8_t *)&dsig->mask);
        data[len++] = dsig->siglen;
        memcpy(&data[len],dsig->sig,dsig->siglen), len += dsig->siglen;
        for (i=0; i<sizeof(dsig->beacon); i++)
            data[len++] = dsig->beacon.bytes[i];
        for (i=0; i<33; i++)
            data[len++] = dsig->senderpub[i];
    }
    else
    {
        if ( (data[0]+((int32_t)data[1]<<8)) != DPOW_VERSION )
            return(-1);
        len = 2;
        memset(dsig,0,sizeof(*dsig));
        dsig->senderind = data[len++];
        if ( dsig->senderind < 0 || dsig->senderind >= DPOW_MAXRELAYS )
            return(-1);
        dsig->lastk = data[len++];
        len += iguana_rwnum(rwflag,&data[len],sizeof(dsig->mask),(uint8_t *)&dsig->mask);
        dsig->siglen = data[len++];
        memcpy(dsig->sig,&data[len],dsig->siglen), len += dsig->siglen;
        for (i=0; i<sizeof(dsig->beacon); i++)
            dsig->beacon.bytes[i] = data[len++];
        for (i=0; i<33; i++)
            dsig->senderpub[i] = data[len++];
    }
    return(len);
}

uint64_t dpow_lastk_mask(struct dpow_block *bp,int8_t *lastkp)
{
    int32_t j,m,k; uint64_t mask = 0;
    *lastkp = -1;
    for (j=m=0; j<bp->numnotaries; j++)
    {
        k = ((bp->height % bp->numnotaries) + j) % bp->numnotaries;
        if ( bits256_nonz(bp->notaries[k].prev_hash) != 0 )
        {
            bp->recvmask |= (1LL << k);
            mask |= (1LL << k);
            if ( ++m >= DPOW_M(bp) )
            {
                *lastkp = k;
                break;
            }
        }
    }
    return(mask);
}

int32_t dpow_bestk(struct dpow_block *bp,uint64_t *maskp)
{
    int8_t lastk; uint64_t mask;
    *maskp = 0;
    mask = dpow_lastk_mask(bp,&lastk);
    if ( lastk < 0 )
        return(-1);
    *maskp = mask;
    return(lastk);
}

uint64_t dpow_maskmin(uint64_t refmask,struct dpow_block *bp,int8_t *lastkp)
{
    int32_t j,m,k; uint64_t mask = 0;
    for (j=m=0; j<bp->numnotaries; j++)
    {
        k = ((bp->height % bp->numnotaries) + j) % bp->numnotaries;
        if ( bits256_nonz(bp->notaries[k].prev_hash) != 0 )
        {
            mask |= (1LL << k);
            if ( ++m >= DPOW_M(bp) )
            {
                *lastkp = k;
                break;
            }
        }
    }
    return(mask);
}

struct dpow_block *dpow_heightfind(struct supernet_info *myinfo,int32_t height,int32_t destflag)
{
    if ( destflag != 0 )
        return(myinfo->DPOW.destblocks!=0?myinfo->DPOW.destblocks[height]:0);
    else return(myinfo->DPOW.srcblocks!=0?myinfo->DPOW.srcblocks[height]:0);
}

struct dpow_entry *dpow_notaryfind(struct supernet_info *myinfo,struct dpow_block *bp,int32_t *senderindp,uint8_t *senderpub)
{
    int32_t i;
    *senderindp = -1;
    for (i=0; i<bp->numnotaries; i++)
    {
        if ( memcmp(bp->notaries[i].pubkey,senderpub,33) == 0 )
        {
            *senderindp = i;
            return(&bp->notaries[i]);
        }
    }
    return(0);
}

bits256 dpow_notarytx(char *signedtx,int32_t *numsigsp,int32_t isPoS,struct dpow_block *bp,char *src)
{
    uint32_t i,j,m,numsigs,locktime,numvouts,version,opretlen,siglen,len,sequenceid = 0xffffffff;
    uint64_t satoshis,satoshisB; uint8_t serialized[32768],opret[1024],data[4096];
    len = locktime = numsigs = 0;
    version = 1;
    len += iguana_rwnum(1,&serialized[len],sizeof(version),&version);
    if ( isPoS != 0 )
        len += iguana_rwnum(1,&serialized[len],sizeof(bp->timestamp),&bp->timestamp);
    m = DPOW_M(bp);
    len += iguana_rwvarint32(1,&serialized[len],(uint32_t *)&m);
    for (j=m=0; j<bp->numnotaries; j++)
    {
        i = ((bp->height % bp->numnotaries) + j) % bp->numnotaries;
        if ( ((1LL << i) & bp->bestmask) != 0 )
        {
            if ( bits256_nonz(bp->notaries[i].prev_hash) == 0 )
                return(bp->notaries[i].prev_hash);
            len += iguana_rwbignum(1,&serialized[len],sizeof(bp->notaries[i].prev_hash),bp->notaries[i].prev_hash.bytes);
            len += iguana_rwnum(1,&serialized[len],sizeof(bp->notaries[i].prev_vout),&bp->notaries[i].prev_vout);
            siglen = bp->notaries[i].siglens[bp->bestk];
            len += iguana_rwvarint32(1,&serialized[len],&siglen);
            if ( siglen > 0 )
            {
                memcpy(&serialized[len],bp->notaries[i].sigs[bp->bestk],siglen);
                len += siglen;
                numsigs++;
            }
            len += iguana_rwnum(1,&serialized[len],sizeof(sequenceid),&sequenceid);
            //printf("height.%d mod.%d VINI.%d <- i.%d j.%d\n",height,height % numnotaries,m,i,j);
            m++;
            if ( m == DPOW_M(bp) && i == bp->bestk )
                break;
        }
    }
    numvouts = 2;
    len += iguana_rwvarint32(1,&serialized[len],&numvouts);
    satoshis = DPOW_UTXOSIZE * m * .76;
    if ( (satoshisB= DPOW_UTXOSIZE * m - 10000) < satoshis )
        satoshis = satoshisB;
    len += iguana_rwnum(1,&serialized[len],sizeof(satoshis),&satoshis);
    serialized[len++] = 35;
    serialized[len++] = 33;
    decode_hex(&serialized[len],33,CRYPTO777_PUBSECPSTR), len += 33;
    serialized[len++] = CHECKSIG;
    satoshis = 0;
    len += iguana_rwnum(1,&serialized[len],sizeof(satoshis),&satoshis);
    opretlen = dpow_rwopret(1,opret,&bp->hashmsg,&bp->height,&bp->btctxid,src);
    opretlen = dpow_opreturnscript(data,opret,opretlen);
    if ( opretlen < 0xfd )
        serialized[len++] = opretlen;
    else
    {
        serialized[len++] = 0xfd;
        serialized[len++] = opretlen & 0xff;
        serialized[len++] = (opretlen >> 8) & 0xff;
    }
    memcpy(&serialized[len],data,opretlen), len += opretlen;
    len += iguana_rwnum(1,&serialized[len],sizeof(locktime),&locktime);
    init_hexbytes_noT(signedtx,serialized,len);
    //printf("notarytx.(%s) opretlen.%d\n",signedtx,opretlen);
    *numsigsp = numsigs;
    return(bits256_doublesha256(0,serialized,len));
}

bits256 dpow_getbestblockhash(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char *retstr; bits256 blockhash;
    memset(blockhash.bytes,0,sizeof(blockhash));
    if ( coin->FULLNODE < 0 )
    {
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getbestblockhash","")) != 0 )
        {
            //printf("%s getbestblockhash.(%s)\n",coin->symbol,retstr);
            if ( is_hexstr(retstr,0) == sizeof(blockhash)*2 )
                decode_hex(blockhash.bytes,sizeof(blockhash),retstr);
            free(retstr);
        }
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        blockhash = coin->blocks.hwmchain.RO.hash2;
    }
    else
    {
        
    }
    return(blockhash);
}

cJSON *dpow_getblock(struct supernet_info *myinfo,struct iguana_info *coin,bits256 blockhash)
{
    char buf[128],str[65],*retstr=0; cJSON *json = 0;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"\"%s\"",bits256_str(str,blockhash));
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getblock",buf);
        //printf("%s getblock.(%s)\n",coin->symbol,retstr);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_getblock(myinfo,coin,0,0,blockhash,1,0);
    }
    else
    {
        return(0);
    }
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
    }
    return(json);
}

char *dpow_decoderawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx)
{
    char *retstr,*paramstr; cJSON *array;
    if ( coin->FULLNODE < 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,rawtx);
        paramstr = jprint(array,1);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"decoderawtransaction",paramstr);
        //printf("%s decoderawtransaction.(%s) <- (%s)\n",coin->symbol,retstr,paramstr);
        free(paramstr);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_decoderawtransaction(myinfo,coin,0,0,rawtx,1);
    }
    else
    {
        return(0);
    }
    return(retstr);
}

cJSON *dpow_gettransaction(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid)
{
    char buf[128],str[65],*retstr=0,*rawtx=0; cJSON *json = 0;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"[\"%s\", 1]",bits256_str(str,txid));
        if ( (rawtx= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getrawtransaction",buf)) != 0 )
        {
            retstr = dpow_decoderawtransaction(myinfo,coin,rawtx);
            free(rawtx);
        }
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_getrawtransaction(myinfo,coin,0,0,txid,1);
    }
    else
    {
        return(0);
    }
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
    }
    return(json);
}

cJSON *dpow_listunspent(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    char buf[128],*retstr; cJSON *json = 0;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"0, 99999999, [\"%s\"]",coinaddr);
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"listunspent",buf)) != 0 )
        {
            json = cJSON_Parse(retstr);
            //printf("%s (%s) listunspent.(%s)\n",coin->symbol,buf,retstr);
            free(retstr);
        } else printf("%s null retstr from (%s)n",coin->symbol,buf);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        json = iguana_listunspents(myinfo,coin,0,1,coin->longestchain,"");
    }
    else
    {
        return(0);
    }
    return(json);
}

char *dpow_signrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx,cJSON *vins)
{
    cJSON *array,*privkeys,*item; char *wifstr,*str,*paramstr,*retstr; uint8_t script[256]; int32_t i,n,len,hashtype; struct vin_info V; struct iguana_waddress *waddr; struct iguana_waccount *wacct;
    if ( 0 )//coin->FULLNODE < 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,rawtx);
        jaddi(array,vins);
        paramstr = jprint(array,1);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"signrawtransaction",paramstr);
        //printf("%s signrawtransaction.(%s) params.(%s)\n",coin->symbol,retstr,paramstr);
        free(paramstr);
        return(retstr);
    }
    else if ( 1 )//coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        privkeys = cJSON_CreateArray();
        if ( (n= cJSON_GetArraySize(vins)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                wifstr = "";
                item = jitem(vins,i);
                if ( (str= jstr(item,"scriptPubkey")) != 0 && is_hexstr(str,0) > 0 && strlen(str) < sizeof(script)*2 )
                {
                    len = (int32_t)strlen(str) >> 1;
                    decode_hex(script,len,str);
                    V.spendlen = len;
                    memcpy(V.spendscript,script,len);
                    if ( (hashtype= _iguana_calcrmd160(coin,&V)) >= 0 && V.coinaddr[0] != 0 )
                    {
                        if ( (waddr= iguana_waddresssearch(myinfo,&wacct,V.coinaddr)) != 0 )
                        {
                            if ( bits256_nonz(waddr->privkey) != 0 )
                            {
                                if ( bitcoin_priv2wif(waddr->wifstr,waddr->privkey,coin->chain->wiftype) > 0 )
                                {
                                    wifstr = waddr->wifstr;
                                }
                            }
                        }
                    }
                }
                jaddistr(privkeys,wifstr);
            }
        }
        retstr = bitcoinrpc_signrawtransaction(myinfo,coin,0,0,rawtx,vins,privkeys,"ALL");
        free_json(privkeys);
        return(retstr);
    }
    else
    {
        return(0);
    }
}

char *dpow_sendrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *signedtx)
{
    bits256 txid; cJSON *json,*array; char *paramstr,*retstr;
    if ( coin->FULLNODE < 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,signedtx);
        paramstr = jprint(array,1);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"sendrawtransaction",paramstr);
        printf(">>>>>>>>>>> %s sendrawtransaction.(%s) -> %s\n",coin->symbol,paramstr,retstr);
        free(paramstr);
        return(retstr);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        txid = iguana_sendrawtransaction(myinfo,coin,signedtx);
        json = cJSON_CreateObject();
        jaddbits256(json,"result",txid);
        return(jprint(json,1));
    }
    else
    {
        return(0);
    }
}

int32_t dpow_getchaintip(struct supernet_info *myinfo,bits256 *blockhashp,uint32_t *blocktimep,bits256 *txs,uint32_t *numtxp,struct iguana_info *coin)
{
    int32_t n,i,height = -1,maxtx = *numtxp; bits256 besthash; cJSON *array,*json;
    *numtxp = *blocktimep = 0;
    *blockhashp = besthash = dpow_getbestblockhash(myinfo,coin);
    if ( bits256_nonz(besthash) != 0 )
    {
        if ( (json= dpow_getblock(myinfo,coin,besthash)) != 0 )
        {
            if ( (height= juint(json,"height")) != 0 && (*blocktimep= juint(json,"time")) != 0 )
            {
                if ( (array= jarray(&n,json,"tx")) != 0 )
                {
                    for (i=0; i<n&&i<maxtx; i++)
                        txs[i] = jbits256i(array,i);
                    //printf("dpow_getchaintip %s ht.%d time.%u numtx.%d\n",coin->symbol,height,*blocktimep,n);
                    *numtxp = n;
                }
            } else height = -1;
            free_json(json);
        }
    }
    return(height);
}

int32_t dpow_vini_ismine(struct supernet_info *myinfo,cJSON *item)
{
    cJSON *sobj; char *hexstr; int32_t len; uint8_t data[35];
    if ( (sobj= jobj(item,"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 )
    {
        len = (int32_t)strlen(hexstr) >> 1;
        if ( len <= sizeof(data) )
        {
            decode_hex(data,len,hexstr);
            if ( len == 35 && data[34] == CHECKSIG && data[0] == 33 && memcmp(data+1,myinfo->DPOW.minerkey33,33) == 0 )
                return(0);
        }
    }
    return(-1);
}

int32_t dpow_haveutxo(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,int32_t *voutp,char *coinaddr)
{
    int32_t i,n,vout,haveutxo = 0; bits256 txid; cJSON *unspents,*item; uint64_t satoshis; char *str,*address; uint8_t script[35];
    memset(txidp,0,sizeof(*txidp));
    *voutp = -1;
    if ( (unspents= dpow_listunspent(myinfo,coin,coinaddr)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(unspents)) > 0 )
        {
            /*{
             "txid" : "34bc21b40d6baf38e2db5be5353dd0bcc9fe416485a2a68753541ed2f9c194b1",
             "vout" : 0,
             "address" : "RFBmvBaRybj9io1UpgWM4pzgufc3E4yza7",
             "scriptPubKey" : "21039a3f7373ae91588b9edd76a9088b2871f62f3438d172b9f18e0581f64887404aac",
             "amount" : 3.00000000,
             "confirmations" : 4282,
             "spendable" : true
             },*/
            for (i=0; i<n; i++)
            {
                item = jitem(unspents,i);
                satoshis = SATOSHIDEN * jdouble(item,"amount");
                if ( satoshis == DPOW_UTXOSIZE && (address= jstr(item,"address")) != 0 && strcmp(address,coinaddr) == 0 )
                {
                    if ( (str= jstr(item,"scriptPubKey")) != 0 && is_hexstr(str,0) == sizeof(script)*2 )
                    {
                        txid = jbits256(item,"txid");
                        vout = jint(item,"vout");
                        if ( bits256_nonz(txid) != 0 && vout >= 0 )
                        {
                            if ( *voutp < 0 )
                            {
                                *voutp = vout;
                                *txidp = txid;
                            }
                            haveutxo++;
                        }
                    }
                }
            }
            if ( haveutxo == 0 )
                printf("no utxo: need to fund address.(%s) or wait for splitfund to confirm\n",coinaddr);
        } else printf("null utxo array size\n");
        free_json(unspents);
    } else printf("null return from dpow_listunspent\n");
    if ( haveutxo > 0 )
        printf("%s haveutxo.%d\n",coin->symbol,haveutxo);
    return(haveutxo);
}

cJSON *dpow_createtx(struct iguana_info *coin,cJSON **vinsp,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t usesigs)
{
    int32_t i,j,m=0,siglen; char scriptstr[256]; cJSON *txobj=0,*vins=0,*item; uint64_t satoshis; uint8_t script[35],*sig;
    if ( (txobj= bitcoin_txcreate(coin->chain->isPoS,0,1,0)) != 0 )
    {
        jaddnum(txobj,"suppress",1);
        jaddnum(txobj,"timestamp",bp->timestamp);
        vins = cJSON_CreateArray();
        for (j=0; j<bp->numnotaries; j++)
        {
            i = ((bp->height % bp->numnotaries) + j) % bp->numnotaries;
            if ( ((1LL << i) & bestmask) != 0 )
            {
                if ( bits256_nonz(bp->notaries[i].prev_hash) != 0 )
                {
                    item = cJSON_CreateObject();
                    jaddbits256(item,"txid",bp->notaries[i].prev_hash);
                    jaddnum(item,"vout",bp->notaries[i].prev_vout);
                    script[0] = 33;
                    memcpy(script+1,bp->notaries[i].pubkey,33);
                    script[34] = CHECKSIG;
                    init_hexbytes_noT(scriptstr,script,35);
                    jaddstr(item,"scriptPubKey",scriptstr);
                    sig = 0, siglen = 0;
                    if ( usesigs != 0 && bp->notaries[i].siglens[bestk] > 0 )
                    {
                        init_hexbytes_noT(scriptstr,bp->notaries[i].sigs[bestk],bp->notaries[i].siglens[bestk]);
                        jaddstr(item,"scriptSig",scriptstr);
                        //printf("sig%d.(%s)\n",i,scriptstr);
                        sig = bp->notaries[i].sigs[bestk];
                        siglen = bp->notaries[i].siglens[bestk];
                    }
                    jaddi(vins,item);
                    bitcoin_txinput(coin,txobj,bp->notaries[i].prev_hash,bp->notaries[i].prev_vout,0xffffffff,script,sizeof(script),0,0,0,0,sig,siglen);
                    //printf("height.%d mod.%d VINI.%d <- i.%d j.%d\n",height,height % numnotaries,m,i,j);
                    m++;
                    if ( m == DPOW_M(bp) && i == bestk )
                        break;
                }
                else
                {
                    free_json(vins), vins = 0;
                    free_json(txobj);
                    return(0);
                }
            }
        }
        satoshis = DPOW_UTXOSIZE * m * .76;
        script[0] = 33;
        decode_hex(script+1,33,CRYPTO777_PUBSECPSTR);
        script[34] = CHECKSIG;
        txobj = bitcoin_txoutput(txobj,script,sizeof(script),satoshis);
    }
    *vinsp = vins;
    if ( 0 && usesigs != 0 )
        printf("%s createtx.(%s)\n",coin->symbol,jprint(txobj,0));
    return(txobj);
}

void dpow_sigsend(struct supernet_info *myinfo,struct dpow_block *bp,int32_t myind,int8_t bestk,uint64_t bestmask,bits256 srchash,uint32_t sigchannel)
{
    struct dpow_sigentry dsig; int32_t i,len; uint8_t data[4096]; struct dpow_entry *ep;
    ep = &bp->notaries[myind];
    //printf("myind.%d bestk.%d %llx\n",myind,bestk,(long long)bestmask);
    memset(&dsig,0,sizeof(dsig));
    for (i=0; i<33; i++)
        dsig.senderpub[i] = myinfo->DPOW.minerkey33[i];
    dsig.lastk = bestk;
    dsig.mask = bestmask;
    dsig.senderind = myind;
    dsig.beacon = bp->beacon;
    dsig.siglen = ep->siglens[bestk];
    memcpy(dsig.sig,ep->sigs[bestk],ep->siglens[bestk]);
    memcpy(dsig.senderpub,myinfo->DPOW.minerkey33,33);
    len = dpow_rwsigentry(1,data,&dsig);
    dpow_send(myinfo,bp,srchash,bp->hashmsg,sigchannel,bp->height,data,len,bp->sigcrcs);
}

void dpow_rawtxsign(struct supernet_info *myinfo,struct iguana_info *coin,struct dpow_block *bp,char *rawtx,cJSON *vins,int8_t bestk,uint64_t bestmask,int32_t myind,uint32_t sigchannel)
{
    int32_t j,m=0,flag=0,retval=-1; char *jsonstr,*signedtx,*rawtx2,*sigstr; cJSON *signobj,*sobj,*txobj2,*item,*vin; bits256 srchash; struct dpow_entry *ep = &bp->notaries[myind];
    /*if ( vins == 0 && bitweight(bestmask) == DPOW_M(bp) )
    {
        if ( (rawtx2= dpow_decoderawtransaction(myinfo,coin,rawtx)) != 0 )
        {
            if ( (txobj= cJSON_Parse(rawtx2)) != 0 )
            {
                vins = jduplicate(jobj(txobj,"vin"));
                free_json(txobj);
                //printf("generated vins.(%s)\n",jprint(vins,0));
            }
            free(rawtx2);
        }
        if ( vins != 0 )
        {
            flag = 1;
            n = cJSON_GetArraySize(vins);
            k = (bp->height % bp->numnotaries) % bp->numnotaries;
            for (i=0; i<n; i++)
            {
                while ( ((1LL << k) & bestmask) == 0 )
                    if ( ++k >= bp->numnotaries )
                        k = 0;
                item = jitem(vins,i);
                //printf("(%s) i.%d of %d, (%d) k.%d bestmask.%llx\n",jprint(item,0),i,n,(bp->height % bp->numnotaries) % bp->numnotaries,k,(long long)bestmask);
                if ( bits256_nonz(bp->notaries[k].prev_hash) == 0 )
                {
                    bp->notaries[k].prev_hash = jbits256(item,"txid");
                    if ( bits256_nonz(bp->notaries[k].prev_hash) != 0 )
                    {
                        bp->notaries[k].prev_vout = jint(item,"vout");
                        bp->recvmask |= (1LL << k);
                        printf(">>>>>>>> rawtx utxo.%d %s/v%d %llx\n",k,bits256_str(str,bp->notaries[k].prev_hash),bp->notaries[k].prev_vout,(long long)bp->recvmask);
                    }
                }
                if ( i < n-1 )
                    k++;
            }
            if ( k != bestk )
                printf("extracted uxto k.%d != bestk.%d %llx\n",k,bestk,(long long)bestmask);
        }
    }*/
    m = 0;
    if ( (jsonstr= dpow_signrawtransaction(myinfo,coin,rawtx,vins)) != 0 )
    {
        //printf("mask.%llx dpowsign.(%s)\n",(long long)mask,jsonstr);
        if ( (signobj= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( ((signedtx= jstr(signobj,"hex")) != 0 || (signedtx= jstr(signobj,"result")) != 0) && (rawtx2= dpow_decoderawtransaction(myinfo,coin,signedtx)) != 0 )
            {
                if ( (txobj2= cJSON_Parse(rawtx2)) != 0 )
                {
                    if ( (vin= jarray(&m,txobj2,"vin")) != 0 )
                    {
                        for (j=0; j<m; j++)
                        {
                            item = jitem(vin,j);
                            if ( (sobj= jobj(item,"scriptSig")) != 0 && (sigstr= jstr(sobj,"hex")) != 0 && strlen(sigstr) > 32 )
                            {
                                //printf("height.%d mod.%d VINI.%d myind.%d MINE.(%s) j.%d\n",height,height%numnotaries,j,myind,jprint(item,0),j);
                                ep->siglens[bestk] = (int32_t)strlen(sigstr) >> 1;
                                decode_hex(ep->sigs[bestk],ep->siglens[bestk],sigstr);
                                ep->masks[bestk] = bestmask;
                                ep->siglens[bestk] = ep->siglens[bestk];
                                ep->beacon = bp->beacon;
                                dpow_sigsend(myinfo,bp,myind,bestk,bestmask,srchash,sigchannel);
                                retval = 0;
                                break;
                            } // else printf("notmine.(%s)\n",jprint(item,0));
                        }
                    } else printf("no vin[] (%s)\n",jprint(txobj2,0));
                    free_json(txobj2);
                } else printf("cant parse.(%s)\n",rawtx2);
                free(rawtx2);
            } //else printf("error decoding (%s) %s\n",signedtx==0?"":signedtx,jsonstr);
            free_json(signobj);
        } else printf("error parsing.(%s)\n",jsonstr);
        free(jsonstr);
    }
    if ( flag != 0 && vins != 0 )
        free_json(vins);
}

int32_t dpow_signedtxgen(struct supernet_info *myinfo,struct iguana_info *coin,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t myind,char *opret_symbol,uint32_t sigchannel)
{
    int32_t j,incr,numsigs,retval=-1; char rawtx[32768]; cJSON *txobj,*vins; bits256 txid,srchash,zero; struct dpow_entry *ep;
    if ( bp->numnotaries < 8 )
        incr = 1;
    else incr = sqrt(bp->numnotaries) + 1;
    bestmask = dpow_maskmin(bestmask,bp,&bestk);
    ep = &bp->notaries[myind];
    memset(&zero,0,sizeof(zero));
    if ( bestk < 0 )
        return(-1);
    for (j=0; j<sizeof(srchash); j++)
        srchash.bytes[j] = myinfo->DPOW.minerkey33[j+1];
    if ( (txobj= dpow_createtx(coin,&vins,bp,bestk,bestmask,0)) != 0 )
    {
        txid = dpow_notarytx(rawtx,&numsigs,coin->chain->isPoS,bp,opret_symbol);
        if ( bits256_nonz(txid) != 0 && rawtx[0] != 0 ) // send tx to share utxo set
        {
            /*memset(&tmp,0,sizeof(tmp));
            tmp.ulongs[1] = bestmask;
            tmp.bytes[31] = bestk;
            len = (int32_t)strlen(rawtx) >> 1;
            decode_hex(txdata+32,len,rawtx);
            for (j=0; j<sizeof(srchash); j++)
                txdata[j] = tmp.bytes[j];
            dpow_send(myinfo,bp,zero,bp->hashmsg,(bits256_nonz(bp->btctxid) == 0) ? DPOW_BTCTXIDCHANNEL : DPOW_TXIDCHANNEL,bp->height,txdata,len+32,bp->txidcrcs);*/
            dpow_rawtxsign(myinfo,coin,bp,rawtx,vins,bestk,bestmask,myind,sigchannel);
        }
        free_json(txobj);
        //fprintf(stderr,"free vins\n");
        //free_json(vins);
    }
    return(retval);
}

void dpow_sigscheck(struct supernet_info *myinfo,struct dpow_block *bp,uint32_t channel,int32_t myind)
{
    bits256 txid,srchash,zero; int32_t j,len,numsigs; char *retstr=0,str[65],str2[65]; uint8_t txdata[32768];
    memset(zero.bytes,0,sizeof(zero));
    if ( bp->state != 0xffffffff && bp->coin != 0 )
    {
        bp->signedtxid = dpow_notarytx(bp->signedtx,&numsigs,bp->coin->chain->isPoS,bp,bp->opret_symbol);
        printf("%s numsigs.%d signedtx.(%s)\n",bits256_str(str,bp->signedtxid),numsigs,bp->signedtx);
        bp->state = 1;
        if ( bits256_nonz(bp->signedtxid) != 0 && numsigs == DPOW_M(bp) )
        {
            if ( (retstr= dpow_sendrawtransaction(myinfo,bp->coin,bp->signedtx)) != 0 )
            {
                printf("sendrawtransaction.(%s)\n",retstr);
                if ( is_hexstr(retstr,0) == sizeof(txid)*2 )
                {
                    decode_hex(txid.bytes,sizeof(txid),retstr);
                    if ( bits256_cmp(txid,bp->signedtxid) == 0 )
                    {
                        len = (int32_t)strlen(bp->signedtx) >> 1;
                        decode_hex(txdata+32,len,bp->signedtx);
                        for (j=0; j<sizeof(srchash); j++)
                            txdata[j] = txid.bytes[j];
                        dpow_send(myinfo,bp,txid,bp->hashmsg,(channel == DPOW_SIGBTCCHANNEL) ? DPOW_BTCTXIDCHANNEL : DPOW_TXIDCHANNEL,bp->height,txdata,len+32,bp->txidcrcs);
                        printf("complete statemachine.%s ht.%d\n",bp->coin->symbol,bp->height);
                        bp->state = 0xffffffff;
                    } else printf("sendtxid mismatch got %s instead of %s\n",bits256_str(str,txid),bits256_str(str2,bp->signedtxid));
                }
                free(retstr);
                retstr = 0;
            }
        }
    }
}

void dpow_datahandler(struct supernet_info *myinfo,struct dpow_block *bp,uint32_t channel,uint32_t height,uint8_t *data,int32_t datalen)
{
    bits256 hashmsg,txid,commit,srchash; uint32_t flag = 0; uint64_t mask; int8_t lastk; int32_t senderind,i,j,r,vout,len,myind = -1; char str[65],str2[65]; uint8_t utxodata[1024]; struct dpow_sigentry dsig; struct dpow_entry *ep,E;
    if ( channel == DPOW_UTXOCHANNEL || channel == DPOW_UTXOBTCCHANNEL )
    {
        memset(&E,0,sizeof(E));
        if ( dpow_rwutxobuf(0,data,&hashmsg,&E) < 0 )
            return;
        if ( bp != 0 || (bp= dpow_heightfind(myinfo,height,channel == DPOW_UTXOBTCCHANNEL)) != 0 )
        {
            dpow_notaryfind(myinfo,bp,&myind,myinfo->DPOW.minerkey33);
            if ( myind < 0 )
                return;
            if ( bits256_cmp(hashmsg,bp->hashmsg) != 0 )
            {
                printf("unexpected mismatch hashmsg.%s vs %s\n",bits256_str(str,hashmsg),bits256_str(str2,bp->hashmsg));
                return;
            }
            if ( (ep= dpow_notaryfind(myinfo,bp,&senderind,E.pubkey)) != 0 )
            {
                if ( bits256_nonz(ep->prev_hash) == 0 )
                {
                    *ep = E;
                    bp->recvmask |= (1LL << senderind);
                    if ( (bp->recvmask ^ E.recvmask) != 0 )
                    {
                        if ( ((1LL << myind) & E.recvmask) == 0 )
                            i = myind;
                        else
                        {
                            r = (rand() % bp->numnotaries);
                            for (j=0; j<DPOW_M(bp); j++)
                            {
                                i = ((bp->height % bp->numnotaries) + j + r) % bp->numnotaries;
                                if ( ((1LL << i) & bp->recvmask) != 0 && ((1LL << i) & bp->recvmask) == 0 )
                                    break;
                            }
                        }
                        printf("sender.%d %llx doesnt have ours %llx\n",senderind,(long long)E.recvmask,(long long)(1LL << i));
                        if ( (len= dpow_rwutxobuf(1,utxodata,&bp->hashmsg,&bp->notaries[i])) > 0 )
                            dpow_send(myinfo,bp,srchash,bp->hashmsg,channel,bp->height,utxodata,len,bp->utxocrcs);
                    }
                    mask = dpow_maskmin(ep->recvmask,bp,&lastk);
                    if ( (mask & bp->recvmask) == mask )
                        dpow_signedtxgen(myinfo,bp->coin,bp,ep->bestk,mask,myind,bp->opret_symbol,bits256_nonz(bp->btctxid) == 0 ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL);
                    flag = 1;
                    printf("<<<<<<<<<< %s from.%ld got ht.%d %s/v%d\n",bp->coin->symbol,((long)ep - (long)bp->notaries)/sizeof(*ep),height,bits256_str(str,E.prev_hash),E.prev_vout);
                }
            }
        }
        if ( 0 && flag == 0 && bp != 0 )
            printf("UTXO.%d hashmsg.(%s) txid.(%s) v%d\n",height,bits256_str(str,hashmsg),bits256_str(str2,E.prev_hash),vout);
    }
    else if ( channel == DPOW_SIGCHANNEL || channel == DPOW_SIGBTCCHANNEL )
    {
        if ( dpow_rwsigentry(0,data,&dsig) < 0 )
            return;
        if ( dsig.senderind >= 0 && dsig.senderind < DPOW_MAXRELAYS && (bp != 0 || (bp= dpow_heightfind(myinfo,height,channel == DPOW_SIGBTCCHANNEL)) != 0) )
        {
            dpow_notaryfind(myinfo,bp,&myind,myinfo->DPOW.minerkey33);
            if ( myind < 0 )
                return;
            if ( dsig.lastk < bp->numnotaries && dsig.senderind < bp->numnotaries && (ep= dpow_notaryfind(myinfo,bp,&senderind,dsig.senderpub)) != 0 )
            {
                vcalc_sha256(0,commit.bytes,dsig.beacon.bytes,sizeof(dsig.beacon));
                if ( memcmp(dsig.senderpub,bp->notaries[dsig.senderind].pubkey,33) == 0 ) //bits256_cmp(ep->commit,commit) == 0 &&
                {
                    if ( ep->masks[dsig.lastk] == 0 )
                    {
                        ep->masks[dsig.lastk] = dsig.mask;
                        ep->siglens[dsig.lastk] = dsig.siglen;
                        memcpy(ep->sigs[dsig.lastk],dsig.sig,dsig.siglen);
                        ep->beacon = dsig.beacon;
                        //for (j=0; j<dsig.siglen; j++)
                        //    printf("%02x",dsig.sig[j]);
                        printf(" <<<<<<<< %s from.%d got lastk.%d %llx siglen.%d >>>>>>>>>\n",bp->coin->symbol,dsig.senderind,dsig.lastk,(long long)dsig.mask,dsig.siglen);
                        mask = dpow_maskmin(ep->recvmask,bp,&lastk);
                        if ( (mask & bp->recvmask) == mask )
                            dpow_signedtxgen(myinfo,bp->coin,bp,dsig.lastk,mask,myind,bp->opret_symbol,bits256_nonz(bp->btctxid) == 0 ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL);
                        if ( ((1LL << myind) & dsig.mask) == 0 )
                        {
                            printf("B sender.%d %llx doesnt have ours %llx\n",dsig.senderind,(long long)dsig.mask,(long long)(1LL << myind));
                            if ( (len= dpow_rwutxobuf(1,utxodata,&bp->hashmsg,&bp->notaries[myind])) > 0 )
                                dpow_send(myinfo,bp,srchash,bp->hashmsg,channel,bp->height,utxodata,len,bp->utxocrcs);
                        }
                        flag = 1;
                    }
                } else printf("%s pubkey mismatch for senderind.%d %llx vs %llx\n",bp->coin->symbol,dsig.senderind,*(long long *)dsig.senderpub,*(long long *)bp->notaries[dsig.senderind].pubkey);
            } else printf("%s illegal lastk.%d or senderind.%d or senderpub.%llx\n",bp->coin->symbol,dsig.lastk,dsig.senderind,*(long long *)dsig.senderpub);
        } else printf("couldnt find senderind.%d height.%d channel.%x\n",dsig.senderind,height,channel);
        if ( 0 && bp != 0 )
            printf(" SIG.%d sender.%d lastk.%d mask.%llx siglen.%d recv.%llx\n",height,dsig.senderind,dsig.lastk,(long long)dsig.mask,dsig.siglen,(long long)bp->recvmask);
    }
    else if ( channel == DPOW_TXIDCHANNEL || channel == DPOW_BTCTXIDCHANNEL )
    {
        if ( bp != 0 || (bp= dpow_heightfind(myinfo,height,channel == DPOW_BTCTXIDCHANNEL)) != 0 )
        {
            if ( bp->state != 0xffffffff )
            {
                for (i=0; i<32; i++)
                    srchash.bytes[i] = data[i];
                /*if ( srchash.ulongs[0] == 0 )
                {
                    init_hexbytes_noT(bp->rawtx,&data[32],datalen-32);
                    //printf("got bestk.%d %llx rawtx.(%s) set utxo\n",srchash.bytes[31],(long long)srchash.ulongs[1],bp->rawtx);
                    dpow_rawtxsign(myinfo,bp->coin,bp,bp->rawtx,0,srchash.bytes[31],srchash.ulongs[1],myind,bits256_nonz(bp->btctxid) == 0 ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL);
                }
                else*/
                {
                    txid = bits256_doublesha256(0,&data[32],datalen-32);
                    init_hexbytes_noT(bp->signedtx,&data[32],datalen-32);
                    if ( bits256_cmp(txid,srchash) == 0 )
                    {
                        printf("verify (%s) it is properly signed! set ht.%d signedtxid to %s\n",bp->coin->symbol,height,bits256_str(str,txid));
                        bp->signedtxid = txid;
                        bp->state = 0xffffffff;
                    }
                    else
                    {
                        init_hexbytes_noT(bp->signedtx,data,datalen);
                        printf("txidchannel txid %s mismatch %s (%s)\n",bits256_str(str,txid),bits256_str(str2,srchash),bp->signedtx);
                        bp->signedtx[0] = 0;
                    }
                }
            }
        } else printf("txidchannel cant find bp for %d\n",height);
    }
}

/*void dpow_handler(struct supernet_info *myinfo,struct basilisk_message *msg)
{
    bits256 srchash,desthash; uint32_t channel,height;
    basilisk_messagekeyread(msg->key,&channel,&height,&srchash,&desthash);
    dpow_datahandler(myinfo,0,channel,height,msg->data,msg->datalen);
}

void dpow_channelget(struct supernet_info *myinfo,struct dpow_block *bp,uint32_t channel)
{
    bits256 zero; cJSON *retarray,*item,*item2,*messages; char *datastr; int32_t i,n,j,m,datalen; uint8_t data[32768];
    memset(zero.bytes,0,sizeof(zero));
    if ( (retarray= basilisk_channelget(myinfo,zero,zero,channel,bp->height,1)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(retarray)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(retarray,i);
                if ( (messages= jarray(&m,item,"messages")) != 0 )
                {
                    for (j=0; j<m; j++)
                    {
                        item2 = jitem(messages,j);
                        if ( (datastr= jstr(item2,"data")) != 0 && (datalen= (int32_t)strlen(datastr)) < sizeof(data)*2 )
                        {
                            datalen >>= 1;
                            decode_hex(data,datalen,datastr);
                            dpow_datahandler(myinfo,bp,channel,bp->height,data,datalen);
                        }
                    }
                }
            }
        }
        free_json(retarray);
    }
}*/

int32_t dpow_update(struct supernet_info *myinfo,struct dpow_block *bp,uint32_t channel,uint32_t sigchannel,uint32_t txidchannel,bits256 srchash,int32_t myind)
{
    struct dpow_entry *ep;
    ep = &bp->notaries[myind];
    //dpow_channelget(myinfo,bp,channel);
    if ( (bp->bestk= dpow_bestk(bp,&bp->bestmask)) >= 0 )
    {
        if ( ep->masks[bp->bestk] == 0 )
            dpow_signedtxgen(myinfo,bp->coin,bp,bp->bestk,bp->bestmask,myind,bp->opret_symbol,sigchannel);
        //else dpow_sigsend(myinfo,bp,myind,bp->bestk,bp->bestmask,srchash,sigchannel);

    }
    //dpow_channelget(myinfo,bp,txidchannel);
    if ( bp->state != 0xffffffff )
    {
        //dpow_channelget(myinfo,bp,sigchannel);
        if ( ep->masks[bp->bestk] == 0 )
            dpow_signedtxgen(myinfo,bp->coin,bp,bp->bestk,bp->bestmask,myind,bp->opret_symbol,sigchannel);
        //else dpow_sigsend(myinfo,bp,myind,bp->bestk,bp->bestmask,srchash,sigchannel);
    }
    return(bp->state);
}

uint32_t dpow_statemachineiterate(struct supernet_info *myinfo,struct dpow_info *dp,struct iguana_info *coin,struct dpow_block *bp,int32_t myind)
{
    // todo: add RBF support
    int32_t j,match,sigmatch,len,vout,incr,haveutxo = 0; cJSON *addresses; char *sendtx,*rawtx,*opret_symbol,coinaddr[64]; uint32_t channel,sigchannel,txidchannel; bits256 txid,srchash,zero; uint8_t data[4096]; int8_t lastk; uint64_t sigsmask;
    if ( bp->numnotaries > 8 )
        incr = sqrt(bp->numnotaries) + 1;
    else incr = 1;
    memset(zero.bytes,0,sizeof(zero));
    if ( bits256_nonz(bp->btctxid) == 0 )
    {
        channel = DPOW_UTXOBTCCHANNEL;
        sigchannel = DPOW_SIGBTCCHANNEL;
        txidchannel = DPOW_BTCTXIDCHANNEL;
        opret_symbol = "";
    }
    else
    {
        channel = DPOW_UTXOCHANNEL;
        sigchannel = DPOW_SIGCHANNEL;
        txidchannel = DPOW_TXIDCHANNEL;
        opret_symbol = dp->symbol;
    }
    bitcoin_address(coinaddr,coin->chain->pubtype,myinfo->DPOW.minerkey33,33);
    if ( bits256_nonz(bp->hashmsg) == 0 )
        return(0xffffffff);
    for (j=0; j<sizeof(srchash); j++)
        srchash.bytes[j] = myinfo->DPOW.minerkey33[j+1];
    if ( bits256_nonz(bp->signedtxid) != 0 )
        bp->state = 0xffffffff;
    sigsmask = match = sigmatch = 0;
    if ( (bp->bestk= dpow_bestk(bp,&bp->bestmask)) >= 0 )
    {
        for (j=0; j<bp->numnotaries; j++)
        {
            if ( bp->notaries[j].masks[bp->bestk] == bp->bestmask )
            {
                match++;
                if ( bp->notaries[j].siglens[bp->bestk] > 0 )
                {
                    sigmatch++;
                    sigsmask |= (1LL << j);
                }
            }
        }
    }
    if ( (rand() % 10) == 0 )
        printf("%s ht.%d FSM.%d %s BTC.%d masks.%llx best.(%d %llx) match.(%d sigs.%d) sigsmask.%llx\n",coin->symbol,bp->height,bp->state,coinaddr,bits256_nonz(bp->btctxid)==0,(long long)bp->recvmask,bp->bestk,(long long)bp->bestmask,match,sigmatch,(long long)sigsmask);
    if ( sigmatch == DPOW_M(bp) )
    {
        printf("sigmatch.%d\n",sigmatch);
        dpow_sigscheck(myinfo,bp,sigchannel,myind);
    }
    switch ( bp->state )
    {
        case 0:
            if ( (haveutxo= dpow_haveutxo(myinfo,coin,&txid,&vout,coinaddr)) != 0 && bits256_nonz(txid) != 0 )
            {
                bp->notaries[myind].prev_hash = txid;
                bp->notaries[myind].prev_vout = vout;
                bp->state = 1;
            }
            if ( haveutxo < 10 && time(NULL) > dp->lastsplit+600 )
            {
                addresses = cJSON_CreateArray();
                jaddistr(addresses,coinaddr);
                if ( (rawtx= iguana_utxoduplicates(myinfo,coin,myinfo->DPOW.minerkey33,DPOW_UTXOSIZE,10,&bp->completed,&bp->signedtxid,0,addresses)) != 0 )
                {
                    if ( (sendtx= dpow_sendrawtransaction(myinfo,coin,rawtx)) != 0 )
                    {
                        printf("sendrawtransaction.(%s)\n",sendtx);
                        free(sendtx);
                    }
                    free(rawtx);
                }
                free_json(addresses);
                dp->lastsplit = (uint32_t)time(NULL);
            }
            break;
        case 1:
            dpow_lastk_mask(bp,&lastk);
            if ( (len= dpow_rwutxobuf(1,data,&bp->hashmsg,&bp->notaries[myind])) > 0 )
                dpow_send(myinfo,bp,srchash,bp->hashmsg,channel,bp->height,data,len,bp->utxocrcs);
            bp->recvmask |= (1LL << myind);
            bp->state = 2;
            break;
        default:
            dpow_update(myinfo,bp,channel,sigchannel,txidchannel,srchash,myind);
            break;
    }
    if ( bits256_nonz(bp->signedtxid) != 0 )
    {
        bp->state = 0xffffffff;
    }
    return(bp->state);
}

void dpow_statemachinestart(void *ptr)
{
    struct supernet_info *myinfo; struct dpow_info *dp; struct dpow_checkpoint checkpoint; void **ptrs = ptr;
    int32_t i,n,myind = -1; struct iguana_info *src,*dest; char str[65],coinaddr[64]; bits256 zero; struct dpow_block *srcbp,*destbp,*bp; uint32_t starttime = (uint32_t)time(NULL);
    memset(&zero,0,sizeof(zero));
    myinfo = ptrs[0];
    dp = ptrs[1];
    dp->destupdated = 0; // prevent another state machine till next BTC block
    memcpy(&checkpoint,&ptrs[2],sizeof(checkpoint));
    printf("statemachinestart %s->%s %s ht.%d\n",dp->symbol,dp->dest,bits256_str(str,checkpoint.blockhash.hash),checkpoint.blockhash.height);
    src = iguana_coinfind(dp->symbol);
    dest = iguana_coinfind(dp->dest);
    if ( (destbp= dp->destblocks[checkpoint.blockhash.height]) == 0 )
    {
        destbp = calloc(1,sizeof(*destbp));
        destbp->coin = iguana_coinfind(dp->dest);
        destbp->opret_symbol = dp->symbol;
        destbp->bestk = -1;
        dp->destblocks[checkpoint.blockhash.height] = destbp;
        destbp->beacon = rand256(0);
        vcalc_sha256(0,destbp->commit.bytes,destbp->beacon.bytes,sizeof(destbp->beacon));
        if ( (bp= dp->destblocks[checkpoint.blockhash.height - 100]) != 0 )
        {
            printf("purge %s.%d\n",dp->dest,checkpoint.blockhash.height - 100);
            dp->destblocks[checkpoint.blockhash.height - 100] = 0;
            free(bp);
        }
    }
    if ( (srcbp= dp->srcblocks[checkpoint.blockhash.height]) == 0 )
    {
        srcbp = calloc(1,sizeof(*srcbp));
        srcbp->coin = iguana_coinfind(dp->symbol);
        srcbp->opret_symbol = dp->symbol;
        srcbp->bestk = -1;
        dp->srcblocks[checkpoint.blockhash.height] = srcbp;
        srcbp->beacon = destbp->beacon;
        srcbp->commit = destbp->commit;
        printf("create srcbp[%d]\n",checkpoint.blockhash.height);
        if ( (bp= dp->srcblocks[checkpoint.blockhash.height - 1000]) != 0 )
        {
            printf("purge %s.%d\n",dp->symbol,checkpoint.blockhash.height - 1000);
            dp->srcblocks[checkpoint.blockhash.height - 1000] = 0;
            free(bp);
        }
    }
    n = (int32_t)(sizeof(Notaries)/sizeof(*Notaries));
    srcbp->numnotaries = destbp->numnotaries = n;
    for (i=0; i<n; i++)
    {
        decode_hex(srcbp->notaries[i].pubkey,33,Notaries[i][1]);
        decode_hex(destbp->notaries[i].pubkey,33,Notaries[i][1]);
        if ( memcmp(destbp->notaries[i].pubkey,myinfo->DPOW.minerkey33,33) == 0 )
            myind = i;
    }
    bitcoin_address(coinaddr,src->chain->pubtype,myinfo->DPOW.minerkey33,33);
    printf(" myaddr.%s\n",coinaddr);
    if ( myind < 0 )
    {
        printf("statemachinestart this node %s is not official notary\n",coinaddr);
        free(ptr);
        return;
    }
    dp->checkpoint = checkpoint;
    srcbp->height = destbp->height = checkpoint.blockhash.height;
    srcbp->timestamp = destbp->timestamp = checkpoint.timestamp;
    srcbp->hashmsg = destbp->hashmsg = checkpoint.blockhash.hash;
    printf("DPOW statemachine checkpoint.%d %s\n",checkpoint.blockhash.height,bits256_str(str,checkpoint.blockhash.hash));
    while ( time(NULL) < starttime+300 && src != 0 && dest != 0 && (srcbp->state != 0xffffffff || destbp->state != 0xffffffff) )
    {
        sleep(1);
        if ( dp->checkpoint.blockhash.height > checkpoint.blockhash.height )
        {
            printf("abort ht.%d due to new checkpoint.%d\n",checkpoint.blockhash.height,dp->checkpoint.blockhash.height);
            break;
        }
        if ( destbp->state != 0xffffffff )
        {
            //printf("dp->ht.%d ht.%d DEST.%08x %s\n",dp->checkpoint.blockhash.height,checkpoint.blockhash.height,deststate,bits256_str(str,srchash.hash));
            destbp->state = dpow_statemachineiterate(myinfo,dp,dest,destbp,myind);
            if ( destbp->state == 0xffffffff )
            {
                srcbp->btctxid = destbp->signedtxid;
                printf("SET BTCTXID.(%s)\n",bits256_str(str,srcbp->btctxid));
            }
        }
        if ( destbp->state == 0xffffffff && bits256_nonz(srcbp->btctxid) != 0 )
        {
            if ( dp->checkpoint.blockhash.height > checkpoint.blockhash.height )
            {
                printf("abort ht.%d due to new checkpoint.%d\n",checkpoint.blockhash.height,dp->checkpoint.blockhash.height);
                break;
            }
            if ( srcbp->state != 0xffffffff )
            {
                //printf("dp->ht.%d ht.%d SRC.%08x %s\n",dp->checkpoint.blockhash.height,checkpoint.blockhash.height,srcbp->state,bits256_str(str,srcbp->btctxid));
                srcbp->state = dpow_statemachineiterate(myinfo,dp,src,srcbp,myind);
            }
        }
    }
    free(ptr);
}

void dpow_fifoupdate(struct supernet_info *myinfo,struct dpow_checkpoint *fifo,struct dpow_checkpoint tip)
{
    int32_t i,ind; struct dpow_checkpoint newfifo[DPOW_FIFOSIZE]; char str[65];
    memset(newfifo,0,sizeof(newfifo));
    for (i=DPOW_FIFOSIZE-1; i>0; i--)
    {
        if ( bits256_nonz(fifo[i-1].blockhash.hash) != 0 && (tip.blockhash.height - fifo[i-1].blockhash.height) != i )
            printf("(%d != %d) ",(tip.blockhash.height - fifo[i-1].blockhash.height),i);
        if ( (ind= (tip.blockhash.height - fifo[i-1].blockhash.height)) >= 0 && ind < DPOW_FIFOSIZE )
            newfifo[ind] = fifo[i-1];
    }
    newfifo[0] = tip;
    memcpy(fifo,newfifo,sizeof(newfifo));
    for (i=0; i<DPOW_FIFOSIZE; i++)
        printf("%d ",bits256_nonz(fifo[i].blockhash.hash));
    printf(" <- fifo %s\n",bits256_str(str,tip.blockhash.hash));
}

void dpow_checkpointset(struct supernet_info *myinfo,struct dpow_checkpoint *checkpoint,int32_t height,bits256 hash,uint32_t timestamp,uint32_t blocktime)
{
    checkpoint->timestamp = timestamp;
    checkpoint->blocktime = blocktime;
    checkpoint->blockhash.hash = hash;
    checkpoint->blockhash.height = height;
}

void dpow_srcupdate(struct supernet_info *myinfo,struct dpow_info *dp,int32_t height,bits256 hash,uint32_t timestamp,uint32_t blocktime)
{
    void **ptrs; char str[65]; struct dpow_checkpoint checkpoint;
    dpow_checkpointset(myinfo,&dp->last,height,hash,timestamp,blocktime);
    checkpoint = dp->srcfifo[dp->srcconfirms];
    printf("%s srcupdate ht.%d destupdated.%u nonz.%d %s\n",dp->symbol,height,dp->destupdated,bits256_nonz(checkpoint.blockhash.hash),bits256_str(str,dp->last.blockhash.hash));
    dpow_fifoupdate(myinfo,dp->srcfifo,dp->last);
    if ( dp->destupdated != 0 && bits256_nonz(checkpoint.blockhash.hash) != 0 && (checkpoint.blockhash.height % DPOW_CHECKPOINTFREQ) == 0 )
    {
        ptrs = calloc(1,sizeof(void *)*2 + sizeof(struct dpow_checkpoint));
        ptrs[0] = (void *)myinfo;
        ptrs[1] = (void *)dp;
        memcpy(&ptrs[2],&checkpoint,sizeof(checkpoint));
        if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)dpow_statemachinestart,(void *)ptrs) != 0 )
        {
        }
    }
}

void dpow_approvedset(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_checkpoint *checkpoint,bits256 *txs,int32_t numtx)
{
    int32_t i,j; bits256 txid;
    if ( txs != 0 )
    {
        for (i=0; i<numtx; i++)
        {
            txid = txs[i];
            if ( bits256_nonz(txid) != 0 )
            {
                for (j=0; j<DPOW_FIFOSIZE; j++)
                {
                    if ( bits256_cmp(txid,dp->approved[j].hash) == 0 )
                    {
                        if ( bits256_nonz(checkpoint->approved.hash) == 0 || dp->approved[j].height >= checkpoint->approved.height )
                            checkpoint->approved = dp->approved[j];
                    }
                }
            }
        }
    }
}

void dpow_destconfirm(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_checkpoint *checkpoint)
{
    int32_t i;
    if ( bits256_nonz(checkpoint->approved.hash) != 0 )
    {
        for (i=DPOW_FIFOSIZE-1; i>0; i--)
            dp->notarized[i] = dp->notarized[i-1];
        dp->notarized[0] = checkpoint->approved;
    }
}

void dpow_destupdate(struct supernet_info *myinfo,struct dpow_info *dp,int32_t height,bits256 hash,uint32_t timestamp,uint32_t blocktime)
{
    printf("%s destupdate ht.%d\n",dp->dest,height);
    dp->destupdated = timestamp;
    dpow_checkpointset(myinfo,&dp->destchaintip,height,hash,timestamp,blocktime);
    dpow_approvedset(myinfo,dp,&dp->destchaintip,dp->desttx,dp->numdesttx);
    dpow_fifoupdate(myinfo,dp->destfifo,dp->destchaintip);
    if ( strcmp(dp->dest,"BTC") == 0 )
        dpow_destconfirm(myinfo,dp,&dp->destfifo[DPOW_BTCCONFIRMS]);
    else
    {
        dpow_destconfirm(myinfo,dp,&dp->destfifo[DPOW_KOMODOCONFIRMS * 2]); // todo: change to notarized KMD depth
    }
}

void iguana_dPoWupdate(struct supernet_info *myinfo)
{
    int32_t height; char str[65]; uint32_t blocktime; bits256 blockhash; struct iguana_info *src,*dest; struct dpow_info *dp = &myinfo->DPOW;
    dpow_nanomsg_update(myinfo);
    src = iguana_coinfind(dp->symbol);
    dest = iguana_coinfind(dp->dest);
    if ( src != 0 && dest != 0 )
    {
        dp->numdesttx = sizeof(dp->desttx)/sizeof(*dp->desttx);
        if ( (height= dpow_getchaintip(myinfo,&blockhash,&blocktime,dp->desttx,&dp->numdesttx,dest)) != dp->destchaintip.blockhash.height && height >= 0 )
        {
            printf("%s %s height.%d vs last.%d\n",dp->dest,bits256_str(str,blockhash),height,dp->destchaintip.blockhash.height);
            if ( height <= dp->destchaintip.blockhash.height )
            {
                printf("iguana_dPoWupdate dest.%s reorg detected %d vs %d\n",dp->dest,height,dp->destchaintip.blockhash.height);
                if ( height == dp->destchaintip.blockhash.height && bits256_cmp(blockhash,dp->destchaintip.blockhash.hash) != 0 )
                    printf("UNEXPECTED ILLEGAL BLOCK in dest chaintip\n");
            } else dpow_destupdate(myinfo,dp,height,blockhash,(uint32_t)time(NULL),blocktime);
        }
        dp->numsrctx = sizeof(dp->srctx)/sizeof(*dp->srctx);
        if ( (height= dpow_getchaintip(myinfo,&blockhash,&blocktime,dp->srctx,&dp->numsrctx,src)) != dp->last.blockhash.height && height >= 0 )
        {
            printf("%s %s height.%d vs last.%d\n",dp->symbol,bits256_str(str,blockhash),height,dp->last.blockhash.height);
            if ( height < dp->last.blockhash.height )
            {
                printf("iguana_dPoWupdate src.%s reorg detected %d vs %d approved.%d notarized.%d\n",dp->symbol,height,dp->last.blockhash.height,dp->approved[0].height,dp->notarized[0].height);
                if ( height <= dp->approved[0].height )
                {
                    if ( bits256_cmp(blockhash,dp->last.blockhash.hash) != 0 )
                        printf("UNEXPECTED ILLEGAL BLOCK in src chaintip\n");
                } else dpow_srcupdate(myinfo,dp,height,blockhash,(uint32_t)time(NULL),blocktime);
            } else dpow_srcupdate(myinfo,dp,height,blockhash,(uint32_t)time(NULL),blocktime);
        }
    } else printf("iguana_dPoWupdate missing src.(%s) %p or dest.(%s) %p\n",dp->symbol,src,dp->dest,dest);
}

#include "../includes/iguana_apidefs.h"

TWO_STRINGS(iguana,dpow,symbol,pubkey)
{
    char *retstr;
    if ( myinfo->NOTARY.RELAYID < 0 )
    {
        if ( (retstr= basilisk_addrelay_info(myinfo,0,(uint32_t)calc_ipbits(myinfo->ipaddr),myinfo->myaddr.persistent)) != 0 )
        {
            printf("addrelay.(%s)\n",retstr);
            free(retstr);
        }
        if ( myinfo->NOTARY.RELAYID < 0 )
            return(clonestr("{\"error\":\"must be running as notary node\"}"));
    }
    if ( myinfo->DPOW.symbol[0] != 0 )
        return(clonestr("{\"error\":\"cant dPoW more than one coin at a time\"}"));
    if ( pubkey == 0 || pubkey[0] == 0 || is_hexstr(pubkey,0) != 66 )
        return(clonestr("{\"error\":\"need 33 byte pubkey\"}"));
    if ( symbol == 0 || symbol[0] == 0 )
        symbol = "KMD";
    if ( iguana_coinfind(symbol) == 0 )
        return(clonestr("{\"error\":\"cant dPoW an inactive coin\"}"));
    if ( strcmp(symbol,"KMD") == 0 && iguana_coinfind("BTC") == 0 )
        return(clonestr("{\"error\":\"cant dPoW KMD without BTC\"}"));
    else if ( strcmp(symbol,"KMD") != 0 && iguana_coinfind("KMD") == 0 )
        return(clonestr("{\"error\":\"cant dPoW without KMD\"}"));
    decode_hex(myinfo->DPOW.minerkey33,33,pubkey);
    if ( bitcoin_pubkeylen(myinfo->DPOW.minerkey33) <= 0 )
        return(clonestr("{\"error\":\"illegal pubkey\"}"));
    strcpy(myinfo->DPOW.symbol,symbol);
    if ( strcmp(myinfo->DPOW.symbol,"KMD") == 0 )
    {
        strcpy(myinfo->DPOW.dest,"BTC");
        myinfo->DPOW.srcconfirms = DPOW_KOMODOCONFIRMS;
    }
    else
    {
        strcpy(myinfo->DPOW.dest,"KMD");
        myinfo->DPOW.srcconfirms = DPOW_THIRDPARTY_CONFIRMS;
    }
    if ( myinfo->DPOW.srcconfirms > DPOW_FIFOSIZE )
        myinfo->DPOW.srcconfirms = DPOW_FIFOSIZE;
    if ( myinfo->DPOW.srcblocks == 0 )
        myinfo->DPOW.srcblocks = calloc(1000000,sizeof(*myinfo->DPOW.srcblocks));
    if ( myinfo->DPOW.destblocks == 0 )
        myinfo->DPOW.destblocks = calloc(1000000,sizeof(*myinfo->DPOW.destblocks));
    return(clonestr("{\"result\":\"success\"}"));
}

char *dpow_passthru(struct iguana_info *coin,char *function,char *hex)
{
    char params[32768]; int32_t len = 0;
    if ( hex != 0 && hex[0] != 0 )
    {
        len = (int32_t)strlen(hex) >> 1;
        if ( len < sizeof(params)-1 )
            decode_hex((uint8_t *)params,(int32_t)strlen(hex),hex);
        else len = 0;
    }
    params[len] = 0;
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,function,params));
}

TWO_STRINGS(zcash,passthru,function,hex)
{
    if ( (coin= iguana_coinfind("ZEC")) != 0 || coin->chain->serverport[0] == 0 )
        return(dpow_passthru(coin,function,hex));
    else return(clonestr("{\"error\":\"ZEC not active, start in bitcoind mode\"}"));
}

TWO_STRINGS(komodo,passthru,function,hex)
{
    if ( (coin= iguana_coinfind("KMD")) != 0 || coin->chain->serverport[0] == 0 )
        return(dpow_passthru(coin,function,hex));
    else return(clonestr("{\"error\":\"KMD not active, start in bitcoind mode\"}"));
}

STRING_ARG(iguana,addnotary,ipaddr)
{
    dpow_nanomsginit(myinfo,ipaddr);
    return(clonestr("{\"result\":\"notary node added\"}"));
}

#include "../includes/iguana_apiundefs.h"
