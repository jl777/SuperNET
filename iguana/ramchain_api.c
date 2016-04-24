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
#include "../includes/iguana_apidefs.h"

STRING_ARG(iguana,validate,activecoin)
{
    int32_t i,total,validated; struct iguana_bundle *bp; cJSON *retjson;
    if ( (coin= iguana_coinfind(activecoin)) != 0 )
    {
        for (i=total=validated=0; i<coin->bundlescount; i++)
            if ( (bp= coin->bundles[i]) != 0 )
            {
                validated += iguana_bundlevalidate(coin,bp,1);
                total += bp->n;
            }
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","validation run");
        jaddstr(retjson,"coin",coin->symbol);
        jaddnum(retjson,"validated",validated);
        jaddnum(retjson,"total",total);
        jaddnum(retjson,"bundles",coin->bundlescount);
        jaddnum(retjson,"accuracy",(double)validated/total);
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"no active coin\"}"));
}

STRING_ARG(iguana,removecoin,activecoin)
{
    struct iguana_bundle *bp; int32_t i,height; char fname[1024];
    if ( (coin= iguana_coinfind(activecoin)) != 0 )
    {
        coin->active = 0;
        coin->started = 0;
        for (i=0; i<IGUANA_MAXPEERS; i++)
        {
            sprintf(fname,"%s/%s/vouts/%04d.vouts",GLOBAL_DBDIR,coin->symbol,i), OS_removefile(fname,0);
            sprintf(fname,"%s/%s/%04d.vins",coin->VALIDATEDIR,coin->symbol,i), OS_removefile(fname,0);
        }
        sprintf(fname,"%s/%s/vouts/*",GLOBAL_DBDIR,coin->symbol), OS_removefile(fname,0);
        sprintf(fname,"%s/%s/*",coin->VALIDATEDIR,coin->symbol), OS_removefile(fname,0);
        for (i=0; i<coin->bundlescount; i++)
        {
            sprintf(fname,"%s/%s/balancecrc.%d",GLOBAL_DBDIR,coin->symbol,i), OS_removefile(fname,0);
            if ( (bp= coin->bundles[i]) != 0 )
            {
                iguana_bundlepurgefiles(coin,bp);
                iguana_bundleremove(coin,bp->hdrsi,1);
            }
        }
        for (height=0; height<coin->longestchain; height+=IGUANA_SUBDIRDIVISOR)
        {
            sprintf(fname,"%s/%s/%d",GLOBAL_DBDIR,coin->symbol,height/IGUANA_SUBDIRDIVISOR);
            OS_remove_directory(fname);
        }
        sprintf(fname,"%s/%s/*",GLOBAL_DBDIR,coin->symbol), OS_remove_directory(fname);
    }
    return(clonestr("{\"error\":\"no active coin\"}"));
}

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

INT_ARG(bitcoinrpc,getblockhash,height)
{
    cJSON *retjson = cJSON_CreateObject();
    jaddbits256(retjson,"result",iguana_blockhash(coin,height));
    return(jprint(retjson,1));
}

HASH_AND_TWOINTS(bitcoinrpc,getblock,blockhash,verbose,remoteonly)
{
    char *blockstr,*datastr; struct iguana_msgblock msg; struct iguana_block *block; cJSON *retjson; bits256 txid; int32_t len;
    retjson = cJSON_CreateObject();
    memset(&msg,0,sizeof(msg));
    if ( remoteonly == 0 && (block= iguana_blockfind("getblockRPC",coin,blockhash)) != 0 )
    {
        if ( verbose != 0 )
            return(jprint(iguana_blockjson(coin,block,1),1));
        else
        {
            if ( (len= iguana_peerblockrequest(coin,coin->blockspace,sizeof(coin->blockspace),0,blockhash,0)) > 0 )
            {
                datastr = malloc(len*2 + 1);
                init_hexbytes_noT(datastr,coin->blockspace,len);
                jaddstr(retjson,"result",datastr);
                free(datastr);
                return(jprint(retjson,1));
            }
            jaddstr(retjson,"error","error getting rawblock");
        }
    }
    else if ( coin->APIblockstr != 0 )
        jaddstr(retjson,"error","already have pending request");
    else
    {
        memset(txid.bytes,0,sizeof(txid));
        if ( (blockstr= iguana_APIrequest(coin,blockhash,txid,5)) != 0 )
        {
            jaddstr(retjson,"result",blockstr);
            free(blockstr);
        } else jaddstr(retjson,"error","cant find blockhash");
    }
    return(jprint(retjson,1));
}

HASH_AND_INT(bitcoinrpc,getrawtransaction,txid,verbose)
{
    struct iguana_txid *tx,T; char *txbytes; bits256 checktxid; int32_t len,height; cJSON *retjson;
    if ( (tx= iguana_txidfind(coin,&height,&T,txid,coin->bundlescount-1)) != 0 )
    {
        retjson = cJSON_CreateObject();
        if ( (len= iguana_ramtxbytes(coin,coin->blockspace,sizeof(coin->blockspace),&checktxid,tx,height,0,0,0)) > 0 )
        {
            txbytes = calloc(1,len*2+1);
            init_hexbytes_noT(txbytes,coin->blockspace,len);
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
    return(bitcoinrpc_getrawtransaction(IGUANA_CALLARGS,txid,1));
}

ZERO_ARGS(bitcoinrpc,getbestblockhash)
{
    cJSON *retjson = cJSON_CreateObject();
    char str[65]; jaddstr(retjson,"result",bits256_str(str,coin->blocks.hwmchain.RO.hash2));
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,getblockcount)
{
    cJSON *retjson = cJSON_CreateObject();
    jaddnum(retjson,"result",coin->blocks.hwmchain.height);
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,makekeypair)
{
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
    plen = (int32_t)strlen(pubkeystr) >> 1;
    if ( plen <= 65 && coin != 0 && coin->chain != 0 )
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

HASH_AND_TWOINTS(bitcoinrpc,listsinceblock,blockhash,target,flag)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

cJSON *iguana_scriptobj(struct iguana_info *coin,uint8_t rmd160[20],char *coinaddr,char *asmstr,uint8_t *script,int32_t scriptlen)
{
    struct vin_info V; int32_t i,plen,asmtype; char pubkeystr[130],rmdstr[41]; cJSON *addrobj,*scriptobj=0;
    if ( (asmtype= iguana_calcrmd160(coin,asmstr,&V,script,scriptlen,rand256(1),1,0xffffffff)) >= 0 )
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

STRING_ARG(bitcoinrpc,decodescript,scriptstr)
{
    int32_t scriptlen; uint8_t script[IGUANA_MAXSCRIPTSIZE],rmd160[20]; char coinaddr[128],asmstr[IGUANA_MAXSCRIPTSIZE*2+1]; cJSON *scriptobj,*retjson = cJSON_CreateObject();
    if ( coin != 0 && (scriptlen= (int32_t)strlen(scriptstr)>>1) < sizeof(script) )
    {
        decode_hex(script,scriptlen,scriptstr);
        if ( (scriptobj= iguana_scriptobj(coin,rmd160,coinaddr,asmstr,script,scriptlen)) != 0 )
            jadd(retjson,"result",scriptobj);
    }
    return(jprint(retjson,1));
}

HASH_AND_TWOINTS(bitcoinrpc,gettxout,txid,vout,mempool)
{
    uint8_t script[IGUANA_MAXSCRIPTSIZE],rmd160[20],pubkey33[33]; char coinaddr[128],asmstr[IGUANA_MAXSCRIPTSIZE*2+1]; struct iguana_bundle *bp; int32_t scriptlen,unspentind,height,spentheight; int64_t RTspend; struct iguana_ramchaindata *rdata; struct iguana_pkhash *P; struct iguana_txid *T; struct iguana_unspent *U; struct iguana_ramchain *ramchain; cJSON *scriptobj,*retjson = cJSON_CreateObject();
    if ( coin != 0 )
    {
        if ( (unspentind= iguana_unspentindfind(coin,&height,txid,vout,coin->bundlescount-1)) != 0 )
        {
            if ( height >= 0 && height < coin->longestchain && (bp= coin->bundles[height / coin->chain->bundlesize]) != 0 )
            {
                ramchain = (bp == coin->current) ? &coin->RTramchain : &bp->ramchain;
                if ( (rdata= ramchain->H.data) != 0 )
                {
                    U = (void *)(long)((long)rdata + rdata->Uoffset);
                    P = (void *)(long)((long)rdata + rdata->Poffset);
                    T = (void *)(long)((long)rdata + rdata->Toffset);
                    RTspend = 0;
                    if ( iguana_spentflag(coin,&RTspend,&spentheight,ramchain,bp->hdrsi,unspentind,height,U[unspentind].value) == 0 )
                    {
                        jaddbits256(retjson,"bestblock",coin->blocks.hwmchain.RO.hash2);
                        jaddnum(retjson,"bestheight",coin->blocks.hwmchain.height);
                        jaddnum(retjson,"height",height);
                        jaddnum(retjson,"confirmations",coin->blocks.hwmchain.height - height);
                        jaddnum(retjson,"value",dstr(U[unspentind].value));
                        memset(rmd160,0,sizeof(rmd160));
                        memset(pubkey33,0,sizeof(pubkey33));
                        memset(coinaddr,0,sizeof(coinaddr));
                        if ( (scriptlen= iguana_voutscript(coin,bp,script,0,&U[unspentind],&P[U[unspentind].pkind],vout)) > 0 )
                        {
                            if ( (scriptobj= iguana_scriptobj(coin,rmd160,coinaddr,asmstr,script,scriptlen)) != 0 )
                                jadd(retjson,"scriptPubKey",scriptobj);
                        }
                        jadd(retjson,"iguana",iguana_unspentjson(coin,bp->hdrsi,unspentind,T,&U[unspentind],rmd160,coinaddr,pubkey33));
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

TWO_STRINGS(bitcoinrpc,signmessage,address,messagestr)
{
    bits256 privkey; int32_t n,len,siglen; char sigstr[256],sig64str[256]; uint8_t sig[128],*message=0; cJSON *retjson = cJSON_CreateObject();
    if ( coin != 0 )
    {
        privkey = iguana_str2priv(coin,address);
        if ( bits256_nonz(privkey) != 0 )
        {
            n = (int32_t)strlen(messagestr) >> 1;
            if ( messagestr[0] == '0' && messagestr[1] == 'x' && is_hexstr(messagestr+2,n-2) > 0 )
            {
                message = malloc(n-2);
                decode_hex(message,n-2,messagestr+2);
                n -= 2;
            } else message = (uint8_t *)messagestr, n <<= 1;
            if ( (siglen= bitcoin_sign(sig,sizeof(sig),message,n,privkey)) > 0 )
            {
                sigstr[0] = sig64str[0] = 0;
                //init_hexbytes_noT(sigstr,sig,siglen);
                len = nn_base64_encode(sig,siglen,sig64str,sizeof(sig64str));
                sig64str[len++] = '=';
                sig64str[len++] = 0;
                jaddstr(retjson,"result",sig64str);
            }
            if ( message != (void *)messagestr )
                free(message);
        } else jaddstr(retjson,"error","invalid address (can be wif, wallet address or privkey hex)");
    }
    return(jprint(retjson,1));
}

THREE_STRINGS(bitcoinrpc,verifymessage,address,sig,message)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// tx
ARRAY_OBJ_INT(bitcoinrpc,createrawtransaction,vins,vouts,locktime)
{
    bits256 txid; int32_t vout,scriptlen=0,p2shlen=0,i,n; uint32_t sequenceid; uint8_t script[IGUANA_MAXSCRIPTSIZE],redeemscript[IGUANA_MAXSCRIPTSIZE]; char *str; cJSON *txobj,*item,*retjson = cJSON_CreateObject();
    if ( coin != 0 && (txobj= bitcoin_createtx(coin,locktime)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(vins)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(vins,i);
                p2shlen = scriptlen = 0;
                if ( (str= jstr(item,"scriptPubKey")) != 0 )
                {
                    scriptlen = (int32_t)strlen(str) >> 1;
                    decode_hex(script,scriptlen,str);
                }
                if ( (str= jstr(item,"redeemScript")) != 0 )
                {
                    p2shlen = (int32_t)strlen(str) >> 1;
                    decode_hex(redeemscript,p2shlen,str);
                }
                vout = jint(item,"vout");
                sequenceid = juint(item,"sequenceid");
                txid = jbits256(item,"txid");
                bitcoin_addinput(coin,txobj,txid,vout,sequenceid,script,scriptlen,redeemscript,p2shlen);
            }
        }
        if ( (n= cJSON_GetArraySize(vouts)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(vouts,i);
            }
        }
    }
    printf("vins.(%s) vouts.(%s) locktime.%u\n",jprint(vins,0),jprint(vouts,0),locktime);
    return(jprint(retjson,1));
}

STRING_AND_TWOARRAYS(bitcoinrpc,signrawtransaction,rawtx,vins,privkeys)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_AND_INT(bitcoinrpc,sendrawtransaction,rawtx,allowhighfees)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// unspents
ZERO_ARGS(bitcoinrpc,gettxoutsetinfo)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(bitcoinrpc,lockunspent,flag,array)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,listlockunspent)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

TWOINTS_AND_ARRAY(bitcoinrpc,listunspent,minconf,maxconf,array)
{
    int32_t numrmds; uint8_t *rmdarray; cJSON *retjson = cJSON_CreateArray();
    if ( minconf == 0 )
        minconf = 1;
    if ( maxconf == 0 )
        maxconf = 9999999;
    rmdarray = iguana_rmdarray(coin,&numrmds,array,0);
    iguana_unspents(myinfo,coin,retjson,minconf,maxconf,rmdarray,numrmds);
    if ( rmdarray != 0 )
        free(rmdarray);
    return(jprint(retjson,1));
}

STRING_AND_INT(bitcoinrpc,getreceivedbyaddress,address,minconf)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// single address/account funcs
ZERO_ARGS(bitcoinrpc,getrawchangeaddress)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

HASH_AND_STRING(bitcoinrpc,verifytx,txid,txbytes)
{
    cJSON *retjson;
    retjson = bitcoin_txtest(coin,txbytes,txid);
    //printf("verifytx.(%s) %p\n",jprint(retjson,0),retjson);
    return(jprint(retjson,1));
}

STRING_AND_INT(iguana,bundleaddresses,activecoin,height)
{
    struct iguana_info *ptr;
    if ( (ptr= iguana_coinfind(activecoin)) != 0 )
        return(iguana_bundleaddrs(ptr,height / coin->chain->bundlesize));
    else return(clonestr("{\"error\":\"activecoin is not active\"}"));
}

STRING_AND_INT(iguana,bundlehashes,activecoin,height)
{
    struct iguana_info *ptr; struct iguana_bundle *bp; int32_t i,hdrsi; cJSON *retjson,*array; struct iguana_ramchaindata *rdata;
    if ( (ptr= iguana_coinfind(activecoin)) != 0 )
    {
        hdrsi = height / coin->chain->bundlesize;
        if ( hdrsi < coin->bundlescount && hdrsi >= 0 && (bp= coin->bundles[hdrsi]) != 0 )
        {
            if ( (rdata= bp->ramchain.H.data) != 0 )
            {
                array = cJSON_CreateArray();
                for (i=0; i<IGUANA_NUMLHASHES; i++)
                    jaddinum(array,rdata->lhashes[i].txid);
                retjson = cJSON_CreateObject();
                jaddstr(retjson,"result","success");
                jaddbits256(retjson,"sha256",rdata->sha256);
                jadd(retjson,"bundlehashes",array);
                return(jprint(retjson,1));
            } else return(clonestr("{\"error\":\"ramchain not there\"}"));
        } else return(clonestr("{\"error\":\"height is too big\"}"));
    } else return(clonestr("{\"error\":\"activecoin is not active\"}"));
}

#undef IGUANA_ARGS
#include "../includes/iguana_apiundefs.h"

