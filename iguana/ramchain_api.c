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

HASH_AND_INT(bitcoinrpc,getblock,blockhash,remoteonly)
{
    char *blockstr; struct iguana_msgblock msg; struct iguana_block *block; cJSON *retjson; bits256 txid;
    retjson = cJSON_CreateObject();
    memset(&msg,0,sizeof(msg));
    if ( remoteonly == 0 && (block= iguana_blockfind(coin,blockhash)) != 0 )
    {
        return(jprint(iguana_blockjson(coin,block,1),1));
/* int32_t len,i; char str[65],hexstr[(sizeof(uint32_t)+sizeof(struct iguana_msgblock))*2+1],*blockstr;
        uint8_t serialized[sizeof(uint32_t)+sizeof(struct iguana_msgblock)]; bits256 hash2,txid;
   msg.H.version = block->RO.version;
        msg.H.merkle_root = block->RO.merkle_root;
        msg.H.timestamp = block->RO.timestamp;
        msg.H.bits = block->RO.bits;
        msg.H.nonce = block->RO.nonce;
        msg.txn_count = block->RO.txn_count;
        jaddnum(retjson,"version",msg.H.version);
        jaddnum(retjson,"timestamp",msg.H.timestamp);
        jaddstr(retjson,"utc",utc_str(str,msg.H.timestamp));
        serialized[0] = ((uint8_t *)&msg.H.bits)[3];
        serialized[1] = ((uint8_t *)&msg.H.bits)[2];
        serialized[2] = ((uint8_t *)&msg.H.bits)[1];
        serialized[3] = ((uint8_t *)&msg.H.bits)[0];
        init_hexbytes_noT(hexstr,serialized,sizeof(uint32_t));
        jaddstr(retjson,"nBits",hexstr);
        jaddnum(retjson,"nonce",msg.H.nonce);
        jaddbits256(retjson,"merkle_root",msg.H.merkle_root);
        jaddnum(retjson,"txn_count",msg.txn_count);
        array = cJSON_CreateArray();
        for (i=0; i<msg.txn_count; i++)
        {
            
        }
        jadd(retjson,"txids",array);
        len = iguana_rwblock(1,&hash2,serialized,&msg);
        char str[65]; printf("timestamp.%u bits.%u nonce.%u v.%d (%s) len.%d (%ld %ld)\n",block->RO.timestamp,block->RO.bits,block->RO.nonce,block->RO.version,bits256_str(str,hash2),len,sizeof(serialized),sizeof(hexstr));
        init_hexbytes_noT(hexstr,serialized,len);
        jaddstr(retjson,"result",hexstr);*/
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

int32_t iguana_ramtxbytes(struct iguana_info *coin,uint8_t *serialized,int32_t maxlen,bits256 *txidp,struct iguana_txid *tx,int32_t height,struct iguana_msgvin *vins,struct iguana_msgvout *vouts)
{
    int32_t i,rwflag=1,len = 0; char asmstr[512],txidstr[65];
    uint32_t numvins,numvouts; struct iguana_msgvin vin; struct iguana_msgvout vout; uint8_t space[8192];
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(tx->version),&tx->version);
    if ( coin->chain->hastimestamp != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(tx->timestamp),&tx->timestamp);
    numvins = tx->numvins, numvouts = tx->numvouts;
    len += iguana_rwvarint32(rwflag,&serialized[len],&numvins);
    for (i=0; i<numvins; i++)
    {
        if ( vins == 0 )
            iguana_vinset(coin,height,&vin,tx,i);
        else vin = vins[i];
        len += iguana_rwvin(rwflag,0,&serialized[len],&vin);
    }
    if ( len > maxlen )
        return(0);
    len += iguana_rwvarint32(rwflag,&serialized[len],&numvouts);
    for (i=0; i<numvouts; i++)
    {
        if ( vouts == 0 )
            iguana_voutset(coin,space,asmstr,height,&vout,tx,i);
        else vout = vouts[i];
        len += iguana_rwvout(rwflag,0,&serialized[len],&vout);
    }
    if ( len > maxlen )
        return(0);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(tx->locktime),&tx->locktime);
    *txidp = bits256_doublesha256(txidstr,serialized,len);
    if ( memcmp(txidp,tx->txid.bytes,sizeof(*txidp)) != 0 )
    {
        //for (i=0; i<len; i++)
        //    printf("%02x",serialized[i]);
        char str[65],str2[65]; printf("\nrw.%d numvins.%d numvouts.%d error generating txbytes, probably due to running without stored sigs txid %s vs %s\n",rwflag,numvins,numvouts,bits256_str(str,*txidp),bits256_str(str2,tx->txid));
        return(len);
    }
    return(len);
}

HASH_AND_INT(bitcoinrpc,getrawtransaction,txid,verbose)
{
    struct iguana_txid *tx,T; char *txbytes; bits256 checktxid; int32_t len,height; cJSON *retjson;
    if ( (tx= iguana_txidfind(coin,&height,&T,txid,coin->bundlescount-1)) != 0 )
    {
        retjson = cJSON_CreateObject();
        if ( (len= iguana_ramtxbytes(coin,coin->blockspace,sizeof(coin->blockspace),&checktxid,tx,height,0,0)) > 0 )
        {
            txbytes = calloc(1,len*2+1);
            init_hexbytes_noT(txbytes,coin->blockspace,len);
            jaddstr(retjson,"result",txbytes);
            //printf("txbytes.(%s)\n",txbytes);
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
    uint8_t *data; int32_t datalen; cJSON *retjson = cJSON_CreateObject(); // struct iguana_msgtx msgtx; 
    datalen = (int32_t)strlen(rawtx) >> 1;
    data = malloc(datalen);
    decode_hex(data,datalen,rawtx);
    //if ( (str= iguana_rawtxbytes(coin,data,datalen,retjson,&msgtx)) != 0 )
    //    free(str);
    free(data);
    return(jprint(retjson,1));
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
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,validatepubkey,pubkey)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

HASH_AND_TWOINTS(bitcoinrpc,listsinceblock,blockhash,target,flag)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,decodescript,script)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,vanitygen,vanity)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

TWO_STRINGS(bitcoinrpc,signmessage,address,message)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

THREE_STRINGS(bitcoinrpc,verifymessage,address,sig,message)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// tx
TWO_ARRAYS(bitcoinrpc,createrawtransaction,vins,vouts)
{
    cJSON *retjson = cJSON_CreateObject();
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

HASH_AND_TWOINTS(bitcoinrpc,gettxout,txid,vout,mempool)
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

STRING_AND_INT(iguana,bundleaddresses,base,height)
{
    struct iguana_info *ptr;
    if ( (ptr= iguana_coinfind(base)) != 0 )
        return(iguana_bundleaddrs(ptr,height / coin->chain->bundlesize));
    else return(clonestr("{\"error\":\"base is not active\"}"));
}
#undef IGUANA_ARGS
#include "../includes/iguana_apiundefs.h"

