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

HASH_AND_INT(ramchain,getblock,blockhash,localonly)
{
    int32_t i,len; char hexstr[(sizeof(uint32_t)+sizeof(struct iguana_msgblock))*2+1];
    uint8_t serialized[sizeof(uint32_t)+sizeof(struct iguana_msgblock)]; bits256 hash2;
    struct iguana_msgblock msg; struct iguana_block *block;
    cJSON *retjson = cJSON_CreateObject();
    memset(&msg,0,sizeof(msg));
    if ( localonly == 0 && (block= iguana_blockfind(coin,blockhash)) != 0 )
    {
        msg.H.version = block->RO.version;
        msg.H.merkle_root = block->RO.merkle_root;
        msg.H.timestamp = block->RO.timestamp;
        msg.H.bits = block->RO.bits;
        msg.H.nonce = block->RO.nonce;
        msg.txn_count = block->RO.txn_count;
        len = iguana_rwblock(1,&hash2,serialized,&msg);
        char str[65]; printf("timestamp.%u bits.%u nonce.%u v.%d (%s) len.%d (%ld %ld)\n",block->RO.timestamp,block->RO.bits,block->RO.nonce,block->RO.version,bits256_str(str,hash2),len,sizeof(serialized),sizeof(hexstr));
        init_hexbytes_noT(hexstr,serialized,len);
        jaddstr(retjson,"result",hexstr);
    }
    else if ( coin->APIblockstr != 0 )
        jaddstr(retjson,"error","already have pending request");
    else
    {
        coin->APIblockhash = blockhash;
        iguana_blockQ(coin,0,-1,blockhash,1);
        for (i=0; i<10; i++)
        {
            if ( coin->APIblockstr != 0 )
            {
                jaddstr(retjson,"result",coin->APIblockstr);
                free(coin->APIblockstr);
                memset(&coin->APIblockhash,0,sizeof(coin->APIblockhash));
                coin->APIblockstr = 0;
                break;
            }
            sleep(1);
        }
        if ( i == 10 )
            jaddstr(retjson,"error","cant find blockhash");
    }
    return(jprint(retjson,1));
}

ZERO_ARGS(ramchain,getinfo)
{
    cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",coin->statusstr);
    return(jprint(retjson,1));
}

ZERO_ARGS(ramchain,getbestblockhash)
{
    cJSON *retjson = cJSON_CreateObject();
    char str[65]; jaddstr(retjson,"result",bits256_str(str,coin->blocks.hwmchain.RO.hash2));
    return(jprint(retjson,1));
}

ZERO_ARGS(ramchain,getblockcount)
{
    cJSON *retjson = cJSON_CreateObject();
    jaddnum(retjson,"result",coin->blocks.hwmchain.height);
    return(jprint(retjson,1));
}

HASH_AND_TWOINTS(ramchain,listsinceblock,blockhash,target,flag)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// pubkeys
ZERO_ARGS(ramchain,makekeypair)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,validatepubkey,pubkey)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_ARRAY_STRING(ramchain,createmultisig,M,array,account)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,decodescript,script)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,vanitygen,vanity)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

TWO_STRINGS(ramchain,signmessage,address,message)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

THREE_STRINGS(ramchain,verifymessage,address,sig,message)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// tx
TWO_ARRAYS(ramchain,createrawtransaction,vins,vouts)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

HASH_AND_INT(ramchain,getrawtransaction,txid,verbose)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,decoderawtransaction,rawtx)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_AND_TWOARRAYS(ramchain,signrawtransaction,rawtx,vins,privkeys)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_AND_INT(ramchain,sendrawtransaction,rawtx,allowhighfees)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// unspents
ZERO_ARGS(ramchain,gettxoutsetinfo)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_AND_ARRAY(ramchain,lockunspent,flag,array)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

ZERO_ARGS(ramchain,listlockunspent)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

HASH_AND_TWOINTS(ramchain,gettxout,txid,vout,mempool)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

TWOINTS_AND_ARRAY(ramchain,listunspent,minconf,maxconf,array)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_AND_INT(ramchain,getreceivedbyaddress,address,minconf)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

THREE_INTS(ramchain,listreceivedbyaddress,minconf,includeempty,flag)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// single address/account funcs
ZERO_ARGS(ramchain,getrawchangeaddress)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,getnewaddress,account)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

TWOSTRINGS_AND_INT(ramchain,importprivkey,wif,account,rescan)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,dumpprivkey,address)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

TWO_STRINGS(ramchain,setaccount,address,account)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,getaccount,address)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,getaccountaddress,account)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// multiple address
THREE_INTS(ramchain,getbalance,confirmations,includeempty,watchonly)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,getaddressesbyaccount,account)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_AND_INT(ramchain,getreceivedbyaccount,account,includeempty)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

THREE_INTS(ramchain,listreceivedbyaccount,confirmations,includeempty,watchonly)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_AND_THREEINTS(ramchain,listtransactions,account,count,skip,includewatchonly)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// spend funcs
DOUBLE_ARG(ramchain,settxfee,amount)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

SS_D_I_S(ramchain,move,fromaccount,toaccount,amount,minconf,comment)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

SS_D_I_SS(ramchain,sendfrom,fromaccount,toaddress,amount,minconf,comment,comment2)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

S_A_I_S(ramchain,sendmany,fromaccount,array,minconf,comment)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

S_D_SS(ramchain,sendtoaddress,address,amount,comment,comment2)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// entire wallet funcs
TWO_INTS(ramchain,listaccounts,minconf,includewatchonly)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

ZERO_ARGS(ramchain,listaddressgroupings)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

ZERO_ARGS(ramchain,walletlock)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

ZERO_ARGS(ramchain,checkwallet)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

ZERO_ARGS(ramchain,repairwallet)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,dumpwallet,filename)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,backupwallet,filename)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,importwallet,filename)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_AND_INT(ramchain,walletpassphrase,passphrase,timeout)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

TWO_STRINGS(ramchain,walletpassphrasechange,oldpassphrase,newpassphrase)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(ramchain,encryptwallet,passphrase)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}


#undef IGUANA_ARGS
#include "../includes/iguana_apiundefs.h"
