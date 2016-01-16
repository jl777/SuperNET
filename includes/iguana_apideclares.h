/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
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

ZERO_ARGS(SuperNET,help);
TWO_STRINGS(SuperNET,html,agentform,htmlfile);
STRING_ARG(SuperNET,bitcoinrpc,setcoin);

STRING_ARG(iguana,peers,activecoin);
STRING_AND_INT(iguana,maxpeers,activecoin,max);
STRING_ARG(iguana,getconnectioncount,activecoin);
STRING_ARG(iguana,addcoin,activecoin);
STRING_ARG(iguana,startcoin,activecoin);
STRING_ARG(iguana,pausecoin,activecoin);
TWO_STRINGS(iguana,addnode,activecoin,ipaddr);
TWO_STRINGS(iguana,removenode,activecoin,ipaddr);
TWO_STRINGS(iguana,oneshot,activecoin,ipaddr);
TWO_STRINGS(iguana,nodestatus,activecoin,ipaddr);

STRING_ARG(ramchain,getpeers,activecoin);
ZERO_ARGS(ramchain,getinfo);
ZERO_ARGS(ramchain,getbestblockhash);
ZERO_ARGS(ramchain,getblockcount);
ZERO_ARGS(ramchain,listaddressgroupings);
ZERO_ARGS(ramchain,walletlock);
ZERO_ARGS(ramchain,checkwallet);
ZERO_ARGS(ramchain,repairwallet);
ZERO_ARGS(ramchain,makekeypair);
ZERO_ARGS(ramchain,gettxoutsetinfo);
ZERO_ARGS(ramchain,listlockunspent);
ZERO_ARGS(ramchain,getrawchangeaddress);

TWO_INTS(ramchain,listaccounts,minconf,includewatchonly);
TWO_INTS(ramchain,listreceivedbyaddress,minconf,includeempty);
TWOINTS_AND_ARRAY(ramchain,listunspent,minconf,maxconf,array);

STRING_ARG(ramchain,dumpwallet,filename);
STRING_ARG(ramchain,backupwallet,filename);
STRING_ARG(ramchain,encryptwallet,passphrase);
STRING_ARG(ramchain,validatepubkey,pubkey);
STRING_ARG(ramchain,getnewaddress,account);
STRING_ARG(ramchain,vanitygen,vanity);

STRING_ARG(ramchain,getaddressesbyaccount,account);
STRING_ARG(ramchain,getaccount,address);
STRING_ARG(ramchain,getaccountaddress,account);
STRING_ARG(ramchain,dumpprivkey,address);
STRING_ARG(ramchain,importwallet,filename);
STRING_ARG(ramchain,decoderawtransaction,rawtx);
STRING_ARG(ramchain,decodescript,script);

TWO_STRINGS(ramchain,setaccount,address,account);
TWO_STRINGS(ramchain,walletpassphrasechange,oldpassphrase,newpassphrase);
TWO_STRINGS(ramchain,signmessage,address,message);

THREE_STRINGS(ramchain,verifymessage,address,sig,message);
THREE_INTS(ramchain,listreceivedbyaccount,confirmations,includeempty,watchonly);
THREE_INTS(ramchain,getbalance,confirmations,includeempty,watchonly);

TWOSTRINGS_AND_INT(ramchain,importprivkey,wif,account,rescan);
STRING_AND_INT(ramchain,getreceivedbyaccount,account,includeempty);
STRING_AND_INT(ramchain,walletpassphrase,passphrase,timeout);
STRING_AND_INT(ramchain,getreceivedbyaddress,address,minconf);
STRING_AND_INT(ramchain,sendrawtransaction,rawtx,allowhighfees);

HASH_AND_INT(ramchain,listsinceblock,blockhash,target);
HASH_AND_INT(ramchain,getrawtransaction,txid,verbose);

STRING_AND_THREEINTS(ramchain,listtransactions,account,count,skip,includewatchonly);

HASH_AND_TWOINTS(ramchain,gettxout,txid,vout,mempool);

DOUBLE_ARG(ramchain,settxfee,amount);

INT_AND_ARRAY(ramchain,lockunspent,flag,array);
INT_ARRAY_STRING(ramchain,createmultisig,M,array,account);

TWO_ARRAYS(ramchain,createrawtransaction,vins,vouts);
STRING_AND_TWOARRAYS(ramchain,signrawtransaction,rawtx,vins,privkeys);

SS_D_I_S(ramchain,move,fromaccount,toaccount,amount,minconf,comment);
SS_D_I_SS(ramchain,sendfrom,fromaccount,toaddress,amount,minconf,comment,comment2);
S_A_I_S(ramchain,sendmany,fromaccount,array,minconf,comment);
S_D_SS(ramchain,sendtoaddress,address,amount,comment,comment2);

STRING_ARG(hash,NXT,passphrase);
STRING_ARG(hash,curve25519,pubkey);
STRING_ARG(hash,crc32,message);
STRING_ARG(hash,base64_encode,message);
STRING_ARG(hash,base64_decode,message);
STRING_ARG(hash,rmd160_sha256,message);
STRING_ARG(hash,sha256_sha256,message);

STRING_ARG(hash,sha224,message);
STRING_ARG(hash,sha256,message);
STRING_ARG(hash,sha384,message);
STRING_ARG(hash,sha512,message);
STRING_ARG(hash,rmd128,message);
STRING_ARG(hash,rmd160,message);
STRING_ARG(hash,rmd256,message);
STRING_ARG(hash,rmd320,message);
STRING_ARG(hash,sha1,message);
STRING_ARG(hash,md2,message);
STRING_ARG(hash,md4,message);
STRING_ARG(hash,md5,message);
STRING_ARG(hash,tiger,message);
STRING_ARG(hash,whirlpool,message);

TWO_STRINGS(hmac,sha224,message,passphrase);
TWO_STRINGS(hmac,sha256,message,passphrase);
TWO_STRINGS(hmac,sha384,message,passphrase);
TWO_STRINGS(hmac,sha512,message,passphrase);
TWO_STRINGS(hmac,rmd128,message,passphrase);
TWO_STRINGS(hmac,rmd160,message,passphrase);
TWO_STRINGS(hmac,rmd256,message,passphrase);
TWO_STRINGS(hmac,rmd320,message,passphrase);
TWO_STRINGS(hmac,sha1,message,passphrase);
TWO_STRINGS(hmac,md2,message,passphrase);
TWO_STRINGS(hmac,md4,message,passphrase);
TWO_STRINGS(hmac,md5,message,passphrase);
TWO_STRINGS(hmac,tiger,message,passphrase);
TWO_STRINGS(hmac,whirlpool,message,passphrase);
