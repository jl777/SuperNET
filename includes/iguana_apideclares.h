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

STRING_ARG(SuperNET,bitcoinrpc,setcoin);
INT_ARG(ramchain,getblockhash,height);
HASH_AND_INT(ramchain,getblock,blockhash,remoteonly);
HASH_AND_INT(ramchain,getrawtransaction,txid,verbose);
HASH_ARG(ramchain,gettransaction,txid);
STRING_ARG(ramchain,decoderawtransaction,rawtx);

FOUR_STRINGS(SuperNET,login,handle,password,permanentfile,passphrase);
ZERO_ARGS(SuperNET,logout);
ZERO_ARGS(SuperNET,activehandle);
THREE_STRINGS(SuperNET,encryptjson,password,permanentfile,anything);
TWO_STRINGS(SuperNET,decryptjson,password,permanentfile);

THREE_STRINGS_AND_THREE_INTS(InstantDEX,orderbook,exchange,base,rel,depth,allfields,ignore);
THREE_STRINGS_AND_THREE_DOUBLES(InstantDEX,buy,exchange,base,rel,price,volume,dotrade);
THREE_STRINGS_AND_THREE_DOUBLES(InstantDEX,sell,exchange,base,rel,price,volume,dotrade);
THREE_STRINGS_AND_DOUBLE(InstantDEX,withdraw,exchange,base,destaddr,amount);
THREE_STRINGS(InstantDEX,apikeypair,exchange,apikey,apisecret);
THREE_STRINGS(InstantDEX,setuserid,exchange,userid,tradepassword);
THREE_STRINGS(InstantDEX,supports,exchange,base,rel);
TWO_STRINGS(InstantDEX,balance,exchange,base);
TWO_STRINGS(InstantDEX,orderstatus,exchange,orderid);
TWO_STRINGS(InstantDEX,cancelorder,exchange,orderid);
STRING_ARG(InstantDEX,openorders,exchange);
STRING_ARG(InstantDEX,tradehistory,exchange);
STRING_AND_INT(InstantDEX,pollgap,exchange,pollgap);
ZERO_ARGS(InstantDEX,allexchanges);
STRING_ARG(InstantDEX,allpairs,exchange);

THREE_STRINGS_AND_DOUBLE(InstantDEX,request,reference,base,rel,volume);
TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,proposal,reference,message,basetxid,reltxid,duration,flags);
TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,accept,reference,message,basetxid,reltxid,duration,flags);
TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,confirm,reference,message,basetxid,reltxid,baseheight,relheight);

THREE_STRINGS_AND_DOUBLE(tradebot,monitor,exchange,base,rel,commission);
STRING_AND_DOUBLE(tradebot,monitorall,exchange,commission);
THREE_STRINGS(tradebot,unmonitor,exchange,base,rel);
THREE_STRINGS_AND_THREE_DOUBLES(tradebot,accumulate,exchange,base,rel,price,volume,duration);
THREE_STRINGS_AND_THREE_DOUBLES(tradebot,divest,exchange,base,rel,price,volume,duration);
STRING_ARG(tradebot,activebots,exchange);
TWO_STRINGS(tradebot,status,exchange,botid);
TWO_STRINGS(tradebot,pause,exchange,botid);
TWO_STRINGS(tradebot,stop,exchange,botid);
TWO_STRINGS(tradebot,resume,exchange,botid);

HASH_ARG(pangea,call,tablehash);
HASH_AND_INT(pangea,raise,tablehash,numchips);
HASH_AND_INT(pangea,bet,tablehash,numchips);
HASH_ARG(pangea,check,tablehash);
HASH_ARG(pangea,fold,tablehash);
HASH_ARG(pangea,allin,tablehash);
HASH_ARG(pangea,status,tablehash);
HASH_AND_STRING(pangea,mode,tablehash,params);
HASH_ARG(pangea,history,tablehash);
HASH_AND_INT(pangea,handhistory,tablehash,hand);
INT_AND_ARRAY(pangea,host,minplayers,params);
ZERO_ARGS(pangea,lobby);
HASH_AND_STRING(pangea,join,tablehash,handle);
HASH_AND_INT(pangea,buyin,tablehash,numchips);
HASH_ARG(pangea,start,tablehash);

ZERO_ARGS(SuperNET,help);
STRING_ARG(SuperNET,utime2utc,utime);
INT_ARG(SuperNET,utc2utime,utc);

TWO_STRINGS(SuperNET,html,agentform,htmlfile);
TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(SuperNET,DHT,hexmsg,destip,categoryhash,subhash,maxdelay,broadcast);

THREE_STRINGS(SuperNET,rosetta,passphrase,pin,showprivkey);
ZERO_ARGS(SuperNET,keypair);
HASH_ARG(SuperNET,priv2pub,privkey);
STRING_ARG(SuperNET,wif2priv,wif);

TWOHASHES_AND_STRING(SuperNET,cipher,privkey,destpubkey,message);
TWOHASHES_AND_STRING(SuperNET,decipher,privkey,srcpubkey,cipherstr);

STRING_ARG(SuperNET,broadcastcipher,message);
STRING_ARG(SuperNET,broadcastdecipher,message);

HASH_AND_STRING(SuperNET,multicastcipher,pubkey,message);
HASH_AND_STRING(SuperNET,multicastdecipher,privkey,cipherstr);

TWO_STRINGS(SuperNET,subscribe,category,subcategory);
TWO_STRINGS(SuperNET,gethexmsg,category,subcategory);
THREE_STRINGS(SuperNET,posthexmsg,category,subcategory,hexmsg);
THREE_STRINGS(SuperNET,announce,category,subcategory,message);
THREE_STRINGS(SuperNET,survey,category,subcategory,message);
TWO_STRINGS(SuperNET,categoryhashes,category,subcategory);

STRING_AND_TWOINTS(mouse,image,name,x,y);
STRING_AND_TWOINTS(mouse,change,name,x,y);
STRING_AND_TWOINTS(mouse,click,name,x,y);
STRING_ARG(mouse,close,name);
STRING_ARG(mouse,leave,name);
STRING_AND_INT(keyboard,key,name,c);

STRING_ARG(SuperNET,getpeers,activecoin);
TWO_ARRAYS(SuperNET,mypeers,supernet,rawpeers);
ZERO_ARGS(SuperNET,stop);
HASH_AND_STRING(SuperNET,saveconf,wallethash,confjsonstr);
HASH_ARRAY_STRING(SuperNET,layer,mypriv,otherpubs,str);

STRING_ARG(iguana,peers,activecoin);
STRING_AND_INT(iguana,maxpeers,activecoin,max);
STRING_ARG(iguana,getconnectioncount,activecoin);
STRING_ARG(iguana,addcoin,newcoin);
STRING_ARG(iguana,startcoin,activecoin);
STRING_ARG(iguana,pausecoin,activecoin);
TWO_STRINGS(iguana,addnode,activecoin,ipaddr);
TWO_STRINGS(iguana,persistent,activecoin,ipaddr);
TWO_STRINGS(iguana,removenode,activecoin,ipaddr);
TWO_STRINGS(iguana,oneshot,activecoin,ipaddr);
TWO_STRINGS(iguana,nodestatus,activecoin,ipaddr);

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
THREE_INTS(ramchain,listreceivedbyaddress,minconf,includeempty,flag);
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

HASH_AND_TWOINTS(ramchain,listsinceblock,blockhash,target,flag);

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

STRING_ARG(hash,hex,message);
STRING_ARG(hash,unhex,hexmsg);
TWO_HASHES(hash,curve25519_pair,element,scalar);
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
STRING_ARG(hash,tiger192_3,message);
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
TWO_STRINGS(hmac,tiger192_3,message,passphrase);
TWO_STRINGS(hmac,whirlpool,message,passphrase);
