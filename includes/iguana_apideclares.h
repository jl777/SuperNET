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

#ifdef INCLUDE_PAX
ZERO_ARGS(pax,start);
#endif
HASH_ARRAY_STRING(tradebot,liquidity,hash,vals,targetcoin);
ZERO_ARGS(tradebot,amlp);
ZERO_ARGS(tradebot,notlp);

INT_AND_ARRAY(iguana,rates,unused,quotes);
TWO_STRINGS(iguana,rate,base,rel);
THREE_STRINGS_AND_THREE_INTS(iguana,prices,exchange,base,rel,period,start,end);

ZERO_ARGS(InstantDEX,allcoins);
STRING_ARG(InstantDEX,available,source);
HASH_ARRAY_STRING(InstantDEX,request,hash,vals,hexstr);

INT_ARG(InstantDEX,incoming,requestid);
INT_ARG(InstantDEX,automatched,requestid);

TWO_INTS(InstantDEX,accept,requestid,quoteid);
//TWO_INTS(InstantDEX,swapstatus,requestid,quoteid);

HASH_ARRAY_STRING(basilisk,genesis_opreturn,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,history,hash,vals,hexstr);

HASH_ARRAY_STRING(basilisk,balances,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,value,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,rawtx,hash,vals,hexstr);

HASH_ARRAY_STRING(basilisk,getmessage,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,sendmessage,hash,vals,hexstr);

HASH_ARRAY_STRING(basilisk,geckoheaders,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,geckoblock,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,geckotx,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,geckoget,hash,vals,hexstr);

HASH_ARRAY_STRING(basilisk,addrelay,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,dispatch,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,publish,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,subscribe,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,forward,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,mailbox,hash,vals,hexstr);

HASH_ARRAY_STRING(basilisk,VPNcreate,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,VPNjoin,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,VPNmessage,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,VPNbroadcast,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,VPNreceive,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,VPNlogout,hash,vals,hexstr);

HASH_ARRAY_STRING(basilisk,vote,hash,vals,hexstr);

ZERO_ARGS(bitcoinrpc,getinfo);
ZERO_ARGS(bitcoinrpc,getblockcount);
ZERO_ARGS(bitcoinrpc,getdifficulty);
ZERO_ARGS(bitcoinrpc,getbestblockhash);
INT_ARG(bitcoinrpc,getblockhash,height);
HASH_AND_TWOINTS(bitcoinrpc,getblock,blockhash,verbose,remoteonly);

HASH_AND_INT(bitcoinrpc,getrawtransaction,txid,verbose);
HASH_ARG(bitcoinrpc,gettransaction,txid);
HASH_AND_TWOINTS(bitcoinrpc,gettxout,txid,vout,mempool);
TWOINTS_AND_ARRAY(bitcoinrpc,listunspent,minconf,maxconf,array);

STRING_ARG(bitcoinrpc,decodescript,scriptstr);
//STRING_ARG(bitcoinrpc,decoderawtransaction,rawtx);
STRING_AND_INT(bitcoinrpc,decoderawtransaction,rawtx,suppress);
STRING_AND_INT(bitcoinrpc,validaterawtransaction,rawtx,suppress);
ARRAY_OBJ_INT(bitcoinrpc,createrawtransaction,vins,vouts,locktime);

ZERO_ARGS(iguana,makekeypair);
STRING_ARG(bitcoinrpc,validatepubkey,pubkey);
STRING_ARG(bitcoinrpc,validateaddress,address);
THREE_INTS(iguana,splitfunds,satoshis,duplicates,sendflag);

ZERO_ARGS(bitcoinrpc,walletlock);
TWOSTRINGS_AND_INT(bitcoinrpc,walletpassphrase,password,permanentfile,timeout);
THREE_STRINGS(bitcoinrpc,encryptwallet,passphrase,password,permanentfile);
FOUR_STRINGS(bitcoinrpc,walletpassphrasechange,oldpassword,newpassword,oldpermanentfile,permanentfile);
STRING_ARG(bitcoinrpc,dumpwallet,filename);
STRING_ARG(bitcoinrpc,backupwallet,filename);
STRING_ARG(bitcoinrpc,importwallet,filename);
STRING_ARG(bitcoinrpc,getnewaddress,account);
TWOSTRINGS_AND_INT(bitcoinrpc,importprivkey,wif,account,rescan);
STRING_ARG(bitcoinrpc,dumpprivkey,address);

STRING_AND_THREEINTS(bitcoinrpc,listtransactions,account,count,skip,includewatchonly);
THREE_INTS(bitcoinrpc,listreceivedbyaddress,minconf,includeempty,flag);
THREE_INTS(bitcoinrpc,listreceivedbyaccount,confirmations,includeempty,watchonly);
TWO_INTS(bitcoinrpc,listaccounts,minconf,includewatchonly);
ZERO_ARGS(bitcoinrpc,listaddressgroupings);
STRING_AND_INT(bitcoinrpc,getreceivedbyaddress,address,minconf);
STRING_AND_INT(bitcoinrpc,getreceivedbyaccount,account,includeempty);
STRING_AND_THREEINTS(bitcoinrpc,getbalance,account,confirmations,includeempty,lastheight);
STRING_ARG(bitcoinrpc,getaddressesbyaccount,account);
STRING_ARG(bitcoinrpc,getaccount,address);
STRING_ARG(bitcoinrpc,getaccountaddress,account);
TWO_STRINGS(bitcoinrpc,setaccount,address,account);

INT_ARRAY_STRING(bitcoinrpc,createmultisig,M,pubkeys,ignore);
INT_ARRAY_STRING(bitcoinrpc,addmultisigaddress,M,pubkeys,account);
DOUBLE_ARG(bitcoinrpc,settxfee,amount);

ZERO_ARGS(bitcoinrpc,checkwallet);
ZERO_ARGS(bitcoinrpc,repairwallet);

STRING_ARRAY_OBJ_STRING(bitcoinrpc,signrawtransaction,rawtx,vins,privkeys,sighash);
TWO_STRINGS(bitcoinrpc,signmessage,address,message);
THREE_STRINGS(bitcoinrpc,verifymessage,address,sig,message);
STRING_AND_INT(bitcoinrpc,sendrawtransaction,rawtx,allowhighfees);

SS_D_I_SS(bitcoinrpc,sendfrom,fromaccount,toaddress,amount,minconf,comment,comment2);
S_A_I_S(bitcoinrpc,sendmany,fromaccount,payments,minconf,comment);
S_D_SS(bitcoinrpc,sendtoaddress,address,amount,comment,comment2);
INT_AND_ARRAY(bitcoinrpc,lockunspent,flag,array); //
ZERO_ARGS(bitcoinrpc,listlockunspent); //
STRING_ARG(bitcoinrpc,submitblock,rawbytes); //

// maybe later
HASH_AND_TWOINTS(bitcoinrpc,listsinceblock,blockhash,target,flag);
ZERO_ARGS(bitcoinrpc,gettxoutsetinfo);
ZERO_ARGS(bitcoinrpc,getrawchangeaddress);
SS_D_I_S(bitcoinrpc,move,fromaccount,toaccount,amount,minconf,comment);

STRING_ARG(iguana,initfastfind,activecoin);
STRING_ARG(iguana,peers,activecoin);
STRING_AND_INT(iguana,maxpeers,activecoin,max);
STRING_ARG(iguana,getconnectioncount,activecoin);
STRING_ARG(iguana,addcoin,newcoin);
STRING_ARG(iguana,validate,activecoin);
STRING_ARG(iguana,removecoin,activecoin);
STRING_ARG(iguana,startcoin,activecoin);
STRING_ARG(iguana,pausecoin,activecoin);
STRING_ARG(iguana,stopcoin,activecoin);
TWO_STRINGS(iguana,addnode,activecoin,ipaddr);
TWO_STRINGS(iguana,persistent,activecoin,ipaddr);
TWO_STRINGS(iguana,removenode,activecoin,ipaddr);
TWO_STRINGS(iguana,oneshot,activecoin,ipaddr);
TWO_STRINGS(iguana,nodestatus,activecoin,ipaddr);
TWO_STRINGS_AND_TWO_DOUBLES(iguana,balance,activecoin,address,heightd,minconfd);
P2SH_SPENDAPI(iguana,spendmsig,activecoin,vintxid,vinvout,destaddress,destamount,destaddress2,destamount2,M,N,pubA,wifA,pubB,wifB,pubC,wifC);
STRING_AND_INT(iguana,bundleaddresses,activecoin,height);
STRING_AND_INT(iguana,bundlehashes,activecoin,height);
STRING_AND_INT(iguana,PoSweights,activecoin,height);
STRING_ARG(iguana,stakers,activecoin);

//TWO_STRINGS_AND_TWO_DOUBLES(InstantDEX,minaccept,base,rel,minprice,basevolume);
//TWO_STRINGS_AND_TWO_DOUBLES(InstantDEX,maxaccept,base,rel,maxprice,basevolume);
THREE_STRINGS_AND_THREE_DOUBLES(InstantDEX,buy,exchange,base,rel,price,volume,dotrade);
THREE_STRINGS_AND_THREE_DOUBLES(InstantDEX,sell,exchange,base,rel,price,volume,dotrade);
THREE_STRINGS_AND_DOUBLE(InstantDEX,withdraw,exchange,base,destaddr,amount);
THREE_STRINGS(InstantDEX,apikeypair,exchange,apikey,apisecret);
THREE_STRINGS(InstantDEX,setuserid,exchange,userid,tradepassword);
TWO_STRINGS(InstantDEX,balance,exchange,base);
TWO_STRINGS(InstantDEX,orderstatus,exchange,orderid);
TWO_STRINGS(InstantDEX,cancelorder,exchange,orderid);
STRING_ARG(InstantDEX,openorders,exchange);
STRING_ARG(InstantDEX,tradehistory,exchange);

THREE_STRINGS_AND_THREE_INTS(InstantDEX,orderbook,exchange,base,rel,depth,allfields,ignore);
STRING_AND_INT(InstantDEX,pollgap,exchange,pollgap);
//TWO_STRINGS(InstantDEX,events,base,rel);
ZERO_ARGS(InstantDEX,allexchanges);
STRING_ARG(InstantDEX,allpairs,exchange);
THREE_STRINGS(InstantDEX,supports,exchange,base,rel);

//THREE_STRINGS(atomic,approve,myorderid,otherid,txname);
//THREE_STRINGS(atomic,claim,myorderid,otherid,txname);

//TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,proposal,reference,message,basetxid,reltxid,duration,flags);
//TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,accept,reference,message,basetxid,reltxid,duration,flags);
//TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,confirm,reference,message,basetxid,reltxid,baseheight,relheight);

THREE_STRINGS_AND_DOUBLE(tradebot,aveprice,comment,base,rel,basevolume);
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

#ifndef WIN32
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
#endif

ZERO_ARGS(SuperNET,help);
STRING_ARG(SuperNET,utime2utc,utime);
INT_ARG(SuperNET,utc2utime,utc);
STRING_ARG(SuperNET,getpeers,activecoin);
TWO_ARRAYS(SuperNET,mypeers,supernet,rawpeers);
ZERO_ARGS(SuperNET,stop);
HASH_AND_STRING(SuperNET,saveconf,wallethash,confjsonstr);
HASH_ARRAY_STRING(SuperNET,layer,mypriv,otherpubs,str);

STRING_ARG(SuperNET,bitcoinrpc,setcoin);
STRING_ARG(SuperNET,myipaddr,ipaddr);
STRING_ARG(SuperNET,setmyipaddr,ipaddr);

FOUR_STRINGS(SuperNET,login,handle,password,permanentfile,passphrase);
ZERO_ARGS(SuperNET,logout);
ZERO_ARGS(SuperNET,activehandle);
THREE_STRINGS(SuperNET,encryptjson,password,permanentfile,payload);
TWO_STRINGS(SuperNET,decryptjson,password,permanentfile);

TWO_STRINGS(SuperNET,html,agentform,htmlfile);
//TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(SuperNET,DHT,hexmsg,destip,categoryhash,subhash,maxdelay,broadcast);

THREE_STRINGS(SuperNET,rosetta,passphrase,pin,showprivkey);
ZERO_ARGS(SuperNET,keypair);
HASH_AND_INT(SuperNET,priv2pub,privkey,addrtype);
STRING_ARG(SuperNET,wif2priv,wif);
STRING_ARG(SuperNET,priv2wif,priv);
STRING_ARG(SuperNET,addr2rmd160,address);
STRING_ARG(SuperNET,rmd160conv,rmd160);

TWOHASHES_AND_STRING(SuperNET,cipher,privkey,destpubkey,message);
TWOHASHES_AND_STRING(SuperNET,decipher,privkey,srcpubkey,cipherstr);

STRING_ARG(SuperNET,broadcastcipher,message);
STRING_ARG(SuperNET,broadcastdecipher,message);

HASH_AND_STRING(SuperNET,multicastcipher,pubkey,message);
HASH_AND_STRING(SuperNET,multicastdecipher,privkey,cipherstr);

/*TWO_STRINGS(SuperNET,subscribe,category,subcategory);
TWO_STRINGS(SuperNET,gethexmsg,category,subcategory);
THREE_STRINGS(SuperNET,posthexmsg,category,subcategory,hexmsg);
THREE_STRINGS(SuperNET,announce,category,subcategory,message);
THREE_STRINGS(SuperNET,survey,category,subcategory,message);
TWO_STRINGS(SuperNET,categoryhashes,category,subcategory);*/

STRING_AND_TWOINTS(mouse,image,name,x,y);
STRING_AND_TWOINTS(mouse,change,name,x,y);
STRING_AND_TWOINTS(mouse,click,name,x,y);
STRING_ARG(mouse,close,name);
STRING_ARG(mouse,leave,name);
STRING_AND_INT(keyboard,key,name,c);

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
