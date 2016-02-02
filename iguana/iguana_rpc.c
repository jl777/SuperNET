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
#include "SuperNET.h"

#define RPCARGS struct supernet_info *myinfo,struct iguana_info *coin,cJSON *params[],int32_t n,cJSON *json,char *remoteaddr

char *sglue(cJSON *json,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,char *agent,char *method)
{
    char *retstr,*rpcretstr; cJSON *retjson,*result,*error; int32_t i,j,len;
    if ( json == 0 )
        json = cJSON_CreateObject();
    jaddstr(json,"agent",agent);
    jaddstr(json,"method",method);
    jaddstr(json,"coin",coin->symbol);
    if ( (retstr= SuperNET_JSON(myinfo,json,remoteaddr)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            jdelete(retjson,"tag");
            //printf("RPCret.(%s) n.%d\n",jprint(retjson,0),cJSON_GetArraySize(retjson));
            result = cJSON_GetObjectItem(retjson,"result");
            error = cJSON_GetObjectItem(retjson,"error");
            if ( result != 0 && cJSON_GetArraySize(retjson) == 1 )
            {
                if ( (error == 0 || (error->type&0xff) == cJSON_NULL) && (result->type&0xff) != cJSON_NULL )
                {
                    rpcretstr = cJSON_Print(result);
                    len = (int32_t)strlen(rpcretstr);
                    if ( rpcretstr[0] == '"' && rpcretstr[len-1] == '"' )
                    {
                        for (i=1,j=0; i<len-1; i++,j++)
                            rpcretstr[j] = rpcretstr[i];
                        rpcretstr[j] = '\n';
                        free_json(json);
                        free_json(retjson);
                        free(retstr);
                        return(rpcretstr);
                    }
                    free(rpcretstr);
                }
                else if ( (error->type&0xff) != cJSON_NULL || (result->type&0xff) != cJSON_NULL )
                    printf("<<<<<<<<<<< bitcoind_RPC: post_process_bitcoind_RPC error.%s\n",retstr);
            }
            free_json(retjson);
        }
    }
    free_json(json);
    return(retstr);
}

char *sglue1(cJSON *json,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,char *agent,char *method,char *field,cJSON *obj)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    if ( obj != 0 )
        jadd(json,field,obj);
    return(sglue(json,myinfo,coin,remoteaddr,agent,method));
}

char *sglueN(cJSON *json,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,char *agent,char *method,char *field,double num)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    jaddnum(json,field,num);
    return(sglue(json,myinfo,coin,remoteaddr,agent,method));
}

char *sglue2(cJSON *json,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,char *agent,char *method,char *field0,cJSON *obj0,char *field1,cJSON *obj1)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    if ( obj1 != 0 )
        jadd(json,field1,obj1);
    return(sglue1(json,myinfo,coin,remoteaddr,agent,method,field0,obj0));
}

char *sglue3(cJSON *json,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,char *agent,char *method,char *field0,cJSON *obj0,char *field1,cJSON *obj1,char *field2,cJSON *obj2)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    if ( obj2 != 0 )
        jadd(json,field2,obj2);
    return(sglue2(json,myinfo,coin,remoteaddr,agent,method,field0,obj0,field1,obj1));
}

char *sglue4(cJSON *json,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,char *agent,char *method,char *field0,cJSON *obj0,char *field1,cJSON *obj1,char *field2,cJSON *obj2,char *field3,cJSON *obj3)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    if ( obj3 != 0 )
        jadd(json,field3,obj3);
    return(sglue3(json,myinfo,coin,remoteaddr,agent,method,field0,obj0,field1,obj1,field2,obj2));
}

char *sglue5(cJSON *json,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,char *agent,char *method,char *field0,cJSON *obj0,char *field1,cJSON *obj1,char *field2,cJSON *obj2,char *field3,cJSON *obj3,char *field4,cJSON *obj4)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    if ( obj4 != 0 )
        jadd(json,field4,obj4);
    return(sglue4(json,myinfo,coin,remoteaddr,agent,method,field0,obj0,field1,obj1,field2,obj2,field3,obj3));
}

char *sglue6(cJSON *json,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,char *agent,char *method,char *field0,cJSON *obj0,char *field1,cJSON *obj1,char *field2,cJSON *obj2,char *field3,cJSON *obj3,char *field4,cJSON *obj4,char *field5,cJSON *obj5)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    if ( obj5 != 0 )
        jadd(json,field5,obj5);
    return(sglue5(json,myinfo,coin,remoteaddr,agent,method,field0,obj0,field1,obj1,field2,obj2,field3,obj3,field4,obj4));
}

// misc
static char *help(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"SuperNET","help"));
}

static char *stop(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"iguana","pausecoin"));
}

static char *sendalert(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"iguana","sendalert","message",params[0]));
}

static char *SuperNET(RPCARGS)
{
    return(SuperNET_JSON(myinfo,json,remoteaddr));
}

static char *getrawmempool(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"iguana","getrawmempool"));
}

// peers
static char *getconnectioncount(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"iguana","getconnectioncount"));
}

static char *getpeerinfo(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"iguana","peers"));
}

static char *addnode(RPCARGS)
{
    char *mode,*cmd = 0;
    if ( (mode= jstr(params[1],0)) != 0 )
    {
        if ( strcmp(mode,"add") == 0 )
            cmd = "addnode";
        else if ( strcmp(mode,"remove") == 0 )
            cmd = "removenode";
        else if ( strcmp(mode,"onetry") == 0 )
            cmd = "onetry";
        if ( cmd != 0 )
            return(sglue1(0,myinfo,coin,remoteaddr,"iguana",cmd,"ipaddr",params[0]));
    }
    // addnode	<node> <add/remove/onetry>	version 0.8 Attempts add or remove <node> from the addnode list or try a connection to <node> once.	N
    return(clonestr("{\"error\":\"invalid addnode parameter\"}"));
}

// address and pubkeys
static char *validateaddress(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","validateaddress","address",params[0]));
}

static char *validatepubkey(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","validatepubkey","pubkey",params[0]));
}

static char *createmultisig(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","createmultisig","M",params[0],"pubkeys",params[1]));
}

static char *addmultisigaddress(RPCARGS)
{
    return(sglue3(0,myinfo,coin,remoteaddr,"ramchain","createmultisig","M",params[0],"pubkeys",params[1],"account",params[2]));
}

// blockchain
static char *getinfo(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"ramchain","status"));
}

static char *getbestblockhash(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"ramchain","getbestblockhash"));
}

static char *getblockcount(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"ramchain","getblockcount"));
}

static char *getblock(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","getblock","blockhash",params[0]));
}

static char *getblockhash(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","getblockhash","height",params[0]));
}

static char *gettransaction(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","tx","txid",params[0]));
}

static char *listtransactions(RPCARGS)
{
    return(sglue3(0,myinfo,coin,remoteaddr,"ramchain","listtransactions","account",params[0],"count",params[1],"from",params[2]));
}

static char *getreceivedbyaddress(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","getreceivedbyaddress","address",params[0],"minconfs",params[1]));
}

static char *listreceivedbyaddress(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","listreceivedbyaddress","minconf",params[0],"includeempty",params[1]));
}

static char *listsinceblock(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","listsinceblock","blockhash",params[0],"target",params[1]));
}

// waccount and waddress funcs
static char *getreceivedbyaccount(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","getreceivedbyaccount","account",params[0],"minconfs",params[1]));
}

static char *listreceivedbyaccount(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","listreceivedbyaccount","account",params[0],"includeempty",params[1]));
}

static char *getnewaddress(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","getnewaddress","account",params[0]));
}

static char *vanitygen(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","vanitygen","vanity",params[0]));
}

static char *makekeypair(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"ramchain","makekeypair"));
}

static char *getaccountaddress(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","getaccountaddress","account",params[0]));
}

static char *setaccount(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","setaccount","address",params[0],"account",params[1]));
}

static char *getaccount(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","getaccount","address",params[0]));
}

static char *getaddressesbyaccount(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","getaddressesbyaccount","account",params[0]));
}

static char *listaddressgroupings(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"ramchain","listaddressgroupings"));
}

static char *getbalance(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","getbalance","account",params[0],"minconf",params[1]));
}

// wallet
static char *listaccounts(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","listaccounts","minconf",params[0]));
}

static char *dumpprivkey(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","dumpprivkey","address",params[0]));
}

static char *importprivkey(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","importprivkey","wif",params[0]));
}

static char *dumpwallet(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"ramchain","dumpwallet"));
}

static char *importwallet(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","importwallet","wallet",params[0]));
}

static char *walletpassphrase(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","walletpassphrase","passphrase",params[0],"timeout",params[1]));
}

static char *walletpassphrasechange(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","walletpassphrasechange","oldpassphrase",params[0],"newpassphrase",params[1]));
}

static char *walletlock(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"ramchain","walletlock"));
}

static char *encryptwallet(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","encryptwallet","passphrase",params[0]));
}

static char *checkwallet(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"ramchain","checkwallet"));
}

static char *repairwallet(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"ramchain","repairwallet"));
}

static char *backupwallet(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","backupwallet","filename",params[0]));
}

// messages
static char *signmessage(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","signmessage","address",params[0],"message",params[1]));
}

static char *verifymessage(RPCARGS)
{
    return(sglue3(0,myinfo,coin,remoteaddr,"ramchain","verifymessage","address",params[0],"sig",params[1],"message",params[2]));
}

// unspents
static char *listunspent(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","listunspent","minconf",params[0],"maxconf",params[1]));
}

static char *lockunspent(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","lockunspent","flag",params[0],"array",params[1]));
}

static char *listlockunspent(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"ramchain","listlockunspent"));
}

static char *gettxout(RPCARGS)
{
    return(sglue3(0,myinfo,coin,remoteaddr,"ramchain","gettxout","txid",params[0],"vout",params[1],"mempool",params[2]));
}

static char *gettxoutsetinfo(RPCARGS)
{
    return(sglue(0,myinfo,coin,remoteaddr,"ramchain","gettxoutsetinfo"));
}

// payments
static char *sendtoaddress(RPCARGS)
{
    return(sglue4(0,myinfo,coin,remoteaddr,"ramchain","sendtoaddress","address",params[0],"amount",params[1],"comment",params[2],"comment2",params[3]));
}

static char *movecmd(RPCARGS)
{
    return(sglue5(0,myinfo,coin,remoteaddr,"ramchain","move","fromaccount",params[0],"toaccount",params[1],"amount",params[2],"minconf",params[3],"comment",params[4]));
}

static char *sendfrom(RPCARGS)
{
    return(sglue6(0,myinfo,coin,remoteaddr,"ramchain","sendfrom","fromaccount",params[0],"toaddress",params[1],"amount",params[2],"minconf",params[3],"comment",params[4],"comment2",params[5]));
}

static char *sendmany(RPCARGS)
{
    return(sglue4(0,myinfo,coin,remoteaddr,"ramchain","sendmany","fromaccount",params[0],"payments",params[1],"minconf",params[2],"comment",params[3]));
}

static char *settxfee(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","settxfee","amount",params[0]));
}

// rawtransaction
static char *getrawtransaction(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","getrawtransaction","txid",params[0],"verbose",params[1]));
}

static char *createrawtransaction(RPCARGS)
{
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","createrawtransaction","vins",params[0],"vouts",params[1]));
}

static char *decoderawtransaction(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","decoderawtransaction","rawtx",params[0]));
}

static char *decodescript(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","decodescript","script",params[0]));
}

static char *signrawtransaction(RPCARGS)
{
    return(sglue3(0,myinfo,coin,remoteaddr,"ramchain","signrawtransaction","rawtx",params[0],"vins",params[1],"privkeys",params[2]));
}

static char *sendrawtransaction(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","sendrawtransaction","rawtx",params[0]));
}

static char *getrawchangeaddress(RPCARGS)
{
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","getrawchangeaddress","account",params[0]));
}

#define true 1
#define false 0
struct RPC_info { char *name; char *(*rpcfunc)(RPCARGS); int32_t flag0,remoteflag; } RPCcalls[] =
{
    { "SuperNET",               &SuperNET,               false,  true },
  //{ "SuperNETb",              &SuperNET,               false,  true },
    { "help",                   &help,                   true,   false },
    { "stop",                   &stop,                   true,   true },
    { "getbestblockhash",       &getbestblockhash,       true,   true },
    { "getblockcount",          &getblockcount,          true,   true },
    { "getconnectioncount",     &getconnectioncount,     true,   true },
    { "getpeerinfo",            &getpeerinfo,            true,   true },
    { "getinfo",                &getinfo,                true,   true },
    { "getnewaddress",          &getnewaddress,          true,   false },
    { "getnewpubkey",           &makekeypair,            true,   false },
    { "getaccountaddress",      &getaccountaddress,      true,   false },
    { "setaccount",             &setaccount,             true,   false },
    { "getaccount",             &getaccount,             false,  false },
    { "getaddressesbyaccount",  &getaddressesbyaccount,  true,   false },
    { "sendtoaddress",          &sendtoaddress,          false,  false },
    { "getreceivedbyaddress",   &getreceivedbyaddress,   false,  false },
    { "getreceivedbyaccount",   &getreceivedbyaccount,   false,  false },
    { "listreceivedbyaddress",  &listreceivedbyaddress,  false,  false },
    { "listreceivedbyaccount",  &listreceivedbyaccount,  false,  false },
    { "backupwallet",           &backupwallet,           true,   false },
    { "walletpassphrase",       &walletpassphrase,       true,   false },
    { "walletpassphrasechange", &walletpassphrasechange, false,  false },
    { "walletlock",             &walletlock,             true,   false },
    { "encryptwallet",          &encryptwallet,          false,  false },
    { "validateaddress",        &validateaddress,        true,   true },
    { "validatepubkey",         &validatepubkey,         true,   true },
    { "getbalance",             &getbalance,             false,  false },
    { "move",                   &movecmd,                false,  false },
    { "sendfrom",               &sendfrom,               false,  false },
    { "sendmany",               &sendmany,               false,  false },
    { "addmultisigaddress",     &addmultisigaddress,     false,  false },
    { "getblock",               &getblock,               false,  true },
    { "getblockhash",           &getblockhash,           false,  true },
    { "gettransaction",         &gettransaction,         false,  true },
    { "listtransactions",       &listtransactions,       false,  false },
    { "listaddressgroupings",   &listaddressgroupings,   false,  false },
    { "signmessage",            &signmessage,            false,  false },
    { "verifymessage",          &verifymessage,          false,  false },
    { "listaccounts",           &listaccounts,           false,  false },
    { "settxfee",               &settxfee,               false,  false },
    { "listsinceblock",         &listsinceblock,         false,  false },
    { "dumpprivkey",            &dumpprivkey,            false,  false },
    { "dumpwallet",             &dumpwallet,             true,   false },
    { "importwallet",           &importwallet,           false,  false },
    { "importprivkey",          &importprivkey,          false,  false },
    { "listunspent",            &listunspent,            false,  false },
    { "getrawtransaction",      &getrawtransaction,      false,  false },
    { "createrawtransaction",   &createrawtransaction,   false,  false },
    { "decoderawtransaction",   &decoderawtransaction,   false,  true },
    { "decodescript",           &decodescript,           false,  true },
    { "signrawtransaction",     &signrawtransaction,     false,  false },
    { "sendrawtransaction",     &sendrawtransaction,     false,  true },
    { "checkwallet",            &checkwallet,            false,  false },
    { "repairwallet",           &repairwallet,           false,  false },
    { "makekeypair",            &makekeypair,            false,  false },
    { "sendalert",              &sendalert,              false,  false },
    //
    { "createmultisig",         &createmultisig,         false,  false },
    { "addnode",                &addnode,                false,  false },
    { "getrawmempool",          &getrawmempool,          false,  true },
    { "getrawchangeaddress",    &getrawchangeaddress,    false,  false },
    { "listlockunspent",        &listlockunspent,        false,  false },
    { "lockunspent",            &lockunspent,            false,  false },
    { "gettxout",               &gettxout,               false,  true },
    { "gettxoutsetinfo",        &gettxoutsetinfo,        false,  true },
    { "vanitygen",              &vanitygen,              false,  false }
#ifdef PEGGY
    //{ "peggytx",                &peggytx,                true,   false },
    //{ "peggypayments",          &peggypayments,          true,   false },
    //{ "getpeggyblock",          &getpeggyblock,          true,   false },
#endif
    //{ "resendtx",               &resendtx,               false,  true},
 // { "addredeemscript",        &addredeemscript,        false,  false },
    //  { "getrawmempool",          &getrawmempool,          true,   false },
    //    { "getdifficulty",          &getdifficulty,          true,   false },
    //    { "getsubsidy",             &getsubsidy,             true,   false },
    //    { "getmininginfo",          &getmininginfo,          true,   false },
    //    { "getstakinginfo",         &getstakinginfo,         true,   false },
    // { "getblockbynumber",       &getblockbynumber,       false,  false },
    //{ "getwork",                &getwork,                true,   false },
    //{ "getworkex",              &getworkex,              true,   false },
    // { "keypoolrefill",          &keypoolrefill,          true,   false },
    //{ "getblocktemplate",       &getblocktemplate,       true,   false },
    //{ "submitblock",            &submitblock,            false,  false },
    // { "getcheckpoint",          &getcheckpoint,          true,   false },
    // { "reservebalance",         &reservebalance,         false,  true},
};

int32_t is_bitcoinrpc(char *method,char *remoteaddr)
{
    int32_t i;
    for (i=0; i<sizeof(RPCcalls)/sizeof(*RPCcalls); i++)
    {
        if ( strcmp(RPCcalls[i].name,method) == 0 )
        {
            if ( RPCcalls[i].remoteflag != 0 || (RPCcalls[i].remoteflag == 0 && (remoteaddr == 0 || remoteaddr[0] == 0 || strcmp(remoteaddr,"127.0.0.1") == 0)) )
                return(i);
        }
    }
    return(-1);
}

char *iguana_bitcoinrpc(struct supernet_info *myinfo,struct iguana_info *coin,char *method,cJSON *params[16],int32_t n,cJSON *json,char *remoteaddr)
{
    int32_t i;
    for (i=0; i<sizeof(RPCcalls)/sizeof(*RPCcalls); i++)
    {
        if ( strcmp(RPCcalls[i].name,method) == 0 )
            return((*RPCcalls[i].rpcfunc)(myinfo,coin,params,n,json,remoteaddr));
    }
    return(clonestr("{\"error\":\"invalid coin address\"}"));
}

char *iguana_bitcoinRPC(struct supernet_info *myinfo,char *method,cJSON *json,char *remoteaddr)
{
    cJSON *params[16],*array; struct iguana_info *coin; char *symbol; int32_t i,n; char *retstr = 0;
    memset(params,0,sizeof(params));
    if ( json != 0 )
    {
        if ( (symbol= jstr(json,"coin")) == 0 || symbol[0] == 0 )
            symbol = myinfo->rpcsymbol;
        if ( method != 0 && symbol != 0 && (coin= iguana_coinfind(symbol)) != 0 )
        {
            if ( (array= jarray(&n,json,"params")) == 0 )
            {
                n = 1;
                params[0] = jobj(json,"params");
            }
            else
            {
                params[0] = jitem(array,0);
                if ( n > 1 )
                    for (i=1; i<n; i++)
                        params[i] = jitem(array,i);
            }
            retstr = iguana_bitcoinrpc(myinfo,coin,method,params,n,json,remoteaddr);
        }
        free_json(json);
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"cant parse jsonstr\"}");
    return(retstr);
}

int32_t Supernet_lineparse(char *key,int32_t keymax,char *value,int32_t valuemax,char *src)
{
    int32_t a,b,c,n = 0; //char *origkey=key,*origvalue=value;
    key[0] = value[0] = 0;
    while ( (c= src[n]) == ' ' || c == '\t' || c == '\n' || c == '\t' )
        n++;
    while ( (c= src[n]) != ':' && c != 0 )
    {
        *key++ = c;
        //printf("(%c) ",c);
        if ( ++n >= keymax-1 )
        {
            *key = 0;
            printf("lineparse overflow key.(%s)\n",src);
            return(-1);
        }
    }
    *key = 0;
    //printf("-> key.(%s)\n",origkey);
    if ( src[n] != ':' )
        return(n);
    n++;
    while ( (c= src[n]) == ' ' || c == '\t' )
        n++;
    while ( (c= src[n]) != 0 && c != '\r' && c != '\n' )
    {
        if ( c == '%' && (a= src[n+1]) != 0 && (b= src[n+2]) != 0 )
            c = ((unhex(a) << 4) | unhex(b)), n += 2;
        *value++ = c;
        n++;
        if ( n >= valuemax-1 )
        {
            *value = 0;
            printf("lineparse overflow.(%s)\n",src);
            return(-1);
        }
    }
    *value = 0;
    if ( src[n] != 0 )
    {
        n++;
        while ( (c= src[n]) == '\r' || c == '\n' )
            n++;
    }
    //printf("key.(%s) value.(%s)\n",origkey,origvalue);
    return(n);
}

cJSON *SuperNET_urlconv(char *value,int32_t bufsize,char *urlstr)
{
    int32_t i,n,totallen,datalen,len = 0; cJSON *json,*array; char key[8192],*data;
    json = cJSON_CreateObject();
    array = cJSON_CreateArray();
    totallen = (int32_t)strlen(urlstr);
    while ( 1 )
    {
        for (i=len; urlstr[i]!=0; i++)
            if ( urlstr[i] == '\r' || urlstr[i] == '\n' )
                break;
        if ( i == len && (urlstr[len] == '\r' || urlstr[len] == '\n') )
        {
            len++;
            continue;
        }
        urlstr[i] = 0;
        //printf("URLSTR[%d]=%s\n",i,&urlstr[len]);
        if ( (n= Supernet_lineparse(key,sizeof(key),value,bufsize,&urlstr[len])) > 0 )
        {
            if ( value[0] != 0 )
                jaddstr(json,key,value);
            else jaddistr(array,key);
            len += (n + 1);
            if ( strcmp(key,"Content-Length") == 0 && (datalen= atoi(value)) > 0 )
            {
                data = &urlstr[totallen - datalen];
                data[-1] = 0;
                //printf("post.(%s) (%c)\n",data,data[0]);
                jaddstr(json,"POST",data);
            }
        } else break;
    }
    jadd(json,"lines",array);
    //printf("urlconv.(%s)\n",jprint(json,0));
    return(json);
}

char *SuperNET_rpcparse(struct supernet_info *myinfo,char *retbuf,int32_t bufsize,int32_t *jsonflagp,int32_t *postflagp,char *urlstr,char *remoteaddr)
{
    cJSON *tokens,*argjson,*json = 0; long filesize;
    char symbol[16],buf[4096],urlmethod[16],*data,url[1024],*retstr,*token = 0; int32_t i,j,n,num=0;
    //printf("rpcparse.(%s)\n",urlstr);
    for (i=0; i<sizeof(urlmethod)-1&&urlstr[i]!=0&&urlstr[i]!=' '; i++)
        urlmethod[i] = urlstr[i];
    urlmethod[i++] = 0;
    n = i;
    //printf("URLMETHOD.(%s)\n",urlmethod);
    *postflagp = (strcmp(urlmethod,"POST") == 0);
    for (i=0; i<sizeof(url)-1&&urlstr[n+i]!=0&&urlstr[n+i]!=' '; i++)
        url[i] = urlstr[n+i];
    url[i++] = 0;
    n += i;
    j = i = 0;
    //printf("url.(%s) method.(%s)\n",&url[i],urlmethod);
    if ( strcmp(&url[i],"/") == 0 && strcmp(urlmethod,"GET") == 0 )
    {
        *jsonflagp = 1;
        SuperNET_htmlstr("index7778.html",retbuf,bufsize,0);
        return(OS_filestr(&filesize,"index7778.html"));
    }
    if ( strncmp(&url[i],"/api",strlen("/api")) == 0 )
    {
        *jsonflagp = 1;
        i += strlen("/api");
    } else *jsonflagp = 0;
    if ( strncmp(&url[i],"/bitmap",strlen("/bitmap")) == 0 )
    {
        i += strlen("/bitmap");
        *jsonflagp = 2;
        if ( url[i] == '/' )
            i++;
        iguana_bitmap(retbuf,bufsize,&url[i]);
        return(retbuf);
    }
    //printf("URL.(%s)\n",url);
    if ( strcmp(url,"/favicon.ico") == 0 )
    {
        *jsonflagp = -1;
        return(0);
    }
    if ( url[i] != '/' )
        token = &url[i];
    n = i;
    tokens = cJSON_CreateArray();
    for (; url[i]!=0; i++)
    {
        //printf("i.%d (%c)\n",i,url[i]);
        if ( url[i] == '/' )
        {
            url[i] = 0;
            if ( token != 0 )
            {
                //printf("TOKEN.(%s) i.%d\n",token,i);
                jaddistr(tokens,token);
                num++;
            }
            token = &url[i+1];
            i++;
            //printf("new token.(%s) i.%d\n",token,i+1);
            continue;
        }
    }
    if ( token != 0 )
    {
        //printf("add token.(%s)\n",token);
        jaddistr(tokens,token);
        num++;
    }
    argjson = cJSON_CreateObject();
    if ( num > 0 )
        jaddstr(argjson,"agent",jstri(tokens,0));
    if ( num > 1 )
        jaddstr(argjson,"method",jstri(tokens,1));
    //printf("urlstr.(%s)\n",urlstr+n);
    if ( (json= SuperNET_urlconv(retbuf,bufsize,urlstr+n)) != 0 )
    {
        jadd(json,"tokens",tokens);
        jaddstr(json,"urlmethod",urlmethod);
        if ( (data= jstr(json,"POST")) == 0 || (argjson= cJSON_Parse(data)) == 0 )
        {
            if ( (n= cJSON_GetArraySize(tokens)) > 0 )
            {
                if ( n > 1 )
                {
                    if ( jstri(tokens,1) != 0 )
                    {
                        char *key,*value;
                        strcpy(buf,jstri(tokens,1));
                        key = value = 0;
                        i = 0;
                        for (; buf[i]!=0; i++)
                        {
                            if ( buf[i] == '?' )
                            {
                                buf[i] = 0;
                                jdelete(argjson,"method");
                                jaddstr(argjson,"method",buf);
                                i++;
                                key = &buf[i];
                                break;
                            }
                        }
                        while ( buf[i] != 0 )
                        {
                            //printf("iter.[%s]\n",&buf[i]);
                            if ( buf[i] != 0 && key != 0 )
                            {
                                for (; buf[i]!=0; i++)
                                {
                                    if ( buf[i] == '=' )
                                    {
                                        buf[i] = 0;
                                        i++;
                                        //printf("got key.(%s)\n",key);
                                        value = &buf[i];
                                        break;
                                    }
                                }
                                if ( buf[i] != 0 && value != 0 )
                                {
                                    for (; buf[i]!=0; i++)
                                    {
                                        if ( buf[i] == '&' )
                                        {
                                            buf[i] = 0;
                                            jaddstr(argjson,key,value);
                                            i++;
                                            //printf("got value.(%s)\n",value);
                                            value = 0;
                                            key = &buf[i];
                                            break;
                                        }
                                        else if ( buf[i] == '+' )
                                            buf[i] = ' ';
                                    }
                                }
                            }
                        }
                        if ( key != 0 && value != 0 )
                            jaddstr(argjson,key,value);
                    }
                    else
                    {
                        //jdelete(argjson,"method");
                        //jaddstr(argjson,"method",buf);
                    }
                }
                for (i=2; i<n; i++)
                {
                    if ( i == n-1 )
                        jaddstr(argjson,"data",jstri(tokens,i));
                    else
                    {
                        if ( strcmp(jstri(tokens,i),"coin") == 0 && strlen(jstri(tokens,i+1)) < 8 )
                        {
                            strcpy(symbol,jstri(tokens,i+1));
                            touppercase(symbol);
                            jaddstr(argjson,jstri(tokens,i),symbol);
                        } else jaddstr(argjson,jstri(tokens,i),jstri(tokens,i+1));
                        i++;
                    }
                }
            }
        }
        //printf("after urlconv.(%s) argjson.(%s)\n",jprint(json,0),jprint(argjson,0));
        if ( jstr(argjson,"method") == 0 )
        {
            free_json(argjson);
            return(0);
        }
        retstr = SuperNET_JSON(myinfo,argjson,remoteaddr);
        //printf("(%s) {%s} -> (%s) postflag.%d (%s)\n",urlstr,jprint(argjson,0),cJSON_Print(json),*postflagp,retstr);
        free_json(argjson);
        return(retstr);
    }
    return(clonestr("{\"error\":\"couldnt process packet\"}"));
}

void iguana_rpcloop(void *args)
{
    struct supernet_info *myinfo = args;
    int32_t recvlen,bindsock,postflag,sock,remains,numsent,jsonflag,len; socklen_t clilen;
    char remoteaddr[64],jsonbuf[8192],*buf,*retstr,*space;//,*retbuf; ,n,i,m
    struct sockaddr_in cli_addr; uint32_t ipbits,i,size = IGUANA_WIDTH*IGUANA_HEIGHT*16 + 512; uint16_t port;
    port = IGUANA_RPCPORT;
    while ( (bindsock= iguana_socket(1,"127.0.0.1",port)) < 0 )
        exit(-1);
    printf("iguana_rpcloop 127.0.0.1:%d bind sock.%d\n",port,bindsock);
    space = calloc(1,size);
    while ( bindsock >= 0 )
    {
        clilen = sizeof(cli_addr);
        //printf("ACCEPT (%s:%d) on sock.%d\n","127.0.0.1",port,bindsock);
        sock = accept(bindsock,(struct sockaddr *)&cli_addr,&clilen);
        if ( sock < 0 )
        {
            //printf("iguana_rpcloop ERROR on accept usock.%d\n",sock);
            continue;
        }
        memcpy(&ipbits,&cli_addr.sin_addr.s_addr,sizeof(ipbits));
        expand_ipbits(remoteaddr,ipbits);
        //printf("RPC.%d for %x (%s)\n",sock,ipbits,ipaddr);
        //printf("%p got.(%s) from %s | usock.%d ready.%u dead.%u\n",addr,H.command,addr->ipaddr,addr->usock,addr->ready,addr->dead);
        memset(jsonbuf,0,sizeof(jsonbuf));
        remains = (int32_t)(sizeof(jsonbuf) - 1);
        buf = jsonbuf;
        recvlen = 0;
        retstr = 0;
        while ( remains > 0 )
        {
            if ( (len= (int32_t)recv(sock,buf,remains,0)) < 0 )
            {
                if ( errno == EAGAIN )
                {
                    printf("EAGAIN for len %d, remains.%d\n",len,remains);
                    usleep(10000);
                }
                break;
            }
            else
            {
                if ( len > 0 )
                {
                    remains -= len;
                    recvlen += len;
                    buf = &buf[len];
                    retstr = SuperNET_rpcparse(myinfo,space,size,&jsonflag,&postflag,jsonbuf,remoteaddr);
                    break;
                } else usleep(10000);
                //printf("got.(%s) %d remains.%d of total.%d\n",jsonbuf,recvlen,remains,len);
                //retstr = iguana_rpcparse(space,size,&postflag,jsonbuf);
                break;
            }
        }
        //if ( retstr == 0 )
        //    retstr = iguana_htmlresponse(space,size,&remains,1,retstr,retstr != space);
        if ( retstr != 0 )
        {
            //if ( 0 && postflag == 0 )
            //    retstr = iguana_htmlresponse(space,size,&remains,1,retstr,retstr != space);
            //else
                //remains = (int32_t)strlen(retstr);
            //printf("POSTFLAG.%d\n",postflag);
            //printf("RETBUF.(%s)\n",retstr);
            /*char hdrs[1024];
		 sprintf(hdrs,"HTTP/1.1 200 OK\r\n");
            if ( remoteaddr[0] != 0 && strcmp(remoteaddr,"127.0.0.1") != 0 )
                sprintf(hdrs,"Access-Control-Allow-Origin: *\r\n");
            else sprintf(hdrs,"Access-Control-Allow-Origin: null\r\n");
            sprintf(hdrs,"Access-Control-Allow-Credentials: true\r\n");
            sprintf(hdrs,"Access-Control-Allow-Headers: Authorization, Content-Type\r\n");
            sprintf(hdrs,"Access-Control-Allow-Methods: GET, POST\r\n");
            sprintf(hdrs,"Cache-Control: no-cache, no-store, must-revalidate\r\n");
            sprintf(hdrs,"Content-type: application/javascript\r\n");
             sprintf(hdrs,"Content-Length: %8d\r\n",(int32_t)strlen(retstr));
             send(sock,hdrs,strlen(hdrs),MSG_NOSIGNAL);*/
            char *response,hdrs[1024];
            if ( jsonflag != 0 )
            {
                response = malloc(strlen(retstr)+1024+1);
                sprintf(hdrs,"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Methods: GET, POST\r\nCache-Control :  no-cache, no-store, must-revalidate\r\nContent-Length : %8d\r\n\r\n",(int32_t)strlen(retstr));
                response[0] = '\0';
                strcat(response,hdrs);
                strcat(response,retstr);
                if ( retstr != space )
                    free(retstr);
                retstr = response;
            }
            remains = (int32_t)strlen(retstr);
            i = 0;
            while ( remains > 0 )
            {
                if ( (numsent= (int32_t)send(sock,&retstr[i],remains,MSG_NOSIGNAL)) < 0 )
                {
                    if ( errno != EAGAIN && errno != EWOULDBLOCK )
                    {
                        //printf("%s: %s numsent.%d vs remains.%d len.%d errno.%d (%s) usock.%d\n",retstr,ipaddr,numsent,remains,recvlen,errno,strerror(errno),sock);
                        break;
                    }
                }
                else if ( remains > 0 )
                {
                    remains -= numsent;
                    i += numsent;
                    if ( remains > 0 )
                        printf("iguana sent.%d remains.%d of len.%d\n",numsent,remains,recvlen);
                }
            }
            if ( retstr != space)
                free(retstr);
        }
        //if ( Currentjsonstr[0] != 0 )
        //    strcpy(Prevjsonstr,Currentjsonstr);
        //Currentjsonstr[0] = 0;
        //printf("done response sock.%d\n",sock);
        closesocket(sock);
    }
}
