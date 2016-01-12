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
    return(sglue1(0,myinfo,coin,remoteaddr,"ramchain","importprivkey","wip",params[0]));
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
    return(sglue2(0,myinfo,coin,remoteaddr,"ramchain","lockunspent","unlock",params[0],"array",params[1]));
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
struct RPC_info { char *name; char *(*rpcfunc)(RPCARGS); int32_t flag0,flag1; } RPCcalls[] =
{
     { "help",                   &help,                   true,   true },
     { "stop",                   &stop,                   true,   true },
     { "getbestblockhash",       &getbestblockhash,       true,   false },
     { "getblockcount",          &getblockcount,          true,   false },
     { "getconnectioncount",     &getconnectioncount,     true,   false },
     { "getpeerinfo",            &getpeerinfo,            true,   false },
     { "getinfo",                &getinfo,                true,   false },
     { "getnewaddress",          &getnewaddress,          true,   false },
     { "getnewpubkey",           &makekeypair,           true,   false },
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
     { "validateaddress",        &validateaddress,        true,   false },
     { "validatepubkey",         &validatepubkey,         true,   false },
     { "getbalance",             &getbalance,             false,  false },
     { "move",                   &movecmd,                false,  false },
     { "sendfrom",               &sendfrom,               false,  false },
     { "sendmany",               &sendmany,               false,  false },
     { "addmultisigaddress",     &addmultisigaddress,     false,  false },
     { "getblock",               &getblock,               false,  false },
     { "getblockhash",           &getblockhash,           false,  false },
     { "gettransaction",         &gettransaction,         false,  false },
     { "listtransactions",       &listtransactions,       false,  false },
     { "listaddressgroupings",   &listaddressgroupings,   false,  false },
     { "signmessage",            &signmessage,            false,  false },
     { "verifymessage",          &verifymessage,          false,  false },
     { "listaccounts",           &listaccounts,           false,  false },
     { "settxfee",               &settxfee,               false,  false },
     { "listsinceblock",         &listsinceblock,         false,  false },
     { "dumpprivkey",            &dumpprivkey,            false,  false },
     { "SuperNET",               &SuperNET,               false,  false },
     { "dumpwallet",             &dumpwallet,             true,   false },
     { "importwallet",           &importwallet,           false,  false },
     { "importprivkey",          &importprivkey,          false,  false },
     { "listunspent",            &listunspent,            false,  false },
     { "getrawtransaction",      &getrawtransaction,      false,  false },
     { "createrawtransaction",   &createrawtransaction,   false,  false },
     { "decoderawtransaction",   &decoderawtransaction,   false,  false },
     { "decodescript",           &decodescript,           false,  false },
     { "signrawtransaction",     &signrawtransaction,     false,  false },
     { "sendrawtransaction",     &sendrawtransaction,     false,  false },
     { "checkwallet",            &checkwallet,            false,  true},
     { "repairwallet",           &repairwallet,           false,  true},
     { "makekeypair",            &makekeypair,            false,  true},
     { "sendalert",              &sendalert,              false,  false},
     //
    { "createmultisig",              &createmultisig,              false,  false},
    { "addnode",              &addnode,              false,  false},
     { "getrawmempool",              &getrawmempool,              false,  false},
     { "getrawchangeaddress",              &getrawchangeaddress,              false,  false},
     { "listlockunspent",              &listlockunspent,              false,  false},
     { "lockunspent",              &lockunspent,              false,  false},
     { "gettxout",              &gettxout,              false,  false},
    { "gettxoutsetinfo",              &gettxoutsetinfo,              false,  false},
    { "vanitygen",              &vanitygen,              false,  false}
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

int32_t is_bitcoinrpc(char *method)
{
    int32_t i;
    for (i=0; i<sizeof(RPCcalls)/sizeof(*RPCcalls); i++)
    {
        if ( strcmp(RPCcalls[i].name,method) == 0 )
            return(i);
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
