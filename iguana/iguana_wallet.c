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

void iguana_walletlock(struct supernet_info *myinfo)
{
    memset(&myinfo->persistent_priv,0,sizeof(myinfo->persistent_priv));
    memset(myinfo->secret,0,sizeof(myinfo->secret));
    printf("wallet locked\n");
}

int32_t iguana_ismine(struct supernet_info *myinfo,uint8_t pubkey[65],uint8_t rmd160[20])
{
    /*int32_t i;
    for (i=0; i<myinfo->numaddrs; i++)
    {
        if ( memcmp(myinfo->addrs[i].rmd160,rmd160,sizeof(myinfo->addrs[i].rmd160)) == 0 )
        {
            memcpy(pubkey,myinfo->addrs[i].pubkey,bitcoin_pubkeylen(myinfo->addrs[i].pubkey));
            return(i);
        }
    }*/
    return(0);
}

uint8_t *iguana_rmdarray(struct iguana_info *coin,int32_t *numrmdsp,cJSON *array,int32_t firsti)
{
    int32_t i,n,j=0; char *coinaddr,rmdstr[41]; uint8_t *addrtypes,*rmdarray = 0;
    *numrmdsp = 0;
    if ( array != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        *numrmdsp = n - firsti;
        rmdarray = calloc(1,(n-firsti) * (21 + 33));
        addrtypes = &rmdarray[(n-firsti) * 20];
        for (i=firsti; i<n; i++)
        {
            if ( (coinaddr= jstr(jitem(array,i),0)) != 0 )
            {
                bitcoin_addr2rmd160(&addrtypes[j],&rmdarray[20 * j],coinaddr);
                init_hexbytes_noT(rmdstr,&rmdarray[20 * j],20);
                printf("(%s %s) ",coinaddr,rmdstr);
                j++;
            }
        }
        printf("rmdarray[%d]\n",n);
    }
    return(rmdarray);
}

struct iguana_waccount *iguana_waccountcreate(struct iguana_info *coin,char *account)
{
    struct iguana_waccount *waddr; int32_t len = (int32_t)strlen(account)+1;
    HASH_FIND(hh,coin->wallet,account,len,waddr);
    if ( waddr != 0 )
        return(waddr);
    waddr = mycalloc('w',1,sizeof(*waddr) + len);
    strcpy(waddr->account,account);
    HASH_ADD(hh,coin->wallet,account,len,waddr);
    return(waddr);
}

struct iguana_waccount *iguana_waccountfind(struct iguana_info *coin,char *account)
{
    struct iguana_waccount *waddr;
    HASH_FIND(hh,coin->wallet,account,strlen(account)+1,waddr);
    return(waddr);
}

struct iguana_waccount *iguana_waccountadd(struct iguana_info *coin,char *walletaccount,struct iguana_waddress *waddr)
{
    struct iguana_waccount *acct;
    if ( (acct= iguana_waccountfind(coin,walletaccount)) == 0 )
        acct = iguana_waccountcreate(coin,walletaccount);
    return(acct);
}

uint8_t *iguana_walletrmds(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *numrmdsp)
{
    int32_t iter,n,m; struct iguana_waccount *acct,*tmp; uint8_t *pubkeys,*addrtypes,*rmdarray = 0; struct iguana_waddress *waddr,*tmp2;
    for (iter=n=m=0; iter<2; iter++)
    {
        HASH_ITER(hh,coin->wallet,acct,tmp)
        {
            HASH_ITER(hh,acct->waddrs,waddr,tmp2)
            {
                if ( iter == 0 )
                    n++;
                else if ( m < n )
                {
                    addrtypes[m] = waddr->type;
                    memcpy(&rmdarray[m * 20],waddr->rmd160,20);
                    memcpy(&pubkeys[m * 33],waddr->pubkey,33);
                    m++;
                }
            }
        }
        if ( iter == 0 )
        {
            rmdarray = calloc(n,20 + 1 + 33);
            addrtypes = &rmdarray[n * 20];
            pubkeys = &rmdarray[n * 21];
        }
    }
    return(rmdarray);
}

int32_t iguana_waccountswitch(struct iguana_info *coin,char *account,struct iguana_waccount *oldwaddr,int32_t oldind,char *coinaddr)
{
    // what if coinaddr is already in an account?
    //printf("change %s walletaccount.(%s) (%s) <- %s\n",coin->symbol,waddr->account,waddr->coinaddr,coinaddr);
    return(0);
}

struct iguana_waccount *iguana_waddressfind(struct iguana_info *coin,int32_t *indp,char *coinaddr)
{
    int32_t n=0; struct iguana_waccount *acct,*tmp; struct iguana_waddress *waddr,*tmp2;
    *indp = -1;
    HASH_ITER(hh,coin->wallet,acct,tmp)
    {
        HASH_ITER(hh,acct->waddrs,waddr,tmp2)
        {
            if ( strcmp(coinaddr,waddr->coinaddr) == 0 )
            {
                *indp = n;
                return(acct);
            }
            n++;
        }
    }
    return(0);
}

char *getaddressesbyaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account)
{
    struct iguana_waccount *subset; struct iguana_waddress *waddr,*tmp; cJSON *retjson,*array;
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    if ( (subset= iguana_waccountfind(coin,account)) != 0 )
    {
        HASH_ITER(hh,subset->waddrs,waddr,tmp)
        {
            jaddistr(array,waddr->coinaddr);
        }
    } else jaddstr(retjson,"result","cant find account");
    jadd(retjson,"addresses",array);
    return(jprint(retjson,1));
}

int32_t iguana_addressvalidate(struct iguana_info *coin,uint8_t *addrtypep,uint8_t rmd160[20],char *address)
{
    char checkaddr[64];
    bitcoin_addr2rmd160(addrtypep,rmd160,address);
    if ( bitcoin_address(checkaddr,*addrtypep,rmd160,20) == checkaddr && strcmp(address,checkaddr) == 0 && (*addrtypep == coin->chain->pubtype || *addrtypep == coin->chain->p2shtype) )
        return(0);
    else return(-1);
}

char *getnewaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *account)
{
    struct iguana_waddress addr; char str[67]; cJSON *retjson = cJSON_CreateObject();
    if ( iguana_waddresscalc(coin->chain->pubtype,coin->chain->wiftype,&addr,rand256(1)) == 0 )
    {
        jaddstr(retjson,"result",addr.coinaddr);
        init_hexbytes_noT(str,addr.pubkey,33);
        jaddstr(retjson,"pubkey",str);
        jaddstr(retjson,"privkey",bits256_str(str,addr.privkey));
        jaddstr(retjson,"wif",addr.wifstr);
        init_hexbytes_noT(str,addr.rmd160,20);
        jaddstr(retjson,"rmd160",str);
        if ( iguana_waccountadd(coin,account,&addr) < 0 )
            jaddstr(retjson,"account","error adding to account");
        else jaddstr(retjson,"account",account);
    } else jaddstr(retjson,"error","cant create address");
    return(jprint(retjson,1));
}

char *getaccountaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *account)
{
    struct iguana_waccount *wacct; struct iguana_waddress *waddr=0,addr; char str[67];cJSON *retjson;
    if ( account != 0 && account[0] != 0 )
    {
        if ( (wacct= iguana_waccountfind(coin,account)) == 0 )
        {
            if ( (waddr= iguana_waddresscalc(coin->chain->pubtype,coin->chain->wiftype,&addr,rand256(1))) == 0 )
                return(clonestr("{\"error\":\"cant generate address\"}"));
            iguana_waccountswitch(coin,account,0,-1,addr.coinaddr);
        }
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result",waddr->coinaddr);
        init_hexbytes_noT(str,addr.pubkey,33);
        jaddstr(retjson,"pubkey",str);
        jaddstr(retjson,"privkey",bits256_str(str,waddr->privkey));
        jaddstr(retjson,"wif",waddr->wifstr);
        init_hexbytes_noT(str,waddr->rmd160,20);
        jaddstr(retjson,"rmd160",str);
        jaddstr(retjson,"account",account);
        return(jprint(retjson,1));
    }
    return(clonestr("{\"error\":\"no account specified\"}"));
}

char *setaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account,char *coinaddr)
{
    struct iguana_waccount *wacct; uint8_t addrtype,rmd160[20]; struct iguana_waddress *waddr=0,addr; int32_t ind=-1;
    if ( coinaddr != 0 && coinaddr[0] != 0 && account != 0 && account[0] != 0 )
    {
        if ( iguana_addressvalidate(coin,&addrtype,rmd160,coinaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        if ( (wacct= iguana_waddressfind(coin,&ind,coinaddr)) == 0 )
        {
            if ( (waddr= iguana_waddresscalc(coin->chain->pubtype,coin->chain->wiftype,&addr,rand256(1))) == 0 )
                return(clonestr("{\"error\":\"cant generate address\"}"));
        }
        iguana_waccountswitch(coin,account,wacct,ind,coinaddr);
        return(clonestr("{\"result\":\"account set\"}"));
    }
    return(clonestr("{\"error\":\"need address and account\"}"));
}

char *getaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    struct iguana_waccount *wacct; uint8_t addrtype,rmd160[20]; cJSON *retjson; int32_t ind;
    if ( iguana_addressvalidate(coin,&addrtype,rmd160,coinaddr) < 0 )
        return(clonestr("{\"error\":\"invalid coin address\"}"));
    if ( (wacct= iguana_waddressfind(coin,&ind,coinaddr)) == 0 )
        return(clonestr("{\"result\":\"no account for address\"}"));
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",wacct->account);
    return(jprint(retjson,1));
}

char *sendtoaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,double amount,char *comment,char *comment2)
{
    uint8_t addrtype,rmd160[20];
    //sendtoaddress	<bitcoinaddress> <amount> [comment] [comment-to]	<amount> is a real and is rounded to 8 decimal places. Returns the transaction ID <txid> if successful.	Y
    if ( coinaddr != 0 && coinaddr[0] != 0 && amount > 0. )
    {
        if ( iguana_addressvalidate(coin,&addrtype,rmd160,coinaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        //amount = jdouble(params[1],0);
        //comment = jstr(params[2],0);
        //comment2 = jstr(params[3],0);
        printf("need to generate send %.8f to %s [%s] [%s]\n",dstr(amount),coinaddr,comment!=0?comment:"",comment2!=0?comment2:"");
    }
    return(clonestr("{\"error\":\"need address and amount\"}"));
}

char *jsuccess()
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

bits256 iguana_str2priv(struct iguana_info *coin,char *str)
{
    bits256 privkey; int32_t ind,n; uint8_t addrtype; struct iguana_waccount *wacct;
    memset(&privkey,0,sizeof(privkey));
    if ( str != 0 )
    {
        n = (int32_t)strlen(str) >> 1;
        if ( n == sizeof(bits256) && is_hexstr(str,sizeof(bits256)) > 0 )
            decode_hex(privkey.bytes,sizeof(privkey),str);
        else if ( btc_wif2priv(&addrtype,privkey.bytes,str) != sizeof(bits256) )
        {
            if ( (wacct= iguana_waddressfind(coin,&ind,str)) != 0 )
                privkey = wacct->waddrs[ind].privkey;
        }
    }
    return(privkey);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

INT_ARRAY_STRING(bitcoinrpc,createmultisig,M,array,account)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

char *iguana_addressconv(struct iguana_info *coin,char *destaddr,struct iguana_info *other,int32_t isp2sh,uint8_t rmd160[20])
{
    if ( bitcoin_address(destaddr,isp2sh != 0 ? other->chain->pubtype : other->chain->p2shtype,rmd160,20) == destaddr )
        return(destaddr);
    else return(0);
}

STRING_ARG(bitcoinrpc,validateaddress,address)
{
    cJSON *retjson; int32_t i; uint8_t addrtype,rmd160[20],pubkey[65]; struct iguana_info *other; char checkaddr[64],str[256];
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( iguana_addressvalidate(coin,&addrtype,rmd160,address) < 0 )
        return(clonestr("{\"error\":\"invalid coin address\"}"));
    if ( strcmp(address,checkaddr) == 0 )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","success");
        jaddnum(retjson,"addrtype",addrtype);
        init_hexbytes_noT(str,rmd160,sizeof(rmd160));
        jaddstr(retjson,"rmd160",str);
        if ( iguana_ismine(myinfo,pubkey,rmd160) > 0 )
        {
            init_hexbytes_noT(str,pubkey,bitcoin_pubkeylen(pubkey));
            jaddstr(retjson,"pubkey",str);
            cJSON_AddTrueToObject(retjson,"ismine");
        }
        else cJSON_AddFalseToObject(retjson,"ismine");
        for (i=0; i<IGUANA_MAXCOINS; i++)
        {
            if ( (other= Coins[i]) != 0 && strcmp(other->symbol,coin->symbol) != 0 )
            {
                iguana_addressconv(coin,str,other,addrtype == coin->chain->p2shtype,rmd160);
                jaddstr(retjson,other->symbol,str);
            }
        }
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"couldnt regenerate address\"}"));
}

ZERO_ARGS(bitcoinrpc,getinfo)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    if ( coin != 0 )
    {
        jaddstr(retjson,"result","success");
        jaddnum(retjson,"protocolversion",PROTOCOL_VERSION);
        jaddnum(retjson,"blocks",coin->blocks.hwmchain.height);
        jaddnum(retjson,"longestchain",coin->longestchain);
        jaddnum(retjson,"port",coin->chain->portp2p);
        jaddnum(retjson,"connections",coin->peers.numranked);
        jaddnum(retjson,"difficulty",coin->blocks.hwmchain.PoW);
        jaddstr(retjson,"status",coin->statusstr);
        jaddstr(retjson,"coin",coin->symbol);
    }
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,walletlock)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    iguana_walletlock(myinfo);
    return(jsuccess());
}

TWOSTRINGS_AND_INT(bitcoinrpc,walletpassphrase,password,permanentfile,timeout)
{
    char *retstr;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( timeout <= 0 )
        return(clonestr("{\"error\":\"timeout must be positive\"}"));
    retstr = SuperNET_login(IGUANA_CALLARGS,myinfo->handle,password,permanentfile,0);
    myinfo->expiration = (uint32_t)time(NULL) + timeout;
    return(retstr);
}

THREE_STRINGS(bitcoinrpc,encryptwallet,passphrase,password,permanentfile)
{
    char *retstr;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( password == 0 || password[0] == 0 )
        password = passphrase;
    retstr = SuperNET_login(IGUANA_CALLARGS,myinfo->handle,password,permanentfile,passphrase);
    iguana_walletlock(myinfo);
    return(retstr);
}

FOUR_STRINGS(bitcoinrpc,walletpassphrasechange,oldpassword,newpassword,oldpermanentfile,newpermanentfile)
{
    char destfname[1024],*tmpstr,*loginstr,*passphrase,*retstr = 0; cJSON *tmpjson,*payload,*loginjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( (tmpstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,oldpassword,oldpermanentfile,0)) != 0 )
    {
        if ( (tmpjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (loginstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,newpassword,newpermanentfile,0)) != 0 )
            {
                if ( (loginjson= cJSON_Parse(loginstr)) != 0 )
                {
                    if ( (passphrase= jstr(loginjson,"passphrase")) != 0 )
                    {
                        if ( (payload= jobj(loginjson,"payload")) != 0 )
                            jadd(loginjson,"payload",payload);
                        _SuperNET_encryptjson(destfname,passphrase,0,newpermanentfile,0,loginjson);
                        iguana_walletlock(myinfo);
                        retstr = SuperNET_login(IGUANA_CALLARGS,myinfo->handle,newpassword,newpermanentfile,0);
                    }
                    free_json(loginjson);
                }
                free(loginstr);
            }
            free_json(tmpjson);
        }
        free(tmpstr);
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"error changing walletpassphrase\"}");
    return(retstr);
}

TWO_STRINGS(bitcoinrpc,setaccount,address,account)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(setaccount(myinfo,coin,account,address));
}

STRING_ARG(bitcoinrpc,getaccount,address)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(getaccount(myinfo,coin,address));
}

STRING_ARG(bitcoinrpc,getnewaddress,account)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(getnewaddress(myinfo,coin,account));
}

STRING_ARG(bitcoinrpc,getaccountaddress,account)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(getaccountaddress(myinfo,coin,account));
}

TWOSTRINGS_AND_INT(bitcoinrpc,importprivkey,wif,account,rescan)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,dumpprivkey,address)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// multiple address
THREE_INTS(bitcoinrpc,getbalance,confirmations,includeempty,watchonly)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,getaddressesbyaccount,account)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_AND_INT(bitcoinrpc,getreceivedbyaccount,account,includeempty)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

THREE_INTS(bitcoinrpc,listreceivedbyaccount,confirmations,includeempty,watchonly)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

THREE_INTS(bitcoinrpc,listreceivedbyaddress,minconf,includeempty,flag)
{
    //cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(jsuccess());
}

STRING_AND_THREEINTS(bitcoinrpc,listtransactions,account,count,skip,includewatchonly)
{
    //cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(jsuccess());
}

S_D_SS(bitcoinrpc,sendtoaddress,address,amount,comment,comment2)
{
    //cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(jsuccess());
}

SS_D_I_SS(bitcoinrpc,sendfrom,fromaccount,toaddress,amount,minconf,comment,comment2)
{
    //cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(jsuccess());
}

DOUBLE_ARG(bitcoinrpc,settxfee,amount)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

SS_D_I_S(bitcoinrpc,move,fromaccount,toaccount,amount,minconf,comment)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

S_A_I_S(bitcoinrpc,sendmany,fromaccount,array,minconf,comment)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

// entire wallet funcs
TWO_INTS(bitcoinrpc,listaccounts,minconf,includewatchonly)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,listaddressgroupings)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,checkwallet)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,repairwallet)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,dumpwallet,filename)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,backupwallet,filename)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,importwallet,filename)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

#include "../includes/iguana_apiundefs.h"

/*
 
 sendtoaddress
 encryptwallet
 sendfrom
 walletlock
 walletpassphrase
 walletpassphrasechange
 
 validateaddress
 
 listreceivedbyaddress
 listtransactions
 
 not implemented yet but needed by GUI
 
 addmultisigaddress (for generating address)
 setaccount       (to give labels to address)
 */
