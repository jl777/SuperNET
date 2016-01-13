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

int32_t iguana_waccountswitch(struct iguana_info *coin,char *account,struct iguana_waccount *oldwaddr,int32_t oldind,char *coinaddr)
{
    // what if coinaddr is already in an account?
    //printf("change %s walletaccount.(%s) (%s) <- %s\n",coin->symbol,waddr->account,waddr->coinaddr,coinaddr);
    return(0);
}

struct iguana_waccount *iguana_waddressfind(struct iguana_info *coin,int32_t *indp,char *coinaddr)
{
    return(0);
}

int32_t iguana_addressvalidate(struct iguana_info *coin,char *coinaddr)
{
    return(0);
}

char *getnewaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *account)
{
    struct iguana_waddress addr; char str[67]; cJSON *retjson = cJSON_CreateObject();
    if ( iguana_waddresscalc(coin,&addr,rand256(1)) == 0 )
    {
        jaddstr(retjson,"result",addr.coinaddr);
        init_hexbytes_noT(str,addr.pubkey,33);
        jaddstr(retjson,"pubkey",str);
        jaddstr(retjson,"privkey",bits256_str(str,addr.privkey));
        jaddstr(retjson,"wip",addr.wipstr);
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
            if ( (waddr= iguana_waddresscalc(coin,&addr,rand256(1))) == 0 )
                return(clonestr("{\"error\":\"cant generate address\"}"));
            iguana_waccountswitch(coin,account,0,-1,addr.coinaddr);
        }
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result",waddr->coinaddr);
        init_hexbytes_noT(str,addr.pubkey,33);
        jaddstr(retjson,"pubkey",str);
        jaddstr(retjson,"privkey",bits256_str(str,waddr->privkey));
        jaddstr(retjson,"wip",waddr->wipstr);
        init_hexbytes_noT(str,waddr->rmd160,20);
        jaddstr(retjson,"rmd160",str);
        jaddstr(retjson,"account",account);
        return(jprint(retjson,1));
    }
    return(clonestr("{\"error\":\"no account specified\"}"));
}

char *setaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account,char *coinaddr)
{
    struct iguana_waccount *wacct; struct iguana_waddress *waddr=0,addr; int32_t ind=-1;
    if ( coinaddr != 0 && coinaddr[0] != 0 && account != 0 && account[0] != 0 )
    {
        if ( iguana_addressvalidate(coin,coinaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        if ( (wacct= iguana_waddressfind(coin,&ind,coinaddr)) == 0 )
        {
            if ( (waddr= iguana_waddresscalc(coin,&addr,rand256(1))) == 0 )
                return(clonestr("{\"error\":\"cant generate address\"}"));
        }
        iguana_waccountswitch(coin,account,wacct,ind,coinaddr);
        return(clonestr("{\"result\":\"account set\"}"));
    }
    return(clonestr("{\"error\":\"need address and account\"}"));
}

char *getaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    struct iguana_waccount *wacct; cJSON *retjson; int32_t ind;
    if ( iguana_addressvalidate(coin,coinaddr) < 0 )
        return(clonestr("{\"error\":\"invalid coin address\"}"));
    if ( (wacct= iguana_waddressfind(coin,&ind,coinaddr)) == 0 )
        return(clonestr("{\"result\":\"no account for address\"}"));
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",wacct->account);
    return(jprint(retjson,1));
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

char *sendtoaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,double amount,char *comment,char *comment2)
{
    //char *coinaddr;
    //sendtoaddress	<bitcoinaddress> <amount> [comment] [comment-to]	<amount> is a real and is rounded to 8 decimal places. Returns the transaction ID <txid> if successful.	Y
    if ( coinaddr != 0 && coinaddr[0] != 0 && amount > 0. )
    {
        if ( iguana_addressvalidate(coin,coinaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        //amount = jdouble(params[1],0);
        //comment = jstr(params[2],0);
        //comment2 = jstr(params[3],0);
        printf("need to generate send %.8f to %s [%s] [%s]\n",dstr(amount),coinaddr,comment!=0?comment:"",comment2!=0?comment2:"");
    }
    return(clonestr("{\"error\":\"need address and amount\"}"));
}

char *iguana_getreceivedbyaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account,int32_t minconf)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


/*char *iguana_listreceivedbyaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account,int32_t includeempty)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}*/



char *iguana_getaccountaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *account)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_setaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *address,char *account)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_getaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_getaddressesbyaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_listaddressgroupings(struct supernet_info *myinfo,struct iguana_info *coin)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


/*char *iguana_getbalance(struct supernet_info *myinfo,struct iguana_info *coin,char *account,int32_t minconf)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_listaccounts(struct supernet_info *myinfo,struct iguana_info *coin,int32_t minconf)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}*/



char *iguana_move(struct supernet_info *myinfo,struct iguana_info *coin,char *fromaccount,char *toaccount,double amount,int32_t minconf,char *comment)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_sendfrom(struct supernet_info *myinfo,struct iguana_info *coin,char *fromaccount,char *toaddress,double amount,int32_t minconf,char *comment,char *comment2)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_sendmany(struct supernet_info *myinfo,struct iguana_info *coin,char *fromaccount,cJSON *payments,int32_t minconf,char *comment)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}



char *iguana_dumpprivkey(struct supernet_info *myinfo,struct iguana_info *coin,char *address)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


/*char *iguana_importprivkey(struct supernet_info *myinfo,struct iguana_info *coin,char *wip)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_dumpwallet(struct supernet_info *myinfo,struct iguana_info *coin)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}*/


char *iguana_importwallet(struct supernet_info *myinfo,struct iguana_info *coin,char *wallet)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_walletpassphrase(struct supernet_info *myinfo,struct iguana_info *coin,char *passphrase,int32_t timeout)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_walletpassphrasechange(struct supernet_info *myinfo,struct iguana_info *coin,char *oldpassphrase,char *newpassphrase)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_walletlock(struct supernet_info *myinfo,struct iguana_info *coin)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_encryptwallet(struct supernet_info *myinfo,struct iguana_info *coin,char *passphrase)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_checkwallet(struct supernet_info *myinfo,struct iguana_info *coin)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_repairwallet(struct supernet_info *myinfo,struct iguana_info *coin)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}


char *iguana_backupwallet(struct supernet_info *myinfo,struct iguana_info *coin,char *filename)
{
    return(clonestr("{\"error\":\"notyet\"}"));
}




