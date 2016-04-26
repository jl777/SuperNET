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

struct iguana_waddress *iguana_waddressfind(struct iguana_info *coin,struct iguana_waccount *wacct,char *coinaddr)
{
    struct iguana_waddress *waddr;
    HASH_FIND(hh,wacct,coinaddr,strlen(coinaddr)+1,waddr);
    return(waddr);
}

struct iguana_waddress *iguana_waddresscreate(struct iguana_info *coin,struct iguana_waccount *wacct,char *coinaddr)
{
    struct iguana_waddress *waddr; int32_t len = (int32_t)strlen(coinaddr)+1;
    HASH_FIND(hh,wacct,coinaddr,len,waddr);
    if ( waddr == 0 )
    {
        waddr = mycalloc('w',1,sizeof(*waddr) + len);
        strcpy(waddr->coinaddr,coinaddr);
        HASH_ADD_KEYPTR(hh,wacct,waddr->coinaddr,len,wacct);
    }
    return(waddr);
}

struct iguana_waddress *iguana_waddressadd(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,struct iguana_waddress *refwaddr)
{
    struct iguana_waddress *waddr; int32_t len = (int32_t)strlen(refwaddr->coinaddr)+1;
    HASH_FIND(hh,wacct,refwaddr->coinaddr,len,waddr);
    if ( waddr == 0 )
        HASH_ADD_KEYPTR(hh,wacct,waddr->coinaddr,len,wacct);
    if ( waddr != refwaddr )
    {
        waddr->privkey = refwaddr->privkey;
        memcpy(waddr->pubkey,refwaddr->pubkey,sizeof(waddr->pubkey));
        memcpy(waddr->rmd160,refwaddr->rmd160,sizeof(waddr->rmd160));
        strcpy(waddr->coinaddr,refwaddr->coinaddr);
        strcpy(waddr->wifstr,refwaddr->wifstr);
        waddr->wiftype = refwaddr->wiftype;
        waddr->type = refwaddr->type;
     }
    return(waddr);
}

struct iguana_waddress *iguana_waddressdelete(struct iguana_info *coin,struct iguana_waccount *wacct,char *coinaddr)
{
    struct iguana_waddress *waddr = 0; int32_t len = (int32_t)strlen(coinaddr)+1;
    HASH_FIND(hh,wacct,coinaddr,len,waddr);
    if ( waddr != 0 )
        HASH_DELETE(hh,wacct,waddr);
    return(waddr);
}

struct iguana_waddress *iguana_waddresssearch(struct iguana_info *coin,struct iguana_waccount **wacctp,char *coinaddr)
{
    struct iguana_waccount *wacct,*tmp; struct iguana_waddress *waddr;
    HASH_ITER(hh,coin->wallet,wacct,tmp)
    {
        if ( (waddr= iguana_waddressfind(coin,wacct,coinaddr)) != 0 )
        {
            (*wacctp) = wacct;
            return(waddr);
        }
    }
    return(0);
}

struct iguana_waccount *iguana_waccountfind(struct iguana_info *coin,char *account)
{
    struct iguana_waccount *waddr;
    HASH_FIND(hh,coin->wallet,account,strlen(account)+1,waddr);
    return(waddr);
}

struct iguana_waccount *iguana_waccountcreate(struct iguana_info *coin,char *account)
{
    struct iguana_waccount *wacct; int32_t len = (int32_t)strlen(account)+1;
    HASH_FIND(hh,coin->wallet,account,len,wacct);
    if ( wacct == 0 )
    {
        wacct = mycalloc('w',1,sizeof(*wacct) + len);
        strcpy(wacct->account,account);
        HASH_ADD_KEYPTR(hh,coin->wallet,account,len,wacct);
    }
    return(wacct);
}

struct iguana_waddress *iguana_waccountswitch(struct iguana_info *coin,char *account,char *coinaddr)
{
    struct iguana_waccount *wacct = 0; struct iguana_waddress *waddr = 0;
    if ( (waddr= iguana_waddresssearch(coin,&wacct,coinaddr)) != 0 )
    {
        HASH_DELETE(hh,wacct,waddr);
        if ( (wacct= iguana_waccountcreate(coin,account)) != 0 )
            waddr = iguana_waddresscreate(coin,wacct,coinaddr);
    }
    return(waddr);
}

uint8_t *iguana_walletrmds(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *numrmdsp)
{
    int32_t iter,n,m; struct iguana_waccount *acct,*tmp; uint8_t *pubkeys,*addrtypes,*rmdarray = 0; struct iguana_waddress *waddr,*tmp2;
    for (iter=n=m=0; iter<2; iter++)
    {
        HASH_ITER(hh,coin->wallet,acct,tmp)
        {
            HASH_ITER(hh,acct->waddr,waddr,tmp2)
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

cJSON *getaddressesbyaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account)
{
    struct iguana_waccount *subset; struct iguana_waddress *waddr,*tmp; cJSON *retjson,*array;
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    if ( (subset= iguana_waccountfind(coin,account)) != 0 )
    {
        HASH_ITER(hh,subset->waddr,waddr,tmp)
        {
            jaddistr(array,waddr->coinaddr);
        }
    } else jaddstr(retjson,"result","cant find account");
    return(array);
}

struct iguana_waddress *iguana_waccountadd(struct iguana_info *coin,struct iguana_waccount **wacctp,char *walletaccount,char *coinaddr)
{
    struct iguana_waccount *wacct; struct iguana_waddress *waddr = 0;
    if ( (wacct= iguana_waccountfind(coin,walletaccount)) == 0 )
        wacct = iguana_waccountcreate(coin,walletaccount);
    if ( wacct != 0 )
        waddr = iguana_waddresscreate(coin,wacct,coinaddr);
    return(waddr);
}

struct iguana_waddress *iguana_waddresscalc(uint8_t pubtype,uint8_t wiftype,struct iguana_waddress *addr,bits256 privkey)
{
    addr->privkey = privkey;
    bitcoin_pubkey33(addr->pubkey,addr->privkey);
    calc_rmd160_sha256(addr->rmd160,addr->pubkey,33);
    bitcoin_address(addr->coinaddr,pubtype,addr->rmd160,sizeof(addr->rmd160));
    if ( bitcoin_priv2wif(addr->wifstr,addr->privkey,wiftype) > 0 )
    {
        addr->wiftype = wiftype;
        addr->type = pubtype;
        return(addr);
    }
    return(0);
}

void iguana_walletlock(struct supernet_info *myinfo)
{
    memset(&myinfo->persistent_priv,0,sizeof(myinfo->persistent_priv));
    memset(myinfo->secret,0,sizeof(myinfo->secret));
    memset(myinfo->permanentfile,0,sizeof(myinfo->permanentfile));
    printf("wallet locked\n");
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

struct iguana_waddress *iguana_ismine(struct iguana_info *coin,uint8_t addrtype,uint8_t pubkey[65],uint8_t rmd160[20])
{
    char coinaddr[65]; struct iguana_waccount *wacct; struct iguana_waddress *waddr = 0;
    if ( bitcoin_address(coinaddr,addrtype,rmd160,20) > 0 )
        waddr = iguana_waddresssearch(coin,&wacct,coinaddr);
    return(waddr);
}

int32_t iguana_addressvalidate(struct iguana_info *coin,uint8_t *addrtypep,uint8_t rmd160[20],char *address)
{
    char checkaddr[64];
    bitcoin_addr2rmd160(addrtypep,rmd160,address);
    if ( bitcoin_address(checkaddr,*addrtypep,rmd160,20) == checkaddr && strcmp(address,checkaddr) == 0 && (*addrtypep == coin->chain->pubtype || *addrtypep == coin->chain->p2shtype) )
        return(0);
    else return(-1);
}

cJSON *iguana_waddressjson(cJSON *item,struct iguana_waddress *waddr)
{
    char str[256];
    if ( item == 0 )
        item = cJSON_CreateObject();
    jaddstr(item,"address",waddr->coinaddr);
    init_hexbytes_noT(str,waddr->pubkey,33);
    jaddstr(item,"pubkey",str);
    //jaddstr(item,"privkey",bits256_str(str,waddr->privkey));
    //jaddstr(item,"wif",waddr->wifstr);
    init_hexbytes_noT(str,waddr->rmd160,20);
    jaddstr(item,"rmd160",str);
    return(item);
}

char *setaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account,char *coinaddr)
{
    uint8_t addrtype,rmd160[20]; struct iguana_waddress *waddr=0;
    if ( coinaddr != 0 && coinaddr[0] != 0 && account != 0 && account[0] != 0 )
    {
        if ( iguana_addressvalidate(coin,&addrtype,rmd160,coinaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        if ( (waddr= iguana_waccountswitch(coin,account,coinaddr)) != 0 )
            return(clonestr("{\"result\":\"success\"}"));
        else return(clonestr("{\"error\":\"couldnt set account\"}"));
    }
    return(clonestr("{\"error\":\"need address and account\"}"));
}

char *getaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    struct iguana_waccount *wacct; struct iguana_waddress *waddr; uint8_t addrtype,rmd160[20]; cJSON *retjson;
    if ( iguana_addressvalidate(coin,&addrtype,rmd160,coinaddr) < 0 )
        return(clonestr("{\"error\":\"invalid coin address\"}"));
    if ( (waddr= iguana_waddresssearch(coin,&wacct,coinaddr)) == 0 )
        return(clonestr("{\"result\":\"no account for address\"}"));
    if ( wacct != 0 )
    {
        retjson = iguana_waddressjson(0,waddr);
        jaddstr(retjson,"account",wacct->account);
        jaddstr(retjson,"result","success");
        return(jprint(retjson,1));
    } else return(clonestr("{\"result\":\"\"}"));
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
    bits256 privkey; int32_t n; uint8_t addrtype; struct iguana_waccount *wacct=0; struct iguana_waddress *waddr;
    memset(&privkey,0,sizeof(privkey));
    if ( str != 0 )
    {
        n = (int32_t)strlen(str) >> 1;
        if ( n == sizeof(bits256) && is_hexstr(str,sizeof(bits256)) > 0 )
            decode_hex(privkey.bytes,sizeof(privkey),str);
        else if ( bitcoin_wif2priv(&addrtype,&privkey,str) != sizeof(bits256) )
        {
            if ( (waddr= iguana_waddresssearch(coin,&wacct,str)) != 0 )
                privkey = waddr->privkey;
        }
    }
    return(privkey);
}

char *iguana_addressconv(struct iguana_info *coin,char *destaddr,struct iguana_info *other,int32_t isp2sh,uint8_t rmd160[20])
{
    if ( bitcoin_address(destaddr,isp2sh != 0 ? other->chain->pubtype : other->chain->p2shtype,rmd160,20) == destaddr )
        return(destaddr);
    else return(0);
}

int32_t iguana_loginsave(struct supernet_info *myinfo,struct iguana_info *coin,char *newstr)
{
    cJSON *loginjson; char *passphrase,destfname[1024];
    if ( (loginjson= cJSON_Parse(newstr)) != 0 )
    {
        if ( (passphrase= jstr(loginjson,"passphrase")) != 0 )
        {
            _SuperNET_encryptjson(destfname,passphrase,0,myinfo->permanentfile,0,loginjson);
            iguana_walletlock(myinfo);
            printf("loginsave.(%s) <= (%s)\n",destfname,newstr);
        }
        free_json(loginjson);
        return(0);
    } return(-1);
}

int32_t iguana_payloadupdate(struct supernet_info *myinfo,struct iguana_info *coin,char *retstr,struct iguana_waddress *waddr,char *account)
{
    cJSON *retjson,*accountobj,*payload,*obj; char *newstr; int32_t retval = -1;
    if ( (retjson= cJSON_Parse(retstr)) != 0 )
    {
        payload = cJSON_DetachItemFromObject(retjson,"payload");
        if ( payload == 0 )
            payload = cJSON_CreateObject();
        if ( (accountobj= jobj(payload,account)) != 0 && (obj= jobj(accountobj,waddr->coinaddr)) != 0 )
        {
            free_json(retjson);
            free_json(payload);
            return(0);
        }
        jaddbits256(payload,waddr->coinaddr,waddr->privkey);
        jadd(retjson,"payload",payload);
        newstr = jprint(retjson,1);
        retval = iguana_loginsave(myinfo,coin,newstr);
        free(newstr);
    }
    return(retval);
}

cJSON *iguana_walletadd(struct supernet_info *myinfo,struct iguana_info *coin,char *retstr,char *account,struct iguana_waddress *refwaddr,int32_t setcurrent)
{
    cJSON *retjson=0; struct iguana_waccount *wacct; struct iguana_waddress *waddr;
    if ( (wacct= iguana_waccountfind(coin,account)) == 0 )
        wacct = iguana_waccountcreate(coin,account);
    if ( wacct != 0 )
    {
        waddr = iguana_waddressfind(coin,wacct,refwaddr->coinaddr);
        if ( waddr != refwaddr )
        {
            waddr = mycalloc('w',1,sizeof(*waddr));
            memcpy(waddr,refwaddr,sizeof(*waddr));
        }
        iguana_waddressadd(myinfo,coin,wacct,waddr);
        if ( setcurrent != 0 )
            wacct->current = waddr;
        if ( iguana_payloadupdate(myinfo,coin,retstr,waddr,account) < 0 )
        {
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"error","couldnt update wallet payload");
        }
        else
        {
            retjson = iguana_waddressjson(retjson,waddr);
            jaddstr(retjson,"account",account);
            jaddstr(retjson,"result","success");
        }
    }
    return(retjson);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

char *getnewaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *account,char *retstr)
{
    struct iguana_waddress addr; cJSON *retjson;
    if ( myinfo->secret[0] == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( retstr != 0 )
    {
        memset(&addr,0,sizeof(addr));
        if ( iguana_waddresscalc(coin->chain->pubtype,coin->chain->wiftype,&addr,rand256(1)) != 0 )
            retjson = iguana_walletadd(myinfo,coin,retstr,account,&addr,1);
        else return(clonestr("{\"error\":\"couldnt calculate waddr\"}"));
    } else return(clonestr("{\"error\":\"no wallet data\"}"));
    return(jprint(retjson,1));
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
        if ( iguana_ismine(coin,addrtype,pubkey,rmd160) > 0 )
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
    char *retstr,*newretstr;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->secret[0] != 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( (retstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,0)) != 0 )
    {
        newretstr = getnewaddress(myinfo,coin,account,retstr);
        free(retstr);
        return(newretstr);
    }
    else return(clonestr("{\"error\":\"no wallet payload\"}"));
}

STRING_ARG(bitcoinrpc,getaccountaddress,account)
{
    char *retstr; struct iguana_waccount *wacct; struct iguana_waddress *waddr=0; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->secret[0] != 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( account != 0 && account[0] != 0 )
    {
        if ( (wacct= iguana_waccountfind(coin,account)) == 0 )
            wacct = iguana_waccountcreate(coin,account);
        if ( wacct != 0 )
        {
            if ( (waddr= wacct->current) == 0 )
            {
                if ( (retstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,0)) != 0 )
                    return(getnewaddress(myinfo,coin,account,retstr));
                else return(clonestr("{\"error\":\"no wallet payload\"}"));
            }
            retjson = iguana_waddressjson(0,waddr);
            jaddstr(retjson,"account",account);
            jaddstr(retjson,"result","success");
            return(jprint(retjson,1));
        } else return(clonestr("{\"error\":\"cant find account\"}"));
    }
    return(clonestr("{\"error\":\"no account specified\"}"));
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
    char destfname[1024],*tmpstr,*loginstr,*passphrase,*retstr = 0; cJSON *tmpjson,*loginjson;
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

TWOSTRINGS_AND_INT(bitcoinrpc,importprivkey,wif,account,rescan)
{
    bits256 privkey; char *retstr; cJSON *retjson; struct iguana_waddress addr,*waddr; struct iguana_waccount *wacct = 0;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    privkey = iguana_str2priv(coin,wif);
    if ( bits256_nonz(privkey) == 0 )
        return(clonestr("{\"error\":\"illegal privkey\"}"));
    memset(&addr,0,sizeof(addr));
    if ( iguana_waddresscalc(coin->chain->pubtype,coin->chain->wiftype,&addr,privkey) != 0 )
    {
        if ( (waddr= iguana_waddresssearch(coin,&wacct,addr.coinaddr)) != 0 )
        {
            if ( account != 0 && account[0] != 0 )
                waddr = iguana_waccountswitch(coin,account,addr.coinaddr);
        }
        if ( myinfo->secret[0] == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (retstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,0)) != 0 )
        {
            iguana_waddresscalc(coin->chain->pubtype,coin->chain->wiftype,waddr,privkey);
            retjson = iguana_walletadd(myinfo,coin,retstr,account,waddr,0);
            free(retstr);
            return(jprint(retjson,1));
        }
    }
    return(clonestr("{\"error\":\"cant calculate waddress\"}"));
}

STRING_ARG(bitcoinrpc,dumpprivkey,address)
{
    cJSON *retjson; struct iguana_waddress *waddr; struct iguana_waccount *wacct;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( (waddr= iguana_waddresssearch(coin,&wacct,address)) != 0 && waddr->wifstr[0] != 0 )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result",waddr->wifstr);
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"no privkey for address\"}"));
}

ZERO_ARGS(bitcoinrpc,checkwallet)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,repairwallet)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,dumpwallet,filename)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->secret[0] != 0 )
        return(SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,0));
    else return(clonestr("{\"error\":\"wallet is locked, cant backup\"}"));
}

// RZXuGgmzABFpXRmGJet8AbJoqVGEs27WgdvkSSXUMg7en8jjBW2m 2016-03-26T18:40:06Z reserve=1 # addr=GRVaqhY6XVWGeEabEEx5gE7mAQ7EYQi5JV

char *iguana_payloadsave(char *filename,char *payloadstr)
{
    FILE *fp;
    if ( (fp= fopen(filename,"wb")) != 0 )
    {
        if ( fwrite(payloadstr,1,strlen(payloadstr),fp) != strlen(payloadstr) )
        {
            fclose(fp);
            return(clonestr("{\"error\":\"couldnt save wallet backup\"}"));
        }
        fclose(fp);
        return(0);
    } else return(clonestr("{\"error\":\"couldnt save wallet backup\"}"));
}

STRING_ARG(bitcoinrpc,backupwallet,filename)
{
    char *loginstr,*payloadstr,*retstr = 0; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->secret[0] != 0 )
    {
        if ( (loginstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,0)) != 0 )
        {
            if ( (retjson= cJSON_Parse(loginstr)) != 0 )
            {
                if ( (payloadstr= jstr(retjson,"payload")) != 0 )
                    retstr = iguana_payloadsave(filename,payloadstr);
                free_json(retjson);
            }
            free(loginstr);
            if ( retstr == 0 )
                return(clonestr("{\"result\":\"wallet backup saved\"}"));
            else return(retstr);
        } else return(clonestr("{\"error\":\"no wallet payload\"}"));
    } else return(clonestr("{\"error\":\"need to unlock wallet\"}"));
}

cJSON *iguana_payloadmerge(cJSON *loginjson,cJSON *importjson)
{
    cJSON *retjson,*item,*obj; char *field;
    if ( loginjson == 0 )
        return(importjson);
    else if ( importjson == 0 )
        return(loginjson);
    retjson = jduplicate(loginjson);
    item = importjson->child;
    while ( item != 0 )
    {
        if ( (field= jfieldname(item)) != 0 )
        {
            if ( (obj= jobj(retjson,field)) == 0 )
                jaddbits256(retjson,field,jbits256(item,0));
        }
        item = item->next;
    }
    return(retjson);
}

STRING_ARG(bitcoinrpc,importwallet,filename)
{
    cJSON *retjson = 0,*importjson,*loginjson = 0; long filesize; char *importstr,*loginstr;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->secret[0] != 0 )
    {
        if ( (importstr= OS_filestr(&filesize,filename)) != 0 )
        {
            if ( (importjson= cJSON_Parse(importstr)) != 0 )
            {
                if ( (loginstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,0)) != 0 )
                {
                    loginjson = cJSON_Parse(loginstr);
                    free(loginstr);
                }
                retjson = iguana_payloadmerge(loginjson,importjson);
                if ( importjson != 0 && importjson != retjson )
                    free_json(importjson);
                if ( loginjson != 0 && loginjson != retjson )
                    free_json(loginjson);
            }
            else
            {
                free(importstr);
                return(clonestr("{\"error\":\"couldnt parse import file\"}"));
            }
            return(clonestr("{\"result\":\"wallet imported\"}"));
        } else return(clonestr("{\"error\":\"couldnt open import file\"}"));
    }
    return(clonestr("{\"error\":\"need to unlock wallet\"}"));
}

// multiple address
STRING_AND_THREEINTS(bitcoinrpc,getbalance,account,minconf,includeempty,lastheight)
{
    int64_t balance; int32_t numrmds=0; uint8_t *rmdarray=0; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( minconf == 0 )
        minconf = 1;
    if ( strcmp(account,"*") != 0 )
        rmdarray = iguana_rmdarray(coin,&numrmds,getaddressesbyaccount(myinfo,coin,account),0);
    balance = iguana_unspents(myinfo,coin,0,minconf,(1 << 30),rmdarray,numrmds,lastheight);
    if ( rmdarray != 0 )
        free(rmdarray);
    retjson = cJSON_CreateObject();
    jaddnum(retjson,"result",dstr(balance));
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,getaddressesbyaccount,account)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",getaddressesbyaccount(myinfo,coin,account));
    return(jprint(retjson,1));
}

int64_t iguana_waccountbalance(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,int32_t minconf,int32_t lastheight)
{
    int64_t balance; int32_t numrmds=0; uint8_t *rmdarray=0;
    if ( minconf == 0 )
        minconf = 1;
    rmdarray = iguana_rmdarray(coin,&numrmds,getaddressesbyaccount(myinfo,coin,wacct->account),0);
    balance = iguana_unspents(myinfo,coin,0,minconf,(1 << 30),rmdarray,numrmds,lastheight);
    if ( rmdarray != 0 )
        free(rmdarray);
    return(balance);
}

STRING_AND_INT(bitcoinrpc,getreceivedbyaccount,account,minconf)
{
    cJSON *retjson; struct iguana_waccount *wacct; int64_t balance;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    if ( (wacct= iguana_waccountfind(coin,account)) != 0 )
    {
        balance = iguana_waccountbalance(myinfo,coin,wacct,minconf,0);
        jaddnum(retjson,"result",dstr(balance));
    }
    return(jprint(retjson,1));
}

STRING_AND_THREEINTS(bitcoinrpc,listtransactions,account,count,skip,includewatchonly)
{ 
    cJSON *retjson,*retarray,*txids,*vouts,*item,*array; int32_t vout,i,j,total,m,n = 0; struct iguana_waccount *wacct; char *coinaddr; bits256 txid;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    retarray = cJSON_CreateArray();
    if ( (wacct= iguana_waccountfind(coin,account)) != 0 )
    {
        if ( (array= getaddressesbyaccount(myinfo,coin,account)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                total = 0;
                for (i=0; i<n; i++)
                {
                    if ( (coinaddr= jstr(jitem(array,i),0)) != 0 )
                    {
                        vouts = cJSON_CreateArray();
                        txids = cJSON_CreateArray();
                        iguana_addressreceived(myinfo,coin,json,remoteaddr,txids,vouts,coinaddr,1);
                        if ( (m= cJSON_GetArraySize(txids)) > 0 )
                        {
                            for (j=0; j<m; j++,total++)
                            {
                                txid = jbits256(jitem(txids,j),0);
                                vout = jint(jitem(vouts,j),0);
                                if ( skip < -count )
                                    break;
                                else
                                {
                                    skip--;
                                    if ( skip <= 0 )
                                    {
                                        /*{
                                          "category": "receive",
                                         "amount": 0.50000000,
                                         "label": "",
                                         "confirmations": 24466,
                                         "blockhash": "00000000000000000517ce625737579f91162c46ad9eaccad0f52ca13715b156",
                                         "blockindex": 78,
                                         "blocktime": 1448045745,
                                         }*/
                                        item = cJSON_CreateObject();
                                        jaddstr(item,"account",wacct->account);
                                        jaddstr(item,"address",coinaddr);
                                        jaddbits256(item,"txid",txid);
                                        jaddnum(item,"vout",vout);
                                        //return(bitcoinrpc_getrawtransaction(IGUANA_CALLARGS,txid,1));

                                        jaddi(retarray,item);
                                    }
                                }
                            }
                        }
                        free_json(txids);
                    }
                }
            }
        }
    }
    jadd(retjson,"result",retarray);
    return(jprint(retjson,1));
}

THREE_INTS(bitcoinrpc,listreceivedbyaccount,minconf,includeempty,watchonly)
{
    cJSON *retjson,*item,*array; struct iguana_waccount *wacct,*tmp; int64_t balance;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    array = cJSON_CreateArray();
    HASH_ITER(hh,coin->wallet,wacct,tmp)
    {
        balance = iguana_waccountbalance(myinfo,coin,wacct,minconf,0);
        item = cJSON_CreateObject();
        jaddstr(item,"account",wacct->account);
        jaddnum(item,"amount",dstr(balance));
        jaddnum(item,"confirmations",minconf);
        jaddi(array,item);
    }
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

THREE_INTS(bitcoinrpc,listreceivedbyaddress,minconf,includeempty,flag)
{
    cJSON *retjson,*item,*array,*txids,*vouts; struct iguana_waccount *wacct,*tmp; struct iguana_waddress *waddr,*tmp2;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    array = cJSON_CreateArray();
    HASH_ITER(hh,coin->wallet,wacct,tmp)
    {
        HASH_ITER(hh,wacct->waddr,waddr,tmp2)
        {
            item = cJSON_CreateObject();
            jaddstr(item,"address",waddr->coinaddr);
            txids = cJSON_CreateArray();
            vouts = cJSON_CreateArray();
            jaddnum(item,"amount",dstr(iguana_addressreceived(myinfo,coin,json,remoteaddr,txids,vouts,waddr->coinaddr,minconf)));
            jadd(item,"txids",txids);
            jadd(item,"vouts",vouts);
            jaddi(array,item);
        }
    }
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

TWO_INTS(bitcoinrpc,listaccounts,minconf,includewatchonly)
{
    cJSON *retjson,*array; int64_t balance; struct iguana_waccount *wacct,*tmp;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    array = cJSON_CreateObject();
    HASH_ITER(hh,coin->wallet,wacct,tmp)
    {
        balance = iguana_waccountbalance(myinfo,coin,wacct,minconf,0);
        jaddnum(array,wacct->account,dstr(balance));
    }
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

HASH_AND_TWOINTS(bitcoinrpc,listsinceblock,blockhash,target,flag)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_AND_INT(bitcoinrpc,getreceivedbyaddress,address,minconf)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_ARRAY_STRING(bitcoinrpc,createmultisig,M,array,ignore)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

INT_ARRAY_STRING(bitcoinrpc,addmultisig,M,array,account) //
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

STRING_AND_INT(bitcoinrpc,sendrawtransaction,rawtx,allowhighfees)
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

DOUBLE_ARG(bitcoinrpc,settxfee,amount)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

S_D_SS(bitcoinrpc,sendtoaddress,address,amount,comment,comment2)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    return(jsuccess());
}

SS_D_I_SS(bitcoinrpc,sendfrom,fromaccount,toaddress,amount,minconf,comment,comment2)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    return(jsuccess());
}

SS_D_I_S(bitcoinrpc,move,fromaccount,toaccount,amount,minconf,comment)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

S_A_I_S(bitcoinrpc,sendmany,fromaccount,array,minconf,comment)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}


#include "../includes/iguana_apiundefs.h"

