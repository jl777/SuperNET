/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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

// included from basilisk.c
// connect DEX to jumblr-core

/*
 z_exportkey "zaddr"
 z_exportwallet "filename"
 z_getoperationstatus (["operationid", ... ])
 z_gettotalbalance ( minconf )
 z_importkey "zkey" ( rescan )
 z_importwallet "filename"
 z_listaddresses
 z_sendmany "fromaddress" [{"address":... ,"amount":..., "memo":"<hex>"},...] ( minconf ) ( fee )
 */

#define JUMBLR_INCR 99.65
#define JUMBLR_TXFEE 0.01
#define JUMBLR_ADDR "RGhxXpXSSBTBm9EvNsXnTQczthMCxHX91t"
#define JUMBLR_BTCADDR "18RmTJe9qMech8siuhYfMtHo8RtcN1obC6"
#define JUMBLR_FEE 0.001

int32_t jumblr_addresstype(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    if ( addr[0] == 'z' && addr[1] == 'c' && strlen(addr) >= 40 )
        return('z');
    else if ( strlen(addr) < 40 )
        return('t');
    else return(-1);
}

struct jumblr_item *jumblr_opidfind(struct supernet_info *myinfo,char *opid)
{
    struct jumblr_item *ptr;
    HASH_FIND(hh,myinfo->jumblrs,opid,(int32_t)strlen(opid),ptr);
    return(ptr);
}

struct jumblr_item *jumblr_opidadd(struct supernet_info *myinfo,struct iguana_info *coin,char *opid)
{
    struct jumblr_item *ptr;
    if ( (ptr= jumblr_opidfind(myinfo,opid)) == 0 )
    {
        ptr = calloc(1,sizeof(*ptr));
        safecopy(ptr->opid,opid,sizeof(ptr->opid));
        HASH_ADD_KEYPTR(hh,myinfo->jumblrs,ptr->opid,(int32_t)strlen(ptr->opid),ptr);
        if ( ptr != jumblr_opidfind(myinfo,opid) )
            printf("jumblr_opidadd.(%s) ERROR, couldnt find after add\n",opid);
    }
    return(ptr);
}

char *jumblr_validateaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char params[1024];
    if ( coin->FULLNODE < 0 )
    {
        sprintf(params,"[\"%s\"]",addr);
        return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"validateaddress",params));
    } else return(_dex_validateaddress(myinfo,coin->symbol,addr));
}

int32_t jumblr_ismine(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char params[1024],*retstr; cJSON *retjson,*obj; int32_t retval = -1;
    sprintf(params,"[\"%s\"]",addr);
    if ( (retstr= jumblr_validateaddress(myinfo,coin,addr)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (obj= jobj(retjson,"ismine")) != 0 && is_cJSON_True(obj) != 0 )
                retval = 1;
            else retval = 0;
            free_json(retjson);
        }
        free(retstr);
    }
    return(retval);
}

char *jumblr_zgetnewaddress(struct supernet_info *myinfo,struct iguana_info *coin)
{
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_getnewaddress",""));
}

char *jumblr_zlistoperationids(struct supernet_info *myinfo,struct iguana_info *coin)
{
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_listoperationids",""));
}

char *jumblr_zgetoperationresult(struct supernet_info *myinfo,struct iguana_info *coin,char *opid)
{
    char params[1024];
    sprintf(params,"[[\"%s\"]]",opid);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_getoperationresult",params));
}

char *jumblr_zgetoperationstatus(struct supernet_info *myinfo,struct iguana_info *coin,char *opid)
{
    char params[1024];
    sprintf(params,"[[\"%s\"]]",opid);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_getoperationstatus",params));
}

char *jumblr_sendt_to_z(struct supernet_info *myinfo,struct iguana_info *coin,char *taddr,char *zaddr,double amount)
{
    char params[1024]; double fee = (amount-3*JUMBLR_TXFEE) * JUMBLR_FEE;
    if ( jumblr_addresstype(myinfo,coin,zaddr) != 'z' || jumblr_addresstype(myinfo,coin,taddr) != 't' )
        return(clonestr("{\"error\":\"illegal address in t to z\"}"));
    sprintf(params,"[\"%s\", [{\"address\":\"%s\",\"amount\":%.8f}, {\"address\":\"%s\",\"amount\":%.8f}], 1, %.8f]",taddr,zaddr,amount-fee-JUMBLR_TXFEE,JUMBLR_ADDR,fee,JUMBLR_TXFEE);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_sendmany",params));
}

char *jumblr_sendz_to_z(struct supernet_info *myinfo,struct iguana_info *coin,char *zaddrS,char *zaddrD,double amount)
{
    char params[1024]; double fee = (amount-2*JUMBLR_TXFEE) * JUMBLR_FEE;
    if ( jumblr_addresstype(myinfo,coin,zaddrS) != 'z' || jumblr_addresstype(myinfo,coin,zaddrD) != 'z' )
        return(clonestr("{\"error\":\"illegal address in z to z\"}"));
    sprintf(params,"[\"%s\", [{\"address\":\"%s\",\"amount\":%.8f}, {\"address\":\"%s\",\"amount\":%.8f}], 1, %.8f]",zaddrS,zaddrD,amount-fee-JUMBLR_TXFEE,JUMBLR_ADDR,fee,JUMBLR_TXFEE);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_sendmany",params));
}

char *jumblr_sendz_to_t(struct supernet_info *myinfo,struct iguana_info *coin,char *zaddr,char *taddr,double amount)
{
    char params[1024]; double fee = (amount-JUMBLR_TXFEE) * JUMBLR_FEE;
    if ( jumblr_addresstype(myinfo,coin,zaddr) != 'z' || jumblr_addresstype(myinfo,coin,taddr) != 't' )
        return(clonestr("{\"error\":\"illegal address in z to t\"}"));
    sprintf(params,"[\"%s\", [{\"address\":\"%s\",\"amount\":%.8f}, {\"address\":\"%s\",\"amount\":%.8f}], 1, %.8f]",zaddr,taddr,amount-fee-JUMBLR_TXFEE,JUMBLR_ADDR,fee,JUMBLR_TXFEE);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_sendmany",params));
}

char *jumblr_zlistreceivedbyaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char params[1024];
    sprintf(params,"[\"%s\", 1]",addr);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_listreceivedbyaddress",params));
}

char *jumblr_getreceivedbyaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char params[1024];
    sprintf(params,"[\"%s\", 1]",addr);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getreceivedbyaddress",params));
}

char *jumblr_importprivkey(struct supernet_info *myinfo,struct iguana_info *coin,char *wifstr)
{
    char params[1024];
    sprintf(params,"[\"%s\", \"\", false]",wifstr);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"importprivkey",params));
}

char *jumblr_zgetbalance(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char params[1024];
    sprintf(params,"[\"%s\", 1]",addr);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_getbalance",params));
}

char *jumblr_listunspent(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char params[1024];
    sprintf(params,"[1, 99999999, [\"%s\"]]",addr);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"listunspent",params));
}

int64_t jumblr_receivedby(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char *retstr; int64_t total = 0;
    if ( (retstr= jumblr_getreceivedbyaddress(myinfo,coin,addr)) != 0 )
    {
        total = atof(retstr) * SATOSHIDEN;
        free(retstr);
    }
    return(total);
}

int64_t jumblr_balance(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char *retstr; double val; cJSON *retjson; int32_t i,n; int64_t balance = 0;
    if ( jumblr_addresstype(myinfo,coin,addr) == 't' )
    {
        if ( coin->FULLNODE < 0 && jumblr_ismine(myinfo,coin,addr) > 0 )
        {
            if ( (retstr= jumblr_listunspent(myinfo,coin,addr)) != 0 )
            {
                if ( (retjson= cJSON_Parse(retstr)) != 0 )
                {
                    if ( (n= cJSON_GetArraySize(retjson)) > 0 )
                        for (i=0; i<n; i++)
                            balance += SATOSHIDEN * jdouble(jitem(retjson,i),"amount");
                    free_json(retjson);
                }
                free(retstr);
            }
        }
        else if ( (retstr= dex_getbalance(myinfo,coin,0,0,coin->symbol,addr)) != 0 )
        {
            //printf("retstr.(%s)\n",retstr);
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                balance = jdouble(retjson,"balance") * SATOSHIDEN;
                free_json(retjson);
            }
            free(retstr);
        }
    }
    else if ( (retstr= jumblr_zgetbalance(myinfo,coin,addr)) != 0 )
    {
        if ( (val= atof(retstr)) > SMALLVAL )
            balance = val * SATOSHIDEN;
        free(retstr);
    }
    return(balance);
}

int32_t jumblr_itemset(struct jumblr_item *ptr,cJSON *item,char *status)
{
    cJSON *params,*amounts,*dest; char *from,*addr; int32_t i,n; int64_t amount;
    /*"params" : {
     "fromaddress" : "RDhEGYScNQYetCyG75Kf8Fg61UWPdwc1C5",
     "amounts" : [
     {
     "address" : "zc9s3UdkDFTnnwHrMCr1vYy2WmkjhmTxXNiqC42s7BjeKBVUwk766TTSsrRPKfnX31Bbu8wbrTqnjDqskYGwx48FZMPHvft",
     "amount" : 3.00000000
     }
     ],
     "minconf" : 1,
     "fee" : 0.00010000
     }*/
    if ( (params= jobj(item,"params")) != 0 )
    {
        //printf("params.(%s)\n",jprint(params,0));
        if ( (from= jstr(params,"fromaddress")) != 0 )
            safecopy(ptr->src,from,sizeof(ptr->src));
        if ( (amounts= jarray(&n,params,"amounts")) != 0 )
        {
            for (i=0; i<n; i++)
            {
                dest = jitem(amounts,i);
                //printf("%s ",jprint(dest,0));
                if ( (addr= jstr(dest,"address")) != 0 && (amount= jdouble(dest,"amount")*SATOSHIDEN) > 0 )
                {
                    if ( strcmp(addr,JUMBLR_ADDR) == 0 )
                        ptr->fee = amount;
                    else
                    {
                        ptr->amount = amount;
                        safecopy(ptr->dest,addr,sizeof(ptr->dest));
                    }
                }
            }
        }
        ptr->txfee = jdouble(params,"fee") * SATOSHIDEN;
    }
    return(1);
}

void jumblr_opidupdate(struct supernet_info *myinfo,struct iguana_info *coin,struct jumblr_item *ptr)
{
    char *retstr,*status; cJSON *retjson,*item;
    if ( ptr->status == 0 )
    {
        if ( (retstr= jumblr_zgetoperationstatus(myinfo,coin,ptr->opid)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( cJSON_GetArraySize(retjson) == 1 )
                {
                    item = jitem(retjson,0);
                    //printf("%s\n",jprint(item,0));
                    if ( (status= jstr(item,"status")) != 0 )
                    {
                        if ( strcmp(status,"success") == 0 )
                        {
                            ptr->status = jumblr_itemset(ptr,item,status);
                        }
                        else if ( strcmp(status,"failed") == 0 )
                        {
                            printf("%s failed\n",ptr->opid);
                            free(jumblr_zgetoperationresult(myinfo,coin,ptr->opid));
                            ptr->status = -1;
                        }
                    }
                }
                free_json(retjson);
            }
            free(retstr);
        }
    }
}

void jumblr_prune(struct supernet_info *myinfo,struct iguana_info *coin,struct jumblr_item *ptr)
{
    struct jumblr_item *tmp; char oldsrc[128]; int32_t flag = 1;
    printf("PRUNE %s\n",ptr->opid);
    strcpy(oldsrc,ptr->src);
    free(jumblr_zgetoperationresult(myinfo,coin,ptr->opid));
    while ( flag != 0 )
    {
        flag = 0;
        HASH_ITER(hh,myinfo->jumblrs,ptr,tmp)
        {
            if ( strcmp(oldsrc,ptr->dest) == 0 )
            {
                printf("prune %s (%s -> %s) matched oldsrc\n",ptr->opid,ptr->src,ptr->dest);
                free(jumblr_zgetoperationresult(myinfo,coin,ptr->opid));
                strcpy(oldsrc,ptr->src);
                flag = 1;
                break;
            }
        }
    }
}

void jumblr_opidsupdate(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char *retstr; cJSON *array; int32_t i,n; struct jumblr_item *ptr;
    if ( (retstr= jumblr_zlistoperationids(myinfo,coin)) != 0 )
    {
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (ptr= jumblr_opidadd(myinfo,coin,jstri(array,i))) != 0 )
                    {
                        if ( ptr->status == 0 )
                            jumblr_opidupdate(myinfo,coin,ptr);
                        //printf("%d: %s -> %s %.8f\n",ptr->status,ptr->src,ptr->dest,dstr(ptr->amount));
                        if ( jumblr_addresstype(myinfo,coin,ptr->src) == 'z' && jumblr_addresstype(myinfo,coin,ptr->dest) == 't' )
                            jumblr_prune(myinfo,coin,ptr);
                    }
                }
            }
            free_json(array);
        }
        free(retstr);
    }
}

bits256 jumblr_privkey(struct supernet_info *myinfo,char *BTCaddr,char *KMDaddr,char *prefix)
{
    bits256 privkey,pubkey; uint8_t pubkey33[33]; char passphrase[sizeof(myinfo->jumblr_passphrase) + 64];
    sprintf(passphrase,"%s%s",prefix,myinfo->jumblr_passphrase);
    conv_NXTpassword(privkey.bytes,pubkey.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
    bitcoin_pubkey33(myinfo->ctx,pubkey33,privkey);
    bitcoin_address(BTCaddr,0,pubkey33,33);
    bitcoin_address(KMDaddr,60,pubkey33,33);
    return(privkey);
}

void jumblr_DEXcheck(struct supernet_info *myinfo,struct iguana_info *coinkmd,char *BTCaddr,char *KMDaddr,bits256 privkey)
{
    static double kmdprice,pending; static uint32_t lasttime;
    double btcavail=0,minbtc,avebid,aveask,highbid,lowask,CMC_average,USD_average,changes[3]; struct iguana_info *coinbtc; cJSON *vals; bits256 hash; char *retstr;
    coinbtc = iguana_coinfind("BTC");
    if ( kmdprice == 0. || time(NULL) > lasttime+60 )
    {
        kmdprice = get_theoretical(&avebid,&aveask,&highbid,&lowask,&CMC_average,changes,"komodo","KMD","BTC",&USD_average);
        lasttime = (uint32_t)time(NULL);
        printf("KMD %.8f\n",kmdprice);
    }
    if ( kmdprice > SMALLVAL )
    {
        minbtc = (kmdprice * 1.1) * (JUMBLR_INCR + 3*(JUMBLR_INCR * JUMBLR_FEE + JUMBLR_TXFEE));
        if ( coinbtc != 0 && (btcavail= dstr(jumblr_balance(myinfo,coinbtc,BTCaddr))) > minbtc+pending )
        {
            printf("BTC deposits %.8f, min %.8f\n",btcavail,minbtc);
            vals = cJSON_CreateObject();
            jaddstr(vals,"source","BTC");
            //hash = curve25519(privkey,curve25519_basepoint9());
            jaddstr(vals,"dest","KMD");
            jaddnum(vals,"amount",btcavail*.3);
            jaddnum(vals,"minprice",kmdprice*.95);
            jaddnum(vals,"usejumblr",1);
            memset(hash.bytes,0,sizeof(hash));
            pending = btcavail;
            if ( (retstr= InstantDEX_request(myinfo,coinbtc,0,0,hash,vals,"")) != 0 )
            {
                printf("request.(%s) -> (%s)\n",jprint(vals,0),retstr);
                free(retstr);
            }
            // curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"request\",\"vals\":{\"source\":\"KMD\",\"amount\":20,\"dest\":\"USD\",\"minprice\":0.08}}"
        } else printf("btcavail %.8f pending %.8f\n",btcavail,pending);
    } else printf("null kmdprice %.8f\n",kmdprice);
}

void jumblr_iteration(struct supernet_info *myinfo,struct iguana_info *coin,int32_t selector,int32_t modval)
{
    //static uint32_t lasttime;
    char BTCaddr[64],KMDaddr[64],*zaddr,*retstr; bits256 privkey; uint64_t amount=0,total=0; double fee; struct jumblr_item *ptr,*tmp; uint8_t r;
    fee = JUMBLR_INCR * JUMBLR_FEE;
    OS_randombytes(&r,sizeof(r));
//r = 0;
    if ( strcmp(coin->symbol,"KMD") == 0 && coin->FULLNODE < 0 )
    {
        //printf("JUMBLR selector.%d modval.%d r.%d\n",selector,modval,r&7);
        switch ( selector )
        {
            case 0: // public -> z, need to importprivkey
                if ( (total= jumblr_balance(myinfo,coin,KMDaddr)) >= (JUMBLR_INCR + 3*(fee+JUMBLR_TXFEE))*SATOSHIDEN )
                {
                    if ( (r & 1) == 0 )
                    {
                        if ( (zaddr= jumblr_zgetnewaddress(myinfo,coin)) != 0 )
                        {
                            if ( total >= SATOSHIDEN * ((JUMBLR_INCR + 3*fee)*100 + 3*JUMBLR_TXFEE) )
                                amount = SATOSHIDEN * ((JUMBLR_INCR + 3*fee)*100 + 3*JUMBLR_TXFEE);
                            else if ( total >= SATOSHIDEN * ((JUMBLR_INCR + 3*fee)*10 + 3*JUMBLR_TXFEE) )
                                amount = SATOSHIDEN * ((JUMBLR_INCR + 3*fee)*10 + 3*JUMBLR_TXFEE);
                            else amount = SATOSHIDEN * ((JUMBLR_INCR + 3*fee) + 3*JUMBLR_TXFEE);
                            if ( (retstr= jumblr_sendt_to_z(myinfo,coin,KMDaddr,zaddr,dstr(amount))) != 0 )
                            {
                                printf("sendt_to_z.(%s)\n",retstr);
                                free(retstr);
                            }
                            free(zaddr);
                        } else printf("no zaddr from jumblr_zgetnewaddress\n");
                    }
                } //else printf("%s total %.8f vs %.8f\n",KMDaddr,dstr(total),(JUMBLR_INCR + 3*(fee+JUMBLR_TXFEE)));
                break;
            case 1: // z -> z
                jumblr_opidsupdate(myinfo,coin);
                HASH_ITER(hh,myinfo->jumblrs,ptr,tmp)
                {
                    if ( jumblr_addresstype(myinfo,coin,ptr->src) == 't' && jumblr_addresstype(myinfo,coin,ptr->dest) == 'z' )
                    {
                        if ( (r & 1) == 0 && ptr->spent == 0 && (total= jumblr_balance(myinfo,coin,ptr->dest)) >= (fee + JUMBLR_FEE)*SATOSHIDEN )
                        {
                            if ( (zaddr= jumblr_zgetnewaddress(myinfo,coin)) != 0 )
                            {
                                if ( (retstr= jumblr_sendz_to_z(myinfo,coin,ptr->dest,zaddr,dstr(total))) != 0 )
                                {
                                    printf("sendz_to_z.(%s)\n",retstr);
                                    free(retstr);
                                }
                                ptr->spent = (uint32_t)time(NULL);
                                free(zaddr);
                                break;
                            }
                        }
                    }
                }
                break;
            case 2: // z -> public
                jumblr_opidsupdate(myinfo,coin);
                HASH_ITER(hh,myinfo->jumblrs,ptr,tmp)
                {
                    if ( jumblr_addresstype(myinfo,coin,ptr->src) == 'z' && jumblr_addresstype(myinfo,coin,ptr->dest) == 'z' )
                    {
                        if ( (r & 1) == 0 && ptr->spent == 0 && (total= jumblr_balance(myinfo,coin,ptr->dest)) >= (fee + JUMBLR_FEE)*SATOSHIDEN )
                        {
                            privkey = jumblr_privkey(myinfo,BTCaddr,KMDaddr,"");
                            if ( (retstr= jumblr_sendz_to_t(myinfo,coin,ptr->dest,KMDaddr,dstr(total))) != 0 )
                            {
                                printf("sendz_to_t.(%s)\n",retstr);
                                free(retstr);
                            }
                            ptr->spent = (uint32_t)time(NULL);
                            break;
                        }
                    }
                }
                break;
        }
    }
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

STRING_ARG(jumblr,setpassphrase,passphrase)
{
    cJSON *retjson; char KMDaddr[64],BTCaddr[64],wifstr[64]; bits256 privkey; struct iguana_info *coinbtc;
    if ( passphrase == 0 || passphrase[0] == 0 || (coin= iguana_coinfind("KMD")) == 0 || coin->FULLNODE >= 0 )
        return(clonestr("{\"error\":\"no passphrase or no native komodod\"}"));
    else
    {
        safecopy(myinfo->jumblr_passphrase,passphrase,sizeof(myinfo->jumblr_passphrase));
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","success");
        privkey = jumblr_privkey(myinfo,BTCaddr,KMDaddr,JUMBLR_DEPOSITPREFIX);
        myinfo->jumblr_depositkey = curve25519(privkey,curve25519_basepoint9());
        bitcoin_priv2wif(wifstr,privkey,coin->chain->wiftype);
        if ( coin->FULLNODE < 0 )
            jumblr_importprivkey(myinfo,coin,wifstr);
        jaddstr(retjson,"KMDdeposit",KMDaddr);
        jaddstr(retjson,"BTCdeposit",BTCaddr);
        if ( (coinbtc= iguana_coinfind("BTC")) != 0 )
        {
            bitcoin_priv2wif(wifstr,privkey,coinbtc->chain->wiftype);
            if ( coinbtc->FULLNODE < 0 )
                jumblr_importprivkey(myinfo,coinbtc,wifstr);
            jaddnum(retjson,"BTCdeposits",dstr(jumblr_balance(myinfo,coinbtc,BTCaddr)));
        }
        privkey = jumblr_privkey(myinfo,BTCaddr,KMDaddr,"");
        myinfo->jumblr_pubkey = curve25519(privkey,curve25519_basepoint9());
        jaddstr(retjson,"KMDjumblr",KMDaddr);
        jaddstr(retjson,"BTCjumblr",BTCaddr);
        if ( coinbtc != 0 )
            jaddnum(retjson,"BTCjumbled",dstr(jumblr_balance(myinfo,coinbtc,BTCaddr)));
        return(jprint(retjson,1));
    }
}

ZERO_ARGS(jumblr,status)
{
    cJSON *retjson; char KMDaddr[64],BTCaddr[64]; struct jumblr_item *ptr,*tmp; struct iguana_info *coinbtc; int64_t received,deposited,jumblred,step_t2z,step_z2z,step_z2t,finished,pending,maxval,minval;
    if ( strcmp(coin->symbol,"KMD") == 0 && coin->FULLNODE < 0 && myinfo->jumblr_passphrase[0] != 0 )
    {
        jumblr_opidsupdate(myinfo,coin);
        retjson = cJSON_CreateObject();
        step_t2z = step_z2z = step_z2t = deposited = finished = pending = 0;
        jumblr_privkey(myinfo,BTCaddr,KMDaddr,JUMBLR_DEPOSITPREFIX);
        jaddstr(retjson,"KMDdeposit",KMDaddr);
        jaddstr(retjson,"BTCdeposit",BTCaddr);
        if ( (coinbtc= iguana_coinfind("BTC")) != 0 )
            jaddnum(retjson,"BTCdeposits",dstr(jumblr_balance(myinfo,coinbtc,BTCaddr)));
        received = jumblr_receivedby(myinfo,coin,KMDaddr);
        deposited = jumblr_balance(myinfo,coin,KMDaddr);
        jumblr_privkey(myinfo,BTCaddr,KMDaddr,"");
        jaddstr(retjson,"KMDjumblr",KMDaddr);
        jaddstr(retjson,"BTCjumblr",BTCaddr);
        if ( coinbtc != 0 )
            jaddnum(retjson,"BTCjumbled",dstr(jumblr_balance(myinfo,coinbtc,BTCaddr)));
        finished = jumblr_receivedby(myinfo,coin,KMDaddr);
        jumblred = jumblr_balance(myinfo,coin,KMDaddr);
        HASH_ITER(hh,myinfo->jumblrs,ptr,tmp)
        {
            if ( strlen(ptr->src) >= 40 )
            {
                if ( strlen(ptr->dest) >= 40 )
                    step_z2z += ptr->amount;
                else step_z2t += ptr->amount;
            } else step_t2z += ptr->amount;
        }
        jaddstr(retjson,"result","success");
        jaddnum(retjson,"deposits",dstr(deposited));
        jaddnum(retjson,"t_to_z",dstr(step_t2z));
        jaddnum(retjson,"z_to_z",dstr(step_z2z));
        jaddnum(retjson,"z_to_t",dstr(step_z2t));
        maxval = MAX(step_t2z,MAX(step_z2z,step_z2t));
        minval = MIN(step_t2z,MIN(step_z2z,step_z2t));
        if ( maxval > minval )
        {
            pending = (maxval - minval);
            if ( pending < finished*.1 )
                pending = 0;
        }
        jaddnum(retjson,"pending",dstr(pending));
        jaddnum(retjson,"jumbled",dstr(jumblred));
        jaddnum(retjson,"received",dstr(received));
        jaddnum(retjson,"finished",dstr(finished));
        return(jprint(retjson,1));
    }
    else
    {
        printf("(%s) (%s) %d\n",coin->symbol,myinfo->jumblr_passphrase,coin->FULLNODE);
        return(clonestr("{\"error\":\"jumblr status no passphrase or no native komodod\"}"));
    }
}

#include "../includes/iguana_apiundefs.h"
