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
#include "exchanges/bitcoin.h"

void scrubfree(char *sensitivestr)
{
    long len,i;
    if ( sensitivestr != 0 )
    {
        len = strlen(sensitivestr);
        memset(sensitivestr,0,len);
        for (i=0; i<len; i++)
            sensitivestr[i] = rand();
        free(sensitivestr);
    }
}

struct iguana_waddress *iguana_waddressfind(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,char *coinaddr)
{
    struct iguana_waddress *waddr; int32_t len = (int32_t)strlen(coinaddr)+1;
    HASH_FIND(hh,wacct->waddr,coinaddr,len,waddr);
    if ( waddr != 0 && coin != 0 && strcmp(coin->symbol,waddr->symbol) != 0 )
        return(0);
    //printf("%s (%s).%d in (%s)\n",waddr==0?"couldnt find":"found",coinaddr,len,wacct->account);
    return(waddr);
}

struct iguana_waddress *iguana_waddressalloc(uint8_t addrtype,char *symbol,char *coinaddr,char *redeemScript)
{
    struct iguana_waddress *waddr; int32_t scriptlen;
    scriptlen = (redeemScript != 0) ? ((int32_t)strlen(redeemScript) >> 1) : 0;
    waddr = mycalloc('w',1,sizeof(*waddr) + scriptlen);
    waddr->addrtype = addrtype;
    strcpy(waddr->coinaddr,coinaddr);
    strcpy(waddr->symbol,symbol);
    if ( (waddr->scriptlen= scriptlen) != 0 )
        decode_hex(waddr->redeemScript,scriptlen,redeemScript);
    return(waddr);
}

struct iguana_waccount *iguana_waccountfind(struct supernet_info *myinfo,struct iguana_info *coin,char *account)
{
    struct iguana_waccount *wacct;
    HASH_FIND(hh,myinfo->wallet,account,strlen(account)+1,wacct);
    //printf("waccountfind.(%s) -> wacct.%p\n",account,wacct);
    return(wacct);
}

struct iguana_waccount *iguana_waccountcreate(struct supernet_info *myinfo,struct iguana_info *coin,char *account)
{
    struct iguana_waccount *wacct,*ptr; int32_t len = (int32_t)strlen(account)+1;
    HASH_FIND(hh,myinfo->wallet,account,len,wacct);
    if ( wacct == 0 )
    {
        wacct = mycalloc('w',1,sizeof(*wacct));
        strcpy(wacct->account,account);
        HASH_ADD_KEYPTR(hh,myinfo->wallet,wacct->account,len,wacct);
        //printf("waccountcreate.(%s) -> wacct.%p\n",account,wacct);
        myinfo->dirty = (uint32_t)time(NULL);
        if ( (ptr= iguana_waccountfind(myinfo,coin,account)) != wacct )
            printf("iguana_waccountcreate verify error %p vs %p\n",ptr,wacct);
    }
    return(wacct);
}

struct iguana_waddress *iguana_waddresscreate(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,char *coinaddr,char *redeemScript)
{
    struct iguana_waddress *waddr,*ptr; int32_t len = (int32_t)strlen(coinaddr)+1;
    if ( wacct == 0 )
        wacct = iguana_waccountcreate(myinfo,coin,"");
    HASH_FIND(hh,wacct->waddr,coinaddr,len,waddr);
    if ( waddr == 0 )
    {
        if ( (waddr= iguana_waddressalloc(redeemScript==0?coin->chain->pubtype : coin->chain->p2shtype,coin->symbol,coinaddr,redeemScript)) != 0 )
        {
            HASH_ADD_KEYPTR(hh,wacct->waddr,waddr->coinaddr,len,waddr);
            myinfo->dirty = (uint32_t)time(NULL);
            printf("create (%s).%d scriptlen.%d -> (%s)\n",coinaddr,len,waddr->scriptlen,wacct->account);
        } else printf("error iguana_waddressalloc null waddr\n");
    } //else printf("have (%s) in (%s)\n",coinaddr,wacct->account);
    if ( (ptr= iguana_waddressfind(myinfo,coin,wacct,coinaddr)) != waddr )
        printf("iguana_waddresscreate verify error %p vs %p\n",ptr,waddr);
    return(waddr);
}

struct iguana_waddress *iguana_waddressadd(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,struct iguana_waddress *addwaddr,char *redeemScript)
{
    struct iguana_waddress *waddr,*ptr; int32_t len = (int32_t)strlen(addwaddr->coinaddr)+1;
    HASH_FIND(hh,wacct->waddr,addwaddr->coinaddr,len,waddr);
    if ( waddr == 0 )
    {
        if ( (waddr= iguana_waddressalloc(redeemScript==0?coin->chain->pubtype : coin->chain->p2shtype,coin->symbol,addwaddr->coinaddr,redeemScript)) != 0 )
        {
            HASH_ADD_KEYPTR(hh,wacct->waddr,waddr->coinaddr,len,waddr);
            myinfo->dirty = (uint32_t)time(NULL);
            printf("add (%s).%d scriptlen.%d -> (%s) wif.(%s)\n",waddr->coinaddr,len,waddr->scriptlen,wacct->account,waddr->wifstr);
        } else printf("error iguana_waddressalloc null waddr\n");
    } //else printf("have (%s) in (%s)\n",waddr->coinaddr,wacct->account);
    if ( (ptr= iguana_waddressfind(myinfo,coin,wacct,waddr->coinaddr)) != waddr )
        printf("iguana_waddressadd verify error %p vs %p\n",ptr,waddr);
    if ( waddr != 0 && waddr != addwaddr )
    {
        waddr->wiftype = coin->chain->wiftype;
        if ( redeemScript != 0 && (addwaddr->scriptlen= (int32_t)strlen(redeemScript) >> 1) != 0 )
        {
            if ( waddr->scriptlen != addwaddr->scriptlen )
            {
                if ( waddr->scriptlen < addwaddr->scriptlen )
                {
                    printf("unexpected waddr->scriptlen mismatch\n");
                }
                waddr->scriptlen = addwaddr->scriptlen;
                decode_hex(waddr->redeemScript,waddr->scriptlen,redeemScript);
            }
            waddr->addrtype = coin->chain->p2shtype;
            memset(&waddr->privkey,0,sizeof(waddr->privkey));
            memset(waddr->pubkey,0,sizeof(waddr->pubkey));
        }
        else
        {
            waddr->addrtype = coin->chain->pubtype;
            waddr->wiftype = addwaddr->wiftype;
            if ( bits256_nonz(waddr->privkey) == 0 )
                waddr->privkey = addwaddr->privkey;
            if ( addwaddr->wifstr[0] != 0 )
                strcpy(waddr->wifstr,addwaddr->wifstr);
            memcpy(waddr->pubkey,addwaddr->pubkey,sizeof(waddr->pubkey));
        }
        memcpy(waddr->rmd160,addwaddr->rmd160,sizeof(waddr->rmd160));
        strcpy(waddr->coinaddr,addwaddr->coinaddr);
        myinfo->dirty = (uint32_t)time(NULL);
    }
    if ( waddr != 0 && waddr->symbol[0] == 0 )
        strcpy(waddr->symbol,coin->symbol);
    return(waddr);
}

struct iguana_waddress *iguana_waddressdelete(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,char *coinaddr)
{
    struct iguana_waddress *waddr = 0; int32_t len = (int32_t)strlen(coinaddr)+1;
    HASH_FIND(hh,wacct->waddr,coinaddr,len,waddr);
    if ( waddr != 0 )
    {
        HASH_DELETE(hh,wacct->waddr,waddr);
        myinfo->dirty = (uint32_t)time(NULL);
    }
    return(waddr);
}

struct iguana_waddress *iguana_waddresssearch(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount **wacctp,char *coinaddr)
{
    struct iguana_waccount *wacct,*tmp; struct iguana_waddress *waddr;
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        if ( (waddr= iguana_waddressfind(myinfo,coin,wacct,coinaddr)) != 0 )
        {
            if ( waddr != 0 && bits256_nonz(waddr->privkey) != 0 )
            {
                if ( bitcoin_priv2wif(waddr->wifstr,waddr->privkey,coin->chain->wiftype) > 0 )
                {
                    if ( waddr->wiftype != coin->chain->wiftype )
                        printf("waddresssearch warning: mismatched wiftype %02x != %02x\n",waddr->wiftype,coin->chain->wiftype);
                    if ( waddr->addrtype != coin->chain->pubtype )
                        printf("waddresssearch warning: mismatched wiftype %02x != %02x\n",waddr->addrtype,coin->chain->pubtype);
                }
            }
            (*wacctp) = wacct;
            return(waddr);
        }
    }
    return(0);
}

struct iguana_waddress *iguana_waddresscalc(struct supernet_info *myinfo,uint8_t pubtype,uint8_t wiftype,struct iguana_waddress *addr,bits256 privkey)
{
    addr->privkey = privkey;
    bitcoin_pubkey33(myinfo->ctx,addr->pubkey,addr->privkey);
    calc_rmd160_sha256(addr->rmd160,addr->pubkey,33);
    bitcoin_address(addr->coinaddr,pubtype,addr->rmd160,sizeof(addr->rmd160));
    if ( bits256_nonz(privkey) != 0 )
    {
        if ( bitcoin_priv2wif(addr->wifstr,addr->privkey,wiftype) > 0 )
        {
            addr->wiftype = wiftype;
            addr->addrtype = pubtype;
            return(addr);
        }
    } else printf("waddress_calc null privkey\n");
    return(0);
}

struct iguana_waddress *iguana_waccountswitch(struct supernet_info *myinfo,struct iguana_info *coin,char *account,char *coinaddr,char *redeemScript)
{
    struct iguana_waccount *wacct = 0; struct iguana_waddress addr,*waddr = 0; int32_t flag = 0;
    if ( (waddr= iguana_waddresssearch(myinfo,coin,&wacct,coinaddr)) != 0 )
    {
        if ( strcmp(wacct->account,account) != 0 )
        {
            addr = *waddr;
            flag = 1;
            iguana_waddressdelete(myinfo,coin,wacct,coinaddr);
        }
    }
    if ( waddr == 0 && (wacct= iguana_waccountcreate(myinfo,coin,account)) != 0 )
    {
        waddr = iguana_waddresscreate(myinfo,coin,wacct,coinaddr,redeemScript);
        if ( flag != 0 && redeemScript == 0 )
            iguana_waddresscalc(myinfo,coin->chain->pubtype,coin->chain->wiftype,waddr,addr.privkey);
    }
    return(waddr);
}

uint8_t *iguana_walletrmds(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *numrmdsp)
{
    int32_t iter,n,m; struct iguana_waccount *acct,*tmp; uint8_t *pubkeys,*addrtypes,*rmdarray = 0; struct iguana_waddress *waddr,*tmp2;
    for (iter=n=m=0; iter<2; iter++)
    {
        HASH_ITER(hh,myinfo->wallet,acct,tmp)
        {
            HASH_ITER(hh,acct->waddr,waddr,tmp2)
            {
                if ( iter == 0 )
                    n++;
                else if ( m < n )
                {
                    addrtypes[m] = waddr->addrtype;
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
    if ( (subset= iguana_waccountfind(myinfo,coin,account)) != 0 )
    {
        HASH_ITER(hh,subset->waddr,waddr,tmp)
        {
            jaddistr(array,waddr->coinaddr);
        }
    } else jaddstr(retjson,"result","cant find account");
    return(array);
}

struct iguana_waddress *iguana_ismine(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t addrtype,uint8_t pubkey[65],uint8_t rmd160[20])
{
    char coinaddr[65]; struct iguana_waccount *wacct; struct iguana_waddress *waddr = 0;
    if ( bitcoin_address(coinaddr,addrtype,rmd160,20) > 0 )
        waddr = iguana_waddresssearch(myinfo,coin,&wacct,coinaddr);
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
    char str[256],redeemScript[4096];
    if ( item == 0 )
        item = cJSON_CreateObject();
    jaddstr(item,"address",waddr->coinaddr);
    //jaddstr(item,"privkey",bits256_str(str,waddr->privkey));
    //jaddstr(item,"wif",waddr->wifstr);
    init_hexbytes_noT(str,waddr->rmd160,20);
    jaddstr(item,"rmd160",str);
    jaddstr(item,"coin",waddr->symbol);
    if ( waddr->scriptlen > 0 )
    {
        init_hexbytes_noT(redeemScript,waddr->redeemScript,waddr->scriptlen);
        jaddstr(item,"redeemScript",redeemScript);
    }
    else
    {
        init_hexbytes_noT(str,waddr->pubkey,33);
        jaddstr(item,"pubkey",str);
    }
    return(item);
}

char *setaccount(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waddress **waddrp,char *account,char *coinaddr,char *redeemScript)
{
    uint8_t addrtype,rmd160[20]; struct iguana_waddress *waddr=0;
    if ( waddrp != 0 )
        *waddrp = 0;
    if ( coinaddr != 0 && coinaddr[0] != 0 && account != 0 && account[0] != 0 )
    {
        if ( iguana_addressvalidate(coin,&addrtype,rmd160,coinaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        if ( (waddr= iguana_waccountswitch(myinfo,coin,account,coinaddr,redeemScript)) != 0 )
        {
            if ( waddrp != 0 )
                *waddrp = waddr;
            return(clonestr("{\"result\":\"success\"}"));
        }
        else return(clonestr("{\"error\":\"couldnt set account\"}"));
    }
    return(clonestr("{\"error\":\"need address and account\"}"));
}

char *getaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    struct iguana_waccount *wacct; struct iguana_waddress *waddr; uint8_t addrtype,rmd160[20]; cJSON *retjson;
    if ( iguana_addressvalidate(coin,&addrtype,rmd160,coinaddr) < 0 )
        return(clonestr("{\"error\":\"invalid coin address\"}"));
    if ( (waddr= iguana_waddresssearch(myinfo,coin,&wacct,coinaddr)) == 0 )
        return(clonestr("{\"result\":\"no account for address\"}"));
    if ( wacct != 0 )
    {
        retjson = iguana_waddressjson(0,waddr);
        jaddstr(retjson,"account",wacct->account);
        jaddstr(retjson,"result","success");
        return(jprint(retjson,1));
    } else return(clonestr("{\"result\":\"\"}"));
}

char *jsuccess()
{
    cJSON *retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
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
            //printf("loginsave.(%s) <= (%s)\n",destfname,newstr);
            //iguana_walletlock(myinfo);
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
        if ( account == 0 || account[0] == 0 )
            account = "default";
        payload = cJSON_DetachItemFromObject(retjson,"wallet");
        if ( payload == 0 )
            payload = cJSON_CreateObject();
        if ( waddr != 0 )
        {
            if ( (accountobj= jobj(payload,account)) != 0 && (obj= jobj(accountobj,waddr->coinaddr)) != 0 )
            {
                free_json(retjson);
                free_json(payload);
                return(0);
            }
            if ( accountobj == 0 )
            {
                accountobj = cJSON_CreateObject();
                jaddbits256(accountobj,waddr->coinaddr,waddr->privkey);
                jadd(payload,account,accountobj);
            } else jaddbits256(accountobj,waddr->coinaddr,waddr->privkey);
        }
        jadd(retjson,"wallet",payload);
        newstr = jprint(retjson,1);
        retval = iguana_loginsave(myinfo,coin,newstr);
        //printf("newstr.(%s) retval.%d\n",newstr,retval);
        free(newstr);
    } else printf("iguana_payloadupdate: error parsing.(%s)\n",retstr);
    return(retval);
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
            {
                if ( strlen(field) == 20*2 )
                    jaddstr(retjson,field,jstr(item,0));
                else jaddbits256(retjson,field,jbits256(item,0));
            }
        }
        item = item->next;
    }
    return(retjson);
}

cJSON *iguana_walletadd(struct supernet_info *myinfo,struct iguana_waddress **waddrp,struct iguana_info *coin,char *retstr,char *account,struct iguana_waddress *refwaddr,int32_t setcurrent,char *redeemScript)
{
    cJSON *retjson=0; struct iguana_waccount *wacct; struct iguana_waddress *waddr;
    if ( (wacct= iguana_waccountfind(myinfo,coin,account)) == 0 )
        wacct = iguana_waccountcreate(myinfo,coin,account);
    if ( wacct != 0 )
    {
        //waddr = iguana_waddressfind(myinfo,coin,wacct,refwaddr->coinaddr);
        waddr = iguana_waddressadd(myinfo,coin,wacct,refwaddr,redeemScript);
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
    if ( waddrp != 0 )
        (*waddrp) = waddr;
    return(retjson);
}

cJSON *iguana_walletjson(struct supernet_info *myinfo)
{
    struct iguana_waccount *wacct,*tmp; struct iguana_waddress *waddr,*tmp2; cJSON *wallet,*account; char scriptstr[4096];
    wallet = cJSON_CreateObject();
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        account = cJSON_CreateObject();
        HASH_ITER(hh,wacct->waddr,waddr,tmp2)
        {
            if ( bits256_nonz(waddr->privkey) == 0 && waddr->scriptlen == 0 )
            {
                free_json(account);
                free_json(wallet);
                printf("found a null privkey in wallet, abort saving\n");
                return(0);
            }
            if ( waddr->scriptlen != 0 )
            {
                init_hexbytes_noT(scriptstr,waddr->redeemScript,waddr->scriptlen);
                jaddstr(account,waddr->coinaddr,scriptstr);
            } else jaddbits256(account,waddr->coinaddr,waddr->privkey);
        }
        jadd(wallet,wacct->account,account);
    }
    return(wallet);
}

int32_t iguana_walletemit(struct supernet_info *myinfo,char *fname,struct iguana_info *coin,cJSON *array)
{
    cJSON *item,*child; uint8_t addrtype,wiftype,rmd160[20]; char p2shaddr[128],str[64],wifstr[128],*account,*coinaddr,*privkeystr; int32_t i,j,n; FILE *fp; bits256 privkey;
    if ( (fp= fopen(fname,"wb")) == 0 )
        return(-1);
    n = cJSON_GetArraySize(array);
    item = array->child;
    for (i=0; i<n; i++)
    {
        if ( item != 0 && (account= item->string) != 0 )
        {
            child = item->child;
            while ( child != 0 )
            {
                coinaddr = child->string;
                privkeystr = child->valuestring;
                if ( coinaddr != 0 && privkeystr != 0 )
                {
                    bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
                    wiftype = 188;
                    for (j=0; j<IGUANA_MAXCOINS; j++)
                    {
                        if ( (coin= Coins[j]) != 0 && coin->chain != 0 )
                        {
                            if ( addrtype == coin->chain->pubtype )
                            {
                                wiftype = coin->chain->wiftype;
                                privkey = bits256_conv(privkeystr);
                                if ( bits256_nonz(privkey) != 0 && bitcoin_priv2wif(wifstr,privkey,wiftype) > 0 )
                                {
                                    fprintf(fp,"%s %s %32s=%d # addr=%s\n",wifstr,utc_str(str,(uint32_t)time(NULL)),account,i+1,coinaddr);
                                }
                                break;
                            }
                            else if ( addrtype == coin->chain->p2shtype )
                            {
                                fprintf(fp,"%s %s %32s=%d # addr=%s # p2sh\n",privkeystr,utc_str(str,(uint32_t)time(NULL)),account,i+1,p2shaddr);
                                break;
                            }
                        }
                    }
                }
                child = child->next;
            }
            //printf("account.(%s)\n",account);
        }
        item = item->next;
    }
    fclose(fp);
    return(0);
}

char *walleterrstr[] = { "P2SH_withpriv", "P2SH_withpub", "rmd160_mismatch", "pubkey_mismatch", "missing_pubkey", "account_mismatch" };
uint8_t iguana_waddrvalidate(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,struct iguana_waddress *waddr,int32_t repairflag,int32_t *errors)
{
    struct iguana_waccount *checkwacct; struct iguana_waddress *checkwaddr; uint8_t checkpub[33],rmd160[20],addrtype,checktype,plen,flag=0;
    if ( waddr != 0 )
    {
        if ( (checkwaddr= iguana_waddresssearch(myinfo,coin,&checkwacct,waddr->coinaddr)) != waddr || checkwacct != wacct )
        {
            errors[5]++;
            flag |= (5 << 0);
            if ( repairflag > 0 )
            {
                printf("waddrvalidate: need to manually setaccount to fix mismatch (%s:%s) <- (%s:%s)\n",checkwacct != 0 ? checkwacct->account : "",checkwaddr != 0 ? checkwaddr->coinaddr : "",wacct != 0 ? wacct->account : "",waddr->coinaddr);
            }
        }
        if ( waddr->scriptlen > 0 )
        {
            checktype = coin->chain->p2shtype;
            if ( bits256_nonz(waddr->privkey) != 0 )
            {
                errors[0]++;
                flag |= (1 << 0);
                if ( repairflag > 0 )
                    memset(&waddr->privkey,0,sizeof(waddr->privkey));
            }
            if ( bitcoin_pubkeylen(waddr->pubkey) > 0 )
            {
                errors[1]++;
                flag |= (1 << 1);
                if ( repairflag > 0 )
                    memset(waddr->pubkey,0,sizeof(waddr->pubkey));
            }
        }
        else checktype = coin->chain->pubtype;
        if ( bitcoin_addr2rmd160(&addrtype,rmd160,waddr->coinaddr) != sizeof(rmd160) || addrtype != checktype || memcmp(rmd160,waddr->rmd160,sizeof(rmd160)) != 0 )
        {
            errors[2]++;
            flag |= (1 << 2);
            if ( repairflag > 0 )
            {
                waddr->addrtype = checktype;
                memcpy(waddr->rmd160,rmd160,sizeof(rmd160));
            }
        }
        if ( waddr->scriptlen == 0 )
        {
            if ( bits256_nonz(waddr->privkey) != 0 )
            {
                bitcoin_pubkey33(myinfo->ctx,checkpub,waddr->privkey);
                if ( memcmp(checkpub,waddr->pubkey,sizeof(checkpub)) != 0 )
                {
                    errors[3]++;
                    flag |= (1 << 3);
                    if ( repairflag > 0 )
                        memcpy(waddr->pubkey,checkpub,sizeof(checkpub));
                }
            }
            if ( (plen= bitcoin_pubkeylen(waddr->pubkey)) > 0 )
            {
                calc_rmd160_sha256(rmd160,waddr->pubkey,plen);
                if ( memcmp(rmd160,waddr->rmd160,sizeof(rmd160)) != 0 )
                {
                    errors[4]++;
                    flag |= (1 << 4);
                    if ( repairflag > 0 )
                    {
                        printf("waddrvalidate unrecoverable error: cant determine pubkey from rmd160\n");
                    }
                }
            }
        }
    }
    return(flag);
}

cJSON *iguana_walletiterate(struct supernet_info *myinfo,struct iguana_info *coin,int32_t flag,cJSON *array,int32_t *goodp,int32_t *badp,int32_t *errors)
{
    struct iguana_waccount *wacct,*tmp; struct iguana_waddress *waddr=0,*tmp2; uint8_t errorflags; int32_t i,good=0,bad=0,_errors[8]; cJSON *item;
    if ( errors == 0 )
        errors = _errors;
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        HASH_ITER(hh,wacct->waddr,waddr,tmp2)
        {
            if ( flag < 0 )
            {
                memset(&waddr->privkey,0,sizeof(waddr->privkey));
                memset(waddr->wifstr,0,sizeof(waddr->wifstr));
                for (i=0; i<sizeof(waddr->privkey); i++)
                    waddr->privkey.bytes[i] = rand();
                for (i=0; i<sizeof(waddr->wifstr); i++)
                    waddr->wifstr[i] = rand();
                if ( flag < -1 )
                {
                    HASH_DELETE(hh,wacct->waddr,waddr);
                    if ( waddr->unspents != 0 )
                        free(waddr->unspents);
                    printf("%p free %s\n",waddr,waddr->coinaddr);
                    myfree(waddr,sizeof(*waddr) + waddr->scriptlen);
                }
            }
            else
            {
                wacct->current = waddr;
                if ( (errorflags= iguana_waddrvalidate(myinfo,coin,wacct,waddr,flag,errors)) != 0 )
                {
                    bad++;
                    if ( array != 0 && (item= cJSON_CreateObject()) != 0 )
                    {
                        jaddnum(item,waddr->coinaddr,errorflags);
                        jaddi(array,item);
                    }
                } else good++;
            }
        }
        if ( flag < -1 )
        {
            HASH_DELETE(hh,myinfo->wallet,wacct);
            myfree(wacct,sizeof(*wacct));
        }
    }
    if ( goodp != 0 )
        *goodp = good;
    if ( badp != 0 )
        *badp = bad;
    return(array);
}

char *iguana_walletscan(struct supernet_info *myinfo,struct iguana_info *coin,int32_t repairflag)
{
    cJSON *retjson; int32_t i,good,bad,errors[8];
    memset(errors,0,sizeof(errors));
    good = bad = 0;
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",iguana_walletiterate(myinfo,coin,repairflag,cJSON_CreateArray(),&good,&bad,errors));
    jaddnum(retjson,"good",good);
    jaddnum(retjson,"bad",bad);
    for (i=0; i<sizeof(errors)/sizeof(errors); i++)
    {
        if ( errors[i] != 0 )
            jaddnum(retjson,walleterrstr[i],errors[i]);
    }
    return(jprint(retjson,1));
}

void iguana_walletinitcheck(struct supernet_info *myinfo,struct iguana_info *coin)
{
    // "wallet":{"test":{"R9S7zZzzvgb4CkiBH1i7gnFcwJuL1MYbxN":"18ab9c89ce83929db720cf26b663bf762532276146cd9d3e1f89086fcdf00053"}}
    cJSON *payload,*item,*array,*child; char *account,*coinaddr,*privkeystr; int32_t i,j,n,len; struct iguana_waccount *wacct,*tmp; struct iguana_waddress waddr; bits256 privkey; uint8_t addrtype,rmd160[20];
    if ( myinfo->wallet == 0 && myinfo->decryptstr != 0 && (payload= cJSON_Parse(myinfo->decryptstr)) != 0 )
    {
        if ( (array= jobj(payload,"wallet")) != 0 )
        {
            n = cJSON_GetArraySize(array);
            //printf("item.(%s) size.%d\n",jprint(array,0),n);
            item = array->child;
            for (i=0; i<n; i++)
            {
                if ( item != 0 && (account= item->string) != 0 )
                {
                    child = item->child;
                    while ( child != 0 )
                    {
                        coinaddr = child->string;
                        privkeystr = child->valuestring;
                        if ( coinaddr != 0 && privkeystr != 0 )
                        {
                            if ( (wacct= iguana_waccountcreate(myinfo,coin,account)) != 0 )
                            {
                                if ( iguana_waddresssearch(myinfo,coin,&tmp,coinaddr) == 0 )
                                {
                                    memset(&waddr,0,sizeof(waddr));
                                    strcpy(waddr.coinaddr,coinaddr);
                                    waddr.addrtype = coin->chain->p2shtype;
                                    if ( bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr) == sizeof(rmd160) && addrtype == coin->chain->p2shtype )
                                        iguana_waddressadd(myinfo,coin,wacct,&waddr,privkeystr);
                                    else
                                    {
                                        waddr.addrtype = coin->chain->pubtype;
                                        privkey = bits256_conv(privkeystr);
                                        if ( iguana_waddresscalc(myinfo,coin->chain->pubtype,coin->chain->wiftype,&waddr,privkey) != 0 )
                                            iguana_waddressadd(myinfo,coin,wacct,&waddr,0);
                                    }
                                } else printf("dup.(%s) ",coinaddr);
                                len = (int32_t)strlen(privkeystr);
                                for (j=0; j<len; j++)
                                    privkeystr[j] = 0;
                                for (j=0; j<len; j++)
                                    privkeystr[j] = 0x20 + (rand() % 64);
                                privkey = rand256(0);
                            }
                        }
                        child = child->next;
                    }
                    printf("account.(%s)\n",account);
                }
                item = item->next;
            }
        }
        free_json(payload);
        myinfo->decryptstr = 0;
        scrubfree(myinfo->decryptstr);
        myinfo->dirty = 0;
    }
    iguana_walletiterate(myinfo,coin,1,0,0,0,0);
}

void iguana_walletlock(struct supernet_info *myinfo,struct iguana_info *coin)
{
    memset(&myinfo->persistent_priv,0,sizeof(myinfo->persistent_priv));
    memset(myinfo->secret,0,sizeof(myinfo->secret));
    memset(myinfo->permanentfile,0,sizeof(myinfo->permanentfile));
    if ( myinfo->decryptstr != 0 )
        scrubfree(myinfo->decryptstr), myinfo->decryptstr = 0;
    myinfo->expiration = 0;
    iguana_walletiterate(myinfo,coin,-2,0,0,0,0);
}

int64_t iguana_waccountbalance(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,int32_t minconf,int32_t lastheight)
{
    int64_t balance; int32_t numrmds=0,numunspents = 0; uint8_t *rmdarray=0;
    if ( minconf == 0 )
        minconf = 1;
    rmdarray = iguana_rmdarray(coin,&numrmds,getaddressesbyaccount(myinfo,coin,wacct->account),0);
    balance = iguana_unspents(myinfo,coin,0,minconf,(1 << 30),rmdarray,numrmds,lastheight,0,&numunspents);
    if ( rmdarray != 0 )
        free(rmdarray);
    return(balance);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

int64_t iguana_addressreceived(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *json,char *remoteaddr,cJSON *txids,cJSON *vouts,char *coinaddr,int32_t minconf)
{
    int64_t balance = 0; cJSON *unspentsjson,*balancejson,*item; int32_t i,n; char *balancestr;
    if ( (balancestr= iguana_balance(IGUANA_CALLARGS,coin->symbol,coinaddr,-1,minconf)) != 0 )
    {
        printf("balancestr.(%s) (%s)\n",balancestr,coinaddr);
        if ( (balancejson= cJSON_Parse(balancestr)) != 0 )
        {
            balance = jdouble(balancejson,"balance") * SATOSHIDEN;
            if ( (txids != 0 || vouts != 0) && (unspentsjson= jarray(&n,balancejson,"unspents")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(balancejson,i);
                    if ( txids != 0 )
                        jaddibits256(txids,jbits256(item,"txid"));
                    if ( vouts != 0 )
                        jaddinum(vouts,jint(item,"vout"));
                }
            }
            free_json(balancejson);
        }
        free(balancestr);
    }
    return(balance);
}


char *getnewaddress(struct supernet_info *myinfo,struct iguana_waddress **waddrp,struct iguana_info *coin,char *account,char *retstr)
{
    struct iguana_waddress addr; cJSON *retjson;
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    if ( retstr != 0 )
    {
        memset(&addr,0,sizeof(addr));
        if ( iguana_waddresscalc(myinfo,coin->chain->pubtype,coin->chain->wiftype,&addr,bitcoin_randkey(myinfo->ctx)) != 0 )
            retjson = iguana_walletadd(myinfo,waddrp,coin,retstr,account,&addr,1,0);
        else return(clonestr("{\"error\":\"couldnt calculate waddr\"}"));
    } else return(clonestr("{\"error\":\"no wallet data\"}"));
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,validateaddress,address)
{
    cJSON *retjson; int32_t i; uint8_t addrtype,rmd160[20],pubkey[65]; struct iguana_info *other; char str[256];
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( iguana_addressvalidate(coin,&addrtype,rmd160,address) < 0 )
        return(clonestr("{\"error\":\"invalid coin address\"}"));
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"addrtype",addrtype);
    init_hexbytes_noT(str+6,rmd160,sizeof(rmd160));
    jaddstr(retjson,"rmd160",str+6);
    memcpy(str,"76a914",6);
    strcat(str,"88ac");
    jaddstr(retjson,"scriptPubKey",str);
    jadd(retjson,"isscript",(addrtype == coin->chain->p2shtype) ? jtrue() : jfalse());
    if ( iguana_ismine(myinfo,coin,addrtype,pubkey,rmd160) > 0 )
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
        jaddnum(retjson,"kbfee",dstr(coin->txfee_perkb));
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
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    return(setaccount(myinfo,coin,0,account,address,0));
}

STRING_ARG(bitcoinrpc,getaccount,address)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(getaccount(myinfo,coin,address));
}

STRING_ARG(bitcoinrpc,getnewaddress,account)
{
    char *retstr,*newretstr; struct iguana_waddress *waddr;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    if ( (retstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,0)) != 0 )
    {
        free(retstr);
        retstr = myinfo->decryptstr, myinfo->decryptstr = 0;
        newretstr = getnewaddress(myinfo,&waddr,coin,account,retstr);
        if ( retstr != 0 )
            scrubfree(retstr);
        return(newretstr);
    }
    else return(clonestr("{\"error\":\"no wallet payload\"}"));
}

STRING_ARG(bitcoinrpc,getaccountaddress,account)
{
    char *retstr,*newstr; struct iguana_waccount *wacct; struct iguana_waddress *waddr=0; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    if ( account != 0 && account[0] != 0 )
    {
        if ( (wacct= iguana_waccountfind(myinfo,coin,account)) == 0 )
            wacct = iguana_waccountcreate(myinfo,coin,account);
        if ( wacct != 0 )
        {
            if ( (waddr= wacct->current) == 0 )
            {
                if ( (retstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,0)) != 0 )
                {
                    free(retstr);
                    retstr = myinfo->decryptstr, myinfo->decryptstr = 0;
                    printf("loginstr.(%s)\n",retstr);
                    newstr = getnewaddress(myinfo,&waddr,coin,account,retstr);
                    if ( retstr != 0 )
                        scrubfree(retstr);
                    retstr = newstr;
                } else return(clonestr("{\"error\":\"no wallet payload\"}"));
            }
            if ( waddr != 0 )
                retjson = iguana_waddressjson(0,waddr);
            else return(clonestr("{\"error\":\"couldnt create address\"}"));
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
    iguana_walletlock(myinfo,coin);
    return(jsuccess());
}

TWOSTRINGS_AND_INT(bitcoinrpc,walletpassphrase,password,permanentfile,timeout)
{
    char *retstr;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( timeout <= 0 )
        return(clonestr("{\"error\":\"timeout must be positive\"}"));
    myinfo->expiration = (uint32_t)time(NULL) + timeout;
    retstr = SuperNET_login(IGUANA_CALLARGS,myinfo->handle,password,permanentfile,0);
    iguana_walletinitcheck(myinfo,coin);
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
    //iguana_walletlock(myinfo);
    return(retstr);
}

FOUR_STRINGS(bitcoinrpc,walletpassphrasechange,oldpassword,newpassword,oldpermanentfile,newpermanentfile)
{
    char destfname[1024],*tmpstr,*loginstr,*passphrase,*retstr = 0; cJSON *tmpjson,*loginjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( (tmpstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,oldpassword,oldpermanentfile,0)) != 0 )
    {
        free(tmpstr);
        tmpstr = myinfo->decryptstr, myinfo->decryptstr = 0;
        if ( (tmpjson= cJSON_Parse(tmpstr)) != 0 )
        {
            if ( (loginstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,newpassword,newpermanentfile,0)) != 0 )
            {
                if ( myinfo->decryptstr != 0 && (loginjson= cJSON_Parse(myinfo->decryptstr)) != 0 )
                {
                    if ( (passphrase= jstr(loginjson,"passphrase")) != 0 )
                    {
                        _SuperNET_encryptjson(destfname,passphrase,0,newpermanentfile,0,loginjson);
                        //iguana_walletlock(myinfo);
                        retstr = SuperNET_login(IGUANA_CALLARGS,myinfo->handle,newpassword,newpermanentfile,0);
                    }
                    free_json(loginjson);
                }
                free(loginstr);
            }
            free_json(tmpjson);
        }
        if ( tmpstr != 0 )
            scrubfree(tmpstr);
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"error changing walletpassphrase\"}");
    return(retstr);
}

TWOSTRINGS_AND_INT(bitcoinrpc,importprivkey,wif,account,rescan)
{
    bits256 privkey; char *retstr,*str; cJSON *retjson; struct iguana_waddress addr,*waddr; struct iguana_waccount *wacct = 0; uint8_t type,redeemScript[4096]; int32_t len; struct vin_info V; bits256 debugtxid;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    if ( account == 0 || account[0] == 0 )
        account = "default";
    len = (int32_t)strlen(wif);
    if ( is_hexstr(wif,len) > 0 )
    {
        len >>= 1;
        decode_hex(redeemScript,len,wif);
        if ( (type= iguana_calcrmd160(coin,0,&V,redeemScript,len,debugtxid,-1,0xffffffff)) == IGUANA_SCRIPT_P2SH || type == IGUANA_SCRIPT_1of1 || V.N > 1 )
        {
            if ( (str= setaccount(myinfo,coin,&waddr,account,V.coinaddr,wif)) != 0 )
                free(str);
            retjson = iguana_p2shjson(myinfo,coin,0,waddr);
            return(jprint(retjson,1));
        }
    }
    privkey = iguana_str2priv(myinfo,coin,wif);
    if ( bits256_nonz(privkey) == 0 )
        return(clonestr("{\"error\":\"illegal privkey\"}"));
    memset(&addr,0,sizeof(addr));
    if ( iguana_waddresscalc(myinfo,coin->chain->pubtype,coin->chain->wiftype,&addr,privkey) != 0 )
    {
        if ( (waddr= iguana_waddresssearch(myinfo,coin,&wacct,addr.coinaddr)) != 0 )
        {
            waddr = iguana_waccountswitch(myinfo,coin,account,addr.coinaddr,0);
            return(clonestr("{\"result\":\"privkey already in wallet\"}"));
        }
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        myinfo->expiration++;
        if ( (retstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,0)) != 0 )
        {
            free(retstr);
            retstr = myinfo->decryptstr, myinfo->decryptstr = 0;
            if ( waddr == 0 )
                waddr = &addr;
            iguana_waddresscalc(myinfo,coin->chain->pubtype,coin->chain->wiftype,waddr,privkey);
            retjson = iguana_walletadd(myinfo,0,coin,retstr,account,waddr,0,0);
            if ( retstr != 0 )
                scrubfree(retstr);
            return(jprint(retjson,1));
        }
    }
    return(clonestr("{\"error\":\"cant calculate waddress\"}"));
}

STRING_ARG(bitcoinrpc,dumpprivkey,address)
{
    cJSON *retjson; int32_t len,p2shflag=0; struct iguana_waddress *waddr; struct iguana_waccount *wacct; uint8_t addrtype,type,redeemScript[IGUANA_MAXSCRIPTSIZE],rmd160[20]; char *coinaddr; struct vin_info V; bits256 debugtxid;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    len = (int32_t)strlen(address);
    coinaddr = address;
    if ( is_hexstr(address,len) > 0 )
    {
        len >>= 1;
        decode_hex(redeemScript,len,address);
        if ( (type= iguana_calcrmd160(coin,0,&V,redeemScript,len,debugtxid,-1,0xffffffff)) == IGUANA_SCRIPT_P2SH || type == IGUANA_SCRIPT_1of1 || V.N > 1 )
        {
            p2shflag = 1;
            coinaddr = V.coinaddr;
        }
    }
    if ( strlen(coinaddr) > sizeof(V.coinaddr) || iguana_addressvalidate(coin,&addrtype,rmd160,coinaddr) < 0 )
        return(clonestr(p2shflag == 0 ? "{\"error\":\"invalid address\"}" : "{\"error\":\"invalid P2SH address\"}"));
    if ( (waddr= iguana_waddresssearch(myinfo,coin,&wacct,coinaddr)) != 0 )
    {
        if ( (waddr->wifstr[0] != 0 || waddr->scriptlen > 0) )
        {
            retjson = cJSON_CreateObject();
            if ( waddr->scriptlen == 0 && waddr->wifstr[0] != 0 )
                jaddstr(retjson,"result",waddr->wifstr);
            else iguana_p2shjson(myinfo,coin,retjson,waddr);
            return(jprint(retjson,1));
        } else return(clonestr("{\"error\":\"no privkey for address\"}"));
    } else return(clonestr("{\"error\":\"couldnt find address in wallet\"}"));
}

STRING_ARG(bitcoinrpc,dumpwallet,filename)
{
    char *retstr,*walletstr; cJSON *retjson,*walletobj,*strobj;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration != 0 )
    {
        myinfo->expiration++;
        if ( (retstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,0)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( (walletstr= myinfo->decryptstr) != 0 )
                {
                    myinfo->decryptstr = 0;
                    if ( (strobj= cJSON_Parse(walletstr)) != 0 )
                    {
                        if ( (walletobj= jobj(strobj,"wallet")) != 0 )
                            jadd(retjson,"wallet",jduplicate(walletobj));
                        if ( 0 && (walletobj= iguana_walletjson(myinfo)) != 0 )
                            jadd(retjson,"memory",walletobj);
                        free_json(strobj);
                    }
                    scrubfree(walletstr);
                }
                return(jprint(retjson,1));
            } else printf("cant parse retstr.(%s)\n",retstr);
        } else return(clonestr("{\"error\":\"couldnt decrypt wallet\"}"));
    }
    return(clonestr("{\"error\":\"wallet is locked, cant backup\"}"));
}

STRING_ARG(bitcoinrpc,backupwallet,filename)
{
    char *loginstr,*retstr = 0; cJSON *retjson,*payload;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration != 0 )
    {
        myinfo->expiration++;
        if ( (loginstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,0)) != 0 )
        {
            retstr = clonestr("{\"error\":\"couldnt backup wallet\"}");
            free(loginstr);
            loginstr = myinfo->decryptstr, myinfo->decryptstr = 0;
            if ( (retjson= cJSON_Parse(loginstr)) != 0 )
            {
                if ( (payload= jobj(retjson,"wallet")) != 0 && iguana_walletemit(myinfo,filename,coin,payload) == 0 )
                    retstr = clonestr("{\"result\":\"wallet backup saved\"}");
                free_json(retjson);
            }
            if ( loginstr != 0 )
                scrubfree(loginstr);
            return(retstr);
        } else return(clonestr("{\"error\":\"no wallet payload\"}"));
    } else return(clonestr("{\"error\":\"need to unlock wallet\"}"));
}

STRING_ARG(bitcoinrpc,importwallet,filename)
{
    cJSON *retjson = 0,*importjson,*loginjson = 0; long filesize; char *importstr,*loginstr;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration != 0 )
    {
        myinfo->expiration++;
        if ( (importstr= OS_filestr(&filesize,filename)) != 0 )
        {
            if ( (importjson= cJSON_Parse(importstr)) != 0 )
            {
                if ( (loginstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,0)) != 0 )
                {
                    free(loginstr);
                    loginstr = myinfo->decryptstr, myinfo->decryptstr = 0;
                    loginjson = cJSON_Parse(loginstr);
                    if ( loginstr != 0 )
                        scrubfree(loginstr);
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

ZERO_ARGS(bitcoinrpc,checkwallet)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    return(iguana_walletscan(myinfo,coin,1));
}

ZERO_ARGS(bitcoinrpc,repairwallet)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    return(iguana_walletscan(myinfo,coin,0));
}

// multiple address
STRING_AND_THREEINTS(bitcoinrpc,getbalance,account,minconf,includeempty,lastheight)
{
    int64_t balance; int32_t numunspents,numrmds=0; uint8_t *rmdarray=0; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( account == 0 )
        account = "";
    if ( minconf == 0 )
        minconf = 1;
    if ( strcmp(account,"*") != 0 )
        rmdarray = iguana_rmdarray(coin,&numrmds,getaddressesbyaccount(myinfo,coin,account),0);
    numunspents = 0;
    balance = iguana_unspents(myinfo,coin,0,minconf,(1 << 30),rmdarray,numrmds,lastheight,0,&numunspents);
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

STRING_AND_INT(bitcoinrpc,getreceivedbyaccount,account,minconf)
{
    cJSON *retjson; struct iguana_waccount *wacct; int64_t balance;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    if ( (wacct= iguana_waccountfind(myinfo,coin,account)) != 0 )
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
    if ( (wacct= iguana_waccountfind(myinfo,coin,account)) != 0 )
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
                        iguana_addressreceived(myinfo,coin,0,remoteaddr,txids,vouts,coinaddr,1);
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
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
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
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        HASH_ITER(hh,wacct->waddr,waddr,tmp2)
        {
            item = cJSON_CreateObject();
            jaddstr(item,"address",waddr->coinaddr);
            txids = cJSON_CreateArray();
            vouts = cJSON_CreateArray();
            jaddnum(item,"amount",dstr(iguana_addressreceived(myinfo,coin,0,remoteaddr,txids,vouts,waddr->coinaddr,minconf)));
            jadd(item,"txids",txids);
            jadd(item,"vouts",vouts);
            jaddi(array,item);
        }
    }
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

STRING_AND_INT(bitcoinrpc,getreceivedbyaddress,address,minconf)
{
    char *balancestr; cJSON *balancejson,*retjson = cJSON_CreateObject();
    if ( (balancestr= iguana_balance(IGUANA_CALLARGS,coin->symbol,address,-1,minconf)) != 0 )
    {
        if ( (balancejson= cJSON_Parse(balancestr)) != 0 )
        {
            jaddnum(retjson,"result",dstr(jdouble(balancejson,"balance")));
            free_json(balancejson);
        }
    }
    if ( jobj(retjson,"result") == 0 )
        jaddstr(retjson,"error","couldnt get received by address");
    return(jprint(retjson,1));
}

TWO_INTS(bitcoinrpc,listaccounts,minconf,includewatchonly)
{
    cJSON *retjson,*array; int64_t balance; struct iguana_waccount *wacct,*tmp;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    array = cJSON_CreateObject();
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        balance = iguana_waccountbalance(myinfo,coin,wacct,minconf,0);
        jaddnum(array,wacct->account,dstr(balance));
    }
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

#include "../includes/iguana_apiundefs.h"

