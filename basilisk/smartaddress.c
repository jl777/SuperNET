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

// deposit address <coin> -> corresponding KMD address, if KMD deposit starts JUMBLR
// jumblr address <coin> is the destination of JUMBLR and JUMBLR BTC (would need tracking to map back to non-BTC)
// <symbol> address <coin> is DEX'ed for <SYMBOL>

// return value convention: -1 error, 0 partial match, >= 1 exact match

int32_t smartaddress_type(char *typestr)
{
    char upper[64];
    if ( strcmp(typestr,"deposit") != 0 && strcmp(typestr,"jumblr") != 0 )
    {
        upper[sizeof(upper)-1] = 0;
        strncpy(upper,typestr,sizeof(upper)-1);
        touppercase(upper);
        if ( iguana_coinfind(upper) != 0 )
            return(0);
    }
    return(-1);
}

bits256 jumblr_privkey(struct supernet_info *myinfo,char *coinaddr,uint8_t pubtype,char *KMDaddr,char *prefix)
{
    bits256 privkey,pubkey; uint8_t pubkey33[33]; char passphrase[sizeof(myinfo->jumblr_passphrase) + 64];
    sprintf(passphrase,"%s%s",prefix,myinfo->jumblr_passphrase);
    if ( myinfo->jumblr_passphrase[0] == 0 )
        strcpy(myinfo->jumblr_passphrase,"password");
    conv_NXTpassword(privkey.bytes,pubkey.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
    bitcoin_pubkey33(myinfo->ctx,pubkey33,privkey);
    bitcoin_address(coinaddr,pubtype,pubkey33,33);
    bitcoin_address(KMDaddr,60,pubkey33,33);
    //printf("(%s) -> (%s %s)\n",passphrase,coinaddr,KMDaddr);
    return(privkey);
}

cJSON *smartaddress_json(struct smartaddress *ap)
{
    char coinaddr[64]; int32_t j,n; struct iguana_info *coin; cJSON *array,*item,*retjson;
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"type",ap->typestr);
    bitcoin_address(coinaddr,60,ap->pubkey33,33);
    jaddstr(retjson,"KMD",coinaddr);
    bitcoin_address(coinaddr,0,ap->pubkey33,33);
    jaddstr(retjson,"BTC",coinaddr);
    if ( (n= ap->numsymbols) > 0 )
    {
        array = cJSON_CreateArray();
        for (j=0; j<n; j++)
        {
            if ( (coin= iguana_coinfind(ap->symbols[j].symbol)) != 0 )
            {
                bitcoin_address(coinaddr,coin->chain->pubtype,ap->pubkey33,33);
                item = cJSON_CreateObject();
                jaddstr(item,"coin",coin->symbol);
                jaddstr(item,"address",coinaddr);
                jaddnum(item,"maxbid",ap->symbols[j].maxbid);
                jaddnum(item,"minask",ap->symbols[j].minask);
                jaddi(array,item);
            }
        }
        jadd(retjson,"coins",array);
    }
    return(retjson);
}

void smartaddress_symboladd(struct smartaddress *ap,char *symbol,double maxbid,double minask)
{
    struct smartaddress_symbol *sp;
    ap->symbols = realloc(ap->symbols,(ap->numsymbols+1) * sizeof(*ap->symbols));
    sp = &ap->symbols[ap->numsymbols++];
    memset(sp,0,sizeof(*sp));
    safecopy(sp->symbol,symbol,sizeof(sp->symbol));
    sp->maxbid = maxbid;
    sp->minask = minask;
}

int32_t _smartaddress_add(struct supernet_info *myinfo,bits256 privkey,char *symbol,double maxbid,double minask)
{
    char coinaddr[64]; uint8_t addrtype,rmd160[20]; struct smartaddress *ap; int32_t i,j,n;
    if ( myinfo->numsmartaddrs < sizeof(myinfo->smartaddrs)/sizeof(*myinfo->smartaddrs) )
    {
        for (i=0; i<myinfo->numsmartaddrs; i++)
            if ( bits256_cmp(myinfo->smartaddrs[i].privkey,privkey) == 0 )
            {
                ap = &myinfo->smartaddrs[i];
                n = ap->numsymbols;
                for (j=0; j<n; j++)
                {
                    if ( strcmp(ap->symbols[j].symbol,symbol) == 0 )
                    {
                        ap->symbols[j].maxbid = maxbid;
                        ap->symbols[j].minask = minask;
                        return(0);
                    }
                }
                smartaddress_symboladd(ap,symbol,maxbid,minask);
                return(i+1);
             }
        ap = &myinfo->smartaddrs[myinfo->numsmartaddrs];
        smartaddress_symboladd(ap,"KMD",0.,0.);
        smartaddress_symboladd(ap,"BTC",0.,0.);
        if ( smartaddress_type(symbol) < 0 )
            return(-1);
        strcpy(ap->typestr,symbol);
        ap->privkey = privkey;
        bitcoin_pubkey33(myinfo->ctx,ap->pubkey33,privkey);
        calc_rmd160_sha256(ap->rmd160,ap->pubkey33,33);
        ap->pubkey = curve25519(privkey,curve25519_basepoint9());
        bitcoin_address(coinaddr,0,ap->pubkey33,33);
        for (i=0; i<20; i++)
            printf("%02x",ap->rmd160[i]);
        bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
        printf(", ");
        for (i=0; i<20; i++)
            printf("%02x",rmd160[i]);
        printf (" <- rmd160 for %d %s\n",myinfo->numsmartaddrs,coinaddr);
        return(++myinfo->numsmartaddrs + 1);
    }
    printf("too many smartaddresses %d vs %d\n",myinfo->numsmartaddrs,(int32_t)(sizeof(myinfo->smartaddrs)/sizeof(*myinfo->smartaddrs)));
    return(-1);
}

int32_t smartaddress_add(struct supernet_info *myinfo,bits256 privkey,char *symbol,double maxbid,double minask)
{
    int32_t retval;
    portable_mutex_lock(&myinfo->smart_mutex);
    retval = _smartaddress_add(myinfo,privkey,symbol,maxbid,minask);
    portable_mutex_unlock(&myinfo->smart_mutex);
    return(retval);
}

int32_t smartaddress_symbolmatch(char *typestr,double *bidaskp,struct smartaddress *ap,char *symbol)
{
    int32_t j,n;
    strcpy(typestr,ap->typestr);
    if ( (n= ap->numsymbols) > 0 )
    {
        for (j=0; j<n; j++)
        {
            if ( strcmp(ap->symbols[j].symbol,symbol) == 0 )
            {
                bidaskp[0] = ap->symbols[j].maxbid;
                bidaskp[1] = ap->symbols[j].minask;
                return(j);
            }
        }
    }
    return(-1);
}

int32_t smartaddress(struct supernet_info *myinfo,char *typestr,double *bidaskp,bits256 *privkeyp,char *symbol,char *coinaddr)
{
    int32_t i,j,retval = -1; uint8_t addrtype,rmd160[20]; struct smartaddress *ap;
    memset(privkeyp,0,sizeof(*privkeyp));
    memset(bidaskp,0,sizeof(*bidaskp) * 2);
    bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
    portable_mutex_lock(&myinfo->smart_mutex);
    for (i=0; i<myinfo->numsmartaddrs; i++)
        if ( memcmp(myinfo->smartaddrs[i].rmd160,rmd160,20) == 0 )
        {
            ap = &myinfo->smartaddrs[i];
            *privkeyp = ap->privkey;
            if ( (j= smartaddress_symbolmatch(typestr,bidaskp,ap,symbol)) >= 0 )
                retval = 0;
            else retval = (i+1);
            break;
        }
    portable_mutex_unlock(&myinfo->smart_mutex);
    for (i=0; i<20; i++)
        printf("%02x",rmd160[i]);
    printf(" <- rmd160 smartaddress cant find (%s) of %d\n",coinaddr,myinfo->numsmartaddrs);
    return(retval);
}

int32_t smartaddress_pubkey(struct supernet_info *myinfo,char *typestr,double *bidaskp,bits256 *privkeyp,char *symbol,bits256 pubkey)
{
    int32_t i,j,retval = -1; struct smartaddress *ap;
    memset(privkeyp,0,sizeof(*privkeyp));
    memset(bidaskp,0,sizeof(*bidaskp) * 2);
    portable_mutex_lock(&myinfo->smart_mutex);
    for (i=0; i<myinfo->numsmartaddrs; i++)
        if ( bits256_cmp(myinfo->smartaddrs[i].pubkey,pubkey) == 0 )
        {
            ap = &myinfo->smartaddrs[i];
            if ( (j= smartaddress_symbolmatch(typestr,bidaskp,ap,symbol)) >= 0 )
                retval = 0;
            else retval = (i+1);
            break;
        }
    portable_mutex_unlock(&myinfo->smart_mutex);
    return(retval);
}

int32_t smartaddress_pubkey33(struct supernet_info *myinfo,char *typestr,double *bidaskp,bits256 *privkeyp,char *symbol,uint8_t *pubkey33)
{
    int32_t i,j,retval = -1; struct smartaddress *ap;
    memset(privkeyp,0,sizeof(*privkeyp));
    memset(bidaskp,0,sizeof(*bidaskp) * 2);
    portable_mutex_lock(&myinfo->smart_mutex);
    for (i=0; i<myinfo->numsmartaddrs; i++)
        if ( memcmp(myinfo->smartaddrs[i].pubkey33,pubkey33,33) == 0 )
        {
            ap = &myinfo->smartaddrs[i];
            *privkeyp = ap->privkey;
            if ( (j= smartaddress_symbolmatch(typestr,bidaskp,ap,symbol)) >= 0 )
                retval = 0;
            else retval = (i+1);
            break;
        }
    portable_mutex_unlock(&myinfo->smart_mutex);
    return(retval);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"
#include "../includes/iguana_apideclares2.h"

ZERO_ARGS(InstantDEX,smartaddresses)
{
    int32_t i; cJSON *retjson = cJSON_CreateArray();
    portable_mutex_lock(&myinfo->smart_mutex);
    for (i=0; i<myinfo->numsmartaddrs; i++)
        jaddi(retjson,smartaddress_json(&myinfo->smartaddrs[i]));
    portable_mutex_unlock(&myinfo->smart_mutex);
    return(jprint(retjson,1));
}

TWO_STRINGS_AND_TWO_DOUBLES(InstantDEX,smartaddress,type,symbol,maxbid,minask)
{
    char prefix[64],coinaddr[64],KMDaddr[64],typestr[64]; double bidask[2]; uint8_t pubkey33[33]; bits256 privkey;
    if ( smartaddress_type(type) < 0 )
        return(clonestr("{\"error\":\"non-supported smartaddress type\"}"));
    if ( iguana_coinfind(symbol) == 0 )
        return(clonestr("{\"error\":\"non-supported smartaddress symbol\"}"));
    if ( strcmp(type,"deposit") == 0 || strcmp(type,"jumblr") == 0 )
    {
        if ( smartaddress_pubkey(myinfo,typestr,bidask,&privkey,symbol,strcmp(type,"deposit") == 0 ? myinfo->jumblr_depositkey : myinfo->jumblr_pubkey) < 0 )
            return(clonestr("{\"error\":\"unexpected missing smartaddress deposit/jumblr\"}"));
    }
    else
    {
        strcpy(prefix,type);
        tolowercase(prefix);
        if ( strcmp(prefix,"btc") == 0 || strcmp(prefix,"kmd") == 0 )
            return(clonestr("{\"success\":\"no need add BTC or KMD to smartaddress\"}"));
        strcat(prefix," ");
        privkey = jumblr_privkey(myinfo,coinaddr,0,KMDaddr,prefix);
    }
    if ( (coin= iguana_coinfind(symbol)) == 0 )
        return(clonestr("{\"error\":\"non-supported smartaddress symbol\"}"));
    bitcoin_pubkey33(myinfo->ctx,pubkey33,privkey);
    bitcoin_address(coinaddr,coin->chain->pubtype,pubkey33,33);
    smartaddress_add(myinfo,privkey,symbol,maxbid,minask);
    return(InstantDEX_smartaddresses(myinfo,0,0,0));
}

#include "../includes/iguana_apiundefs.h"
