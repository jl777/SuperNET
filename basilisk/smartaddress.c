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
    char coinaddr[64],*symbol; int32_t j,n; struct iguana_info *coin; cJSON *item = cJSON_CreateObject();
    bitcoin_address(coinaddr,60,ap->pubkey33,33);
    jaddstr(item,"KMD",coinaddr);
    bitcoin_address(coinaddr,0,ap->pubkey33,33);
    jaddstr(item,"BTC",coinaddr);
    if ( ap->typejson != 0 )
    {
        jadd(item,"type",ap->typejson);
        if ( (n= cJSON_GetArraySize(ap->typejson)) > 1 )
        {
            for (j=1; j<n; j++)
            {
                if ( (symbol= jstri(ap->typejson,j)) != 0 )
                {
                    if ( strcmp(symbol,"KMD") != 0 && strcmp(symbol,"BTC") != 0 )
                    {
                        if ( (coin= iguana_coinfind(symbol)) != 0 )
                        {
                            bitcoin_address(coinaddr,coin->chain->pubtype,ap->pubkey33,33);
                            jaddstr(item,symbol,coinaddr);
                        }
                    }
                }
            }
        }
    }
    return(item);
}

int32_t smartaddress_add(struct supernet_info *myinfo,bits256 privkey,char *symbol)
{
    char coinaddr[64]; uint8_t addrtype,rmd160[20]; struct smartaddress *ap; int32_t i,j,n;
    if ( myinfo->numsmartaddrs < sizeof(myinfo->smartaddrs)/sizeof(*myinfo->smartaddrs) )
    {
        for (i=0; i<myinfo->numsmartaddrs; i++)
            if ( bits256_cmp(myinfo->smartaddrs[i].privkey,privkey) == 0 )
            {
                ap = &myinfo->smartaddrs[i];
                if ( ap->typejson == 0 )
                    return(-1);
                else
                {
                    n = cJSON_GetArraySize(ap->typejson);
                    for (j=0; j<n; j++)
                    {
                        if ( strcmp(jstri(ap->typejson,j),symbol) == 0 )
                            return(0);
                    }
                }
                jaddistr(ap->typejson,symbol);
                return(i+1);
             }
        ap = &myinfo->smartaddrs[myinfo->numsmartaddrs];
        ap->typejson = cJSON_CreateArray();
        if ( smartaddress_type(symbol) < 0 )
            return(-1);
        jaddistr(ap->typejson,symbol);
        jaddistr(ap->typejson,"KMD");
        jaddistr(ap->typejson,"BTC");
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

int32_t smartaddress_symbolmatch(struct smartaddress *ap,char *symbol)
{
    int32_t j,n;
    if ( ap->typejson != 0 && (n= cJSON_GetArraySize(ap->typejson)) > 0 )
    {
        for (j=0; j<n; j++)
        {
            if ( strcmp(jstri(ap->typejson,j),symbol) == 0 )
                return(j);
        }
    }
    return(-1);
}

int32_t smartaddress(struct supernet_info *myinfo,bits256 *privkeyp,char *symbol,char *coinaddr)
{
    int32_t i,j; uint8_t addrtype,rmd160[20]; struct smartaddress *ap;
    memset(privkeyp,0,sizeof(*privkeyp));
    bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
    for (i=0; i<myinfo->numsmartaddrs; i++)
        if ( memcmp(myinfo->smartaddrs[i].rmd160,rmd160,20) == 0 )
        {
            ap = &myinfo->smartaddrs[i];
            *privkeyp = ap->privkey;
            if ( (j= smartaddress_symbolmatch(ap,symbol)) >= 0 )
                return(0);
            return(i+1);
        }
    for (i=0; i<20; i++)
        printf("%02x",rmd160[i]);
    printf(" <- rmd160 smartaddress cant find (%s) of %d\n",coinaddr,myinfo->numsmartaddrs);
    return(-1);
}

int32_t smartaddress_pubkey(struct supernet_info *myinfo,bits256 *privkeyp,char *symbol,bits256 pubkey)
{
    int32_t i,j; struct smartaddress *ap;
    memset(privkeyp,0,sizeof(*privkeyp));
    for (i=0; i<myinfo->numsmartaddrs; i++)
        if ( bits256_cmp(myinfo->smartaddrs[i].pubkey,pubkey) == 0 )
        {
            ap = &myinfo->smartaddrs[i];
            *privkeyp = ap->privkey;
            if ( (j= smartaddress_symbolmatch(ap,symbol)) >= 0 )
                return(0);
            return(i+1);
        }
    return(-1);
}

int32_t smartaddress_pubkey33(struct supernet_info *myinfo,bits256 *privkeyp,char *symbol,uint8_t *pubkey33)
{
    int32_t i,j; struct smartaddress *ap;
    memset(privkeyp,0,sizeof(*privkeyp));
    for (i=0; i<myinfo->numsmartaddrs; i++)
        if ( memcmp(myinfo->smartaddrs[i].pubkey33,pubkey33,33) == 0 )
        {
            ap = &myinfo->smartaddrs[i];
            *privkeyp = ap->privkey;
            if ( (j= smartaddress_symbolmatch(ap,symbol)) >= 0 )
                return(0);
            return(i+1);
        }
    return(-1);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"
#include "../includes/iguana_apideclares2.h"

ZERO_ARGS(InstantDEX,smartaddresses)
{
    int32_t i; cJSON *retjson = cJSON_CreateArray();
    for (i=0; i<myinfo->numsmartaddrs; i++)
        jaddi(retjson,smartaddress_json(&myinfo->smartaddrs[i]));
    return(jprint(retjson,1));
}

TWO_STRINGS(InstantDEX,smartaddress,type,symbol)
{
    char prefix[64],coinaddr[64],KMDaddr[64]; uint8_t pubkey33[33]; bits256 privkey;
    if ( smartaddress_type(type) < 0 )
        return(clonestr("{\"error\":\"non-supported smartaddress type\"}"));
    if ( iguana_coinfind(symbol) == 0 )
        return(clonestr("{\"error\":\"non-supported smartaddress symbol\"}"));
    if ( strcmp(type,"deposit") == 0 || strcmp(type,"jumblr") == 0 )
    {
        if ( smartaddress_pubkey(myinfo,&privkey,symbol,strcmp(type,"deposit") == 0 ? myinfo->jumblr_depositkey : myinfo->jumblr_pubkey) < 0 )
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
    smartaddress_add(myinfo,privkey,symbol);
    return(InstantDEX_smartaddresses(myinfo,0,0,0));
}

#include "../includes/iguana_apiundefs.h"
