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

// BTCoffer:
// sends NXT assetid, volume and desired
// request:
// other node sends (othercoin, othercoinaddr, otherNXT and reftx that expires well before phasedtx)
// proposal:
// NXT node submits phasedtx that refers to it, but it wont confirm
// approve:
// other node verifies unconfirmed has phasedtx and broadcasts cltv, also to NXT node, releases trigger
// confirm:
// NXT node verifies bitcoin txbytes has proper payment and cashes in with onetimepubkey
// BTC* node approves phased tx with onetimepubkey
/*if ( retap != 0 )
{
    retap->A.pendingvolume -= volume;
    price = retap->A.price;
}
struct instantdex_accept *instantdex_acceptable(struct supernet_info *myinfo,cJSON *array,char *refstr,char *base,char *rel,char *offerside,int32_t offerdir,double offerprice,double volume)
*/

char *instantdex_BTCswap(struct supernet_info *myinfo,struct exchange_info *exchange,char *cmdstr,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen) // receiving side
{
    char *base,*rel,*offerside,*retstr = 0; int32_t offerdir = 0; struct instantdex_accept *ap; double offerprice,volume;
    if ( exchange == 0 )
        return(clonestr("{\"error\":\"instantdex_BTCswap null exchange ptr\"}"));
    if ( strcmp(cmdstr,"offer") == 0 )
    {
        base = jstr(argjson,"base"), rel = jstr(argjson,"rel");
        if ( rel == 0 || strcmp(rel,"BTC") != 0 )
            return(clonestr("{\"error\":\"instantdex_BTCswap offer non BTC rel\"}"));
        offerprice = jdouble(argjson,"price"), volume = jdouble(argjson,"volume");
        offerside = "BTC";
       // offerdir = xxx
       // printf("got offer.(%s) offerside.%s offerdir.%d\n",jprint(argjson,0),offerside,offerdir);
        if ( (ap= instantdex_acceptable(exchange,base,rel,offerside,offerdir,offerprice,volume)) != 0 )
        {
            
        }
    }
    else if ( strcmp(cmdstr,"proposal") == 0 )
    {
        
    }
    else if ( strcmp(cmdstr,"accept") == 0 )
    {
        
    }
    else if ( strcmp(cmdstr,"confirm") == 0 )
    {
        
    }
    else retstr = clonestr("{\"error\":\"BTC swap got unrecognized command\"}");
    return(retstr);
}
