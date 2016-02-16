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

char *instantdex_PAXswap(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *ap,char *cmdstr,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen) // receiving side
{
    char *retstr = 0;
    return(clonestr("{\"error\":\"PAX swap is not yet\"}"));
    if ( strcmp(cmdstr,"offer") == 0 )
    {
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
    else retstr = clonestr("{\"error\":\"PAX swap got unrecognized command\"}");
    return(retstr);
}

#include "../../includes/secp256k1.h"
//#include "../../crypto777/secp256k1/modules/rangeproof/pedersen_impl.h"
//#include "../../crypto777/secp256k1/modules/rangeproof/borromean_impl.h"
//#include "../../crypto777/secp256k1/modules/rangeproof/rangeproof_impl.h"
void secp256k1_pedersen_context_initialize(secp256k1_context_t *ctx);
int secp256k1_pedersen_commit(const secp256k1_context_t* ctx, unsigned char *commit, unsigned char *blind, uint64_t value);
// ./configure --enable-module-ecdh --enable-module-schnorr --enable-module-rangeproof
void ztest()
{
#ifdef __APPLE__
    printf("ztests\n");
    secp256k1_context_t *ctx;  uint8_t commit[33],blind[32]; int32_t i,retval;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pedersen_context_initialize(ctx);
    retval = secp256k1_pedersen_commit(ctx,commit,blind,0x14234);
    OS_randombytes(blind,sizeof(blind));
    for (i=0; i<33; i++)
        printf("%02x",commit[i]);
    printf(" pederson commit.%d\n",retval);
    //getchar();
#endif
}