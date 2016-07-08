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

#ifndef iguana777_net_h
#define iguana777_net_h

struct supernet_info;
struct exchange_info;

#include "../crypto777/OS_portable.h"
#include "../datachain/datachain.h"

#include "../includes/iguana_defines.h"
#include "../includes/iguana_types.h"
#include "../includes/iguana_structs.h"
#include "../includes/iguana_funcs.h"
#include "../includes/iguana_globals.h"
#include "../basilisk/basilisk.h"
#include "../gecko/gecko.h"


struct supernet_address
{
    bits256 pubkey,iphash,persistent;
    uint32_t selfipbits,myipbits; int32_t confirmed,totalconfirmed; uint64_t nxt64bits;
    char NXTADDR[32],BTC[64],BTCD[64];
};

struct supernet_info
{
    struct supernet_address myaddr;
    bits256 persistent_priv,privkey;
    uint8_t persistent_pubkey33[33];
    char ipaddr[64],NXTAPIURL[512],secret[4096],rpcsymbol[64],handle[1024],permanentfile[1024];
    char *decryptstr;
    int32_t maxdelay,IAMRELAY,publicRPC,basilisk_busy,genesisresults;
    uint32_t expiration,dirty,DEXactive;
    uint16_t argport,rpcport;
    struct basilisk_info basilisks;
    struct exchange_info *tradingexchanges[SUPERNET_MAXEXCHANGES]; int32_t numexchanges;
    struct iguana_waccount *wallet;
    struct iguana_info *allcoins; int32_t allcoins_being_added,allcoins_numvirts;
    portable_mutex_t bu_mutex,allcoins_mutex,gecko_mutex,basilisk_mutex,DEX_mutex,DEX_reqmutex,DEX_swapmutex;
    struct queueitem *DEX_quotes;
    struct basilisk_swap *swaps[256]; int32_t numswaps;
    struct basilisk_message *messagetable; portable_mutex_t messagemutex; queue_t msgQ;
    void *ctx;
    uint8_t *pingbuf;
    struct delayedPoW_info dPoW;
    struct basilisk_relay relays[BASILISK_MAXRELAYS];
    int32_t numrelays,RELAYID;
    // compatibility
    bits256 pangea_category,instantdex_category;
};

#endif
