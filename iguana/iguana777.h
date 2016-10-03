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

#if defined(_WIN32) || defined(_WIN64)
#define WIN32
#endif

#if (defined(_WIN32) || defined(__WIN32__)) && \
!defined(WIN32) && !defined(__SYMBIAN32__)
#define WIN32
#endif

#ifdef WIN32
#define __MINGW


#else
#ifndef __MINGW
#include <arpa/inet.h>
#endif
#endif

//#define BTC2_VERSION
#define BTC2_HARDFORK_HEIGHT 444444
#define BTC2_SIGHASH_FORKID 0xcf
#define BTC2_NETMAGIC 0xaabbccdd
#define BTC2_DEFAULT_PORT 8222
#define BTC2_DIFF_WINDOW 60

struct supernet_info;
struct exchange_info;

#include "../crypto777/OS_portable.h"
#include "../datachain/datachain.h"

#include "../includes/iguana_defines.h"
#include "../includes/iguana_types.h"
#include "../includes/iguana_structs.h"
#include "../basilisk/basilisk.h"

struct supernet_address
{
    bits256 pubkey,iphash,persistent;
    uint32_t selfipbits,myipbits; int32_t confirmed,totalconfirmed; uint64_t nxt64bits;
    char NXTADDR[32],BTC[64],BTCD[64];
};

struct liquidity_info { char base[64],rel[64]; double profit,refprice; };
struct message_info { int32_t msgcount; bits256 refhash,msghashes[64]; uint32_t timestamps[64]; };

struct komodo_notaries
{
    struct basilisk_relay RELAYS[BASILISK_MAXRELAYS];
    int32_t NUMRELAYS,RELAYID;
};

struct supernet_info
{
    struct supernet_address myaddr;
    bits256 persistent_priv,privkey;
    uint8_t persistent_pubkey33[33];
    char ipaddr[64],NXTAPIURL[512],secret[4096],password[4096],rpcsymbol[64],handle[1024],permanentfile[1024];
    char *decryptstr;
    int32_t maxdelay,IAMRELAY,IAMNOTARY,IAMLP,publicRPC,basilisk_busy,genesisresults,remoteorigin;
    uint32_t expiration,dirty,DEXactive,DEXpoll,totalcoins;
    uint16_t argport,rpcport;
    struct basilisk_info basilisks;
    struct exchange_info *tradingexchanges[SUPERNET_MAXEXCHANGES]; int32_t numexchanges;
    struct iguana_waccount *wallet;
    struct iguana_info *allcoins; int32_t allcoins_being_added,allcoins_numvirts;
    portable_mutex_t bu_mutex,allcoins_mutex,gecko_mutex,basilisk_mutex,DEX_mutex,DEX_reqmutex,DEX_swapmutex;
    struct queueitem *DEX_quotes; cJSON *Cunspents,*Cspends;
    struct basilisk_swap *swaps[256]; int32_t numswaps;
    struct basilisk_message *messagetable; portable_mutex_t messagemutex; queue_t msgQ,p2pQ;
    void *ctx;
    uint8_t *pingbuf;
    FILE *dexfp;
    struct delayedPoW_info dPoW;
    struct basilisk_spend *spends; int32_t numspends;
    struct peggy_info *PEGS;
    struct liquidity_info linfos[64];
    struct komodo_notaries NOTARY;
    // compatibility
    bits256 pangea_category,instantdex_category;
    uint8_t logs[256],exps[510];
    struct message_info msgids[8192];
};

#include "../includes/iguana_funcs.h"
#include "../includes/iguana_globals.h"
#include "../gecko/gecko.h"

#ifndef MAX
#define MAX(a,b) ((a) >= (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#endif
