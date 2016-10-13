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

#ifndef INCLUDE_DPOW_H
#define INCLUDE_DPOW_H

#define DPOW_M(bp) (4)  // (((bp)->numnotaries >> 1) + 1)

#define DPOW_UTXOSIZE 10000

#define DPOW_FIFOSIZE 64
#define DPOW_MAXTX 8192
#define DPOW_THIRDPARTY_CONFIRMS 10
#define DPOW_KOMODOCONFIRMS 1
#define DPOW_BTCCONFIRMS 1
#define DPOW_MAXRELAYS 64
#define DPOW_CHECKPOINTFREQ 5

struct dpow_entry
{
    bits256 prev_hash,commit,beacon;
    uint64_t masks[DPOW_MAXRELAYS],bestmask;
    int32_t prev_vout,height;
    int8_t bestk;
    uint8_t pubkey[33],siglens[DPOW_MAXRELAYS],sigs[DPOW_MAXRELAYS][76];
};

struct dpow_sigentry
{
    bits256 beacon;
    uint64_t mask;
    int32_t refcount;
    uint8_t senderind,lastk,siglen,sig[80],senderpub[33];
};

struct komodo_notaries
{
    struct basilisk_relay RELAYS[DPOW_MAXRELAYS];
    int32_t NUMRELAYS,RELAYID;
};

struct dpow_hashheight { bits256 hash; int32_t height; };

struct dpow_checkpoint { struct dpow_hashheight blockhash,approved; bits256 miner; uint32_t blocktime,timestamp; };

struct dpow_block
{
    bits256 hashmsg,btctxid,signedtxid,beacon,commit;
    struct iguana_info *coin; char *opret_symbol;
    uint64_t recvmask,bestmask;
    struct dpow_entry notaries[DPOW_MAXRELAYS];
    uint32_t state,timestamp,waiting,sigcrcs[2],txidcrcs[2],utxocrcs[2];
    int32_t height,numnotaries,completed;
    int8_t bestk;
    char signedtx[32768];
};

struct dpow_info
{
    char symbol[16],dest[16]; uint8_t minerkey33[33],minerid;
    struct dpow_checkpoint checkpoint,last,destchaintip,srcfifo[DPOW_FIFOSIZE],destfifo[DPOW_FIFOSIZE];
    struct dpow_hashheight approved[DPOW_FIFOSIZE],notarized[DPOW_FIFOSIZE];
    bits256 srctx[DPOW_MAXTX],desttx[DPOW_MAXTX];
    uint32_t destupdated,srcconfirms,numdesttx,numsrctx,lastsplit;
    struct dpow_block **srcblocks,**destblocks;
};


#endif
