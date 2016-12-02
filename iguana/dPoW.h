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

#define DPOW_FIRSTRATIFY 1000

#define DPOW_CHECKPOINTFREQ 10
#define DPOW_MINSIGS 13     //((height < 90000) ? 7 : 11)
//#define DPOW_M(bp) ((bp)->minsigs)  // (((bp)->numnotaries >> 1) + 1)
#define DPOW_MODIND(bp,offset) (((((bp)->height / DPOW_CHECKPOINTFREQ) % (bp)->numnotaries) + (offset)) % (bp)->numnotaries)
#define DPOW_VERSION 0x0770
#define DPOW_UTXOSIZE 10000
#define DPOW_MINOUTPUT 6000
#define DPOW_DURATION 300
#define DPOW_RATIFYDURATION (3600 * 24)

//#define DPOW_ENTRIESCHANNEL ('e' | ('n' << 8) | ('t' << 16) | ('r' << 24))
//#define DPOW_BTCENTRIESCHANNEL (~DPOW_ENTRIESCHANNEL)
//#define DPOW_UTXOCHANNEL ('d' | ('P' << 8) | ('o' << 16) | ('W' << 24))
#define DPOW_SIGCHANNEL ('s' | ('i' << 8) | ('g' << 16) | ('s' << 24))
#define DPOW_SIGBTCCHANNEL (~DPOW_SIGCHANNEL)
#define DPOW_TXIDCHANNEL ('t' | ('x' << 8) | ('i' << 16) | ('d' << 24))
#define DPOW_BTCTXIDCHANNEL (~DPOW_TXIDCHANNEL)


#define DPOW_FIFOSIZE 64
#define DPOW_MAXTX 8192
#define DPOW_THIRDPARTY_CONFIRMS 0
#define DPOW_KOMODOCONFIRMS 10
#define DPOW_BTCCONFIRMS 1
#define DPOW_MAXRELAYS 64
#define DPOW_MAXSIGLEN 128

#define DEX_VERSION 0x0101
#define DPOW_SOCK 7775
#define DEX_SOCK 7774
#define PUB_SOCK 7773
#define REP_SOCK 7772

struct dpow_coinentry
{
    bits256 prev_hash;
    uint8_t siglens[DPOW_MAXRELAYS],sigs[DPOW_MAXRELAYS][DPOW_MAXSIGLEN];
    int32_t prev_vout;
};

struct dpow_utxoentry
{
    bits256 srchash,desthash,commit,hashmsg;
    uint64_t recvmask,othermasks[DPOW_MAXRELAYS];
    int32_t srcvout,destvout,height;
    int8_t bestk; uint8_t pubkey[33];
};

struct dpow_entry
{
    bits256 commit,beacon,ratifysrcutxo,ratifydestutxo;
    uint64_t masks[2][DPOW_MAXRELAYS],recvmask,othermask,bestmask,ratifyrecvmask,ratifybestmask;
    int32_t height; uint32_t pendingcrcs[2];
    uint16_t ratifysrcvout,ratifydestvout;
    int8_t bestk,ratifybestk;
    uint8_t pubkey[33],ratifysigs[2][DPOW_MAXSIGLEN],ratifysiglens[2];
    struct dpow_coinentry src,dest;
};

struct dpow_sigentry
{
    bits256 beacon;
    uint64_t mask;
    int32_t refcount;
    uint8_t senderind,lastk,siglen,sig[DPOW_MAXSIGLEN],senderpub[33];
};

struct komodo_notaries
{
    struct basilisk_relay RELAYS[DPOW_MAXRELAYS];
    int32_t NUMRELAYS,RELAYID;
};

struct dpow_hashheight { bits256 hash; int32_t height; };

struct dpow_checkpoint
{
    struct dpow_hashheight blockhash,approved;
    bits256 miner; uint32_t blocktime,timestamp;
};

struct dpow_block
{
    bits256 hashmsg,desttxid,srctxid,beacon,commit;
    struct iguana_info *srccoin,*destcoin; char *opret_symbol;
    uint64_t destsigsmasks[DPOW_MAXRELAYS],srcsigsmasks[DPOW_MAXRELAYS];
    uint64_t recvmask,bestmask,ratifybestmask,ratifyrecvmask,pendingbestmask,pendingratifybestmask,ratifysigmasks[2];
    struct dpow_entry notaries[DPOW_MAXRELAYS];
    uint32_t state,starttime,timestamp,waiting,sigcrcs[2],txidcrcs[2],utxocrcs[2],lastepoch;
    int32_t rawratifiedlens[2],height,numnotaries,numerrors,completed,minsigs,duration,numratified,isratify,require0,scores[DPOW_MAXRELAYS];
    int8_t myind,bestk,ratifybestk,pendingbestk,pendingratifybestk;
    cJSON *ratified;
    uint8_t ratified_pubkeys[DPOW_MAXRELAYS][33],ratifysigs[2][DPOW_MAXSIGLEN],ratifysiglens[2];
    char handles[DPOW_MAXRELAYS][32];
    char signedtx[32768]; uint8_t ratifyrawtx[2][32768]; uint32_t pendingcrcs[2];
};

struct pax_transaction
{
    UT_hash_handle hh;
    bits256 txid;
    uint64_t komodoshis,fiatoshis;
    int32_t marked,height,kmdheight;
    uint16_t vout;
    char symbol[16],coinaddr[64]; uint8_t rmd160[20],shortflag;
};

struct dpow_info
{
    char symbol[16],dest[16]; uint8_t minerkey33[33],minerid; uint64_t lastrecvmask;
    struct dpow_checkpoint checkpoint,last,destchaintip,srcfifo[DPOW_FIFOSIZE],destfifo[DPOW_FIFOSIZE];
    struct dpow_hashheight approved[DPOW_FIFOSIZE],notarized[DPOW_FIFOSIZE];
    bits256 srctx[DPOW_MAXTX],desttx[DPOW_MAXTX];
    uint32_t SRCREALTIME,destupdated,srcconfirms,numdesttx,numsrctx,lastsplit,cancelratify;
    int32_t lastheight,maxblocks,SRCHEIGHT,SHORTFLAG,ratifying;
    struct pax_transaction *PAX;
    portable_mutex_t mutex;
    uint32_t ipbits[64],numipbits;
    struct dpow_block **blocks;
};


#endif
