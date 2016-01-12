/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
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
#include "../crypto777/OS_portable.h"
#include "SuperNET.h"

//#define IGUANA_DISABLEPEERS
#define IGUANA_MAXCOINS 64
#define IGUANA_MAXDELAY_MILLIS (3600 * 1000) 

#define IGUANA_EXCHANGEIDLE 10
#define IGUANS_JSMILLIS 100

#define IGUANA_WIDTH 1024
#define IGUANA_HEIGHT 200

#define IGUANA_MAXPENDHDRS 1
#define _IGUANA_MAXPENDING 3    //64
#define _IGUANA_MAXBUNDLES 8 
#define IGUANA_MAXACTIVEBUNDLES 32
#define IGUANA_MAXFILES 4096
#define IGUANA_BUNDLELOOP 1000
#define IGUANA_RPCPORT 7778
#define IGUANA_MAXRAMCHAINSIZE ((uint64_t)1024L * 1024L * 1024L * 16)

#define IGUANA_MAPHASHTABLES 1
#define IGUANA_DEFAULTRAM 4
#define IGUANA_MAXRECVCACHE ((int64_t)1024L * 1024 * 1024L)
#define IGUANA_MAXBUNDLES (5000000 / 500)
#define IGUANA_LOG2MAXPEERS 9
#define IGUANA_LOG2PACKETSIZE 21
#define IGUANA_LOG2PEERFILESIZE 23

#define IGUANA_MAXPEERS (1 << IGUANA_LOG2MAXPEERS)
#define IGUANA_MAXPACKETSIZE (1 << IGUANA_LOG2PACKETSIZE)
#define IGUANA_PEERFILESIZE (1 << IGUANA_LOG2PEERFILESIZE)
struct iguana_txdatabits { uint64_t addrind:IGUANA_LOG2MAXPEERS,filecount:10,fpos:IGUANA_LOG2PEERFILESIZE,datalen:IGUANA_LOG2PACKETSIZE,isdir:1; };

#define IGUANA_MAXFILEITEMS 8192

#define IGUANA_RECENTPEER (3600 * 24 * 7)

#define IGUANA_PERMTHREAD 0
#define IGUANA_CONNTHREAD 1
#define IGUANA_SENDTHREAD 2
#define IGUANA_RECVTHREAD 3
#define IGUANA_HELPERTHREAD 4
#define IGUANA_EXCHANGETHREAD 5

#define IGUANA_DEDICATED_THREADS
#ifdef IGUANA_DEDICATED_THREADS
#define IGUANA_MAXCONNTHREADS 64
#define IGUANA_MAXSENDTHREADS IGUANA_MAXPEERS
#define IGUANA_MAXRECVTHREADS IGUANA_MAXPEERS
#else
#define IGUANA_MAXCONNTHREADS 64
#define IGUANA_MAXSENDTHREADS 64
#define IGUANA_MAXRECVTHREADS 64
#endif


#ifdef __PNACL
void PNACL_message(const char* format, ...);
#endif

extern int32_t IGUANA_NUMHELPERS;

#ifdef __PNACL
#define printf PNACL_message
#define MS_ASYNC	1		/* Sync memory asynchronously.  */
#define MS_SYNC		4		/* Synchronous memory sync.  */
#else
#define PNACL_message printf
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000	// Do not generate SIGPIPE
#endif

#define BIP0031_VERSION	 60000
#define CADDR_TIME_VERSION 31402
#define MIN_PROTO_VERSION 209
#define MAX_BLOCK_SIZE 1000000
#define COINBASE_MATURITY 100

#define _IGUANA_HDRSCOUNT 2000
#define _IGUANA_BLOCKHASHES 500
#define IGUANA_MAXBUNDLESIZE _IGUANA_HDRSCOUNT

#define NODE_NETWORK (1 << 0)
#define NODE_GETUTXO (1 << 1)
#define NODE_BLOOM (1 << 2)

#define PROTOCOL_VERSION 70011
#define INIT_PROTO_VERSION 209 // initial proto version, to be increased after version/verack negotiation
#define GETHEADERS_VERSION 31800 // In this version, 'getheaders' was introduced.
#define MIN_PEER_PROTO_VERSION GETHEADERS_VERSION // disconnect from peers older than this proto version
// nTime field added to CAddress, starting with this version, if possible, avoid requesting addresses nodes older than this
#define CADDR_TIME_VERSION 31402
// only request blocks from nodes outside this range of versions
#define NOBLKS_VERSION_START 32000
#define NOBLKS_VERSION_END 32400

#define BIP0031_VERSION 60000 // BIP 0031, pong message, is enabled for all versions AFTER this one
#define MEMPOOL_GD_VERSION 60002 // "mempool" command, enhanced "getdata" behavior starts with this version
#define NO_BLOOM_VERSION 70011 // "filter*" disabled without NODE_BLOOM after and including this version

#define MSG_TX 1
#define MSG_BLOCK 2
#define MSG_FILTERED_BLOCK 3

#define IGUANA_MAXLOCATORS 64
#define IGUANA_MAXINV 50000

#define IGUANA_VOLATILE 1
#define IGUANA_ITEMIND_DATA 2
#define IGUANA_MAPPED_ITEM 4
#define IGUANA_SHA256 0x80
#define IGUANA_ALLOC_MULT 1.1
#define IGUANA_ALLOC_INCR 1000

#define IGUANA_JSONTIMEOUT 1000

#define IGUANA_MAPRECVDATA 1
#define IGUANA_MAPTXIDITEMS 2
#define IGUANA_MAPPKITEMS 4
#define IGUANA_MAPBLOCKITEMS 8
#define IGUANA_MAPPEERITEMS 16

#define IGUANA_PEER_ELIGIBLE 1
#define IGUANA_PEER_CONNECTING 2
#define IGUANA_PEER_READY 3
#define IGUANA_PEER_KILLED 4

#define CHAIN_BTCD 0
#define CHAIN_TESTNET3 1
#define CHAIN_BITCOIN 2

#define IGUANA_SEARCHBUNDLE 1
#define IGUANA_SEARCHNOLAST (IGUANA_SEARCHBUNDLE | 2)
#define IGUANA_SEARCHPREV 4
#define IGUANA_SEARCHNEXT 8
#define IGUANA_SEARCHALL (IGUANA_SEARCHBUNDLE | IGUANA_SEARCHPREV | IGUANA_SEARCHNEXT)


typedef void (*iguana_func)(void *);
struct iguana_thread
{
    struct queueitem DL;
    pthread_t handle;
    struct iguana_info *coin;
    char name[16];
    uint8_t type;
    iguana_func funcp;
    void *arg;
};

struct iguana_chain
{
	//const int32_t chain_id;
    char name[32],symbol[8];
    uint8_t pubval,p2shval,wipval,netmagic[4];
    char *genesis_hash,*genesis_hex; // hex string
    uint16_t portp2p,portrpc,hastimestamp;
    uint64_t rewards[512][2];
    uint8_t genesis_hashdata[32],unitval,minconfirms;
    uint16_t ramchainport,bundlesize,hasheaders;
    char gethdrsmsg[16];
};

struct iguana_msgaddress {	uint32_t nTime; uint64_t nServices; uint8_t ip[16]; uint16_t port; } __attribute__((packed));

struct iguana_msgversion
{
	uint32_t nVersion;
	uint64_t nServices;
	int64_t nTime;
	struct iguana_msgaddress addrTo,addrFrom;
	uint64_t nonce;
	char strSubVer[80];
	uint32_t nStartingHeight;
    uint8_t relayflag;
};

struct iguana_msgblockhdr
{
    uint32_t version;
    bits256 prev_block,merkle_root;
    uint32_t timestamp,bits,nonce;
} __attribute__((packed));

struct iguana_msgblock
{
    struct iguana_msgblockhdr H; // double hashed for blockhash
    uint32_t txn_count;
} __attribute__((packed));

struct iguana_msgvin { bits256 prev_hash; uint8_t *script; uint32_t prev_vout,scriptlen,sequence; } __attribute__((packed));

struct iguana_msgvout { uint64_t value; uint32_t pk_scriptlen; uint8_t *pk_script; } __attribute__((packed));

struct iguana_msgtx
{
    uint32_t version,tx_in,tx_out,lock_time;
    struct iguana_msgvin *vins;
    struct iguana_msgvout *vouts;
    bits256 txid;
    int32_t allocsize,timestamp;
} __attribute__((packed));

struct iguana_packet { struct queueitem DL; struct iguana_peer *addr; struct tai embargo; int32_t datalen,getdatablock; uint8_t serialized[]; };

struct msgcounts { uint32_t version,verack,getaddr,addr,inv,getdata,notfound,getblocks,getheaders,headers,tx,block,mempool,ping,pong,reject,filterload,filteradd,filterclear,merkleblock,alert; };

struct iguana_fileitem { bits256 hash2; struct iguana_txdatabits txdatabits; };

struct iguana_kvitem { UT_hash_handle hh; uint8_t keyvalue[]; } __attribute__((packed));

struct iguana_iAddr
{
    UT_hash_handle hh; uint32_t ipbits;
    uint32_t lastkilled,lastconnect;
    int32_t status,height,numkilled,numconnects;
};

struct iguana_cacheptr { struct queueitem DL; int32_t allocsize,recvlen; uint8_t *data; };

// iguana blocks
struct iguana_blockRO
{
    bits256 hash2,prev_block,merkle_root;
    uint32_t timestamp,nonce,bits,version;
    uint32_t firsttxidind,firstvin,firstvout,firstpkind,firstexternalind,recvlen:24,tbd:8;
    uint16_t txn_count,numvouts,numvins,extra;
};

struct iguana_block
{
    struct iguana_blockRO RO;
    double PoW; // NOT consensus safe, for estimation purposes only
    int32_t height,fpos; uint32_t fpipbits;
    uint16_t hdrsi,bundlei:12,mainchain:1,valid:1,queued:1,tbd:1,numrequests:8,extra:8;
    UT_hash_handle hh;
} __attribute__((packed));


#define IGUANA_LHASH_BLOCKS 0
#define IGUANA_LHASH_TXIDS 1 //
#define IGUANA_LHASH_UNSPENTS 2 //
#define IGUANA_LHASH_SPENDS 3 //
#define IGUANA_LHASH_PKHASHES 4 //
//#define IGUANA_LHASH_SPENTINDS 5
//#define IGUANA_LHASH_FIRSTSPENDS 5 //
#define IGUANA_LHASH_ACCOUNTS 5 //
#define IGUANA_LHASH_EXTERNALS 6 //
#define IGUANA_LHASH_TXBITS 7 //
#define IGUANA_LHASH_PKBITS 8 //
#define IGUANA_NUMLHASHES (IGUANA_LHASH_PKBITS + 1)

struct iguana_counts
{
    uint32_t firsttxidind,firstunspentind,firstspendind,firstpkind;
    //bits256 lhashes[IGUANA_NUMAPPENDS],ledgerhash; struct sha256_vstate states[IGUANA_NUMAPPENDS];
    //bits256 blockhash,merkle_root;
    uint64_t credits,debits;
    //uint32_t timestamp,height;
    //struct iguana_prevdep dep;
    struct iguana_block block;
} __attribute__((packed));

struct iguana_blocks
{
    char coin[8];
	struct iguanakv *db;
    struct iguana_block *hash; struct iguana_blockRO *RO; int32_t maxbits;
    int32_t maxblocks,initblocks,hashblocks,issuedblocks,recvblocks,emitblocks,parsedblocks,dirty;
	struct iguana_block hwmchain;
};

struct iguana_ledger
{
    struct iguana_counts snapshot;
    //struct iguana_account accounts[];
} __attribute__((packed));

// ramchain append only structs -> canonical 32bit inds and ledgerhashes
struct iguana_txid { bits256 txid; uint32_t txidind,firstvout,firstvin,locktime,version,timestamp; uint16_t numvouts,numvins; } __attribute__((packed));

struct iguana_unspent { uint64_t value; uint32_t txidind,pkind,prevunspentind; uint16_t hdrsi:12,type:4,vout; } __attribute__((packed));
struct iguana_unspent20 { uint64_t value; uint32_t txidind:28,type:4; uint8_t rmd160[20]; } __attribute__((packed));

struct iguana_spend256 { bits256 prevhash2; int16_t prevout; uint16_t spendind:15,diffsequence:1; } __attribute__((packed));
struct iguana_spend { uint32_t spendtxidind; int16_t prevout; uint16_t tbd:14,external:1,diffsequence:1; } __attribute__((packed));

struct iguana_pkhash { uint8_t rmd160[20]; uint32_t pkind,firstunspentind,flags:23,type:8,ps2h:1; } __attribute__((packed));

// dynamic
struct iguana_account { uint64_t balance; uint32_t lastunspentind; } __attribute__((packed)); // pkind

// GLOBAL one zero to non-zero write (unless reorg)
struct iguana_Uextra { uint32_t spendind; uint16_t hdrsi; } __attribute__((packed)); // unspentind
//struct iguana_pkextra { uint32_t firstspendind; } __attribute__((packed)); // pkind

struct iguana_txblock
{
    uint32_t numtxids,numunspents,numspends,extralen,recvlen;
    // following set during second pass (still in peer context)
    uint32_t numpkinds,numexternaltxids,datalen,pkoffset;
    uint8_t space[256]; // order: extra[], T, U, S, P, external txids
    struct iguana_block block;
};

struct iguana_ramchaindata
{
    bits256 sha256;
    bits256 lhashes[IGUANA_NUMLHASHES],firsthash2,lasthash2;
    int64_t allocsize,Boffset,Toffset,Uoffset,Soffset,Poffset,Aoffset,Xoffset,TXoffset,PKoffset;
    int32_t numblocks,height,firsti,hdrsi,txsparsebits,pksparsebits;
    uint32_t numtxids,numunspents,numspends,numpkinds,numexternaltxids,numtxsparse,numpksparse;
    uint8_t rdata[];
};

struct iguana_ramchain_hdr
{
    uint32_t txidind,unspentind,spendind; uint16_t hdrsi,bundlei:15,ROflag:1;
    struct iguana_ramchaindata *data;
};

struct iguana_ramchain
{
    struct iguana_ramchain_hdr H; bits256 lasthash2; uint64_t datasize;
    uint32_t numblocks:31,expanded:1,pkind,externalind,height;
    struct iguana_kvitem *txids,*pkhashes;
    struct OS_memspace *hashmem; long filesize; void *fileptr;
    struct iguana_account *A,*roA; //struct iguana_Uextra *U2,*roU2; struct iguana_pkextra *P2,*roP2;
};

struct iguana_peer
{
    struct queueitem DL;
    queue_t sendQ;
    struct iguana_msgaddress A;
    char ipaddr[64],lastcommand[16],coinstr[16],symbol[16];
    uint64_t pingnonce,totalsent,totalrecv; double pingtime,sendmillis,pingsum,getdatamillis;
    uint32_t lastcontact,sendtime,ready,startsend,startrecv,pending,ipbits,lastgotaddr,lastblockrecv,pendtime,lastflush,lastpoll;
    int32_t supernet,dead,addrind,usock,lastheight,protover,relayflag,numpackets,numpings,ipv6,height,rank,pendhdrs,pendblocks,recvhdrs,lastlefti;
    double recvblocks,recvtotal;
    int64_t allocated,freed;
    struct msgcounts msgcounts;
    //FILE *fp; int32_t filecount,addrind;
    struct OS_memspace RAWMEM,TXDATA,HASHMEM;
    struct iguana_ramchain ramchain;
    //struct iguana_kvitem *txids,*pkhashes;
    struct iguana_fileitem *filehash2; int32_t numfilehash2,maxfilehash2;
#ifdef IGUANA_PEERALLOC
    struct OS_memspace *SEROUT[128];
#endif
};

struct iguana_peers
{
    bits256 lastrequest;
    struct iguana_peer active[IGUANA_MAXPEERS],*ranked[IGUANA_MAXPEERS],*localaddr;
    struct iguana_thread *peersloop,*recvloop; pthread_t *acceptloop;
    double topmetrics[IGUANA_MAXPEERS],avemetric;
    uint32_t numranked,mostreceived,shuttingdown,lastpeer,lastmetrics,numconnected;
    int32_t numfiles;
};

struct iguana_bloom16 { uint8_t hash2bits[65536 / 8]; };

struct iguana_bundle
{
    struct queueitem DL; struct iguana_info *coin; struct iguana_bundle *nextbp;
    struct iguana_bloom16 bloom;
    uint32_t issuetime,hdrtime,emitfinish,mergefinish,purgetime;
    int32_t minrequests,numhashes,numissued,numrecv,n,hdrsi,bundleheight,numtxids,numspends,numunspents;
    double avetime,threshold,metric; uint64_t datasize,estsize;
    struct iguana_block *blocks[IGUANA_MAXBUNDLESIZE]; uint32_t issued[IGUANA_MAXBUNDLESIZE];
    bits256 prevbundlehash2,hashes[IGUANA_MAXBUNDLESIZE+1],nextbundlehash2,allhash;
    struct iguana_ramchain ramchain; uint8_t red,green,blue;
};

struct iguana_bundlereq
{
    struct queueitem DL; struct iguana_info *coin; int32_t type;
    struct iguana_peer *addr; struct iguana_block *blocks,block; bits256 *hashes,txid;
    struct iguana_txdatabits txdatabits;
    struct iguana_msghdr H;
    int32_t allocsize,datalen,n,recvlen,numtx; uint32_t ipbits;
    uint8_t copyflag,serialized[];
};

struct iguana_bitmap { int32_t width,height,amplitude; char name[52]; uint8_t data[IGUANA_WIDTH*IGUANA_HEIGHT*3]; };

struct iguana_waddress { UT_hash_handle hh; uint8_t rmd160[20],type,pubkey[33],wiptype; uint32_t symbolbits; bits256 privkey; char coinaddr[36],wipstr[50]; };
struct iguana_waccount { UT_hash_handle hh; char account[128]; struct iguana_waddress *waddrs; };
struct iguana_wallet { UT_hash_handle hh; struct iguana_waccount *waccts; };

struct iguana_info
{
    char name[64],symbol[8],statusstr[512];
    struct iguana_peers peers;
    uint64_t instance_nonce,myservices,totalsize,totalrecv,totalpackets,sleeptime;
    int64_t mining,totalfees,TMPallocated,MAXRECVCACHE,MAXMEM,estsize,activebundles;
    int32_t MAXPEERS,MAXPENDING,MAXBUNDLES,active,closestbundle,numemitted,lastsweep,startutc,newramchain,numcached,cachefreed;
    uint32_t longestchain,lastsync,parsetime,numiAddrs,firstblock,lastpossible,bundlescount,savedblocks;
    struct tai starttime; double startmillis;
    struct iguana_chain *chain;
    struct iguana_iAddr *iAddrs;
    struct iguanakv *txids,*spends,*unspents,*pkhashes;
    struct iguana_txid *T;
    struct iguana_unspent *U; struct iguana_Uextra *Uextras;
    struct iguana_spend *S; struct iguana_Sextra *Sextras;
    struct iguana_pkhash *P; struct iguana_account *accounts; struct iguana_pkextra *pkextras;
    //struct iguana_counts latest;
    //struct iguana_ledger LEDGER,loadedLEDGER;

    struct iguana_bitmap screen;
    //struct pollfd fds[IGUANA_MAXPEERS]; struct iguana_peer bindaddr; int32_t numsocks;
    struct OS_memspace TXMEM;
    queue_t acceptQ,bundlesQ,hdrsQ,blocksQ,priorityQ,possibleQ,TerminateQ,cacheQ;
    double parsemillis,avetime; uint32_t Launched[8],Terminated[8];
    portable_mutex_t peers_mutex,blocks_mutex;
    struct iguana_bundle *bundles[IGUANA_MAXBUNDLES];
    int32_t numpendings,zcount,recvcount,bcount,pcount,lastbundle; uint32_t recvtime,hdrstime,backstoptime,lastbundletime,numreqsent;
    double backstopmillis; bits256 backstophash2;
    int32_t initialheight,mapflags,minconfirms,numrecv,isRT,backstop,blocksrecv,merging,polltimeout,numreqtxids; bits256 reqtxids[64];
    void *launched,*started;
    uint64_t bloomsearches,bloomhits,bloomfalse,collisions; uint8_t blockspace[IGUANA_MAXPACKETSIZE + 8192]; struct OS_memspace blockMEM;
    struct iguana_blocks blocks;
    struct iguana_waccount *wallet;
};

// peers
int32_t iguana_verifypeer(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize);
int32_t iguana_peermetrics(struct iguana_info *coin);
void iguana_peersloop(void *arg);
int32_t iguana_queue_send(struct iguana_info *coin,struct iguana_peer *addr,int32_t delay,uint8_t *serialized,char *cmd,int32_t len,int32_t getdatablock,int32_t forceflag);
uint32_t iguana_ipbits2ind(struct iguana_info *coin,struct iguana_iAddr *iA,uint32_t ipbits,int32_t createflag);
uint32_t iguana_rwiAddrind(struct iguana_info *coin,int32_t rwflag,struct iguana_iAddr *iA,uint32_t ind);
//uint32_t iguana_rwipbits_status(struct iguana_info *coin,int32_t rwflag,uint32_t ipbits,int32_t *statusp);
void iguana_connections(void *arg);
uint32_t iguana_possible_peer(struct iguana_info *coin,char *ipaddr);
//int32_t iguana_set_iAddrheight(struct iguana_info *coin,uint32_t ipbits,int32_t height);
//struct iguana_peer *iguana_choosepeer(struct iguana_info *coin);
void iguana_initpeer(struct iguana_info *coin,struct iguana_peer *addr,uint32_t ipbits);
void iguana_startconnection(void *arg);
void iguana_shutdownpeers(struct iguana_info *coin,int32_t forceflag);
void iguana_acceptloop(void *args);
void iguana_recvloop(void *args);
int32_t iguana_send(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *serialized,int32_t len);
uint32_t iguana_updatemetrics(struct iguana_info *coin);
void *iguana_peeralloc(struct iguana_info *coin,struct iguana_peer *addr,int32_t datalen);
int64_t iguana_peerfree(struct iguana_info *coin,struct iguana_peer *addr,void *ptr,int32_t datalen);
int64_t iguana_peerallocated(struct iguana_info *coin,struct iguana_peer *addr);

// serdes
int32_t iguana_rwmem(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp);
int32_t iguana_rwnum(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp);
int32_t iguana_rwvarint32(int32_t rwflag,uint8_t *serialized,uint32_t *int32p);
int32_t iguana_rwbignum(int32_t rwflag,uint8_t *serialized,int32_t len,uint8_t *endianedp);
int32_t iguana_rwblock(int32_t rwflag,bits256 *hash2p,uint8_t *serialized,struct iguana_msgblock *msg);
int32_t iguana_serialize_block(bits256 *hash2p,uint8_t serialized[sizeof(struct iguana_msgblock)],struct iguana_block *block);
void iguana_blockconv(struct iguana_block *dest,struct iguana_msgblock *msg,bits256 hash2,int32_t height);
//void iguana_freetx(struct iguana_msgtx *tx,int32_t n);
int32_t iguana_msgparser(struct iguana_info *coin,struct iguana_peer *addr,struct OS_memspace *rawmem,struct OS_memspace *txmem,struct OS_memspace *hashmem,struct iguana_msghdr *H,uint8_t *data,int32_t datalen);

// send message
int32_t iguana_validatehdr(struct iguana_msghdr *H);
int32_t iguana_sethdr(struct iguana_msghdr *H,const uint8_t netmagic[4],char *command,uint8_t *data,int32_t datalen);
int32_t iguana_send_version(struct iguana_info *coin,struct iguana_peer *addr,uint64_t myservices);
int32_t iguana_gentxarray(struct iguana_info *coin,struct OS_memspace *mem,struct iguana_txblock *txblock,int32_t *lenp,uint8_t *data,int32_t datalen);
int32_t iguana_gethdrs(struct iguana_info *coin,uint8_t *serialized,char *cmd,char *hashstr);
int32_t iguana_getdata(struct iguana_info *coin,uint8_t *serialized,int32_t type,char *hashstr);

// ramchain
int64_t iguana_verifyaccount(struct iguana_info *coin,struct iguana_account *acct,uint32_t pkind);
int32_t iguana_initramchain(struct iguana_info *coin,int32_t initialheight,int32_t mapflags,int32_t fullverify);
void iguana_syncramchain(struct iguana_info *coin);
//int32_t iguana_validateramchain(struct iguana_info *coin,int64_t *netp,uint64_t *creditsp,uint64_t *debitsp,int32_t height,struct iguana_block *block,int32_t hwmheight,struct iguana_prevdep *lp);
int32_t iguana_calcrmd160(struct iguana_info *coin,uint8_t rmd160[20],uint8_t msigs160[16][20],int32_t *Mp,int32_t *nump,uint8_t *pk_script,int32_t pk_scriptlen,bits256 debugtxid);
uint32_t iguana_updatescript(struct iguana_info *coin,uint32_t blocknum,uint32_t txidind,uint32_t spendind,uint32_t unspentind,uint64_t value,uint8_t *script,int32_t scriptlen,uint32_t sequence);
void iguana_gotblockM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *txdata,struct iguana_msgtx *txarray,struct iguana_msghdr *H,uint8_t *data,int32_t datalen);
int32_t iguana_parseblock(struct iguana_info *coin,struct iguana_block *block,struct iguana_msgtx *tx,int32_t numtx);
uint32_t iguana_txidind(struct iguana_info *coin,uint32_t *firstvoutp,uint32_t *firstvinp,bits256 txid);
bits256 iguana_txidstr(struct iguana_info *coin,uint32_t *firstvoutp,uint32_t *firstvinp,char *txidstr,uint32_t txidind);
int32_t iguana_updateramchain(struct iguana_info *coin);
//void iguana_emittxarray(struct iguana_info *coin,FILE *fp,struct iguana_bundle *bundle,struct iguana_block *block,struct iguana_msgtx *txarray,int32_t numtx);

// blockchain
int32_t iguana_needhdrs(struct iguana_info *coin);
struct iguana_chain *iguana_chainfind(char *name);
int32_t iguana_chainextend(struct iguana_info *coin,struct iguana_block *newblock);
uint64_t iguana_miningreward(struct iguana_info *coin,uint32_t blocknum);

// tx
int32_t iguana_rwtx(int32_t rwflag,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgtx *msg,int32_t maxsize,bits256 *txidp,int32_t height,int32_t hastimestamp);
void iguana_gottxidsM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *txids,int32_t n);
void iguana_gotunconfirmedM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgtx *tx,uint8_t *data,int32_t datalen);
void iguana_gotblockhashesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *blockhashes,int32_t n);

// blocks
bits256 iguana_blockhash(struct iguana_info *coin,int32_t height);
#define iguana_blockfind(coin,hash2) iguana_blockhashset(coin,-1,hash2,0)
struct iguana_block *iguana_blockhashset(struct iguana_info *coin,int32_t height,bits256 hash2,int32_t createflag);

uint32_t iguana_syncs(struct iguana_info *coin);
void iguana_gotdata(struct iguana_info *coin,struct iguana_peer *addr,int32_t height);
int64_t iguana_balance(struct iguana_info *coin,uint64_t *creditsp,uint64_t *debitsp,int32_t *nump,uint32_t *unspents,long max,struct iguana_pkhash *P,uint32_t pkind);
int32_t iguana_queueblock(struct iguana_info *coin,int32_t height,bits256 hash2,int32_t priority);
int32_t iguana_updatewaiting(struct iguana_info *coin,int32_t starti,int32_t max);

// recvbits
int32_t iguana_recvinit(struct iguana_info *coin,int32_t initialheight);
int32_t ramcoder_decompress(uint8_t *data,int32_t maxlen,uint8_t *bits,uint32_t numbits,bits256 seed);
int32_t ramcoder_compress(uint8_t *bits,int32_t maxlen,uint8_t *data,int32_t datalen,uint64_t *histo,bits256 seed);
uint64_t hconv_bitlen(uint64_t bitlen);
struct iguana_block *iguana_blockptr(struct iguana_info *coin,int32_t height);
int32_t iguana_processrecv(struct iguana_info *coin); // single threaded
void iguana_recvalloc(struct iguana_info *coin,int32_t numitems);
void iguana_coins(void *arg);
int32_t iguana_savehdrs(struct iguana_info *coin);

// hdrs
struct iguana_bundle *iguana_bundlecreate(struct iguana_info *coin,int32_t *bundleip,int32_t bundleheight,bits256 bundlehash2,bits256 allhash,int32_t issueflag);
struct iguana_block *iguana_updatehdrs(struct iguana_info *coin,int32_t *newhwmp,struct iguana_block *block,bits256 prevhash2,bits256 hash2);
void iguana_parseline(struct iguana_info *coin,int32_t iter,FILE *fp);
void iguana_gotheadersM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n);
void iguana_emittxdata(struct iguana_info *coin,struct iguana_bundle *bp);
int32_t iguana_pollQsPT(struct iguana_info *coin,struct iguana_peer *addr);
int32_t iguana_avail(struct iguana_info *coin,int32_t height,int32_t n);
int32_t iguana_updatebundles(struct iguana_info *coin);
void iguana_bundlestats(struct iguana_info *coin,char *str);

// init
struct iguana_info *iguana_startcoin(struct iguana_info *coin,int32_t initialheight,int32_t mapflags);
void iguana_initcoin(struct iguana_info *coin);
void iguana_coinloop(void *arg);

// utils
double PoW_from_compact(uint32_t nBits,uint8_t unitval);
void calc_rmd160(char *hexstr,uint8_t buf[20],uint8_t *msg,int32_t len);
void calc_OP_HASH160(char *hexstr,uint8_t hash160[20],char *msg);
double dxblend(double *destp,double val,double decay);

// json
int32_t iguana_processjsonQ(struct iguana_info *coin); // reentrant, can be called during any idletime
char *iguana_JSON(char *jsonstr);
char *SuperNET_p2p(struct iguana_info *coin,int32_t *delaymillisp,char *ipaddr,uint8_t *data,int32_t datalen);

char *mbstr(char *str,double);
int init_hexbytes_noT(char *hexbytes,unsigned char *message,long len);
int32_t decode_hex(unsigned char *bytes,int32_t n,char *hex);
char hexbyte(int32_t c);
char *clonestr(char *str);
long _stripwhite(char *buf,int accept);
int32_t myatoi(char *str,int32_t range);
int32_t safecopy(char *dest,char *src,long len);
void escape_code(char *escaped,char *str);
int32_t is_zeroes(char *str);
int64_t conv_floatstr(char *numstr);
int32_t has_backslash(char *str);

struct iguana_thread *iguana_launch(struct iguana_info *coin,char *name,iguana_func funcp,void *arg,uint8_t type);
int32_t iguana_numthreads(struct iguana_info *coin,int32_t mask);
void iguana_terminator(void *arg);

int32_t is_hexstr(char *str,int32_t n);
void iguana_initQ(queue_t *Q,char *name);
void iguana_emitQ(struct iguana_info *coin,struct iguana_bundle *bp);
void iguana_txdataQ(struct iguana_info *coin,struct iguana_peer *addr,FILE *fp,long fpos,int32_t datalen);
void iguana_helper(void *arg);

struct iguana_helper { struct queueitem DL; void *coin,*addr,*bp,*nextbp,*fp; long fpos; int32_t allocsize,type,hdrsi,bundlei,datalen; uint32_t starttime; };
int32_t iguana_helpertask(FILE *fp,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_helper *ptr);
void iguana_flushQ(struct iguana_info *coin,struct iguana_peer *addr);
//struct iguana_txdatabits iguana_peerfilePT(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2,struct iguana_txdatabits txdatabits,int32_t recvlen);
struct iguana_txdatabits iguana_calctxidbits(uint32_t addrind,uint32_t filecount,uint32_t fpos,uint32_t datalen);
int32_t iguana_bundlesaveHT(struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_bundle *bp,uint32_t starttime); // helper thread
int32_t iguana_bundlemergeHT(struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_bundle *bp,struct iguana_bundle *nextbp,uint32_t starttime); // helper thread

void iguana_peerfilename(struct iguana_info *coin,char *fname,uint32_t addrind,uint32_t filecount);

struct iguana_txblock *iguana_ramchainptrs(struct iguana_txid **Tptrp,struct iguana_unspent20 **Uptrp,struct iguana_spend256 **Sptrp,struct iguana_pkhash **Pptrp,bits256 **externalTptrp,struct OS_memspace *mem,struct iguana_txblock *origtxdata);

int32_t iguana_ramchainsave(struct iguana_info *coin,struct iguana_ramchain *ramchain);
int32_t iguana_ramchainfree(struct iguana_info *coin,struct OS_memspace *mem,struct iguana_ramchain *ramchain);
struct iguana_ramchain *iguana_ramchainmergeHT(struct iguana_info *coin,struct OS_memspace *mem,struct iguana_ramchain *ramchains[],int32_t n,struct iguana_bundle *bp);
void iguana_ramchainmerge(struct iguana_info *coin);

int32_t iguana_blockQ(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t priority);
void iguana_blockcopy(struct iguana_info *coin,struct iguana_block *block,struct iguana_block *origblock);
int32_t iguana_rpctest(struct iguana_info *coin);
extern queue_t helperQ;
extern const char *Hardcoded_coins[][3];
void iguana_main(void *arg);
extern struct iguana_info *Coins[64];
int32_t iguana_peerfname(struct iguana_info *coin,int32_t *hdrsip,char *dirname,char *fname,uint32_t ipbits,bits256 hash2,bits256 prevhash2,int32_t numblocks);
struct iguana_txblock *iguana_peertxdata(struct iguana_info *coin,int32_t *bundleip,char *fname,struct OS_memspace *mem,uint32_t ipbits,bits256 hash2);
int32_t iguana_peerfile_exists(struct iguana_info *coin,struct iguana_peer *addr,char *dirname,char *fname,bits256 hash2,bits256 prevhash2,int32_t numblocks);
struct iguana_ramchain *iguana_ramchainset(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct iguana_txblock *txdata);
void *iguana_iAddriterator(struct iguana_info *coin,struct iguana_iAddr *iA);
long iguana_ramchain_data(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *origtxdata,struct iguana_msgtx *txarray,int32_t txn_count,uint8_t *data,int32_t recvlen);
int32_t iguana_bundlehash2add(struct iguana_info *coin,struct iguana_block **blockp,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2);
struct iguana_block *iguana_bundleblockadd(struct iguana_info *coin,struct iguana_bundle **bpp,int32_t *bundleip,struct iguana_block *origblock);
int32_t iguana_chainextend(struct iguana_info *coin,struct iguana_block *newblock);
int32_t iguana_blockvalidate(struct iguana_info *coin,int32_t *validp,struct iguana_block *block);
char *iguana_bundledisp(struct iguana_info *coin,struct iguana_bundle *prevbp,struct iguana_bundle *bp,struct iguana_bundle *nextbp,int32_t m);
struct iguana_bundle *iguana_bundlefind(struct iguana_info *coin,struct iguana_bundle **bpp,int32_t *bundleip,bits256 hash2);
//int32_t iguana_chainheight(struct iguana_info *coin,struct iguana_block *origblock);
bits256 *iguana_blockhashptr(struct iguana_info *coin,int32_t height);
int32_t iguana_hash2set(struct iguana_info *coin,char *debugstr,struct iguana_bundle *bp,int32_t bundlei,bits256 newhash2);
struct iguana_block *_iguana_chainlink(struct iguana_info *coin,struct iguana_block *newblock);
int32_t iguana_hashfree(struct iguana_kvitem *hashtable,int32_t freeitem);
int32_t iguana_processbundlesQ(struct iguana_info *coin,int32_t *newhwmp); // single threaded
int32_t iguana_ramchainverifyPT(struct iguana_info *coin,struct iguana_ramchain *ramchain);
void *map_file(char *fname,long *filesizep,int32_t enablewrite);
void iguana_rpcloop(void *args);
int32_t iguana_socket(int32_t bindflag,char *hostname,uint16_t port);
void iguana_mergeQ(struct iguana_info *coin,struct iguana_bundle *bp,struct iguana_bundle *nextbp);

#define bits256_nonz(a) (((a).ulongs[0] | (a).ulongs[1] | (a).ulongs[2] | (a).ulongs[3]) != 0)
int32_t btc_addr2univ(uint8_t *addrtypep,uint8_t rmd160[20],char *coinaddr);

struct iguana_agent
{
    char name[32],hostname[64]; void *methods; uint16_t port; int32_t sock,nummethods;
    bits256 pubkey,privkey;
    char *(*parsefunc)(struct iguana_agent *agent,char *method,void *json,char *remoteaddr);
};

int32_t iguana_txbytes(struct iguana_info *coin,uint8_t *serialized,int32_t maxlen,bits256 *txidp,struct iguana_txid *tx,int32_t height,struct iguana_msgvin *vins,struct iguana_msgvout *vouts);
void iguana_vinset(struct iguana_info *coin,int32_t height,struct iguana_msgvin *vin,struct iguana_txid *tx,int32_t i);
int32_t iguana_voutset(struct iguana_info *coin,uint8_t *scriptspace,char *asmstr,int32_t height,struct iguana_msgvout *vout,struct iguana_txid *tx,int32_t i);
int32_t btc_convrmd160(char *coinaddr,uint8_t addrtype,uint8_t rmd160[20]);
struct iguana_txid *iguana_bundletx(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,struct iguana_txid *tx,int32_t txidind);
int32_t iguana_txidreq(struct iguana_info *coin,char **retstrp,bits256 txid);
void iguana_bundleiclear(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei);
int32_t hcalc_bitsize(uint64_t x);
struct iguana_pkhash *iguana_pkhashfind(struct iguana_info *coin,struct iguana_pkhash *p,uint8_t rmd160[20]);
struct iguana_txid *iguana_txidfind(struct iguana_info *coin,int32_t *heightp,struct iguana_txid *tx,bits256 txid);
int32_t iguana_scriptgen(struct iguana_info *coin,uint8_t *script,char *asmstr,struct iguana_bundle *bp,struct iguana_pkhash *p,uint8_t type);
int32_t iguana_ramchain_spendtxid(struct iguana_info *coin,bits256 *txidp,struct iguana_txid *T,int32_t numtxids,bits256 *X,int32_t numexternaltxids,struct iguana_spend *s);
struct iguana_info *iguana_coinselect();
void iguana_dedicatedloop(struct iguana_info *coin,struct iguana_peer *addr);
struct iguana_peer *iguana_peerslot(struct iguana_info *coin,uint32_t ipbits);

char *busdata_sync(uint32_t *noncep,char *jsonstr,char *broadcastmode,char *destNXTaddr);
void peggy();
int32_t opreturns_init(uint32_t blocknum,uint32_t blocktimestamp,char *path);
struct iguana_info *iguana_coinfind(const char *symbol);
struct iguana_info *iguana_coinadd(const char *symbol);
struct iguana_ramchain *iguana_bundleload(struct iguana_info *coin,struct iguana_bundle *bp);
int32_t iguana_sendblockreq(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t iamthreadsafe);
int32_t iguana_send_supernet(struct iguana_info *coin,struct iguana_peer *addr,char *jsonstr,int32_t delay);

struct iguana_waccount *iguana_waccountfind(struct iguana_info *coin,char *account);
struct iguana_waccount *iguana_waccountadd(struct iguana_info *coin,char *walletaccount,struct iguana_waddress *waddr);
int32_t iguana_waccountswitch(struct iguana_info *coin,char *account,struct iguana_waccount *oldwaddr,int32_t oldind,char *coinaddr);
struct iguana_waddress *iguana_waddresscalc(struct iguana_info *coin,struct iguana_waddress *addr,bits256 privkey);
struct iguana_waccount *iguana_waddressfind(struct iguana_info *coin,int32_t *indp,char *coinaddr);
char *iguana_coinjson(struct iguana_info *coin,char *method,cJSON *json);
cJSON *iguana_peersjson(struct iguana_info *coin,int32_t addronly);
int32_t btc_priv2wip(char *wipstr,uint8_t privkey[32],uint8_t addrtype);
int32_t btc_pub2rmd(uint8_t rmd160[20],uint8_t pubkey[33]);
int32_t iguana_launchcoin(char *symbol,cJSON *json);
int32_t iguana_jsonQ();
int32_t is_bitcoinrpc(char *method);
char *iguana_bitcoinRPC(struct supernet_info *myinfo,char *method,cJSON *json,char *remoteaddr);
cJSON *iguana_pubkeyjson(struct iguana_info *coin,char *pubkeystr);

// API functions
char *iguana_getinfo(struct supernet_info *myinfo,struct iguana_info *coin);
char *iguana_getbestblockhash(struct supernet_info *myinfo,struct iguana_info *coin);
char *iguana_getblockcount(struct supernet_info *myinfo,struct iguana_info *coin);
char *iguana_listsinceblock(struct supernet_info *myinfo,struct iguana_info *coin,bits256 blockhash,int32_t target);
char *iguana_getreceivedbyaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account,int32_t minconf);
char *iguana_listreceivedbyaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account,int32_t includeempty);

char *iguana_getaccountaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *account);
char *iguana_setaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account);
char *iguana_getaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account);
char *iguana_getaddressesbyaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account);
char *iguana_listaddressgroupings(struct supernet_info *myinfo,struct iguana_info *coin);
char *iguana_getbalance(struct supernet_info *myinfo,struct iguana_info *coin,char *account,int32_t minconf);
char *iguana_listaccounts(struct supernet_info *myinfo,struct iguana_info *coin,int32_t minconf);

char *iguana_move(struct supernet_info *myinfo,struct iguana_info *coin,char *fromaccount,char *toaccount,double amount,int32_t minconf,char *comment);
char *iguana_sendfrom(struct supernet_info *myinfo,struct iguana_info *coin,char *fromaccount,char *toaddress,double amount,int32_t minconf,char *comment,char *comment2);
char *iguana_sendmany(struct supernet_info *myinfo,struct iguana_info *coin,char *fromaccount,cJSON *payments,int32_t minconf,char *comment);

char *iguana_dumpprivkey(struct supernet_info *myinfo,struct iguana_info *coin,char *address);
char *iguana_importprivkey(struct supernet_info *myinfo,struct iguana_info *coin,char *wip);
char *iguana_dumpwallet(struct supernet_info *myinfo,struct iguana_info *coin);
char *iguana_importwallet(struct supernet_info *myinfo,struct iguana_info *coin,char *wallet);
char *iguana_walletpassphrase(struct supernet_info *myinfo,struct iguana_info *coin,char *passphrase,int32_t timeout);
char *iguana_walletpassphrasechange(struct supernet_info *myinfo,struct iguana_info *coin,char *oldpassphrase,char *newpassphrase);
char *iguana_walletlock(struct supernet_info *myinfo,struct iguana_info *coin);
char *iguana_encryptwallet(struct supernet_info *myinfo,struct iguana_info *coin,char *passphrase);
char *iguana_checkwallet(struct supernet_info *myinfo,struct iguana_info *coin);
char *iguana_repairwallet(struct supernet_info *myinfo,struct iguana_info *coin);
char *iguana_backupwallet(struct supernet_info *myinfo,struct iguana_info *coin,char *filename);

char *iguana_signmessage(struct supernet_info *myinfo,struct iguana_info *coin,char *address,char *message);
char *iguana_verifymessage(struct supernet_info *myinfo,struct iguana_info *coin,char *address,char *sig,char *message);
char *iguana_validatepubkey(struct supernet_info *myinfo,struct iguana_info *coin,char *pubkey);
char *iguana_getnewaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *account);
char *iguana_makekeypair(struct supernet_info *myinfo,struct iguana_info *coin);
char *iguana_vanitygen(struct supernet_info *myinfo,struct iguana_info *coin,char *vanity);
char *iguana_createmultisig(struct supernet_info *myinfo,struct iguana_info *coin,int32_t M,cJSON *pubkeys,char *account);

char *iguana_getrawchangeaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *account);
char *iguana_settxfee(struct supernet_info *myinfo,struct iguana_info *coin,double amount);
char *iguana_listtransactions(struct supernet_info *myinfo,struct iguana_info *coin,char *account,int32_t count,int32_t from);
char *iguana_listunspent(struct supernet_info *myinfo,struct iguana_info *coin,int32_t minconf,int32_t maxconf);
char *iguana_lockunspent(struct supernet_info *myinfo,struct iguana_info *coin,char *filename);
char *iguana_listlockunspent(struct supernet_info *myinfo,struct iguana_info *coin,char *unlock,cJSON *array);
char *iguana_gettxout(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid,int32_t vout,int32_t mempool);
char *iguana_gettxoutsetinfo(struct supernet_info *myinfo,struct iguana_info *coin);
char *iguana_getrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid,int32_t verbose);
char *iguana_createrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *vins,cJSON *vouts);
char *iguana_decoderawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx);
char *iguana_decodescript(struct supernet_info *myinfo,struct iguana_info *coin,char *script);
char *iguana_signrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx,cJSON *vins,cJSON *privkeys);
char *iguana_sendrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx);
char *iguana_sendtoaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address,double amount,char *comment,char *comment2);
char *iguana_getreceivedbyaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address,int32_t minconf);
char *iguana_listreceivedbyaddress(struct supernet_info *myinfo,struct iguana_info *coin,int32_t minconf,int32_t includeempty);


#endif
