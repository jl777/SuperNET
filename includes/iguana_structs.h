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

#ifndef H_IGUANASTRUCTS_H
#define H_IGUANASTRUCTS_H


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

struct iguana_blockreq { struct queueitem DL; bits256 hash2,*blockhashes; struct iguana_bundle *bp; int32_t n,height,bundlei; };

struct iguana_peermsgrequest { struct queueitem DL; struct iguana_peer *addr; bits256 hash2; int32_t type; };

struct iguana_chain
{
	//const int32_t chain_id;
    char name[32],symbol[8],messagemagic[64];
    uint8_t pubtype,p2shtype,wiftype,netmagic[4];
    char *genesis_hash,*genesis_hex; // hex string
    uint16_t portp2p,rpcport;
    uint8_t isPoS,unitval;
    uint64_t rewards[512][2];
    uint8_t genesis_hashdata[32],minconfirms;
    uint16_t bundlesize,hasheaders;
    char gethdrsmsg[16];
    uint64_t txfee,minoutput,dust;
    blockhashfunc hashalgo;
    char userhome[512],serverport[128],userpass[1024];
    char use_addmultisig,do_opreturn;
    int32_t estblocktime,protover;
    bits256 genesishash2,PoWtarget,PoStargets[16]; int32_t numPoStargets,PoSheights[16];
    uint8_t zcash,auxpow,alertpubkey[65];
    uint16_t targetspacing,targettimespan; uint32_t nBits,normal_txversion,locktime_txversion;
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
} __attribute__((packed));

struct iguana_msgalert // warning, many varints/variable length fields, struct is 1:1
{
    int32_t version;
    int64_t relayuntil,expiration;
    int32_t ID,cancel;
    uint32_t numcancellist;
    int32_t minver,maxver;
    uint32_t setsubvervar; char subver[1024];
    int32_t priority;
    char comment[1024],statusbar[1024],reserved[1024];
    uint8_t siglen,sig[74];
    uint32_t list[64];
};

struct iguana_VPNversion
{
	uint32_t nVersion;
	uint64_t nServices;
	int64_t nTime;
	struct iguana_msgaddress addrTo,addrFrom;
	uint64_t nonce;
	char strSubVer[80];
	uint32_t nStartingHeight;
    uint32_t iVer,v_Network_id; uint16_t wPort; uint8_t bIsGui; uint16_t wCtPort,wPrPort;
} __attribute__((packed));

struct iguana_msgblockhdr
{
    uint32_t version;
    bits256 prev_block,merkle_root;
    uint32_t timestamp,bits,nonce;
} __attribute__((packed));

#define ZKSNARK_PROOF_SIZE 584
#define ZCASH_SOLUTION_ELEMENTS 32

struct iguana_msgblockhdr_zcash
{
    bits256 bignonce;
    uint8_t numelements;
    uint32_t solution[ZCASH_SOLUTION_ELEMENTS];
    //bits256 reserved; // only here if auxpow is set
} __attribute__((packed));

struct iguana_msgmerkle
{
    uint32_t branch_length;
    bits256 branch_hash[4096];
    uint32_t branch_side_mask;
} __attribute__((packed));

struct iguana_msgblock
{
    struct iguana_msgblockhdr H; // double hashed for blockhash
    struct iguana_msgblockhdr_zcash zH;
    uint32_t txn_count;
} __attribute__((packed));

struct iguana_msgvin { bits256 prev_hash; uint8_t *vinscript,*spendscript,*redeemscript; uint32_t prev_vout,sequence; uint16_t scriptlen,p2shlen,suffixlen,spendlen; } __attribute__((packed));

struct iguana_msgvout { uint64_t value; uint32_t pk_scriptlen; uint8_t *pk_script; } __attribute__((packed));

struct iguana_msgtx
{
    uint32_t version,tx_in,tx_out,lock_time;
    struct iguana_msgvin *vins;
    struct iguana_msgvout *vouts;
    bits256 txid;
    int32_t allocsize,timestamp;
} __attribute__((packed));

struct iguana_msgjoinsplit
{
    uint64_t vpub_old,vpub_new;
    bits256 anchor,nullifiers[2],commitments[2],ephemeralkey;
    uint8_t ciphertexts[2][217];
    bits256 randomseed,vmacs[2];
    uint8_t zkproof[ZKSNARK_PROOF_SIZE-1];
} __attribute__((packed));

struct iguana_packet { struct queueitem DL; struct iguana_peer *addr; struct tai embargo; int32_t datalen,getdatablock; uint8_t serialized[]; };

struct msgcounts { uint32_t version,verack,getaddr,addr,inv,getdata,notfound,getblocks,getheaders,headers,tx,block,mempool,ping,pong,reject,filterload,filteradd,filterclear,merkleblock,alert; };

struct iguana_fileitem { bits256 hash2; struct iguana_txdatabits txdatabits; };

struct iguana_kvitem { UT_hash_handle hh; uint8_t keyvalue[]; };// __attribute__((packed));

struct iguana_iAddr
{
    UT_hash_handle hh; uint64_t ipbits;
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
    uint16_t txn_count,numvouts,numvins,allocsize;
} __attribute__((packed));

struct iguana_zcashRO { bits256 bignonce; uint32_t solution[ZCASH_SOLUTION_ELEMENTS]; } __attribute__((packed));

struct iguana_zblockRO
{
    struct iguana_blockRO RO;
    struct iguana_zcashRO zRO;
} __attribute__((packed));

#define iguana_blockfields      double PoW; \
int32_t height,fpos; uint32_t fpipbits,issued,lag:20,peerid:12; \
uint16_t hdrsi:15,mainchain:1,bundlei:11,valid:1,queued:1,txvalid:1,newtx:1,processed:1; \
UT_hash_handle hh; struct iguana_bundlereq *req; \
struct iguana_blockRO RO

struct iguana_block
{
    iguana_blockfields;
    struct iguana_zcashRO zRO[];
} __attribute__((packed));

struct iguana_zblock // mu
{
    iguana_blockfields;
    struct iguana_zcashRO zRO;
} __attribute__((packed));

#define IGUANA_LHASH_BLOCKS 0
#define IGUANA_LHASH_TXIDS 1 //
#define IGUANA_LHASH_UNSPENTS 2 //
#define IGUANA_LHASH_SPENDS 3 //
#define IGUANA_LHASH_PKHASHES 4 //
#define IGUANA_LHASH_ACCOUNTS 5 //
#define IGUANA_LHASH_EXTERNALS 6 //
#define IGUANA_LHASH_KSPACE 7 //
#define IGUANA_LHASH_TXBITS 8 //
#define IGUANA_LHASH_PKBITS 9 //
#define IGUANA_NUMLHASHES (IGUANA_LHASH_PKBITS + 1)

struct iguana_counts
{
    uint32_t firsttxidind,firstunspentind,firstspendind,firstpkind;
    uint64_t credits,debits;
    struct iguana_block block;
} __attribute__((packed));

struct iguana_blocks
{
    char coin[8];
	struct iguanakv *db;
    struct iguana_block *hash; //struct iguana_blockRO *RO; int32_t maxbits;
    int32_t maxblocks,initblocks,hashblocks,pending,issuedblocks,recvblocks,emitblocks,parsedblocks,dirty;
	struct iguana_zblock hwmchain,prev,prev2;
};

struct iguana_ledger
{
    struct iguana_counts snapshot;
    //struct iguana_account accounts[];
} __attribute__((packed));

// ramchain temp file structures
struct iguana_unspent20 { uint64_t value; uint32_t scriptpos,txidind:28,type:4; uint16_t scriptlen,fileid; uint8_t rmd160[20]; } __attribute__((packed));
struct iguana_spend256 { bits256 prevhash2; uint64_t scriptpos:48,vinscriptlen:16; uint32_t sequenceid; int16_t prevout; uint16_t spendind,fileid; } __attribute__((packed));

// permanent readonly structs
struct iguana_txid { bits256 txid; uint32_t txidind:29,firstvout:28,firstvin:28,bundlei:11,locktime,version,timestamp,extraoffset; uint16_t numvouts,numvins; } __attribute__((packed));

struct iguana_unspent { uint64_t value; uint32_t txidind,pkind,prevunspentind,scriptpos; uint16_t scriptlen,hdrsi; uint16_t fileid:11,type:5; int16_t vout; } __attribute__((packed));

struct iguana_spend { uint64_t scriptpos:48,scriptlen:16; uint32_t spendtxidind,sequenceid; int16_t prevout; uint16_t fileid:15,external:1; } __attribute__((packed)); // numsigs:4,numpubkeys:4,p2sh:1,sighash:4

struct iguana_pkhash { uint8_t rmd160[20]; uint32_t pkind; } __attribute__((packed)); //firstunspentind,pubkeyoffset

// dynamic
struct iguana_account { int64_t total; uint32_t lastunspentind; } __attribute__((packed));
struct iguana_utxo { uint32_t fromheight:31,lockedflag:1,prevunspentind:31,spentflag:1; } __attribute__((packed));
struct iguana_hhaccount { UT_hash_handle hh; uint64_t pval; struct iguana_account a; } __attribute__((packed));
struct iguana_hhutxo { UT_hash_handle hh; uint64_t uval; struct iguana_utxo u; } __attribute__((packed));

// GLOBAL one zero to non-zero write (unless reorg)
struct iguana_spendvector { uint64_t value; uint32_t pkind,unspentind; int32_t fromheight; uint16_t hdrsi:15,tmpflag:1; } __attribute__((packed)); // unspentind
//struct iguana_pkextra { uint32_t firstspendind; } __attribute__((packed)); // pkind

struct iguana_txblock
{
    uint32_t numtxids,numunspents,numspends,extralen,recvlen;
    // following set during second pass (still in peer context)
    uint32_t numpkinds,numexternaltxids,datalen,pkoffset;
    uint8_t space[256]; // order: extra[], T, U, S, P, external txids
    struct iguana_zblock zblock;
};

#define RAMCHAIN_PTR(rdata,offset) ((void *)(long)((long)(rdata) + (long)(rdata)->offset))
struct iguana_ramchaindata
{
    bits256 sha256;
    bits256 lhashes[IGUANA_NUMLHASHES],firsthash2,prevhash2;
    int64_t allocsize,Boffset,Toffset,Uoffset,Soffset,Poffset,Aoffset,Xoffset,TXoffset,PKoffset,Koffset;
    int32_t numblocks,height,firsti,hdrsi,txsparsebits,pksparsebits;
    uint32_t numtxids,numunspents,numspends,numpkinds,numexternaltxids,numtxsparse,numpksparse,scriptspace,stackspace;
    uint8_t rdata[];
};

struct iguana_ramchain_hdr
{
    uint32_t txidind,unspentind,spendind,scriptoffset,stacksize; uint16_t hdrsi,bundlei:15,ROflag:1;
    struct iguana_ramchaindata *data;
};

struct iguana_ramchain
{
    struct iguana_ramchain_hdr H; bits256 lasthash2; uint64_t datasize,allocatedA2,allocatedU2;
    uint32_t numblocks:31,expanded:1,pkind,externalind,height,numXspends;
    long sparseadds,sparsesearches,sparseadditers,sparsesearchiters,sparsehits,sparsemax;
    struct iguana_kvitem *txids,*pkhashes;
    struct OS_memspace *hashmem; long filesize,sigsfilesize,debitsfilesize,lastspendsfilesize;
    void *fileptr,*sigsfileptr,*Xspendptr,*debitsfileptr,*lastspendsfileptr;
    char from_ro,from_roX,from_roA,from_roU;
    struct iguana_account *A,*A2,*creditsA; struct iguana_spendvector *Xspendinds;
    struct iguana_utxo *Uextras; uint8_t *txbits; struct iguana_txid *cacheT;
    //int16_t permutation[IGUANA_MAXBUNDLES];
    //struct iguana_Uextra *U2,*roU2; struct iguana_pkextra *P2,*roP2;
};

struct iguana_peer
{
    struct queueitem DL;
    queue_t sendQ;
    bits256 iphash,pubkey,persistent; uint32_t lastpersist; uint8_t netmagic[4];
    struct iguana_msgaddress A;
    char ipaddr[64],lastcommand[16],coinname[64],symbol[64];
    uint64_t pingnonce,totalsent,totalrecv,ipbits; double pingtime,sendmillis,pingsum,getdatamillis;
    uint32_t lastcontact,sendtime,ready,startsend,startrecv,pending,lastgotaddr,lastblockrecv,pendtime,lastflush,lastpoll,myipbits,persistent_peer,protover;
    int32_t supernet,basilisk,dead,addrind,usock,lastheight,relayflag,numpackets,numpings,ipv6,height,rank,pendhdrs,pendblocks,recvhdrs,lastlefti,validpub,othervalid,dirty[2],laggard,headerserror;
    double recvblocks,recvtotal;
    int64_t allocated,freed;
    bits256 RThashes[IGUANA_MAXBUNDLESIZE]; int32_t numRThashes;
    struct msgcounts msgcounts;
    struct OS_memspace RAWMEM,TXDATA,HASHMEM;
    struct iguana_ramchain ramchain;
    struct iguana_fileitem *filehash2; int32_t numfilehash2,maxfilehash2;
    //struct iguana_bundle *bp;
    FILE *voutsfp,*vinsfp;
    uint8_t *blockspace;//[IGUANA_MAXPACKETSIZE + 8192];
#ifdef IGUANA_PEERALLOC
    struct OS_memspace *SEROUT[128];
#endif
};

struct iguana_peers
{
    bits256 lastrequest;
    struct iguana_peer active[IGUANA_MAXPEERS+1],*ranked[IGUANA_MAXPEERS+1],*localaddr;
    struct iguana_thread *peersloop,*recvloop; pthread_t *acceptloop;
    double topmetrics[IGUANA_MAXPEERS+1],avemetric;
    long vinptrs[IGUANA_MAXPEERS+1][2],voutptrs[IGUANA_MAXPEERS+1][2];
    uint32_t numranked,mostreceived,shuttingdown,lastpeer,lastmetrics,numconnected;
    int32_t numfiles;
};

struct iguana_bloom16 { uint8_t hash2bits[65536 / 8]; };
struct iguana_bloominds { uint16_t inds[8]; };

struct iguana_bundle
{
    struct queueitem DL; struct iguana_info *coin; struct iguana_bundle *nextbp;
    struct iguana_bloom16 bloom; int64_t totaldurations,duplicatedurations; int32_t durationscount,duplicatescount;
    uint32_t issuetime,hdrtime,emitfinish,mergefinish,purgetime,queued,startutxo,utxofinish,balancefinish,validated,lastspeculative,dirty,nexttime,currenttime,lastprefetch,lastRT,missingstime,unsticktime,converted;
    int32_t numhashes,numrecv,numsaved,numcached,generrs,currentflag,origmissings,numissued,Xvalid;
    int32_t minrequests,n,hdrsi,bundleheight,numtxids,numspends,numunspents,numspec,isRT;
    double avetime,threshold,metric; uint64_t datasize,estsize;
    struct iguana_block *blocks[IGUANA_MAXBUNDLESIZE];
    uint8_t *speculativecache[IGUANA_MAXBUNDLESIZE],haveblock[IGUANA_MAXBUNDLESIZE/3+1];
    uint32_t issued[IGUANA_MAXBUNDLESIZE];
    bits256 prevbundlehash2,hashes[IGUANA_MAXBUNDLESIZE+1],nextbundlehash2,allhash,*speculative,validatehash;
    struct iguana_ramchain ramchain; uint8_t red,green,blue;
    struct iguana_spendvector *tmpspends; int32_t numtmpspends;
};

struct iguana_bundlereq
{
    struct queueitem DL; struct iguana_info *coin; int32_t type;
    struct iguana_peer *addr; struct iguana_zblock *blocks; bits256 *hashes,txid;
    struct iguana_txdatabits txdatabits;
    struct iguana_msghdr H;
    int32_t allocsize,datalen,n,recvlen,numtx; uint32_t ipbits;
    struct iguana_zblock zblock;
    uint8_t copyflag,serializeddata[];
};

struct iguana_bitmap { int32_t width,height,amplitude; char name[52]; uint8_t data[IGUANA_WIDTH*IGUANA_HEIGHT*3]; };

struct iguana_waddress { UT_hash_handle hh; uint64_t balance,*unspents; uint32_t maxunspents,numunspents; uint16_t scriptlen; uint8_t rmd160[20],pubkey[33],wiftype,addrtype; bits256 privkey; char symbol[8],coinaddr[36],wifstr[54]; uint8_t redeemScript[]; };
struct iguana_waccount { UT_hash_handle hh; char account[128]; struct iguana_waddress *waddr,*current; };
struct iguana_wallet { UT_hash_handle hh; struct iguana_waccount *wacct; };

struct scriptinfo { UT_hash_handle hh; uint32_t fpos; uint16_t scriptlen; uint8_t script[]; };
struct hhbits256 { UT_hash_handle hh; bits256 txid; int32_t height; uint16_t firstvout; };

struct iguana_monitorinfo { bits256 txid; int32_t numreported; uint8_t peerbits[IGUANA_MAXPEERS >> 3]; };


struct iguana_info
{
    UT_hash_handle hh;
    char name[64],symbol[64],protocol,statusstr[512],scriptsfname[2][512];
    struct iguana_peers *peers; struct iguana_peer internaladdr;
    basilisk_func basilisk_rawtx,basilisk_balances,basilisk_value;
    basilisk_metricfunc basilisk_rawtxmetric,basilisk_balancesmetric,basilisk_valuemetric;
    
    uint32_t fastfind; FILE *fastfps[0x100]; uint8_t *fast[0x100]; int32_t *fasttables[0x100]; long fastsizes[0x100];
    uint64_t instance_nonce,myservices,totalsize,totalrecv,totalpackets,sleeptime;
    int64_t mining,totalfees,TMPallocated,MAXRECVCACHE,MAXMEM,PREFETCHLAG,estsize,activebundles;
    int32_t MAXPEERS,MAXPENDINGREQUESTS,MAXBUNDLES,MAXSTUCKTIME,active,closestbundle,numemitted,lastsweep,numemit,startutc,newramchain,numcached,cachefreed,helperdepth,startPEND,endPEND,enableCACHE,RELAYNODE,VALIDATENODE,origbalanceswritten,balanceswritten,RTheight,RTdatabad;
    bits256 balancehash,allbundles;
    uint32_t lastsync,parsetime,numiAddrs,lastpossible,bundlescount,savedblocks,backlog,spendvectorsaved,laststats,lastinv2,symbolcrc; char VALIDATEDIR[512];
    int32_t longestchain,badlongestchain,longestchain_strange,RTramchain_busy,emitbusy,stuckiters,virtualchain;
    struct tai starttime; double startmillis;
    struct iguana_chain *chain;
    struct iguana_iAddr *iAddrs;
    void *ctx;
    struct iguana_bitmap *screen;
    struct OS_memspace TXMEM,MEM,MEMB[IGUANA_MAXBUNDLESIZE];
    queue_t acceptQ,hdrsQ,blocksQ,priorityQ,possibleQ,cacheQ,recvQ,msgrequestQ;
    double parsemillis,avetime; uint32_t Launched[8],Terminated[8];
    portable_mutex_t peers_mutex,blocks_mutex;
    char changeaddr[64];
    struct iguana_bundle *bundles[IGUANA_MAXBUNDLES],*current,*lastpending;
    struct iguana_ramchain RTramchain; struct OS_memspace RTmem,RThashmem; bits256 RThash1;
    int32_t numremain,numpendings,zcount,recvcount,bcount,pcount,lastbundle,numsaved,pendbalances,numverified,blockdepth;
    uint32_t recvtime,hdrstime,backstoptime,lastbundletime,numreqsent,numbundlesQ,lastbundleitime,lastdisp,RTgenesis,firstRTgenesis,RTstarti,idletime,stucktime,stuckmonitor,maxstuck,lastreqtime,RThdrstime,nextchecked;
    double bandwidth,maxbandwidth,backstopmillis; bits256 backstophash2; int64_t spaceused;
    int32_t initialheight,mapflags,minconfirms,numrecv,bindsock,isRT,backstop,blocksrecv,merging,polltimeout,numreqtxids,allhashes,balanceflush; bits256 reqtxids[64];
    void *launched,*started,*rpcloop;
    uint64_t bloomsearches,bloomhits,bloomfalse,collisions,txfee_perkb,txfee;
    uint8_t *blockspace; int32_t blockspacesize; struct OS_memspace blockMEM;
    bits256 APIblockhash,APItxid; char *APIblockstr;
    struct iguana_hhutxo *utxotable; struct iguana_hhaccount *accountstable; char lastdispstr[2048];
    double txidfind_totalmillis,txidfind_num,spendtxid_totalmillis,spendtxid_num;
    struct iguana_monitorinfo monitoring[256];
    struct gecko_sequences SEQ;
    struct iguana_blocks blocks;
};

struct vin_signer { bits256 privkey; char coinaddr[64]; uint8_t siglen,sig[80],rmd160[20],pubkey[66]; };

struct vin_info
{
    struct iguana_msgvin vin; uint64_t amount; cJSON *extras; bits256 sigtxid;
    int32_t M,N,validmask,spendlen,type,p2shlen,suffixlen,numpubkeys,numsigs,height,hashtype;
    uint32_t sequence,unspentind; struct vin_signer signers[16]; char coinaddr[65];
    uint8_t rmd160[20],spendscript[IGUANA_MAXSCRIPTSIZE],p2shscript[IGUANA_MAXSCRIPTSIZE];
};

struct bitcoin_unspent
{
    bits256 txid,privkeys[16]; uint64_t value; int32_t vout,spendlen,p2shlen,numpubkeys; uint32_t sequence;
    uint8_t addrtype,rmd160[20],pubkeys[16][65],spendscript[IGUANA_MAXSCRIPTSIZE],p2shscript[IGUANA_MAXSCRIPTSIZE];
};

struct bitcoin_spend
{
    char changeaddr[64]; uint8_t change160[20];
    int32_t numinputs;
    int64_t txfee,input_satoshis,satoshis,change;
    struct bitcoin_unspent inputs[];
};

struct exchange_quote { uint64_t satoshis,orderid,offerNXT,exchangebits; double price,volume; uint32_t timestamp,val; };

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
    int32_t maxdelay,IAMRELAY,publicRPC;
    uint32_t expiration,dirty;
    uint16_t argport,rpcport;
    struct basilisk_info basilisks;
    struct exchange_info *tradingexchanges[SUPERNET_MAXEXCHANGES]; int32_t numexchanges;
    struct iguana_waccount *wallet;
    struct iguana_info *allcoins; int32_t allcoins_being_added,allcoins_numvirts; portable_mutex_t allcoins_mutex;
    void *ctx;
    
    // compatibility
    bits256 pangea_category,instantdex_category;
};
#endif

