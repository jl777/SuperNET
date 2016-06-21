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

#ifndef H_IGUANAFUNCS_H
#define H_IGUANAFUNCS_H
// peers
int32_t iguana_verifypeer(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize);
int32_t iguana_peermetrics(struct supernet_info *myinfo,struct iguana_info *coin);
void iguana_peersloop(void *arg);
int32_t iguana_queue_send(struct iguana_peer *addr,int32_t delay,uint8_t *serialized,char *cmd,int32_t len);
uint32_t iguana_rwiAddrind(struct iguana_info *coin,int32_t rwflag,struct iguana_iAddr *iA,uint32_t ind);
void iguana_connections(void *arg);
uint32_t iguana_possible_peer(struct iguana_info *coin,char *ip_port);
//int32_t iguana_set_iAddrheight(struct iguana_info *coin,uint32_t ipbits,int32_t height);
//struct iguana_peer *iguana_choosepeer(struct iguana_info *coin);
void iguana_initpeer(struct iguana_info *coin,struct iguana_peer *addr,uint64_t ipbits);
void iguana_startconnection(void *arg);
void iguana_shutdownpeers(struct iguana_info *coin,int32_t forceflag);
void iguana_acceptloop(void *args);
void iguana_recvloop(void *args);
int32_t iguana_send(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *serialized,int32_t len);
uint32_t iguana_updatemetrics(struct supernet_info *myinfo,struct iguana_info *coin);
void *iguana_peeralloc(struct iguana_info *coin,struct iguana_peer *addr,int32_t datalen);
int64_t iguana_peerfree(struct iguana_info *coin,struct iguana_peer *addr,void *ptr,int32_t datalen);
int64_t iguana_peerallocated(struct iguana_info *coin,struct iguana_peer *addr);

// serdes
int32_t iguana_rwmem(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp);
int32_t iguana_rwnum(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp);
int32_t iguana_rwvarint32(int32_t rwflag,uint8_t *serialized,uint32_t *int32p);
int32_t iguana_rwbignum(int32_t rwflag,uint8_t *serialized,int32_t len,uint8_t *endianedp);
int32_t iguana_rwblock(char *symbol,uint8_t zcash,uint8_t auxpow,int32_t (*hashalgo)(uint8_t *blockhashp,uint8_t *serialized,int32_t len),int32_t rwflag,bits256 *hash2p,uint8_t *serialized,struct iguana_msgblock *msg,int32_t maxlen);
int32_t iguana_serialize_block(struct iguana_chain *chain,bits256 *hash2p,uint8_t serialized[sizeof(struct iguana_msgblock)],struct iguana_block *block);
void iguana_blockconv(uint8_t zcash,uint8_t auxpow,struct iguana_block *dest,struct iguana_msgblock *msg,bits256 hash2,int32_t height);
//void iguana_freetx(struct iguana_msgtx *tx,int32_t n);
int32_t iguana_msgparser(struct iguana_info *coin,struct iguana_peer *addr,struct OS_memspace *rawmem,struct OS_memspace *txmem,struct OS_memspace *hashmem,struct iguana_msghdr *H,uint8_t *data,int32_t datalen);

// send message
int32_t iguana_validatehdr(char *symbol,struct iguana_msghdr *H);
int32_t iguana_sethdr(struct iguana_msghdr *H,const uint8_t netmagic[4],char *command,uint8_t *data,int32_t datalen);
int32_t iguana_send_version(struct iguana_info *coin,struct iguana_peer *addr,uint64_t myservices);
int32_t iguana_gentxarray(struct iguana_info *coin,struct OS_memspace *mem,struct iguana_txblock *txblock,int32_t *lenp,uint8_t *data,int32_t datalen);
int32_t iguana_gethdrs(struct iguana_info *coin,uint8_t *serialized,char *cmd,char *hashstr);
int32_t iguana_getdata(struct iguana_info *coin,uint8_t *serialized,int32_t type,bits256 *hashes,int32_t n);
void iguana_blockunconv(uint8_t zcash,uint8_t auxpow,struct iguana_msgblock *msg,struct iguana_block *src,int32_t cleartxn_count);
int32_t iguana_peerblockrequest(struct iguana_info *coin,uint8_t *blockspace,int32_t max,struct iguana_peer *addr,bits256 hash2,int32_t validatesigs);
int32_t iguana_validatesigs(struct iguana_info *coin,struct iguana_msgvin *vin);

// ramchain
int64_t iguana_verifyaccount(struct iguana_info *coin,struct iguana_account *acct,uint32_t pkind);
int32_t iguana_initramchain(struct iguana_info *coin,int32_t initialheight,int32_t mapflags,int32_t fullverify);
void iguana_syncramchain(struct iguana_info *coin);
//int32_t iguana_validateramchain(struct iguana_info *coin,int64_t *netp,uint64_t *creditsp,uint64_t *debitsp,int32_t height,struct iguana_block *block,int32_t hwmheight,struct iguana_prevdep *lp);
int32_t iguana_calcrmd160(struct iguana_info *coin,char *asmstr,struct vin_info *vp,uint8_t *pk_script,int32_t pk_scriptlen,bits256 debugtxid,int32_t vout,uint32_t sequence);
uint32_t iguana_updatescript(struct iguana_info *coin,uint32_t blocknum,uint32_t txidind,uint32_t spendind,uint32_t unspentind,uint64_t value,uint8_t *script,int32_t scriptlen,uint32_t sequence);
void iguana_gotblockM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *txdata,struct iguana_msgtx *txarray,struct iguana_msghdr *H,uint8_t *data,int32_t datalen);
int32_t iguana_parseblock(struct iguana_info *coin,struct iguana_block *block,struct iguana_msgtx *tx,int32_t numtx);
uint32_t iguana_txidind(struct iguana_info *coin,uint32_t *firstvoutp,uint32_t *firstvinp,bits256 txid);
bits256 iguana_txidstr(struct iguana_info *coin,uint32_t *firstvoutp,uint32_t *firstvinp,char *txidstr,uint32_t txidind);
int32_t iguana_updateramchain(struct iguana_info *coin);
//void iguana_emittxarray(struct iguana_info *coin,FILE *fp,struct iguana_bundle *bundle,struct iguana_block *block,struct iguana_msgtx *txarray,int32_t numtx);

// blockchain
int32_t iguana_needhdrs(struct iguana_info *coin);
struct iguana_chain *iguana_chainfind(char *name,cJSON *argjson,int32_t createflag);
int32_t iguana_chainextend(struct iguana_info *coin,struct iguana_block *newblock);
uint64_t iguana_miningreward(struct iguana_info *coin,uint32_t blocknum);

// tx
int32_t iguana_rwtx(uint8_t zcash,int32_t rwflag,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgtx *msg,int32_t maxsize,bits256 *txidp,int32_t hastimestamp,int32_t isvpncoin);
void iguana_gottxidsM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *txids,int32_t n);
void iguana_gotquotesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *quotes,int32_t n);
void iguana_gotunconfirmedM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgtx *tx,uint8_t *data,int32_t datalen);
void iguana_gotblockhashesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *blockhashes,int32_t n);

// blocks
bits256 iguana_blockhash(struct iguana_info *coin,int32_t height);
#define iguana_blockfind(str,coin,hash2) iguana_blockhashset(str,coin,-1,hash2,0)
struct iguana_block *iguana_blockhashset(char *debugstr,struct iguana_info *coin,int32_t height,bits256 hash2,int32_t createflag);
struct iguana_block *iguana_prevblock(struct iguana_info *coin,struct iguana_block *block,int32_t PoSflag);
uint32_t iguana_targetbits(struct iguana_info *coin,struct iguana_block *hwmchain,struct iguana_block *prev,struct iguana_block *prev2,int32_t PoSflag,int32_t targetspacing,int32_t targettimespan);

uint32_t iguana_syncs(struct iguana_info *coin);
void iguana_gotdata(struct iguana_info *coin,struct iguana_peer *addr,int32_t height);
//int64_t iguana_getbalance(struct iguana_info *coin,uint64_t *creditsp,uint64_t *debitsp,int32_t *nump,uint32_t *unspents,long max,struct iguana_pkhash *P,uint32_t pkind);
int32_t iguana_queueblock(struct iguana_info *coin,int32_t height,bits256 hash2,int32_t priority);
int32_t iguana_updatewaiting(struct iguana_info *coin,int32_t starti,int32_t max);

// recvbits
int32_t iguana_recvinit(struct iguana_info *coin,int32_t initialheight);
int32_t ramcoder_decompress(uint8_t *data,int32_t maxlen,uint8_t *bits,uint32_t numbits,bits256 seed);
int32_t ramcoder_compress(uint8_t *bits,int32_t maxlen,uint8_t *data,int32_t datalen,bits256 seed);
uint64_t hconv_bitlen(uint64_t bitlen);
struct iguana_block *iguana_blockptr(char *debugstr,struct iguana_info *coin,int32_t height);
int32_t iguana_processrecv(struct supernet_info *myinfo,struct iguana_info *coin); // single threaded
//void iguana_recvalloc(struct iguana_info *coin,int32_t numitems);
void iguana_coins(void *arg);
int32_t iguana_savehdrs(struct iguana_info *coin);

// hdrs
struct iguana_bundle *iguana_bundlecreate(struct iguana_info *coin,int32_t *bundleip,int32_t bundleheight,bits256 bundlehash2,bits256 allhash,int32_t issueflag);
struct iguana_block *iguana_updatehdrs(struct iguana_info *coin,int32_t *newhwmp,struct iguana_block *block,bits256 prevhash2,bits256 hash2);
void iguana_parseline(struct iguana_info *coin,int32_t iter,FILE *fp);
void iguana_gotheadersM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_zblock *zblocks,int32_t n);
void iguana_emittxdata(struct iguana_info *coin,struct iguana_bundle *bp);
int32_t iguana_pollQsPT(struct iguana_info *coin,struct iguana_peer *addr);
int32_t iguana_avail(struct iguana_info *coin,int32_t height,int32_t n);
int32_t iguana_updatebundles(struct iguana_info *coin);
void iguana_bundlestats(struct iguana_info *coin,char *str,int32_t lag);
void iguana_chaininit(struct iguana_chain *chain,int32_t hasheaders,cJSON *argjson);
void iguana_coinargs(char *symbol,int64_t *maxrecvcachep,int32_t *minconfirmsp,int32_t *maxpeersp,int32_t *initialheightp,uint64_t *servicesp,int32_t *maxrequestsp,int32_t *maxbundlesp,cJSON *json);
struct iguana_info *iguana_setcoin(char *symbol,void *launched,int32_t maxpeers,int64_t maxrecvcache,uint64_t services,int32_t initialheight,int32_t maphash,int32_t minconfirms,int32_t maxrequests,int32_t maxbundles,cJSON *json);

// init
struct iguana_info *iguana_coinstart(struct iguana_info *coin,int32_t initialheight,int32_t mapflags);
void iguana_callcoinstart(struct supernet_info *myinfo,struct iguana_info *coin);
void iguana_initcoin(struct iguana_info *coin,cJSON *argjson);
void iguana_coinloop(void *arg);

// utils
double PoW_from_compact(uint32_t nBits,uint8_t unitval);
void calc_rmd160(char *hexstr,uint8_t buf[20],uint8_t *msg,int32_t len);
void calc_OP_HASH160(char *hexstr,uint8_t hash160[20],char *msg);
double dxblend(double *destp,double val,double decay);

// json
int32_t iguana_processjsonQ(struct iguana_info *coin); // reentrant, can be called during any idletime
char *iguana_JSON(char *,uint16_t port);
char *SuperNET_p2p(struct iguana_info *coin,struct iguana_peer *addr,int32_t *delaymillisp,char *ipaddr,uint8_t *data,int32_t datalen,int32_t compressed);

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

struct iguana_helper { struct queueitem DL; void *coin,*addr,*bp,*nextbp,*fp; long fpos; int32_t allocsize,type,hdrsi,bundlei,datalen,timelimit; uint32_t starttime; };
int32_t iguana_helpertask(FILE *fp,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_helper *ptr);
void iguana_flushQ(struct iguana_info *coin,struct iguana_peer *addr);
//struct iguana_txdatabits iguana_peerfilePT(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2,struct iguana_txdatabits txdatabits,int32_t recvlen);
struct iguana_txdatabits iguana_calctxidbits(uint32_t addrind,uint32_t filecount,uint32_t fpos,uint32_t datalen);
int32_t iguana_bundlesaveHT(struct supernet_info *myinfo,struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_bundle *bp,uint32_t starttime); // helper thread
int32_t iguana_bundlemergeHT(struct supernet_info *myinfo,char *fname,struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_bundle *bp,struct iguana_bundle *nextbp,uint32_t starttime); // helper thread

void iguana_peerfilename(struct iguana_info *coin,char *fname,uint32_t addrind,uint32_t filecount);

struct iguana_txblock *iguana_ramchainptrs(struct iguana_txid **Tptrp,struct iguana_unspent20 **Uptrp,struct iguana_spend256 **Sptrp,struct iguana_pkhash **Pptrp,bits256 **externalTptrp,struct OS_memspace *mem,struct iguana_txblock *origtxdata);

int32_t iguana_ramchainsave(struct iguana_info *coin,struct iguana_ramchain *ramchain);
int32_t iguana_ramchainfree(struct iguana_info *coin,struct OS_memspace *mem,struct iguana_ramchain *ramchain);
struct iguana_ramchain *iguana_ramchainmergeHT(struct iguana_info *coin,struct OS_memspace *mem,struct iguana_ramchain *ramchains[],int32_t n,struct iguana_bundle *bp);
void iguana_ramchainmerge(struct iguana_info *coin);

int32_t iguana_blockQ(char *argstr,struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t priority);
void iguana_blockcopy(uint8_t zcash,uint8_t auxpow,struct iguana_info *coin,struct iguana_block *block,struct iguana_block *origblock);
int32_t iguana_rpctest(struct iguana_info *coin);
extern queue_t helperQ;
extern const char *Hardcoded_coins[][3];
void iguana_main(void *arg);

int32_t iguana_peerfname(struct iguana_info *coin,int32_t *hdrsip,char *dirname,char *fname,uint32_t ipbits,bits256 hash2,bits256 prevhash2,int32_t numblocks,int32_t dispflag);
struct iguana_txblock *iguana_peertxdata(struct iguana_info *coin,int32_t *bundleip,char *fname,struct OS_memspace *mem,uint32_t ipbits,bits256 hash2);
int32_t iguana_peerfile_exists(struct iguana_info *coin,struct iguana_peer *addr,char *dirname,char *fname,bits256 hash2,bits256 prevhash2,int32_t numblocks);
struct iguana_ramchain *iguana_ramchainset(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct iguana_txblock *txdata);
void *iguana_iAddriterator(struct iguana_info *coin,struct iguana_iAddr *iA);
long iguana_ramchain_data(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *origtxdata,struct iguana_msgtx *txarray,int32_t txn_count,uint8_t *data,int32_t recvlen);
int32_t iguana_bundlehash2add(struct iguana_info *coin,struct iguana_block **blockp,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2);
struct iguana_block *iguana_bundleblockadd(struct iguana_info *coin,struct iguana_bundle **bpp,int32_t *bundleip,struct iguana_block *origblock);
int32_t iguana_chainextend(struct iguana_info *coin,struct iguana_block *newblock);
int32_t iguana_blockvalidate(struct iguana_info *coin,int32_t *validp,struct iguana_block *block,int32_t dispflag);
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
//int32_t btc_addr2univ(uint8_t *addrtypep,uint8_t rmd160[20],char *coinaddr);

struct iguana_agent
{
    char name[32],hostname[64]; void *methods; uint16_t port; int32_t sock,nummethods;
    bits256 pubkey,privkey;
    char *(*parsefunc)(struct iguana_agent *agent,char *method,void *json,char *remoteaddr);
};

int32_t iguana_txbytes(struct iguana_info *coin,uint8_t *serialized,int32_t maxlen,bits256 *txidp,struct iguana_txid *tx,int32_t height,struct iguana_msgvin *vins,struct iguana_msgvout *vouts);
int32_t iguana_vinset(struct iguana_info *coin,uint8_t *scriptspace,int32_t height,struct iguana_msgvin *vin,struct iguana_txid *tx,int32_t i);
int32_t iguana_voutset(struct iguana_info *coin,uint8_t *scriptspace,char *asmstr,int32_t height,struct iguana_msgvout *vout,struct iguana_txid *tx,int32_t i);
//int32_t btc_convrmd160(char *coinaddr,uint8_t addrtype,uint8_t rmd160[20]);
struct iguana_txid *iguana_bundletx(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,struct iguana_txid *tx,int32_t txidind);
int32_t iguana_txidreq(struct iguana_info *coin,char **retstrp,bits256 txid);
void iguana_bundleiclear(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei);
int32_t hcalc_bitsize(uint64_t x);
struct iguana_txid *iguana_txidfind(struct iguana_info *coin,int32_t *heightp,struct iguana_txid *tx,bits256 txid,int32_t lasthdrsi);
int32_t iguana_scriptgen(struct iguana_info *coin,int32_t *Mp,int32_t *nump,char *coinaddr,uint8_t *script,char *asmstr,uint8_t rmd160[20],uint8_t type,const struct vin_info *vp,int32_t txi);
int32_t iguana_ramchain_spendtxid(struct iguana_info *coin,uint32_t *unspentindp,bits256 *txidp,struct iguana_txid *T,int32_t numtxids,bits256 *X,int32_t numexternaltxids,struct iguana_spend *s);
void iguana_dedicatedloop(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr);
struct iguana_peer *iguana_peerslot(struct iguana_info *coin,uint64_t ipbits,int32_t forceflag);
void iguana_dedicatedglue(void *arg);
void SuperNET_remotepeer(struct supernet_info *myinfo,struct iguana_info *coin,char *symbol,char *ipaddr,int32_t supernetflag);
void SuperNET_yourip(struct supernet_info *myinfo,char *yourip);
void iguana_peerkill(struct iguana_info *coin);
int32_t blockhash_sha256(uint8_t *blockhashp,uint8_t *serialized,int32_t len);
void iguana_nameset(char name[64],char *symbol,cJSON *json);

char *busdata_sync(uint32_t *noncep,char *jsonstr,char *broadcastmode,char *destNXTaddr);
void peggy();
int32_t opreturns_init(uint32_t blocknum,uint32_t blocktimestamp,char *path);
struct iguana_info *iguana_coinfind(char *symbol);
struct iguana_info *iguana_coinadd(char *symbol,char *nane,cJSON *json);
struct iguana_ramchain *iguana_bundleload(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct iguana_bundle *bp,int32_t extraflag);
int32_t iguana_sendblockreq(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t iamthreadsafe);
int32_t iguana_send_supernet(struct iguana_peer *addr,char *jsonstr,int32_t delay);

struct iguana_waccount *iguana_waccountfind(struct supernet_info *myinfo,struct iguana_info *coin,char *account);
struct iguana_waddress *iguana_waccountadd(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount **wacctp,char *walletaccount,char *coinaddr);
struct iguana_waddress *iguana_waccountswitch(struct supernet_info *myinfo,struct iguana_info *coin,char *account,char *coinaddr,char *redeemScript);
struct iguana_waddress *iguana_waddresscalc(struct supernet_info *myinfo,uint8_t pubval,uint8_t wiftype,struct iguana_waddress *addr,bits256 privkey);
struct iguana_waddress *iguana_waddressfind(struct supernet_info *myinfo,struct iguana_waccount *wacct,char *coinaddr);
char *iguana_coinjson(struct iguana_info *coin,char *method,cJSON *json);
cJSON *iguana_peersjson(struct iguana_info *coin,int32_t addronly);
//int32_t btc_priv2wif(char *wifstr,uint8_t privkey[32],uint8_t addrtype);
//int32_t btc_pub2rmd(uint8_t rmd160[20],uint8_t pubkey[33]);
int32_t iguana_launchcoin(struct supernet_info *myinfo,char *symbol,cJSON *json);
int32_t iguana_bundleinitmap(struct iguana_info *coin,struct iguana_bundle *bp,int32_t height,bits256 hash2,bits256 hash1);
int32_t iguana_jsonQ();
int32_t is_bitcoinrpc(struct supernet_info *myinfo,char *method,char *remoteaddr);
char *iguana_bitcoinRPC(struct supernet_info *myinfo,char *method,cJSON *json,char *remoteaddr,uint16_t port);
cJSON *iguana_pubkeyjson(struct iguana_info *coin,char *pubkeystr);
void iguana_bundleQ(struct iguana_info *coin,struct iguana_bundle *bp,int32_t timelimit);
int32_t iguana_bundleiters(struct supernet_info *myinfo,struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_bundle *bp,int32_t timelimit,int32_t lag);
void ramcoder_test(void *data,int64_t len);
void iguana_exit();
int32_t iguana_pendingaccept(struct iguana_info *coin);
char *iguana_blockingjsonstr(struct supernet_info *myinfo,char *jsonstr,uint64_t tag,int32_t maxmillis,char *remoteaddr,uint16_t port);
void iguana_iAkill(struct iguana_info *coin,struct iguana_peer *addr,int32_t markflag);
cJSON *SuperNET_bits2json(uint8_t *serialized,int32_t datalen);
int32_t SuperNET_sendmsg(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,bits256 destpub,bits256 mypriv,bits256 mypub,uint8_t *msg,int32_t len,uint8_t *data,int32_t delaymillis);
int32_t category_peer(struct supernet_info *myinfo,struct iguana_peer *addr,bits256 category,bits256 subhash);
int32_t bitcoin_wif2priv(uint8_t *addrtypep,bits256 *privkeyp,char *wifstr);
int32_t bitcoin_priv2wif(char *wifstr,bits256 privkey,uint8_t addrtype);
bits256 iguana_chaingenesis(char *symbol,uint8_t zcash,uint8_t auxpow,int32_t (*hashalgo)(uint8_t *blockhashp,uint8_t *serialized,int32_t len),bits256 genesishash,char *genesisblock,char *hashalgostr,int32_t version,uint32_t timestamp,uint32_t bits,uint32_t nonce,bits256 merkle_root);
int32_t iguana_send_ConnectTo(struct iguana_info *coin,struct iguana_peer *addr);
cJSON *iguana_txjson(struct iguana_info *coin,struct iguana_txid *tx,int32_t height,struct vin_info *V);
char *iguana_txscan(struct iguana_info *coin,cJSON *json,uint8_t *data,int32_t recvlen,bits256 txid);
char *iguana_rawtxbytes(struct iguana_info *coin,cJSON *json,struct iguana_msgtx *msgtx);
int32_t iguana_send_VPNversion(struct iguana_info *coin,struct iguana_peer *addr,uint64_t myservices);
void exchanges777_init(struct supernet_info *myinfo,cJSON *exchanges,int32_t sleepflag);
int32_t iguana_rwvout(int32_t rwflag,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgvout *msg);
int32_t iguana_rwvin(int32_t rwflag,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgvin *msg);
int32_t iguana_rwmsgtx(struct iguana_info *coin,int32_t rwflag,cJSON *json,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,bits256 *txidp,char *vpnstr,uint8_t *extraspace,int32_t extralen,cJSON *vins);
int32_t iguana_ramtxbytes(struct iguana_info *coin,uint8_t *serialized,int32_t maxlen,bits256 *txidp,struct iguana_txid *tx,int32_t height,struct iguana_msgvin *vins,struct iguana_msgvout *vouts,int32_t validatesigs);
cJSON *bitcoin_txtest(struct iguana_info *coin,char *rawtxstr,bits256 txid);
cJSON *iguana_blockjson(struct iguana_info *coin,struct iguana_block *block,int32_t txidsflag);
int32_t iguana_rwblockhdr(int32_t rwflag,uint8_t zcash,uint8_t *serialized,struct iguana_msgblock *msg);
//int32_t iguana_sig(uint8_t *sig,int32_t maxsize,uint8_t *data,int32_t datalen,bits256 privkey);
//int32_t iguana_ver(uint8_t *sig,int32_t siglen,uint8_t *data,int32_t datalen,bits256 pubkey);
//int32_t iguana_ver(uint8_t *sig,int32_t siglen,uint8_t *data,int32_t datalen,uint8_t *pubkey);
void calc_rmd160_sha256(uint8_t rmd160[20],uint8_t *data,int32_t datalen);
int32_t bitcoin_checklocktimeverify(uint8_t *script,int32_t n,uint32_t locktime);
struct bitcoin_spend *iguana_spendset(struct supernet_info *myinfo,struct iguana_info *coin,int64_t amount,int64_t txfee,cJSON *addresses,int32_t minconf);
cJSON *bitcoin_hex2json(struct iguana_info *coin,bits256 *txidp,struct iguana_msgtx *msgtx,char *txbytes,uint8_t *extrapace,int32_t extralen,uint8_t *serialized);
cJSON *iguana_signtx(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,char **signedtxp,struct bitcoin_spend *spend,cJSON *txobj,cJSON *vins);
void iguana_addscript(struct iguana_info *coin,cJSON *dest,uint8_t *script,int32_t scriptlen,char *fieldname);
bits256 iguana_genesis(struct iguana_info *coin,struct iguana_chain *chain);

cJSON *bitcoin_txcreate(int32_t isPoS,int64_t locktime,uint32_t txversion);
cJSON *bitcoin_txoutput(cJSON *txobj,uint8_t *paymentscript,int32_t len,uint64_t satoshis);
cJSON *bitcoin_txinput(struct iguana_info *coin,cJSON *txobj,bits256 txid,int32_t vout,uint32_t sequenceid,uint8_t *spendscript,int32_t spendlen,uint8_t *redeemscript,int32_t p2shlen,uint8_t *pubkeys[],int32_t numpubkeys);

int32_t bitcoin_changescript(struct iguana_info *coin,uint8_t *changescript,int32_t n,uint64_t *changep,char *changeaddr,uint64_t inputsatoshis,uint64_t satoshis,uint64_t txfee);
//cJSON *bitcoin_addinput(struct iguana_info *coin,cJSON *txobj,bits256 txid,int32_t vout,uint32_t sequenceid,uint8_t *spendscript,int32_t spendlen,uint8_t *redeemscript,int32_t p2shlen,uint8_t *pubkeys[],int32_t numpubkeys);
int32_t bitcoin_verifytx(struct iguana_info *coin,bits256 *signedtxidp,char **signedtx,char *rawtxstr,struct vin_info *V,int32_t numinputs);
int32_t bitcoin_verify(void *ctx,uint8_t *sig,int32_t siglen,bits256 txhash2,uint8_t *pubkey,int32_t plen);
char *bitcoin_json2hex(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,cJSON *txjson,struct vin_info *V);
int32_t bitcoin_addr2rmd160(uint8_t *addrtypep,uint8_t rmd160[20],char *coinaddr);
char *issue_startForging(struct supernet_info *myinfo,char *secret);
struct bitcoin_unspent *iguana_unspentsget(struct supernet_info *myinfo,struct iguana_info *coin,char **retstrp,double *balancep,int32_t *numunspentsp,double minconfirms,char *address);
void iguana_chainparms(struct iguana_chain *chain,cJSON *argjson);
int32_t iguana_pkhasharray(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,int32_t minconf,int32_t maxconf,int64_t *totalp,struct iguana_pkhash *P,int32_t max,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33,int32_t lastheight,int64_t *unspents,int32_t *numunspentsp,int32_t maxunspents);
long iguana_spentsfile(struct iguana_info *coin,int32_t n);
uint8_t *iguana_rmdarray(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *numrmdsp,cJSON *array,int32_t firsti);
int64_t iguana_unspents(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,int32_t minconf,int32_t maxconf,uint8_t *rmdarray,int32_t numrmds,int32_t lastheight,int64_t *unspents,int32_t *numunspentsp);
uint8_t *iguana_walletrmds(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *numrmdsp);
char *iguana_bundleaddrs(struct iguana_info *coin,int32_t hdrsi);
uint32_t iguana_sparseaddpk(uint8_t *bits,int32_t width,uint32_t tablesize,uint8_t rmd160[20],struct iguana_pkhash *P,uint32_t pkind,struct iguana_ramchain *ramchain);
int32_t iguana_vinscriptparse(struct iguana_info *coin,struct vin_info *vp,uint32_t *sigsizep,uint32_t *pubkeysizep,uint32_t *p2shsizep,uint32_t *suffixp,uint8_t *vinscript,int32_t scriptlen);
void iguana_parsebuf(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msghdr *H,uint8_t *buf,int32_t len);
int32_t _iguana_calcrmd160(struct iguana_info *coin,struct vin_info *vp);
int32_t iguana_spendvectors(struct iguana_info *coin,struct iguana_bundle *bp,struct iguana_ramchain *ramchain,int32_t starti,int32_t numblocks,int32_t convertflag,int32_t iterate);
int32_t iguana_balancegen(struct iguana_info *coin,int32_t incremental,struct iguana_bundle *bp,int32_t startheight,int32_t endheight,int32_t startemit);
int32_t iguana_bundlevalidate(struct iguana_info *coin,struct iguana_bundle *bp,int32_t forceflag);
void iguana_validateQ(struct iguana_info *coin,struct iguana_bundle *bp);
struct iguana_bloominds iguana_calcbloom(bits256 hash2);
int32_t iguana_bloomfind(struct iguana_info *coin,struct iguana_bloom16 *bloom,int32_t incr,struct iguana_bloominds bit);
struct iguana_bloominds iguana_bloomset(struct iguana_info *coin,struct iguana_bloom16 *bloom,int32_t incr,struct iguana_bloominds bit);
int32_t iguana_Xspendmap(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct iguana_bundle *bp);
//void iguana_balancesQ(struct iguana_info *coin,struct iguana_bundle *bp);
int32_t iguana_balanceflush(struct iguana_info *coin,int32_t refhdrsi);
int32_t iguana_bundleissue(struct iguana_info *coin,struct iguana_bundle *bp,int32_t starti,int32_t max);
int32_t iguana_balancecalc(struct iguana_info *coin,struct iguana_bundle *bp,int32_t startheight,int32_t endheight);
int32_t iguana_sendblockreqPT(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t iamthreadsafe);
int32_t iguana_blockreq(struct iguana_info *coin,int32_t height,int32_t priority);
int64_t iguana_bundlecalcs(struct iguana_info *coin,struct iguana_bundle *bp,int32_t lag);
int32_t iguana_ramchain_prefetch(struct iguana_info *coin,struct iguana_ramchain *ramchain,int32_t txonly);
int32_t iguana_realtime_update(struct supernet_info *myinfo,struct iguana_info *coin);
int32_t iguana_volatilesmap(struct iguana_info *coin,struct iguana_ramchain *ramchain);
void iguana_volatilespurge(struct iguana_info *coin,struct iguana_ramchain *ramchain);
int32_t iguana_volatilesinit(struct iguana_info *coin);
void iguana_initfinal(struct iguana_info *coin,bits256 lastbundle);
int64_t iguana_ramchainopen(char *fname,struct iguana_info *coin,struct iguana_ramchain *ramchain,struct OS_memspace *mem,struct OS_memspace *hashmem,int32_t bundleheight,bits256 hash2);
int32_t iguana_ramchain_free(struct iguana_info *coin,struct iguana_ramchain *ramchain,int32_t deleteflag);
void iguana_blocksetcounters(struct iguana_info *coin,struct iguana_block *block,struct iguana_ramchain * ramchain);
int32_t iguana_ramchain_iterate(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_ramchain *dest,struct iguana_ramchain *ramchain,struct iguana_bundle *bp,int16_t bundlei);
void *iguana_bundlefile(struct iguana_info *coin,char *fname,long *filesizep,struct iguana_bundle *bp,int32_t bundlei);
int32_t iguana_mapchaininit(char *fname,struct iguana_info *coin,struct iguana_ramchain *mapchain,struct iguana_bundle *bp,int32_t bundlei,struct iguana_block *block,void *ptr,long filesize);
void iguana_autoextend(struct iguana_info *coin,struct iguana_bundle *bp);
void iguana_RTramchainfree(struct iguana_info *coin,struct iguana_bundle *bp);
void iguana_coinpurge(struct iguana_info *coin);
int32_t iguana_setmaxbundles(struct iguana_info *coin);
void iguana_bundlepurgefiles(struct iguana_info *coin,struct iguana_bundle *bp);
uint32_t iguana_sparseaddtx(uint8_t *bits,int32_t width,uint32_t tablesize,bits256 txid,struct iguana_txid *T,uint32_t txidind,struct iguana_ramchain *ramchain);
void iguana_launchpeer(struct iguana_info *coin,char *ipaddr);
//void iguana_spendvectorsQ(struct iguana_info *coin,struct iguana_bundle *bp);
int8_t iguana_blockstatus(struct iguana_info *coin,struct iguana_block *block);
int32_t iguana_peerslotinit(struct iguana_info *coin,struct iguana_peer *addr,int32_t slotid,uint64_t ipbits);
void iguana_blockunmark(struct iguana_info *coin,struct iguana_block *block,struct iguana_bundle *bp,int32_t i,int32_t deletefile);
int32_t iguana_reqblocks(struct iguana_info *coin);
void iguana_walletlock(struct supernet_info *myinfo,struct iguana_info *coin);
int32_t _SuperNET_encryptjson(char *destfname,char *passphrase,int32_t passsize,char *fname2fa,int32_t fnamesize,cJSON *argjson);
int32_t bitcoin_pubkeylen(const uint8_t *pubkey);
struct iguana_block *iguana_bundleblock(struct iguana_info *coin,bits256 *hash2p,struct iguana_bundle *bp,int32_t i);
void *iguana_ramchainfile(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_ramchain *dest,struct iguana_ramchain *R,struct iguana_bundle *bp,int32_t bundlei,struct iguana_block *block);
int32_t iguana_bundlehashadd(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,struct iguana_block *block);
int32_t iguana_convert(struct iguana_info *coin,int32_t helperid,struct iguana_bundle *bp,int32_t RTflag,int32_t starti);
int32_t iguana_bundleissuemissing(struct iguana_info *coin,struct iguana_bundle *bp,int32_t priority,double mult);
FILE *myfopen(char *fname,char *mode);
int32_t myfclose(FILE *fp);
int32_t iguana_walkchain(struct iguana_info *coin,int32_t skipflag);
struct iguana_block *iguana_fastlink(struct iguana_info *coin,int32_t hwmheight);
int32_t iguana_balancenormal(struct iguana_info *coin,struct iguana_bundle *bp,int32_t startheight,int32_t endheight);
int32_t iguana_spendvectorsaves(struct iguana_info *coin);
int32_t iguana_convertfinished(struct iguana_info *coin);
int32_t iguana_emitfinished(struct iguana_info *coin,int32_t queueincomplete);
int32_t iguana_utxofinished(struct iguana_info *coin);
int32_t iguana_balancefinished(struct iguana_info *coin);
int32_t iguana_alloctxbits(struct iguana_info *coin,struct iguana_ramchain *ramchain);
void iguana_allocvolatile(struct iguana_info *coin,struct iguana_ramchain *ramchain);
int32_t iguana_rwaddr(int32_t rwflag,uint8_t *serialized,struct iguana_msgaddress *addr,int32_t protover);
struct iguana_bundle *iguana_bundleset(struct iguana_info *coin,struct iguana_block **blockp,int32_t *bundleip,struct iguana_block *origblock);
struct iguana_waddress *iguana_waddresscreate(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,char *coinaddr,char *redeemScript);

int32_t iguana_peerhdrrequest(struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_peer *addr,bits256 hash2);
int32_t iguana_peeraddrrequest(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *space,int32_t max);
int32_t iguana_peerdatarequest(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *space,int32_t max);
int32_t iguana_peergetrequest(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *data,int32_t recvlen,int32_t getblock);
int32_t iguana_bundlefname(struct iguana_info *coin,struct iguana_bundle *bp,char *fname);
int32_t iguana_bundleremove(struct iguana_info *coin,int32_t hdrsi,int32_t tmpfiles);
int32_t iguana_voutsfname(struct iguana_info *coin,int32_t roflag,char *fname,int32_t slotid);
int32_t iguana_vinsfname(struct iguana_info *coin,int32_t roflag,char *fname,int32_t slotid);
bits256 iguana_merkle(bits256 *tree,int32_t txn_count);
int32_t iguana_bundleready(struct iguana_info *coin,struct iguana_bundle *bp,int32_t requiredflag);
int32_t iguana_blast(struct iguana_info *coin,struct iguana_peer *addr);
int32_t iguana_validated(struct iguana_info *coin);
void iguana_volatilesalloc(struct iguana_info *coin,struct iguana_ramchain *ramchain,int32_t copyflag);
int32_t iguana_send_ping(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr);
int32_t iguana_process_msgrequestQ(struct supernet_info *myinfo,struct iguana_info *coin);
uint32_t iguana_fastfindinit(struct iguana_info *coin);
int32_t iguana_unspentindfind(struct iguana_info *coin,char *coinaddr,uint8_t *spendscript,int32_t *scriptlenp,uint64_t *valuep,int32_t *heightp,bits256 txid,int32_t vout,int32_t lasthdrsi,int32_t mempool);
int32_t iguana_addressvalidate(struct iguana_info *coin,uint8_t *addrtypep,char *address);
int32_t bitcoin_sign(void *ctx,char *symbol,uint8_t *sig,bits256 txhash2,bits256 privkey,int32_t recoverflag);
bits256 iguana_str2priv(struct supernet_info *myinfo,struct iguana_info *coin,char *str);
int32_t iguana_spentflag(struct iguana_info *coin,int64_t *RTspendp,int32_t *spentheightp,struct iguana_ramchain *ramchain,int16_t spent_hdrsi,uint32_t spent_unspentind,int32_t height,int32_t minconf,int32_t maxconf,uint64_t amount);
int32_t iguana_voutscript(struct iguana_info *coin,struct iguana_bundle *bp,uint8_t *scriptspace,char *asmstr,struct iguana_unspent *u,struct iguana_pkhash *p,int32_t txi);
cJSON *iguana_unspentjson(struct supernet_info *myinfo,struct iguana_info *coin,int32_t hdrsi,uint32_t unspentind,struct iguana_txid *T,struct iguana_unspent *up,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33);
int32_t bitcoin_standardspend(uint8_t *script,int32_t n,uint8_t rmd160[20]);
struct iguana_waddress *iguana_waddresssearch(struct supernet_info *myinfo,struct iguana_waccount **wacctp,char *coinaddr);
int64_t iguana_addressreceived(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *json,char *remoteaddr,cJSON *txids,cJSON *vouts,char *coinaddr,int32_t minconf);
cJSON *iguana_walletjson(struct supernet_info *myinfo);
int32_t iguana_payloadupdate(struct supernet_info *myinfo,struct iguana_info *coin,char *retstr,struct iguana_waddress *waddr,char *account);
int32_t bitcoin_MofNspendscript(uint8_t p2sh_rmd160[20],uint8_t *script,int32_t n,const struct vin_info *vp);
cJSON *iguana_p2shjson(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *retjson,struct iguana_waddress *waddr);
char *setaccount(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waddress **waddrp,char *account,char *coinaddr,char *redeemScript);
char *iguana_APIrequest(struct iguana_info *coin,bits256 blockhash,bits256 txid,int32_t seconds);
int32_t bitcoin_verifyvins(struct iguana_info *coin,bits256 *signedtxidp,char **signedtx,struct iguana_msgtx *msgtx,uint8_t *serialized,int32_t maxsize,struct vin_info *V,int32_t sighash,int32_t signtx);
char *iguana_validaterawtx(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_msgtx *msgtx,uint8_t *extraspace,int32_t extralen,char *rawtx,int32_t mempool);
int64_t iguana_fastfindcreate(struct iguana_info *coin);
int32_t bitcoin_validaddress(struct iguana_info *coin,char *coinaddr);
int32_t iguana_volatileupdate(struct iguana_info *coin,int32_t incremental,struct iguana_ramchain *spentchain,int16_t spent_hdrsi,uint32_t spent_unspentind,uint32_t spent_pkind,uint64_t spent_value,uint32_t spendind,uint32_t fromheight);
int32_t iguana_utxoupdate(struct iguana_info *coin,int16_t spent_hdrsi,uint32_t spent_unspentind,uint32_t spent_pkind,uint64_t spent_value,uint32_t spendind,uint32_t fromheight);
int32_t iguana_unspentslists(struct supernet_info *myinfo,struct iguana_info *coin,int64_t *totalp,int64_t *unspents,int32_t max,int64_t required,int32_t minconf,cJSON *addresses);
int64_t iguana_unspentset(struct supernet_info *myinfo,struct iguana_info *coin);
int32_t iguana_txidfastfind(struct iguana_info *coin,int32_t *heightp,bits256 txid,int32_t lasthdrsi);
uint8_t iguana_addrtype(struct iguana_info *coin,uint8_t script_type);
struct iguana_waddress *iguana_waddressadd(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,struct iguana_waddress *addwaddr,char *redeemScript);
cJSON *iguana_createvins(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *txobj,cJSON *vins);
bits256 bitcoin_pubkey33(void *ctx,uint8_t *data,bits256 privkey);
bits256 bitcoin_randkey(void *ctx);
int32_t bitcoin_recoververify(void *ctx,char *symbol,uint8_t *sig64,bits256 messagehash2,uint8_t *pubkey);
int32_t bitcoin_assembler(struct iguana_info *coin,cJSON *logarray,uint8_t script[IGUANA_MAXSCRIPTSIZE],cJSON *scriptobj,int32_t interpret,int64_t nLockTime,struct vin_info *V);
cJSON *iguana_spendasm(struct iguana_info *coin,uint8_t *spendscript,int32_t spendlen);
int64_t iguana_unspentavail(struct iguana_info *coin,uint64_t hdrsi_unspendind,int32_t minconf,int32_t maxconf);
struct iguana_utxo iguana_utxofind(struct iguana_info *coin,int16_t spent_hdrsi,uint32_t spent_unspentind,int32_t *RTspendflagp,int32_t lockflag);
int32_t iguana_signrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_msgtx *msgtx,char **signedtxp,bits256 *signedtxidp,struct vin_info *V,int32_t numinputs,char *rawtx,cJSON *vins,cJSON *privkeys);
cJSON *iguana_privkeysjson(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *vins);
char *iguana_inputaddress(struct iguana_info *coin,char *coinaddr,int16_t *spent_hdrsip,uint32_t *unspentindp,cJSON *vinobj);
struct iguana_waddress *iguana_getaccountaddress(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *json,char *remoteaddr,char *coinaddr,char *account);
int32_t iguana_uvaltxid(struct supernet_info *myinfo,bits256 *txidp,struct iguana_info *coin,int16_t hdrsi,uint32_t unspentind);
struct instantdex_accept *instantdex_quotefind(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,bits256 encodedhash);
int32_t instantdex_quoterequest(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *serialized,int32_t maxlen,struct iguana_peer *addr,bits256 encodedhash);
int32_t instantdex_peerhas_clear(struct iguana_info *coin,struct iguana_peer *addr);
int32_t instantdex_quotep2p(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,uint8_t *serialized,int32_t recvlen);
void instantdex_update(struct supernet_info *myinfo);
cJSON *iguana_getaddressesbyaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account);
int32_t iguana_interpreter(struct iguana_info *coin,cJSON *logarray,int64_t nLockTime,struct vin_info *V,int32_t numvins);
int32_t iguana_parsevinobj(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_msgvin *vin,cJSON *vinobj,struct vin_info *V);
//int64_t iguana_availunspents(struct supernet_info *myinfo,uint64_t **unspentsp,int32_t *nump,struct iguana_info *coin,int32_t minconf,char *account,void *ptr,int32_t maxsize);
char *iguana_signunspents(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *signedtxidp,int32_t *completedp,cJSON *txobj,uint64_t satoshis,char *changeaddr,uint64_t txfee,uint64_t *unspents,int32_t num);
bits256 iguana_sendrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *signedtx);
int32_t iguana_inv2packet(uint8_t *serialized,int32_t maxsize,int32_t type,bits256 *hashes,int32_t n);
int32_t instantdex_inv2data(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,struct exchange_info *exchange);
struct iguana_bundlereq *instantdex_recvquotes(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *encodedhash,int32_t n);
struct exchange_info *exchange_create(char *exchangestr,cJSON *argjson);
int32_t iguana_inv2poll(struct supernet_info *myinfo,struct iguana_info *coin);
struct iguana_bundlereq *iguana_bundlereq(struct iguana_info *coin,struct iguana_peer *addr,int32_t type,uint8_t *data,int32_t datalen);
void instantdex_FSMinit();
void iguana_unspentslock(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *vins);
char *iguana_calcrawtx(struct supernet_info *myinfo,struct iguana_info *coin,cJSON **vinsp,cJSON *txobj,int64_t satoshis,char *changeaddr,int64_t txfee,cJSON *addresses,int32_t minconf);
char *iguana_signrawtx(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *signedtxidp,int32_t *completedp,cJSON *vins,char *rawtx,cJSON *privkey);
bits256 scrypt_blockhash(const void *input);
bits256 iguana_calcblockhash(char *symbol,int32_t (*hashalgo)(uint8_t *blockhashp,uint8_t *serialized,int32_t len),uint8_t *serialized,int32_t len);
struct bitcoin_eventitem *instantdex_event(char *cmdstr,cJSON *argjson,cJSON *newjson,uint8_t *serdata,int32_t serdatalen);
void instantdex_eventfree(struct bitcoin_eventitem *ptr);
struct iguana_monitorinfo *iguana_txidmonitor(struct iguana_info *coin,bits256 txid);
struct iguana_monitorinfo *iguana_txidreport(struct iguana_info *coin,bits256 txid,struct iguana_peer *addr);
double iguana_txidstatus(struct iguana_info *coin,bits256 txid);
void basilisk_functions(struct iguana_info *coin,int32_t protocol);
char *bitcoind_passthru(char *coinstr,char *serverport,char *userpass,char *method,char *params);
char *bitcoin_calcrawtx(struct supernet_info *myinfo,struct iguana_info *coin,cJSON **vinsp,int64_t satoshis,char *paymentscriptstr,char *changeaddr,int64_t txfee,cJSON *addresses,int32_t minconf,uint32_t locktime);
char *bitcoin_blockhashstr(char *coinstr,char *serverport,char *userpass,int32_t height);
bits256 basilisk_blockhash(struct iguana_info *coin,bits256 prevhash2);
void calc_scrypthash(uint32_t *hash,void *data);
int32_t iguana_rwvarstr(int32_t rwflag,uint8_t *serialized,int32_t maxlen,char *endianedp);
bits256 bitcoin_sharedsecret(void *ctx,bits256 privkey,uint8_t *pubkey,int32_t plen);
int32_t iguana_blockhdrsize(char *symbol,uint8_t zcash,uint8_t auxpow);//,uint8_t *serialized,int32_t maxlen);
int32_t iguana_blockROsize(uint8_t zcash);
void *iguana_blockzcopyRO(uint8_t zcash,struct iguana_blockRO *dest,int32_t desti,struct iguana_blockRO *src,int32_t srci);
void iguana_blockzcopy(uint8_t zcash,struct iguana_block *dest,struct iguana_block *src);
int32_t iguana_blocksizecheck(char *debugstr,uint8_t zcash,struct iguana_block *block);
void basilisk_miner(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_info *virt,int32_t maxmillis,char *mineraddr);
int32_t bitcoin_pubkeyspend(uint8_t *script,int32_t n,uint8_t pubkey[66]);
int32_t basilisk_blocksubmit(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_info *virt,char *blockstr,bits256 hash2);
struct supernet_info *SuperNET_MYINFO(char *passphrase);
bits256 calc_categoryhashes(bits256 *subhashp,char *category,char *subcategory);
struct gecko_chain *category_find(bits256 categoryhash,bits256 subhash);
void *category_subscribe(struct supernet_info *myinfo,bits256 category,bits256 keyhash);
char *bitcoin_address(char *coinaddr,uint8_t addrtype,uint8_t *pubkey_or_rmd160,int32_t len);
char *SuperNET_JSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr,uint16_t port);
struct supernet_info *SuperNET_accountfind(cJSON *json);
cJSON *SuperNET_rosettajson(bits256 privkey,int32_t showprivs);
double instantdex_aveprice(struct supernet_info *myinfo,struct exchange_quote *sortbuf,int32_t max,double *totalvolp,char *base,char *rel,double basevolume,cJSON *argjson);
char *SuperNET_keysinit(struct supernet_info *myinfo,char *argjsonstr);
char *SuperNET_parser(struct supernet_info *myinfo,char *agentstr,char *method,cJSON *json,char *remoteaddr);
char *SuperNET_htmlstr(char *fname,char *htmlstr,int32_t maxsize,char *agentstr);
void SuperNET_setkeys(struct supernet_info *myinfo,void *pass,int32_t passlen,int32_t dosha256);
int32_t iguana_headerget(struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_block *block);
int32_t iguana_bundlefinalize(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,struct OS_memspace *mem,struct OS_memspace *memB);
bits256 iguana_parsetxobj(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *txstartp,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,cJSON *txobj,struct vin_info *V);
int32_t iguana_ROallocsize(struct iguana_info *virt);
long iguana_bundlesload(struct supernet_info *myinfo,struct iguana_info *coin);
void basilisk_wait(struct supernet_info *myinfo,struct iguana_info *coin);
int32_t bitcoin_pubkey_combine(void *ctx,uint8_t *combined_pub,uint8_t *skipkey,bits256 *evenkeys,int32_t n,bits256 *oddkeys,int32_t m);
bits256 bitcoin_pub256(void *ctx,bits256 *privkeyp,uint8_t odd_even);
bits256 bitcoin_schnorr_noncepair(void *ctx,uint8_t *pubnonce,bits256 txhash2,bits256 privkey);
int32_t bitcoin_schnorr_combine(void *ctx,uint8_t *sig64,uint8_t *allpub,uint8_t **sigs,int32_t n,bits256 txhash2);
int32_t bitcoin_schnorr_verify(void *ctx,uint8_t *sig64,bits256 txhash2,uint8_t *pubkey,int32_t plen);
int32_t iguana_parsevoutobj(struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_msgvout *vout,cJSON *voutobj);
struct gecko_memtx *gecko_unspentfind(struct gecko_memtx ***ptrpp,struct iguana_info *virt,bits256 txid);
int64_t *gecko_valueptr(struct gecko_memtx *memtx,int32_t vout);
struct iguana_peer *iguana_peerfindipaddr(struct iguana_info *coin,char *ipaddr,int32_t needalive);
struct iguana_peer *iguana_peerfindipbits(struct iguana_info *coin,uint32_t ipbits,int32_t needalive);
int32_t basilisk_relays_send(struct supernet_info *myinfo,struct iguana_peer *addr);
int32_t basilisk_hashes_send(struct supernet_info *myinfo,struct iguana_info *virt,struct iguana_peer *addr,char *CMD,bits256 *txids,int32_t num);
int32_t iguana_opreturn(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,int64_t crypto777_payment,int32_t height,uint64_t hdrsi_unspentind,int64_t payment,uint32_t fileid,uint64_t scriptpos,uint32_t scriptlen);
int32_t iguana_scriptdata(struct iguana_info *coin,uint8_t *scriptspace,long fileptr[2],char *fname,uint64_t scriptpos,int32_t scriptlen);
struct iguana_peer *basilisk_ensurerelay(struct iguana_info *btcd,uint32_t ipbits);

#include "../includes/iguana_api.h"


#endif

