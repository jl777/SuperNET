
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
//
//  LP_include.h
//  marketmaker
//

#ifndef LP_INCLUDE_H
#define LP_INCLUDE_H

#define BASILISK_DISABLEWAITTX
#define BASILISK_DISABLESENDTX

#define BASILISK_DEFAULT_NUMCONFIRMS 5
#define DEX_SLEEP 3
#define BASILISK_DEXDURATION 300
#define BASILISK_MSGDURATION 30
#define BASILISK_AUCTION_DURATION 5

#define BASILISK_MAXFUTUREBLOCK 60
#define BASILISK_KEYSIZE ((int32_t)(2*sizeof(bits256)+sizeof(uint32_t)*2))

extern char GLOBAL_DBDIR[];

void *bitcoin_ctx();
int32_t bitcoin_verify(void *ctx,uint8_t *sig,int32_t siglen,bits256 txhash2,uint8_t *pubkey,int32_t plen);
int32_t bitcoin_recoververify(void *ctx,char *symbol,uint8_t *sig,bits256 messagehash2,uint8_t *pubkey,size_t plen);
int32_t bitcoin_sign(void *ctx,char *symbol,uint8_t *sig,bits256 txhash2,bits256 privkey,int32_t recoverflag);
bits256 bitcoin_pubkey33(void *ctx,uint8_t *data,bits256 privkey);
bits256 bitcoin_pub256(void *ctx,bits256 *privkeyp,uint8_t odd_even);

char *bitcoin_base58encode(char *coinaddr,uint8_t *data,int32_t datalen);
int32_t bitcoin_base58decode(uint8_t *data,char *coinaddr);

#define IGUANA_MAXSCRIPTSIZE 10001
#define IGUANA_SEQUENCEID_FINAL 0xfffffffe

#define IGUANA_SCRIPT_NULL 0
#define IGUANA_SCRIPT_76AC 1
#define IGUANA_SCRIPT_76A988AC 2
#define IGUANA_SCRIPT_P2SH 3
#define IGUANA_SCRIPT_OPRETURN 4
#define IGUANA_SCRIPT_3of3 5
#define IGUANA_SCRIPT_2of3 6
#define IGUANA_SCRIPT_1of3 7
#define IGUANA_SCRIPT_2of2 8
#define IGUANA_SCRIPT_1of2 9
#define IGUANA_SCRIPT_MSIG 10
#define IGUANA_SCRIPT_DATA 11
#define IGUANA_SCRIPT_AC 12
#define IGUANA_SCRIPT_1of1 13
#define IGUANA_SCRIPT_STRANGE 15

#define BASILISK_TIMEOUT 3000
#define BASILISK_MINFANOUT 8
#define BASILISK_MAXFANOUT 64
#define BASILISK_DEFAULTDIFF 0x1effffff
#define BASILISK_HDROFFSET ((int32_t)(sizeof(bits256)+sizeof(struct iguana_msghdr)+sizeof(uint32_t)))

#define INSTANTDEX_DECKSIZE 1000
#define INSTANTDEX_LOCKTIME (3600*2 + 300*2)
#define INSTANTDEX_INSURANCEDIV 777
#define INSTANTDEX_PUBKEY "03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06"
#define INSTANTDEX_RMD160 "ca1e04745e8ca0c60d8c5881531d51bec470743f"
#define JUMBLR_RMD160 "5177f8b427e5f47342a4b8ab5dac770815d4389e"
#define TIERNOLAN_RMD160 "daedddd8dbe7a2439841ced40ba9c3d375f98146"
#define INSTANTDEX_BTC "1KRhTPvoxyJmVALwHFXZdeeWFbcJSbkFPu"
#define INSTANTDEX_BTCD "RThtXup6Zo7LZAi8kRWgjAyi1s4u6U9Cpf"

struct iguana_msgvin { bits256 prev_hash; uint8_t *vinscript,*userdata,*spendscript,*redeemscript; uint32_t prev_vout,sequence; uint16_t scriptlen,p2shlen,userdatalen,spendlen; };

struct iguana_msgvout { uint64_t value; uint32_t pk_scriptlen; uint8_t *pk_script; };

struct iguana_msgtx
{
    uint32_t version,tx_in,tx_out,lock_time;
    struct iguana_msgvin *vins;
    struct iguana_msgvout *vouts;
    bits256 txid;
    int32_t allocsize,timestamp,numinputs,numoutputs;
    int64_t inputsum,outputsum,txfee;
    uint8_t *serialized;
};

struct vin_signer { bits256 privkey; char coinaddr[64]; uint8_t siglen,sig[80],rmd160[20],pubkey[66]; };

struct vin_info
{
    struct iguana_msgvin vin; uint64_t amount; cJSON *extras; bits256 sigtxid;
    int32_t M,N,validmask,spendlen,type,p2shlen,numpubkeys,numsigs,height,hashtype,userdatalen,suppress_pubkeys,ignore_cltverr;
    uint32_t sequence,unspentind; struct vin_signer signers[16]; char coinaddr[65];
    uint8_t rmd160[20],spendscript[IGUANA_MAXSCRIPTSIZE],p2shscript[IGUANA_MAXSCRIPTSIZE],userdata[IGUANA_MAXSCRIPTSIZE];
};

struct basilisk_swapmessage
{
    bits256 srchash,desthash;
    uint32_t crc32,msgbits,quoteid,datalen;
    uint8_t *data;
};

struct basilisk_swap;

struct basilisk_rawtxinfo
{
    char destaddr[64],coinstr[16];
    bits256 txid,signedtxid,actualtxid;
    uint64_t amount,change,inputsum;
    int32_t redeemlen,datalen,completed,vintype,vouttype,numconfirms,spendlen,secretstart,suppress_pubkeys;
    uint32_t locktime,crcs[2];
    uint8_t addrtype,pubkey33[33],rmd160[20];
};

struct basilisk_request
{
    uint32_t requestid,timestamp,quoteid,quotetime; // 0 to 15
    uint64_t srcamount,unused; // 16 to 31
    bits256 srchash; // 32 to 63
    bits256 desthash;
    char src[8],dest[8];
    uint64_t destamount;
    int32_t optionhours,DEXselector;
};

struct basilisk_rawtx
{
    char name[32];
    struct iguana_msgtx msgtx;
    struct basilisk_rawtxinfo I;
    struct iguana_info *coin;
    char vinstr[8192],p2shaddr[64];
    cJSON *vins;
    bits256 utxotxid; int32_t utxovout;
    uint8_t txbytes[16384],spendscript[512],redeemscript[1024],extraspace[4096],pubkey33[33];
};

struct basilisk_swapinfo
{
    struct basilisk_request req;
    char bobstr[64],alicestr[64];
    bits256 myhash,otherhash,orderhash;
    uint32_t statebits,otherstatebits,started,expiration,finished,dead,reftime,putduration,callduration;
    int32_t bobconfirms,aliceconfirms,iambob,reclaimed,bobspent,alicespent,pad;
    uint64_t alicesatoshis,bobsatoshis,bobinsurance,aliceinsurance;
    
    bits256 myprivs[2],mypubs[2],otherpubs[2],pubA0,pubA1,pubB0,pubB1,privAm,pubAm,privBn,pubBn;
    uint32_t crcs_mypub[2],crcs_mychoosei[2],crcs_myprivs[2],crcs_mypriv[2];
    int32_t choosei,otherchoosei,cutverified,otherverifiedcut,numpubs,havestate,otherhavestate,pad2;
    uint8_t secretAm[20],secretBn[20];
    uint8_t secretAm256[32],secretBn256[32];
    uint8_t userdata_aliceclaim[256],userdata_aliceclaimlen;
    uint8_t userdata_alicereclaim[256],userdata_alicereclaimlen;
    uint8_t userdata_alicespend[256],userdata_alicespendlen;
    uint8_t userdata_bobspend[256],userdata_bobspendlen;
    uint8_t userdata_bobreclaim[256],userdata_bobreclaimlen;
    uint8_t userdata_bobrefund[256],userdata_bobrefundlen;
};

struct iguana_info
{
    uint64_t txfee,estimatedrate;
    int32_t longestchain;
    uint8_t pubtype,p2shtype,isPoS,wiftype;
    char symbol[16],changeaddr[64],userpass[1024],serverport[128];
};

struct basilisk_swap
{
    void *ctx; struct iguana_info bobcoin,alicecoin;
    void (*balancingtrade)(struct basilisk_swap *swap,int32_t iambob);
    int32_t subsock,pushsock,connected,aliceunconf,depositunconf,paymentunconf; uint32_t lasttime,aborted;
    FILE *fp;
    bits256 persistent_privkey,persistent_pubkey;
    struct basilisk_swapinfo I;
    struct basilisk_rawtx bobdeposit,bobpayment,alicepayment,myfee,otherfee,aliceclaim,alicespend,bobreclaim,bobspend,bobrefund,alicereclaim;
    bits256 privkeys[INSTANTDEX_DECKSIZE];
    struct basilisk_swapmessage *messages; int32_t nummessages;
    char Bdeposit[64],Bpayment[64];
    uint64_t otherdeck[INSTANTDEX_DECKSIZE][2],deck[INSTANTDEX_DECKSIZE][2];
    uint8_t persistent_pubkey33[33],pad[15],verifybuf[65536];
    
};

static struct bitcoin_opcode { UT_hash_handle hh; uint8_t opcode,flags,stackitems; int8_t extralen; } *OPTABLE; static char *OPCODES[0x100]; static int32_t OPCODELENS[0x100];

#define SIGHASH_ALL 1
#define SIGHASH_NONE 2
#define SIGHASH_SINGLE 3
#define SIGHASH_ANYONECANPAY 0x80

#define SCRIPT_OP_NOP 0x00
#define SCRIPT_OP_TRUE 0x51
#define SCRIPT_OP_2 0x52
#define SCRIPT_OP_3 0x53
#define SCRIPT_OP_4 0x54
#define SCRIPT_OP_IF 0x63
#define SCRIPT_OP_ELSE 0x67
#define SCRIPT_OP_RETURN 0x6a
#define SCRIPT_OP_DUP 0x76
#define SCRIPT_OP_ENDIF 0x68
#define SCRIPT_OP_DROP 0x75
#define SCRIPT_OP_EQUALVERIFY 0x88
#define SCRIPT_OP_SHA256 0xa8
#define SCRIPT_OP_HASH160 0xa9

#define SCRIPT_OP_EQUAL 0x87
#define SCRIPT_OP_CHECKSIG 0xac
#define SCRIPT_OP_CHECKMULTISIG 0xae
#define SCRIPT_OP_CHECKSEQUENCEVERIFY	0xb2
#define SCRIPT_OP_CHECKLOCKTIMEVERIFY 0xb1
#define IGUANA_OP_0 0x00
#define IGUANA_OP_PUSHDATA1 0x4c
#define IGUANA_OP_PUSHDATA2 0x4d
#define IGUANA_OP_PUSHDATA4 0x4e
#define IGUANA_OP_1NEGATE 0x4f
#define IGUANA_OP_1 0x51
#define IGUANA_OP_16 0x60
#define IGUANA_OP_NOP 0x61
#define IGUANA_OP_IF 0x63
#define IGUANA_OP_NOTIF 0x64
#define IGUANA_OP_ELSE 0x67
#define IGUANA_OP_ENDIF 0x68
#define IGUANA_OP_VERIFY 0x69
#define IGUANA_OP_RETURN 0x6a

#define IGUANA_OP_TOALTSTACK 0x6b
#define IGUANA_OP_FROMALTSTACK 0x6c
#define IGUANA_OP_2DROP 0x6d
#define IGUANA_OP_2DUP 0x6e
#define IGUANA_OP_3DUP 0x6f
#define IGUANA_OP_2OVER 0x70
#define IGUANA_OP_2ROT 0x71
#define IGUANA_OP_2SWAP 0x72
#define IGUANA_OP_IFDUP 0x73
#define IGUANA_OP_DEPTH 0x74
#define IGUANA_OP_DROP 0x75
#define IGUANA_OP_DUP 0x76
#define IGUANA_OP_NIP 0x77
#define IGUANA_OP_OVER 0x78
#define IGUANA_OP_PICK 0x79
#define IGUANA_OP_ROLL 0x7a
#define IGUANA_OP_ROT 0x7b
#define IGUANA_OP_SWAP 0x7c
#define IGUANA_OP_TUCK 0x7d

#define IGUANA_OP_EQUAL 0x87
#define IGUANA_OP_EQUALVERIFY 0x88

#define IGUANA_OP_1ADD 0x8b
#define IGUANA_OP_1SUB 0x8c
#define IGUANA_OP_NEGATE 0x8f
#define IGUANA_OP_ABS 0x90
#define IGUANA_OP_NOT 0x91
#define IGUANA_OP_0NOTEQUAL 0x92
#define IGUANA_OP_ADD 0x93
#define IGUANA_OP_SUB 0x94

#define IGUANA_OP_BOOLAND 0x9a
#define IGUANA_OP_BOOLOR 0x9b
#define IGUANA_OP_NUMEQUAL 0x9c
#define IGUANA_OP_NUMEQUALVERIFY 0x9d
#define IGUANA_OP_NUMNOTEQUAL 0x9e
#define IGUANA_OP_LESSTHAN 0x9f
#define IGUANA_OP_GREATERTHAN 0xa0
#define IGUANA_OP_LESSTHANOREQUAL 0xa1
#define IGUANA_OP_GREATERTHANOREQUAL 0xa2
#define IGUANA_OP_MIN 0xa3
#define IGUANA_OP_MAX 0xa4
#define IGUANA_OP_WITHIN 0xa5

#define IGUANA_OP_RIPEMD160 0xa6
#define IGUANA_OP_SHA1 0xa7
#define IGUANA_OP_SHA256 0xa8
#define IGUANA_OP_HASH160 0xa9
#define IGUANA_OP_HASH256 0xaa
#define IGUANA_OP_CODESEPARATOR 0xab
#define IGUANA_OP_CHECKSIG 0xac
#define IGUANA_OP_CHECKSIGVERIFY 0xad
#define IGUANA_OP_CHECKMULTISIG 0xae
#define IGUANA_OP_CHECKMULTISIGVERIFY 0xaf

#define IGUANA_OP_NOP1 0xb0
#define IGUANA_OP_CHECKLOCKTIMEVERIFY 0xb1
#define IGUANA_OP_CHECKSEQUENCEVERIFY 0xb2
#define IGUANA_OP_NOP10 0xb9

#define IGUANA_OP_COMBINEPUBKEYS 0xc0
#define IGUANA_OP_CHECKSCHNORR 0xc1
#define IGUANA_OP_CHECKSCHNORRVERIFY 0xc2

// https://github.com/TierNolan/bips/blob/cpkv/bip-cprkv.mediawiki
#define IGUANA_OP_CHECKPRIVATEKEY 0xc3
#define IGUANA_OP_CHECKPRIVATEKEYVERIFY 0xc4

#define IGUANA_NOPFLAG 1
#define IGUANA_ALWAYSILLEGAL 2
#define IGUANA_EXECUTIONILLEGAL 4
#define IGUANA_POSTVERIFY 8
#define IGUANA_CRYPTOFLAG 16
#define IGUANA_MATHFLAG 32
#define IGUANA_CONTROLFLAG 64
#define IGUANA_STACKFLAG 128

enum opcodetype
{
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE=OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,
    
    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,
    
    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,
    
    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,
    
    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,
    
    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,
    
    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,
    
    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,
    
    OP_WITHIN = 0xa5,
    
    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,
    
    // expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY  = 0xb1,
    OP_CHECKSEQUENCEVERIFY   = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,
    
    OP_COMBINEPUBKEYS = 0xc0,
    OP_CHECKSCHNORR = 0xc1,
    OP_CHECKSCHNORRVERIFY = 0xc2,
    OP_CHECKPRIVATEKEY = 0xc3,
    OP_CHECKPRIVATEKEYVERIFY = 0xc4,
    
    // template matching params
    //OP_SMALLINTEGER = 0xfa,
    //OP_PUBKEYS = 0xfb,
    //OP_PUBKEYHASH = 0xfd,
    //OP_PUBKEY = 0xfe,
    
    OP_INVALIDOPCODE = 0xff,
};
void basilisk_dontforget_update(struct basilisk_swap *swap,struct basilisk_rawtx *rawtx);
uint32_t basilisk_requestid(struct basilisk_request *rp);
uint32_t basilisk_quoteid(struct basilisk_request *rp);
char *bitcoind_passthru(char *coinstr,char *serverport,char *userpass,char *method,char *params);
struct iguana_info *LP_coinfind(char *symbol);

#endif
