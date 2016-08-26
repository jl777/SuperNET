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

#ifndef H_BITCOIN_H
#define H_BITCOIN_H

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
#define SCRIPT_OP_HASH160 0xa9
#define SCRIPT_OP_EQUAL 0x87
#define SCRIPT_OP_CHECKSIG 0xac
#define SCRIPT_OP_CHECKMULTISIG 0xae
#define SCRIPT_OP_CHECKSEQUENCEVERIFY	0xb2
#define SCRIPT_OP_CHECKLOCKTIMEVERIFY 0xb1


int32_t bitcoin_validaddress(struct iguana_info *coin,char *coinaddr);
int32_t bitcoin_cltvscript(uint8_t p2shtype,char *ps2h_coinaddr,uint8_t p2sh_rmd160[20],uint8_t *script,int32_t n,char *senderaddr,char *otheraddr,uint8_t secret160[20],uint32_t locktime);
int32_t bitcoin_addr2rmd160(uint8_t *addrtypep,uint8_t rmd160[20],char *coinaddr);
char *bitcoin_cltvtx(struct iguana_info *coin,char *changeaddr,char *senderaddr,char *senders_otheraddr,char *otheraddr,uint32_t locktime,uint64_t satoshis,bits256 txid,int32_t vout,uint64_t inputsatoshis,bits256 privkey);
int32_t bitcoin_MofNspendscript(uint8_t p2sh_rmd160[20],uint8_t *script,int32_t n,const struct vin_info *vp);

int32_t bitcoin_pubkeyspend(uint8_t *script,int32_t n,uint8_t pubkey[66]);
int32_t bitcoin_p2shspend(uint8_t *script,int32_t n,uint8_t rmd160[20]);
int32_t bitcoin_revealsecret160(uint8_t *script,int32_t n,uint8_t secret160[20]);
int32_t bitcoin_standardspend(uint8_t *script,int32_t n,uint8_t rmd160[20]);

int32_t bitcoin_pubkeylen(const uint8_t *pubkey);
int32_t bitcoin_scriptget(struct iguana_info *coin,int32_t *hashtypep,uint32_t *sigsizep,uint32_t *pubkeysizep,uint8_t **userdatap,uint32_t *userdatalenp,struct vin_info *vp,uint8_t *scriptsig,int32_t len,int32_t spendtype);
int32_t iguana_expandscript(struct iguana_info *coin,char *asmstr,int32_t maxlen,uint8_t *script,int32_t scriptlen);
int32_t bitcoin_scriptsig(struct iguana_info *coin,uint8_t *script,int32_t n,const struct vin_info *vp,struct iguana_msgtx *msgtx);
char *iguana_scriptget(struct iguana_info *coin,char *scriptstr,char *asmstr,int32_t max,int32_t hdrsi,uint32_t unspentind,bits256 txid,int32_t vout,uint8_t *rmd160,int32_t type,uint8_t *pubkey33);

int32_t bitcoin_base58decode(uint8_t *data,char *coinaddr);
char *bitcoin_base58encode(char *coinaddr,uint8_t *data_,int32_t datalen);
int32_t bitcoin_sign(void *ctx,char *symbol,uint8_t *sig,bits256 txhash2,bits256 privkey,int32_t recoverflag);
int32_t oldbitcoin_verify(uint8_t *sig,int32_t siglen,uint8_t *data,int32_t datalen,uint8_t *pubkey,int32_t len);


#endif

