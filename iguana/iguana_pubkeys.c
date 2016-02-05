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

#include "iguana777.h"
#include <stdbool.h>
#include "../includes/openssl/ec.h"
#include "../includes/openssl/ecdsa.h"
#include "../includes/openssl/obj_mac.h"
//#include "../includes/openssl/ripemd.h"
//#include "../includes/openssl/sha.h"

#define SCRIPT_OP_IF 0x63
#define SCRIPT_OP_ELSE 0x67
#define SCRIPT_OP_DUP 0x76
#define SCRIPT_OP_ENDIF 0x68
#define SCRIPT_OP_TRUE 0x51
#define SCRIPT_OP_NOP 0x61
#define SCRIPT_OP_2 0x52
#define SCRIPT_OP_3 0x53
#define SCRIPT_OP_EQUALVERIFY 0x88
#define SCRIPT_OP_HASH160 0xa9
#define SCRIPT_OP_EQUAL 0x87
#define SCRIPT_OP_CHECKSIG 0xac
#define SCRIPT_OP_CHECKMULTISIG 0xae
#define SCRIPT_OP_CHECKMULTISIGVERIFY 0xaf

struct bp_key { EC_KEY *k; };
typedef struct cstring { char *str; size_t len,alloc; } cstring;

static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static bool cstr_alloc_min_sz(cstring *s, size_t sz)
{
	char *new_s; uint32_t al_sz,shift = 3;
	sz++; // NUL overhead
	if ( s->alloc && (s->alloc >= sz) )
		return true;
	while ( (al_sz = (1 << shift)) < sz )
		shift++;
	if ( (new_s= mycalloc('C',1,al_sz)) != 0 )
    {
        if ( s->str != 0 )
        {
            memcpy(new_s,s->str,s->len);
            myfree(s->str,s->alloc);
        }
        s->str = new_s;
        s->alloc = al_sz;
        s->str[s->len] = 0;
        return true;
    }
    return false;
}

cstring *cstr_new_sz(size_t sz)
{
	cstring *s = mycalloc('C',1,sizeof(cstring));
	if (!s)
		return NULL;
	if (!cstr_alloc_min_sz(s, sz))
    {
		myfree(s,sizeof(cstring));
		return NULL;
	}
	return s;
}

cstring *cstr_new_buf(const void *buf, size_t sz)
{
	cstring *s = cstr_new_sz(sz);
	if (!s)
		return NULL;
	memcpy(s->str, buf, sz);
	s->len = sz;
	s->str[s->len] = 0;
	return s;
}

cstring *cstr_new(const char *init_str)
{
	if ( !init_str || !*init_str )
		return cstr_new_sz(0);
	size_t slen = strlen(init_str);
	return cstr_new_buf(init_str, slen);
}

void cstr_free(cstring *s, bool free_buf)
{
	if (!s)
		return;
	if (free_buf)
		myfree(s->str,s->alloc);
	memset(s, 0, sizeof(*s));
	myfree(s,sizeof(*s));
}

bool cstr_erase(cstring *s,size_t pos,ssize_t len)
{
	if (pos == s->len && len == 0)
		return true;
	if (pos >= s->len)
		return false;
	size_t old_tail = s->len - pos;
	if ((len >= 0) && (len > old_tail))
		return false;
	memmove(&s->str[pos], &s->str[pos + len], old_tail - len);
	s->len -= len;
	s->str[s->len] = 0;
	return true;
}

bool cstr_resize(cstring *s, size_t new_sz)
{
	// no change
	if (new_sz == s->len)
		return true;
	// truncate string
	if (new_sz <= s->len) {
		s->len = new_sz;
		s->str[s->len] = 0;
		return true;
	}
	// increase string size
	if (!cstr_alloc_min_sz(s, new_sz))
		return false;
	// contents of string tail undefined
	s->len = new_sz;
	s->str[s->len] = 0;
	return true;
}

bool cstr_append_buf(cstring *s, const void *buf, size_t sz)
{
	if (!cstr_alloc_min_sz(s, s->len + sz))
		return false;
	memcpy(s->str + s->len, buf, sz);
	s->len += sz;
	s->str[s->len] = 0;
	return true;
}
static inline bool cstr_append_c(cstring *s,char ch) { return cstr_append_buf(s,&ch,1); }

void bu_reverse_copy(uint8_t *dst, const uint8_t *src, size_t len)
{
	uint32_t i;
	for (i=0; i<len; i++)
		dst[len - i - 1] = src[i];
}

void bn_setvch(BIGNUM *vo,const void *data_,size_t data_len)
{
	const uint8_t *data = data_;
	uint32_t vch2_len = (int32_t)data_len + 4;
	uint8_t vch2[vch2_len];
	vch2[0] = (data_len >> 24) & 0xff;
	vch2[1] = (data_len >> 16) & 0xff;
	vch2[2] = (data_len >> 8) & 0xff;
	vch2[3] = (data_len >> 0) & 0xff;
	bu_reverse_copy(vch2 + 4, data, data_len);
	BN_mpi2bn(vch2, vch2_len, vo);
}

cstring *bn_getvch(const BIGNUM *v)
{
	cstring *s_be,*s_le; uint32_t le_sz,sz = BN_bn2mpi(v,NULL);
	if ( sz <= 4 ) // get MPI format size
		return cstr_new(NULL);
	// store bignum as MPI
	s_be = cstr_new_sz(sz);
	cstr_resize(s_be, sz);
	BN_bn2mpi(v,(uint8_t *) s_be->str);
	// copy-swap MPI to little endian, sans 32-bit size prefix
    le_sz = sz - 4;
	s_le = cstr_new_sz(le_sz);
	cstr_resize(s_le, le_sz);
	bu_reverse_copy((uint8_t *)s_le->str,(uint8_t *)s_be->str + 4, le_sz);
	cstr_free(s_be,true);
	return s_le;
}

cstring *base58_encode(const void *data_, size_t data_len)
{
    uint8_t swapbuf[data_len + 1]; uint32_t i,c; BN_CTX *ctx; BIGNUM bn58,bn0,bn,dv,rem;
    cstring *rs,*rs_swap; const uint8_t *data = data_;
    ctx = BN_CTX_new();
	BN_init(&bn58), BN_init(&bn0), BN_init(&bn), BN_init(&dv), BN_init(&rem);
	BN_set_word(&bn58,58), BN_set_word(&bn0,0);
	bu_reverse_copy(swapbuf,data,data_len);
	swapbuf[data_len] = 0;
	bn_setvch(&bn,swapbuf,sizeof(swapbuf));
	rs = cstr_new_sz(data_len * 138 / 100 + 1);
	while ( BN_cmp(&bn,&bn0) > 0 )
    {
		if ( !BN_div(&dv,&rem,&bn,&bn58,ctx) )
        {
            cstr_free(rs,true);
            rs = NULL;
            goto out;
        }
		BN_copy(&bn, &dv);
        c = (int32_t)BN_get_word(&rem);
		cstr_append_c(rs,base58_chars[c]);
	}
	for (i=0; i<data_len; i++)
    {
		if ( data[i] == 0 )
			cstr_append_c(rs,base58_chars[0]);
		else break;
	}
    rs_swap = cstr_new_sz(rs->len);
	cstr_resize(rs_swap, rs->len);
	bu_reverse_copy((uint8_t *)rs_swap->str,(uint8_t *)rs->str,rs->len);
	cstr_free(rs,true);
	rs = rs_swap;
out:
	BN_clear_free(&bn58);
	BN_clear_free(&bn0);
	BN_clear_free(&bn);
	BN_clear_free(&dv);
	BN_clear_free(&rem);
	BN_CTX_free(ctx);
	return rs;
}

/*void bu_Hash(unsigned char *md256, const void *data, size_t data_len)
{
	unsigned char md1[32];
	SHA256(data,data_len,md1);
	SHA256(md1,32,md256);
}

void bu_Hash4(unsigned char *md32, const void *data, size_t data_len)
{
	unsigned char md256[32];
	bu_Hash(md256,data,data_len);
	memcpy(md32,md256,4);
}*/

cstring *base58_encode_check(uint8_t addrtype,bool have_addrtype,const void *data,size_t data_len)
{
    uint8_t i,buf[64]; bits256 hash; cstring *s_enc;//,*s = cstr_new_sz(data_len + 1 + 4);
    buf[0] = addrtype;
    memcpy(buf+1,data,data_len);
    hash = bits256_doublesha256(0,buf,(int32_t)data_len+1);
    //bu_Hash4(md32,buf,(int32_t)data_len+1);
    for (i=0; i<4; i++)
    {
        buf[data_len+i+1] = hash.bytes[31-i];
        //printf("(%02x %02x) ",hash.bytes[31-i],md32[i]);
    }
    //printf("hash4 cmp\n");
    s_enc = base58_encode(buf,data_len+5);
    /*if ( 0 )
    {
        if ( have_addrtype )
            cstr_append_c(s,addrtype);
        cstr_append_buf(s,data,data_len);
        hash = bits256_doublesha256(0,(uint8_t *)s->str,(int32_t)s->len);
        cstr_append_buf(s,hash.bytes,4);
        //bu_Hash4(md32, s->str, s->len);
        //cstr_append_buf(s, md32, 4);
        s_enc = base58_encode(s->str, s->len);
        cstr_free(s,true);
    }*/
	return s_enc;
}

cstring *base58_decode(const char *s_in)
{
 	uint32_t leading_zero,be_sz; const char *p,*p1; BIGNUM bn58,bn,bnChar; BN_CTX *ctx; cstring *tmp_be,*tmp,*ret = NULL;
	ctx = BN_CTX_new();
	BN_init(&bn58), BN_init(&bn), BN_init(&bnChar);
	BN_set_word(&bn58,58), BN_set_word(&bn,0);
	while ( isspace((uint32_t)*s_in) )
		s_in++;
	for (p=s_in; *p; p++)
    {
		p1 = strchr(base58_chars,*p);
		if ( !p1 )
        {
			while (isspace((uint32_t)*p))
				p++;
			if ( *p != '\0' )
				goto out;
			break;
		}
		BN_set_word(&bnChar,(int32_t)(p1 - base58_chars));
		if (!BN_mul(&bn, &bn, &bn58, ctx))
			goto out;
		if (!BN_add(&bn, &bn, &bnChar))
			goto out;
	}
	tmp = bn_getvch(&bn);
	if ( (tmp->len >= 2) && (tmp->str[tmp->len - 1] == 0) && ((uint8_t)tmp->str[tmp->len - 2] >= 0x80))
		cstr_resize(tmp, tmp->len - 1);
    leading_zero = 0;
	for (p=s_in; *p==base58_chars[0]; p++)
		leading_zero++;
    be_sz = (uint32_t)tmp->len + (uint32_t)leading_zero;
	tmp_be = cstr_new_sz(be_sz);
	cstr_resize(tmp_be, be_sz);
	memset(tmp_be->str, 0, be_sz);
	bu_reverse_copy((uint8_t *)tmp_be->str + leading_zero,(uint8_t *)tmp->str,tmp->len);
	cstr_free(tmp,true);
	ret = tmp_be;
out:
	BN_clear_free(&bn58);
	BN_clear_free(&bn);
	BN_clear_free(&bnChar);
	BN_CTX_free(ctx);
	return ret;
}

cstring *base58_decode_check(uint8_t *addrtype,const char *s_in)
{
    bits256 hash; cstring *s = base58_decode(s_in);
	if ( s != 0 )
    {
        if ( s->len >= 4 )
        {
            // validate with trailing hash, then remove hash
            hash = bits256_doublesha256(0,(uint8_t *)s->str,(int32_t)s->len - 4);
            //bu_Hash4(md32,s->str,s->len - 4);
            if ( (s->str[s->len - 4]&0xff) == hash.bytes[31] && (s->str[s->len - 3]&0xff) == hash.bytes[30] &&(s->str[s->len - 2]&0xff) == hash.bytes[29] &&(s->str[s->len - 1]&0xff) == hash.bytes[28] )
            {
                cstr_resize(s,s->len - 4);
                if ( addrtype ) // if addrtype requested, remove from front of data string
                {
                    *addrtype = (uint8_t)s->str[0];
                    cstr_erase(s,0,1);
                }
                return(s);
            }
            else
            {
                char str[65]; printf("checkhash mismatch %02x %02x %02x %02x vs %02x %02x %02x %02x (%s)\n",s->str[s->len - 4]&0xff,s->str[s->len - 3]&0xff,s->str[s->len - 2]&0xff,s->str[s->len - 1]&0xff,hash.bytes[31],hash.bytes[30],hash.bytes[29],hash.bytes[28],bits256_str(str,hash));
            }
        }
        cstr_free(s,true);
    }
	return(NULL);
}

/* Generate a private key from just the secret parameter */
static int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
	int ok = 0;
	BN_CTX *ctx = NULL;
	EC_POINT *pub_key = NULL;
    
	if (!eckey) return 0;
    
	const EC_GROUP *group = EC_KEY_get0_group(eckey);
    
	if ((ctx = BN_CTX_new()) == NULL)
		goto err;
    
	pub_key = EC_POINT_new(group);
    
	if (pub_key == NULL)
		goto err;
    
	if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
		goto err;
    
	EC_KEY_set_private_key(eckey,priv_key);
	EC_KEY_set_public_key(eckey,pub_key);
    
	ok = 1;
    
err:
    
	if (pub_key)
		EC_POINT_free(pub_key);
	if (ctx != NULL)
		BN_CTX_free(ctx);
    
	return(ok);
}

int32_t bp_key_init(struct bp_key *key)
{
	memset(key, 0, sizeof(*key));
    
	key->k = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (!key->k)
		return false;
    
	return true;
}

void bp_key_free(struct bp_key *key)
{
	if (key->k) {
		EC_KEY_free(key->k);
		key->k = NULL;
	}
}

bool bp_key_generate(struct bp_key *key)
{
	if (!key->k)
		return false;
    
	if (!EC_KEY_generate_key(key->k))
		return false;
	if (!EC_KEY_check_key(key->k))
		return false;
    
	EC_KEY_set_conv_form(key->k, POINT_CONVERSION_COMPRESSED);
    
	return true;
}

bool bp_privkey_set(struct bp_key *key, const void *privkey_, size_t pk_len)
{
	const unsigned char *privkey = privkey_;
	if (!d2i_ECPrivateKey(&key->k, &privkey, pk_len))
		return false;
    
	if (!EC_KEY_check_key(key->k))
		return false;
    
	EC_KEY_set_conv_form(key->k, POINT_CONVERSION_COMPRESSED);
    
	return true;
}

bool bp_pubkey_set(struct bp_key *key, const void *pubkey_, size_t pk_len)
{
	const unsigned char *pubkey = pubkey_;
	if (!o2i_ECPublicKey(&key->k, &pubkey, pk_len))
		return false;
	if (pk_len == 33)
		EC_KEY_set_conv_form(key->k, POINT_CONVERSION_COMPRESSED);
	return true;
}

bool bp_key_secret_set(struct bp_key *key, const void *privkey_, size_t pk_len)
{
	bp_key_free(key);
    
	if (!privkey_ || pk_len != 32)
		return false;
    
	const unsigned char *privkey = privkey_;
	BIGNUM *bn = BN_bin2bn(privkey, 32, BN_new());
	if (!bn)
		return false;
    
	key->k = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (!key->k)
		goto err_out;
    
	if (!EC_KEY_regenerate_key(key->k, bn))
		goto err_out;
	if (!EC_KEY_check_key(key->k))
		return false;
    
	EC_KEY_set_conv_form(key->k, POINT_CONVERSION_COMPRESSED);
    
	BN_clear_free(bn);
	return true;
    
err_out:
	bp_key_free(key);
	BN_clear_free(bn);
	return false;
}

bool bp_privkey_get(const struct bp_key *key, void **privkey, size_t *pk_len)
{
	if (!EC_KEY_check_key(key->k))
		return false;
    
	size_t sz = i2d_ECPrivateKey(key->k, 0);
	unsigned char *orig_mem, *mem = mycalloc('b',1,sz);
	orig_mem = mem;
	i2d_ECPrivateKey(key->k, &mem);
    
	*privkey = orig_mem;
	*pk_len = sz;
    
	return true;
}

bool bp_pubkey_get(const struct bp_key *key, void **pubkey, size_t *pk_len)
{
	if (!EC_KEY_check_key(key->k))
		return false;
    
	size_t sz = i2o_ECPublicKey(key->k, 0);
	unsigned char *orig_mem, *mem = mycalloc('b',1,sz);
	orig_mem = mem;
	i2o_ECPublicKey(key->k, &mem);
    
	*pubkey = orig_mem;
	*pk_len = sz;
    
	return true;
}

bool bp_key_secret_get(void *p, size_t len, const struct bp_key *key)
{
	if (!p || len < 32 || !key)
		return false;
    
	/* zero buffer */
	memset(p, 0, len);
    
	/* get bignum secret */
	const BIGNUM *bn = EC_KEY_get0_private_key(key->k);
	if (!bn)
		return false;
	int nBytes = BN_num_bytes(bn);
    
	/* store secret at end of buffer */
	int n = BN_bn2bin(bn, p + (len - nBytes));
	if (n != nBytes)
		return false;
    
	return true;
}

bool bp_sign(EC_KEY *key, const void *data, size_t data_len,void **sig_, size_t *sig_len_)
{
	size_t sig_sz = ECDSA_size(key);
	void *sig = mycalloc('b',1, sig_sz);
	unsigned int sig_sz_out = (int32_t)sig_sz;
    *sig_len_ = 0;
	int src = ECDSA_sign(0, data, (int32_t)data_len, sig, &sig_sz_out, key);
	if (src != 1) {
		myfree(sig,sig_sz);
		return false;
	}
    
	*sig_ = sig;
	*sig_len_ = sig_sz_out;
    
	return true;
}

bool bp_verify(EC_KEY *key, const void *data, size_t data_len,const void *sig_, size_t sig_len)
{
	const unsigned char *sig = sig_;
	ECDSA_SIG *esig;
	bool b = false;
    
	esig = ECDSA_SIG_new();
	if (!esig)
		goto out;
    
	if (!d2i_ECDSA_SIG(&esig, &sig, sig_len))
		goto out_free;
    
	b = ECDSA_do_verify(data,(int32_t) data_len, esig, key) == 1;
    
out_free:
	ECDSA_SIG_free(esig);
out:
	return b;
}

int32_t btc_getpubkey(char pubkeystr[67],uint8_t pubkeybuf[33],struct bp_key *key)
{
    void *pubkey = 0; size_t len = 0;
    bp_pubkey_get(key,&pubkey,&len);
    //printf("btc_getpubkey len.%ld %p\n",len,pubkey);
    if ( pubkey != 0 )
    {
        if ( pubkeystr != 0 )
        {
            if ( len < 34 )
            {
                init_hexbytes_noT(pubkeystr,pubkey,(int32_t)len);
                memcpy(pubkeybuf,pubkey,len);
            }
            else printf("btc_getpubkey error len.%d\n",(int32_t)len), len = -1;
        }
    } else len = -1;
    return((int32_t)len);
}

int32_t btc_convrmd160(char *coinaddr,uint8_t addrtype,uint8_t rmd160[20])
{
    cstring *btc_addr;
    if ( (btc_addr= base58_encode_check(addrtype,true,rmd160,20)) != 0 )
    {
        strcpy(coinaddr,btc_addr->str);
        cstr_free(btc_addr,true);
        return(0);
    }
    return(-1);
}

int32_t btc_coinaddr(char *coinaddr,uint8_t addrtype,char *pubkeystr)
{
    uint8_t rmd160[20]; char hashstr[41];
    calc_OP_HASH160(hashstr,rmd160,pubkeystr);
    return(btc_convrmd160(coinaddr,addrtype,rmd160));
}

int32_t btc_convaddr(char *hexaddr,char *addr58)
{
    uint8_t addrtype; cstring *cstr;
    if ( (cstr= base58_decode_check(&addrtype,(const char *)addr58)) != 0 )
    {
        sprintf(hexaddr,"%02x",addrtype);
        init_hexbytes_noT(hexaddr+2,(void *)cstr->str,cstr->len);
        cstr_free(cstr,true);
        return(0);
    }
    return(-1);
}

int32_t btc_addr2univ(uint8_t *addrtypep,uint8_t rmd160[20],char *coinaddr)
{
    char hexstr[512]; uint8_t hex[21];
    if ( btc_convaddr(hexstr,coinaddr) == 0 )
    {
        decode_hex(hex,21,hexstr);
        *addrtypep = hex[0];
        memcpy(rmd160,hex+1,20);
        return(0);
    }
    return(-1);
}

int32_t btc_priv2wif(char *wifstr,uint8_t privkey[32],uint8_t addrtype)
{
    uint8_t tmp[128]; char hexstr[67]; cstring *btc_addr;
    memcpy(tmp,privkey,32);
    tmp[32] = 1;
    init_hexbytes_noT(hexstr,tmp,32);
    if ( (btc_addr= base58_encode_check(addrtype,true,tmp,33)) != 0 )
    {
        strcpy(wifstr,btc_addr->str);
        cstr_free(btc_addr,true);
    }
    printf("-> (%s) -> wif.(%s) addrtype.%02x\n",hexstr,wifstr,addrtype);
    return(0);
}

int32_t btc_wif2priv(uint8_t *addrtypep,uint8_t privkey[32],char *wifstr)
{
    cstring *cstr; int32_t len = -1;
    if ( (cstr= base58_decode_check(addrtypep,(const char *)wifstr)) != 0 )
    {
        init_hexbytes_noT((void *)privkey,(void *)cstr->str,cstr->len);
        if ( cstr->str[cstr->len-1] == 0x01 )
            cstr->len--;
        memcpy(privkey,cstr->str,cstr->len);
        len = (int32_t)cstr->len;
        char tmp[138];
        btc_priv2wif(tmp,privkey,*addrtypep);
        printf("addrtype.%02x wifstr.(%llx) len.%d\n",*addrtypep,*(long long *)privkey,len);
        cstr_free(cstr,true);
    }
    return(len);
}

int32_t btc_setprivkey(struct bp_key *key,char *wifstr)
{
    uint8_t privkey[512],privkeytype; int32_t len;
    len = btc_wif2priv(&privkeytype,privkey,wifstr);
    if ( len < 0 || bp_key_init(key) == 0 || bp_key_secret_set(key,privkey,len) == 0 )
    {
        printf("error setting privkey\n");
        return(-1);
    }
    return(0);
}

void btc_freekey(void *key)
{
    bp_key_free(key);
    myfree(key,sizeof(struct bp_key));
}

int32_t btc_priv2pub(uint8_t pubkey[33],uint8_t privkey[32])
{
    size_t len; void *pub = 0; 
    struct bp_key key;
    if ( bp_key_init(&key) != 0 && bp_key_secret_set(&key,privkey,32) != 0 )
    {
        bp_pubkey_get(&key,&pub,&len);
        bp_key_free(&key);
        if ( len == 33 )
            memcpy(pubkey,pub,33);
        if ( pub != 0 )
            myfree(pub,len);
        return(0);
    }
    bp_key_free(&key);
    return(-1);
}

int32_t btc_pub2rmd(uint8_t rmd160[20],uint8_t pubkey[33])
{
    char pubkeystr[67],hashstr[41];
    init_hexbytes_noT(pubkeystr,pubkey,33);
    calc_OP_HASH160(hashstr,rmd160,pubkeystr);
    return(0);
}

int32_t create_MofN(uint8_t addrtype,char *redeemScript,char *scriptPubKey,char *p2shaddr,char *pubkeys[],int32_t M,int32_t N)
{
    cstring *btc_addr; uint8_t pubkey[33],tmpbuf[24],hex[4096]; int32_t i,n = 0;
    hex[n++] = 0x50 + M;
    for (i=0; i<N; i++)
    {
        decode_hex(pubkey,33,pubkeys[i]);
        hex[n++] = 33;
        memcpy(&hex[n],pubkey,33);
        n += 33;
    }
    hex[n++] = 0x50 + N;
    hex[n++] = SCRIPT_OP_CHECKMULTISIG;
    for (i=0; i<n; i++)
    {
        redeemScript[i*2] = hexbyte((hex[i]>>4) & 0xf);
        redeemScript[i*2 + 1] = hexbyte(hex[i] & 0xf);
        //fprintf(stderr,"%02x",hex[i]);
    }
    //fprintf(stderr," n.%d\n",n);
    redeemScript[n*2] = 0;
    calc_OP_HASH160(0,tmpbuf+2,redeemScript);
    //printf("op160.(%s)\n",redeemScript);
    tmpbuf[0] = SCRIPT_OP_HASH160;
    tmpbuf[1] = 20;
    tmpbuf[22] = SCRIPT_OP_EQUAL;
    init_hexbytes_noT(scriptPubKey,tmpbuf,23);
    p2shaddr[0] = 0;
    if ( (btc_addr= base58_encode_check(addrtype,true,tmpbuf+2,20)) != 0 )
    {
        if ( strlen(btc_addr->str) < 36 )
            strcpy(p2shaddr,btc_addr->str);
        cstr_free(btc_addr,true);
    }
    return(n);
}

int32_t btc_pub65toaddr(char *coinaddr,uint8_t addrtype,char pubkey[131],uint8_t *pk)
{
    int32_t retval = -1; char pubkeystr[67]; uint8_t *ptr; size_t len;
    EC_KEY *key;
  	key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if ( key != 0 )
    {
        if (!EC_KEY_generate_key(key))
        {
            printf("generate error\n");
            return(-1);
        }
        if (!EC_KEY_check_key(key))
        {
            printf("key check error0\n");
            return(-1);
        }
        pubkeystr[0] = 0;
      	const EC_GROUP *group = EC_KEY_get0_group(key);
        EC_POINT *pkey = EC_POINT_new(group);
        EC_POINT_hex2point(group,pubkey,pkey,NULL);
        if (!EC_KEY_check_key(key))
        {
            printf("key check error\n");
            return(-1);
        }
        retval = EC_KEY_set_public_key(key,pkey);
        if (!EC_KEY_check_key(key))
        {
            printf("key check error2\n");
            return(-1);
        }
        len = i2o_ECPublicKey(key,0);
        ptr = mycalloc('b',1,len);
        i2o_ECPublicKey(key,&ptr);
        printf("btc_getpubkey len.%ld %p\n",(long)len,ptr);
        EC_KEY_set_conv_form(key,POINT_CONVERSION_COMPRESSED);
        EC_KEY_free(key);
    }
    return(retval);
}

struct iguana_waddress *iguana_waddresscalc(uint8_t pubtype,uint8_t wiftype,struct iguana_waddress *addr,bits256 privkey)
{
    memset(addr,0,sizeof(*addr));
    addr->privkey = privkey;
    if ( btc_priv2pub(addr->pubkey,addr->privkey.bytes) == 0 && btc_priv2wif(addr->wifstr,addr->privkey.bytes,wiftype) == 0 && btc_pub2rmd(addr->rmd160,addr->pubkey) == 0 && btc_convrmd160(addr->coinaddr,pubtype,addr->rmd160) == 0 )
    {
        addr->wiftype = wiftype;
        addr->type = pubtype;
        return(addr);
    }
    return(0);
}

int32_t iguana_ver(uint8_t *sig,int32_t siglen,uint8_t *data,int32_t datalen,bits256 pub)
{
    struct bp_key key; uint8_t pubkey[33];
    memcpy(pubkey+1,pub.bytes,sizeof(pub));
    if ( bp_key_init(&key) != 0 )
    {
        for (pubkey[0]=2; pubkey[0]<=3; pubkey[0]++)
        {
            if ( bp_pubkey_set(&key,pubkey,33) != 0 )
            {
                if ( bp_verify(key.k,data,datalen,sig,siglen) != 0 )
                {
                    printf("verified.[%d]\n",pubkey[0]);
                    return(0);
                }
            }
        }
    }
    return(-1);
}

int32_t iguana_sig(uint8_t *sig,int32_t maxsize,uint8_t *data,int32_t datalen,bits256 privkey)
{
    struct bp_key key; void *sigptr = NULL; size_t siglen = 0;
    if ( bp_key_init(&key) != 0 && bp_key_secret_set(&key,privkey.bytes,sizeof(privkey)) != 0 )
    {
        if ( bp_sign(key.k,data,datalen,&sigptr,&siglen) != 0 )
        {
            if ( siglen < maxsize && sigptr != 0 )
            {
                memcpy(sig,sigptr,siglen);
                free(sigptr);
                return((int32_t)siglen);
            }
        }
    }
    return(-1);
}
/*char *iguana_txsign(struct iguana_info *coin,struct cointx_info *refT,int32_t redeemi,char *redeemscript,char sigs[][256],int32_t n,uint8_t privkey[32],int32_t privkeyind)
{
    char hexstr[16384]; bits256 hash2; uint8_t data[4096],sigbuf[512]; struct bp_key key;
    struct cointx_info *T; int32_t i,len; void *sig = NULL; size_t siglen = 0; struct cointx_input *vin;
    if ( bp_key_init(&key) != 0 && bp_key_secret_set(&key,privkey,32) != 0 )
    {
        if ( (T= calloc(1,sizeof(*T))) == 0 )
            return(0);
        *T = *refT; vin = &T->inputs[redeemi];
        for (i=0; i<T->numinputs; i++)
            strcpy(T->inputs[i].sigs,"00");
        strcpy(vin->sigs,redeemscript);
        vin->sequence = (uint32_t)-1;
        T->nlocktime = 0;
        //disp_cointx(&T);
        emit_cointx(&hash2,data,sizeof(data),T,oldtx_format,SIGHASH_ALL);
        //printf("HASH2.(%llx)\n",(long long)hash2.txid);
        if ( bp_sign(&key,hash2.bytes,sizeof(hash2),&sig,&siglen) != 0 )
        {
            memcpy(sigbuf,sig,siglen);
            sigbuf[siglen++] = SIGHASH_ALL;
            init_hexbytes_noT(sigs[privkeyind],sigbuf,(int32_t)siglen);
            strcpy(vin->sigs,"00");
            for (i=0; i<n; i++)
            {
                if ( sigs[i][0] != 0 )
                {
                    sprintf(vin->sigs + strlen(vin->sigs),"%02x%s",(int32_t)strlen(sigs[i])>>1,sigs[i]);
                    //printf("(%s).%ld ",sigs[i],strlen(sigs[i]));
                }
            }
            len = (int32_t)(strlen(redeemscript)/2);
            if ( len >= 0xfd )
                sprintf(&vin->sigs[strlen(vin->sigs)],"4d%02x%02x",len & 0xff,(len >> 8) & 0xff);
            else sprintf(&vin->sigs[strlen(vin->sigs)],"4c%02x",len);
            sprintf(&vin->sigs[strlen(vin->sigs)],"%s",redeemscript);
            //printf("after A.(%s) othersig.(%s) siglen.%02lx -> (%s)\n",hexstr,othersig != 0 ? othersig : "",siglen,vin->sigs);
            //printf("vinsigs.(%s) %ld\n",vin->sigs,strlen(vin->sigs));
            _emit_cointx(hexstr,sizeof(hexstr),T,oldtx_format);
            //disp_cointx(&T);
            free(T);
            return(clonestr(hexstr));
        }
        else printf("error signing\n");
        free(T);
    }
    return(0);
}*/

char *makekeypair(struct iguana_info *coin)
{
    struct iguana_waddress addr; char str[67]; cJSON *retjson = cJSON_CreateObject();
    if ( iguana_waddresscalc(coin->chain->pubtype,coin->chain->wiftype,&addr,rand256(1)) == 0 )
    {
        init_hexbytes_noT(str,addr.pubkey,33);
        jaddstr(retjson,"result",str);
        jaddstr(retjson,"privkey",bits256_str(str,addr.privkey));
    } else jaddstr(retjson,"error","cant create address");
    return(jprint(retjson,1));
}

cJSON *iguana_pubkeyjson(struct iguana_info *coin,char *pubkeystr)
{
    cJSON *json = cJSON_CreateObject();
    return(json);
}
