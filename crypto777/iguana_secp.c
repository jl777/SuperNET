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

#include <ctype.h>
#include <string.h>
#include "../includes/curve25519.h"
#include "../includes/openssl/ec.h"
#include "../includes/openssl/ecdsa.h"
#include "../includes/openssl/obj_mac.h"

static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
struct bp_key { EC_KEY *k; };

void bn_mpi2bn(BIGNUM *vo,uint8_t *data,int32_t datalen)
{
	uint8_t vch2[64 + 4]; uint32_t i,vch2_len = (int32_t)datalen + 4;
    if ( datalen < sizeof(vch2) )
    {
        vch2[0] = (datalen >> 24) & 0xff;
        vch2[1] = (datalen >> 16) & 0xff;
        vch2[2] = (datalen >> 8) & 0xff;
        vch2[3] = (datalen >> 0) & 0xff;
        for (i=0; i<datalen; i++)
            vch2[4 + datalen - i - 1] = data[i];
        BN_mpi2bn(vch2,vch2_len,vo);
    }
}

int32_t bn_bn2mpi(uint8_t *data,const BIGNUM *v)
{
	uint8_t s_be[64]; int32_t i,sz = BN_bn2mpi(v,NULL);
	if ( sz >= 4 && sz < sizeof(s_be) ) // get MPI format size
    {
        BN_bn2mpi(v,s_be);
        // copy-swap MPI to little endian, sans 32-bit size prefix
        sz -= 4;
        for (i=0; i<sz; i++)
            data[sz - i - 1] = s_be[i + 4];
    }
	return(sz);
}

char *bitcoin_base58encode(char *coinaddr,uint8_t *data_,int32_t datalen)
{
	BIGNUM bn58,bn0,bn,dv,rem; BN_CTX *ctx; uint32_t i,n,flag=0; uint8_t swapbuf[512],rs[512];
    const uint8_t *data = (void *)data_;
    rs[0] = 0;
    n = 0;
    if ( datalen < (sizeof(swapbuf) >> 1) )
    {
        ctx = BN_CTX_new();
        BN_init(&bn58), BN_init(&bn0), BN_init(&bn), BN_init(&dv), BN_init(&rem);
        BN_set_word(&bn58,58);
        BN_set_word(&bn0,0);
        for (i=0; i<datalen; i++)
            swapbuf[datalen - i - 1] = data[i];
        swapbuf[datalen] = 0;
        bn_mpi2bn(&bn,swapbuf,datalen+1);
        while ( BN_cmp(&bn,&bn0) > 0 )
        {
            if ( BN_div(&dv,&rem,&bn,&bn58,ctx) == 0 )
            {
                flag = -1;
                break;
            }
            BN_copy(&bn,&dv);
            rs[n++] = base58_chars[BN_get_word(&rem)];
        }
        if ( flag == 0 )
        {
            for (i=0; i<datalen; i++)
            {
                if ( data[i] == 0 )
                    rs[n++] = base58_chars[0];
                else break;
            }
            for (i=0; i<n; i++)
                coinaddr[n - i - 1] = rs[i];
            coinaddr[n] = 0;
        }
        BN_clear_free(&bn58), BN_clear_free(&bn0), BN_clear_free(&bn), BN_clear_free(&dv), BN_clear_free(&rem);
        BN_CTX_free(ctx);
        return(coinaddr);
    }
    return(0);
}

int32_t bitcoin_base58decode(uint8_t *data,char *coinaddr)
{
 	uint32_t zeroes,be_sz=0,i,len; const char *p,*p1; BIGNUM bn58,bn,bnChar; uint8_t revdata[64]; BN_CTX *ctx;
	ctx = BN_CTX_new();
	BN_init(&bn58), BN_init(&bn), BN_init(&bnChar);
    BN_set_word(&bn58,58), BN_set_word(&bn,0);
	while ( isspace((uint32_t)(*coinaddr & 0xff)) )
		coinaddr++;
	for (p=coinaddr; *p; p++)
    {
		p1 = strchr(base58_chars,*p);
		if ( p1 == 0 )
        {
			while (isspace((uint32_t)*p))
				p++;
			if ( *p != '\0' )
				goto out;
			break;
		}
		BN_set_word(&bnChar,(int32_t)(p1 - base58_chars));
		if ( BN_mul(&bn,&bn,&bn58,ctx) == 0 || BN_add(&bn,&bn,&bnChar) == 0 )
			goto out;
	}
    len = bn_bn2mpi(revdata,&bn);
	if ( len >= 2 && revdata[len - 1] == 0 && revdata[len - 2] >= 0x80 )
		len--;
    zeroes = 0;
	for (p=coinaddr; *p==base58_chars[0]; p++)
		zeroes++;
    be_sz = (uint32_t)len + (uint32_t)zeroes;
	memset(data,0,be_sz);
    for (i=0; i<len; i++)
        data[i+zeroes] = revdata[len - 1 - i];
    //printf("len.%d be_sz.%d zeroes.%d data[0] %02x\n",len,be_sz,zeroes,data[0]);
out:
	BN_clear_free(&bn58), BN_clear_free(&bn), BN_clear_free(&bnChar);
	BN_CTX_free(ctx);
	return(be_sz);
}

EC_KEY *bitcoin_privkeyset(uint8_t *oddevenp,bits256 *pubkeyp,bits256 privkey)
{
    BIGNUM *bn; BN_CTX *ctx = NULL; uint8_t *ptr,tmp[33]; EC_POINT *pub_key = NULL; const EC_GROUP *group;
    EC_KEY *KEY = EC_KEY_new_by_curve_name(NID_secp256k1);
    *oddevenp = 0;
    EC_KEY_set_conv_form(KEY,POINT_CONVERSION_COMPRESSED);
    {
        if ( (group= EC_KEY_get0_group(KEY)) != 0 && (ctx= BN_CTX_new()) != 0 )
        {
            if ( (pub_key= EC_POINT_new(group)) != 0 )
            {
                if ( (bn= BN_bin2bn(privkey.bytes,sizeof(privkey),BN_new())) != 0 )
                {
                    if ( EC_POINT_mul(group,pub_key,bn,NULL,NULL,ctx) > 0 )
                    {
                        EC_KEY_set_private_key(KEY,bn);
                        EC_KEY_set_public_key(KEY,pub_key);
                        ptr = tmp;
                        i2o_ECPublicKey(KEY,&ptr);
                        *oddevenp = tmp[0];
                        memcpy(pubkeyp->bytes,&tmp[1],sizeof(*pubkeyp));
                    }
                    BN_clear_free(bn);
                }
                EC_POINT_free(pub_key);
            }
            BN_CTX_free(ctx);
        }
    }
    return(KEY);
}

bits256 bitcoin_pubkey33(uint8_t *data,bits256 privkey)
{
    uint8_t oddeven; bits256 pubkey;
    EC_KEY *KEY;
    if ( (KEY= bitcoin_privkeyset(&oddeven,&pubkey,privkey)) != 0 )
    {
        data[0] = oddeven;
        memcpy(data+1,pubkey.bytes,sizeof(pubkey));
        EC_KEY_free(KEY);
    }
    return(pubkey);
}

int32_t bitcoin_sign(uint8_t *sig,int32_t maxlen,uint8_t *data,int32_t datalen,bits256 privkey)
{
    uint32_t siglen; EC_KEY *KEY; uint8_t oddeven; bits256 pubkey; int32_t retval = -1;
    if ( (KEY= bitcoin_privkeyset(&oddeven,&pubkey,privkey)) != 0 )
    {
        if ( ECDSA_sign(0,data,datalen,sig,&siglen,KEY) > 0 && siglen <= maxlen )
            retval = siglen;
        EC_KEY_free(KEY);
    }
    return(retval);
}

int32_t bitcoin_verify(uint8_t *sig,int32_t siglen,uint8_t *data,int32_t datalen,uint8_t *pubkey,int32_t len)
{
    ECDSA_SIG *esig; int32_t retval = -1; uint8_t tmp[33],*ptr,*sigptr = sig; EC_KEY *KEY = 0;
    if ( len < 0 )
        return(-1);
    if ( (esig= ECDSA_SIG_new()) != 0 )
    {
        if ( d2i_ECDSA_SIG(&esig,(const uint8_t **)&sigptr,siglen) != 0 )
        {
            if ( (KEY= EC_KEY_new_by_curve_name(NID_secp256k1)) != 0 )
            {
                EC_KEY_set_conv_form(KEY,POINT_CONVERSION_COMPRESSED);
                if ( len == 32 )
                {
                    memcpy(tmp+1,pubkey,len);
                    for (tmp[0]=2; tmp[0]<=3; tmp[0]++)
                    {
                        ptr = tmp;
                        o2i_ECPublicKey(&KEY,(const uint8_t **)&ptr,33);
                        if ( ECDSA_do_verify(data,datalen,esig,KEY) > 0 )
                        {
                            retval = 0;
                            break;
                        }
                    }
                }
                else
                {
                    ptr = pubkey;
                    o2i_ECPublicKey(&KEY,(const uint8_t **)&ptr,len);
                    if ( ECDSA_do_verify(data,datalen,esig,KEY) > 0 )
                        retval = 0;
                }
                EC_KEY_free(KEY);
            }
        }
        ECDSA_SIG_free(esig);
    }
    return(retval);
}


