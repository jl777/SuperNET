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
#include <stdio.h>
#include <stdlib.h>
#include "../includes/curve25519.h"
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_ecdh.h"
#include "secp256k1/include/secp256k1_schnorr.h"
#include "secp256k1/include/secp256k1_rangeproof.h"
#include "secp256k1/include/secp256k1_recovery.h"
#define bits256_nonz(a) (((a).ulongs[0] | (a).ulongs[1] | (a).ulongs[2] | (a).ulongs[3]) != 0)

#define SECP_ENSURE_CTX int32_t flag = 0; if ( ctx == 0 ) { ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY); secp256k1_pedersen_context_initialize(ctx); secp256k1_rangeproof_context_initialize(ctx); flag++; } else flag = 0; if ( ctx != 0 )
#define ENDSECP_ENSURE_CTX if ( flag != 0 ) secp256k1_context_destroy(ctx);

bits256 bitcoin_randkey(secp256k1_context *ctx)
{
    int32_t i; bits256 privkey;
    SECP_ENSURE_CTX
    {
        for (i=0; i<100; i++)
        {
            privkey = rand256(0);
            if ( secp256k1_ec_seckey_verify(ctx,privkey.bytes) > 0 )
            {
                ENDSECP_ENSURE_CTX
                return(privkey);
            }
        }
        ENDSECP_ENSURE_CTX
    }
    fprintf(stderr,"couldnt generate valid bitcoin privkey. something is REALLY wrong. exiting\n");
    exit(-1);
}

bits256 bitcoin_pubkey33(secp256k1_context *ctx,uint8_t *data,bits256 privkey)
{
    size_t plen; bits256 pubkey; secp256k1_pubkey secppub;
    memset(pubkey.bytes,0,sizeof(pubkey));
    SECP_ENSURE_CTX
    {
        if ( secp256k1_ec_seckey_verify(ctx,privkey.bytes) == 0 )
        {
            printf("bitcoin_sign illegal privkey\n");
            return(pubkey);
        }
        if ( secp256k1_ec_pubkey_create(ctx,&secppub,privkey.bytes) > 0 )
        {
            plen = 33;
            secp256k1_ec_pubkey_serialize(ctx,data,&plen,&secppub,SECP256K1_EC_COMPRESSED);
            if ( plen == 33 )
                memcpy(pubkey.bytes,data+1,sizeof(pubkey));
        }
        ENDSECP_ENSURE_CTX
    }
    return(pubkey);
}

int32_t bitcoin_sign(void *ctx,char *symbol,uint8_t *sig,bits256 txhash2,bits256 privkey,int32_t recoverflag)
{
    int32_t fCompressed = 1;
    secp256k1_ecdsa_signature SIG; secp256k1_ecdsa_recoverable_signature rSIG; bits256 extra_entropy,seed; int32_t recid,retval = -1; size_t siglen = 72; secp256k1_pubkey SECPUB,CHECKPUB;
    seed = rand256(0);
    extra_entropy = rand256(0);
    SECP_ENSURE_CTX
    {
        if ( secp256k1_ec_seckey_verify(ctx,privkey.bytes) == 0 )
        {
            printf("bitcoin_sign illegal privkey\n");
            return(-1);
        }
        if ( secp256k1_context_randomize(ctx,seed.bytes) > 0 )
        {
            if ( recoverflag != 0 )
            {
                if ( secp256k1_ecdsa_sign_recoverable(ctx,&rSIG,txhash2.bytes,privkey.bytes,secp256k1_nonce_function_rfc6979,extra_entropy.bytes) > 0 )
                {
                    recid = -1;
                    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx,sig+1,&recid,&rSIG);
                    if ( secp256k1_ecdsa_recover(ctx,&SECPUB,&rSIG,txhash2.bytes) > 0 )
                    {
                        if ( secp256k1_ec_pubkey_create(ctx,&CHECKPUB,privkey.bytes) > 0 )
                        {
                            if ( memcmp(&SECPUB,&CHECKPUB,sizeof(SECPUB)) == 0 )
                            {
                                sig[0] = 27 + recid + (fCompressed != 0 ? 4 : 0);
                                retval = 64 + 1;
                            }
                            else printf("secpub mismatch\n");
                        } else printf("pubkey create error\n");
                    } else printf("recover error\n");
                } else printf("secp256k1_ecdsa_sign_recoverable error\n");
            }
            else
            {
                if ( secp256k1_ecdsa_sign(ctx,&SIG,txhash2.bytes,privkey.bytes,secp256k1_nonce_function_rfc6979,extra_entropy.bytes) > 0 )
                {
                    if ( secp256k1_ecdsa_signature_serialize_der(ctx,sig,&siglen,&SIG) > 0 )
                        retval = (int32_t)siglen;
                }
            }
        }
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_recoververify(void *ctx,char *symbol,uint8_t *sig65,bits256 messagehash2,uint8_t *pubkey)
{
    int32_t retval = -1; size_t plen; secp256k1_pubkey PUB; secp256k1_ecdsa_signature SIG; secp256k1_ecdsa_recoverable_signature rSIG;
    pubkey[0] = 0;
    SECP_ENSURE_CTX
    {
        plen = (sig65[0] <= 31) ? 65 : 33;
        secp256k1_ecdsa_recoverable_signature_parse_compact(ctx,&rSIG,sig65 + 1,0);
        secp256k1_ecdsa_recoverable_signature_convert(ctx,&SIG,&rSIG);
        if ( secp256k1_ecdsa_recover(ctx,&PUB,&rSIG,messagehash2.bytes) > 0 )
        {
            secp256k1_ec_pubkey_serialize(ctx,pubkey,&plen,&PUB,plen == 65 ? SECP256K1_EC_UNCOMPRESSED : SECP256K1_EC_COMPRESSED);
            if ( secp256k1_ecdsa_verify(ctx,&SIG,messagehash2.bytes,&PUB) > 0 )
                retval = 0;
            else printf("secp256k1_ecdsa_verify error\n");
        } else printf("secp256k1_ecdsa_recover error\n");
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_verify(void *ctx,uint8_t *sig,int32_t siglen,bits256 txhash2,uint8_t *pubkey,int32_t plen)
{
    int32_t retval = -1; secp256k1_pubkey PUB; secp256k1_ecdsa_signature SIG;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_ec_pubkey_parse(ctx,&PUB,pubkey,plen) > 0 )
        {
            secp256k1_ecdsa_signature_parse_der(ctx,&SIG,sig,siglen);
            if ( secp256k1_ecdsa_verify(ctx,&SIG,txhash2.bytes,&PUB) > 0 )
                retval = 0;
        }
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

bits256 bitcoin_sharedsecret(void *ctx,bits256 privkey,uint8_t *pubkey,int32_t plen)
{
    int32_t retval = -1; bits256 shared; secp256k1_pubkey PUB;
    memset(shared.bytes,0,sizeof(shared));
    SECP_ENSURE_CTX
    {
        if ( secp256k1_ec_pubkey_parse(ctx,&PUB,pubkey,plen) > 0 )
        {
            if ( secp256k1_ecdh(ctx,shared.bytes,&PUB,privkey.bytes) > 0 )
                retval = 0;
            else memset(shared.bytes,0,sizeof(shared));
        }
        ENDSECP_ENSURE_CTX
    }
    return(shared);
}

int32_t bitcoin_schnorr_sign(void *ctx,uint8_t *sig64,bits256 txhash2,bits256 privkey)
{
    int32_t retval = -1;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_schnorr_sign(ctx,sig64,txhash2.bytes,privkey.bytes,secp256k1_nonce_function_rfc6979,rand256(0).bytes) > 0 )
            retval = 0;
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_schnorr_verify(void *ctx,uint8_t *sig64,bits256 txhash2,uint8_t *pubkey,int32_t plen)
{
    int32_t retval = -1; secp256k1_pubkey PUB;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_ec_pubkey_parse(ctx,&PUB,pubkey,plen) > 0 )
        {
            if ( secp256k1_schnorr_verify(ctx,sig64,txhash2.bytes,&PUB) > 0 )
                retval = 0;
        }
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_schnorr_recover(void *ctx,uint8_t *pubkey,uint8_t *sig64,bits256 txhash2)
{
    int32_t retval = -1; secp256k1_pubkey PUB; size_t plen;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_schnorr_recover(ctx,&PUB,sig64,txhash2.bytes) > 0 )
        {
            plen = 33;
            secp256k1_ec_pubkey_serialize(ctx,pubkey,&plen,&PUB,SECP256K1_EC_COMPRESSED);
            retval = 0;
        }
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

bits256 bitcoin_schnorr_noncepair(void *ctx,uint8_t *pubnonce,bits256 txhash2,bits256 privkey) //exchange
{
    int32_t retval = -1; size_t plen; secp256k1_pubkey PUB; bits256 privnonce;
    memset(privnonce.bytes,0,sizeof(privnonce));
    pubnonce[0] = 0;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_schnorr_generate_nonce_pair(ctx,&PUB,privnonce.bytes,txhash2.bytes,privkey.bytes,NULL,NULL) > 0 )
        {
            plen = 33;
            secp256k1_ec_pubkey_serialize(ctx,pubnonce,&plen,&PUB,SECP256K1_EC_COMPRESSED);
            retval = 0;
        }
        ENDSECP_ENSURE_CTX
    }
    return(privnonce);
}

int32_t bitcoin_schnorr_partialsign(void *ctx,uint8_t *sig64,uint8_t *combined_pub,bits256 txhash2,bits256 privkey,bits256 privnonce,uint8_t *pubptrs[],int32_t n) // generate and exchange
{
    int32_t bitcoin_pubkeylen(const uint8_t *pubkey);
    int32_t i,retval = -1; secp256k1_pubkey PUBall,**PUBptrs; size_t plen;
    SECP_ENSURE_CTX
    {
        PUBptrs = calloc(n,sizeof(*PUBptrs));
        for (i=0; i<n; i++)
        {
            PUBptrs[i] = calloc(1,sizeof(secp256k1_pubkey));
            if ( secp256k1_ec_pubkey_parse(ctx,PUBptrs[i],pubptrs[i],bitcoin_pubkeylen(pubptrs[i])) == 0 )
                break;
        }
        if ( n > 0 && secp256k1_ec_pubkey_combine(ctx,&PUBall,(void *)PUBptrs,n) > 0 )
        {
            plen = 33;
            if ( secp256k1_schnorr_partial_sign(ctx,sig64,txhash2.bytes,privkey.bytes,&PUBall,privnonce.bytes) > 0 )
            {
                secp256k1_ec_pubkey_serialize(ctx,combined_pub,&plen,&PUBall,SECP256K1_EC_COMPRESSED);
                retval = 0;
            }
        }
        free(PUBptrs);
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_schnorr_combine(void *ctx,uint8_t *sig64,uint8_t *allpub,uint8_t **sigs,int32_t n,bits256 txhash2)
{
    int32_t rc,retval = -1;
    SECP_ENSURE_CTX
    {
        if ( (rc= secp256k1_schnorr_partial_combine(ctx,sig64,(void *)sigs,n)) > 0 )
        {
            if ( bitcoin_schnorr_recover(ctx,allpub,sig64,txhash2) == 0 )
            {
                if ( bitcoin_schnorr_verify(ctx,sig64,txhash2,allpub,33) == 0 )
                    retval = 0;
            }
        }
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_pederson_commit(void *ctx,uint8_t *commit,bits256 blind,uint64_t value)
{
    int32_t retval = -1;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_pedersen_commit(ctx,commit,blind.bytes,value) > 0 )
            retval = 0;
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

bits256 bitcoin_pederson_blindsum(void *ctx,bits256 **blindptrs,int32_t n,int32_t numpos)
{
    bits256 blind_out;
    memset(blind_out.bytes,0,sizeof(blind_out));
    SECP_ENSURE_CTX
    {
        if ( secp256k1_pedersen_blind_sum(ctx,blind_out.bytes,(void *)blindptrs,n,numpos) == 0 )
            memset(blind_out.bytes,0,sizeof(blind_out));
        ENDSECP_ENSURE_CTX
    }
    return(blind_out);
}

int32_t bitcoin_pederson_tally(void *ctx,uint8_t **commits,int32_t n,int32_t numpos,int64_t excess)
{
    int32_t retval = -1;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_pedersen_verify_tally(ctx,(void *)commits,numpos,(void *)&commits[numpos],n - numpos,excess) > 0 )
            retval = 0;
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_rangeproof_message(void *ctx,uint8_t *blind_out,uint8_t *message,uint64_t *valuep,bits256 nonce,uint64_t *min_valuep,uint64_t *max_valuep,uint8_t *commit,uint8_t *proof,int32_t prooflen)
{
    int32_t outlen = 0,retval = -1;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_rangeproof_rewind(ctx,blind_out,valuep,message,&outlen,nonce.bytes,min_valuep,max_valuep,commit,proof,prooflen) > 0 )
            retval = outlen;
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

uint64_t bitcoin_rangeverify(void *ctx,int32_t *exponentp,int32_t *mantissap,uint64_t *min_valuep,uint8_t *commit,uint8_t *proof,int32_t prooflen)
{
    uint64_t max_value,retval = 0;
    max_value = *min_valuep = *exponentp = *mantissap = 0;
    if ( secp256k1_rangeproof_info(ctx,exponentp,mantissap,min_valuep,&max_value,proof,prooflen) > 0 )
    {
        if ( commit != 0 )
        {
            if ( secp256k1_rangeproof_verify(ctx,min_valuep,&max_value,commit,proof,prooflen) > 0 )
                retval = max_value;
        } else retval = max_value;
    }
    return(retval);
}

int32_t bitcoin_rangeproof(void *ctx,uint8_t *proof,uint8_t *commit,bits256 blind,bits256 nonce,uint64_t value,uint64_t min_value,int32_t exponent,int32_t min_bits)
{
    int32_t prooflen=0  ,retval = -1;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_rangeproof_sign(ctx,proof,&prooflen,min_value,commit,blind.bytes,nonce.bytes,exponent,min_bits,value) > 0 )
            retval = prooflen;
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

    /*
 * The intended procedure for creating a multiparty signature is:
 * - Each signer S[i] with private key x[i] and public key Q[i] runs
 *   secp256k1_schnorr_generate_nonce_pair to produce a pair (k[i],R[i]) of private/public nonces.
 * - All signers communicate their public nonces to each other (revealing your
 *   private nonce can lead to discovery of your private key, so it should be considered secret).
 * - All signers combine all the public nonces they received (excluding their
 *   own) using secp256k1_ec_pubkey_combine to obtain an Rall[i] = sum(R[0..i-1,i+1..n]).
 * - All signers produce a partial signature using
 *   secp256k1_schnorr_partial_sign, passing in their own private key x[i],
 *   their own private nonce k[i], and the sum of the others' public nonces Rall[i].
 * - All signers communicate their partial signatures to each other.
 * - Someone combines all partial signatures using secp256k1_schnorr_partial_combine, to obtain a full signature.
 * - The resulting signature is validatable using secp256k1_schnorr_verify, with
 *   public key equal to the result of secp256k1_ec_pubkey_combine of the signers' public keys (sum(Q[0..n])).
 *
 *  Note that secp256k1_schnorr_partial_combine and secp256k1_ec_pubkey_combine
 *  function take their arguments in any order, and it is possible to
 *  pre-combine several inputs already with one call, and add more inputs later
 *  by calling the function again (they are commutative and associative).
 */

#ifdef test_schnorr
#include "secp256k1/src/util.h"
#include "secp256k1/src/hash_impl.h"
#include "secp256k1/src/testrand_impl.h"

void test_schnorr_threshold(void *ctx) {
    unsigned char msg[32];
    unsigned char sec[5][32];
    secp256k1_pubkey pub[5];
    unsigned char nonce[5][32];
    secp256k1_pubkey pubnonce[5];
    unsigned char sig[5][64];
    const unsigned char* sigs[5];
    unsigned char allsig[64];
    const secp256k1_pubkey* pubs[5];
    secp256k1_pubkey allpub;
    int n, i;
    int damage;
    int ret = 0;
    
    damage = secp256k1_rand_bits(1) ? (1 + secp256k1_rand_int(4)) : 0;
    secp256k1_rand256_test(msg);
    n = 2 + secp256k1_rand_int(4);
    for (i = 0; i < n; i++) {
        do {
            secp256k1_rand256_test(sec[i]);
        } while (!secp256k1_ec_seckey_verify(ctx, sec[i]));
        CHECK(secp256k1_ec_pubkey_create(ctx, &pub[i], sec[i]));
        CHECK(secp256k1_schnorr_generate_nonce_pair(ctx, &pubnonce[i], nonce[i], msg, sec[i], NULL, NULL));
        pubs[i] = &pub[i];
    }
    if (damage == 1) {
        nonce[secp256k1_rand_int(n)][secp256k1_rand_int(32)] ^= 1 + secp256k1_rand_int(255);
    } else if (damage == 2) {
        sec[secp256k1_rand_int(n)][secp256k1_rand_int(32)] ^= 1 + secp256k1_rand_int(255);
    }
    for (i = 0; i < n; i++) {
        secp256k1_pubkey allpubnonce;
        const secp256k1_pubkey *pubnonces[4];
        int j;
        for (j = 0; j < i; j++) {
            pubnonces[j] = &pubnonce[j];
        }
        for (j = i + 1; j < n; j++) {
            pubnonces[j - 1] = &pubnonce[j];
        }
        CHECK(secp256k1_ec_pubkey_combine(ctx, &allpubnonce, pubnonces, n - 1));
        ret |= (secp256k1_schnorr_partial_sign(ctx, sig[i], msg, sec[i], &allpubnonce, nonce[i]) != 1) * 1;
        sigs[i] = sig[i];
    }
    if (damage == 3) {
        sig[secp256k1_rand_int(n)][secp256k1_rand_bits(6)] ^= 1 + secp256k1_rand_int(255);
    }
    ret |= (secp256k1_ec_pubkey_combine(ctx, &allpub, pubs, n) != 1) * 2;
    if ((ret & 1) == 0) {
        ret |= (secp256k1_schnorr_partial_combine(ctx, allsig, sigs, n) != 1) * 4;
    }
    if (damage == 4) {
        allsig[secp256k1_rand_int(32)] ^= 1 + secp256k1_rand_int(255);
    }
    if ((ret & 7) == 0) {
        ret |= (secp256k1_schnorr_verify(ctx, allsig, msg, &allpub) != 1) * 8;
    }
    CHECK((ret == 0) == (damage == 0));
}
#endif

int32_t iguana_pederson_test(void *ctx)
{
    uint8_t commits[100][33],*commitptrs[100],proofs[100][5138]; uint16_t vouts[100]; int64_t min_value,values[100],totalpos,totalneg; bits256 txids[100],nonces[100],blinds[100],*blindptrs[100],blindsum; int32_t prooflens[100],i,r,pos,neg,numpos,exponent,min_bits,n,N = 100;
    srand(100);
    for (i=numpos=n=0; i<N; i++)
    {
        values[i] = rand();
        vouts[i] = (rand() % 300);
        txids[i] = rand256(0);
        nonces[i] = rand256(0);
        blinds[i] = rand256(0);
        if ( bitcoin_pederson_commit(ctx,commits[i],blinds[i],values[i]) < 0 )
            break;
        if ( ((r= rand()) % 2) == 0 )
            values[i] = -values[i];
        else
        {
            exponent = 0;
            min_bits = 64;
            min_value = 0;
            prooflens[i] = bitcoin_rangeproof(ctx,proofs[i],commits[i],blinds[i],nonces[i],values[i],min_value,exponent,min_bits);
            printf("%d ",prooflens[i]);
            numpos++;
        }
        n++;
    }
    if ( i != N )
    {
        printf("commit failure i.%d of N.%d\n",i,N);
        return(-1);
    }
    for (totalpos=i=pos=0; i<N; i++)
    {
        if ( values[i] > 0 )
        {
            commitptrs[pos] = commits[i];
            blindptrs[pos] = &blinds[i];
            totalpos += values[i];
            pos++;
        }
    }
    if ( pos != numpos )
    {
        printf("pos.%d != numpos.%d\n",pos,numpos);
        return(-1);
    }
    for (totalneg=i=neg=0; i<N; i++)
    {
        if ( values[i] < 0 )
        {
            commitptrs[numpos + neg] = commits[i];
            blindptrs[numpos + neg] = &blinds[i];
            totalneg -= values[i];
            neg++;
        }
    }
    if ( numpos+neg != N )
    {
        printf("numpos.%d + neg.%d != N.%d\n",numpos,neg,N);
        return(-1);
    }
    blindsum = bitcoin_pederson_blindsum(ctx,blindptrs,N,numpos);
    if ( bits256_nonz(blindsum) == 0 )
    {
        printf("error doing blindsum numpos.%d N.%d\n",numpos,N);
        return(-2);
    }
    if ( bitcoin_pederson_tally(ctx,commitptrs,N,numpos,totalneg - totalpos) == 0 )
    {
        printf("error doing pederson tally\n");
        return(-3);
    } else printf("pederson tally matches\n");
    return(0);
}

int32_t iguana_schnorr_test(void *ctx)
{
    bits256 privnonces[100],privkeys[100],txhash2; uint8_t *sigs[100],allpub[100][33],sig64[100][64],allsig64[100][64],combined_pub[100][33],pubnonces[100][33],*pubptrs[100]; int32_t i,j,N,n,errs = 0;
    iguana_pederson_test(ctx);
    SECP_ENSURE_CTX
    {
        N = 100;
        txhash2 = rand256(0);
        for (i=0; i<N; i++)
        {
            privkeys[i] = bitcoin_randkey(ctx);
            privnonces[i] = bitcoin_schnorr_noncepair(ctx,pubnonces[i],txhash2,privkeys[i]);
        }
        if ( i != N )
        {
            printf("error getting nonce pair\n");
            exit(-1);
        }
        for (i=0; i<N; i++)
        {
            for (j=n=0; j<N; j++)
                if ( j != i )
                    pubptrs[n++] = pubnonces[j];
            if ( N > 1 )
            {
                if ( bitcoin_schnorr_partialsign(ctx,sig64[i],combined_pub[i],txhash2,privkeys[i],privnonces[i],pubptrs,N-1) < 0 )
                    errs++;
            }
            else
            {
                if ( bitcoin_schnorr_sign(ctx,sig64[0],txhash2,privkeys[0]) < 0 )
                    errs++;
            }
        }
        if ( errs != 0 )
            printf("partialsign errs.%d\n",errs);
        for (i=0; i<N; i++)
        {
            sigs[i] = sig64[i];
            continue;
            for (j=0; j<64; j++)
                printf("%02x",sig64[i][j]);
            printf(" sig[%d]\n",i);
        }
        for (i=0; i<N; i++)
        {
            if ( bitcoin_schnorr_combine(ctx,allsig64[i],allpub[i],sigs,N,txhash2) < 0 )
                errs++;
            else if ( memcmp(allpub[i],allpub[0],33) != 0 )
                errs++;
            else if ( memcmp(allsig64[i],allsig64[0],33) != 0 )
                errs++;
        }
        if ( errs != 0 )
            printf("combine errs.%d\n",errs);
        if ( bitcoin_schnorr_verify(ctx,allsig64[0],txhash2,allpub[0],33) < 0 )
            errs++;
        printf("schnorr errs.%d\n",errs);
        ENDSECP_ENSURE_CTX
    }
    return(errs);
}

#ifdef oldway
#include "../includes/openssl/ec.h"
#include "../includes/openssl/ecdsa.h"
#include "../includes/openssl/obj_mac.h"

static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

struct bp_key { EC_KEY *k; };

EC_KEY *oldbitcoin_privkeyset(uint8_t *oddevenp,bits256 *pubkeyp,bits256 privkey)
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

int32_t oldbitcoin_verify(uint8_t *sig,int32_t siglen,uint8_t *data,int32_t datalen,uint8_t *pubkey,int32_t len)
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

int32_t oldbitcoin_sign(uint8_t *sig,int32_t maxlen,uint8_t *data,int32_t datalen,bits256 privkey)
{
    EC_KEY *KEY; uint8_t oddeven; bits256 pubkey; uint8_t *ptr; int32_t siglen,retval = -1;
    ECDSA_SIG *SIG; BN_CTX *ctx; const EC_GROUP *group; BIGNUM *order,*halforder;
    if ( (KEY= oldbitcoin_privkeyset(&oddeven,&pubkey,privkey)) != 0 )
    {
        if ( (SIG= ECDSA_do_sign(data,datalen,KEY)) != 0 )
        {
            ctx = BN_CTX_new();
            BN_CTX_start(ctx);
            group = EC_KEY_get0_group(KEY);
            order = BN_CTX_get(ctx);
            halforder = BN_CTX_get(ctx);
            EC_GROUP_get_order(group,order,ctx);
            BN_rshift1(halforder,order);
            if ( BN_cmp(SIG->s,halforder) > 0 )
            {
                // enforce low S values, by negating the value (modulo the order) if above order/2.
                BN_sub(SIG->s,order,SIG->s);
            }
            ptr = 0;
            siglen = i2d_ECDSA_SIG(SIG,&ptr);
            if ( ptr != 0 )
            {
                if ( siglen > 0 )
                {
                    memcpy(sig,ptr,siglen);
                    retval = siglen;
                }
                free(ptr);
            }
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            ECDSA_SIG_free(SIG);
        }
        //if ( ECDSA_sign(0,data,datalen,sig,&siglen,KEY) > 0 && siglen <= maxlen )
        //    retval = siglen;
        EC_KEY_free(KEY);
    }
    return(retval);
}

bits256 oldbitcoin_pubkey33(void *_ctx,uint8_t *data,bits256 privkey)
{
    uint8_t oddeven,data2[65]; size_t plen; bits256 pubkey; secp256k1_pubkey secppub; secp256k1_context *ctx;
    EC_KEY *KEY;
    if ( (KEY= oldbitcoin_privkeyset(&oddeven,&pubkey,privkey)) != 0 )
    {
        data[0] = oddeven;
        memcpy(data+1,pubkey.bytes,sizeof(pubkey));
        EC_KEY_free(KEY);
        if ( (ctx= secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)) != 0 )
        {
            if ( secp256k1_ec_pubkey_create(ctx,&secppub,privkey.bytes) > 0 )
            {
                plen = 33;
                secp256k1_ec_pubkey_serialize(ctx,data2,&plen,&secppub,1);
                if ( memcmp(data2,data,plen) != 0 )
                    printf("pubkey compare error plen.%d\n",(int32_t)plen);
                else printf("pubkey verified\n");
            } //else printf("error secp256k1_ec_pubkey_create\n");
            secp256k1_context_destroy(ctx);
        }
    } else memset(pubkey.bytes,0,sizeof(pubkey));
    return(pubkey);
}

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

int32_t oldbitcoin_base58decode(uint8_t *data,char *coinaddr)
{
    int32_t bitcoin_base58decode_mpz(uint8_t *data,char *coinaddr);
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
    {
        int32_t checkval; uint8_t data2[256];
        if ( (checkval= bitcoin_base58decode_mpz(data2,coinaddr)) != be_sz )
            printf("base58 decode error checkval.%d != be_sz.%d\n",checkval,be_sz);
        else if ( memcmp(data2,data,be_sz) != 0 )
        {
            for (i=0; i<be_sz; i++)
                printf("%02x",data[i]);
            printf(" data[%d]\n",be_sz);
            for (i=0; i<be_sz; i++)
                printf("%02x",data2[i]);
            printf(" data\n");
            printf("base58 decode data error\n");
        }
        else printf("base58 decode match\n");
    }
	return(be_sz);
}

char *oldbitcoin_base58encode(char *coinaddr,uint8_t *data_,int32_t datalen)
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
        {
            char *bitcoin_base58encode_mpz(char *coinaddr,uint8_t *data,int32_t datalen);
            char checkaddr[64];
            bitcoin_base58encode_mpz(checkaddr,data_,datalen);
            if ( strcmp(checkaddr,coinaddr) != 0 )
                printf("mpz base58 error (%s) vs (%s)\n",checkaddr,coinaddr);
            else printf("mpz matches\n");
        }
        return(coinaddr);
    }
    return(0);
}

#endif


