/*-
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2011 pooler, 2013 Balthazar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include "../includes/curve25519.h"
#define SCRYPT_BUFFER_SIZE (131072 + 63)

/*
static inline uint32_t be32dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;
    return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) + ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static inline void be32enc(void *pp,uint32_t x)
{
    uint8_t *p = (uint8_t *)pp;
    p[3] = x & 0xff;
    p[2] = (x >> 8) & 0xff;
    p[1] = (x >> 16) & 0xff;
    p[0] = (x >> 24) & 0xff;
}

void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx,const void * _K,size_t Klen)
{
    size_t i; uint8_t pad[64],khash[32]; const uint8_t * K = (const uint8_t *)_K;
    // If Klen > 64, the key is really SHA256(K).
    if ( Klen > 64 )
    {
        SHA256_Init(&ctx->ictx);
        SHA256_Update(&ctx->ictx, K, Klen);
        SHA256_Final(khash, &ctx->ictx);
        K = khash;
        Klen = 32;
    }
    // Inner SHA256 operation is SHA256(K xor [block of 0x36] || data).
    SHA256_Init(&ctx->ictx);
    memset(pad, 0x36, 64);
    for (i = 0; i < Klen; i++)
        pad[i] ^= K[i];
    SHA256_Update(&ctx->ictx, pad, 64);
    // Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash).
    SHA256_Init(&ctx->octx);
    memset(pad, 0x5c, 64);
    for (i = 0; i < Klen; i++)
        pad[i] ^= K[i];
    SHA256_Update(&ctx->octx, pad, 64);
    // Clean the stack.
    memset(khash,0,32);
}

// Add bytes to the HMAC-SHA256 operation.
void HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx,const void *in,size_t len)
{
    SHA256_Update(&ctx->ictx,in,len);
}

// Finish an HMAC-SHA256 operation.
void HMAC_SHA256_Final(uint8_t digest[32],HMAC_SHA256_CTX *ctx)
{
    uint8_t ihash[32];
    SHA256_Final(ihash,&ctx->ictx);
    SHA256_Update(&ctx->octx,ihash,32);
    SHA256_Final(digest,&ctx->octx);
    memset(ihash,0,32);
}

// PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen): Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1)
void PBKDF2_SHA256(const uint8_t *passwd,size_t passwdlen,const uint8_t *salt,size_t saltlen,uint64_t c,uint8_t *buf,size_t dkLen)
{
    HMAC_SHA256_CTX PShctx, hctx;
    size_t i,clen; uint8_t ivec[4],U[32],T[32]; uint64_t j; int32_t k;
    // Compute HMAC state after processing P and S.
    HMAC_SHA256_Init(&PShctx, passwd, passwdlen);
    HMAC_SHA256_Update(&PShctx, salt, saltlen);
    // Iterate through the blocks.
    for (i=0; i*32<dkLen; i++)
    {
        // Generate INT(i + 1).
        be32enc(ivec,(uint32_t)(i + 1));
        // Compute U_1 = PRF(P, S || INT(i)).
        memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX));
        HMAC_SHA256_Update(&hctx, ivec, 4);
        HMAC_SHA256_Final(U, &hctx);
        // T_i = U_1 ...
        memcpy(T,U,32);
        for (j=2; j<=c; j++)
        {
            // Compute U_j.
            HMAC_SHA256_Init(&hctx, passwd, passwdlen);
            HMAC_SHA256_Update(&hctx, U, 32);
            HMAC_SHA256_Final(U, &hctx);
            // ... xor U_j ...
            for (k=0; k<32; k++)
                T[k] ^= U[k];
        }
        // Copy as many bytes as necessary into buf
        clen = dkLen - i * 32;
        if (clen > 32)
            clen = 32;
        memcpy(&buf[i * 32],T,clen);
    }
}*/

// Generic scrypt_core implementation

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
    int32_t i; uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
    x00 = (B[0] ^= Bx[0]);
    x01 = (B[1] ^= Bx[1]);
    x02 = (B[2] ^= Bx[2]);
    x03 = (B[3] ^= Bx[3]);
    x04 = (B[4] ^= Bx[4]);
    x05 = (B[5] ^= Bx[5]);
    x06 = (B[6] ^= Bx[6]);
    x07 = (B[7] ^= Bx[7]);
    x08 = (B[8] ^= Bx[8]);
    x09 = (B[9] ^= Bx[9]);
    x10 = (B[10] ^= Bx[10]);
    x11 = (B[11] ^= Bx[11]);
    x12 = (B[12] ^= Bx[12]);
    x13 = (B[13] ^= Bx[13]);
    x14 = (B[14] ^= Bx[14]);
    x15 = (B[15] ^= Bx[15]);
    for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
        /* Operate on columns. */
        x04 ^= R(x00+x12, 7); x09 ^= R(x05+x01, 7);
        x14 ^= R(x10+x06, 7); x03 ^= R(x15+x11, 7);

        x08 ^= R(x04+x00, 9); x13 ^= R(x09+x05, 9);
        x02 ^= R(x14+x10, 9); x07 ^= R(x03+x15, 9);

        x12 ^= R(x08+x04,13); x01 ^= R(x13+x09,13);
        x06 ^= R(x02+x14,13); x11 ^= R(x07+x03,13);

        x00 ^= R(x12+x08,18); x05 ^= R(x01+x13,18);
        x10 ^= R(x06+x02,18); x15 ^= R(x11+x07,18);

        /* Operate on rows. */
        x01 ^= R(x00+x03, 7); x06 ^= R(x05+x04, 7);
        x11 ^= R(x10+x09, 7); x12 ^= R(x15+x14, 7);

        x02 ^= R(x01+x00, 9); x07 ^= R(x06+x05, 9);
        x08 ^= R(x11+x10, 9); x13 ^= R(x12+x15, 9);

        x03 ^= R(x02+x01,13); x04 ^= R(x07+x06,13);
        x09 ^= R(x08+x11,13); x14 ^= R(x13+x12,13);

        x00 ^= R(x03+x02,18); x05 ^= R(x04+x07,18);
        x10 ^= R(x09+x08,18); x15 ^= R(x14+x13,18);
#undef R
    }
    B[0] += x00;
    B[1] += x01;
    B[2] += x02;
    B[3] += x03;
    B[4] += x04;
    B[5] += x05;
    B[6] += x06;
    B[7] += x07;
    B[8] += x08;
    B[9] += x09;
    B[10] += x10;
    B[11] += x11;
    B[12] += x12;
    B[13] += x13;
    B[14] += x14;
    B[15] += x15;
}

static inline void scrypt_core(uint32_t *X,uint32_t *V)
{
    uint32_t i,j,k;
    for (i=0; i<1024; i++)
    {
        memcpy(&V[i * 32],X,128);
        xor_salsa8(&X[0],&X[16]);
        xor_salsa8(&X[16],&X[0]);
    }
    for (i=0; i<1024; i++)
    {
        j = 32 * (X[16] & 1023);
        for (k = 0; k < 32; k++)
            X[k] ^= V[j + k];
        xor_salsa8(&X[0],&X[16]);
        xor_salsa8(&X[16],&X[0]);
    }
}

/* cpu and memory intensive function to transform a 80 byte buffer into a 32 byte output
   scratchpad size needs to be at least 63 + (128 * r * p) + (256 * r + 64) + (128 * r * N) bytes
   r = 1, p = 1, N = 1024
 */

bits256 scrypt_nosalt(const void *input,size_t inputlen,void *scratchpad)
{
    uint32_t *V; uint32_t X[32]; bits256 result;
    memset(result.bytes,0,sizeof(result));
    V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));
    calc_hmac_sha256((void *)X,128,(void *)input,(int32_t)inputlen,(void *)input,(int32_t)inputlen);
    //PBKDF2_SHA256((const uint8_t *)input,inputlen,(const uint8_t *)input,inputlen,1,(uint8_t *)X,128);
    scrypt_core(X,V);
    calc_hmac_sha256((void *)result.bytes,sizeof(result),(void *)input,(int32_t)inputlen,(void *)X,128);
    //PBKDF2_SHA256((const uint8_t *)input,inputlen,(uint8_t *)X,128,1,(uint8_t*)&result,32);
    return result;
}

bits256 scrypt(const void *data,size_t datalen,const void *salt,size_t saltlen,void *scratchpad)
{
    uint32_t *V; uint32_t X[32]; bits256 result;
    memset(result.bytes,0,sizeof(result));
    V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));
    calc_hmac_sha256((void *)X,128,(void *)data,(int32_t)datalen,(void *)salt,(int32_t)saltlen);
    //PBKDF2_SHA256((const uint8_t *)data,datalen,(const uint8_t *)salt,saltlen,1,(uint8_t *)X,128);
    scrypt_core(X,V);
    calc_hmac_sha256((void *)result.bytes,sizeof(result),(void *)data,(int32_t)datalen,(void *)X,128);
    //PBKDF2_SHA256((const uint8_t *)data,datalen,(uint8_t *)X,128,1,(uint8_t *)&result,32);
    return result;
}

bits256 scrypt_hash(const void *input,size_t inputlen)
{
    uint8_t scratchpad[SCRYPT_BUFFER_SIZE];
    return scrypt_nosalt(input,inputlen,scratchpad);
}

bits256 scrypt_salted_hash(const void *input,size_t inputlen,const void *salt,size_t saltlen)
{
    uint8_t scratchpad[SCRYPT_BUFFER_SIZE];
    return scrypt(input,inputlen,salt,saltlen,scratchpad);
}

bits256 scrypt_salted_multiround_hash(const void *input,size_t inputlen,const void *salt,size_t saltlen,const uint32_t nRounds)
{
    uint32_t i; bits256 resultHash = scrypt_salted_hash(input,inputlen,salt,saltlen);
    bits256 transitionalHash = resultHash;
    for(i=1; i<nRounds; i++)
    {
        resultHash = scrypt_salted_hash(input,inputlen,(const void *)&transitionalHash,32);
        transitionalHash = resultHash;
    }
    return resultHash;
}

bits256 scrypt_blockhash(const void *input)
{
    uint8_t scratchpad[SCRYPT_BUFFER_SIZE];
    return scrypt_nosalt(input,80,scratchpad);
}

