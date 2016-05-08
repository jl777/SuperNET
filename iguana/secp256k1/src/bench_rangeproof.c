/**********************************************************************
 * Copyright (c) 2014, 2015 Pieter Wuille, Gregory Maxwell            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdint.h>

#include "../include/secp256k1_rangeproof.h"
#include "util.h"
#include "bench.h"

typedef struct {
    secp256k1_context *ctx;
    unsigned char commit[33];
    unsigned char proof[5134];
    unsigned char message[4096];
    unsigned char blind[32];
    unsigned char nonce[32];
    int prooflen;
    int min_bits;
    uint64_t v;
} bench_rangeproof_t;

static void bench_rangeproof_setup(void* arg)
{
    int i;
    uint64_t minv;
    uint64_t maxv;
    bench_rangeproof_t *data = (bench_rangeproof_t *)arg;
    for (i = 0; i < 32; i++)
    {
        data->blind[i] = rand();
        data->nonce[i] = rand();
    }
#define PRIVATEBITS 32
#define PUBLICDIGITS 0
#define ENCODEVALUE 2
    data->v = ENCODEVALUE;
    CHECK(secp256k1_pedersen_commit(data->ctx, data->commit, data->blind, data->v));
    data->prooflen = 5134;
    for (i=0; i<data->prooflen; i++)
    {
        //data->proof[i] = i;
        if ( i < sizeof(data->prooflen) )
            data->message[i] = i;
    }
    CHECK(secp256k1_rangeproof_sign(data->ctx, data->proof, &data->prooflen,0, data->commit, data->blind, data->nonce, PUBLICDIGITS, data->min_bits, data->v,data->message));
    //for (i=0; i<data->prooflen; i++)
    //    printf("%02x",data->proof[i]);
    CHECK(secp256k1_rangeproof_verify(data->ctx, &minv, &maxv, data->commit, data->proof, data->prooflen));
    printf(" proof.%d [%llx, %llx]\n",data->prooflen,(long long)minv,(long long)maxv);
    uint8_t blindout[32],message_out[5134]; uint64_t value_out,min_value,max_value; int32_t outlen;
    for (i=0; i<32; i++)
        message_out[i] = 0;
    CHECK(secp256k1_rangeproof_rewind(data->ctx,blindout,&value_out,message_out,&outlen,data->nonce,&min_value,&max_value,data->commit,data->proof,data->prooflen));
    for (i=0; i<32; i++)
        printf("%02x:%02x",data->blind[i],blindout[i]);
    printf(" blind, ");
    for (i=0; i<outlen; i++)
        if ( message_out[i] != 0 )
            printf("%02x",message_out[i]);
    printf(" message.%d, [%llx, %llx] value %llx prooflen.%d\n",outlen,(long long)min_value,(long long)max_value,(long long)value_out,data->prooflen);
}

static void bench_rangeproof(void* arg)
{
    int i;
    bench_rangeproof_t *data = (bench_rangeproof_t*)arg;

    for (i = 0; i < 1000; i++) {
        int j;
        uint64_t minv;
        uint64_t maxv;
        j = secp256k1_rangeproof_verify(data->ctx, &minv, &maxv, data->commit, data->proof, data->prooflen);
        for (j = 0; j < 4; j++)
        {
            data->proof[j + 2 + 32 *((data->min_bits + 1) >> 1) - 4] = (i >> 8)&255;
        }
    }
}

int proofmain(void)
{
    bench_rangeproof_t data;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pedersen_context_initialize(data.ctx);
    secp256k1_rangeproof_context_initialize(data.ctx);

    data.min_bits = PRIVATEBITS;

    run_benchmark("rangeproof_verify_bit", bench_rangeproof, bench_rangeproof_setup, NULL, &data, 10, 1000 * data.min_bits);

    secp256k1_context_destroy(data.ctx);
    return 0;
}
