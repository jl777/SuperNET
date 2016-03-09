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

// BTCoffer:
// sends NXT assetid, volume and desired
// request:
// other node sends (othercoin, othercoinaddr, otherNXT and reftx that expires well before phasedtx)
// proposal:
// NXT node submits phasedtx that refers to it, but it wont confirm
// approve:
// other node verifies unconfirmed has phasedtx and broadcasts cltv, also to NXT node, releases trigger
// confirm:
// NXT node verifies bitcoin txbytes has proper payment and cashes in with onetimepubkey
// BTC* node approves phased tx with onetimepubkey

char *instantdex_PAXswap(struct supernet_info *myinfo,struct exchange_info *exchange,struct instantdex_accept *ap,char *cmdstr,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen) // receiving side
{
    char *retstr = 0;
    return(clonestr("{\"error\":\"PAX swap is not yet\"}"));
    if ( strcmp(cmdstr,"offer") == 0 )
    {
    }
    else if ( strcmp(cmdstr,"proposal") == 0 )
    {
        
    }
    else if ( strcmp(cmdstr,"accept") == 0 )
    {
        
    }
    else if ( strcmp(cmdstr,"confirm") == 0 )
    {
        
    }
    else retstr = clonestr("{\"error\":\"PAX swap got unrecognized command\"}");
    return(retstr);
}

#ifdef __APPLE__
#include "../../includes/secp256k1.h"
//#include "../../crypto777/secp256k1/modules/rangeproof/pedersen_impl.h"
//#include "../../crypto777/secp256k1/modules/rangeproof/borromean_impl.h"
//#include "../../crypto777/secp256k1/modules/rangeproof/rangeproof_impl.h"
void secp256k1_pedersen_context_initialize(secp256k1_context_t *ctx);
int secp256k1_pedersen_commit(const secp256k1_context_t* ctx, unsigned char *commit, unsigned char *blind, uint64_t value);
int secp256k1_pedersen_blind_sum(const secp256k1_context_t* ctx, unsigned char *blind_out, const unsigned char * const *blinds, int n, int npositive);
int secp256k1_pedersen_verify_tally(const secp256k1_context_t* ctx, const unsigned char * const *commits, int pcnt,const unsigned char * const *ncommits, int ncnt, int64_t excess);
// ./configure --enable-module-ecdh --enable-module-schnorr --enable-module-rangeproof

void CHECK(int32_t val) { if ( val != 1 ) printf("error\n"),getchar(); }

typedef struct {
    uint64_t d[4];
} secp256k1_scalar_t;

static void secp256k1_scalar_get_b32(unsigned char *bin, const secp256k1_scalar_t* a) {
    bin[0] = a->d[3] >> 56; bin[1] = a->d[3] >> 48; bin[2] = a->d[3] >> 40; bin[3] = a->d[3] >> 32; bin[4] = a->d[3] >> 24; bin[5] = a->d[3] >> 16; bin[6] = a->d[3] >> 8; bin[7] = a->d[3];
    bin[8] = a->d[2] >> 56; bin[9] = a->d[2] >> 48; bin[10] = a->d[2] >> 40; bin[11] = a->d[2] >> 32; bin[12] = a->d[2] >> 24; bin[13] = a->d[2] >> 16; bin[14] = a->d[2] >> 8; bin[15] = a->d[2];
    bin[16] = a->d[1] >> 56; bin[17] = a->d[1] >> 48; bin[18] = a->d[1] >> 40; bin[19] = a->d[1] >> 32; bin[20] = a->d[1] >> 24; bin[21] = a->d[1] >> 16; bin[22] = a->d[1] >> 8; bin[23] = a->d[1];
    bin[24] = a->d[0] >> 56; bin[25] = a->d[0] >> 48; bin[26] = a->d[0] >> 40; bin[27] = a->d[0] >> 32; bin[28] = a->d[0] >> 24; bin[29] = a->d[0] >> 16; bin[30] = a->d[0] >> 8; bin[31] = a->d[0];
}

#define SECP256K1_N_0 ((uint64_t)0xBFD25E8CD0364141ULL)
#define SECP256K1_N_1 ((uint64_t)0xBAAEDCE6AF48A03BULL)
#define SECP256K1_N_2 ((uint64_t)0xFFFFFFFFFFFFFFFEULL)
#define SECP256K1_N_3 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)
/* Limbs of 2^256 minus the secp256k1 order. */
#define SECP256K1_N_C_0 (~SECP256K1_N_0 + 1)
#define SECP256K1_N_C_1 (~SECP256K1_N_1)
#define SECP256K1_N_C_2 (1)

static int secp256k1_scalar_check_overflow(const secp256k1_scalar_t *a) {
    int yes = 0;
    int no = 0;
    no |= (a->d[3] < SECP256K1_N_3); /* No need for a > check. */
    no |= (a->d[2] < SECP256K1_N_2);
    yes |= (a->d[2] > SECP256K1_N_2) & ~no;
    no |= (a->d[1] < SECP256K1_N_1);
    yes |= (a->d[1] > SECP256K1_N_1) & ~no;
    yes |= (a->d[0] >= SECP256K1_N_0) & ~no;
    return yes;
}
typedef unsigned uint128_t __attribute__((mode(TI)));

static int secp256k1_scalar_reduce(secp256k1_scalar_t *r, unsigned int overflow) {
    uint128_t t;
    t = (uint128_t)r->d[0] + overflow * SECP256K1_N_C_0;
    r->d[0] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint128_t)r->d[1] + overflow * SECP256K1_N_C_1;
    r->d[1] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint128_t)r->d[2] + overflow * SECP256K1_N_C_2;
    r->d[2] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint64_t)r->d[3];
    r->d[3] = t & 0xFFFFFFFFFFFFFFFFULL;
    return overflow;
}

static void secp256k1_scalar_set_b32(secp256k1_scalar_t *r, const unsigned char *b32, int *overflow) {
    int over;
    r->d[0] = (uint64_t)b32[31] | (uint64_t)b32[30] << 8 | (uint64_t)b32[29] << 16 | (uint64_t)b32[28] << 24 | (uint64_t)b32[27] << 32 | (uint64_t)b32[26] << 40 | (uint64_t)b32[25] << 48 | (uint64_t)b32[24] << 56;
    r->d[1] = (uint64_t)b32[23] | (uint64_t)b32[22] << 8 | (uint64_t)b32[21] << 16 | (uint64_t)b32[20] << 24 | (uint64_t)b32[19] << 32 | (uint64_t)b32[18] << 40 | (uint64_t)b32[17] << 48 | (uint64_t)b32[16] << 56;
    r->d[2] = (uint64_t)b32[15] | (uint64_t)b32[14] << 8 | (uint64_t)b32[13] << 16 | (uint64_t)b32[12] << 24 | (uint64_t)b32[11] << 32 | (uint64_t)b32[10] << 40 | (uint64_t)b32[9] << 48 | (uint64_t)b32[8] << 56;
    r->d[3] = (uint64_t)b32[7] | (uint64_t)b32[6] << 8 | (uint64_t)b32[5] << 16 | (uint64_t)b32[4] << 24 | (uint64_t)b32[3] << 32 | (uint64_t)b32[2] << 40 | (uint64_t)b32[1] << 48 | (uint64_t)b32[0] << 56;
    over = secp256k1_scalar_reduce(r, secp256k1_scalar_check_overflow(r));
    if (overflow) {
        *overflow = over;
    }
}

void random_scalar_order(secp256k1_scalar_t *num) {
    do {
        unsigned char b32[32];
        int overflow = 0;
        OS_randombytes(b32,sizeof(b32));
        //secp256k1_rand256(b32);
        secp256k1_scalar_set_b32(num, b32, &overflow);
        if ( overflow != 0 || bits256_nonz(*(bits256 *)num) == 0 )
            continue;
        break;
    } while(1);
}

bits256 rand_secp()
{
    bits256 s,ret;
    random_scalar_order((void *)&s);
    secp256k1_scalar_get_b32((void *)&ret,(void *)&s);
    return(ret);
}

void test_pedersen(void) {
    secp256k1_context_t *ctx;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pedersen_context_initialize(ctx);
  unsigned char commits[33*19];
    const unsigned char *cptr[19];
    unsigned char blinds[32*19];
    const unsigned char *bptr[19];
    uint64_t values[19];
    int64_t totalv;
    secp256k1_scalar_t s;
    int i; uint8_t r,r2;
    int inputs;
    int outputs;
    int total;
    OS_randombytes((void *)&r,sizeof(r));
    OS_randombytes((void *)&r2,sizeof(r2));
    inputs = (r & 7) + 1;
    outputs = (r2 & 7) + 2;
    total = inputs + outputs;
    printf("inputs.%d outputs.%d\n",inputs,outputs);
    for (i = 0; i < 19; i++) {
        cptr[i] = &commits[i * 33];
        bptr[i] = &blinds[i * 32];
    }
    totalv = 0;
    for (i = 0; i < inputs; i++) {
        OS_randombytes((void *)&r,sizeof(r));
        values[i] = r;
        totalv += values[i];
    }
    if (1 ){//rand() & 1) {
        for (i = 0; i < outputs; i++) {
            int64_t max = INT64_MAX;
            if (totalv < 0) {
                max += totalv;
            }
            OS_randombytes((void *)&r,sizeof(r));
            values[i + inputs] = r;
            totalv -= values[i + inputs];
        }
    } else {
        for (i = 0; i < outputs - 1; i++) {
            OS_randombytes((void *)&r,sizeof(r));
            values[i + inputs] = r;
            totalv -= values[i + inputs];
        }
        values[total - 1] = totalv >> (rand() & 1);
        totalv -= values[total - 1];
    }
    for (i = 0; i < total - 1; i++) {
        random_scalar_order(&s);
        secp256k1_scalar_get_b32(&blinds[i * 32], &s);
    }
    CHECK(secp256k1_pedersen_blind_sum(ctx, &blinds[(total - 1) * 32], bptr, total - 1, inputs));
    printf("sum total.%d %lld\n",total,(long long)values[total-1]);
    for (i = 0; i < total; i++) {
        printf("%llu ",(long long)values[i]);
        CHECK(secp256k1_pedersen_commit(ctx, &commits[i * 33], &blinds[i * 32], values[i]));
    }
    printf("commits totalv.%lld\n",(long long)totalv);
    CHECK(secp256k1_pedersen_verify_tally(ctx, cptr, inputs, &cptr[inputs], outputs, totalv));
    printf("tally\n");
    CHECK(!secp256k1_pedersen_verify_tally(ctx, cptr, inputs, &cptr[inputs], outputs, totalv + 1));
    printf("!tally\n");
    getchar();
    return;
    for (i = 0; i < 4; i++) {
        //OS_randombytes(&blinds[i * 32],32);
        *(bits256 *)&blinds[i * 32] = rand_secp();
    }
    values[0] = INT64_MAX;
    values[1] = 0;
    values[2] = 1;
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_pedersen_commit(ctx, &commits[i * 33], &blinds[i * 32], values[i]));
    }
    printf("a\n");
    CHECK(secp256k1_pedersen_verify_tally(ctx, &cptr[1], 1, &cptr[2], 1, -1));
    printf("b\n");
    CHECK(secp256k1_pedersen_verify_tally(ctx, &cptr[2], 1, &cptr[1], 1, 1));
    printf("c\n");
    CHECK(secp256k1_pedersen_verify_tally(ctx, &cptr[0], 1, &cptr[0], 1, 0));
    printf("d\n");
    CHECK(secp256k1_pedersen_verify_tally(ctx, &cptr[0], 1, &cptr[1], 1, INT64_MAX));
    printf("e\n");
    CHECK(secp256k1_pedersen_verify_tally(ctx, &cptr[1], 1, &cptr[1], 1, 0));
    printf("f\n");
    CHECK(secp256k1_pedersen_verify_tally(ctx, &cptr[1], 1, &cptr[0], 1, -INT64_MAX));
    printf("g\n");
}
#endif

void ztest()
{
#ifdef __APPLE__
    return;
    printf("ztests\n");
    //test_pedersen();
    secp256k1_context_t *ctx;  uint8_t commits[13][33],blinds[13][32]; int32_t i,j,ret,retvals[13]; int64_t val,excess = 0; const uint8_t *commitptrs[13],*blindptrs[13]; bits256 s;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pedersen_context_initialize(ctx);
    for (j=0; j<13; j++)
    {
        blindptrs[j] = blinds[j];
        commitptrs[j] = commits[j];
        s = rand_secp();
        memcpy(blinds[j],s.bytes,sizeof(s));
        //OS_randombytes(blinds[j],sizeof(blinds[j]));
    }
    ret = secp256k1_pedersen_blind_sum(ctx,blinds[12],blindptrs,12,12);
    for (i=0; i<32; i++)
        printf("%02x",blindptrs[12][i]);
    printf(" blindsum.%d\n",ret);
    for (j=0; j<13; j++)
    {
        val = (j < 12) ? (j + 1) : -excess;
        while ( 1 )
        {
            retvals[j] = secp256k1_pedersen_commit(ctx,commits[j],blinds[j],val);
            //if ( commits[j][0] == 0x02 )
                break;
        }
        if ( j < 12 )
            excess += val;
        for (i=0; i<33; i++)
            printf("%02x",commits[j][i]);
        printf(" pederson commit.%d val.%lld\n",retvals[j],(long long)val);
    }
    ret = secp256k1_pedersen_verify_tally(ctx,commitptrs,12,&commitptrs[12],1,0);
    printf("tally.%d vs %lld\n",ret,(long long)excess);
    //getchar();
#endif
}