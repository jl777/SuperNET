/*
 * This file is Copyright Daniel Silverstone <dsilvers@digital-scurf.org> 2006
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */
#include <stdio.h>

//#include "config.h"
#include "OS_portable.h"
#include "../includes/libgfshare.h"
//#include "../includes/libgfshare_tables.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define XMALLOC malloc
#define XFREE free

struct _gfshare_ctx
{
    uint32_t sharecount,threshold,size,buffersize;
    uint8_t sharenrs[255],buffer[];
};

uint8_t ctx_logs[256] = {
    0x00, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1a, 0xc6,
    0x03, 0xdf, 0x33, 0xee, 0x1b, 0x68, 0xc7, 0x4b,
    0x04, 0x64, 0xe0, 0x0e, 0x34, 0x8d, 0xef, 0x81,
    0x1c, 0xc1, 0x69, 0xf8, 0xc8, 0x08, 0x4c, 0x71,
    0x05, 0x8a, 0x65, 0x2f, 0xe1, 0x24, 0x0f, 0x21,
    0x35, 0x93, 0x8e, 0xda, 0xf0, 0x12, 0x82, 0x45,
    0x1d, 0xb5, 0xc2, 0x7d, 0x6a, 0x27, 0xf9, 0xb9,
    0xc9, 0x9a, 0x09, 0x78, 0x4d, 0xe4, 0x72, 0xa6,
    0x06, 0xbf, 0x8b, 0x62, 0x66, 0xdd, 0x30, 0xfd,
    0xe2, 0x98, 0x25, 0xb3, 0x10, 0x91, 0x22, 0x88,
    0x36, 0xd0, 0x94, 0xce, 0x8f, 0x96, 0xdb, 0xbd,
    0xf1, 0xd2, 0x13, 0x5c, 0x83, 0x38, 0x46, 0x40,
    0x1e, 0x42, 0xb6, 0xa3, 0xc3, 0x48, 0x7e, 0x6e,
    0x6b, 0x3a, 0x28, 0x54, 0xfa, 0x85, 0xba, 0x3d,
    0xca, 0x5e, 0x9b, 0x9f, 0x0a, 0x15, 0x79, 0x2b,
    0x4e, 0xd4, 0xe5, 0xac, 0x73, 0xf3, 0xa7, 0x57,
    0x07, 0x70, 0xc0, 0xf7, 0x8c, 0x80, 0x63, 0x0d,
    0x67, 0x4a, 0xde, 0xed, 0x31, 0xc5, 0xfe, 0x18,
    0xe3, 0xa5, 0x99, 0x77, 0x26, 0xb8, 0xb4, 0x7c,
    0x11, 0x44, 0x92, 0xd9, 0x23, 0x20, 0x89, 0x2e,
    0x37, 0x3f, 0xd1, 0x5b, 0x95, 0xbc, 0xcf, 0xcd,
    0x90, 0x87, 0x97, 0xb2, 0xdc, 0xfc, 0xbe, 0x61,
    0xf2, 0x56, 0xd3, 0xab, 0x14, 0x2a, 0x5d, 0x9e,
    0x84, 0x3c, 0x39, 0x53, 0x47, 0x6d, 0x41, 0xa2,
    0x1f, 0x2d, 0x43, 0xd8, 0xb7, 0x7b, 0xa4, 0x76,
    0xc4, 0x17, 0x49, 0xec, 0x7f, 0x0c, 0x6f, 0xf6,
    0x6c, 0xa1, 0x3b, 0x52, 0x29, 0x9d, 0x55, 0xaa,
    0xfb, 0x60, 0x86, 0xb1, 0xbb, 0xcc, 0x3e, 0x5a,
    0xcb, 0x59, 0x5f, 0xb0, 0x9c, 0xa9, 0xa0, 0x51,
    0x0b, 0xf5, 0x16, 0xeb, 0x7a, 0x75, 0x2c, 0xd7,
    0x4f, 0xae, 0xd5, 0xe9, 0xe6, 0xe7, 0xad, 0xe8,
    0x74, 0xd6, 0xf4, 0xea, 0xa8, 0x50, 0x58, 0xaf };

uint8_t ctx_exps[510] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1d, 0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13, 0x26,
    0x4c, 0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9,
    0x8f, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0,
    0x9d, 0x27, 0x4e, 0x9c, 0x25, 0x4a, 0x94, 0x35,
    0x6a, 0xd4, 0xb5, 0x77, 0xee, 0xc1, 0x9f, 0x23,
    0x46, 0x8c, 0x05, 0x0a, 0x14, 0x28, 0x50, 0xa0,
    0x5d, 0xba, 0x69, 0xd2, 0xb9, 0x6f, 0xde, 0xa1,
    0x5f, 0xbe, 0x61, 0xc2, 0x99, 0x2f, 0x5e, 0xbc,
    0x65, 0xca, 0x89, 0x0f, 0x1e, 0x3c, 0x78, 0xf0,
    0xfd, 0xe7, 0xd3, 0xbb, 0x6b, 0xd6, 0xb1, 0x7f,
    0xfe, 0xe1, 0xdf, 0xa3, 0x5b, 0xb6, 0x71, 0xe2,
    0xd9, 0xaf, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88,
    0x0d, 0x1a, 0x34, 0x68, 0xd0, 0xbd, 0x67, 0xce,
    0x81, 0x1f, 0x3e, 0x7c, 0xf8, 0xed, 0xc7, 0x93,
    0x3b, 0x76, 0xec, 0xc5, 0x97, 0x33, 0x66, 0xcc,
    0x85, 0x17, 0x2e, 0x5c, 0xb8, 0x6d, 0xda, 0xa9,
    0x4f, 0x9e, 0x21, 0x42, 0x84, 0x15, 0x2a, 0x54,
    0xa8, 0x4d, 0x9a, 0x29, 0x52, 0xa4, 0x55, 0xaa,
    0x49, 0x92, 0x39, 0x72, 0xe4, 0xd5, 0xb7, 0x73,
    0xe6, 0xd1, 0xbf, 0x63, 0xc6, 0x91, 0x3f, 0x7e,
    0xfc, 0xe5, 0xd7, 0xb3, 0x7b, 0xf6, 0xf1, 0xff,
    0xe3, 0xdb, 0xab, 0x4b, 0x96, 0x31, 0x62, 0xc4,
    0x95, 0x37, 0x6e, 0xdc, 0xa5, 0x57, 0xae, 0x41,
    0x82, 0x19, 0x32, 0x64, 0xc8, 0x8d, 0x07, 0x0e,
    0x1c, 0x38, 0x70, 0xe0, 0xdd, 0xa7, 0x53, 0xa6,
    0x51, 0xa2, 0x59, 0xb2, 0x79, 0xf2, 0xf9, 0xef,
    0xc3, 0x9b, 0x2b, 0x56, 0xac, 0x45, 0x8a, 0x09,
    0x12, 0x24, 0x48, 0x90, 0x3d, 0x7a, 0xf4, 0xf5,
    0xf7, 0xf3, 0xfb, 0xeb, 0xcb, 0x8b, 0x0b, 0x16,
    0x2c, 0x58, 0xb0, 0x7d, 0xfa, 0xe9, 0xcf, 0x83,
    0x1b, 0x36, 0x6c, 0xd8, 0xad, 0x47, 0x8e, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1d,
    0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13, 0x26, 0x4c,
    0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9, 0x8f,
    0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0, 0x9d,
    0x27, 0x4e, 0x9c, 0x25, 0x4a, 0x94, 0x35, 0x6a,
    0xd4, 0xb5, 0x77, 0xee, 0xc1, 0x9f, 0x23, 0x46,
    0x8c, 0x05, 0x0a, 0x14, 0x28, 0x50, 0xa0, 0x5d,
    0xba, 0x69, 0xd2, 0xb9, 0x6f, 0xde, 0xa1, 0x5f,
    0xbe, 0x61, 0xc2, 0x99, 0x2f, 0x5e, 0xbc, 0x65,
    0xca, 0x89, 0x0f, 0x1e, 0x3c, 0x78, 0xf0, 0xfd,
    0xe7, 0xd3, 0xbb, 0x6b, 0xd6, 0xb1, 0x7f, 0xfe,
    0xe1, 0xdf, 0xa3, 0x5b, 0xb6, 0x71, 0xe2, 0xd9,
    0xaf, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88, 0x0d,
    0x1a, 0x34, 0x68, 0xd0, 0xbd, 0x67, 0xce, 0x81,
    0x1f, 0x3e, 0x7c, 0xf8, 0xed, 0xc7, 0x93, 0x3b,
    0x76, 0xec, 0xc5, 0x97, 0x33, 0x66, 0xcc, 0x85,
    0x17, 0x2e, 0x5c, 0xb8, 0x6d, 0xda, 0xa9, 0x4f,
    0x9e, 0x21, 0x42, 0x84, 0x15, 0x2a, 0x54, 0xa8,
    0x4d, 0x9a, 0x29, 0x52, 0xa4, 0x55, 0xaa, 0x49,
    0x92, 0x39, 0x72, 0xe4, 0xd5, 0xb7, 0x73, 0xe6,
    0xd1, 0xbf, 0x63, 0xc6, 0x91, 0x3f, 0x7e, 0xfc,
    0xe5, 0xd7, 0xb3, 0x7b, 0xf6, 0xf1, 0xff, 0xe3,
    0xdb, 0xab, 0x4b, 0x96, 0x31, 0x62, 0xc4, 0x95,
    0x37, 0x6e, 0xdc, 0xa5, 0x57, 0xae, 0x41, 0x82,
    0x19, 0x32, 0x64, 0xc8, 0x8d, 0x07, 0x0e, 0x1c,
    0x38, 0x70, 0xe0, 0xdd, 0xa7, 0x53, 0xa6, 0x51,
    0xa2, 0x59, 0xb2, 0x79, 0xf2, 0xf9, 0xef, 0xc3,
    0x9b, 0x2b, 0x56, 0xac, 0x45, 0x8a, 0x09, 0x12,
    0x24, 0x48, 0x90, 0x3d, 0x7a, 0xf4, 0xf5, 0xf7,
    0xf3, 0xfb, 0xeb, 0xcb, 0x8b, 0x0b, 0x16, 0x2c,
    0x58, 0xb0, 0x7d, 0xfa, 0xe9, 0xcf, 0x83, 0x1b,
    0x36, 0x6c, 0xd8, 0xad, 0x47, 0x8e };

/*void _gfshare_fill_rand_using_random(uint8_t *buffer,unsigned long long count)
{
    uint32_t i;
    for (i=0; i<count; i++)
        buffer[i] = (random() & 0xff00) >> 8; // apparently the bottom 8 aren't very random but the middles ones are
}*/
//void randombytes(uint8_t *x,long xlen);

//gfshare_rand_func_t gfshare_fill_rand = _gfshare_fill_rand_using_random;
//gfshare_rand_func_t gfshare_fill_rand = OS_randombytes;

// ------------------------------------------------------[ Preparation ]----

gfshare_ctx *_gfshare_ctx_init_core(uint8_t *sharenrs,uint32_t sharecount,uint8_t threshold,uint32_t size)
{
    gfshare_ctx *ctx;
    ctx = XMALLOC(sizeof(struct _gfshare_ctx) + threshold * size);
    if ( ctx == NULL )
        return(NULL); // errno should still be set from XMALLOC()
    ctx->sharecount = sharecount;
    ctx->threshold = threshold;
    ctx->size = size;
    memcpy(ctx->sharenrs,sharenrs,sharecount);
    ctx->buffersize = threshold * size;
    return(ctx);
}

// Initialise a gfshare context for producing shares
gfshare_ctx *gfshare_ctx_init_enc(uint8_t *sharenrs,uint32_t sharecount,uint8_t threshold,uint32_t size)
{
    uint32_t i;
    // can't have x[i] = 0 - that would just be a copy of the secret, in theory
    // in fact, due to the way we use exp/log for multiplication and treat log(0) as 0, it ends up as a copy of x[i] = 1
    for (i=0; i<sharecount; i++)
    {
        if ( sharenrs[i] == 0 )
        {
            printf("null sharenrs error\n");
            errno = EINVAL;
            return NULL;
        }
    }
    return(_gfshare_ctx_init_core(sharenrs,sharecount,threshold,size));
}

// Initialise a gfshare context for recombining shares
gfshare_ctx *gfshare_ctx_init_dec(uint8_t *sharenrs,uint32_t sharecount,uint32_t size)
{
    gfshare_ctx *ctx = _gfshare_ctx_init_core(sharenrs,sharecount,sharecount,size);
    if ( ctx != NULL )
        ctx->threshold = 0;
    return(ctx);
}

// Free a share context's memory.
void gfshare_ctx_free(gfshare_ctx *ctx)
{
    long len = sizeof(struct _gfshare_ctx) + ctx->buffersize;
    //gfshare_fill_rand((uint8_t*)ctx,len);
    OS_randombytes((uint8_t *)ctx,len);
    XFREE(ctx);
}

// --------------------------------------------------------[ Splitting ]----

// Provide a secret to the encoder. (this re-scrambles the coefficients)
void gfshare_ctx_enc_setsecret(gfshare_ctx *ctx,uint8_t *secret)
{
    memcpy(ctx->buffer + ((ctx->threshold-1) * ctx->size),secret,ctx->size);
    //gfshare_fill_rand(ctx->buffer,(ctx->threshold-1) * ctx->size);
    OS_randombytes(ctx->buffer,(ctx->threshold-1) * ctx->size);
}

// Extract a share from the context. 'share' must be preallocated and at least 'size' bytes long.
// 'sharenr' is the index into the 'sharenrs' array of the share you want.
void calc_share(uint8_t *buffer,int32_t size,int32_t M,uint32_t ilog,uint8_t *share)
{
    uint32_t pos,coefficient;//,ilog = ctx_logs[ctx->sharenrs[sharenr]];
    //uint8_t *coefficient_ptr = buffer;
    uint8_t *share_ptr,share_byte;
    for (pos=0; pos<size; pos++)
        share[pos] = *(buffer++);
    for (coefficient=1; coefficient<M; coefficient++)
    {
        share_ptr = share;
        for (pos=0; pos<size; pos++)
        {
            share_byte = *share_ptr;
            if ( share_byte != 0 )
                share_byte = ctx_exps[ilog + ctx_logs[share_byte]];
            *share_ptr++ = (share_byte ^ *buffer++);
        }
    }
}

void gfshare_ctx_enc_getshare(gfshare_ctx *ctx,uint8_t sharenr,uint8_t *share)
{
    calc_share(ctx->buffer,ctx->size,ctx->threshold,ctx_logs[ctx->sharenrs[sharenr]],share);
}

#ifdef notnow
void calc_shares(uint8_t *shares,uint8_t *secret,int32_t size,int32_t width,int32_t M,int32_t N,uint8_t *sharenrs)
{
    int32_t i;
    uint8_t *buffer = calloc(M,width);
    memset(shares,0,N*width);
    memcpy(buffer + ((M - 1) * size),secret,size);
    //gfshare_fill_rand(buffer,(M - 1) * size);
    OS_randombytes(buffer,(M - 1) * size);
    for (i=0; i<N; i++)
    {
        //uint32_t _crc32(uint32_t crc, const void *buf, size_t size);
        calc_share(buffer,size,M,ctx_logs[sharenrs[i]],&shares[i * width]);
        printf("(%02x %08x) ",sharenrs[i],calc_crc32(0,&shares[i*width],size));
    }
    free(buffer);
}
#endif

// ----------------------------------------------------[ Recombination ]----

// Inform a recombination context of a change in share indexes
void gfshare_ctx_dec_newshares(gfshare_ctx *ctx,uint8_t *sharenrs)
{
    memcpy(ctx->sharenrs,sharenrs,ctx->sharecount);
}

// Provide a share context with one of the shares. The 'sharenr' is the index into the 'sharenrs' array
void gfshare_ctx_dec_giveshare(gfshare_ctx *ctx,uint8_t sharenr,uint8_t *share)
{
    memcpy(ctx->buffer + (sharenr * ctx->size),share,ctx->size);
}

// Extract the secret by interpolation of the shares. secretbuf must be allocated and at least 'size' bytes long
void gfshare_extract(uint8_t *secretbuf,uint8_t *sharenrs,int32_t N,uint8_t *buffer,int32_t size,int32_t width)
{
    uint32_t i,j,Li_top,Li_bottom; uint8_t *secret_ptr,*share_ptr,sharei,sharej;
    memset(secretbuf,0,width);
    for (i=0; i<N; i++)
    {
        // Compute L(i) as per Lagrange Interpolation
        Li_top = Li_bottom = 0;
        if ( (sharei= sharenrs[i]) == 0 )
            continue; // this share is not provided.
        for (j=0; j<N; j++)
        {
            if ( i == j )
                continue;
            if ( (sharej= sharenrs[j]) == 0 )
                continue; // skip empty share
            Li_top += ctx_logs[sharej];
            if ( Li_top >= 0xff )
                Li_top -= 0xff;
            Li_bottom += ctx_logs[sharei ^ sharej];
            if ( Li_bottom >= 0xff )
                Li_bottom -= 0xff;
        }
        if ( Li_bottom > Li_top )
            Li_top += 0xff;
        Li_top -= Li_bottom; // Li_top is now log(L(i))
        secret_ptr = secretbuf;
        share_ptr = buffer + (width * i);
        for (j=0; j<size; j++)
        {
            if ( *share_ptr != 0 )
                (*secret_ptr) ^= ctx_exps[Li_top + ctx_logs[*share_ptr]];
            share_ptr++;
            secret_ptr++;
        }
    }
}

void gfshare_ctx_dec_extract(gfshare_ctx *ctx,uint8_t *secretbuf)
{
    gfshare_extract(secretbuf,ctx->sharenrs,ctx->sharecount,ctx->buffer,ctx->size,ctx->size);
}

int32_t init_sharenrs(uint8_t sharenrs[255],uint8_t *orig,int32_t m,int32_t n)
{
    uint8_t *randvals,valid[255];
    int32_t i,j,r,remains,orign;
    if ( m > n || n >= 0xff ) // reserve 255 for illegal sharei
    {
        printf("illegal M.%d of N.%d\n",m,n);
        return(-1);
    }
    randvals = calloc(1,65536);
    OS_randombytes(randvals,65536);
    memset(sharenrs,0,n);
    if ( orig == 0 && n == m )
    {
        for (i=0; i<255; i++)
            valid[i] = (i + 1);
        remains = orign = 255;
        for (i=0; i<n; i++)
        {
            r = (randvals[i] % remains);
            sharenrs[i] = valid[r];
            printf("%d ",sharenrs[i]);
            valid[r] = valid[--remains];
        }
        printf("FULL SET\n");
    }
    else
    {
        remains = n;
        orign = n;
        memcpy(valid,sharenrs,n);
        i = j = 0;
        memset(sharenrs,0,n);
        for (i=0; i<m; i++)
        {
            r = (rand() >> 8) % remains;
            sharenrs[i] = valid[r];
            valid[r] = valid[--remains];
        }
        /*while ( i < m )
        {
            if ( j >= 65536 )
            {
                gfshare_fill_rand(randvals,65536);
                printf("refill j.%d\n",j);
                j = 0;
            }
            r = (randvals[j++] % n);
            if ( valid[r] != 0 )
            {
                remains--;
                i++;
                sharenrs[r] = valid[r];
                //printf("%d ",sharenrs[i]);
                valid[r] = 0;
            }
        }*/
        for (i=0; i<n; i++)
            printf("%d ",valid[i]);
        printf("valid\n");
        for (i=0; i<m; i++)
            printf("%d ",sharenrs[i]);
        printf("sharenrs vals m.%d of n.%d\n",m,n);
        //getchar();
    }
    free(randvals);
    //printf("sharenrs m.%d of n.%d\n",m,n);
    if ( remains != (orign - m) )
    {
        printf("remains algo error??\n");
        return(-1);
    }
    for (i=0; i<m; i++)
    {
        for (j=0; j<m; j++)
        {
            if ( i == j )
                continue;
            if ( sharenrs[i] != 0 && sharenrs[i] == sharenrs[j] )
            {
                printf("FATAL: duplicate entry sharenrs[%d] %d vs %d sharenrs[%d]\n",i,sharenrs[i],sharenrs[j],j);
                return(-1);
            }
        }
    }
    return(0);
}

// test
int test_m_of_n(int m,int n,int size,int maxiters)
{
    int32_t i,j,r,err = -1;
    uint8_t *secret,*recomb,**shares,*allshares,sharenrs[255],testnrs[255];
    gfshare_ctx *G;
    if ( init_sharenrs(sharenrs,0,n,n) < 0 )
        return(err);
    secret = malloc(size);
    recomb = malloc(size);
    shares = calloc(n,sizeof(*shares));
    allshares = calloc(254,size);
    for (i=0; i<n; i++)
        shares[i] = malloc(size);
    // Stage 1, make a secret
    OS_randombytes(secret,size);
    
    err = 0;
    r = m;
    for (j=0; j<maxiters; j++)
    {
        memset(allshares,0,254*size);
        // Stage 2, split it n ways with a threshold of m
        if ( 1 )
        {
            G = gfshare_ctx_init_enc(sharenrs,n,r,size);
            gfshare_ctx_enc_setsecret(G,secret);
            for (i=0; i<n; i++)
                gfshare_ctx_enc_getshare(G,i,shares[i]);
            gfshare_ctx_free(G);
        }
        else calc_shares(allshares,secret,size,size,r,n,sharenrs);

        // Prep the decode shape
        memset(testnrs,0,n);
        if ( init_sharenrs(testnrs,sharenrs,r,n) < 0 )
        {
            printf("iter.%d error init_sharenrs(m.%d of n.%d)\n",j,r,n);
            goto cleanup;
        }
        G = gfshare_ctx_init_dec(testnrs,n,size);
        for (i=0; i<n; i++)
            if ( testnrs[i] == sharenrs[i] )
                gfshare_ctx_dec_giveshare(G,i,&allshares[i*size]);//shares[i]); //

        gfshare_ctx_dec_newshares(G,testnrs);
        gfshare_ctx_dec_extract(G,recomb);
        if ( memcmp(secret,recomb,size) != 0 )
            fprintf(stderr,"(ERRROR M.%d)\n",r), err++;
        else fprintf(stderr,"M.%d\n",r);
        r = ((rand() >> 8) % n) + 1;
    }
    err = 0;
    printf("err.%d\n",err);
//#ifdef hardcoded_m_of_n_test
    int32_t ok;
    // Stage 3, attempt a recombination with shares 1 and 2
    sharenrs[2] = 0;
    gfshare_ctx_dec_newshares(G,sharenrs);
    gfshare_ctx_dec_extract( G, recomb );
    for( i = 0; i < 512; ++i )
        if( secret[i] != recomb[i] )
            ok = 0;
    printf("shares 1 + 2: ok.%d\n",ok);
    err += (ok == 0), ok = 1;
    // Stage 4, attempt a recombination with shares 1 and 3
    sharenrs[2] = '2';
    sharenrs[1] = 0;
    gfshare_ctx_dec_newshares( G, sharenrs );
    gfshare_ctx_dec_extract( G, recomb );
    for( i = 0; i < 512; ++i )
        if( secret[i] != recomb[i] )
            ok = 0;
    printf("shares 1 + 3: ok.%d\n",ok);
    err += (ok == 0), ok = 1;
    // Stage 5, attempt a recombination with shares 2 and 3
    sharenrs[0] = 0;
    sharenrs[1] = '1';
    gfshare_ctx_dec_newshares( G, sharenrs );
    gfshare_ctx_dec_extract( G, recomb );
    for( i = 0; i < 512; ++i )
        if( secret[i] != recomb[i] )
            ok = 0;
    printf("shares 2 + 3: ok.%d\n",ok);
    err += (ok == 0), ok = 1;
    // Stage 6, attempt a recombination with shares 1, 2 and 3
    sharenrs[0] = '0';
    gfshare_ctx_dec_newshares( G, sharenrs );
    gfshare_ctx_dec_extract( G, recomb );
    for( i = 0; i < 512; ++i )
        if( secret[i] != recomb[i] )
            ok = 0;
    printf("shares 1 + 2 + 3: ok.%d\n",ok);
    err += (ok == 0), ok = 1;
    gfshare_ctx_free( G );
    printf("total error test_m_of_n %d\n",err);
//#endif
cleanup:
    for (i=0; i<n; i++)
        free(shares[i]);
    free(shares);
    free(allshares);
    free(secret);
    free(recomb);
    return(-err);
}


