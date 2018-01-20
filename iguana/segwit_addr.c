/* Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "segwit_addr.h"
#define BECH32_DELIM ':'

/*uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
        (-((b >> 1) & 1) & 0x26508e6dUL) ^
        (-((b >> 2) & 1) & 0x1ea119faUL) ^
        (-((b >> 3) & 1) & 0x3d4233ddUL) ^
        (-((b >> 4) & 1) & 0x2a1462b3UL);
}*/

uint64_t PolyMod_step(uint64_t c,uint8_t d)
{
    uint8_t c0 = c >> 35;
    //printf("step (%llx) + %d -> ",(long long)c,d);
    c = ((c & 0x07ffffffff) << 5) ^ d;
    if (c0 & 0x01) c ^= 0x98f2bc8e61;
    if (c0 & 0x02) c ^= 0x79b76d99e2;
    if (c0 & 0x04) c ^= 0xf33e5fb3c4;
    if (c0 & 0x08) c ^= 0xae2eabe2a8;
    if (c0 & 0x10) c ^= 0x1e4f43e470;
    //printf("%llx\n",(long long)c);
    return(c);
}

static const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const int8_t charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7,
    5,  -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22,
    31, 27, 19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1,
    -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27, 19, -1, 1,  0,
    3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1, -1};

int bech32_encode(char *output,const char *hrp,const uint8_t *data,int32_t data_len)
{
    uint64_t chk = 1; size_t i = 0; int32_t ch,chklen = 8;
    while ( hrp[i] != 0 )
    {
        ch = hrp[i];
        if ( ch < 33 || ch > 126 )
        {
            printf("bech32_encode illegal ch.%d\n",ch);
            return 0;
        }
        if ( ch >= 'A' && ch <= 'Z' )
        {
            printf("bech32_encode illegal uppercase.%c\n",ch);
            return 0;
        }
        i++;
    }
    //printf("bech32_encode after hrp.(%s)\n",hrp);
    if ( i + chklen + 2 + data_len > 90 )
        return 0;
    while ( *hrp != 0 )
    {
        chk = PolyMod_step(chk,*hrp & 0x1f);
        *(output++) = *(hrp++);
    }
    chk = PolyMod_step(chk,0);
    *(output++) = BECH32_DELIM;
    for (i=0; i<data_len; i++)
    {
        if ( *data >> 5 )
        {
            printf("bech32_encode out of band data.%c\n",*data);
            return 0;
        }
        chk = PolyMod_step(chk,*data);
        *(output++) = charset[*(data++)];
    }
    for (i = 0; i < chklen; ++i)
        chk = PolyMod_step(chk,0);
    chk ^= 1;
    //printf("bech32_encode emit >>>>>>> ");
    for (i = 0; i < chklen; ++i) {
        *output = charset[(chk >> ((chklen - 1 - i) * 5)) & 0x1f];
        //printf("%c",*output);
        output++;
    }
    *output = 0;
    //printf(" checksum %llx\n",(long long)chk);
    return 1;
}

int bech32_decode(char *hrp,uint8_t *data,int32_t *data_len,const char *input)
{
    uint64_t chk = 1; int32_t chklen = 8; size_t i,hrp_len,input_len = strlen(input);
    int have_lower = 0, have_upper = 0;
    if ( input_len < 8 || input_len > 90 )
    {
        printf("bech32_decode: invalid input_len.%d\n",(int32_t)input_len);
        return 0;
    }
    *data_len = 0;
    while ( *data_len < input_len && input[(input_len - 1) - *data_len] != BECH32_DELIM )
        ++(*data_len);
    hrp_len = input_len - (1 + *data_len);
    if ( hrp_len < 1 || *data_len < chklen )
    {
        printf("bech32_decode: invalid hrp_len.%d or datalen.%d\n",(int32_t)hrp_len,(int32_t)*data_len);
        return 0;
    }
    *(data_len) -= chklen;
    for (i=0; i<hrp_len; i++)
    {
        int ch = input[i];
        if ( ch < 33 || ch > 126 )
        {
            printf("bech32_decode: invalid char.%d\n",ch);
            return 0;
        }
        if ( ch >= 'a' && ch <= 'z' )
            have_lower = 1;
        else if ( ch >= 'A' && ch <= 'Z' )
        {
            have_upper = 1;
            ch = (ch - 'A') + 'a';
        }
        hrp[i] = ch;
        chk = PolyMod_step(chk,ch & 0x1f);
    }
    hrp[i++] = 0;
    chk = PolyMod_step(chk,0);
    while ( i < input_len )
    {
        int v = (input[i] & 0x80) ? -1 : charset_rev[(int)input[i]];
        if ( input[i] >= 'a' && input[i] <= 'z' )
            have_lower = 1;
        else if ( input[i] >= 'A' && input[i] <= 'Z' )
            have_upper = 1;
        if ( v == -1 )
        {
            printf("bech32_decode: invalid v.%d from input.[%d] %d\n",(int32_t)v,(int32_t)i,(int32_t)input[i]);
            return 0;
        }
        chk = PolyMod_step(chk,v);
        if (i + chklen < input_len)
            data[i - (1 + hrp_len)] = v;
        ++i;
    }
    if ( have_lower && have_upper )
    {
        printf("bech32_decode: have_lower.%d have_upper.%d\n",have_lower,have_upper);
        return 0;
    }
    //printf("checksum chk.%llx lower.%d upper.%d inputlen.%d\n",(long long)chk,have_lower,have_upper,(int32_t)input_len);
    return chk == 1;
}

int bech32_convert_bits(uint8_t *out,int32_t *outlen,int outbits,const uint8_t *in,int32_t inlen,int inbits,int pad)
{
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return 0;
    }
    return 1;
}

/*int segwit_addr_encode(char *output, const char *hrp, int witver, const uint8_t *witprog, size_t witprog_len) {
    uint8_t data[65];
    size_t datalen = 0;
    if (witver > 16) return 0;
    if (witver == 0 && witprog_len != 20 && witprog_len != 32) return 0;
    if (witprog_len < 2 || witprog_len > 40) return 0;
    data[0] = witver;
    convert_bits(data + 1, &datalen, 5, witprog, witprog_len, 8, 1);
    ++datalen;
    return bech32_encode(output, hrp, data, datalen);
}

int segwit_addr_decode(int* witver, uint8_t* witdata, size_t* witdata_len, const char* hrp, const char* addr) {
    uint8_t data[84];
    char hrp_actual[84];
    size_t data_len;
    if (!bech32_decode(hrp_actual, data, &data_len, addr)) return 0;
    if (data_len == 0 || data_len > 65) return 0;
    if (strncmp(hrp, hrp_actual, 84) != 0) return 0;
    if (data[0] > 16) return 0;
    *witdata_len = 0;
    if (!convert_bits(witdata, witdata_len, 8, data + 1, data_len - 1, 5, 0)) return 0;
    if (*witdata_len < 2 || *witdata_len > 40) return 0;
    if (data[0] == 0 && *witdata_len != 20 && *witdata_len != 32) return 0;
    *witver = data[0];
    return 1;
}*/
