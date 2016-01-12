/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
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

#include "../iguana/iguana777.h"

bits256 bits256_doublesha256(char *hashstr,uint8_t *data,int32_t datalen)
{
    bits256 hash,hash2; int32_t i;
    vcalc_sha256(0,hash.bytes,data,datalen);
    vcalc_sha256(0,hash2.bytes,hash.bytes,sizeof(hash));
    for (i=0; i<sizeof(hash); i++)
        hash.bytes[i] = hash2.bytes[sizeof(hash) - 1 - i];
    if ( hashstr != 0 )
        init_hexbytes_noT(hashstr,hash.bytes,sizeof(hash));
    return(hash);
}

char *bits256_str(char hexstr[65],bits256 x)
{
    init_hexbytes_noT(hexstr,x.bytes,sizeof(x));
    return(hexstr);
}

char *bits256_lstr(char hexstr[65],bits256 x)
{
    bits256 revx; int32_t i;
    for (i=0; i<32; i++)
        revx.bytes[i] = x.bytes[31-i];
    init_hexbytes_noT(hexstr,revx.bytes,sizeof(revx));
    return(hexstr);
}

bits256 bits256_add(bits256 a,bits256 b)
{
    int32_t i; bits256 sum; uint64_t x,carry = 0;
    memset(sum.bytes,0,sizeof(sum));
    for (i=0; i<4; i++)
    {
        x = a.ulongs[i] + b.ulongs[i];
        sum.ulongs[i] = (x + carry);
        if ( x < a.ulongs[i] || x < b.ulongs[i] )
            carry = 1;
        else carry = 0;
    }
    return(sum);
}

int32_t bits256_cmp(bits256 a,bits256 b)
{
    int32_t i;
    for (i=0; i<4; i++)
    {
        if ( a.ulongs[i] > b.ulongs[i] )
            return(1);
        else if ( a.ulongs[i] < b.ulongs[i] )
            return(-1);
    }
    return(0);
}

bits256 bits256_lshift(bits256 x)
{
    int32_t i,carry,prevcarry = 0; uint64_t mask = (1LL << 63);
    for (i=0; i<4; i++)
    {
        carry = ((mask & x.ulongs[i]) != 0);
        x.ulongs[i] = (x.ulongs[i] << 1) | prevcarry;
        prevcarry = carry;
    }
    return(x);
}

bits256 bits256_from_compact(uint32_t c)
{
	uint32_t nbytes,nbits,i; bits256 x;
    memset(x.bytes,0,sizeof(x));
    nbytes = (c >> 24) & 0xFF;
    nbits = (8 * (nbytes - 3));
    x.ulongs[0] = c & 0xFFFFFF;
    for (i=0; i<nbits; i++) // horrible inefficient
        x = bits256_lshift(x);
    return(x);
}

void calc_OP_HASH160(char hexstr[41],uint8_t hash160[20],char *pubkey)
{
    uint8_t sha256[32],buf[4096]; int32_t len;
    len = (int32_t)strlen(pubkey)/2;
    if ( len > sizeof(buf) )
    {
        printf("calc_OP_HASH160 overflow len.%d vs %d\n",len,(int32_t)sizeof(buf));
        return;
    }
    decode_hex(buf,len,pubkey);
    vcalc_sha256(0,sha256,buf,len);
    calc_rmd160(0,hash160,sha256,sizeof(sha256));
    if ( 0 )
    {
        int i;
        for (i=0; i<20; i++)
            printf("%02x",hash160[i]);
        printf("<- (%s)\n",pubkey);
    }
    if ( hexstr != 0 )
        init_hexbytes_noT(hexstr,hash160,20);
}

double _dxblend(double *destp,double val,double decay)
{
    double oldval;
	if ( (oldval = *destp) != 0. )
		return((oldval * decay) + ((1. - decay) * val));
	else return(val);
}

double dxblend(double *destp,double val,double decay)
{
	double newval,slope;
	if ( isnan(*destp) != 0 )
		*destp = 0.;
	if ( isnan(val) != 0 )
		return(0.);
	if ( *destp == 0 )
	{
		*destp = val;
		return(0);
	}
	newval = _dxblend(destp,val,decay);
	if ( newval < SMALLVAL && newval > -SMALLVAL )
	{
		// non-zero marker for actual values close to or even equal to zero
		if ( newval < 0. )
			newval = -SMALLVAL;
		else newval = SMALLVAL;
	}
	if ( *destp != 0. && newval != 0. )
		slope = (newval - *destp);
	else slope = 0.;
	*destp = newval;
	return(slope);
}

/*queue_t TerminateQ; int32_t TerminateQ_queued;
void iguana_terminator(void *arg)
{
    struct iguana_thread *t; uint32_t lastdisp = 0; int32_t terminated = 0;
    printf("iguana_terminator\n");
    while ( 1 )
    {
        if ( (t= queue_dequeue(&TerminateQ,0)) != 0 )
        {
            printf("terminate.%p\n",t);
            iguana_terminate(t);
            terminated++;
            continue;
        }
        sleep(1);
        if ( time(NULL) > lastdisp+60 )
        {
            lastdisp = (uint32_t)time(NULL);
            printf("TerminateQ %d terminated of %d queued\n",terminated,TerminateQ_queued);
        }
    }
}*/


int32_t iguana_numthreads(struct iguana_info *coin,int32_t mask)
{
    int32_t i,sum = 0;
    for (i=0; i<8; i++)
        if ( ((1 << i) & mask) != 0 )
            sum += (coin->Launched[i] - coin->Terminated[i]);
    return(sum);
}

void iguana_launcher(void *ptr)
{
    struct iguana_thread *t = ptr; struct iguana_info *coin;
    coin = t->coin;
    t->funcp(t->arg);
    coin->Terminated[t->type % (sizeof(coin->Terminated)/sizeof(*coin->Terminated))]++;
    queue_enqueue("TerminateQ",&coin->TerminateQ,&t->DL,0);
}

void iguana_terminate(struct iguana_info *coin,struct iguana_thread *t)
{
    int32_t retval;
    retval = pthread_join(t->handle,NULL);
    if ( retval != 0 )
        printf("error.%d terminating t.%p thread.%s\n",retval,t,t->name);
    myfree(t,sizeof(*t));
}

struct iguana_thread *iguana_launch(struct iguana_info *coin,char *name,iguana_func funcp,void *arg,uint8_t type)
{
    int32_t retval; struct iguana_thread *t;
    t = mycalloc('Z',1,sizeof(*t));
    strcpy(t->name,name);
    t->coin = coin;
    t->funcp = funcp;
    t->arg = arg;
    t->type = (type % (sizeof(coin->Terminated)/sizeof(*coin->Terminated)));
    coin->Launched[t->type]++;
    retval = OS_thread_create(&t->handle,NULL,(void *)iguana_launcher,(void *)t);
    if ( retval != 0 )
        printf("error launching %s\n",t->name);
    while ( (t= queue_dequeue(&coin->TerminateQ,0)) != 0 )
    {
        if ( (rand() % 100000) == 0 )
            printf("terminated.%d launched.%d terminate.%p\n",coin->Terminated[t->type],coin->Launched[t->type],t);
        iguana_terminate(coin,t);
    }
    return(t);
}

char hexbyte(int32_t c)
{
    c &= 0xf;
    if ( c < 10 )
        return('0'+c);
    else if ( c < 16 )
        return('a'+c-10);
    else return(0);
}

int32_t _unhex(char c)
{
    if ( c >= '0' && c <= '9' )
        return(c - '0');
    else if ( c >= 'a' && c <= 'f' )
        return(c - 'a' + 10);
    else if ( c >= 'A' && c <= 'F' )
        return(c - 'A' + 10);
    return(-1);
}

int32_t is_hexstr(char *str,int32_t n)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(0);
    for (i=0; str[i]!=0&&(i<n||n==0); i++)
        if ( _unhex(str[i]) < 0 )
            return(0);
    return(1);
}

int32_t unhex(char c)
{
    int32_t hex;
    if ( (hex= _unhex(c)) < 0 )
    {
        //printf("unhex: illegal hexchar.(%c)\n",c);
    }
    return(hex);
}

unsigned char _decode_hex(char *hex) { return((unhex(hex[0])<<4) | unhex(hex[1])); }

int32_t decode_hex(unsigned char *bytes,int32_t n,char *hex)
{
    int32_t adjust,i = 0;
    //printf("decode.(%s)\n",hex);
    if ( is_hexstr(hex,64) == 0 )
    {
        memset(bytes,0,n);
        return(n);
    }
    if ( n == 0 || (hex[n*2+1] == 0 && hex[n*2] != 0) )
    {
        bytes[0] = unhex(hex[0]);
        printf("decode_hex n.%d hex[0] (%c) -> %d hex.(%s) [n*2+1: %d] [n*2: %d %c] len.%ld\n",n,hex[0],bytes[0],hex,hex[n*2+1],hex[n*2],hex[n*2],(long)strlen(hex));
#ifdef __APPLE__
        getchar();
#endif
        bytes++;
        hex++;
        adjust = 1;
    } else adjust = 0;
    if ( n > 0 )
    {
        for (i=0; i<n; i++)
            bytes[i] = _decode_hex(&hex[i*2]);
    }
    //bytes[i] = 0;
    return(n + adjust);
}

int32_t init_hexbytes_noT(char *hexbytes,unsigned char *message,long len)
{
    int32_t i;
    if ( len == 0 )
    {
        hexbytes[0] = 0;
        return(1);
    }
    for (i=0; i<len; i++)
    {
        hexbytes[i*2] = hexbyte((message[i]>>4) & 0xf);
        hexbytes[i*2 + 1] = hexbyte(message[i] & 0xf);
        //printf("i.%d (%02x) [%c%c]\n",i,message[i],hexbytes[i*2],hexbytes[i*2+1]);
    }
    hexbytes[len*2] = 0;
    //printf("len.%ld\n",len*2+1);
    return((int32_t)len*2+1);
}

void touppercase(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return;
    for (i=0; str[i]!=0; i++)
        str[i] = toupper(((int32_t)str[i]));
}

long _stripwhite(char *buf,int accept)
{
    int32_t i,j,c;
    if ( buf == 0 || buf[0] == 0 )
        return(0);
    for (i=j=0; buf[i]!=0; i++)
    {
        buf[j] = c = buf[i];
        if ( c == accept || (c != ' ' && c != '\n' && c != '\r' && c != '\t' && c != '\b') )
            j++;
    }
    buf[j] = 0;
    return(j);
}

char *clonestr(char *str)
{
    char *clone;
    if ( str == 0 || str[0] == 0 )
    {
        printf("warning cloning nullstr.%p\n",str);
#ifdef __APPLE__
        while ( 1 ) sleep(1);
#endif
        str = (char *)"<nullstr>";
    }
    clone = (char *)malloc(strlen(str)+16);
    strcpy(clone,str);
    return(clone);
}


int32_t safecopy(char *dest,char *src,long len)
{
    int32_t i = -1;
    if ( dest != 0 )
        memset(dest,0,len);
    if ( src != 0 && dest != 0 )
    {
        for (i=0; i<len&&src[i]!=0; i++)
            dest[i] = src[i];
        if ( i == len )
        {
            printf("safecopy: %s too long %ld\n",src,len);
#ifdef __APPLE__
            //getchar();
#endif
            return(-1);
        }
        dest[i] = 0;
    }
    return(i);
}

void escape_code(char *escaped,char *str)
{
    int32_t i,j,c; char esc[16];
    for (i=j=0; str[i]!=0; i++)
    {
        if ( ((c= str[i]) >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') )
            escaped[j++] = c;
        else
        {
            sprintf(esc,"%%%02X",c);
            //sprintf(esc,"\\\\%c",c);
            strcpy(escaped + j,esc);
            j += strlen(esc);
        }
    }
    escaped[j] = 0;
    //printf("escape_code: (%s) -> (%s)\n",str,escaped);
}

int32_t is_zeroes(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(1);
    for (i=0; str[i]!=0; i++)
        if ( str[i] != '0' )
            return(0);
    return(1);
}

int64_t conv_floatstr(char *numstr)
{
    double val,corr;
    val = atof(numstr);
    corr = (val < 0.) ? -0.50000000001 : 0.50000000001;
    return((int64_t)(val * SATOSHIDEN + corr));
}

int32_t has_backslash(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(0);
    for (i=0; str[i]!=0; i++)
        if ( str[i] == '\\' )
            return(1);
    return(0);
}

/*int32_t iguana_sortbignum(void *buf,int32_t size,uint32_t num,int32_t structsize,int32_t dir)
{
    int32_t retval = 0;
    if ( dir > 0 )
    {
        if ( size == 32 )
            qsort(buf,num,structsize,_increasing_bits256);
        else if ( size == 20 )
            qsort(buf,num,structsize,_increasing_rmd160);
        else retval = -1;
    }
    else
    {
        if ( size == 32 )
            qsort(buf,num,structsize,_decreasing_bits256);
        else if ( size == 20 )
            qsort(buf,num,structsize,_decreasing_rmd160);
        else retval = -1;
    }
    if ( retval < 0 )
        printf("iguana_sortbignum only does bits256 and rmd160 for now\n");
	return(retval);
}
*/

void tolowercase(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return;
    for (i=0; str[i]!=0; i++)
        str[i] = tolower(((int32_t)str[i]));
}

int32_t is_decimalstr(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(0);
    for (i=0; str[i]!=0; i++)
        if ( str[i] < '0' || str[i] > '9' )
            return(0);
    return(i);
}

int32_t unstringbits(char *buf,uint64_t bits)
{
    int32_t i;
    for (i=0; i<8; i++,bits>>=8)
        if ( (buf[i]= (char)(bits & 0xff)) == 0 )
            break;
    buf[i] = 0;
    return(i);
}

uint64_t stringbits(char *str)
{
    uint64_t bits = 0;
    if ( str == 0 )
        return(0);
    int32_t i,n = (int32_t)strlen(str);
    if ( n > 8 )
        n = 8;
    for (i=n-1; i>=0; i--)
        bits = (bits << 8) | (str[i] & 0xff);
    //printf("(%s) -> %llx %llu\n",str,(long long)bits,(long long)bits);
    return(bits);
}

char *unstringify(char *str)
{
    int32_t i,j,n;
    if ( str == 0 )
        return(0);
    else if ( str[0] == 0 )
        return(str);
    n = (int32_t)strlen(str);
    if ( str[0] == '"' && str[n-1] == '"' )
        str[n-1] = 0, i = 1;
    else i = 0;
    for (j=0; str[i]!=0; i++)
    {
        if ( str[i] == '\\' && (str[i+1] == 't' || str[i+1] == 'n' || str[i+1] == 'b' || str[i+1] == 'r') )
            i++;
        else if ( str[i] == '\\' && str[i+1] == '"' )
            str[j++] = '"', i++;
        else str[j++] = str[i];
    }
    str[j] = 0;
    return(str);
}

void reverse_hexstr(char *str)
{
    int i,n;
    char *rev;
    n = (int32_t)strlen(str);
    rev = (char *)malloc(n + 1);
    for (i=0; i<n; i+=2)
    {
        rev[n-2-i] = str[i];
        rev[n-1-i] = str[i+1];
    }
    rev[n] = 0;
    strcpy(str,rev);
    free(rev);
}

int32_t nn_base64_decode (const char *in, size_t in_len,uint8_t *out, size_t out_len)
{
    uint32_t ii,io,rem,v; uint8_t ch;
    //  Unrolled lookup of ASCII code points. 0xFF represents a non-base64 valid character.
    const uint8_t DECODEMAP [256] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF,
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    
    for (io = 0, ii = 0, v = 0, rem = 0; ii < in_len; ii++) {
        if (isspace ((uint32_t)in [ii]))
            continue;
        
        if (in [ii] == '=')
            break;
        
        ch = DECODEMAP [(uint32_t)in [ii]];
        
        /*  Discard invalid characters as per RFC 2045. */
        if (ch == 0xFF)
            break;
        
        v = (v << 6) | ch;
        rem += 6;
        
        if (rem >= 8) {
            rem -= 8;
            if (io >= out_len)
                return -ENOBUFS;
            out [io++] = (v >> rem) & 255;
        }
    }
    if (rem >= 8) {
        rem -= 8;
        if (io >= out_len)
            return -ENOBUFS;
        out [io++] = (v >> rem) & 255;
    }
    return io;
}

int32_t nn_base64_encode (const uint8_t *in, size_t in_len,char *out, size_t out_len)
{
    uint32_t ii,io,rem,v; uint8_t ch;
    const uint8_t ENCODEMAP [64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
    
    for (io = 0, ii = 0, v = 0, rem = 0; ii < in_len; ii++) {
        ch = in [ii];
        v = (v << 8) | ch;
        rem += 8;
        while (rem >= 6) {
            rem -= 6;
            if (io >= out_len)
                return -ENOBUFS;
            out [io++] = ENCODEMAP [(v >> rem) & 63];
        }
    }
    
    if (rem) {
        v <<= (6 - rem);
        if (io >= out_len)
            return -ENOBUFS;
        out [io++] = ENCODEMAP [v & 63];
    }
    
    /*  Pad to a multiple of 3. */
    while (io & 3) {
        if (io >= out_len)
            return -ENOBUFS;
        out [io++] = '=';
    }
    
    if (io >= out_len)
        return -ENOBUFS;
    
    out [io] = '\0';
    
    return io;
}
/*
 NXT address converter,
 Ported from original javascript (nxtchg)
 To C by Jones
 */

int32_t gexp[] = {1, 2, 4, 8, 16, 5, 10, 20, 13, 26, 17, 7, 14, 28, 29, 31, 27, 19, 3, 6, 12, 24, 21, 15, 30, 25, 23, 11, 22, 9, 18, 1};
int32_t glog[] = {0, 0, 1, 18, 2, 5, 19, 11, 3, 29, 6, 27, 20, 8, 12, 23, 4, 10, 30, 17, 7, 22, 28, 26, 21, 25, 9, 16, 13, 14, 24, 15};
int32_t cwmap[] = {3, 2, 1, 0, 7, 6, 5, 4, 13, 14, 15, 16, 12, 8, 9, 10, 11};
char alphabet[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

int32_t gmult(int32_t a,int32_t b)
{
    if ( a == 0 || b == 0 )
        return 0;
    int32_t idx = (glog[a] + glog[b]) % 31;
    return gexp[idx];
}

int32_t letterval(char letter)
{
    int32_t ret = 0;
    if ( letter < '9' )
        ret = letter - '2';
    else
    {
        ret = letter - 'A' + 8;
        if ( letter > 'I' )
            ret--;
        if ( letter > 'O' )
            ret--;
    }
    return ret;
}

uint64_t RS_decode(char *rs)
{
    int32_t code[] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int32_t i,p = 4;
    if ( strncmp("NXT-",rs,4) != 0 )
        return(0);
    for (i=0; i<17; i++)
    {
        code[cwmap[i]] = letterval(rs[p]);
        p++;
        if ( rs[p] == '-' )
            p++;
    }
    uint64_t out = 0;
    for (i=12; i>=0; i--)
        out = out * 32 + code[i];
    return out;
}

int32_t RS_encode(char *rsaddr,uint64_t id)
{
    int32_t a,code[] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int32_t inp[32],out[32],i,j,fb,pos = 0,len = 0;
    char acc[64];
    rsaddr[0] = 0;
    memset(inp,0,sizeof(inp));
    memset(out,0,sizeof(out));
    memset(acc,0,sizeof(acc));
    expand_nxt64bits(acc,id);
    //sprintf(acc,"%llu",(long long)id);
    for (a=0; *(acc+a) != '\0'; a++)
        len++;
    if ( len == 20 && *acc != '1' )
    {
        printf("error (%s) doesnt start with 1",acc);
        return(-1);
    }
    for (i=0; i<len; i++)
        inp[i] = (int32_t)*(acc+i) - (int32_t)'0';
    int32_t divide = 0;
    int32_t newlen = 0;
    do // base 10 to base 32 conversion
    {
        divide = 0;
        newlen = 0;
        for (i=0; i<len; i++)
        {
            divide = divide * 10 + inp[i];
            if (divide >= 32)
            {
                inp[newlen++] = divide >> 5;
                divide &= 31;
            }
            else if ( newlen > 0 )
                inp[newlen++] = 0;
        }
        len = newlen;
        out[pos++] = divide;
    } while ( newlen != 0 );
    for (i=0; i<13; i++) // copy to code in reverse, pad with 0's
        code[i] = (--pos >= 0 ? out[i] : 0);
    int32_t p[] = {0, 0, 0, 0};
    for (i=12; i>=0; i--)
    {
        fb = code[i] ^ p[3];
        p[3] = p[2] ^ gmult(30, fb);
        p[2] = p[1] ^ gmult(6, fb);
        p[1] = p[0] ^ gmult(9, fb);
        p[0] = gmult(17, fb);
    }
    code[13] = p[0];
    code[14] = p[1];
    code[15] = p[2];
    code[16] = p[3];
    strcpy(rsaddr,"NXT-");
    j=4;
    for (i=0; i<17; i++)
    {
        rsaddr[j++] = alphabet[code[cwmap[i]]];
        if ( (j % 5) == 3 && j < 20 )
            rsaddr[j++] = '-';
    }
    rsaddr[j] = 0;
    return(0);
}

void calc_base64_encodestr(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len)
{
    nn_base64_encode(msg,len,hexstr,64);
}

void calc_base64_decodestr(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len)
{
    nn_base64_decode((void *)msg,len,(void *)hexstr,1024);
}

void sha256_sha256(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len)
{
    bits256_doublesha256(hexstr,msg,len);
}

void rmd160ofsha256(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len)
{
    uint8_t sha256[32];
    vcalc_sha256(0,sha256,(void *)msg,len);
    calc_rmd160(hexstr,buf,sha256,sizeof(sha256));
}

void calc_md2str(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len)
{
    bits128 x;
    calc_md2(hexstr,buf,msg,len);
    decode_hex(buf,sizeof(x),hexstr);
    memcpy(buf,x.bytes,sizeof(x));
}

void calc_md4str(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len)
{
    bits128 x;
    calc_md4(hexstr,buf,msg,len);
    decode_hex(buf,sizeof(x),hexstr);
    memcpy(buf,x.bytes,sizeof(x));
}

void calc_md5str(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len)
{
    bits128 x;
    calc_md5(hexstr,msg,len);
    decode_hex(buf,sizeof(x),hexstr);
    memcpy(buf,x.bytes,sizeof(x));
}

void calc_crc32str(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len)
{
    uint32_t crc = calc_crc32(0,msg,len);
    init_hexbytes_noT(hexstr,(uint8_t *)&crc,sizeof(crc));
}

void calc_NXTaddr(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len)
{
    uint8_t mysecret[32]; uint64_t nxt64bits;
    nxt64bits = conv_NXTpassword(mysecret,buf,msg,len);
    RS_encode(hexstr,nxt64bits);
}

void calc_curve25519_str(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len)
{
    bits256 x = curve25519(*(bits256 *)msg,curve25519_basepoint9());
    init_hexbytes_noT(hexstr,x.bytes,sizeof(x));
}
