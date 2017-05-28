
/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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
//
//  LP_bitcoin.c
//  marketmaker
//

int32_t iguana_rwnum(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp)
{
    int32_t i; uint64_t x;
    if ( rwflag == 0 )
    {
        x = 0;
        for (i=len-1; i>=0; i--)
        {
            x <<= 8;
            x |= serialized[i];
        }
        switch ( len )
        {
            case 1: *(uint8_t *)endianedp = (uint8_t)x; break;
            case 2: *(uint16_t *)endianedp = (uint16_t)x; break;
            case 4: *(uint32_t *)endianedp = (uint32_t)x; break;
            case 8: *(uint64_t *)endianedp = (uint64_t)x; break;
        }
    }
    else
    {
        x = 0;
        switch ( len )
        {
            case 1: x = *(uint8_t *)endianedp; break;
            case 2: x = *(uint16_t *)endianedp; break;
            case 4: x = *(uint32_t *)endianedp; break;
            case 8: x = *(uint64_t *)endianedp; break;
        }
        for (i=0; i<len; i++,x >>= 8)
            serialized[i] = (uint8_t)(x & 0xff);
    }
    return(len);
}

int32_t iguana_rwbignum(int32_t rwflag,uint8_t *serialized,int32_t len,uint8_t *endianedp)
{
    int32_t i;
    if ( rwflag == 0 )
    {
        for (i=0; i<len; i++)
            endianedp[i] = serialized[len - 1 - i];
    }
    else
    {
        for (i=0; i<len; i++)
            serialized[i] = endianedp[len - 1 - i];
    }
    return(len);
}

uint8_t *iguana_varint16(int32_t rwflag,uint8_t *serialized,uint16_t *varint16p)
{
    uint16_t n = 0;
    if ( rwflag == 0 )
    {
        n = *serialized++;
        n |= ((int32_t)*serialized++ << 8);
        *varint16p = n;
    }
    else
    {
        n = *varint16p;
        *serialized++ = (uint8_t)n & 0xff;
        *serialized++ = (uint8_t)(n >> 8) & 0xff;
    }
    return(serialized);
}

uint8_t *iguana_varint32(int32_t rwflag,uint8_t *serialized,uint16_t *varint16p)
{
    serialized = iguana_varint16(rwflag,serialized,varint16p);
    serialized = iguana_varint16(rwflag,serialized,&varint16p[1]);
    return(serialized);
}

uint8_t *iguana_varint64(int32_t rwflag,uint8_t *serialized,uint32_t *varint32p)
{
    serialized = iguana_varint32(rwflag,serialized,(uint16_t *)varint32p);
    serialized = iguana_varint32(rwflag,serialized,(uint16_t *)&varint32p[1]);
    return(serialized);
}

int32_t iguana_rwvarint(int32_t rwflag,uint8_t *serialized,uint64_t *varint64p)
{
    uint64_t n; int32_t vlen = 1;
    if ( rwflag == 0 )
    {
        *varint64p = 0;
        if ( (n= *serialized++) >= 0xfd )
        {
            if ( n == 0xfd )
            {
                n = 0;
                iguana_varint16(rwflag,serialized,(uint16_t *)&n);
                vlen += 2;
            }
            else if ( n == 0xfe )
            {
                n = 0;
                iguana_varint32(rwflag,serialized,(uint16_t *)&n);
                vlen += 4;
            }
            else if ( n == 0xff )
            {
                n = 0;
                iguana_varint64(rwflag,serialized,(uint32_t *)&n);
                vlen += 8;
            }
        }
        *varint64p = n;
    }
    else
    {
        n = *varint64p;
        if ( n < 0xfd )
            *serialized++ = (uint8_t)n;
        else if ( n <= 0xffff )
        {
            *serialized++ = 0xfd;
            iguana_varint16(rwflag,serialized,(uint16_t *)varint64p);
            vlen += 2;
        }
        else if ( n <= 0xffffffff )
        {
            *serialized++ = 0xfe;
            iguana_varint32(rwflag,serialized,(uint16_t *)varint64p);
            vlen += 4;
        }
        else
        {
            *serialized++ = 0xff;
            iguana_varint64(rwflag,serialized,(uint32_t *)varint64p);
            vlen += 8;
        }
    }
    return(vlen);
}

int32_t iguana_rwvarint32(int32_t rwflag,uint8_t *serialized,uint32_t *int32p)
{
    int32_t len; uint64_t x = 0;
    if ( rwflag != 0 )
        x = *int32p;
    len = iguana_rwvarint(rwflag,serialized,&x);
    if ( rwflag == 0 )
        *int32p = (int32_t)x;
    return(len);
}

int32_t iguana_rwvarstr(int32_t rwflag,uint8_t *serialized,int32_t maxlen,char *endianedp)
{
    int32_t vlen; uint64_t n;
    if ( rwflag == 0 )
    {
        vlen = iguana_rwvarint(rwflag,serialized,&n);
        memcpy(endianedp,&serialized[vlen],n);
        ((uint8_t *)endianedp)[n] = 0;
    }
    else
    {
        n = strlen(endianedp);
        if ( n > maxlen )
            n = maxlen;
        vlen = iguana_rwvarint(rwflag,serialized,&n);
        memcpy(&serialized[vlen],endianedp,n);
    }
    return((int32_t)(n + vlen));
}

int32_t iguana_rwmem(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp)
{
    if ( rwflag == 0 )
        memcpy(endianedp,serialized,len);
    else memcpy(serialized,endianedp,len);
    return(len);
}

const char *get_opname(uint8_t *stackitemsp,uint8_t *flagsp,int32_t *extralenp,enum opcodetype opcode)
{
    *extralenp = 0;
    switch ( opcode )
    {
            // push value
        case OP_0            : return "0";
        case OP_PUSHDATA1    : *extralenp = 1; return "OP_PUSHDATA1";
        case OP_PUSHDATA2    : *extralenp = 2; return "OP_PUSHDATA2";
        case OP_PUSHDATA4    : *flagsp = IGUANA_EXECUTIONILLEGAL; return "OP_PUSHDATA4";
        case OP_1NEGATE      : return "-1";
        case OP_RESERVED     : *flagsp = IGUANA_EXECUTIONILLEGAL; return "OP_RESERVED";
        case OP_1            : return "1";
        case OP_2            : return "2";
        case OP_3            : return "3";
        case OP_4            : return "4";
        case OP_5            : return "5";
        case OP_6            : return "6";
        case OP_7            : return "7";
        case OP_8            : return "8";
        case OP_9            : return "9";
        case OP_10           : return "10";
        case OP_11           : return "11";
        case OP_12           : return "12";
        case OP_13           : return "13";
        case OP_14           : return "14";
        case OP_15           : return "15";
        case OP_16           : return "16";
            
            // control
        case OP_NOP          : *flagsp = IGUANA_NOPFLAG; return "OP_NOP";
        case OP_VER          : *flagsp = IGUANA_EXECUTIONILLEGAL; return "OP_VER";
        case OP_IF           : *flagsp = IGUANA_CONTROLFLAG; *stackitemsp = 1; return "OP_IF";
        case OP_NOTIF        : *flagsp = IGUANA_CONTROLFLAG; *stackitemsp = 1; return "OP_NOTIF";
        case OP_VERIF        : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_VERIF";
        case OP_VERNOTIF     : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_VERNOTIF";
        case OP_ELSE         : *flagsp = IGUANA_CONTROLFLAG; return "OP_ELSE";
        case OP_ENDIF        : *flagsp = IGUANA_CONTROLFLAG; return "OP_ENDIF";
        case OP_VERIFY       : *flagsp = IGUANA_POSTVERIFY; return "OP_VERIFY";
        case OP_RETURN       : *flagsp = IGUANA_CONTROLFLAG; return "OP_RETURN";
            
            // stack ops
        case OP_TOALTSTACK   : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 1; return "OP_TOALTSTACK";
        case OP_FROMALTSTACK : *flagsp = IGUANA_STACKFLAG; return "OP_FROMALTSTACK";
        case OP_2DROP        : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 2; return "OP_2DROP";
        case OP_2DUP         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 2; return "OP_2DUP";
        case OP_3DUP         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 3; return "OP_3DUP";
        case OP_2OVER        : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 4; return "OP_2OVER";
        case OP_2ROT         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 6; return "OP_2ROT";
        case OP_2SWAP        : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 4; return "OP_2SWAP";
        case OP_IFDUP        : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 1; return "OP_IFDUP";
        case OP_DEPTH        : *flagsp = IGUANA_STACKFLAG; return "OP_DEPTH";
        case OP_DROP         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 1; return "OP_DROP";
        case OP_DUP          : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 1; return "OP_DUP";
        case OP_NIP          : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 2; return "OP_NIP";
        case OP_OVER         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 2; return "OP_OVER";
        case OP_PICK         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 1; return "OP_PICK";
        case OP_ROLL         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 1; return "OP_ROLL";
        case OP_ROT          : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 3; return "OP_ROT";
        case OP_SWAP         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 2; return "OP_SWAP";
        case OP_TUCK         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 2; return "OP_TUCK";
            
            // splice ops
        case OP_CAT          : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_CAT";
        case OP_SUBSTR       : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_SUBSTR";
        case OP_LEFT         : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_LEFT";
        case OP_RIGHT        : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_RIGHT";
        case OP_SIZE         : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_SIZE";
            
            // bit logic
        case OP_INVERT       : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_INVERT";
        case OP_AND          : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_AND";
        case OP_OR           : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_OR";
        case OP_XOR          : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_XOR";
        case OP_EQUAL        : *stackitemsp = 2; return "OP_EQUAL";
        case OP_EQUALVERIFY  : *stackitemsp = 2; *flagsp = IGUANA_POSTVERIFY; return "OP_EQUALVERIFY";
        case OP_RESERVED1    : *flagsp = IGUANA_EXECUTIONILLEGAL; return "OP_RESERVED1";
        case OP_RESERVED2    : *flagsp = IGUANA_EXECUTIONILLEGAL; return "OP_RESERVED2";
            
            // numeric
        case OP_1ADD         : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 1; return "OP_1ADD";
        case OP_1SUB         : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 1; return "OP_1SUB";
        case OP_2MUL         : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_2MUL";
        case OP_2DIV         : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_2DIV";
        case OP_NEGATE       : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 1; return "OP_NEGATE";
        case OP_ABS          : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 1; return "OP_ABS";
        case OP_NOT          : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 1; return "OP_NOT";
        case OP_0NOTEQUAL    : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 1; return "OP_0NOTEQUAL";
        case OP_ADD          : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_ADD";
        case OP_SUB          : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_SUB";
        case OP_MUL          : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_MUL";
        case OP_DIV          : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_DIV";
        case OP_MOD          : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_MOD";
        case OP_LSHIFT       : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_LSHIFT";
        case OP_RSHIFT       : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_RSHIFT";
        case OP_BOOLAND      : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_BOOLAND";
        case OP_BOOLOR       : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_BOOLOR";
        case OP_NUMEQUAL     : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_NUMEQUAL";
        case OP_NUMEQUALVERIFY: *flagsp = IGUANA_MATHFLAG | IGUANA_POSTVERIFY; *stackitemsp = 2; return "OP_NUMEQUALVERIFY";
        case OP_NUMNOTEQUAL  : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_NUMNOTEQUAL";
        case OP_LESSTHAN     : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_LESSTHAN";
        case OP_GREATERTHAN  : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_GREATERTHAN";
        case OP_LESSTHANOREQUAL: *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_LESSTHANOREQUAL";
        case OP_GREATERTHANOREQUAL: *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_GREATERTHANOREQUAL";
        case OP_MIN          : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_MIN";
        case OP_MAX          : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_MAX";
        case OP_WITHIN       : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 3; return "OP_WITHIN";
            
            // crypto
        case OP_RIPEMD160    : *stackitemsp = 1; *flagsp = IGUANA_CRYPTOFLAG; return "OP_RIPEMD160";
        case OP_SHA1         : *stackitemsp = 1; *flagsp = IGUANA_CRYPTOFLAG; return "OP_SHA1";
        case OP_SHA256       : *stackitemsp = 1; *flagsp = IGUANA_CRYPTOFLAG; return "OP_SHA256";
        case OP_HASH160      : *stackitemsp = 1; *flagsp = IGUANA_CRYPTOFLAG; return "OP_HASH160";
        case OP_HASH256      : *stackitemsp = 1; *flagsp = IGUANA_CRYPTOFLAG; return "OP_HASH256";
        case OP_CODESEPARATOR: return "OP_CODESEPARATOR";
        case OP_CHECKSIG     : *stackitemsp = 2; *flagsp = IGUANA_CRYPTOFLAG; return "OP_CHECKSIG";
        case OP_CHECKSIGVERIFY: *stackitemsp = 2; *flagsp = IGUANA_CRYPTOFLAG | IGUANA_POSTVERIFY; return "OP_CHECKSIGVERIFY";
        case OP_CHECKMULTISIG:       *flagsp = IGUANA_CRYPTOFLAG; return "OP_CHECKMULTISIG";
        case OP_CHECKMULTISIGVERIFY: *flagsp = IGUANA_CRYPTOFLAG | IGUANA_POSTVERIFY; return "OP_CHECKMULTISIGVERIFY";
        case OP_COMBINEPUBKEYS:     *flagsp = IGUANA_CRYPTOFLAG; return "OP_COMBINEPUBKEYS";
        case OP_CHECKSCHNORR:  *stackitemsp = 3; *flagsp = IGUANA_CRYPTOFLAG; return "OP_CHECKSCHNORR";
        case OP_CHECKSCHNORRVERIFY: *stackitemsp = 3; *flagsp = IGUANA_CRYPTOFLAG | IGUANA_POSTVERIFY; return "OP_CHECKSCHNORRVERIFY";
        case OP_CHECKPRIVATEKEY: *stackitemsp = 2; *flagsp = IGUANA_CRYPTOFLAG; return "OP_CHECKPRIVATEKEY";
        case OP_CHECKPRIVATEKEYVERIFY: *stackitemsp = 2; *flagsp = IGUANA_CRYPTOFLAG | IGUANA_POSTVERIFY; return "OP_CHECKPRIVATEKEYVERIFY";
            
            // expanson
        case OP_NOP1         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP1";
        case OP_CHECKLOCKTIMEVERIFY: *stackitemsp = 1; return "OP_CHECKLOCKTIMEVERIFY";
        case OP_CHECKSEQUENCEVERIFY: *stackitemsp = 1; return "OP_CHECKSEQUENCEVERIFY";
        case OP_NOP4         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP4";
        case OP_NOP5         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP5";
        case OP_NOP6         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP6";
        case OP_NOP7         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP7";
        case OP_NOP8         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP8";
        case OP_NOP9         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP9";
        case OP_NOP10        : *flagsp = IGUANA_NOPFLAG; return "OP_NOP10";
            
        case OP_INVALIDOPCODE: return "OP_INVALIDOPCODE";
        default: return "OP_UNKNOWN";
    }
}

void iguana_optableinit()
{
    int32_t i,extralen; uint8_t stackitems,flags; char *opname; struct bitcoin_opcode *op;
    if ( OPTABLE == 0 )
    {
        for (i=0; i<0x100; i++)
            OPCODES[i] = "OP_UNKNOWN";
        for (i=0; i<0x100; i++)
        {
            extralen = stackitems = flags = 0;
            opname = (char *)get_opname(&stackitems,&flags,&extralen,i);
            if ( strcmp("OP_UNKNOWN",opname) != 0 )
            {
                op = calloc(1,sizeof(*op));
                HASH_ADD_KEYPTR(hh,OPTABLE,opname,strlen(opname),op);
                //printf("{%-16s %02x} ",opname,i);
                op->opcode = i;
                op->flags = flags;
                op->stackitems = stackitems;
                op->extralen = extralen;
                OPCODES[i] = (char *)op->hh.key;
                OPCODELENS[i] = (int32_t)strlen(OPCODES[i]);
            }
        }
        //printf("bitcoin opcodes\n");
    }
}

int32_t iguana_expandscript(char *asmstr,int32_t maxlen,uint8_t *script,int32_t scriptlen)
{
    int32_t len,n,j,i = 0; uint8_t opcode; uint32_t val,extraflag;
    iguana_optableinit();
    asmstr[0] = len = 0;
    while ( i < scriptlen )
    {
        val = extraflag = 0;
        opcode = script[i++];
        if ( opcode > 0 && opcode < 76 )
        {
            for (j=0; j<opcode; j++)
                sprintf(&asmstr[len],"%02x",script[i++]), len += 2;
        }
        else if ( opcode >= IGUANA_OP_1 && opcode <= IGUANA_OP_16 )
        {
            sprintf(&asmstr[len],"%d",opcode - IGUANA_OP_1 + 1);
            len += strlen(&asmstr[len]);
        }
        else if ( opcode == IGUANA_OP_0 )
        {
            strcpy(&asmstr[len],"OP_FALSE");
            len += 8;
        }
        else if ( opcode == IGUANA_OP_1NEGATE )
        {
            asmstr[len++] = '-';
            asmstr[len++] = '1';
        }
        else
        {
            //printf("dest.%p <- %p %02x\n",&asmstr[len],OPCODES[opcode],opcode);
            strcpy(&asmstr[len],OPCODES[opcode]);
            len += OPCODELENS[opcode];
        }
        if ( i < scriptlen )
            asmstr[len++] = ' ';
        if ( opcode == IGUANA_OP_PUSHDATA1 )
        {
            n = script[i++];
            for (j=0; j<n; j++)
                sprintf(&asmstr[len],"%02x",script[i++]), len += 2;
            extraflag = 1;
        }
        else if ( opcode == IGUANA_OP_PUSHDATA2 )
        {
            n = script[i++];
            n = (n << 8) | script[i++];
            if ( n+len < maxlen )
            {
                for (j=0; j<n; j++)
                    sprintf(&asmstr[len],"%02x",script[i++]), len += 2;
                extraflag = 1;
            } else return(-1);
        }
        else if ( opcode == IGUANA_OP_PUSHDATA4 )
        {
            n = script[i++];
            n = (n << 8) | script[i++];
            n = (n << 8) | script[i++];
            n = (n << 8) | script[i++];
            if ( n < IGUANA_MAXSCRIPTSIZE )
            {
                for (j=0; j<n; j++)
                    sprintf(&asmstr[len],"%02x",script[i++]), len += 2;
                extraflag = 1;
            } else return(-1);
        }
        if ( extraflag != 0 && i < scriptlen )
            asmstr[len++] = ' ';
    }
    asmstr[len] = 0;
    return(len);
}

/*void calc_rmd160_sha256(uint8_t rmd160[20],uint8_t *data,int32_t datalen)
{
    bits256 hash;
    vcalc_sha256(0,hash.bytes,data,datalen);
    calc_rmd160(0,rmd160,hash.bytes,sizeof(hash));
}*/

void revcalc_rmd160_sha256(uint8_t rmd160[20],bits256 revhash)
{
    bits256 hash; int32_t i;
    for (i=0; i<32; i++)
        hash.bytes[i] = revhash.bytes[31-i];
    calc_rmd160_sha256(rmd160,hash.bytes,sizeof(hash));
}

bits256 revcalc_sha256(bits256 revhash)
{
    bits256 hash,dest; int32_t i;
    for (i=0; i<32; i++)
        hash.bytes[i] = revhash.bytes[31-i];
    vcalc_sha256(0,dest.bytes,hash.bytes,sizeof(hash));
    return(dest);
}

int32_t bitcoin_pubkeylen(const uint8_t *pubkey)
{
    if ( pubkey[0] == 2 || pubkey[0] == 3 )
        return(33);
    else if ( pubkey[0] == 4 )
        return(65);
    else
    {
        //printf("illegal pubkey.[%02x] %llx\n",pubkey[0],*(long long *)pubkey);
        return(-1);
    }
}

int32_t bitcoin_pubkeyspend(uint8_t *script,int32_t n,uint8_t pubkey[66])
{
    int32_t plen = bitcoin_pubkeylen(pubkey);
    script[n++] = plen;
    memcpy(&script[n],pubkey,plen);
    n += plen;
    script[n++] = SCRIPT_OP_CHECKSIG;
    return(n);
}

int32_t bitcoin_p2shspend(uint8_t *script,int32_t n,uint8_t rmd160[20])
{
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14; memcpy(&script[n],rmd160,0x14); n += 0x14;
    script[n++] = SCRIPT_OP_EQUAL;
    return(n);
}

int32_t bitcoin_secret160verify(uint8_t *script,int32_t n,uint8_t secret160[20])
{
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14;
    memcpy(&script[n],secret160,0x14);
    n += 0x14;
    script[n++] = SCRIPT_OP_EQUALVERIFY;
    return(n);
}

int32_t bitcoin_secret256spend(uint8_t *script,int32_t n,bits256 secret)
{
    script[n++] = SCRIPT_OP_SHA256;
    script[n++] = 0x20;
    memcpy(&script[n],secret.bytes,0x20);
    n += 0x20;
    script[n++] = SCRIPT_OP_EQUAL;
    return(n);
}

// OP_DUP OP_HASH160 <hash of pubkey> OP_EQUALVERIFY OP_CHECKSIG
int32_t bitcoin_standardspend(uint8_t *script,int32_t n,uint8_t rmd160[20])
{
    script[n++] = SCRIPT_OP_DUP;
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14; memcpy(&script[n],rmd160,0x14); n += 0x14;
    script[n++] = SCRIPT_OP_EQUALVERIFY;
    script[n++] = SCRIPT_OP_CHECKSIG;
    return(n);
}

int32_t bitcoin_checklocktimeverify(uint8_t *script,int32_t n,uint32_t locktime)
{
    script[n++] = 4;
    script[n++] = locktime & 0xff, locktime >>= 8;
    script[n++] = locktime & 0xff, locktime >>= 8;
    script[n++] = locktime & 0xff, locktime >>= 8;
    script[n++] = locktime & 0xff;
    script[n++] = SCRIPT_OP_CHECKLOCKTIMEVERIFY;
    script[n++] = SCRIPT_OP_DROP;
    return(n);
}

int32_t bitcoin_timelockspend(uint8_t *script,int32_t n,uint8_t rmd160[20],uint32_t timestamp)
{
    n = bitcoin_checklocktimeverify(script,n,timestamp);
    n = bitcoin_standardspend(script,n,rmd160);
    return(n);
}

int32_t bitcoin_MofNspendscript(uint8_t p2sh_rmd160[20],uint8_t *script,int32_t n,const struct vin_info *vp)
{
    int32_t i,plen;
    script[n++] = 0x50 + vp->M;
    for (i=0; i<vp->N; i++)
    {
        if ( (plen= bitcoin_pubkeylen(vp->signers[i].pubkey)) < 0 )
            return(-1);
        script[n++] = plen;
        memcpy(&script[n],vp->signers[i].pubkey,plen);
        n += plen;
    }
    script[n++] = 0x50 + vp->N;
    script[n++] = SCRIPT_OP_CHECKMULTISIG;
    calc_rmd160_sha256(p2sh_rmd160,script,n);
    return(n);
}

int32_t bitcoin_p2shscript(uint8_t *script,int32_t n,const uint8_t *p2shscript,const int32_t p2shlen)
{
    if ( p2shlen >= 0xfd )
    {
        script[n++] = 0x4d;
        script[n++] = (p2shlen & 0xff);
        script[n++] = ((p2shlen >> 8) & 0xff);
    }
    else if ( p2shlen > 76 )
    {
        script[n++] = 0x4c;
        script[n++] = p2shlen;
    } else script[n++] = p2shlen;
    memcpy(&script[n],p2shscript,p2shlen), n += p2shlen;
    return(n);
}

char *bitcoind_passthru(char *coinstr,char *serverport,char *userpass,char *method,char *params)
{
    return(bitcoind_RPC(0,coinstr,serverport,userpass,method,params));
}

int32_t bitcoin_addr2rmd160(uint8_t *addrtypep,uint8_t rmd160[20],char *coinaddr)
{
    bits256 hash; uint8_t *buf,_buf[25]; int32_t len;
    memset(rmd160,0,20);
    *addrtypep = 0;
    buf = _buf;
    if ( (len= bitcoin_base58decode(buf,coinaddr)) >= 4 )
    {
        // validate with trailing hash, then remove hash
        hash = bits256_doublesha256(0,buf,21);
        *addrtypep = *buf;
        memcpy(rmd160,buf+1,20);
        if ( (buf[21]&0xff) == hash.bytes[31] && (buf[22]&0xff) == hash.bytes[30] &&(buf[23]&0xff) == hash.bytes[29] && (buf[24]&0xff) == hash.bytes[28] )
        {
            //printf("coinaddr.(%s) valid checksum addrtype.%02x\n",coinaddr,*addrtypep);
            return(20);
        }
        else
        {
            int32_t i;
            if ( len > 20 )
            {
                hash = bits256_doublesha256(0,buf,len);
            }
            for (i=0; i<len; i++)
                printf("%02x ",buf[i]);
            char str[65]; printf("\nhex checkhash.(%s) len.%d mismatch %02x %02x %02x %02x vs %02x %02x %02x %02x (%s)\n",coinaddr,len,buf[len-1]&0xff,buf[len-2]&0xff,buf[len-3]&0xff,buf[len-4]&0xff,hash.bytes[31],hash.bytes[30],hash.bytes[29],hash.bytes[28],bits256_str(str,hash));
        }
    }
    return(0);
}

char *bitcoin_address(char *coinaddr,uint8_t addrtype,uint8_t *pubkey_or_rmd160,int32_t len)
{
    int32_t i; uint8_t data[25]; bits256 hash;// char checkaddr[65];
    if ( len != 20 )
        calc_rmd160_sha256(data+1,pubkey_or_rmd160,len);
    else memcpy(data+1,pubkey_or_rmd160,20);
    //btc_convrmd160(checkaddr,addrtype,data+1);
    data[0] = addrtype;
    hash = bits256_doublesha256(0,data,21);
    for (i=0; i<4; i++)
        data[21+i] = hash.bytes[31-i];
    if ( (coinaddr= bitcoin_base58encode(coinaddr,data,25)) != 0 )
    {
        //uint8_t checktype,rmd160[20];
        //bitcoin_addr2rmd160(&checktype,rmd160,coinaddr);
        //if ( strcmp(checkaddr,coinaddr) != 0 )
        //    printf("checkaddr.(%s) vs coinaddr.(%s) %02x vs [%02x] memcmp.%d\n",checkaddr,coinaddr,addrtype,checktype,memcmp(rmd160,data+1,20));
    }
    return(coinaddr);
}

int32_t bitcoin_validaddress(uint8_t pubtype,uint8_t p2shtype,char *coinaddr)
{
    uint8_t rmd160[20],addrtype; char checkaddr[128];
    if ( coinaddr == 0 || coinaddr[0] == 0 )
        return(-1);
    else if ( bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr) < 0 )
        return(-1);
    else if ( addrtype != pubtype && addrtype != p2shtype )
        return(-1);
    else if ( bitcoin_address(checkaddr,addrtype,rmd160,sizeof(rmd160)) != checkaddr || strcmp(checkaddr,coinaddr) != 0 )
        return(-1);
    return(0);
}

int32_t base58encode_checkbuf(uint8_t addrtype,uint8_t *data,int32_t data_len)
{
    uint8_t i; bits256 hash;
    data[0] = addrtype;
    //for (i=0; i<data_len+1; i++)
    //    printf("%02x",data[i]);
    //printf(" extpriv -> ");
    hash = bits256_doublesha256(0,data,(int32_t)data_len+1);
    //for (i=0; i<32; i++)
    //    printf("%02x",hash.bytes[i]);
    //printf(" checkhash\n");
    for (i=0; i<4; i++)
        data[data_len+i+1] = hash.bytes[31-i];
    return(data_len + 5);
}

int32_t bitcoin_wif2priv(uint8_t *addrtypep,bits256 *privkeyp,char *wifstr)
{
    int32_t len = -1; bits256 hash; uint8_t buf[256];
    memset(buf,0,sizeof(buf));
    if ( (len= bitcoin_base58decode(buf,wifstr)) >= 4 )
    {
        // validate with trailing hash, then remove hash
        if ( len < 38 )
            len = 38;
        hash = bits256_doublesha256(0,buf,len - 4);
        *addrtypep = *buf;
        memcpy(privkeyp,buf+1,32);
        if ( (buf[len - 4]&0xff) == hash.bytes[31] && (buf[len - 3]&0xff) == hash.bytes[30] &&(buf[len - 2]&0xff) == hash.bytes[29] && (buf[len - 1]&0xff) == hash.bytes[28] )
        {
            //int32_t i; for (i=0; i<len; i++)
            //    printf("%02x ",buf[i]);
            //printf(" buf, hash.%02x %02x %02x %02x ",hash.bytes[28],hash.bytes[29],hash.bytes[30],hash.bytes[31]);
            //printf("wifstr.(%s) valid len.%d\n",wifstr,len);
            return(32);
        }
        else
        {
            int32_t i; for (i=0; i<len; i++)
                printf("%02x ",buf[i]);
            printf(" buf, hash.%02x %02x %02x %02x\n",hash.bytes[28],hash.bytes[29],hash.bytes[30],hash.bytes[31]);
        }
    }
    return(-1);
}

int32_t bitcoin_priv2wif(char *wifstr,bits256 privkey,uint8_t addrtype)
{
    uint8_t data[128]; int32_t len = 32;
    memcpy(data+1,privkey.bytes,sizeof(privkey));
    data[1 + len++] = 1;
    len = base58encode_checkbuf(addrtype,data,len);
    if ( bitcoin_base58encode(wifstr,data,len) == 0 )
        return(-1);
    if ( 1 )
    {
        uint8_t checktype; bits256 checkpriv; char str[65],str2[65];
        if ( bitcoin_wif2priv(&checktype,&checkpriv,wifstr) == sizeof(bits256) )
        {
            if ( checktype != addrtype || bits256_cmp(checkpriv,privkey) != 0 )
                printf("(%s) -> wif.(%s) addrtype.%02x -> %02x (%s)\n",bits256_str(str,privkey),wifstr,addrtype,checktype,bits256_str(str2,checkpriv));
        }
    }
    return((int32_t)strlen(wifstr));
}

int32_t bitcoin_priv2wiflong(char *wifstr,bits256 privkey,uint8_t addrtype)
{
    uint8_t data[128]; int32_t len = 32;
    memcpy(data+1,privkey.bytes,sizeof(privkey));
    len = base58encode_checkbuf(addrtype,data,len);
    if ( bitcoin_base58encode(wifstr,data,len) == 0 )
        return(-1);
    if ( 1 )
    {
        uint8_t checktype; bits256 checkpriv; char str[65],str2[65];
        if ( bitcoin_wif2priv(&checktype,&checkpriv,wifstr) == sizeof(bits256) )
        {
            if ( checktype != addrtype || bits256_cmp(checkpriv,privkey) != 0 )
                printf("(%s) -> wif.(%s) addrtype.%02x -> %02x (%s)\n",bits256_str(str,privkey),wifstr,addrtype,checktype,bits256_str(str2,checkpriv));
        }
    }
    return((int32_t)strlen(wifstr));
}

char *_setVsigner(uint8_t pubtype,struct vin_info *V,int32_t ind,char *pubstr,char *wifstr)
{
    uint8_t addrtype;
    decode_hex(V->signers[ind].pubkey,(int32_t)strlen(pubstr)/2,pubstr);
    bitcoin_wif2priv(&addrtype,&V->signers[ind].privkey,wifstr);
    if ( addrtype != pubtype )
        return(clonestr("{\"error\":\"invalid wifA\"}"));
    else return(0);
}

uint8_t iguana_addrtype(uint8_t pubtype,uint8_t p2shtype,uint8_t script_type)
{
    if ( script_type == IGUANA_SCRIPT_76A988AC || script_type == IGUANA_SCRIPT_AC || script_type == IGUANA_SCRIPT_76AC )
        return(pubtype);
    else
    {
        //printf("P2SH type.%d\n",script_type);
        return(p2shtype);
    }
}

int32_t iguana_scriptgen(uint8_t pubtype,uint8_t p2shtype,int32_t *Mp,int32_t *nump,char *coinaddr,uint8_t *script,char *asmstr,uint8_t rmd160[20],uint8_t type,const struct vin_info *vp,int32_t txi)
{
    uint8_t addrtype; char rmd160str[41],pubkeystr[256]; int32_t plen,i,m,n,flag = 0,scriptlen = 0;
    m = n = 0;
    if ( asmstr != 0 )
        asmstr[0] = 0;
    addrtype = iguana_addrtype(pubtype,p2shtype,type);
    if ( type == IGUANA_SCRIPT_76A988AC || type == IGUANA_SCRIPT_AC || type == IGUANA_SCRIPT_76AC || type == IGUANA_SCRIPT_P2SH )
    {
        init_hexbytes_noT(rmd160str,rmd160,20);
        bitcoin_address(coinaddr,addrtype,rmd160,20);
    }
    switch ( type )
    {
        case IGUANA_SCRIPT_NULL:
            if ( asmstr != 0 )
                strcpy(asmstr,txi == 0 ? "coinbase " : "PoSbase ");
            flag++;
            coinaddr[0] = 0;
            break;
        case IGUANA_SCRIPT_76AC:
        case IGUANA_SCRIPT_AC:
            if ( (plen= bitcoin_pubkeylen(vp->signers[0].pubkey)) < 0 )
                return(0);
            init_hexbytes_noT(pubkeystr,(uint8_t *)vp->signers[0].pubkey,plen);
            if ( asmstr != 0 )
            {
                if ( type == IGUANA_SCRIPT_76AC )
                    strcpy(asmstr,"OP_DUP ");
                sprintf(asmstr + strlen(asmstr),"%s OP_CHECKSIG // %s",pubkeystr,coinaddr);
            }
            if ( type == IGUANA_SCRIPT_76AC )
                script[scriptlen++] = 0x76;
            scriptlen = bitcoin_pubkeyspend(script,scriptlen,(uint8_t *)vp->signers[0].pubkey);
            //printf("[%02x] type.%d scriptlen.%d\n",vp->signers[0].pubkey[0],type,scriptlen);
            break;
        case IGUANA_SCRIPT_76A988AC:
            if ( asmstr != 0 )
                sprintf(asmstr,"OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG // %s",rmd160str,coinaddr);
            scriptlen = bitcoin_standardspend(script,0,rmd160);
            break;
        case IGUANA_SCRIPT_P2SH:
            if ( asmstr != 0 )
                sprintf(asmstr,"OP_HASH160 %s OP_EQUAL // %s",rmd160str,coinaddr);
            scriptlen = bitcoin_p2shspend(script,0,rmd160);
            break;
        case IGUANA_SCRIPT_OPRETURN:
            if ( asmstr != 0 )
                strcpy(asmstr,"OP_RETURN ");
            bitcoin_address(coinaddr,addrtype,(uint8_t *)&vp->spendscript[0],vp->spendlen);
            flag++;
            break;
        case IGUANA_SCRIPT_3of3: m = 3, n = 3; break;
        case IGUANA_SCRIPT_2of3: m = 2, n = 3; break;
        case IGUANA_SCRIPT_1of3: m = 1, n = 3; break;
        case IGUANA_SCRIPT_2of2: m = 2, n = 2; break;
        case IGUANA_SCRIPT_1of2: m = 1, n = 2; break;
        case IGUANA_SCRIPT_1of1: m = 1, n = 1; break;
        case IGUANA_SCRIPT_MSIG: m = vp->M, n = vp->N; break;
        case IGUANA_SCRIPT_DATA:
            if ( asmstr != 0 )
                strcpy(asmstr,"DATA ONLY");
            bitcoin_address(coinaddr,addrtype,(uint8_t *)&vp->spendscript[0],vp->spendlen);
            flag++;
            break;
        case IGUANA_SCRIPT_STRANGE:
            if ( asmstr != 0 )
                strcpy(asmstr,"STRANGE SCRIPT ");
            bitcoin_address(coinaddr,addrtype,(uint8_t *)&vp->spendscript[0],vp->spendlen);
            flag++;
            break;
        default: break;//printf("unexpected script type.%d\n",type); break;
    }
    if ( n > 0 )
    {
        scriptlen = bitcoin_MofNspendscript(rmd160,script,0,vp);
        bitcoin_address(coinaddr,p2shtype,script,scriptlen);
        if ( asmstr != 0 )
        {
            sprintf(asmstr,"%d ",m);
            for (i=0; i<n; i++)
            {
                if ( (plen= bitcoin_pubkeylen(vp->signers[i].pubkey)) > 0 )
                {
                    init_hexbytes_noT(asmstr + strlen(asmstr),(uint8_t *)vp->signers[i].pubkey,plen);
                    if ( asmstr != 0 )
                        strcat(asmstr," ");
                }
                else if ( asmstr != 0 )
                    strcat(asmstr,"NOPUBKEY ");
                sprintf(asmstr + strlen(asmstr),"%d // M.%d of N.%d [",n,m,n);
                for (i=0; i<n; i++)
                    sprintf(asmstr + strlen(asmstr),"%s%s",vp->signers[i].coinaddr,i<n-1?" ":"");
            }
            strcat(asmstr,"]\n");
        }
    }
    if ( flag != 0 && asmstr != 0 && vp->spendlen > 0 )
        init_hexbytes_noT(asmstr + strlen(asmstr),(uint8_t *)vp->spendscript,vp->spendlen);
    *Mp = m, *nump = n;
    return(scriptlen);
}

int32_t bitcoin_scriptget(uint8_t pubtype,uint8_t p2shtype,int32_t *hashtypep,uint32_t *sigsizep,uint32_t *pubkeysizep,uint8_t **userdatap,uint32_t *userdatalenp,struct vin_info *vp,uint8_t *scriptsig,int32_t len,int32_t spendtype)
{
    int32_t j,n,siglen,plen; uint8_t *p2shscript;
    j = n = 0;
    *userdatap = 0;
    *userdatalenp = *pubkeysizep = *sigsizep = 0;
    *hashtypep = SIGHASH_ALL;
    while ( (siglen= scriptsig[n]) >= 70 && siglen <= 73 && n+siglen < len && j < 16 )
    {
        vp->signers[j].siglen = siglen;
        memcpy(vp->signers[j].sig,&scriptsig[n+1],siglen);
        if ( j == 0 )
            *hashtypep = vp->signers[j].sig[siglen-1];
        else if ( vp->signers[j].sig[siglen-1] != *hashtypep )
        {
            //printf("SIGHASH.%d  mismatch %d vs %d\n",j,vp->signers[j].sig[siglen-1],*hashtypep);
            break;
        }
        (*sigsizep) += siglen;
        //printf("sigsize %d [%02x]\n",*sigsizep,vp->signers[j].sig[siglen-1]);
        n += (siglen + 1);
        j++;
        if ( spendtype == 0 && j > 1 )
            spendtype = IGUANA_SCRIPT_MSIG;
    }
    vp->numsigs = j;
    vp->type = spendtype;
    if ( j == 0 )
    {
        //*userdatalenp = len;
        vp->spendlen = len;
        return(vp->spendlen);
    }
    j = 0;
    while ( ((plen= scriptsig[n]) == 33 || plen == 65) && j < 16 && plen+n <= len )
    {
        memcpy(vp->signers[j].pubkey,&scriptsig[n+1],plen);
        calc_rmd160_sha256(vp->signers[j].rmd160,vp->signers[j].pubkey,plen);
        if ( j == 0 )
            memcpy(vp->rmd160,vp->signers[j].rmd160,20);
        n += (plen + 1);
        (*pubkeysizep) += plen;
        j++;
    }
    vp->numpubkeys = j;
    *userdatap = &scriptsig[n];
    if ( len > n )
        *userdatalenp = (len - n);
    p2shscript = 0;
    while ( n < len )
    {
        if ( n+2 < len && (scriptsig[n] == 0x4c || scriptsig[n] == 0x4d) )
        {
            if ( scriptsig[n] == 0x4c )
                vp->p2shlen = scriptsig[n+1], n += 2;
            else vp->p2shlen = ((uint32_t)scriptsig[n+1] + ((uint32_t)scriptsig[n+2] << 8)), n += 3;
            //printf("p2sh opcode.%02x %02x %02x scriptlen.%d\n",scriptsig[n],scriptsig[n+1],scriptsig[n+2],vp->p2shlen);
            if ( vp->p2shlen < IGUANA_MAXSCRIPTSIZE && n+vp->p2shlen <= len )
            {
                p2shscript = &scriptsig[n];
                memcpy(vp->p2shscript,&scriptsig[n],vp->p2shlen);
                n += vp->p2shlen;
                vp->type = IGUANA_SCRIPT_P2SH;
            } else vp->p2shlen = 0;
        }
    }
    if ( *userdatap == p2shscript )
        *userdatap = 0;
    /*if ( len == 0 )
     {
     //  txid.(eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2).v1
     decode_hex(vp->rmd160,20,"010966776006953d5567439e5e39f86a0d273bee");//3564a74f9ddb4372301c49154605573d7d1a88fe");
     vp->type = IGUANA_SCRIPT_76A988AC;
     }*/
    vp->spendlen = iguana_scriptgen(pubtype,p2shtype,&vp->M,&vp->N,vp->coinaddr,vp->spendscript,0,vp->rmd160,vp->type,(const struct vin_info *)vp,vp->vin.prev_vout);
    //printf("type.%d asmstr.(%s) spendlen.%d\n",vp->type,asmstr,vp->spendlen);
    return(vp->spendlen);
}

int32_t _iguana_calcrmd160(uint8_t pubtype,uint8_t p2shtype,struct vin_info *vp)
{
    static uint8_t zero_rmd160[20];
    char hexstr[8192]; uint8_t *script,type; int32_t i,n,m,plen;
    if ( vp->N == 0 )
        vp->N = 1;
    if ( vp->M == 0 )
        vp->M = 1;
    type = IGUANA_SCRIPT_STRANGE;
    init_hexbytes_noT(hexstr,vp->spendscript,vp->spendlen);
    //char str[65]; printf("script.(%s).%d in %s len.%d plen.%d spendlen.%d cmp.%d\n",hexstr,vp->spendlen,bits256_str(str,vp->vin.prev_hash),vp->spendlen,bitcoin_pubkeylen(&vp->spendscript[1]),vp->spendlen,vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKSIG);
    if ( vp->spendlen == 0 )
    {
        if ( zero_rmd160[0] == 0 )
        {
            calc_rmd160_sha256(zero_rmd160,vp->spendscript,vp->spendlen);
            //vcalc_sha256(0,sha256,vp->spendscript,vp->spendlen); // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            //calc_rmd160(0,zero_rmd160,sha256,sizeof(sha256)); // b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
            init_hexbytes_noT(hexstr,zero_rmd160,20);
        }
        memcpy(vp->rmd160,zero_rmd160,sizeof(zero_rmd160));
        return(IGUANA_SCRIPT_NULL);
    }
    else if ( vp->spendscript[0] == SCRIPT_OP_RETURN )
        type = IGUANA_SCRIPT_OPRETURN;
    else if ( vp->spendscript[0] == SCRIPT_OP_DUP && vp->spendscript[1] == SCRIPT_OP_HASH160 && vp->spendscript[2] == 20 && vp->spendscript[vp->spendscript[2]+3] == SCRIPT_OP_EQUALVERIFY && vp->spendscript[vp->spendscript[2]+4] == SCRIPT_OP_CHECKSIG )
    {
        //printf("IGUANA_SCRIPT_76A988AC plen.%d vs %d vp->spendlen\n",vp->spendscript[2]+4,vp->spendlen);
        // 76a9145f69cb73016264270dae9f65c51f60d0e4d6fd4488ac
        memcpy(vp->rmd160,&vp->spendscript[3],20);
        if ( (plen= vp->spendscript[2]+5) != vp->spendlen )
        {
            return(IGUANA_SCRIPT_STRANGE);
            /*while ( plen < vp->spendlen )
             if ( vp->spendscript[plen++] != 0x61 ) // nop
             return(IGUANA_SCRIPT_STRANGE);*/
        }
        return(IGUANA_SCRIPT_76A988AC);
    }
    // 21035f1321ed17d387e4433b2fa229c53616057964af065f98bfcae2233c5108055eac
    else if ( vp->spendscript[0] == SCRIPT_OP_DUP && (plen= bitcoin_pubkeylen(&vp->spendscript[2])) > 0 && vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKSIG && vp->spendscript[0] == plen && vp->spendlen == plen+3 )
    {
        memcpy(vp->signers[0].pubkey,&vp->spendscript[2],plen);
        calc_rmd160_sha256(vp->rmd160,vp->signers[0].pubkey,plen);
        //printf("found IGUANA_SCRIPT_76AC\n");
        return(IGUANA_SCRIPT_76AC);
    }
    else if ( (plen= bitcoin_pubkeylen(&vp->spendscript[1])) > 0 && vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKSIG && vp->spendscript[0] == plen && vp->spendlen == plen+2 )
    {
        memcpy(vp->signers[0].pubkey,&vp->spendscript[1],plen);
        calc_rmd160_sha256(vp->rmd160,vp->signers[0].pubkey,plen);
        //printf("found IGUANA_SCRIPT_AC\n");
        return(IGUANA_SCRIPT_AC);
    }
    else if ( vp->spendscript[0] == SCRIPT_OP_HASH160 && vp->spendscript[1] == 0x14 && vp->spendlen == 23 && vp->spendscript[22] == SCRIPT_OP_EQUAL )
    {
        memcpy(vp->rmd160,vp->spendscript+2,20);
        return(IGUANA_SCRIPT_P2SH);
    }
    else if ( vp->spendlen > 34 && vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKMULTISIG && (n= vp->spendscript[vp->spendlen-2]) >= 0x51 && n <= 0x60 && (m= vp->spendscript[0]) >= 0x51 && m <= n ) // m of n multisig
    {
        m -= 0x50, n -= 0x50;
        script = vp->spendscript+1;
        for (i=0; i<n; i++,script += plen)
        {
            plen = *script++;
            if ( bitcoin_pubkeylen(script) != plen )
            {
                static int32_t counter;
                if ( counter++ < 3 )
                    printf("multisig.%d of %d: invalid pubkey[%02x] len %d\n",i,n,script[0],bitcoin_pubkeylen(script));
                return(-1);
            }
            memcpy(vp->signers[i].pubkey,script,plen);
            calc_rmd160_sha256(vp->signers[i].rmd160,vp->signers[i].pubkey,plen);
            bitcoin_address(vp->signers[i].coinaddr,pubtype,vp->signers[i].pubkey,plen);
        }
        if ( (int32_t)((long)script - (long)vp->spendscript) == vp->spendlen-2 )
        {
            vp->N = n;
            vp->M = m;
            //printf("M.%d N.%d\n",m,n);
        }
        calc_rmd160_sha256(vp->rmd160,vp->spendscript,vp->spendlen);
        if ( n == 3 )
        {
            if ( m == 3 )
                return(IGUANA_SCRIPT_3of3);
            else if ( m == 2 )
                return(IGUANA_SCRIPT_2of3);
            else if ( m == 1 )
                return(IGUANA_SCRIPT_1of3);
        }
        else if ( n == 2 )
        {
            if ( m == 2 )
                return(IGUANA_SCRIPT_2of2);
            else if ( m == 1 )
                return(IGUANA_SCRIPT_1of2);
        }
        else if ( m == 1 && n == 1 )
            return(IGUANA_SCRIPT_1of1);
        //printf("strange msig M.%d of N.%d\n",m,n);
        return(IGUANA_SCRIPT_MSIG);
    }
    else if ( vp->spendlen == vp->spendscript[0]+1 )
    {
        //printf("just data.%d\n",vp->spendlen);
        memcpy(vp->rmd160,zero_rmd160,sizeof(zero_rmd160));
        return(IGUANA_SCRIPT_DATA);
    }
    if ( type != IGUANA_SCRIPT_OPRETURN && type != IGUANA_SCRIPT_DATA )
    {
        if ( vp->spendlen > 0 && vp->spendlen < sizeof(hexstr)/2-1 )
        {
            static FILE *fp;
            init_hexbytes_noT(hexstr,vp->spendscript,vp->spendlen);
            //char str[65]; printf("unparsed script.(%s).%d in %s len.%d\n",hexstr,vp->spendlen,bits256_str(str,vp->vin.prev_hash),vp->spendlen);
            if ( 1 && fp == 0 )
                fp = fopen("unparsed.txt","w");
            if ( fp != 0 )
                fprintf(fp,"%s\n",hexstr), fflush(fp);
        } else sprintf(hexstr,"pkscript overflowed %ld\n",(long)sizeof(hexstr));
    }
    calc_rmd160_sha256(vp->rmd160,vp->spendscript,vp->spendlen);
    return(type);
}

int32_t iguana_calcrmd160(uint8_t pubtype,uint8_t p2shtype,char *asmstr,struct vin_info *vp,uint8_t *pk_script,int32_t pk_scriptlen,bits256 debugtxid,int32_t vout,uint32_t sequence)
{
    int32_t scriptlen; uint8_t script[IGUANA_MAXSCRIPTSIZE];
    memset(vp,0,sizeof(*vp));
    vp->vin.prev_hash = debugtxid, vp->vin.prev_vout = vout;
    vp->spendlen = pk_scriptlen;
    vp->vin.sequence = sequence;
    memcpy(vp->spendscript,pk_script,pk_scriptlen);
    if ( (vp->type= _iguana_calcrmd160(pubtype,p2shtype,vp)) >= 0 )
    {
        scriptlen = iguana_scriptgen(pubtype,p2shtype,&vp->M,&vp->N,vp->coinaddr,script,asmstr,vp->rmd160,vp->type,(const struct vin_info *)vp,vout);
        if ( vp->M == 0 && vp->N == 0 )
        {
            vp->M = vp->N = 1;
            strcpy(vp->signers[0].coinaddr,vp->coinaddr);
            memcpy(vp->signers[0].rmd160,vp->rmd160,20);
        }
        if ( scriptlen != pk_scriptlen || (scriptlen != 0 && memcmp(script,pk_script,scriptlen) != 0) )
        {
            if ( vp->type != IGUANA_SCRIPT_OPRETURN && vp->type != IGUANA_SCRIPT_DATA && vp->type != IGUANA_SCRIPT_STRANGE )
            {
                int32_t i;
                printf("\n--------------------\n");
                for (i=0; i<scriptlen; i++)
                    printf("%02x ",script[i]);
                printf("script.%d\n",scriptlen);
                for (i=0; i<pk_scriptlen; i++)
                    printf("%02x ",pk_script[i]);
                printf("original script.%d\n",pk_scriptlen);
                printf("iguana_calcrmd160 type.%d error regenerating scriptlen.%d vs %d\n\n",vp->type,scriptlen,pk_scriptlen);
            }
        }
    }
    return(vp->type);
}

cJSON *bitcoin_txscript(char *asmstr,char **vardata,int32_t numvars)
{
    int32_t i; cJSON *scriptjson,*array;
    scriptjson = cJSON_CreateObject();
    jaddstr(scriptjson,"asm",asmstr);
    jaddnum(scriptjson,"numvars",numvars);
    if ( numvars > 0 )
    {
        array = cJSON_CreateArray();
        for (i=0; i<numvars; i++)
            jaddistr(array,vardata[i]);
        jadd(scriptjson,"args",array);
    }
    return(scriptjson);
}

cJSON *iguana_scriptpubkeys(uint8_t pubtype,uint8_t p2shtype,uint8_t *script,int32_t scriptlen,bits256 txid,int16_t vout,uint32_t sequenceid)
{
    int32_t type,i,n,plen; struct vin_info V; cJSON *pubkeys; char pubkeystr[256];
    pubkeys = cJSON_CreateArray();
    if ( (type= iguana_calcrmd160(pubtype,p2shtype,0,&V,script,scriptlen,txid,vout,sequenceid)) >= 0 )
    {
        if ( (n= V.N) == 0 )
            n = 1;
        for (i=0; i<n; i++)
        {
            if ( (plen= bitcoin_pubkeylen(V.signers[i].pubkey)) > 0 )
                init_hexbytes_noT(pubkeystr,V.signers[i].pubkey,plen);
            else pubkeystr[0] = 0;
            jaddistr(pubkeys,pubkeystr);
        }
    }
    return(pubkeys);
}

void iguana_addscript(cJSON *dest,uint8_t *script,int32_t scriptlen,char *fieldname)
{
    char *scriptstr,scriptbuf[8192+256]; int32_t maxlen; cJSON *scriptobj;
    if ( scriptlen < 0 || scriptlen > IGUANA_MAXSCRIPTSIZE || scriptlen > sizeof(scriptbuf) )
        return;
    scriptstr = scriptbuf, maxlen = sizeof(scriptbuf);
    init_hexbytes_noT(scriptstr,script,scriptlen);
    //if ( strcmp(fieldname,"userdata") == 0 )
    //    printf("SCRIPT_USERDATA.(%s)\n",scriptstr);
    if ( strcmp(fieldname,"coinbase") == 0 )
        jaddstr(dest,"coinbase",scriptstr);
    else
    {
        scriptobj = cJSON_CreateObject();
        jaddstr(scriptobj,"hex",scriptstr);
        iguana_expandscript(scriptstr,maxlen,script,scriptlen);
        if ( scriptstr[0] != 0 )
            jaddstr(scriptobj,"asm",scriptstr);
        if ( scriptstr != scriptbuf )
            free(scriptstr);
        jadd(dest,fieldname,scriptobj);
    }
}

cJSON *iguana_pubkeysjson(uint8_t *pubkeyptrs[],int32_t numpubkeys)
{
    int32_t i,plen; char pubkeystr[256]; cJSON *pubkeysjson = cJSON_CreateArray();
    for (i=0; i<numpubkeys; i++)
    {
        if ( pubkeyptrs != 0 && (plen= bitcoin_pubkeylen(pubkeyptrs[i])) > 0 )
            init_hexbytes_noT(pubkeystr,pubkeyptrs[i],plen);
        else pubkeystr[0] = 0;
        jaddistr(pubkeysjson,pubkeystr);
    }
    return(pubkeysjson);
}

cJSON *bitcoin_txinput(uint8_t pubtype,uint8_t p2shtype,cJSON *txobj,bits256 txid,int32_t vout,uint32_t sequenceid,uint8_t *spendscript,int32_t spendlen,uint8_t *redeemscript,int32_t p2shlen,uint8_t *pubkeys[],int32_t numpubkeys,uint8_t *sig,int32_t siglen)
{
    cJSON *item,*vins; char p2shscriptstr[IGUANA_MAXSCRIPTSIZE*2+1]; uint8_t *script,len=0;
    vins = jduplicate(jobj(txobj,"vin"));
    jdelete(txobj,"vin");
    item = cJSON_CreateObject();
    if ( sig != 0 && siglen > 0 )
        iguana_addscript(item,sig,siglen,"scriptSig");
    if ( spendscript != 0 && spendscript > 0 )
    {
        iguana_addscript(item,spendscript,spendlen,"scriptPubKey");
        script = spendscript, len = spendlen;
    }
    else if ( redeemscript != 0 && p2shlen > 0 )
    {
        init_hexbytes_noT(p2shscriptstr,redeemscript,p2shlen);
        jaddstr(item,"redeemScript",p2shscriptstr);
        script = redeemscript, len = p2shlen;
    } else script = 0;
    if ( script != 0 && numpubkeys == 0 )
        jadd(item,"pubkeys",iguana_scriptpubkeys(pubtype,p2shtype,script,len,txid,vout,sequenceid));
    else if ( pubkeys != 0 && numpubkeys > 0 )
        jadd(item,"pubkeys",iguana_pubkeysjson(pubkeys,numpubkeys));
    jaddbits256(item,"txid",txid);
    jaddnum(item,"vout",vout);
    jaddnum(item,"sequence",sequenceid);
    jaddi(vins,item);
    jadd(txobj,"vin",vins);
    //printf("addvin -> (%s)\n",jprint(txobj,0));
    return(txobj);
}

cJSON *bitcoin_txcreate(char *symbol,int32_t isPoS,int64_t locktime,uint32_t txversion,uint32_t timestamp)
{
    cJSON *json = cJSON_CreateObject();
    jaddnum(json,"version",txversion);
    if ( locktime == 0 && strcmp(symbol,"KMD") == 0 )
        locktime = (uint32_t)time(NULL);
    jaddnum(json,"locktime",locktime);
    if ( isPoS != 0 )
        jaddnum(json,"timestamp",timestamp == 0 ? time(NULL) : timestamp);
    jadd(json,"vin",cJSON_CreateArray());
    jadd(json,"vout",cJSON_CreateArray());
    return(json);
}

cJSON *bitcoin_txoutput(cJSON *txobj,uint8_t *paymentscript,int32_t len,uint64_t satoshis)
{
    char *hexstr; cJSON *item,*skey,*vouts = jduplicate(jobj(txobj,"vout"));
    jdelete(txobj,"vout");
    item = cJSON_CreateObject();
    jadd64bits(item,"satoshis",satoshis);
    skey = cJSON_CreateObject();
    hexstr = malloc(len*2 + 1);
    init_hexbytes_noT(hexstr,paymentscript,len);
    jaddstr(skey,"hex",hexstr);
    //printf("addoutput.(%s %s)\n",hexstr,jprint(skey,0));
    free(hexstr);
    jadd(item,"scriptPubkey",skey);
    jaddi(vouts,item);
    jadd(txobj,"vout",vouts);
    return(txobj);
}

int32_t bitcoin_txaddspend(uint8_t pubtype,uint8_t p2shtype,cJSON *txobj,char *destaddress,uint64_t satoshis)
{
    uint8_t outputscript[128],addrtype,rmd160[20]; int32_t scriptlen;
    if ( bitcoin_validaddress(pubtype,p2shtype,destaddress) == 0 && satoshis != 0 )
    {
        bitcoin_addr2rmd160(&addrtype,rmd160,destaddress);
        scriptlen = bitcoin_standardspend(outputscript,0,rmd160);
        bitcoin_txoutput(txobj,outputscript,scriptlen,satoshis);
        return(0);
    } else return(-1);
}

int32_t iguana_vinparse(int32_t rwflag,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t p2shlen,len = 0; uint32_t tmp;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    //char str[65]; printf("prev_hash.(%s) v%d\n",bits256_str(str,msg->prev_hash),msg->prev_vout);
    if ( rwflag == 1 )
    {
        tmp = msg->scriptlen + msg->userdatalen + msg->p2shlen;
        if ( msg->p2shlen != 0 )
        {
            if ( msg->p2shlen < 76 )
                tmp++;
            else if ( msg->p2shlen < 0x100 )
                tmp += 2;
            else tmp += 3;
        }
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&tmp);
    if ( rwflag == 0 )
    {
        /*if ( msg->p2shlen != 0 )
         {
         if ( msg->p2shlen < 76 )
         tmp++;
         else if ( msg->p2shlen < 0x100 )
         tmp += 2;
         else tmp += 3;
         }*/
        msg->scriptlen = tmp;
    }
    if ( msg->scriptlen > IGUANA_MAXSCRIPTSIZE )
    {
        printf("iguana_vinparse illegal scriptlen.%d\n",msg->scriptlen);
        return(-1);
    }
    //printf("len.%d scriptlen.%d user.%d p2sh.%d\n",len,msg->scriptlen,msg->userdatalen,msg->p2shlen);
    if ( rwflag == 0 )
    {
        msg->vinscript = &serialized[len];
        len += msg->scriptlen;
    }
    else
    {
        if ( msg->vinscript != 0 && msg->scriptlen > 0 )
            memcpy(&serialized[len],msg->vinscript,msg->scriptlen), len += msg->scriptlen; // pubkeys here
        if ( msg->userdatalen > 0 && msg->userdata != 0 )
        {
            //printf("userdata.%d scriptlen.%d\n",msg->userdatalen,msg->scriptlen);
            memcpy(&serialized[len],msg->userdata,msg->userdatalen);
            len += msg->userdatalen;
        }
        if ( (p2shlen= msg->p2shlen) > 0 && msg->redeemscript != 0 )
        {
            if ( p2shlen < 76 )
                serialized[len++] = p2shlen;
            else if ( p2shlen <= 0xff )
            {
                serialized[len++] = 0x4c;
                serialized[len++] = p2shlen;
            }
            else if ( p2shlen <= 0xffff )
            {
                serialized[len++] = 0x4d;
                serialized[len++] = (p2shlen & 0xff);
                serialized[len++] = ((p2shlen >> 8) & 0xff);
            } else return(-1);
            memcpy(&serialized[len],msg->redeemscript,p2shlen), len += p2shlen;
            if ( (0) )
            {
                int32_t j;
                for (j=0; j<p2shlen; j++)
                    printf("%02x",msg->redeemscript[j]);
                printf(" p2shlen.%d %x\n",p2shlen,p2shlen);
            }
        }
    }
    //printf("sequence starts.%d %08x\n",len,*(int32_t *)&serialized[len]);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->sequence),&msg->sequence);
    if ( (0) )
    {
        int32_t i; char str[65];
        for (i=0; i<len; i++)
            printf("%02x",serialized[i]);
        printf(" %08x prev_hash.(%s) vout.%d [%p] scriptlen.%d rwflag.%d\n",msg->sequence,bits256_str(str,msg->prev_hash),msg->prev_vout,msg->vinscript,msg->scriptlen,rwflag);
    }
    return(len);
}

int32_t iguana_voutparse(int32_t rwflag,uint8_t *serialized,struct iguana_msgvout *msg)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->value),&msg->value);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->pk_scriptlen);
    if ( msg->pk_scriptlen > IGUANA_MAXSCRIPTSIZE )
    {
        printf("iguana_voutparse illegal scriptlen.%d\n",msg->pk_scriptlen);
        return(-1);
    }
    if ( rwflag == 0 )
        msg->pk_script = &serialized[len];
    else if ( msg->pk_scriptlen > 0 )
    {
        memcpy(&serialized[len],msg->pk_script,msg->pk_scriptlen);
        if ( (0) )
        {
            int32_t i;
            for (i=0; i<msg->pk_scriptlen; i++)
                printf("%02x",msg->pk_script[i]);
            printf(" [%p] scriptlen.%d rwflag.%d %.8f\n",msg->pk_script,msg->pk_scriptlen,rwflag,dstr(msg->value));
        }
    } // else serialized[len++] = 0;
    len += msg->pk_scriptlen;
    return(len);
}

cJSON *iguana_vinjson(struct iguana_msgvin *vin,bits256 sigtxid)
{
    char str[65]; int32_t vout; cJSON *json = cJSON_CreateObject();
    vout = vin->prev_vout;
    jaddnum(json,"sequence",vin->sequence);
    if ( vout < 0 && bits256_nonz(vin->prev_hash) == 0 )
        iguana_addscript(json,vin->vinscript,vin->scriptlen,"coinbase");
    else
    {
        jaddstr(json,"txid",bits256_str(str,vin->prev_hash));
        jaddnum(json,"vout",vout);
        if ( bits256_nonz(sigtxid) != 0 )
            jaddbits256(json,"sigtxid",sigtxid);
        if ( vin->scriptlen > 0 && vin->vinscript != 0 ) // sigs
            iguana_addscript(json,vin->vinscript,vin->scriptlen,"scriptSig");
        if ( vin->userdatalen > 0 && vin->userdata != 0 )
            iguana_addscript(json,vin->userdata,vin->userdatalen,"userdata");
        if ( vin->p2shlen > 0 && vin->redeemscript != 0 )
            iguana_addscript(json,vin->redeemscript,vin->p2shlen,"redeemScript");
        if ( vin->spendlen > 0 && vin->spendscript != 0 )
            iguana_addscript(json,vin->spendscript,vin->spendlen,"scriptPubKey");
    }
    return(json);
}

int32_t iguana_parsehexstr(uint8_t **destp,uint16_t *lenp,uint8_t *dest2,int32_t *len2p,uint8_t *serialized,char *hexstr)
{
    int32_t n;
    n = (int32_t)strlen(hexstr) >> 1;
    //printf("addhex.(%s) %d\n",hexstr,n);
    if ( serialized == 0 )
    {
        if ( (serialized= *destp) == 0 )
            printf("iguana_parsehexstr null serialized and destp\n");
    }
    if ( serialized != 0 )
    {
        decode_hex(serialized,n,hexstr);
        *destp = serialized;
        *lenp = n;
        if ( dest2 != 0 && len2p != 0 )
        {
            *len2p = n;
            memcpy(dest2,serialized,n);
        }
    }
    return(n);
}

int32_t iguana_scriptnum(uint8_t opcode)
{
    if ( opcode == 0x00 )
        return(0);
    else if ( opcode >= 0x51 && opcode < 0x60 )
        return(opcode - 0x50);
    else return(-1);
}

int32_t iguana_parsevinobj(uint8_t *serialized,int32_t maxsize,struct iguana_msgvin *vin,cJSON *vinobj,struct vin_info *V)
{
    //struct iguana_outpoint outpt; struct iguana_waddress *waddr; struct iguana_waccount *wacct;
    uint8_t lastbyte; uint32_t tmp=0; int32_t i,n,starti,suppress_pubkeys,siglen,plen,m,endi,rwflag=1,len = 0; char *userdata=0,*pubkeystr,*hexstr = 0,*redeemstr = 0,*spendstr = 0; cJSON *scriptjson = 0,*obj,*pubkeysjson = 0;
    //printf("PARSEVIN.(%s) vin.%p\n",jprint(vinobj,0),vin);
    if ( V == 0 )
        memset(vin,0,sizeof(*vin));
    vin->prev_vout = -1;
    suppress_pubkeys = juint(vinobj,"suppress");
    if ( jobj(vinobj,"sequence") != 0 )
        vin->sequence = juint(vinobj,"sequence");
    else vin->sequence = 0xffffffff;
    if ( (hexstr= jstr(vinobj,"coinbase")) == 0 )
    {
        vin->prev_hash = jbits256(vinobj,"txid");
        //char str[65]; printf("vin->prev_hash.(%s)\n",bits256_str(str,vin->prev_hash));
        vin->prev_vout = jint(vinobj,"vout");
        if ( (scriptjson= jobj(vinobj,"scriptSig")) != 0 )
            hexstr = jstr(scriptjson,"hex");
        if ( ((spendstr= jstr(vinobj,"scriptPub")) == 0 && (spendstr= jstr(vinobj,"scriptPubKey")) == 0) || is_hexstr(spendstr,(int32_t)strlen(spendstr)) <= 0 )
        {
            if ( (obj= jobj(vinobj,"scriptPub")) != 0 || (obj= jobj(vinobj,"scriptPubKey")) != 0 )
            {
                spendstr = jstr(obj,"hex");
                if ( spendstr[0] != 0 )
                {
                    lastbyte = _decode_hex(&spendstr[strlen(spendstr)-2]);
                    //if ( lastbyte == SCRIPT_OP_CHECKMULTISIG )
                    //    need_op0 = 1;
                    if ( V != 0 )
                    {
                        V->spendlen = (int32_t)strlen(spendstr) >> 1;
                        decode_hex(V->spendscript,V->spendlen,spendstr);
                    }
                }
            }
        }
        if ( (redeemstr= jstr(vinobj,"redeemScript")) == 0 || is_hexstr(redeemstr,(int32_t)strlen(redeemstr)) <= 0 )
        {
            if ( (obj= jobj(vinobj,"redeemScript")) != 0 )
            {
                redeemstr = jstr(obj,"hex");
                lastbyte = _decode_hex(&redeemstr[strlen(redeemstr)-2]);
                //if ( lastbyte == SCRIPT_OP_CHECKMULTISIG )
                //    need_op0 = 1;
            }
        }
        if ( (userdata= jstr(vinobj,"userdata")) == 0 || is_hexstr(userdata,(int32_t)strlen(userdata)) <= 0 )
        {
            if ( (obj= jobj(vinobj,"userdata")) != 0 )
                userdata = jstr(obj,"hex");
        }
    }
    //char str[65]; printf("rw.%d prevhash.(%s)\n",rwflag,bits256_str(str,vin->prev_hash));
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(vin->prev_hash),vin->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(vin->prev_vout),&vin->prev_vout);
    if ( V != 0 )
    {
        V->suppress_pubkeys = suppress_pubkeys;
        if ( vin->vinscript == 0 && V->spendlen == 0 )
        {
            /*if ( iguana_RTunspentindfind(coin,&outpt,V->coinaddr,spendscript,&spendlen,&V->amount,&V->height,vin->prev_hash,vin->prev_vout,coin->bundlescount-1,0) == 0 )
            {
                V->unspentind = outpt.unspentind;
                if ( V->coinaddr[0] != 0 && (waddr= iguana_waddresssearch(&wacct,V->coinaddr)) != 0 )
                {
                    plen = bitcoin_pubkeylen(waddr->pubkey);
                    for (z=0; z<plen; z++)
                        V->signers[0].pubkey[z] = waddr->pubkey[z];
                }
                //printf("V %.8f (%s) spendscript.[%d]\n",dstr(V->amount),V->coinaddr,V->spendlen);
            }
            if ( spendlen != 0 && V->spendlen == 0 )
            {
                V->spendlen = spendlen;
                memcpy(V->spendscript,spendscript,spendlen);
            }*/
        }
    }
    tmp = IGUANA_MAXSCRIPTSIZE;
    starti = len;
    len += iguana_rwvarint32(rwflag,&serialized[len],&tmp);
    endi = len;
    //printf("rwflag.%d len.%d tmp.%d\n",rwflag,len,tmp);
    //if ( need_op0 != 0 )
    //    serialized[len++] = 0; // hack for bug for bug backward compatibility
    if ( hexstr != 0 )
    {
        n = (int32_t)strlen(hexstr) >> 1;
        //printf("add.(%s) offset.%d\n",hexstr,len);
        vin->vinscript = &serialized[len];
        decode_hex(&serialized[len],n,hexstr);
        vin->scriptlen = n;// + need_op0;
        if ( V != 0 )
        {
            i = m = 0;
            while ( m < n )
            {
                siglen = serialized[len + m++];
                //if ( i == 0 && m == 1 && siglen == 0 ) // multisig backward compatible
                //    continue;
                if ( serialized[len + m + siglen - 1] == SIGHASH_ALL )
                    memcpy(V->signers[i++].sig,&serialized[len + m],siglen);
                if ( (0) )
                {
                    int32_t j;
                    for (j=0; j<siglen; j++)
                        printf("%02x",serialized[len + m + j]);
                    printf(" (%d) parsedvin\n",siglen);
                }
                m += siglen;
                i++;
            }
            if ( m != n )
                printf("ERROR: (%s) len.%d n.%d i.%d\n",hexstr,m,n,i);
        }
        len += n;
    } //else printf("iguana_parsevinobj: hex script missing (%s)\n",jprint(vinobj,0));
    if ( (pubkeysjson= jarray(&n,vinobj,"pubkeys")) != 0 && vin->vinscript != 0 )
    {
        /*if ( vin->vinscript == 0 )
         {
         vin->vinscript = serialized;
         vin->vinscript[0] = 0;
         vin->scriptlen = 1;
         }*/
        for (i=0; i<n; i++)
        {
            if ( (pubkeystr= jstr(jitem(pubkeysjson,i),0)) != 0 && (plen= (int32_t)strlen(pubkeystr) >> 1) > 0 )
            {
                if ( V != 0 )
                {
                    memcpy(V->signers[i].pubkey,&vin->vinscript[vin->scriptlen],plen);
                    if ( V->spendlen == 35 && V->spendscript[0] == 33 && V->spendscript[34] == 0xac )
                        suppress_pubkeys = 1;
                }
                if ( suppress_pubkeys == 0 )
                {
                    printf("addpub.(%s)\n",pubkeystr);
                    vin->vinscript[vin->scriptlen++] = plen;
                    decode_hex(&vin->vinscript[vin->scriptlen],plen,pubkeystr);
                    vin->scriptlen += plen;
                    serialized[len++] = plen;
                    memcpy(&serialized[len],&vin->vinscript[vin->scriptlen],plen), len += plen;
                }
            }
        }
    }
    //printf("userdata len.%d: ",len);
    if ( userdata != 0 )
    {
        n = iguana_parsehexstr(&vin->userdata,&vin->userdatalen,V!=0?V->userdata:0,V!=0?&V->userdatalen:0,&serialized[len],userdata);
        //printf("parsed userdata.%d\n",n);
        len += n;
    }
    //printf("redeemlen.%d: ",len);
    if ( redeemstr != 0 )
    {
        n = (int32_t)strlen(redeemstr) >> 1;
        if ( n < 76 )
            serialized[len++] = n;
        else if ( n <= 0xff )
        {
            serialized[len++] = 0x4c;
            serialized[len++] = n;
        }
        else
        {
            serialized[len++] = 0x4d;
            serialized[len++] = n & 0xff;
            serialized[len++] = (n >> 8) & 0xff;
        }
        n = iguana_parsehexstr(&vin->redeemscript,&vin->p2shlen,V!=0?V->p2shscript:0,V!=0?&V->p2shlen:0,&serialized[len],redeemstr);
        len += n;
        if ( vin->redeemscript[vin->p2shlen-1] == SCRIPT_OP_CHECKMULTISIG )
        {
            V->M = iguana_scriptnum(vin->redeemscript[0]);
            V->N = iguana_scriptnum(vin->redeemscript[vin->p2shlen-2]);
        }
    }
    tmp = (len - endi);
    if ( tmp < 0xfd )
    {
        serialized[starti] = tmp;
        for (i=starti+1; i<starti+1+tmp; i++)
            serialized[i] = serialized[i+2];
        //printf("tmp.%d (len.%d - starti.%d) i.%d\n",tmp,len,starti,i);
        len -= 2;
    }
    else
    {
        //for (i=0; i<len; i++)
        //    printf("%02x",serialized[i]);
        //printf(" <- offset.%d tmp.%d starti.%d\n",len,tmp,starti);
        serialized[starti+1] = (tmp & 0xff);
        serialized[starti+2] = ((tmp >> 8) & 0xff);
    }
    //printf("len.%d tmp.%d output sequence.[%d] <- %x\n",len,tmp,len,vin->sequence);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(vin->sequence),&vin->sequence);
    if ( spendstr != 0 )
    {
        if ( V != 0 )
        {
            if ( V->spendlen == 0 )
            {
                V->spendlen = (int32_t)strlen(spendstr) >> 1;
                decode_hex(V->spendscript,V->spendlen,spendstr);
            }
            if ( vin->spendscript == 0 )
                vin->spendscript = V->spendscript;
        }
        if ( vin->spendlen == 0 && vin->spendscript != 0 )
        {
            vin->spendlen = (int32_t)strlen(spendstr) >> 1;
            decode_hex(vin->spendscript,vin->spendlen,spendstr);
        }
        //printf("serialized.%p len.%d\n",serialized,len);
        //n = iguana_parsehexstr(&vin->spendscript,&vin->spendlen,V!=0?V->spendscript:0,V!=0?&V->spendlen:0,&serialized[len],spendstr);
        //len += n;
    }
    return(len);
}

int32_t iguana_parsevoutobj(uint8_t *serialized,int32_t maxsize,struct iguana_msgvout *vout,cJSON *voutobj)
{
    int32_t n,len = 0,rwflag = 1; cJSON *skey; char *hexstr;
    memset(vout,0,sizeof(*vout));
    if ( jobj(voutobj,"satoshis") != 0 )
        vout->value = j64bits(voutobj,"satoshis");
    else vout->value = jdouble(voutobj,"value") * SATOSHIDEN;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(vout->value),&vout->value);
    if ( (skey= jobj(voutobj,"scriptPubKey")) != 0 )
    {
        if ( (hexstr= jstr(skey,"hex")) != 0 )
        {
            n = (int32_t)strlen(hexstr) >> 1;
            vout->pk_scriptlen = n;
            len += iguana_rwvarint32(rwflag,&serialized[len],&vout->pk_scriptlen);
            decode_hex(&serialized[len],n,hexstr);
            vout->pk_script = &serialized[len];
            len += n;
        } // else serialized[len++] = 0;
    } //else serialized[len++] = 0;
    return(len);
}

cJSON *iguana_voutjson(uint8_t pubtype,uint8_t p2shtype,struct iguana_msgvout *vout,int32_t txi,bits256 txid)
{
    // 035f1321ed17d387e4433b2fa229c53616057964af065f98bfcae2233c5108055e OP_CHECKSIG
    char scriptstr[IGUANA_MAXSCRIPTSIZE+1],asmstr[2*IGUANA_MAXSCRIPTSIZE+1]; int32_t i,m,n,scriptlen,asmtype; struct vin_info *vp;
    uint8_t space[8192]; cJSON *addrs,*skey,*json = cJSON_CreateObject();
    vp = calloc(1,sizeof(*vp));
    jadd64bits(json,"satoshis",vout->value);
    jaddnum(json,"value",dstr(vout->value));
    jaddnum(json,"n",txi);
    //"scriptPubKey":{"asm":"OP_DUP OP_HASH160 5f69cb73016264270dae9f65c51f60d0e4d6fd44 OP_EQUALVERIFY OP_CHECKSIG","reqSigs":1,"type":"pubkeyhash","addresses":["RHyh1V9syARTf2pyxibz7v27D5paBeWza5"]}
    if ( vout->pk_script != 0 && vout->pk_scriptlen*2+1 < sizeof(scriptstr) )
    {
        memset(vp,0,sizeof(*vp));
        if ( (asmtype= iguana_calcrmd160(pubtype,p2shtype,asmstr,vp,vout->pk_script,vout->pk_scriptlen,txid,txi,0xffffffff)) >= 0 )
        {
            skey = cJSON_CreateObject();
            scriptlen = iguana_scriptgen(pubtype,p2shtype,&m,&n,vp->coinaddr,space,asmstr,vp->rmd160,asmtype,vp,txi);
            if ( asmstr[0] != 0 )
                jaddstr(skey,"asm",asmstr);
            addrs = cJSON_CreateArray();
            if ( vp->N == 1 )
            {
                if ( asmtype == 2 )
                {
                    jaddnum(skey,"reqSigs",1);
                    jaddstr(skey,"type","pubkeyhash");
                }
                if ( vp->coinaddr[0] != 0 )
                    jaddistr(addrs,vp->coinaddr);
            }
            else
            {
                jaddnum(skey,"reqSigs",vp->M);
                for (i=0; i<vp->N; i++)
                {
                    //btc_convrmd160(coinaddr,coin->chain->pubtype,V.signers[i].pubkey);
                    jaddistr(addrs,vp->signers[i].coinaddr);
                }
            }
            jadd(skey,"addresses",addrs);
            init_hexbytes_noT(scriptstr,vout->pk_script,vout->pk_scriptlen);
            if ( scriptstr[0] != 0 )
                jaddstr(skey,"hex",scriptstr);
            jadd(json,"scriptPubKey",skey);
        }
    }
    return(json);
}

void iguana_vinobjset(struct iguana_msgvin *vin,cJSON *item,uint8_t *spendscript,int32_t maxsize)
{
    char *redeemstr,*hexstr=0; cJSON *sobj;
    if ( (redeemstr= jstr(item,"redeemScript")) != 0 && is_hexstr(redeemstr,0) > 0 )
    {
        vin->p2shlen = (int32_t)strlen(redeemstr) >> 1;
        vin->spendlen = vin->p2shlen;
        vin->redeemscript = calloc(1,vin->p2shlen);
        decode_hex(vin->redeemscript,vin->p2shlen,redeemstr);
        hexstr = redeemstr;
        //printf("VINOBJSET.(%s)\n",redeemstr);
    }
    else if ( (sobj= jobj(item,"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 && is_hexstr(hexstr,0) > 0 && (vin->spendlen == 0 || vin->spendscript == 0) )
    {
        vin->spendlen = (int32_t)strlen(hexstr) >> 1;
    }
    if ( hexstr != 0 && vin->spendlen != 0 )
    {
        if ( vin->spendlen < maxsize )
        {
            if ( vin->spendscript == 0 )
                vin->spendscript = spendscript;
            decode_hex(vin->spendscript,vin->spendlen,hexstr);
        }
    }
}

int32_t iguana_vinarray_check(cJSON *vinarray,bits256 txid,int32_t vout)
{
    bits256 array_txid; cJSON *item; int32_t array_vout,i,n = cJSON_GetArraySize(vinarray);
    for (i=0; i<n; i++)
    {
        item = jitem(vinarray,i);
        array_txid = jbits256(item,"txid");
        array_vout = jint(item,"vout");
        if ( bits256_cmp(array_txid,txid) == 0 && array_vout == vout )
        {
            printf("vinarray.[%d] duplicate\n",i);
            return(i);
        }
    }
    return(-1);
}

int32_t iguana_rwmsgtx(uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,int32_t rwflag,cJSON *json,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,bits256 *txidp,char *vpnstr,uint8_t *extraspace,int32_t extralen,cJSON *vins,int32_t suppress_pubkeys);

bits256 bitcoin_sigtxid(uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,uint8_t *serialized,int32_t maxlen,struct iguana_msgtx *msgtx,int32_t vini,uint8_t *spendscript,int32_t spendlen,int32_t hashtype,char *vpnstr,int32_t suppress_pubkeys)
{
    int32_t i,len; bits256 sigtxid,txid,revsigtxid; struct iguana_msgtx dest;
    dest = *msgtx;
    dest.vins = calloc(dest.tx_in,sizeof(*dest.vins));
    dest.vouts = calloc(dest.tx_out,sizeof(*dest.vouts));
    memcpy(dest.vins,msgtx->vins,dest.tx_in * sizeof(*dest.vins));
    memcpy(dest.vouts,msgtx->vouts,dest.tx_out * sizeof(*dest.vouts));
    memset(sigtxid.bytes,0,sizeof(sigtxid));
    if ( hashtype != SIGHASH_ALL )
    {
        printf("currently only SIGHASH_ALL supported, not %d\n",hashtype);
        return(sigtxid);
    }
    for (i=0; i<dest.tx_in; i++)
    {
        if ( i == vini )
        {
            dest.vins[i].vinscript = spendscript;
            dest.vins[i].scriptlen = spendlen;
            //int32_t j; for (j=0; j<spendlen; j++)
            //    printf("%02x",spendscript[j]);
            //printf(" tmpscript.%d vini.%d\n",spendlen,vini);
        }
        else
        {
            dest.vins[i].vinscript = (uint8_t *)"";
            dest.vins[i].scriptlen = 0;
        }
        dest.vins[i].p2shlen = 0;
        dest.vins[i].redeemscript = 0;
        dest.vins[i].userdata = 0;
        dest.vins[i].userdatalen = 0;
    }
    len = iguana_rwmsgtx(pubtype,p2shtype,isPoS,height,1,0,serialized,maxlen,&dest,&txid,vpnstr,0,0,0,suppress_pubkeys);
    //for (i=0; i<len; i++)
    //    printf("%02x",serialized[i]);
    //printf(" <- sigtx len.%d supp.%d user[0].%d\n",len,suppress_pubkeys,dest.vins[0].userdatalen);
    if ( len > 0 ) // (dest.tx_in != 1 || bits256_nonz(dest.vins[0].prev_hash) != 0) && dest.vins[0].scriptlen > 0 &&
    {
#ifdef BTC2_VERSION
        if ( height >= BTC2_HARDFORK_HEIGHT )
            hashtype |= (0x777 << 20);
#endif
        len += iguana_rwnum(1,&serialized[len],sizeof(hashtype),&hashtype);
        revsigtxid = bits256_doublesha256(0,serialized,len);
        for (i=0; i<sizeof(revsigtxid); i++)
            sigtxid.bytes[31-i] = revsigtxid.bytes[i];
        //char str[65]; printf("SIGTXID.(%s) numvouts.%d\n",bits256_str(str,sigtxid),dest.tx_out);
    }
    free(dest.vins);
    free(dest.vouts);
    return(sigtxid);
}

int32_t iguana_rwmsgtx(uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,int32_t rwflag,cJSON *json,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,bits256 *txidp,char *vpnstr,uint8_t *extraspace,int32_t extralen,cJSON *vins,int32_t suppress_pubkeys)
{
    int32_t i,n,len = 0,extraused=0; uint8_t spendscript[IGUANA_MAXSCRIPTSIZE],*txstart = serialized,*sigser=0; char txidstr[65]; cJSON *vinarray=0,*voutarray=0; bits256 sigtxid;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( json != 0 )
    {
        jaddnum(json,"version",msg->version);
        vinarray = cJSON_CreateArray();
        voutarray = cJSON_CreateArray();
        if ( rwflag == 0 )
            sigser = calloc(1,maxsize*2);
        //printf("json.%p array.%p sigser.%p\n",json,vinarray,sigser);
    }
    //printf("version.%d\n",msg->version);
    if ( isPoS != 0 )
    {
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->timestamp),&msg->timestamp);
        //char str[65]; printf("version.%d timestamp.%08x %u %s\n",msg->version,msg->timestamp,msg->timestamp,utc_str(str,msg->timestamp));
        if ( json != 0 )
            jaddnum(json,"timestamp",msg->timestamp);
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
    if ( rwflag == 0 )
    {
        if ( msg->vins == 0 )
        {
            if ( sizeof(struct iguana_msgvin)*msg->tx_in > extralen )
            {
                printf("(size.%d * tx_in.%d) > extralen.%d\n",(int32_t)sizeof(struct iguana_msgvin),msg->tx_in,extralen);
                return(-1);
            }
            msg->vins = (struct iguana_msgvin *)extraspace;
            extraused += (sizeof(struct iguana_msgvin) * msg->tx_in);
        } else printf("unexpected non-null msg->vins.%p\n",msg->vins);
        memset(msg->vins,0,sizeof(struct iguana_msgvin) * msg->tx_in);
    }
    for (i=0; i<msg->tx_in; i++)
    {
        //printf("vin.%d starts offset.%d\n",i,len);
        if ( vins != 0 && jitem(vins,i) != 0 )
            iguana_vinobjset(&msg->vins[i],jitem(vins,i),spendscript,sizeof(spendscript));
        if ( (n= iguana_vinparse(rwflag,&serialized[len],&msg->vins[i])) < 0 )
            return(-1);
        //printf("serialized vin.[%02x %02x %02x]\n",serialized[len],serialized[len+1],serialized[len+2]);
        if ( msg->vins[i].spendscript == spendscript )
            msg->vins[i].spendscript = 0;
        //printf("vin.%d n.%d len.%d\n",i,n,len);
        len += n;
        if ( len > maxsize )
        {
            printf("invalid tx_in.%d len.%d vs maxsize.%d\n",msg->tx_in,len,maxsize);
            return(-1);
        }
    }
    //for (i=-3; i<7; i++)
    //    printf("%02x",serialized[len+i]);
    //printf(" prev 3 bytes before tx_out rw.%d\n",rwflag);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_out);
    if ( rwflag == 0 )
    {
        if ( msg->vouts == 0 )
        {
            if ( (extraused & 0xf) != 0 )
                extraused += 0xf - (extraused & 0xf);
            if ( extraused + sizeof(struct iguana_msgvout)*msg->tx_out > extralen )
            {
                printf("extraused.%d + tx_out.%d > extralen.%d\n",extraused,msg->tx_out,extralen);
                return(-1);
            }
            msg->vouts = (struct iguana_msgvout *)&extraspace[extraused];
            extraused += (sizeof(struct iguana_msgvout) * msg->tx_out);
        } else printf("unexpected non-null msg->vouts %p\n",msg->vouts);
        memset(msg->vouts,0,sizeof(struct iguana_msgvout) * msg->tx_out);
    }
    for (i=0; i<msg->tx_out; i++)
    {
        //printf("rwflag.%d vout.%d starts %d\n",rwflag,i,len);
        if ( (n= iguana_voutparse(rwflag,&serialized[len],&msg->vouts[i])) < 0 )
            return(-1);
        len += n;
        if ( len > maxsize )
        {
            printf("invalidC tx_out.%d of %d len.%d vs maxsize.%d n.%d\n",i,msg->tx_out,len,maxsize,n);
            return(-1);
        }
        if ( voutarray != 0 )
            jaddi(voutarray,iguana_voutjson(pubtype,p2shtype,&msg->vouts[i],i,*txidp));
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    //printf("lock_time.%08x len.%d\n",msg->lock_time,len);
    /*if ( strcmp(coin->symbol,"VPN") == 0 )
    {
        uint16_t ddosflag = 0;
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(ddosflag),&ddosflag);
        for (i=0; serialized[len]!=0&&len<maxsize; len++,i++) // eat null terminated string
        {
            if ( rwflag == 0 )
                serialized[len] = vpnstr[i];
            else vpnstr[i] = serialized[len];
        }
        if ( rwflag == 0 )
            serialized[len] = 0;
        else vpnstr[i] = 0;
        len++;
        if ( json != 0 )
        {
            jaddnum(json,"ddosflag",ddosflag);
            jaddstr(json,"vpnstr",vpnstr);
        }
    }*/
    if ( sigser != 0 && vinarray != 0 )
    {
        for (i=0; i<msg->tx_in; i++)
        {
            memset(sigtxid.bytes,0,sizeof(sigtxid));
            if ( vins != 0 && jitem(vins,i) != 0 )
            {
                iguana_vinobjset(&msg->vins[i],jitem(vins,i),spendscript,sizeof(spendscript));
                sigtxid = bitcoin_sigtxid(pubtype,p2shtype,isPoS,height,sigser,maxsize*2,msg,i,msg->vins[i].spendscript,msg->vins[i].spendlen,SIGHASH_ALL,vpnstr,suppress_pubkeys);
                //printf("after vini.%d vinscript.%p spendscript.%p spendlen.%d (%s)\n",i,msg->vins[i].vinscript,msg->vins[i].spendscript,msg->vins[i].spendlen,jprint(jitem(vins,i),0));
                if ( iguana_vinarray_check(vinarray,msg->vins[i].prev_hash,msg->vins[i].prev_vout) < 0 )
                    jaddi(vinarray,iguana_vinjson(&msg->vins[i],sigtxid));
                if ( msg->vins[i].spendscript == spendscript )
                    msg->vins[i].spendscript = 0;
            } else if ( iguana_vinarray_check(vinarray,msg->vins[i].prev_hash,msg->vins[i].prev_vout) < 0 )
                jaddi(vinarray,iguana_vinjson(&msg->vins[i],sigtxid));
        }
        free(sigser);
        jadd(json,"vin",vinarray);
        msg->tx_in = cJSON_GetArraySize(vinarray);
        jaddnum(json,"numvins",msg->tx_in);
    }
    if ( voutarray != 0 )
    {
        jadd(json,"vout",voutarray);
        jaddnum(json,"numvouts",msg->tx_out);
    }
    *txidp = bits256_doublesha256(txidstr,txstart,len);
    if ( json != 0 )
    {
        jaddnum(json,"locktime",msg->lock_time);
        jaddnum(json,"size",len);
        jaddbits256(json,"txid",*txidp);
        //printf("TX.(%s) %p\n",jprint(json,0),json);
    }
    msg->allocsize = len;
    return(len);
}

bits256 iguana_parsetxobj(uint8_t isPoS,int32_t *txstartp,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,cJSON *txobj,struct vin_info *V)
{
    int32_t i,n,numvins,numvouts,len = 0,rwflag=1; cJSON *array=0; bits256 txid; char vpnstr[64];
    memset(&txid,0,sizeof(txid));
    memset(msg,0,sizeof(*msg));
    *txstartp = 0;
    if ( txobj == 0 )
        return(txid);
    vpnstr[0] = 0;
    if ( (msg->version= juint(txobj,"version")) == 0 )
        msg->version = 1;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( isPoS != 0 )
    {
        if ( (msg->timestamp= juint(txobj,"timestamp")) == 0 )
            msg->timestamp = (uint32_t)time(NULL);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->timestamp),&msg->timestamp);
    }
    if ( (array= jarray(&numvins,txobj,"vin")) != 0 )
    {
        msg->tx_in = numvins;
        len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
        if ( len + sizeof(struct iguana_msgvin)*msg->tx_in > maxsize )
            return(txid);
        maxsize -= (sizeof(struct iguana_msgvin) * msg->tx_in);
        msg->vins = (struct iguana_msgvin *)&serialized[maxsize];
        memset(msg->vins,0,sizeof(struct iguana_msgvin) * msg->tx_in);
        if ( msg->tx_in > 0 && msg->tx_in*sizeof(struct iguana_msgvin) < maxsize )
        {
            for (i=0; i<msg->tx_in; i++)
            {
                n = iguana_parsevinobj(&serialized[len],maxsize,&msg->vins[i],jitem(array,i),V!=0?&V[i]:0);
                //for (j=0; j<8; j++)
                //    printf("%02x",serialized[len+j]);
                //char str[65]; printf(" <- vinobj.%d starts offset.%d %s\n",i,len,bits256_str(str,msg->vins[i].prev_hash));
                len += n;
            }
        }
    }
    if ( (array= jarray(&numvouts,txobj,"vout")) != 0 )
    {
        msg->tx_out = numvouts;
        len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_out);
        if ( len + sizeof(struct iguana_msgvout)*msg->tx_out > maxsize )
            return(txid);
        maxsize -= (sizeof(struct iguana_msgvout) * msg->tx_out);
        msg->vouts = (struct iguana_msgvout *)&serialized[maxsize];
        memset(msg->vouts,0,sizeof(struct iguana_msgvout) * msg->tx_out);
        if ( msg->tx_out > 0 && msg->tx_out*sizeof(struct iguana_msgvout) < maxsize )
        {
            for (i=0; i<msg->tx_out; i++)
            {
                //printf("parsetxobj parsevout.%d starts %d\n",i,len);
                len += iguana_parsevoutobj(&serialized[len],maxsize,&msg->vouts[i],jitem(array,i));
            }
        }
    }
    msg->lock_time = jint(txobj,"locktime");
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    //msg->txid = jbits256(txobj,"txid");
    *txstartp = 0;
    msg->allocsize = len;
    msg->txid = txid = bits256_doublesha256(0,serialized,len);
    return(txid);
}

char *iguana_rawtxbytes(uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,cJSON *json,struct iguana_msgtx *msgtx,int32_t suppress_pubkeys)
{
    int32_t n; char *txbytes = 0,vpnstr[64]; uint8_t *serialized;
    serialized = malloc(IGUANA_MAXPACKETSIZE);
    vpnstr[0] = 0;
    //char str[65]; printf("%d of %d: %s\n",i,msg.txn_count,bits256_str(str,tx.txid));
    if ( (n= iguana_rwmsgtx(pubtype,p2shtype,isPoS,height,1,json,serialized,IGUANA_MAXPACKETSIZE,msgtx,&msgtx->txid,vpnstr,0,0,0,suppress_pubkeys)) > 0 )
    {
        txbytes = malloc(n*2+1);
        init_hexbytes_noT(txbytes,serialized,n);
    }
    free(serialized);
    return(txbytes);
}

char *bitcoin_json2hex(uint8_t isPoS,bits256 *txidp,cJSON *txjson,struct vin_info *V)
{
    int32_t txstart; uint8_t *serialized; struct iguana_msgtx msgtx; char *txbytes = 0;
    if ( txjson == 0 )
    {
        memset(txidp,0,sizeof(*txidp));
        return(0);
    }
    serialized = malloc(IGUANA_MAXPACKETSIZE*1.5);
    *txidp = iguana_parsetxobj(isPoS,&txstart,serialized,IGUANA_MAXPACKETSIZE*1.5,&msgtx,txjson,V);
    if ( msgtx.allocsize > 0 )
    {
        txbytes = malloc(msgtx.allocsize*2 + 1);
        init_hexbytes_noT(txbytes,&serialized[txstart],msgtx.allocsize);
    } else printf("bitcoin_txtest: zero msgtx allocsize.(%s)\n",jprint(txjson,0));
    free(serialized);
    return(txbytes);
}

cJSON *bitcoin_data2json(uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,bits256 *txidp,struct iguana_msgtx *msgtx,uint8_t *extraspace,int32_t extralen,uint8_t *serialized,int32_t len,cJSON *vins,int32_t suppress_pubkeys)
{
    int32_t n; char vpnstr[64]; struct iguana_msgtx M; cJSON *txobj;
    if ( serialized == 0 )
        return(0);
    txobj = cJSON_CreateObject();
    if ( msgtx == 0 )
        msgtx = &M;
    memset(msgtx,0,sizeof(M));
    vpnstr[0] = 0;
    memset(txidp,0,sizeof(*txidp));
    if ( (n= iguana_rwmsgtx(pubtype,p2shtype,isPoS,height,0,txobj,serialized,len,msgtx,txidp,vpnstr,extraspace,extralen,vins,suppress_pubkeys)) <= 0 )
    {
        printf("errortxobj.(%s)\n",jprint(txobj,0));
        free_json(txobj);
        txobj = cJSON_CreateObject();
        jaddstr(txobj,"error","couldnt decode transaction");
    }
    //printf("msgtx.(%s)\n",jprint(txobj,0));
    if ( n != len )
    {
        int32_t i;
        for (i=0; i<=len; i++)
            printf("%02x",serialized[i]);
        printf(" data2json n.%d vs len.%d\n",n,len);
    }
    return(txobj);
}

cJSON *bitcoin_hex2json(uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,bits256 *txidp,struct iguana_msgtx *msgtx,char *txbytes,uint8_t *extraspace,int32_t extralen,uint8_t *origserialized,cJSON *vins,int32_t suppress_pubkeys)
{
    int32_t len; uint8_t *serialized; cJSON *txobj;
    if ( txbytes == 0 )
        return(0);
    len = (int32_t)strlen(txbytes) >> 1;
    if ( (serialized= origserialized) == 0 )
        serialized = calloc(1,len+4096);
    decode_hex(serialized,len,txbytes);
    txobj = bitcoin_data2json(pubtype,p2shtype,isPoS,height,txidp,msgtx,extraspace,extralen,serialized,len,vins,suppress_pubkeys);
    if ( serialized != origserialized )
        free(serialized);
    return(txobj);
}
