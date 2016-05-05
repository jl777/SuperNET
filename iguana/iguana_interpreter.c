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
#include "exchanges/bitcoin.h"
#include "mini-gmp.h"

#define MAX_SCRIPT_ELEMENT_SIZE 520
#define MAX_OPS_PER_SCRIPT 201 // Maximum number of non-push operations per script
#define MAX_PUBKEYS_PER_MULTISIG 20 // Maximum number of public keys per multisig

#define IGUANA_MAXSTACKITEMS ((int32_t)(IGUANA_MAXSCRIPTSIZE / sizeof(uint32_t)))
#define IGUANA_MAXSTACKDEPTH 128

#define IGUANA_OP_0 0x00
#define IGUANA_OP_PUSHDATA1 0x4c
#define IGUANA_OP_PUSHDATA2 0x4d
#define IGUANA_OP_PUSHDATA4 0x4e
#define IGUANA_OP_1NEGATE 0x4f
#define IGUANA_OP_1 0x51
#define IGUANA_OP_16 0x60
#define IGUANA_OP_NOP 0x61
#define IGUANA_OP_IF 0x63
#define IGUANA_OP_NOTIF 0x64
#define IGUANA_OP_ELSE 0x67
#define IGUANA_OP_ENDIF 0x68
#define IGUANA_OP_VERIFY 0x69
#define IGUANA_OP_RETURN 0x6a

#define IGUANA_OP_TOALTSTACK 0x6b
#define IGUANA_OP_FROMALTSTACK 0x6c
#define IGUANA_OP_2DROP 0x6d
#define IGUANA_OP_2DUP 0x6e
#define IGUANA_OP_3DUP 0x6f
#define IGUANA_OP_2OVER 0x70
#define IGUANA_OP_2ROT 0x71
#define IGUANA_OP_2SWAP 0x72
#define IGUANA_OP_IFDUP 0x73
#define IGUANA_OP_DEPTH 0x74
#define IGUANA_OP_DROP 0x75
#define IGUANA_OP_DUP 0x76
#define IGUANA_OP_NIP 0x77
#define IGUANA_OP_OVER 0x78
#define IGUANA_OP_PICK 0x79
#define IGUANA_OP_ROLL 0x7a
#define IGUANA_OP_ROT 0x7b
#define IGUANA_OP_SWAP 0x7c
#define IGUANA_OP_TUCK 0x7d

#define IGUANA_OP_EQUAL 0x87
#define IGUANA_OP_EQUALVERIFY 0x88

#define IGUANA_OP_1ADD 0x8b
#define IGUANA_OP_1SUB 0x8c
#define IGUANA_OP_NEGATE 0x8f
#define IGUANA_OP_ABS 0x90
#define IGUANA_OP_NOT 0x91
#define IGUANA_OP_0NOTEQUAL 0x92
#define IGUANA_OP_ADD 0x93
#define IGUANA_OP_SUB 0x94

#define IGUANA_OP_BOOLAND 0x9a
#define IGUANA_OP_BOOLOR 0x9b
#define IGUANA_OP_NUMEQUAL 0x9c
#define IGUANA_OP_NUMEQUALVERIFY 0x9d
#define IGUANA_OP_NUMNOTEQUAL 0x9e
#define IGUANA_OP_LESSTHAN 0x9f
#define IGUANA_OP_GREATERTHAN 0xa0
#define IGUANA_OP_LESSTHANOREQUAL 0xa1
#define IGUANA_OP_GREATERTHANOREQUAL 0xa2
#define IGUANA_OP_MIN 0xa3
#define IGUANA_OP_MAX 0xa4
#define IGUANA_OP_WITHIN 0xa5

#define IGUANA_OP_RIPEMD160 0xa6
#define IGUANA_OP_SHA1 0xa7
#define IGUANA_OP_SHA256 0xa8
#define IGUANA_OP_HASH160 0xa9
#define IGUANA_OP_HASH256 0xaa
#define IGUANA_OP_CODESEPARATOR 0xab
#define IGUANA_OP_CHECKSIG 0xac
#define IGUANA_OP_CHECKSIGVERIFY 0xad
#define IGUANA_OP_CHECKMULTISIG 0xae
#define IGUANA_OP_CHECKMULTISIGVERIFY 0xaf

#define IGUANA_OP_NOP1 0xb0
#define IGUANA_OP_CHECKLOCKTIMEVERIFY 0xb1
#define IGUANA_OP_CHECKSEQUENCEVERIFY 0xb2
#define IGUANA_OP_NOP10 0xb9

#define IGUANA_NOPFLAG 1
#define IGUANA_ALWAYSILLEGAL 2
#define IGUANA_EXECUTIONILLEGAL 4
#define IGUANA_POSTVERIFY 8
#define IGUANA_CRYPTOFLAG 16
#define IGUANA_MATHFLAG 32
#define IGUANA_CONTROLFLAG 64
#define IGUANA_STACKFLAG 128

enum opcodetype
{
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE=OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,
    
    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,
    
    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,
    
    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,
    
    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,
    
    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,
    
    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,
    
    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,
    
    OP_WITHIN = 0xa5,
    
    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,
    
    // expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY  = 0xb1,
    OP_CHECKSEQUENCEVERIFY   = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,
    
    // template matching params
    //OP_SMALLINTEGER = 0xfa,
    //OP_PUBKEYS = 0xfb,
    //OP_PUBKEYHASH = 0xfd,
    //OP_PUBKEY = 0xfe,
    
    OP_INVALIDOPCODE = 0xff,
};

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

static inline int32_t is_delim(int32_t c)
{
    if ( c == 0 || c == ' ' || c == '\t' || c == '\r' || c == '\n' )
        return(1);
    else return(0);
}

union iguana_stacknum { int32_t val; int64_t val64; uint8_t rmd160[20]; bits256 hash2; uint8_t *data; };
struct iguana_stackdata { uint16_t size; union iguana_stacknum U; };

struct iguana_interpreter
{
    int32_t active,ifdepth,elsedepth,codeseparator,stackdepth,altstackdepth,maxstackdepth;
    int8_t lastpath[IGUANA_MAXSTACKDEPTH];
    cJSON *logarray;
    struct iguana_stackdata stack[];
};
static struct bitcoin_opcode { UT_hash_handle hh; uint8_t opcode,flags,stackitems; int8_t extralen; } *optable;

static struct iguana_stackdata iguana_pop(struct iguana_interpreter *stacks)
{
    struct iguana_stackdata Snum;
    Snum = stacks->stack[--stacks->stackdepth];
    memset(&stacks->stack[stacks->stackdepth],0,sizeof(Snum));
    return(Snum);
}

static int32_t iguana_altpush(struct iguana_interpreter *stacks,struct iguana_stackdata Snum)
{
    stacks->stack[2*IGUANA_MAXSTACKITEMS - ++stacks->altstackdepth] = Snum;
    return(stacks->altstackdepth);
}

static struct iguana_stackdata iguana_altpop(struct iguana_interpreter *stacks)
{
    struct iguana_stackdata Snum,*ptr;
    ptr = &stacks->stack[2*IGUANA_MAXSTACKITEMS - --stacks->altstackdepth];
    Snum = *ptr;
    memset(ptr,0,sizeof(Snum));
    return(Snum);
}

static struct iguana_stackdata iguana_clone(struct iguana_stackdata Snum)
{
    struct iguana_stackdata clone;
    clone = Snum;
    if ( Snum.U.data != 0 )
    {
        clone.U.data = malloc(Snum.size);
        memcpy(clone.U.data,Snum.U.data,Snum.size);
    }
    return(clone);
}

static int32_t iguana_isnonz(struct iguana_stackdata Snum)
{
    uint8_t *buf; int32_t i;
    if ( Snum.size == sizeof(int32_t) )
        return(Snum.U.val != 0);
    else if ( Snum.size == sizeof(int64_t) )
        return(Snum.U.val64 != 0);
    else if ( Snum.size == 20 )
        buf = Snum.U.rmd160;
    else if ( Snum.size == sizeof(bits256) )
        buf = Snum.U.hash2.bytes;
    else buf = Snum.U.data;
    for (i=0; i<Snum.size; i++)
        if ( buf[i] != 0 )
            return(1);
    return(0);
}

static int32_t iguana_num(struct iguana_stackdata Snum)
{
    if ( Snum.size == sizeof(int32_t) )
        return(Snum.U.val);
    else return(0);
}

static int32_t iguana_pushdata(struct iguana_interpreter *stacks,int64_t num64,uint8_t *numbuf,int32_t numlen)
{
    struct iguana_stackdata Snum; cJSON *item = 0; char str[256]; int32_t num = (int32_t)num64;
    if ( stacks->maxstackdepth > 0 )
    {
        if ( stacks->stackdepth < stacks->maxstackdepth )
        {
            if ( stacks->logarray != 0 )
                item = cJSON_CreateObject();
            memset(&Snum,0,sizeof(Snum));
            if ( numbuf != 0 )
            {
                if ( numlen <= sizeof(int32_t) )
                {
                    iguana_rwnum(1,(void *)&num,numlen,numbuf);
                    numlen = sizeof(num);
                    Snum.U.val = num;
                    if ( item != 0 )
                        jaddnum(item,"push",num);
                }
                else if ( numlen <= sizeof(int64_t) )
                {
                    iguana_rwnum(1,(void *)&num64,numlen,numbuf);
                    numlen = sizeof(num64);
                    Snum.U.val64 = num64;
                    if ( item != 0 )
                        jadd64bits(item,"push",num64);
                }
                else if ( numlen == 20 )
                {
                    memcpy(Snum.U.rmd160,numbuf,20);
                    if ( item != 0 )
                    {
                        init_hexbytes_noT(str,Snum.U.rmd160,20);
                        jaddstr(item,"push",str);
                    }
                }
                else if ( numlen == sizeof(bits256) )
                {
                    iguana_rwbignum(1,Snum.U.hash2.bytes,sizeof(Snum.U.hash2),numbuf);
                    if ( item != 0 )
                        jaddbits256(item,"push",Snum.U.hash2);
                }
                else
                {
                    Snum.U.data = malloc(Snum.size);
                    memcpy(Snum.U.data,numbuf,numlen);
                    if ( item != 0 )
                        jaddnum(item,"push",numlen);
                }
                Snum.size = numlen;
            }
            else if ( num64 <= 0xffffffff ) // what about negative numbers?
                Snum.U.val = num, Snum.size = sizeof(num);
            else
                Snum.U.val64 = num64, Snum.size = sizeof(num64);
            if ( item != 0 )
            {
                jaddnum(item,"depth",stacks->stackdepth);
                if ( stacks->logarray != 0 )
                    jaddi(stacks->logarray,item);
            }
            stacks->stack[stacks->stackdepth++] = Snum;
        } else return(-1);
    } else stacks->stackdepth++;
    return(0);
}

int32_t iguana_databuf(uint8_t *databuf,struct iguana_stackdata Snum)
{
    if ( Snum.size == 4 )
        memcpy(databuf,&Snum.U.val,4);
    else if ( Snum.size == 8 )
        memcpy(databuf,&Snum.U.val64,8);
    else if ( Snum.size == 20 )
        memcpy(databuf,&Snum.U.rmd160,20);
    else if ( Snum.size == 32 )
        memcpy(databuf,&Snum.U.hash2.bytes,32);
    else memcpy(databuf,&Snum.U.data,Snum.size);
    return(Snum.size);
}

static int32_t iguana_cmp(struct iguana_stackdata *a,struct iguana_stackdata *b)
{
    if ( a->size == b->size )
    {
        if ( a->size == 4 )
            return(a->U.val == b->U.val);
        else if ( a->size == 8 )
            return(a->U.val64 == b->U.val64);
        else if ( a->size == 20 )
            return(memcmp(a->U.rmd160,b->U.rmd160,sizeof(a->U.rmd160)) == 0);
        else if ( a->size == 32 )
            return(memcmp(a->U.hash2.bytes,b->U.hash2.bytes,sizeof(a->U.hash2)) == 0);
        else return(memcmp(a->U.data,b->U.data,sizeof(a->size)) == 0);
    }
    return(-1);
}

static int32_t iguana_dataparse(struct iguana_interpreter *stacks,uint8_t *script,int32_t k,char *str,int32_t *lenp)
{
    int32_t n,c,len; char tmp[4];
    *lenp = 0;
    c = str[0];
    if ( (n= is_hexstr(str,0)) > 0 )
    {
        if ( (n & 1) != 0 )
            len = (n+1) >> 1;
        else len = n >> 1;
        if ( len < 76 )
        {
            if ( len == 1 )
            {
                if ( n == 1 )
                {
                    tmp[0] = '0';
                    tmp[1] = c;
                    tmp[2] = 0;
                    decode_hex(&script[k],1,tmp), (*lenp) = 1;
                    if ( script[k] != 0 )
                        script[k++] += (IGUANA_OP_1 - 1);
                    iguana_pushdata(stacks,c,0,0);
                    return(k);
                }
                else if ( n == 2 && c == '1' && str[1] == '0' && is_delim(str[2]) != 0 )
                {
                    script[k++] = (IGUANA_OP_1 - 1) + 0x10, (*lenp) = 2;
                    iguana_pushdata(stacks,0x10,0,0);
                    return(k);
                }
                else if ( n == 2 && c == '8' && is_delim(str[2]) != 0 )
                {
                    if ( str[1] == '1' )
                    {
                        script[k++] = IGUANA_OP_1NEGATE, (*lenp) = 2;
                        iguana_pushdata(stacks,-1,0,0);
                        return(k);
                    }
                    else if ( str[1] == '0' )
                    {
                        script[k++] = IGUANA_OP_0, (*lenp) = 2;
                        iguana_pushdata(stacks,0,0,0);
                        return(k);
                    }
                }
            }
            if ( len != 0 )
                script[k++] = len;
        }
        else if ( len <= 0xff )
        {
            script[k++] = IGUANA_OP_PUSHDATA1;
            script[k++] = len;
        }
        else if ( len <= 0xffff )
        {
            if ( len <= MAX_SCRIPT_ELEMENT_SIZE )
            {
                script[k++] = IGUANA_OP_PUSHDATA2;
                script[k++] = (len & 0xff);
                script[k++] = ((len >> 8) & 0xff);
            }
            else
            {
                printf("len.%d > MAX_SCRIPT_ELEMENT_SIZE.%d, offset.%d\n",len,MAX_SCRIPT_ELEMENT_SIZE,k);
                return(-1);
            }
        }
        else
        {
            printf("len.%d > MAX_SCRIPT_ELEMENT_SIZE.%d, offset.%d\n",len,MAX_SCRIPT_ELEMENT_SIZE,k);
            return(-1);
        }
        if ( len != 0 )
        {
            uint8_t *numstart; int32_t numlen;
            numstart = &script[k], numlen = len;
            if ( (n & 1) != 0 )
            {
                tmp[0] = '0';
                tmp[1] = c;
                tmp[2] = 0;
                decode_hex(&script[k++],1,tmp), *lenp = 1;
                len--;
            }
            if ( len != 0 )
            {
                decode_hex(&script[k],len,str), (*lenp) += (len << 1);
                k += len;
            }
            iguana_pushdata(stacks,0,numstart,numlen);
        }
        return(k);
    }
    return(0);
}

void iguana_stack(struct iguana_interpreter *stacks,struct iguana_stackdata *args,int32_t num,char *pushstr,char *clonestr)
{
    int32_t i,c;
    while ( (c= *pushstr++) != 0 )
        stacks->stack[stacks->stackdepth++] = args[c - '0'];
    while ( (c= *clonestr++) != 0 )
        stacks->stack[stacks->stackdepth++] = iguana_clone(args[c - '0']);
    if ( num > 0 )
    {
        for (i=0; i<num; i++)
            memset(&args[i],0,sizeof(args[i]));
    }
}

int32_t iguana_checksig(struct iguana_info *coin,struct iguana_stackdata pubkeyarg,struct iguana_stackdata sigarg,bits256 txhash2)
{
    uint8_t pubkey[MAX_SCRIPT_ELEMENT_SIZE],sig[MAX_SCRIPT_ELEMENT_SIZE]; int32_t plen,siglen;
    plen = iguana_databuf(pubkey,pubkeyarg);
    siglen = iguana_databuf(sig,sigarg);
    if ( bitcoin_pubkeylen(pubkey) == plen && plen > 0 && siglen > 0 && siglen < 74 )
        return(bitcoin_verify(coin->ctx,sig,siglen,txhash2,pubkey,plen) == 0);
    return(0);
}

int32_t iguana_checkmultisig(struct iguana_info *coin,struct iguana_interpreter *stacks,int32_t M,int32_t N,bits256 txhash2)
{
    int32_t i,j=0,len,valid=0,numsigners = 0,siglens[MAX_PUBKEYS_PER_MULTISIG]; uint8_t pubkeys[MAX_PUBKEYS_PER_MULTISIG][MAX_SCRIPT_ELEMENT_SIZE],sigs[MAX_PUBKEYS_PER_MULTISIG][MAX_SCRIPT_ELEMENT_SIZE];
    if ( M <= N && N <= MAX_PUBKEYS_PER_MULTISIG )
    {
        for (i=0; i<N; i++)
        {
            if ( stacks->stackdepth <= 0 )
                return(0);
            len = iguana_databuf(pubkeys[i],iguana_pop(stacks));
            if ( len == bitcoin_pubkeylen(pubkeys[i]) )
                numsigners++;
            else
            {
                memcpy(sigs[0],pubkeys[i],len);
                siglens[0] = len;
                break;
            }
        }
        for (i=1; i<numsigners; i++)
        {
            if ( stacks->stackdepth <= 0 )
                return(0);
            siglens[i] = iguana_databuf(sigs[i],iguana_pop(stacks));
            if ( siglens[i] > 0 && siglens[i] < 74 )
                break;
        }
        if ( i == numsigners )
        {
            iguana_pop(stacks);
            j = numsigners-1;
            for (i=numsigners-1; i>=0; i--)
            {
                for (; j>=0; j--)
                {
                    if ( bitcoin_verify(coin->ctx,sigs[i],siglens[i],txhash2,pubkeys[j],bitcoin_pubkeylen(pubkeys[j])) == 0 )
                    {
                        if ( ++valid >= M )
                            return(1);
                        j--;
                        break;
                    }
                }
            }
        }
    }
    printf("valid.%d j.%d M.%d N.%d numsigners.%d\n",valid,j,M,N,numsigners);
    return(0);
}

int32_t iguana_checklocktimeverify(struct iguana_info *coin,int64_t nLockTime,uint32_t nSequence,struct iguana_stackdata Snum)
{
    int32_t num = iguana_num(Snum);
    if ( num < 0 || (num >= 500000000 && nLockTime < 500000000) || (num < 500000000 && nLockTime >= 500000000) || nSequence == 0xffffffff || num > nLockTime )
        return(-1);
    return(0);
}

int32_t iguana_checksequenceverify(struct iguana_info *coin,int64_t nLockTime,uint32_t nSequence,struct iguana_stackdata Snum)
{
    return(0);
}

int32_t iguana_expandscript(struct iguana_info *coin,char *asmstr,int32_t maxlen,uint8_t *script,int32_t scriptlen)
{
    asmstr[0] = 0;
    
    return(0);
}

cJSON *iguana_spendasm(struct iguana_info *coin,uint8_t *spendscript,int32_t spendlen)
{
    char asmstr[IGUANA_MAXSCRIPTSIZE*2+1]; cJSON *spendasm = cJSON_CreateObject();
    iguana_expandscript(coin,asmstr,sizeof(asmstr),spendscript,spendlen);
    jaddstr(spendasm,"interpreter",asmstr);
    return(spendasm);
}

int32_t bitcoin_assembler(struct iguana_info *coin,uint8_t script[IGUANA_MAXSCRIPTSIZE],cJSON *interpreter,int32_t interpret,int64_t nLockTime,struct vin_info *V)
{
    struct bitcoin_opcode *op; cJSON *array = 0; struct iguana_interpreter STACKS,*stacks = &STACKS;
    struct iguana_stackdata args[MAX_PUBKEYS_PER_MULTISIG];
    uint8_t databuf[MAX_SCRIPT_ELEMENT_SIZE],flags,stackitems; char *asmstr,*str,*hexstr,*opname;
    int32_t c,numops,numvars,numused,numargs,i,j,k,n,len,val,datalen,extralen,errs=0;
    if ( optable == 0 )
    {
        for (i=0; i<0x100; i++)
        {
            extralen = stackitems = flags = 0;
            opname = (char *)get_opname(&stackitems,&flags,&extralen,i);
            if ( strcmp("OP_UNKNOWN",opname) != 0 )
            {
                op = calloc(1,sizeof(*op));
                HASH_ADD_KEYPTR(hh,optable,opname,strlen(opname),op);
                //printf("{%-16s %02x} ",opname,i);
                op->opcode = i;
                op->flags = flags;
                op->stackitems = stackitems;
                op->extralen = extralen;
            }
        }
        //printf("bitcoin opcodes\n");
    }
    if ( (asmstr= jstr(interpreter,"interpreter")) == 0 )
        return(-1);
    if ( (numvars= juint(interpreter,"numvars")) > 0 )
    {
        if ( (array= jarray(&n,interpreter,"args")) == 0 || (interpret != 0 && n != numvars) )
            return(-2);
    }
    str = asmstr;
    if ( interpret != 0 )
    {
        stacks = calloc(1,sizeof(*stacks) + sizeof(*stacks->stack)*2*IGUANA_MAXSTACKITEMS);
        stacks->maxstackdepth = IGUANA_MAXSTACKITEMS;
        if ( interpret > 1 )
            stacks->logarray = cJSON_CreateArray();
        if ( V->M == 0 && V->N == 0 )
            V->N = V->M = 1;
        for (i=0; i<V->N; i++)
        {
            if ( V->signers[i].siglen != 0 )
            {
                iguana_pushdata(stacks,0,V->signers[i].sig,V->signers[i].siglen);
                if ( bitcoin_pubkeylen(V->signers[i].pubkey) <= 0 )
                {
                    printf("missing pubkey.[%d]\n",i);
                    free(stacks);
                    return(-1);
                }
            }
        }
        for (i=0; i<V->N; i++)
        {
            if ( V->signers[i].siglen != 0 )
                iguana_pushdata(stacks,0,V->signers[i].pubkey,bitcoin_pubkeylen(V->signers[i].pubkey));
        }
        if ( V->extras != 0 )
        {
            if ( (n= cJSON_GetArraySize(V->extras)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (hexstr= jstr(jitem(V->extras,i),0)) != 0 && (len= is_hexstr(hexstr,0)) > 0 )
                    {
                        len >>= 1;
                        decode_hex(databuf,len,hexstr);
                        iguana_pushdata(stacks,0,databuf,len);
                    }
                }
            }
        }
    } else memset(stacks,0,sizeof(*stacks));
    stacks->lastpath[0] = 1;
    k = numops = numused = 0;
    script[k] = 0;
    while ( (c= *str++) != 0 )
    {
        while ( is_delim(c) != 0 )
            continue;
        if ( c == '/' && *str == '/' ) // support //
            break;
        else if ( c == '-' && *str == '1' && is_delim(str[1]) != 0 )
        {
            script[k++] = IGUANA_OP_1NEGATE, str += 3; // OP_1NEGATE;
            iguana_pushdata(stacks,-1,0,0);
            continue;
        }
        else if ( c == '%' && *str == 's' )
        {
            str++;
            if ( numused < numvars && (hexstr= jstr(jitem(array,numused++),0)) != 0 )
            {
                if ( (n= iguana_dataparse(stacks,script,k,str,&len)) > 0 )
                {
                    k = n;
                    continue;
                }
            }
            printf("dataparse error.%d, numused.%d >= numvars.%d\n",n,numused,numvars);
            errs++;
            break;
        }
        else
        {
            str--;
            if ( (n= iguana_dataparse(stacks,script,k,str,&len)) > 0 )
            {
                k = n;
                str += len;
                continue;
            }
            else if ( n < 0 )
            {
                errs++;
                break;
            }
        }
        for (j=0; j<32; j++)
            if ( is_delim(str[j]) != 0 )
                break;
        if ( j == 32 )
        {
            printf("too long opcode.%s at offset.%ld\n",str,(long)str-(long)asmstr);
            errs++;
            break;
        }
        HASH_FIND(hh,optable,str,j,op);
        str += j;
        if ( op != 0 )
        {
            if ( numargs > 0 )
            {
                for (i=0; i<numargs; i++)
                    if ( args[i].U.data != 0 )
                        free(args[i].U.data);
            }
            memset(args,0,sizeof(args));
            numargs = 0;
            if ( op->opcode <= IGUANA_OP_16 || ++numops <= MAX_OPS_PER_SCRIPT )
            {
                script[k++] = op->opcode;
                if ( stacks->logarray )
                    jaddistr(stacks->logarray,(char *)op->hh.key);
                if ( (op->flags & IGUANA_ALWAYSILLEGAL) != 0 )
                {
                    printf("disabled opcode.%s at offset.%ld\n",str,(long)str-(long)asmstr);
                    errs++;
                    break;
                }
                else if ( op->extralen > 0 )
                {
                    if ( is_delim(*str) != 0 )
                        str++;
                    if ( is_hexstr(str,0) != (op->extralen<<1) )
                    {
                        printf("expected extralen.%d of hex, got.(%s) at offset.%ld\n",op->extralen,str,(long)str-(long)asmstr);
                        errs++;
                        break;
                    }
                    decode_hex(&script[k],op->extralen,str), str += (op->extralen << 1);
                    if ( op->extralen == 1 )
                        iguana_pushdata(stacks,script[k],0,0);
                    else if ( op->extralen == 2 )
                        iguana_pushdata(stacks,script[k] + ((uint32_t)script[k]<<8),0,0);
                    k += op->extralen;
                    continue;
                }
                if ( interpret == 0 || V == 0 )
                    continue;
                if ( (numargs= op->stackitems) > 0 )
                {
                    if ( stacks->stackdepth < op->stackitems )
                    {
                        printf("stackdepth.%d needed.%d (%s) at offset.%ld\n",stacks->stackdepth,op->stackitems,str,(long)str-(long)asmstr);
                        errs++;
                        break;
                    }
                    for (i=0; i<numargs; i++)
                        args[numargs - 1 - i] = iguana_pop(stacks);
                }
                if ( (op->flags & IGUANA_NOPFLAG) != 0 )
                    continue;
                if ( (op->flags & IGUANA_CONTROLFLAG) != 0 )
                {
                    switch ( op->opcode )
                    {
                        case IGUANA_OP_IF: case IGUANA_OP_NOTIF:
                            if ( stacks->ifdepth >= IGUANA_MAXSTACKDEPTH )
                            {
                                printf("ifdepth.%d >= MAXSTACKDEPTH.%d\n",stacks->ifdepth,IGUANA_MAXSTACKDEPTH);
                                errs++;
                            }
                            else
                            {
                                if ( iguana_isnonz(args[0]) == (op->opcode == IGUANA_OP_IF) )
                                    val = 1;
                                else val = -1;
                                stacks->lastpath[++stacks->ifdepth] = val;
                            }
                            break;
                        case IGUANA_OP_ELSE:
                            if ( stacks->ifdepth <= stacks->elsedepth )
                            {
                                printf("unhandled opcode.%02x stacks->ifdepth %d <= %d stacks->elsedepth\n",op->opcode,stacks->ifdepth,stacks->elsedepth);
                                errs++;
                            }
                            stacks->lastpath[stacks->ifdepth] *= -1;
                            break;
                        case IGUANA_OP_ENDIF:
                            if ( stacks->ifdepth <= 0 )
                            {
                                printf("endif without if offset.%ld\n",(long)str-(long)asmstr);
                                errs++;
                            }
                            stacks->ifdepth--;
                            break;
                        case IGUANA_OP_VERIFY: break;
                        case IGUANA_OP_RETURN:
                            iguana_pushdata(stacks,0,0,0);
                            errs++;
                            break;
                    }
                    if ( errs != 0 )
                        break;
                    continue;
                }
                if ( stacks->lastpath[stacks->ifdepth] < 0 )
                {
                    if ( stacks->logarray )
                        jaddistr(stacks->logarray,"skip");
                    continue;
                }
                else if ( (op->flags & IGUANA_EXECUTIONILLEGAL) != 0 )
                {
                    printf("opcode not allowed to run.%s at %ld\n",(char *)op->hh.key,(long)str-(long)asmstr);
                    errs++;
                    break;
                }
                else if ( op->opcode == IGUANA_OP_EQUALVERIFY || op->opcode == IGUANA_OP_EQUAL )
                {
                    if ( iguana_cmp(&args[0],&args[1]) == 0 )
                        iguana_pushdata(stacks,1,0,0);
                    else iguana_pushdata(stacks,0,0,0);
                }
                else if ( (op->flags & IGUANA_CRYPTOFLAG) != 0 )
                {
                    uint8_t rmd160[20]; bits256 hash;
                    datalen = iguana_databuf(databuf,args[0]);
                    switch ( op->opcode )
                    {
                        case IGUANA_OP_RIPEMD160:
                            calc_rmd160(0,rmd160,databuf,datalen);
                            iguana_pushdata(stacks,0,rmd160,sizeof(rmd160));
                            break;
                        case IGUANA_OP_SHA1:
                            calc_sha1(0,rmd160,databuf,datalen);
                            iguana_pushdata(stacks,0,rmd160,sizeof(rmd160));
                            break;
                        case IGUANA_OP_HASH160:
                            calc_rmd160_sha256(rmd160,databuf,datalen);
                            iguana_pushdata(stacks,0,rmd160,sizeof(rmd160));
                            break;
                        case IGUANA_OP_SHA256:
                            vcalc_sha256(0,hash.bytes,databuf,datalen);
                            iguana_pushdata(stacks,0,hash.bytes,sizeof(hash));
                            break;
                        case IGUANA_OP_HASH256:
                            hash = bits256_doublesha256(0,databuf,datalen);
                            iguana_pushdata(stacks,0,hash.bytes,sizeof(hash));
                            break;
                        case IGUANA_OP_CHECKSIG: case IGUANA_OP_CHECKSIGVERIFY:
                            iguana_pushdata(stacks,iguana_checksig(coin,args[0],args[1],V->sigtxid),0,0);
                            break;
                        case IGUANA_OP_CHECKMULTISIG: case IGUANA_OP_CHECKMULTISIGVERIFY:
                            iguana_pushdata(stacks,iguana_checkmultisig(coin,stacks,V->M,V->N,V->sigtxid),0,0);
                            break;
                    }
                }
                else if ( op->opcode == IGUANA_OP_CHECKLOCKTIMEVERIFY ) // former OP_NOP2
                {
                    if ( iguana_checklocktimeverify(coin,nLockTime,V->sequence,args[0]) < 0 )
                    {
                        iguana_stack(stacks,args,1,"0","");
                        errs++;
                        break;
                    }
                    iguana_stack(stacks,args,1,"0","");
                    continue;
                }
                else if ( op->opcode == IGUANA_OP_CHECKSEQUENCEVERIFY ) // former OP_NOP3
                {
                    if ( iguana_checksequenceverify(coin,nLockTime,V->sequence,args[0]) < 0 )
                    {
                        iguana_stack(stacks,args,1,"0","");
                        errs++;
                        break;
                    }
                    iguana_stack(stacks,args,1,"0","");
                    continue;
                }
                else if ( (op->flags & IGUANA_STACKFLAG) != 0 )
                {
                    if ( op->opcode == IGUANA_OP_PICK || op->opcode == IGUANA_OP_ROLL )
                    {
                        if ( interpret != 0 && stacks->stackdepth < (val= iguana_num(args[0])) )
                        {
                            printf("stack not deep enough %d < %d\n",stacks->stackdepth,iguana_num(args[0]));
                            errs++;
                            break;
                        }
                        if ( op->opcode == IGUANA_OP_PICK )
                        {
                            stacks->stack[stacks->stackdepth] = iguana_clone(stacks->stack[stacks->stackdepth - 1 - val]);
                            stacks->stackdepth++;
                        }
                        else
                        {
                            args[1] = stacks->stack[stacks->stackdepth - 1 - val];
                            for (i=stacks->stackdepth-1-val; i<stacks->stackdepth-1; i++)
                                stacks->stack[i] = stacks->stack[i+1];
                            stacks->stack[stacks->stackdepth - 1] = args[1];
                        }
                    }
                    else
                    {
                        switch ( op->opcode )
                        {
                            case IGUANA_OP_TOALTSTACK:
                                if ( stacks->altstackdepth < stacks->maxstackdepth )
                                {
                                    iguana_altpush(stacks,args[0]);
                                    memset(&args[0],0,sizeof(args[0]));
                                }
                                else
                                {
                                    printf("altstack overflow %d vs %d\n",stacks->altstackdepth,stacks->maxstackdepth);
                                    errs++;
                                }
                                break;
                            case IGUANA_OP_FROMALTSTACK:
                                stacks->stack[stacks->stackdepth++] = iguana_altpop(stacks);
                                break;
                            case IGUANA_OP_DEPTH: iguana_pushdata(stacks,stacks->stackdepth,0,0); break;
                            case IGUANA_OP_DROP: case IGUANA_OP_2DROP: break;
                            case IGUANA_OP_3DUP:  iguana_stack(stacks,args,3,"012","012"); break;
                            case IGUANA_OP_2OVER: iguana_stack(stacks,args,4,"0123","01"); break;
                            case IGUANA_OP_2ROT:  iguana_stack(stacks,args,6,"234501",""); break;
                            case IGUANA_OP_2SWAP: iguana_stack(stacks,args,4,"2301",""); break;
                            case IGUANA_OP_IFDUP:
                                if ( iguana_isnonz(args[0]) != 0 )
                                    iguana_stack(stacks,args,0,"","0");
                                iguana_stack(stacks,args,1,"0","");
                                break;
                            case IGUANA_OP_DUP:   iguana_stack(stacks,args,1,"0","0"); break;
                            case IGUANA_OP_2DUP:  iguana_stack(stacks,args,2,"01","01"); break;
                            case IGUANA_OP_NIP:
                                if ( args[0].U.data != 0 )
                                    free(args[0].U.data);
                                iguana_stack(stacks,args,2,"1","");
                                break;
                            case IGUANA_OP_OVER:  iguana_stack(stacks,args,2,"01","0"); break;
                            case IGUANA_OP_ROT:   iguana_stack(stacks,args,3,"120",""); break;
                            case IGUANA_OP_SWAP:  iguana_stack(stacks,args,2,"10",""); break;
                            case IGUANA_OP_TUCK:  iguana_stack(stacks,args,2,"10","1"); break;
                        }
                    }
                }
                else if ( (op->flags & IGUANA_MATHFLAG) != 0 )
                {
                    int32_t numA,numB,numC;
                    for (i=0; i<op->stackitems; i++)
                    {
                        if ( args[i].size != sizeof(int32_t) )
                            break;
                        if ( i == 0 )
                            numA = iguana_num(args[i]);
                        else if ( i == 1 )
                            numB = iguana_num(args[i]);
                        else if ( i == 2 )
                            numC = iguana_num(args[i]);
                    }
                    if ( i != op->stackitems )
                    {
                        printf("math script non-int32_t arg[%d] of %d\n",i,op->stackitems);
                        errs++;
                        break;
                    }
                    switch ( op->opcode )
                    {
                        case IGUANA_OP_1ADD:   iguana_pushdata(stacks,numA + 1,0,0); break;
                        case IGUANA_OP_1SUB:   iguana_pushdata(stacks,numA - 1,0,0); break;
                        case IGUANA_OP_NEGATE: iguana_pushdata(stacks,-numA,0,0); break;
                        case IGUANA_OP_ABS:    iguana_pushdata(stacks,numA<0?-numA:numA,0,0); break;
                        case IGUANA_OP_NOT:    iguana_pushdata(stacks,numA == 0,0,0); break;
                        case IGUANA_OP_0NOTEQUAL: iguana_pushdata(stacks,numA != 0,0,0); break;
                        case IGUANA_OP_ADD:    iguana_pushdata(stacks,numA + numB,0,0); break;
                        case IGUANA_OP_SUB:    iguana_pushdata(stacks,numA - numB,0,0); break;
                        case IGUANA_OP_BOOLAND:iguana_pushdata(stacks,numA != 0 && numB != 0,0,0); break;
                        case IGUANA_OP_BOOLOR: iguana_pushdata(stacks,numA != 0 || numB != 0,0,0); break;
                        case IGUANA_OP_NUMEQUAL: case IGUANA_OP_NUMEQUALVERIFY:
                                               iguana_pushdata(stacks,numA == numB,0,0); break;
                        case IGUANA_OP_NUMNOTEQUAL:iguana_pushdata(stacks,numA != numB,0,0); break;
                        case IGUANA_OP_LESSTHAN:   iguana_pushdata(stacks,numA < numB,0,0); break;
                        case IGUANA_OP_GREATERTHAN:iguana_pushdata(stacks,numA > numB,0,0); break;
                        case IGUANA_OP_LESSTHANOREQUAL:iguana_pushdata(stacks,numA <= numB,0,0); break;
                        case IGUANA_OP_GREATERTHANOREQUAL:iguana_pushdata(stacks,numA >= numB,0,0); break;
                        case IGUANA_OP_MIN: iguana_pushdata(stacks,numA <= numB ? numA : numB,0,0); break;
                        case IGUANA_OP_MAX: iguana_pushdata(stacks,numA >= numB ? numA : numB,0,0); break;
                        case IGUANA_OP_WITHIN: iguana_pushdata(stacks,numB <= numA && numA < numC,0,0); break;
                    }
                }
                else if ( op->opcode == IGUANA_OP_CODESEPARATOR )
                {
                    if ( stacks != 0 )
                        stacks->codeseparator = k;
                    continue;
                }
                else
                {
                    printf("unhandled opcode.%02x (%s)\n",op->opcode,str);
                    errs++;
                    break;
                }
                if ( (op->flags & IGUANA_POSTVERIFY) != 0 )
                {
                    if ( stacks->stackdepth < 1 )
                    {
                        printf("empty stack at offset.%ld\n",(long)str - (long)asmstr);
                        errs++;
                        break;
                    }
                    if ( iguana_isnonz(stacks->stack[stacks->stackdepth-1]) == 0 )
                        break;
                }
            }
            else
            {
                printf("too many ops opcode.%s at offset.%ld\n",str,(long)str - (long)asmstr);
                errs++;
                break;
            }
        }
        else
        {
            printf("unknown opcode.%s at offset.%ld\n",str,(long)str - (long)asmstr);
            errs++;
            break;
        }
    }
    if ( stacks != &STACKS )
    {
        if ( jobj(interpreter,"result") != 0 )
            jdelete(interpreter,"result");
        if ( stacks->stackdepth <= 0 )
        {
            errs++;
            printf("empty stack error\n");
            jadd(interpreter,"result",jfalse());
        }
        else if ( iguana_isnonz(stacks->stack[--stacks->stackdepth]) != 0 )
        {
            printf("Evaluate true, depth.%d\n",stacks->stackdepth);
            jadd(interpreter,"result",jtrue());
        }
        if ( stacks->logarray != 0 )
            printf("LOG.(%s)\n",jprint(stacks->logarray,1));
        if ( numargs > 0 )
        {
            for (i=0; i<numargs; i++)
                if ( args[i].U.data != 0 )
                    free(args[i].U.data);
        }
        free(stacks);
    }
    if ( errs == 0 )
        return(k);
    else return(-errs);
}


#ifdef reference
/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.  There are no loops.
 */
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))
static inline void popstack(vector<valtype>& stack)
{
    if (stack.empty())
        throw runtime_error("popstack(): stack empty");
    stack.pop_back();
}

bool static IsCompressedOrUncompressedPubKey(const valtype &vchPubKey) {
    if (vchPubKey.size() < 33) {
        //  Non-canonical public key: too short
        return false;
    }
    if (vchPubKey[0] == 0x04) {
        if (vchPubKey.size() != 65) {
            //  Non-canonical public key: invalid length for uncompressed key
            return false;
        }
    } else if (vchPubKey[0] == 0x02 || vchPubKey[0] == 0x03) {
        if (vchPubKey.size() != 33) {
            //  Non-canonical public key: invalid length for compressed key
            return false;
        }
    } else {
        //  Non-canonical public key: neither compressed nor uncompressed
        return false;
    }
    return true;
}

/**
 * A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 *
 * This function is consensus-critical since BIP66.
 */
bool static IsValidSignatureEncoding(const std::vector<unsigned char> &sig) {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)
    
    // Minimum and maximum size constraints.
    if (sig.size() < 9) return false;
    if (sig.size() > 73) return false;
    
    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) return false;
    
    // Make sure the length covers the entire signature.
    if (sig[1] != sig.size() - 3) return false;
    
    // Extract the length of the R element.
    unsigned int lenR = sig[3];
    
    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= sig.size()) return false;
    
    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];
    
    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)(lenR + lenS + 7) != sig.size()) return false;
    
    // Check whether the R element is an integer.
    if (sig[2] != 0x02) return false;
    
    // Zero-length integers are not allowed for R.
    if (lenR == 0) return false;
    
    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) return false;
    
    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;
    
    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) return false;
    
    // Zero-length integers are not allowed for S.
    if (lenS == 0) return false;
    
    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) return false;
    
    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;
    
    return true;
}

bool static IsLowDERSignature(const valtype &vchSig, ScriptError* serror) {
    if (!IsValidSignatureEncoding(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }
    std::vector<unsigned char> vchSigCopy(vchSig.begin(), vchSig.begin() + vchSig.size() - 1);
    if (!CPubKey::CheckLowS(vchSigCopy)) {
        return set_error(serror, SCRIPT_ERR_SIG_HIGH_S);
    }
    return true;
}

bool static IsDefinedHashtypeSignature(const valtype &vchSig) {
    if (vchSig.size() == 0) {
        return false;
    }
    unsigned char nHashType = vchSig[vchSig.size() - 1] & (~(SIGHASH_ANYONECANPAY));
    if (nHashType < SIGHASH_ALL || nHashType > SIGHASH_SINGLE)
        return false;
    
    return true;
}

bool CheckSignatureEncoding(const vector<unsigned char> &vchSig, unsigned int flags, ScriptError* serror) {
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (vchSig.size() == 0) {
        return true;
    }
    if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !IsValidSignatureEncoding(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    } else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !IsLowDERSignature(vchSig, serror)) {
        // serror is set
        return false;
    } else if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsDefinedHashtypeSignature(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
    }
    return true;
}

bool static CheckPubKeyEncoding(const valtype &vchSig, unsigned int flags, ScriptError* serror) {
    if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsCompressedOrUncompressedPubKey(vchSig)) {
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    }
    return true;
}

bool static CheckMinimalPush(const valtype& data, opcodetype opcode) {
    if (data.size() == 0) {
        // Could have used OP_0.
        return opcode == OP_0;
    } else if (data.size() == 1 && data[0] >= 1 && data[0] <= 16) {
        // Could have used OP_1 .. OP_16.
        return opcode == OP_1 + (data[0] - 1);
    } else if (data.size() == 1 && data[0] == 0x81) {
        // Could have used OP_1NEGATE.
        return opcode == OP_1NEGATE;
    } else if (data.size() <= 75) {
        // Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
        return opcode == data.size();
    } else if (data.size() <= 255) {
        // Could have used OP_PUSHDATA.
        return opcode == OP_PUSHDATA1;
    } else if (data.size() <= 65535) {
        // Could have used OP_PUSHDATA2.
        return opcode == OP_PUSHDATA2;
    }
    return true;
}

bool EvalScript(vector<vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror)
{
    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    static const CScriptNum bnFalse(0);
    static const CScriptNum bnTrue(1);
    static const valtype vchFalse(0);
    static const valtype vchZero(0);
    static const valtype vchTrue(1, 1);
    
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    opcodetype opcode;
    valtype vchPushValue;
    vector<bool> vfExec;
    vector<valtype> altstack;
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    if (script.size() > 10000)
        return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
    int nOpCount = 0;
    bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
    
    try
    {
        while (pc < pend)
        {
            bool fExec = !count(vfExec.begin(), vfExec.end(), false);
            
            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue))
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
            
            // Note how OP_RESERVED does not count towards the opcode limit.
            if (opcode > OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT)
                return set_error(serror, SCRIPT_ERR_OP_COUNT);
            
            if (opcode == OP_CAT ||
                opcode == OP_SUBSTR ||
                opcode == OP_LEFT ||
                opcode == OP_RIGHT ||
                opcode == OP_INVERT ||
                opcode == OP_AND ||
                opcode == OP_OR ||
                opcode == OP_XOR ||
                opcode == OP_2MUL ||
                opcode == OP_2DIV ||
                opcode == OP_MUL ||
                opcode == OP_DIV ||
                opcode == OP_MOD ||
                opcode == OP_LSHIFT ||
                opcode == OP_RSHIFT)
                return set_error(serror, SCRIPT_ERR_DISABLED_OPCODE); // Disabled opcodes.
            
            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4) {
                if (fRequireMinimal && !CheckMinimalPush(vchPushValue, opcode)) {
                    return set_error(serror, SCRIPT_ERR_MINIMALDATA);
                }
                stack.push_back(vchPushValue);
            } else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
                switch (opcode)
            {
                    //
                    // Push value
                    //
                case OP_1NEGATE:
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                {
                    // ( -- value)
                    CScriptNum bn((int)opcode - (int)(OP_1 - 1));
                    stack.push_back(bn.getvch());
                    // The result of these opcodes should always be the minimal way to push the data
                    // they push, so no need for a CheckMinimalPush here.
                }
                    break;
                    
                    
                    //
                    // Control
                    //
                case OP_NOP:
                    break;
                    
                case OP_CHECKLOCKTIMEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                        // not enabled; treat as a NOP2
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }
                        break;
                    }
                    
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    
                    // Note that elsewhere numeric opcodes are limited to
                    // operands in the range -2**31+1 to 2**31-1, however it is
                    // legal for opcodes to produce results exceeding that
                    // range. This limitation is implemented by CScriptNum's
                    // default 4-byte limit.
                    //
                    // If we kept to that limit we'd have a year 2038 problem,
                    // even though the nLockTime field in transactions
                    // themselves is uint32 which only becomes meaningless
                    // after the year 2106.
                    //
                    // Thus as a special case we tell CScriptNum to accept up
                    // to 5-byte bignums, which are good until 2**39-1, well
                    // beyond the 2**32-1 limit of the nLockTime field itself.
                    const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);
                    
                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKLOCKTIMEVERIFY.
                    if (nLockTime < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);
                    
                    // Actually compare the specified lock time with the transaction.
                    if (!checker.CheckLockTime(nLockTime))
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
                    
                    break;
                }
                    
                case OP_NOP1: case OP_NOP3: case OP_NOP4: case OP_NOP5:
                case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
                {
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                }
                    break;
                    
                case OP_IF:
                case OP_NOTIF:
                {
                    // <expression> if [statements] [else [statements]] endif
                    bool fValue = false;
                    if (fExec)
                    {
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        valtype& vch = stacktop(-1);
                        fValue = CastToBool(vch);
                        if (opcode == OP_NOTIF)
                            fValue = !fValue;
                        popstack(stack);
                    }
                    vfExec.push_back(fValue);
                }
                    break;
                    
                case OP_ELSE:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.back() = !vfExec.back();
                }
                    break;
                    
                case OP_ENDIF:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.pop_back();
                }
                    break;
                    
                case OP_VERIFY:
                {
                    // (true -- ) or
                    // (false -- false) and return
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    bool fValue = CastToBool(stacktop(-1));
                    if (fValue)
                        popstack(stack);
                    else
                        return set_error(serror, SCRIPT_ERR_VERIFY);
                }
                    break;
                    
                case OP_RETURN:
                {
                    return set_error(serror, SCRIPT_ERR_OP_RETURN);
                }
                    break;
                    
                    
                    //
                    // Stack ops
                    //
                case OP_TOALTSTACK:
                {
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    altstack.push_back(stacktop(-1));
                    popstack(stack);
                }
                    break;
                    
                case OP_FROMALTSTACK:
                {
                    if (altstack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
                    stack.push_back(altstacktop(-1));
                    popstack(altstack);
                }
                    break;
                    
                case OP_2DROP:
                {
                    // (x1 x2 -- )
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                    popstack(stack);
                }
                    break;
                    
                case OP_2DUP:
                {
                    // (x1 x2 -- x1 x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-2);
                    valtype vch2 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                    break;
                    
                case OP_3DUP:
                {
                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-3);
                    valtype vch2 = stacktop(-2);
                    valtype vch3 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                    stack.push_back(vch3);
                }
                    break;
                    
                case OP_2OVER:
                {
                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-4);
                    valtype vch2 = stacktop(-3);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                    break;
                    
                case OP_2ROT:
                {
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if (stack.size() < 6)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-6);
                    valtype vch2 = stacktop(-5);
                    stack.erase(stack.end()-6, stack.end()-4);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                    break;
                    
                case OP_2SWAP:
                {
                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-4), stacktop(-2));
                    swap(stacktop(-3), stacktop(-1));
                }
                    break;
                    
                case OP_IFDUP:
                {
                    // (x - 0 | x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    if (CastToBool(vch))
                        stack.push_back(vch);
                }
                    break;
                    
                case OP_DEPTH:
                {
                    // -- stacksize
                    CScriptNum bn(stack.size());
                    stack.push_back(bn.getvch());
                }
                    break;
                    
                case OP_DROP:
                {
                    // (x -- )
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                }
                    break;
                    
                case OP_DUP:
                {
                    // (x -- x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.push_back(vch);
                }
                    break;
                    
                case OP_NIP:
                {
                    // (x1 x2 -- x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    stack.erase(stack.end() - 2);
                }
                    break;
                    
                case OP_OVER:
                {
                    // (x1 x2 -- x1 x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-2);
                    stack.push_back(vch);
                }
                    break;
                    
                case OP_PICK:
                case OP_ROLL:
                {
                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    int n = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                    popstack(stack);
                    if (n < 0 || n >= (int)stack.size())
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-n-1);
                    if (opcode == OP_ROLL)
                        stack.erase(stack.end()-n-1);
                    stack.push_back(vch);
                }
                    break;
                    
                case OP_ROT:
                {
                    // (x1 x2 x3 -- x2 x3 x1)
                    //  x2 x1 x3  after first swap
                    //  x2 x3 x1  after second swap
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-3), stacktop(-2));
                    swap(stacktop(-2), stacktop(-1));
                }
                    break;
                    
                case OP_SWAP:
                {
                    // (x1 x2 -- x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-2), stacktop(-1));
                }
                    break;
                    
                case OP_TUCK:
                {
                    // (x1 x2 -- x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.insert(stack.end()-2, vch);
                }
                    break;
                    
                    
                case OP_SIZE:
                {
                    // (in -- in size)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1).size());
                    stack.push_back(bn.getvch());
                }
                    break;
                    
                    
                    //
                    // Bitwise logic
                    //
                case OP_EQUAL:
                case OP_EQUALVERIFY:
                    //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                {
                    // (x1 x2 - bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch1 = stacktop(-2);
                    valtype& vch2 = stacktop(-1);
                    bool fEqual = (vch1 == vch2);
                    // OP_NOTEQUAL is disabled because it would be too easy to say
                    // something like n != 1 and have some wiseguy pass in 1 with extra
                    // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                    //if (opcode == OP_NOTEQUAL)
                    //    fEqual = !fEqual;
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fEqual ? vchTrue : vchFalse);
                    if (opcode == OP_EQUALVERIFY)
                    {
                        if (fEqual)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_EQUALVERIFY);
                    }
                }
                    break;
                    
                    
                    //
                    // Numeric
                    //
                case OP_1ADD:
                case OP_1SUB:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                {
                    // (in -- out)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1), fRequireMinimal);
                    switch (opcode)
                    {
                        case OP_1ADD:       bn += bnOne; break;
                        case OP_1SUB:       bn -= bnOne; break;
                        case OP_NEGATE:     bn = -bn; break;
                        case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                        case OP_NOT:        bn = (bn == bnZero); break;
                        case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                        default:            assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    stack.push_back(bn.getvch());
                }
                    break;
                    
                case OP_ADD:
                case OP_SUB:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMEQUALVERIFY:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-2), fRequireMinimal);
                    CScriptNum bn2(stacktop(-1), fRequireMinimal);
                    CScriptNum bn(0);
                    switch (opcode)
                    {
                        case OP_ADD:
                            bn = bn1 + bn2;
                            break;
                            
                        case OP_SUB:
                            bn = bn1 - bn2;
                            break;
                            
                        case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                        case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                        case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                        case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                        case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                        case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                        case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                        case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                        case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                        case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                        case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                        default:                     assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(bn.getvch());
                    
                    if (opcode == OP_NUMEQUALVERIFY)
                    {
                        if (CastToBool(stacktop(-1)))
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_NUMEQUALVERIFY);
                    }
                }
                    break;
                    
                case OP_WITHIN:
                {
                    // (x min max -- out)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-3), fRequireMinimal);
                    CScriptNum bn2(stacktop(-2), fRequireMinimal);
                    CScriptNum bn3(stacktop(-1), fRequireMinimal);
                    bool fValue = (bn2 <= bn1 && bn1 < bn3);
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fValue ? vchTrue : vchFalse);
                }
                    break;
                    
                    
                    //
                    // Crypto
                    //
                case OP_RIPEMD160:
                case OP_SHA1:
                case OP_SHA256:
                case OP_HASH160:
                case OP_HASH256:
                {
                    // (in -- hash)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch = stacktop(-1);
                    valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
                    if (opcode == OP_RIPEMD160)
                        CRIPEMD160().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    else if (opcode == OP_SHA1)
                        CSHA1().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    else if (opcode == OP_SHA256)
                        CSHA256().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    else if (opcode == OP_HASH160)
                        CHash160().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    else if (opcode == OP_HASH256)
                        CHash256().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    popstack(stack);
                    stack.push_back(vchHash);
                }
                    break;
                    
                case OP_CODESEPARATOR:
                {
                    // Hash starts after the code separator
                    pbegincodehash = pc;
                }
                    break;
                    
                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                {
                    // (sig pubkey -- bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    
                    valtype& vchSig    = stacktop(-2);
                    valtype& vchPubKey = stacktop(-1);
                    
                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);
                    
                    // Drop the signature, since there's no way for a signature to sign itself
                    scriptCode.FindAndDelete(CScript(vchSig));
                    
                    if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, serror)) {
                        //serror is set
                        return false;
                    }
                    bool fSuccess = checker.CheckSig(vchSig, vchPubKey, scriptCode);
                    
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fSuccess ? vchTrue : vchFalse);
                    if (opcode == OP_CHECKSIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKSIGVERIFY);
                    }
                }
                    break;
                    
                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
                    // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
                    
                    int i = 1;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    
                    int nKeysCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                    if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG)
                        return set_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
                    nOpCount += nKeysCount;
                    if (nOpCount > MAX_OPS_PER_SCRIPT)
                        return set_error(serror, SCRIPT_ERR_OP_COUNT);
                    int ikey = ++i;
                    i += nKeysCount;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    
                    int nSigsCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                    if (nSigsCount < 0 || nSigsCount > nKeysCount)
                        return set_error(serror, SCRIPT_ERR_SIG_COUNT);
                    int isig = ++i;
                    i += nSigsCount;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    
                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);
                    
                    // Drop the signatures, since there's no way for a signature to sign itself
                    for (int k = 0; k < nSigsCount; k++)
                    {
                        valtype& vchSig = stacktop(-isig-k);
                        scriptCode.FindAndDelete(CScript(vchSig));
                    }
                    
                    bool fSuccess = true;
                    while (fSuccess && nSigsCount > 0)
                    {
                        valtype& vchSig    = stacktop(-isig);
                        valtype& vchPubKey = stacktop(-ikey);
                        
                        // Note how this makes the exact order of pubkey/signature evaluation
                        // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                        // See the script_(in)valid tests for details.
                        if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, serror)) {
                            // serror is set
                            return false;
                        }
                        
                        // Check signature
                        bool fOk = checker.CheckSig(vchSig, vchPubKey, scriptCode);
                        
                        if (fOk) {
                            isig++;
                            nSigsCount--;
                        }
                        ikey++;
                        nKeysCount--;
                        
                        // If there are more signatures left than keys left,
                        // then too many signatures have failed. Exit early,
                        // without checking any further signatures.
                        if (nSigsCount > nKeysCount)
                            fSuccess = false;
                    }
                    
                    // Clean up stack of actual arguments
                    while (i-- > 1)
                        popstack(stack);
                    
                    // A bug causes CHECKMULTISIG to consume one extra argument
                    // whose contents were not checked in any way.
                    //
                    // Unfortunately this is a potential source of mutability,
                    // so optionally verify it is exactly equal to zero prior
                    // to removing it from the stack.
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    if ((flags & SCRIPT_VERIFY_NULLDUMMY) && stacktop(-1).size())
                        return set_error(serror, SCRIPT_ERR_SIG_NULLDUMMY);
                    popstack(stack);
                    
                    stack.push_back(fSuccess ? vchTrue : vchFalse);
                    
                    if (opcode == OP_CHECKMULTISIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
                    }
                }
                    break;
                    
                default:
                    return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            }
            
            // Size limits
            if (stack.size() + altstack.size() > 1000)
                return set_error(serror, SCRIPT_ERR_STACK_SIZE);
        }
    }
    catch (...)
    {
        return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    }
    
    if (!vfExec.empty())
        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
    
    return set_success(serror);
}

namespace {
    
    /**
     * Wrapper that serializes like CTransaction, but with the modifications
     *  required for the signature hash done in-place
     */
    class CTransactionSignatureSerializer {
    private:
        const CTransaction &txTo;  //! reference to the spending transaction (the one being serialized)
        const CScript &scriptCode; //! output script being consumed
        const unsigned int nIn;    //! input index of txTo being signed
        const bool fAnyoneCanPay;  //! whether the hashtype has the SIGHASH_ANYONECANPAY flag set
        const bool fHashSingle;    //! whether the hashtype is SIGHASH_SINGLE
        const bool fHashNone;      //! whether the hashtype is SIGHASH_NONE
        
    public:
        CTransactionSignatureSerializer(const CTransaction &txToIn, const CScript &scriptCodeIn, unsigned int nInIn, int nHashTypeIn) :
        txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn),
        fAnyoneCanPay(!!(nHashTypeIn & SIGHASH_ANYONECANPAY)),
        fHashSingle((nHashTypeIn & 0x1f) == SIGHASH_SINGLE),
        fHashNone((nHashTypeIn & 0x1f) == SIGHASH_NONE) {}
        
        /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
        template<typename S>
        void SerializeScriptCode(S &s, int nType, int nVersion) const {
            CScript::const_iterator it = scriptCode.begin();
            CScript::const_iterator itBegin = it;
            opcodetype opcode;
            unsigned int nCodeSeparators = 0;
            while (scriptCode.GetOp(it, opcode)) {
                if (opcode == OP_CODESEPARATOR)
                    nCodeSeparators++;
            }
            ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
            it = itBegin;
            while (scriptCode.GetOp(it, opcode)) {
                if (opcode == OP_CODESEPARATOR) {
                    s.write((char*)&itBegin[0], it-itBegin-1);
                    itBegin = it;
                }
            }
            if (itBegin != scriptCode.end())
                s.write((char*)&itBegin[0], it-itBegin);
        }
        
        /** Serialize an input of txTo */
        template<typename S>
        void SerializeInput(S &s, unsigned int nInput, int nType, int nVersion) const {
            // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
            if (fAnyoneCanPay)
                nInput = nIn;
            // Serialize the prevout
            ::Serialize(s, txTo.vin[nInput].prevout, nType, nVersion);
            // Serialize the script
            if (nInput != nIn)
                // Blank out other inputs' signatures
                ::Serialize(s, CScriptBase(), nType, nVersion);
            else
                SerializeScriptCode(s, nType, nVersion);
            // Serialize the nSequence
            if (nInput != nIn && (fHashSingle || fHashNone))
                // let the others update at will
                ::Serialize(s, (int)0, nType, nVersion);
            else
                ::Serialize(s, txTo.vin[nInput].nSequence, nType, nVersion);
        }
        
        /** Serialize an output of txTo */
        template<typename S>
        void SerializeOutput(S &s, unsigned int nOutput, int nType, int nVersion) const {
            if (fHashSingle && nOutput != nIn)
                // Do not lock-in the txout payee at other indices as txin
                ::Serialize(s, CTxOut(), nType, nVersion);
            else
                ::Serialize(s, txTo.vout[nOutput], nType, nVersion);
        }
        
        /** Serialize txTo */
        template<typename S>
        void Serialize(S &s, int nType, int nVersion) const {
            // Serialize nVersion
            ::Serialize(s, txTo.nVersion, nType, nVersion);
            // Serialize vin
            unsigned int nInputs = fAnyoneCanPay ? 1 : txTo.vin.size();
            ::WriteCompactSize(s, nInputs);
            for (unsigned int nInput = 0; nInput < nInputs; nInput++)
                SerializeInput(s, nInput, nType, nVersion);
            // Serialize vout
            unsigned int nOutputs = fHashNone ? 0 : (fHashSingle ? nIn+1 : txTo.vout.size());
            ::WriteCompactSize(s, nOutputs);
            for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
                SerializeOutput(s, nOutput, nType, nVersion);
            // Serialize nLockTime
            ::Serialize(s, txTo.nLockTime, nType, nVersion);
        }
    };
    
} // anon namespace

uint256 SignatureHash(const CScript& scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType, size_t* nHashedOut)
{
    static const uint256 one(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));
    if (nIn >= txTo.vin.size()) {
        //  nIn out of range
        return one;
    }
    
    // Check for invalid use of SIGHASH_SINGLE
    if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
        if (nIn >= txTo.vout.size()) {
            //  nOut out of range
            return one;
        }
    }
    
    // Wrapper to serialize only the necessary parts of the transaction being signed
    CTransactionSignatureSerializer txTmp(txTo, scriptCode, nIn, nHashType);
    
    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << nHashType;
    if (nHashedOut != NULL)
        *nHashedOut = ss.GetNumBytesHashed();
    return ss.GetHash();
}

bool TransactionSignatureChecker::VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const
{
    return pubkey.Verify(sighash, vchSig);
}

bool TransactionSignatureChecker::CheckSig(const vector<unsigned char>& vchSigIn, const vector<unsigned char>& vchPubKey,
                                           const CScript& scriptCode) const
{
    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;
    
    // Hash type is one byte tacked on to the end of the signature
    vector<unsigned char> vchSig(vchSigIn);
    if (vchSig.empty())
        return false;
    int nHashType = vchSig.back();
    vchSig.pop_back();
    
    size_t nHashed = 0;
    uint256 sighash = SignatureHash(scriptCode, *txTo, nIn, nHashType, &nHashed);
    nBytesHashed += nHashed;
    ++nSigops;
    
    if (!VerifySignature(vchSig, pubkey, sighash))
        return false;
    
    return true;
}

bool TransactionSignatureChecker::CheckLockTime(const CScriptNum& nLockTime) const
{
    // There are two kinds of nLockTime: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nLockTime < LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nLockTime being tested is the same as
    // the nLockTime in the transaction.
    if (!(
          (txTo->nLockTime <  LOCKTIME_THRESHOLD && nLockTime <  LOCKTIME_THRESHOLD) ||
          (txTo->nLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD)
          ))
        return false;
    
    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nLockTime > (int64_t)txTo->nLockTime)
        return false;
    
    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been
    // finalized by setting nSequence to maxint. The
    // transaction would be allowed into the blockchain, making
    // the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to
    // prevent this condition. Alternatively we could test all
    // inputs, but testing just this input minimizes the data
    // required to prove correct CHECKLOCKTIMEVERIFY execution.
    if (txTo->vin[nIn].IsFinal())
        return false;
    
    return true;
}


bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror)
{
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    
    if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.IsPushOnly()) {
        return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
    }
    
    vector<vector<unsigned char> > stack, stackCopy;
    if (!EvalScript(stack, scriptSig, flags, checker, serror))
        // serror is set
        return false;
    if (flags & SCRIPT_VERIFY_P2SH)
        stackCopy = stack;
    if (!EvalScript(stack, scriptPubKey, flags, checker, serror))
        // serror is set
        return false;
    if (stack.empty())
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (CastToBool(stack.back()) == false)
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    
    // Additional validation for spend-to-script-hash transactions:
    if ((flags & SCRIPT_VERIFY_P2SH) && scriptPubKey.IsPayToScriptHash())
    {
        // scriptSig must be literals-only or validation fails
        if (!scriptSig.IsPushOnly())
            return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
        
        // Restore stack.
        swap(stack, stackCopy);
        
        // stack cannot be empty here, because if it was the
        // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        // an empty stack and the EvalScript above would return false.
        assert(!stack.empty());
        
        const valtype& pubKeySerialized = stack.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stack);
        
        if (!EvalScript(stack, pubKey2, flags, checker, serror))
            // serror is set
            return false;
        if (stack.empty())
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        if (!CastToBool(stack.back()))
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    }
    
    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain).
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
        // Disallow CLEANSTACK without P2SH, as otherwise a switch CLEANSTACK->P2SH+CLEANSTACK
        // would be possible, which is not a softfork (and P2SH should be one).
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        if (stack.size() != 1) {
            return set_error(serror, SCRIPT_ERR_CLEANSTACK);
        }
    }
    
    return set_success(serror);
}
#endif

