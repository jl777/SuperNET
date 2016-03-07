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
    OP_NOP2 = 0xb1,
    OP_NOP3 = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,
    
    // template matching params
    OP_SMALLINTEGER = 0xfa,
    OP_PUBKEYS = 0xfb,
    OP_PUBKEYHASH = 0xfd,
    OP_PUBKEY = 0xfe,
    
    OP_INVALIDOPCODE = 0xff,
};

const char *get_opname(int32_t *extralenp,enum opcodetype opcode)
{
    *extralenp = 0;
    switch (opcode)
    {
            // push value
        case OP_0                      : return "0";
        case OP_PUSHDATA1              : *extralenp = 1; return "OP_PUSHDATA1";
        case OP_PUSHDATA2              : *extralenp = 2; return "OP_PUSHDATA2";
        case OP_PUSHDATA4              : *extralenp = 4; return "OP_PUSHDATA4";
        case OP_1NEGATE                : return "-1";
        case OP_RESERVED               : return "OP_RESERVED";
        case OP_1                      : return "1";
        case OP_2                      : return "2";
        case OP_3                      : return "3";
        case OP_4                      : return "4";
        case OP_5                      : return "5";
        case OP_6                      : return "6";
        case OP_7                      : return "7";
        case OP_8                      : return "8";
        case OP_9                      : return "9";
        case OP_10                     : return "10";
        case OP_11                     : return "11";
        case OP_12                     : return "12";
        case OP_13                     : return "13";
        case OP_14                     : return "14";
        case OP_15                     : return "15";
        case OP_16                     : return "16";
            
            // control
        case OP_NOP                    : return "OP_NOP";
        case OP_VER                    : return "OP_VER";
        case OP_IF                     : return "OP_IF";
        case OP_NOTIF                  : return "OP_NOTIF";
        case OP_VERIF                  : return "OP_VERIF";
        case OP_VERNOTIF               : return "OP_VERNOTIF";
        case OP_ELSE                   : return "OP_ELSE";
        case OP_ENDIF                  : return "OP_ENDIF";
        case OP_VERIFY                 : return "OP_VERIFY";
        case OP_RETURN                 : return "OP_RETURN";
            
            // stack ops
        case OP_TOALTSTACK             : return "OP_TOALTSTACK";
        case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
        case OP_2DROP                  : return "OP_2DROP";
        case OP_2DUP                   : return "OP_2DUP";
        case OP_3DUP                   : return "OP_3DUP";
        case OP_2OVER                  : return "OP_2OVER";
        case OP_2ROT                   : return "OP_2ROT";
        case OP_2SWAP                  : return "OP_2SWAP";
        case OP_IFDUP                  : return "OP_IFDUP";
        case OP_DEPTH                  : return "OP_DEPTH";
        case OP_DROP                   : return "OP_DROP";
        case OP_DUP                    : return "OP_DUP";
        case OP_NIP                    : return "OP_NIP";
        case OP_OVER                   : return "OP_OVER";
        case OP_PICK                   : return "OP_PICK";
        case OP_ROLL                   : return "OP_ROLL";
        case OP_ROT                    : return "OP_ROT";
        case OP_SWAP                   : return "OP_SWAP";
        case OP_TUCK                   : return "OP_TUCK";
            
            // splice ops
        case OP_CAT                    : return "OP_CAT";
        case OP_SUBSTR                 : return "OP_SUBSTR";
        case OP_LEFT                   : return "OP_LEFT";
        case OP_RIGHT                  : return "OP_RIGHT";
        case OP_SIZE                   : return "OP_SIZE";
            
            // bit logic
        case OP_INVERT                 : return "OP_INVERT";
        case OP_AND                    : return "OP_AND";
        case OP_OR                     : return "OP_OR";
        case OP_XOR                    : return "OP_XOR";
        case OP_EQUAL                  : return "OP_EQUAL";
        case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
        case OP_RESERVED1              : return "OP_RESERVED1";
        case OP_RESERVED2              : return "OP_RESERVED2";
            
            // numeric
        case OP_1ADD                   : return "OP_1ADD";
        case OP_1SUB                   : return "OP_1SUB";
        case OP_2MUL                   : return "OP_2MUL";
        case OP_2DIV                   : return "OP_2DIV";
        case OP_NEGATE                 : return "OP_NEGATE";
        case OP_ABS                    : return "OP_ABS";
        case OP_NOT                    : return "OP_NOT";
        case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
        case OP_ADD                    : return "OP_ADD";
        case OP_SUB                    : return "OP_SUB";
        case OP_MUL                    : return "OP_MUL";
        case OP_DIV                    : return "OP_DIV";
        case OP_MOD                    : return "OP_MOD";
        case OP_LSHIFT                 : return "OP_LSHIFT";
        case OP_RSHIFT                 : return "OP_RSHIFT";
        case OP_BOOLAND                : return "OP_BOOLAND";
        case OP_BOOLOR                 : return "OP_BOOLOR";
        case OP_NUMEQUAL               : return "OP_NUMEQUAL";
        case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
        case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
        case OP_LESSTHAN               : return "OP_LESSTHAN";
        case OP_GREATERTHAN            : return "OP_GREATERTHAN";
        case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
        case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
        case OP_MIN                    : return "OP_MIN";
        case OP_MAX                    : return "OP_MAX";
        case OP_WITHIN                 : return "OP_WITHIN";
            
            // crypto
        case OP_RIPEMD160              : return "OP_RIPEMD160";
        case OP_SHA1                   : return "OP_SHA1";
        case OP_SHA256                 : return "OP_SHA256";
        case OP_HASH160                : return "OP_HASH160";
        case OP_HASH256                : return "OP_HASH256";
        case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
        case OP_CHECKSIG               : return "OP_CHECKSIG";
        case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
        case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
        case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";
            
            // expanson
        case OP_NOP1                   : return "OP_NOP1";
        case OP_NOP2                   : return "OP_NOP2";
        case OP_NOP3                   : return "OP_NOP3";
        case OP_NOP4                   : return "OP_NOP4";
        case OP_NOP5                   : return "OP_NOP5";
        case OP_NOP6                   : return "OP_NOP6";
        case OP_NOP7                   : return "OP_NOP7";
        case OP_NOP8                   : return "OP_NOP8";
        case OP_NOP9                   : return "OP_NOP9";
        case OP_NOP10                  : return "OP_NOP10";
            
        case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";
            // Note:
            //  The template matching params OP_SMALLDATA/etc are defined in opcodetype enum
            //  as kind of implementation hack, they are *NOT* real opcodes.  If found in real
            //  Script, just let the default: case deal with them.
        default: return "OP_UNKNOWN";
    }
}

int32_t bitcoin_pubkeyspend(uint8_t *script,int32_t n,uint8_t pubkey[66])
{
    int32_t scriptlen = bitcoin_pubkeylen(pubkey);
    script[n++] = scriptlen;
    memcpy(&script[n],pubkey,scriptlen);
    n += scriptlen;
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

int32_t bitcoin_revealsecret160(uint8_t *script,int32_t n,uint8_t secret160[20])
{
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14; memcpy(&script[n],secret160,0x14); n += 0x14;
    script[n++] = SCRIPT_OP_EQUALVERIFY;
    return(n);
}

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
    script[n++] = (locktime >> 24), script[n++] = (locktime >> 16), script[n++] = (locktime >> 8), script[n++] = locktime;
    script[n++] = SCRIPT_OP_CHECKLOCKTIMEVERIFY;
    script[n++] = SCRIPT_OP_DROP;
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
    else
    {
        script[n++] = 0x4c;
        script[n++] = p2shlen;
    }
    memcpy(&script[n],p2shscript,p2shlen), n += p2shlen;
    return(n);
}

int32_t bitcoin_changescript(struct iguana_info *coin,uint8_t *changescript,int32_t n,uint64_t *changep,char *changeaddr,uint64_t inputsatoshis,uint64_t satoshis,uint64_t txfee)
{
    uint8_t addrtype,rmd160[20]; int32_t len;
    *changep = 0;
    if ( inputsatoshis >= (satoshis + txfee) )
    {
        *changep = inputsatoshis - (satoshis + txfee);
        if ( changeaddr != 0 && changeaddr[0] != 0 )
        {
            bitcoin_addr2rmd160(&addrtype,rmd160,changeaddr);
            if ( addrtype == coin->chain->pubtype )
                len = bitcoin_standardspend(changescript,0,rmd160);
            else if ( addrtype == coin->chain->p2shtype )
                len = bitcoin_standardspend(changescript,0,rmd160);
            else
            {
                printf("error with mismatched addrtype.%02x vs (%02x %02x)\n",addrtype,coin->chain->pubtype,coin->chain->p2shtype);
                return(-1);
            }
            return(len);
        }
        else printf("error no change address when there is change\n");
    }
    return(-1);
}

int32_t bitcoin_scriptsig(struct iguana_info *coin,uint8_t *script,int32_t n,const struct vin_info *vp,struct iguana_msgtx *msgtx)
{
    int32_t i,siglen;
    if ( vp->N > 1 )
        script[n++] = SCRIPT_OP_NOP;
    for (i=0; i<vp->N; i++)
    {
        if ( (siglen= vp->signers[i].siglen) != 0 )
        {
            script[n++] = siglen;
            memcpy(&script[n],vp->signers[i].sig,siglen), n += siglen;
        }
    }
    if ( vp->type == IGUANA_SCRIPT_P2SH )
    {
        printf("add p2sh script to sig\n");
        n = bitcoin_p2shscript(script,n,vp->p2shscript,vp->p2shlen);
    }
    return(n);
}

int32_t bitcoin_cltvscript(uint8_t p2shtype,char *ps2h_coinaddr,uint8_t p2sh_rmd160[20],uint8_t *script,int32_t n,char *senderaddr,char *otheraddr,uint8_t secret160[20],uint32_t locktime)
{
    // OP_IF
    //      <timestamp> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
    // OP_ELSE
    //      OP_HASH160 secret160 OP_EQUALVERIFY OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG // standard spend
    // OP_ENDIF
    uint8_t rmd160A[20],rmd160B[20],addrtypeA,addrtypeB;
    bitcoin_addr2rmd160(&addrtypeA,rmd160A,senderaddr);
    bitcoin_addr2rmd160(&addrtypeB,rmd160B,otheraddr);
    script[n++] = SCRIPT_OP_IF;
    n = bitcoin_checklocktimeverify(script,n,locktime);
    n = bitcoin_standardspend(script,n,rmd160A);
    script[n++] = SCRIPT_OP_ELSE;
    n = bitcoin_revealsecret160(script,n,secret160);
    n = bitcoin_standardspend(script,n,rmd160B);
    script[n++] = SCRIPT_OP_ENDIF;
    calc_rmd160_sha256(p2sh_rmd160,script,n);
    bitcoin_address(ps2h_coinaddr,p2shtype,p2sh_rmd160,20);
    return(n);
}

int32_t iguana_scriptgen(struct iguana_info *coin,int32_t *Mp,int32_t *nump,char *coinaddr,uint8_t *script,char *asmstr,uint8_t rmd160[20],uint8_t type,const struct vin_info *vp,int32_t txi)
{
    uint8_t addrtype; char rmd160str[41],pubkeystr[256]; int32_t plen,i,m,n,flag = 0,scriptlen = 0;
    m = n = 1;
    asmstr[0] = 0;
    if ( type == IGUANA_SCRIPT_76A988AC || type == IGUANA_SCRIPT_76AC || type == IGUANA_SCRIPT_P2SH )
    {
        if ( type == IGUANA_SCRIPT_P2SH )
            addrtype = coin->chain->p2shtype;
        else addrtype = coin->chain->pubtype;
        init_hexbytes_noT(rmd160str,rmd160,20);
        bitcoin_address(coinaddr,addrtype,rmd160,20);
    }
    switch ( type )
    {
        case IGUANA_SCRIPT_NULL:
            strcpy(asmstr,txi == 0 ? "coinbase " : "PoSbase ");
            flag++;
            coinaddr[0] = 0;
            break;
        case IGUANA_SCRIPT_76AC:
            if ( (plen= bitcoin_pubkeylen(vp->signers[0].pubkey)) < 0 )
                return(0);
            init_hexbytes_noT(pubkeystr,(uint8_t *)vp->signers[0].pubkey,plen);
            sprintf(asmstr,"OP_DUP %s OP_CHECKSIG // %s",pubkeystr,coinaddr);
            scriptlen = bitcoin_pubkeyspend(script,0,(uint8_t *)vp->signers[0].pubkey);
            //printf("[%02x] scriptlen.%d (%s)\n",vp->signers[0].pubkey[0],scriptlen,asmstr);
            break;
        case IGUANA_SCRIPT_76A988AC:
            sprintf(asmstr,"OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG // %s",rmd160str,coinaddr);
            scriptlen = bitcoin_standardspend(script,0,rmd160);
            break;
        case IGUANA_SCRIPT_P2SH:
            sprintf(asmstr,"OP_HASH160 %s OP_EQUAL // %s",rmd160str,coinaddr);
            scriptlen = bitcoin_p2shspend(script,0,rmd160);
            break;
        case IGUANA_SCRIPT_OPRETURN:
            strcpy(asmstr,"OP_RETURN ");
            flag++;
            break;
        case IGUANA_SCRIPT_3of3: m = 3, n = 3; break;
        case IGUANA_SCRIPT_2of3: m = 2, n = 3; break;
        case IGUANA_SCRIPT_1of3: m = 1, n = 3; break;
        case IGUANA_SCRIPT_2of2: m = 2, n = 2; break;
        case IGUANA_SCRIPT_1of2: m = 1, n = 2; break;
        case IGUANA_SCRIPT_MSIG: m = vp->M, n = vp->N; break;
        case IGUANA_SCRIPT_DATA:
            strcpy(asmstr,"DATA ONLY");
            flag++;
            break;
        case IGUANA_SCRIPT_STRANGE:
            strcpy(asmstr,"STRANGE SCRIPT ");
            flag++;
            break;
        default: break;//printf("unexpected script type.%d\n",type); break;
    }
    if ( n > 1 )
    {
        scriptlen = bitcoin_MofNspendscript(rmd160,script,0,vp);
        sprintf(asmstr,"%d ",m);
        for (i=0; i<n; i++)
        {
            if ( (plen= bitcoin_pubkeylen(vp->signers[i].pubkey)) > 0 )
            {
                init_hexbytes_noT(asmstr + strlen(asmstr),(uint8_t *)vp->signers[i].pubkey,plen);
                strcat(asmstr," ");
            } else strcat(asmstr,"NOPUBKEY ");
        }
        sprintf(asmstr + strlen(asmstr),"%d // M.%d of N.%d [",n,m,n);
        for (i=0; i<n; i++)
            sprintf(asmstr + strlen(asmstr),"%s%s",vp->signers[i].coinaddr,i<n-1?" ":"");
        strcat(asmstr,"]\n");
    }
    if ( flag != 0 && vp->spendlen > 0 )
        init_hexbytes_noT(asmstr + strlen(asmstr),(uint8_t *)vp->spendscript,vp->spendlen);
    *Mp = m, *nump = n;
    return(scriptlen);
}

int32_t iguana_expandscript(struct iguana_info *coin,char *asmstr,int32_t maxlen,uint8_t *script,int32_t scriptlen)
{
    asmstr[0] = 0;
    return(0);
}

int32_t _iguana_calcrmd160(struct iguana_info *coin,struct vin_info *vp)
{
    static uint8_t zero_rmd160[20];
    char hexstr[8192]; uint8_t sha256[32],*script,type; int32_t i,n,m,plen;
    vp->N = 1;
    vp->M = 1;
    type = IGUANA_SCRIPT_STRANGE;
    if ( vp->spendlen == 0 )
    {
        if ( zero_rmd160[0] == 0 )
        {
            calc_rmd160_sha256(zero_rmd160,vp->spendscript,vp->spendlen);
            //vcalc_sha256(0,sha256,vp->spendscript,vp->spendlen); // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            //calc_rmd160(0,zero_rmd160,sha256,sizeof(sha256)); // b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
            init_hexbytes_noT(hexstr,zero_rmd160,20);
            char str[65]; printf("iguana_calcrmd160 zero len %s -> %s\n",bits256_str(str,*(bits256 *)sha256),hexstr);
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
            while ( plen < vp->spendlen )
                if ( vp->spendscript[plen++] != 0x61 ) // nop
                    return(IGUANA_SCRIPT_STRANGE);
        }
        return(IGUANA_SCRIPT_76A988AC);
    }
    // 21035f1321ed17d387e4433b2fa229c53616057964af065f98bfcae2233c5108055eac
    else if ( vp->spendscript[0] > 0 && vp->spendscript[0] < 76 && vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKSIG && vp->spendscript[0] == vp->spendlen-2 )
    {
        memcpy(vp->signers[0].pubkey,&vp->spendscript[1],vp->spendscript[0]);
        calc_rmd160_sha256(vp->rmd160,vp->signers[0].pubkey,vp->spendscript[0]);
        return(IGUANA_SCRIPT_76AC);
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
            bitcoin_address(vp->signers[i].coinaddr,coin->chain->pubtype,vp->signers[i].pubkey,plen);
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
        printf("strange msig M.%d of N.%d\n",m,n);
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

int32_t iguana_calcrmd160(struct iguana_info *coin,struct vin_info *vp,uint8_t *pk_script,int32_t pk_scriptlen,bits256 debugtxid,int32_t vout,uint32_t sequence)
{
    int32_t scriptlen; uint8_t script[IGUANA_MAXSCRIPTSIZE]; char asmstr[IGUANA_MAXSCRIPTSIZE*3];
    memset(vp,0,sizeof(*vp));
    vp->vin.prev_hash = debugtxid, vp->vin.prev_vout = vout;
    vp->spendlen = pk_scriptlen;
    vp->vin.sequence = sequence;
    memcpy(vp->spendscript,pk_script,pk_scriptlen);
    if ( (vp->type= _iguana_calcrmd160(coin,vp)) >= 0 && 0 )
    {
        scriptlen = iguana_scriptgen(coin,&vp->M,&vp->N,vp->coinaddr,script,asmstr,vp->rmd160,vp->type,(const struct vin_info *)vp,vout);
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

int32_t bitcoin_scriptget(struct iguana_info *coin,int32_t *hashtypep,int32_t *sigsizep,int32_t *pubkeysizep,int32_t *suffixp,struct vin_info *vp,uint8_t *scriptsig,int32_t len,int32_t spendtype)
{
    char asmstr[IGUANA_MAXSCRIPTSIZE*3]; int32_t j,n,siglen,plen;
    j = n = 0;
    *suffixp = 0;
    *hashtypep = SIGHASH_ALL;
    while ( (siglen= scriptsig[n]) >= 70 && siglen <= 73 && n+siglen+1 < len && j < 16 )
    {
        vp->signers[j].siglen = siglen;
        memcpy(vp->signers[j].sig,&scriptsig[n+1],siglen);
        if ( j == 0 )
            *hashtypep = vp->signers[j].sig[siglen-1];
        else if ( vp->signers[j].sig[siglen-1] != *hashtypep )
        {
            printf("SIGHASH mismatch %d vs %d\n",vp->signers[j].sig[siglen-1],*hashtypep);
        }
        (*sigsizep) += siglen;
        //printf("sigsize %d [%02x]\n",*sigsizep,vp->signers[j].sig[siglen-1]);
        n += (siglen + 1);
        j++;
        if ( spendtype == 0 && j > 1 )
            spendtype = IGUANA_SCRIPT_MSIG;
    }
    vp->type = spendtype;
    j = 0;
    while ( ((plen= scriptsig[n]) == 33 || plen == 65 ) && j < 16 )
    {
        memcpy(vp->signers[j].pubkey,&scriptsig[n+1],plen);
        calc_rmd160_sha256(vp->signers[j].rmd160,vp->signers[j].pubkey,plen);
        if ( j == 0 )
            memcpy(vp->rmd160,vp->signers[j].rmd160,20);
        n += (plen + 1);
        (*pubkeysizep) += plen;
        j++;
    }
    if ( n < len && (scriptsig[n] == 0x4c || scriptsig[n] == 0x4d) )
    {
        if ( scriptsig[n] == 0x4c )
            vp->p2shlen = scriptsig[n+1], n += 2;
        else vp->p2shlen = ((uint32_t)scriptsig[n+1] + ((uint32_t)scriptsig[n+2] << 8)), n += 3;
        printf("p2sh opcode.%02x %02x %02x scriptlen.%d\n",scriptsig[n],scriptsig[n+1],scriptsig[n+2],vp->p2shlen);
        if ( vp->p2shlen < IGUANA_MAXSCRIPTSIZE )
        {
            memcpy(vp->p2shscript,&scriptsig[n],vp->p2shlen);
            n += vp->p2shlen;
            vp->type = IGUANA_SCRIPT_P2SH;
        } else vp->p2shlen = 0;
    }
    if ( n < len )
        *suffixp = (len - n);
    /*if ( len == 0 )
     {
     //  txid.(eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2).v1
     decode_hex(vp->rmd160,20,"010966776006953d5567439e5e39f86a0d273bee");//3564a74f9ddb4372301c49154605573d7d1a88fe");
     vp->type = IGUANA_SCRIPT_76A988AC;
     }*/
    vp->spendlen = iguana_scriptgen(coin,&vp->M,&vp->N,vp->coinaddr,vp->spendscript,asmstr,vp->rmd160,vp->type,(const struct vin_info *)vp,vp->vin.prev_vout);
    //printf("type.%d asmstr.(%s) spendlen.%d\n",vp->type,asmstr,vp->spendlen);
    return(vp->spendlen);
}

int32_t iguana_vinscriptparse(struct iguana_info *coin,struct vin_info *vp,int32_t *sigsizep,int32_t *pubkeysizep,int32_t *p2shsizep,int32_t *suffixp,uint8_t *vinscript,int32_t scriptlen)
{
    int32_t hashtype;
    *sigsizep = *pubkeysizep = *p2shsizep = *suffixp = 0;
    memset(vp,0,sizeof(*vp));
    if ( bitcoin_scriptget(coin,&hashtype,sigsizep,pubkeysizep,suffixp,vp,vinscript,scriptlen,0) < 0 )
    {
        printf("iguana_vinscriptparse: error parsing vinscript?\n");
        return(-1);
    }
    if ( vp->type == IGUANA_SCRIPT_P2SH )
    {
        *p2shsizep = vp->p2shlen + 1 + (vp->p2shlen >= 0xfd)*2;
        printf("P2SHSIZE.%d\n",*p2shsizep);
    }
    return(hashtype);
}

char *iguana_scriptget(struct iguana_info *coin,char *scriptstr,char *asmstr,int32_t max,int32_t hdrsi,uint32_t unspentind,bits256 txid,int32_t vout,uint8_t *rmd160,int32_t type,uint8_t *pubkey33)
{
    int32_t scriptlen; uint8_t script[IGUANA_MAXSCRIPTSIZE]; struct vin_info V,*vp = &V;
    memset(vp,0,sizeof(*vp));
    scriptstr[0] = asmstr[0] = 0;
    if ( pubkey33 != 0 && bitcoin_pubkeylen(pubkey33) > 0 )
        memcpy(vp->signers[0].pubkey,pubkey33,33);
    scriptlen = iguana_scriptgen(coin,&vp->M,&vp->N,vp->coinaddr,script,asmstr,rmd160,type,(const struct vin_info *)vp,vout);
    init_hexbytes_noT(scriptstr,script,scriptlen);
    return(scriptstr);
}

/*void iguana_bundlescript(struct iguana_info *coin,uint32_t offset,struct iguana_bundle *bp,uint32_t ind,uint8_t *spendscript,int32_t spendlen)
{
    long size = sizeof(offset) + sizeof(ind); uint32_t *ptr;
    if ( bp->numscriptsmaps >= bp->maxscriptsmaps )
    {
        bp->scriptsmap = realloc(bp->scriptsmap,(1000+bp->maxscriptsmaps) * (sizeof(offset) + sizeof(ind)));
        bp->maxscriptsmaps += 1000;
    }
    ptr = (void *)((long)bp->scriptsmap + bp->numscriptsmaps*size);
    ptr[0] = ind;
    ptr[1] = offset;
    bp->numscriptsmaps++;
}*/

uint32_t iguana_scriptstableadd(struct iguana_info *coin,int32_t spendflag,uint32_t fpos,uint8_t *script,uint16_t scriptlen)
{
    struct scriptinfo *ptr;
    HASH_FIND(hh,coin->scriptstable[spendflag],script,scriptlen,ptr);
    if ( ptr == 0 )
    {
        ptr = mycalloc('w',1,sizeof(*ptr) + scriptlen);
        ptr->fpos = fpos;
        ptr->scriptlen = scriptlen;
        memcpy(ptr->script,script,scriptlen);
        HASH_ADD(hh,coin->scriptstable[spendflag],script,scriptlen,ptr);
    }
    return(fpos);
}

uint32_t iguana_scriptstablefind(struct iguana_info *coin,int32_t spendflag,uint8_t *script,int32_t scriptlen)
{
    struct scriptinfo *ptr;
    HASH_FIND(hh,coin->scriptstable[spendflag],script,scriptlen,ptr);
    if ( ptr != 0 )
        return(ptr->fpos);
    else return(0);
}

long iguana_rwscript(struct iguana_info *coin,int32_t rwflag,void *fileptr,long offset,long filesize,FILE *fp,struct iguana_bundle *bp,uint8_t **scriptptrp,int32_t *lenp,int32_t hdrsi,uint32_t ind,int32_t spendflag)
{
    long scriptpos; struct scriptdata data; uint8_t *script = *scriptptrp;
    if ( spendflag == 0 && (scriptpos= iguana_scriptstablefind(coin,spendflag,script,*lenp)) != 0 )
        return(scriptpos);
    memset(&data,0,sizeof(data));
    if ( rwflag != 0 && fp != 0 && fileptr == 0 )
    {
        scriptpos = ftell(fp);
        data.ind = ind, data.spendflag = spendflag;
        data.hdrsi = hdrsi;
        data.scriptlen = *lenp;
        if ( fwrite(&data,1,sizeof(data),fp) != sizeof(data) )
            return(-1);
        if ( fwrite(script,1,data.scriptlen,fp) != data.scriptlen )
            return(-1);
        offset = (uint32_t)ftell(fp);
        //printf("spend.%d filesize.%ld wrote.h%d u%d len.%d [%ld,%ld) crc.%08x\n",spendflag,coin->scriptsfilesize[spendflag],hdrsi,ind,data.scriptlen,scriptpos,ftell(fp),calc_crc32(0,script,data.scriptlen));
    }
    else if ( rwflag == 0 && fp == 0 && fileptr != 0 )
    {
        scriptpos = offset;
        if ( offset+sizeof(data) <= filesize )
        {
            memcpy(&data,(void *)((long)fileptr + offset),sizeof(data));
            if ( data.scriptlen > 0 && data.scriptlen < *lenp && offset+sizeof(data)+data.scriptlen <= filesize )
            {
                if ( data.scriptlen > 0 )
                {
                    *scriptptrp = script = (void *)((long)fileptr + offset);
                    offset += data.scriptlen + sizeof(data);
                    if ( data.hdrsi < coin->bundlescount )
                        bp = coin->bundles[data.hdrsi];
                    else printf("illegal hdrsi.%d/%d\n",data.hdrsi,coin->bundlescount);
                } else printf("illegal scriptlen %d\n",data.scriptlen);
                //printf("hdrsi.%d loaded script.%d %u s%d\n",data.hdrsi,data.scriptlen,data.ind,data.spendflag);
            }
            else if ( data.scriptlen > 0 )
            {
                printf("spendlen overflow.%d vs %d\n",data.scriptlen,*lenp);
                return(-1);
            }
        }
        else
        {
            printf("error reading from %ld\n",scriptpos);
            return(-1);
        }
        //printf("hdrsi.%d scriptlen.%d\n",data.hdrsi,data.scriptlen);
        *lenp = data.scriptlen;
    }
    if ( bp != 0 )
    {
        //if ( spendflag == 0 )
            iguana_scriptstableadd(coin,spendflag,(uint32_t)scriptpos,script,*lenp);
    }
    else if ( rwflag == 0 )
    {
        printf("null bp for iguana_rwscript hdrsi.%d/%d\n",data.hdrsi,coin->bundlescount);
        return(-1);
    }
    return(offset);
}

long iguana_initscripts(struct iguana_info *coin)
{
    long fpos=0,offset = 0; uint8_t scriptdata[IGUANA_MAXSCRIPTSIZE],*scriptptr; int32_t spendflag,size,n=0; struct scriptdata script;
    for (spendflag=0; spendflag<2; spendflag++)
    {
        portable_mutex_lock(&coin->scripts_mutex[spendflag]);
        sprintf(coin->scriptsfname[spendflag],"tmp/%s/%sscripts",coin->symbol,spendflag==0?"":"sig"), OS_portable_path(coin->scriptsfname[spendflag]);
        printf("scripts fname.(%s)\n",coin->scriptsfname[spendflag]);
        if ( (coin->scriptsptr[spendflag]= OS_mapfile(coin->scriptsfname[spendflag],&coin->scriptsfilesize[spendflag],0)) == 0 )
        {
            coin->scriptsfp[spendflag] = fopen(coin->scriptsfname[spendflag],"wb");
            memset(&script,0,sizeof(script));
            fwrite(&script,1,sizeof(script),coin->scriptsfp[spendflag]);
        }
        else
        {
            while ( 1 )
            {
                size = sizeof(scriptdata);
                scriptptr = scriptdata;
                if ( (offset= iguana_rwscript(coin,0,coin->scriptsptr[spendflag],offset,coin->scriptsfilesize[spendflag],0,0,&scriptptr,&size,0,0,spendflag)) < 0 )
                    break;
                else fpos = offset;
                n++;
            }
            coin->scriptsfp[spendflag] = fopen(coin->scriptsfname[spendflag],"ab");
            portable_mutex_unlock(&coin->scripts_mutex[spendflag]);
            printf("initialized %d scripts, fpos %ld\n",n,fpos);
            return(offset);
        }
        portable_mutex_unlock(&coin->scripts_mutex[spendflag]);
    }
    return(-1);
}

uint32_t iguana_scriptsave(struct iguana_info *coin,struct iguana_bundle *bp,uint32_t ind,int32_t spendflag,uint8_t *script,int32_t scriptlen)
{
    FILE *fp; long fpos = 0;
    if ( scriptlen > 0 && (fp= coin->scriptsfp[spendflag]) != 0 )
    {
        portable_mutex_lock(&coin->scripts_mutex[spendflag]);
        fpos = ftell(fp);
        if ( iguana_rwscript(coin,1,0,0,0,fp,bp,&script,&scriptlen,bp->hdrsi,ind,spendflag) < 0 )
        {
            fseek(fp,fpos,SEEK_SET);
            fpos = -1;
            printf("error saving script at %ld\n",fpos);
        } else fflush(fp);
        portable_mutex_unlock(&coin->scripts_mutex[spendflag]);
    } else printf("cant scriptsave.%d to (%s).%p scriptlen.%d\n",spendflag,coin->scriptsfname[spendflag],coin->scriptsfp[spendflag],scriptlen);
    return((uint32_t)fpos);
}

long iguana_scriptadd(struct iguana_info *coin,struct iguana_bundle *bp,uint32_t unspentind,int32_t type,uint8_t *spendscript,int32_t spendlen,uint8_t rmd160[20],int32_t vout)
{
    static long total,saved;
    int32_t scriptlen; char asmstr[IGUANA_MAXSCRIPTSIZE*2+1]; uint8_t script[IGUANA_MAXSCRIPTSIZE]; long fpos=0; struct vin_info V,*vp = &V;
    if ( spendlen == 0 )
    {
        printf("null script?\n");
        getchar();
        return(0);
    }
    memset(vp,0,sizeof(*vp));
    asmstr[0] = 0;
    total++;
    fprintf(stderr,"scriptgen\n");
    scriptlen = iguana_scriptgen(coin,&vp->M,&vp->N,vp->coinaddr,script,asmstr,rmd160,type,(const struct vin_info *)vp,vout);
    if ( scriptlen == spendlen && memcmp(script,spendscript,scriptlen) == 0 )
        return(0);
    else
    {
        saved++;
        //if ( (saved % 1000) == 0 )
            printf("add type.%d scriptlen.%d fpos.%ld saved.%ld/%ld\n",type,spendlen,coin->scriptsfp!=0?ftell(coin->scriptsfp[0]):-1,saved,total);
        fpos = iguana_scriptsave(coin,bp,unspentind,0,spendscript,spendlen);
    }
    return(fpos);
}
