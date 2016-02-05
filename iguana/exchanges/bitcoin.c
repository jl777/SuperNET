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

#include "bitcoin.h"

static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#define IGUANA_SCRIPT_NULL 0
#define IGUANA_SCRIPT_76AC 1
#define IGUANA_SCRIPT_76A988AC 2
#define IGUANA_SCRIPT_P2SH 3
#define IGUANA_SCRIPT_OPRETURN 4
#define IGUANA_SCRIPT_3of3 5
#define IGUANA_SCRIPT_2of3 6
#define IGUANA_SCRIPT_1of3 7
#define IGUANA_SCRIPT_2of2 8
#define IGUANA_SCRIPT_1of2 9
#define IGUANA_SCRIPT_MSIG 10
#define IGUANA_SCRIPT_DATA 11
#define IGUANA_SCRIPT_STRANGE 15

int32_t bitcoin_standardspend(uint8_t *script,int32_t n,uint8_t rmd160[20])
{
    script[n++] = SCRIPT_OP_DUP;
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 20; memcpy(&script[n],rmd160,20); n += 20;
    script[n++] = SCRIPT_OP_EQUALVERIFY;
    script[n++] = SCRIPT_OP_CHECKSIG;
    return(n);
}

int32_t bitcoin_checklocktimeverify(uint8_t *script,int32_t n,uint32_t locktime)
{
    script[n++] = (locktime >> 24), script[n++] = (locktime >> 16), script[n++] = (locktime >> 8), script[n++] = locktime;
    script[n++] = OP_CHECKLOCKTIMEVERIFY;
    script[n++] = OP_DROP;
    return(n);
}

char *create_atomictx_cltvspend(char *scriptstr,uint8_t *rmd160A,uint8_t *rmd160B,uint32_t locktime)
{
    // OP_IF
    //      <timestamp> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
    // OP_ELSE
    //      OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG // standard spend
    // OP_ENDIF
    uint8_t hex[4096]; int32_t n = 0;
    hex[n++] = SCRIPT_OP_IF;
    n = bitcoin_checklocktimeverify(hex,n,locktime);
    n = bitcoin_standardspend(hex,n,rmd160A);
    hex[n++] = SCRIPT_OP_ELSE;
    n = bitcoin_standardspend(hex,n,rmd160B);
    hex[n++] = SCRIPT_OP_ENDIF;
    init_hexbytes_noT(scriptstr,hex,n);
    return(scriptstr);
}

/*struct vin_signer { bits256 privkey; uint8_t siglen,sig[80],pubkey[65]; };
 
 struct vin_info
 {
 struct iguana_msgvin vin;
 int32_t M,N,validmask,voutlen;
 struct vin_signer signers[16];
 uint8_t voutscript[IGUANA_MAXSCRIPTSIZE];
 };*/

int32_t iguana_scriptgen(struct iguana_info *coin,char *coinaddr,uint8_t *script,char *asmstr,uint8_t rmd160[20],uint8_t type,int32_t txi)
{
    uint8_t addrtype; char rmd160str[41]; int32_t scriptlen = 0;
    if ( type == IGUANA_SCRIPT_76A988AC || type == IGUANA_SCRIPT_76AC )
        addrtype = coin->chain->pubtype;
    else addrtype = coin->chain->p2shtype;
    btc_convrmd160(coinaddr,addrtype,rmd160);
    init_hexbytes_noT(rmd160str,rmd160,20);
    //printf("addrtype.%d\n",addrtype);
    switch ( type )
    {
        case IGUANA_SCRIPT_NULL:
            strcpy(asmstr,txi == 0 ? "coinbase" : "PoSbase");
            coinaddr[0] = 0;
            break;
        case IGUANA_SCRIPT_76AC:
            sprintf(asmstr,"OP_DUP %s OP_CHECKSIG",rmd160str);
            break;
        case IGUANA_SCRIPT_76A988AC:
            sprintf(asmstr,"OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG",rmd160str);
            break;
        case IGUANA_SCRIPT_P2SH:
            script[0] = SCRIPT_OP_HASH160, script[1] = 0x14;
            memcpy(&script[2],rmd160,20);
            script[22] = SCRIPT_OP_EQUAL;
            sprintf(asmstr,"OP_HASH160 %s OP_EQUAL",coinaddr);
            scriptlen = 23;
            break;
        case IGUANA_SCRIPT_OPRETURN: strcpy(asmstr,"OP_RETURN"); break;
        case IGUANA_SCRIPT_3of3: strcpy(asmstr,"3 of 3 MSIG"); break;
        case IGUANA_SCRIPT_2of3: strcpy(asmstr,"2 of 3 MSIG"); break;
        case IGUANA_SCRIPT_1of3: strcpy(asmstr,"1 of 3 MSIG"); break;
        case IGUANA_SCRIPT_2of2: strcpy(asmstr,"2 of 2 MSIG"); break;
        case IGUANA_SCRIPT_1of2: strcpy(asmstr,"1 of 2 MSIG"); break;
        case IGUANA_SCRIPT_MSIG: strcpy(asmstr,"NON-STANDARD MSIG"); break;
        case IGUANA_SCRIPT_DATA: strcpy(asmstr,"DATA ONLY"); break;
        case IGUANA_SCRIPT_STRANGE: strcpy(asmstr,"STRANGE SCRIPT"); break;
        default: printf("unexpected script type\n"); break;
    }
    return(0);
}

int32_t _iguana_calcrmd160(struct iguana_info *coin,uint8_t rmd160[20],uint8_t msigs160[16][20],int32_t *Mp,int32_t *nump,uint8_t *pk_script,int32_t pk_scriptlen,bits256 txid,int32_t vout)
{
    static uint8_t zero_rmd160[20];
    char hexstr[8192]; uint8_t sha256[32],*script,type; int32_t i,n,m,plen;
    if ( nump != 0 )
        *nump = 0;
    type = IGUANA_SCRIPT_STRANGE;
    if ( pk_scriptlen == 0 )
    {
        if ( zero_rmd160[0] == 0 )
        {
            vcalc_sha256(0,sha256,pk_script,pk_scriptlen); // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            calc_rmd160(0,zero_rmd160,sha256,sizeof(sha256)); // b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
            init_hexbytes_noT(hexstr,zero_rmd160,20);
            char str[65]; printf("iguana_calcrmd160 zero len %s -> %s\n",bits256_str(str,*(bits256 *)sha256),hexstr);
        }
        memcpy(rmd160,zero_rmd160,sizeof(zero_rmd160));
        return(IGUANA_SCRIPT_NULL);
    }
    else if ( pk_script[0] == 0x6a )
        type = IGUANA_SCRIPT_OPRETURN;
    else if ( pk_script[0] == 0x76 && pk_script[1] == 0xa9 && pk_script[2] == 20 && pk_script[pk_script[2]+3] == 0x88 && pk_script[pk_script[2]+4] == 0xac )
    {
        //printf("IGUANA_SCRIPT_76A988AC plen.%d vs %d pk_scriptlen\n",pk_script[2]+4,pk_scriptlen);
        // 76a9145f69cb73016264270dae9f65c51f60d0e4d6fd4488ac
        //vcalc_sha256(0,sha256,&pk_script[3],pk_script[2]);
        //calc_rmd160(0,rmd160,sha256,sizeof(sha256));
        memcpy(rmd160,&pk_script[3],20);
        if ( (plen= pk_script[2]+5) < pk_scriptlen )
        {
            while ( plen < pk_scriptlen )
                if ( pk_script[plen++] != 0x61 ) // nop
                    return(IGUANA_SCRIPT_STRANGE);
        }
        return(IGUANA_SCRIPT_76A988AC);
    }
    // 21035f1321ed17d387e4433b2fa229c53616057964af065f98bfcae2233c5108055eac
    else if ( pk_script[0] > 0 && pk_script[0] < 76 && pk_script[pk_scriptlen-1] == 0xac && pk_script[0] == pk_scriptlen-2 )
    {
        vcalc_sha256(0,sha256,&pk_script[1],pk_script[0]);
        calc_rmd160(0,rmd160,sha256,sizeof(sha256));
        return(IGUANA_SCRIPT_76AC);
    }
    else if ( pk_script[0] == 0xa9 && pk_script[1] == 0x14 && pk_scriptlen == 23 && pk_script[22] == 0x87 )
    {
        memcpy(rmd160,pk_script+2,20);
        return(IGUANA_SCRIPT_P2SH);
    }
    else if ( pk_scriptlen > 34 && pk_script[pk_scriptlen-1] == 0xae && (n= pk_script[pk_scriptlen-2]) >= 0x51 && n <= 0x60 && (m= pk_script[0]) >= 0x51 && m <= n ) // m of n multisig
    {
        m -= 0x50, n -= 0x50;
        if ( msigs160 != 0 && nump != 0 && *Mp != 0 )
        {
            script = pk_script+1;
            for (i=0; i<n; i++,script += plen)
            {
                plen = *script++;
                vcalc_sha256(0,sha256,script,plen);
                calc_rmd160(0,msigs160[i],sha256,sizeof(sha256));
            }
            if ( (int32_t)((long)script - (long)pk_script) == pk_scriptlen-2 )
            {
                *nump = n;
                *Mp = m;
                //printf("M.%d N.%d\n",m,n);
            }
        }
        vcalc_sha256(0,sha256,pk_script,pk_scriptlen);
        calc_rmd160(0,rmd160,sha256,sizeof(sha256));
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
    else if ( pk_scriptlen == pk_script[0]+1 )
    {
        //printf("just data.%d\n",pk_scriptlen);
        memcpy(rmd160,zero_rmd160,sizeof(zero_rmd160));
        return(IGUANA_SCRIPT_DATA);
    }
    if ( type != IGUANA_SCRIPT_OPRETURN )
    {
        if ( pk_scriptlen < sizeof(hexstr)/2-1)
        {
            static FILE *fp;
            init_hexbytes_noT(hexstr,pk_script,pk_scriptlen);
            char str[65]; printf("unparsed script.(%s).%d in %s len.%d\n",hexstr,pk_scriptlen,bits256_str(str,txid),pk_scriptlen);
            if ( 1 && fp == 0 )
                fp = fopen("unparsed.txt","w");
            if ( fp != 0 )
                fprintf(fp,"%s\n",hexstr), fflush(fp);
        } else sprintf(hexstr,"pkscript overflowed %ld\n",(long)sizeof(hexstr));
    }
    vcalc_sha256(0,sha256,pk_script,pk_scriptlen);
    calc_rmd160(0,rmd160,sha256,sizeof(sha256));
    return(type);
}

int32_t iguana_calcrmd160(struct iguana_info *coin,uint8_t rmd160[20],uint8_t msigs160[16][20],int32_t *Mp,int32_t *nump,uint8_t *pk_script,int32_t pk_scriptlen,bits256 debugtxid,int32_t vout)
{
    int32_t type,scriptlen; uint8_t script[IGUANA_MAXSCRIPTSIZE];
    char asmstr[IGUANA_MAXSCRIPTSIZE*3],coinaddr[65];
    type = _iguana_calcrmd160(coin,rmd160,msigs160,Mp,nump,pk_script,pk_scriptlen,debugtxid,vout);
    scriptlen = iguana_scriptgen(coin,coinaddr,script,asmstr,rmd160,type,vout);
    if ( scriptlen != pk_scriptlen || memcmp(script,pk_script,scriptlen) != 0 )
    {
        printf("iguana_calcrmd160 type.%d error regenerating scriptlen.%d vs %d\n",type,scriptlen,pk_scriptlen);
    }
    return(type);
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

char *bitcoin_base58encode(char *coinaddr,uint8_t *data_,int32_t datalen)
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
        bn_mpi2bn(&bn,swapbuf,datalen);
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
        return(coinaddr);
    }
    return(0);
}

int32_t bitcoin_base58decode(uint8_t *data,char *coinaddr)
{
 	uint32_t zeroes,be_sz=0,i,len; const char *p,*p1; BIGNUM bn58,bn,bnChar; uint8_t revdata[64]; BN_CTX *ctx;
	ctx = BN_CTX_new();
	BN_init(&bn58), BN_init(&bn), BN_init(&bnChar);
    BN_set_word(&bn58,58), BN_set_word(&bn,0);
	while ( isspace(*coinaddr) )
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
        data[i + zeroes] = revdata[be_sz - 1 - i];
out:
	BN_clear_free(&bn58), BN_clear_free(&bn), BN_clear_free(&bnChar);
	BN_CTX_free(ctx);
	return(be_sz);
}

int32_t bitcoin_addr2rmd160(uint8_t *addrtypep,uint8_t rmd160[20],char *coinaddr)
{
    bits256 hash; uint8_t buf[25]; int32_t len;
    memset(rmd160,0,20);
    *addrtypep = 0;
    if ( (len= bitcoin_base58decode(buf,coinaddr)) >= 4 )
    {
        // validate with trailing hash, then remove hash
        hash = bits256_doublesha256(0,buf,len - 4);
        if ( (buf[len - 4]&0xff) == hash.bytes[31] && (buf[len - 3]&0xff) == hash.bytes[30] &&(buf[len - 2]&0xff) == hash.bytes[29] &&(buf[len - 1]&0xff) == hash.bytes[28] )
        {
            *addrtypep = buf[0];
            memcpy(rmd160,buf+1,20);
            return(20);
        }
        else
        {
            char str[65]; printf("checkhash mismatch %02x %02x %02x %02x vs %02x %02x %02x %02x (%s)\n",buf[len - 4]&0xff,buf[len - 3]&0xff,buf[len - 2]&0xff,buf[len - 1]&0xff,hash.bytes[31],hash.bytes[30],hash.bytes[29],hash.bytes[28],bits256_str(str,hash));
        }
    }
	return(0);
}

char *bitcoin_address(char *coinaddr,uint8_t addrtype,uint8_t *pubkey,int32_t len)
{
    int32_t i; uint8_t data[25]; bits256 hash; char checkaddr[65];
    vcalc_sha256(0,hash.bytes,pubkey,len);
    calc_rmd160(0,data+1,hash.bytes,sizeof(hash));
    btc_convrmd160(checkaddr,addrtype,data+1);
    for (i=0; i<20; i++)
        printf("%02x",data[i+1]);
    printf(" RMD160 len.%d\n",len);
    data[0] = addrtype;
    hash = bits256_doublesha256(0,data,21);
    for (i=0; i<4; i++)
        data[21+i] = hash.bytes[31-i];
    if ( (coinaddr= bitcoin_base58encode(coinaddr,data,25)) != 0 )
    {
        uint8_t checktype,rmd160[20];
        bitcoin_addr2rmd160(&checktype,rmd160,coinaddr);
        printf("checkaddr.(%s) vs coinaddr.(%s) %02x vs [%02x] memcmp.%d\n",checkaddr,coinaddr,addrtype,checktype,memcmp(rmd160,data+1,20));
    }
    return(coinaddr);
}

EC_KEY *bitcoin_privkeyset(uint8_t *oddevenp,bits256 *pubkeyp,bits256 privkey)
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

bits256 bitcoin_pubkey(uint8_t *data,bits256 privkey)
{
    uint8_t oddeven; bits256 pubkey;
    EC_KEY *KEY;
    if ( (KEY= bitcoin_privkeyset(&oddeven,&pubkey,privkey)) != 0 )
    {
        data[0] = oddeven;
        memcpy(data+1,pubkey.bytes,sizeof(pubkey));
        EC_KEY_free(KEY);
    }
    return(pubkey);
}

int32_t bitcoin_sign(uint8_t *sig,int32_t maxlen,uint8_t *data,int32_t datalen,bits256 privkey)
{
    uint32_t siglen; EC_KEY *KEY; uint8_t oddeven; bits256 pubkey; int32_t retval = -1;
    if ( (KEY= bitcoin_privkeyset(&oddeven,&pubkey,privkey)) != 0 )
    {
        if ( ECDSA_sign(0,data,datalen,sig,&siglen,KEY) > 0 && siglen <= maxlen )
            retval = siglen;
        EC_KEY_free(KEY);
    }
    return(retval);
}

int32_t bitcoin_verify(uint8_t *sig,int32_t siglen,uint8_t *data,int32_t datalen,EC_KEY *KEY,uint8_t *pubkey,int32_t len)
{
    ECDSA_SIG *esig; int32_t retval = -1; uint8_t tmp[33],*ptr,*sigptr = sig; EC_KEY *origkey = KEY;
    if ( (esig= ECDSA_SIG_new()) != 0 )
    {
        if ( d2i_ECDSA_SIG(&esig,(const uint8_t **)&sigptr,siglen) != 0 )
        {
            if ( KEY != 0 || (KEY= EC_KEY_new_by_curve_name(NID_secp256k1)) != 0 )
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
                if ( origkey == 0 )
                    EC_KEY_free(KEY);
            }
        }
        ECDSA_SIG_free(esig);
    }
    return(retval);
}

int32_t iguana_parsevoutobj(struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_msgvout *vout,cJSON *voutobj)
{
    int32_t len = 0; cJSON *skey; char *hexstr;
    memset(vout,0,sizeof(*vout));
    vout->value = jdouble(voutobj,"value") * SATOSHIDEN;
    if ( (skey= jobj(voutobj,"scriptPubKey")) != 0 )
    {
        if ( (hexstr= jstr(skey,"hex")) != 0 )
        {
            len = (int32_t)strlen(hexstr) >> 1;
            decode_hex(serialized,len,hexstr);
            vout->pk_script = serialized;
            vout->pk_scriptlen = len;
        }
    }
    return(len);
}

int32_t iguana_parsevinobj(struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_msgvin *vin,cJSON *vinobj)
{
    int32_t len = 0; char *hexstr; cJSON *sigjson;
    memset(vin,0,sizeof(*vin));
    vin->prev_vout = -1;
    vin->sequence = juint(vinobj,"sequence");
    if ( (hexstr= jstr(vinobj,"coinbase")) == 0 )
    {
        vin->prev_hash = jbits256(vinobj,"txid");
        vin->prev_vout = jint(vinobj,"vout");
        if ( (sigjson= jobj(vinobj,"scriptSig")) != 0 )
            hexstr = jstr(sigjson,"redeemScript");
    }
    if ( hexstr != 0 )
    {
        len = (int32_t)strlen(hexstr) >> 1;
        decode_hex(serialized,len,hexstr);
        vin->script = serialized;
        vin->scriptlen = len;
    }
    else
    {
        printf("iguana_parsevinobj: hex script missing (%s)\n",jprint(vinobj,0));
        return(0);
    }
    return(len);
}

//{"result":{"txid":"a2b81b9894205ced12dfe276cbe27c05308976b5a2e12789ccd167fe6c3217f7","version":1,"time":1433295027,"locktime":0,"vin":[{"txid":"cf8f5e26e29a74c4fb867338213c02059b975fcfeae993926edbad8aba1cfedb","vout":1,"scriptSig":{"asm":"3045022100f86ab6815d1c22bf9f0fb6c389b558eb644159462054039d393cdba6e480a952022079b7f804c48a0ef5de68bc4be4c18cd5ea947763f4d5f6d415092f8dc00ee1aa01","hex":"483045022100f86ab6815d1c22bf9f0fb6c389b558eb644159462054039d393cdba6e480a952022079b7f804c48a0ef5de68bc4be4c18cd5ea947763f4d5f6d415092f8dc00ee1aa01"},"sequence":4294967295},{"txid":"cfcaef36853be671a5247c1ccb2a54a59d8b4628d0d63726dcdc8dbf73116ae3","vout":2,"scriptSig":{"asm":"3045022100a84f56626e4558e13911290e72d498796ba0bc70a0c9eb59b20d50f6ed94cee30220734c94ab1e89dfe26b3cc1b519a5a6f37863829e9eccdb246843e76577b4040f01","hex":"483045022100a84f56626e4558e13911290e72d498796ba0bc70a0c9eb59b20d50f6ed94cee30220734c94ab1e89dfe26b3cc1b519a5a6f37863829e9eccdb246843e76577b4040f01"},"sequence":4294967295}],"vout":[{"value":0.00000000,"n":0,"scriptPubKey":{"asm":"","type":"nonstandard"}},{"value":1036.57541260,"n":1,"scriptPubKey":{"asm":"03506a52e95cdfbb9d17d702af6259ba7de8b7a604007999e0266edbf6e4bb6974 OP_CHECKSIG","reqSigs":1,"type":"pubkey","addresses":["RJyYWRKSK7cMg5EeW9aHAaT3hHVEkAXnP9"]}}],"blockhash":"6863f2bab8cd9b69dd7a446aa63281f9e5301520f9ba02ca3acc892866872fe4","confirmations":374485},"error":null,"id":"jl777"}

//{"result":{"version":1,"timestamp":1433295027,"vin":[{"sequence":4294967295,"txid":"cf8f5e26e29a74c4fb867338213c02059b975fcfeae993926edbad8aba1cfedb","vout":1,"hex":"483045022100f86ab6815d1c22bf9f0fb6c389b558eb644159462054039d393cdba6e480a952022079b7f804c48a0ef5de68bc4be4c18cd5ea947763f4d5f6d415092f8dc00ee1aa01"}, {"sequence":4294967295,"txid":"cfcaef36853be671a5247c1ccb2a54a59d8b4628d0d63726dcdc8dbf73116ae3","vout":2,"hex":"483045022100a84f56626e4558e13911290e72d498796ba0bc70a0c9eb59b20d50f6ed94cee30220734c94ab1e89dfe26b3cc1b519a5a6f37863829e9eccdb246843e76577b4040f01"}],"numvins":2,"vout":[{"value":0,"n":0,"scriptPubKey":{"asm":"coinbase","addresses":[]}}, {"value":1036.57541260,"n":1,"scriptPubKey":{"asm":"OP_DUP 6a5ad2f911f1bfd7c018c95154e2c049accd04da OP_CHECKSIG","addresses":["RJyYWRKSK7cMg5EeW9aHAaT3hHVEkAXnP9"],"hex":"2103506a52e95cdfbb9d17d702af6259ba7de8b7a604007999e0266edbf6e4bb6974ac"}}],"numvouts":2,"locktime":0,"size":295,"txid":"a2b81b9894205ced12dfe276cbe27c05308976b5a2e12789ccd167fe6c3217f7"},"height":555555,"confirmations":333945,"blockhash":"6863f2bab8cd9b69dd7a446aa63281f9e5301520f9ba02ca3acc892866872fe4","tag":"731886559821890929"}

cJSON *iguana_voutjson(struct iguana_info *coin,struct iguana_msgvout *vout,int32_t txi,bits256 txid)
{
    // 035f1321ed17d387e4433b2fa229c53616057964af065f98bfcae2233c5108055e OP_CHECKSIG
    char scriptstr[8192+1],coinaddr[65],asmstr[16384]; int32_t i,M,N,asmtype;
    uint8_t rmd160[20],msigs160[16][20],addrtype,space[8192];
    cJSON *addrs,*skey,*json = cJSON_CreateObject();
    jaddnum(json,"value",dstr(vout->value));
    jaddnum(json,"n",txi);
    //"scriptPubKey":{"asm":"OP_DUP OP_HASH160 5f69cb73016264270dae9f65c51f60d0e4d6fd44 OP_EQUALVERIFY OP_CHECKSIG","reqSigs":1,"type":"pubkeyhash","addresses":["RHyh1V9syARTf2pyxibz7v27D5paBeWza5"]}
    if ( vout->pk_script != 0 && vout->pk_scriptlen*2+1 < sizeof(scriptstr) )
    {
        if ( (asmtype= iguana_calcrmd160(coin,rmd160,msigs160,&M,&N,vout->pk_script,vout->pk_scriptlen,txid,txi)) >= 0 )
        {
            skey = cJSON_CreateObject();
            addrtype = iguana_scriptgen(coin,coinaddr,space,asmstr,rmd160,asmtype,txi);
            if ( asmstr[0] != 0 )
                jaddstr(skey,"asm",asmstr);
            addrs = cJSON_CreateArray();
            if ( M == 0 )
            {
                if ( asmtype == 2 )
                {
                    jaddnum(skey,"reqSigs",1);
                    jaddstr(skey,"type","pubkeyhash");
                }
                if ( coinaddr[0] != 0 )
                    jaddistr(addrs,coinaddr);
            }
            else
            {
                jaddnum(skey,"reqSigs",M);
                for (i=0; i<N; i++)
                {
                    btc_convrmd160(coinaddr,coin->chain->pubtype,msigs160[i]);
                    jaddistr(addrs,coinaddr);
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

cJSON *iguana_vinjson(struct iguana_info *coin,struct iguana_msgvin *vin)
{
    char scriptstr[8192+1],str[65]; int32_t vout; cJSON *sigjson,*json = cJSON_CreateObject();
    vout = vin->prev_vout;
    jaddnum(json,"sequence",vin->sequence);
    if ( vin->script != 0 && vin->scriptlen*2+1 < sizeof(scriptstr) )
        init_hexbytes_noT(scriptstr,vin->script,vin->scriptlen);
    if ( vout < 0 && bits256_nonz(vin->prev_hash) == 0 )
        jaddstr(json,"coinbase",scriptstr);
    else
    {
        jaddstr(json,"txid",bits256_str(str,vin->prev_hash));
        jaddnum(json,"vout",vout);
        sigjson = cJSON_CreateObject();
        jaddstr(sigjson,"redeemScript",scriptstr);
        jadd(json,"scriptSig",sigjson);
    }
    return(json);
}

cJSON *iguana_txjson(struct iguana_info *coin,struct iguana_txid *tx,int32_t height)
{
    struct iguana_msgvin vin; struct iguana_msgvout vout; int32_t i; char asmstr[512],str[65]; uint8_t space[8192];
    cJSON *vouts,*vins,*json;
    json = cJSON_CreateObject();
    jaddstr(json,"txid",bits256_str(str,tx->txid));
    if ( height >= 0 )
        jaddnum(json,"height",height);
    jaddnum(json,"version",tx->version);
    jaddnum(json,"timestamp",tx->timestamp);
    jaddnum(json,"locktime",tx->locktime);
    vins = cJSON_CreateArray();
    vouts = cJSON_CreateArray();
    for (i=0; i<tx->numvouts; i++)
    {
        iguana_voutset(coin,space,asmstr,height,&vout,tx,i);
        jaddi(vouts,iguana_voutjson(coin,&vout,i,tx->txid));
    }
    jadd(json,"vout",vouts);
    for (i=0; i<tx->numvins; i++)
    {
        iguana_vinset(coin,height,&vin,tx,i);
        jaddi(vins,iguana_vinjson(coin,&vin));
    }
    jadd(json,"vin",vins);
    return(json);
}

int32_t iguana_vinparse(int32_t rwflag,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t len = 0;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->scriptlen);
    if ( rwflag == 0 )
        msg->script = &serialized[len];
    else memcpy(&serialized[len],msg->script,msg->scriptlen);
    len += msg->scriptlen;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->sequence),&msg->sequence);
    if ( 0 )
    {
        int32_t i; char str[65];
        for (i=0; i<msg->scriptlen; i++)
            printf("%02x",msg->script[i]);
        printf(" prev_hash.(%s) vout.%d [%p] scriptlen.%d rwflag.%d\n",bits256_str(str,msg->prev_hash),msg->prev_vout,msg->script,msg->scriptlen,rwflag);
    }
    return(len);
}

int32_t iguana_voutparse(int32_t rwflag,uint8_t *serialized,struct iguana_msgvout *msg)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->value),&msg->value);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->pk_scriptlen);
    if ( rwflag == 0 )
        msg->pk_script = &serialized[len];
    else memcpy(&serialized[len],msg->pk_script,msg->pk_scriptlen);
    if ( 0 )
    {
        int32_t i;
        for (i=0; i<msg->pk_scriptlen; i++)
            printf("%02x",msg->pk_script[i]);
        printf(" [%p] scriptlen.%d rwflag.%d %.8f\n",msg->pk_script,msg->pk_scriptlen,rwflag,dstr(msg->value));
    }
    len += msg->pk_scriptlen;
    return(len);
}

// {"result":{"txid":"867ab5071349ef8d0dcd03a43017b6b440c9533cb26a8a6870127e7884ff96f6","version":1,"time":1404960685,"locktime":0,"vin":[{"coinbase":"510103","sequence":4294967295}],"vout":[{"value":80.00000000,"n":0,"scriptPubKey":{"asm":"OP_DUP OP_HASH160 5f69cb73016264270dae9f65c51f60d0e4d6fd44 OP_EQUALVERIFY OP_CHECKSIG","reqSigs":1,"type":"pubkeyhash","addresses":["RHyh1V9syARTf2pyxibz7v27D5paBeWza5"]}}],"blockhash":"000000000c4682089c916de89eb080a877566494d4009c0089baf35fe94de22f","confirmations":930039}
//{"version":1,"timestamp":1404960685,"vins":[{"sequence":4294967295,"coinbase":"510103"}],"numvins":1,"vouts":[{"value":80,"n":0,"scriptPubKey":{"asm":"OP_DUP OP_HASH160 5f69cb73016264270dae9f65c51f60d0e4d6fd44 OP_EQUALVERIFY OP_CHECKSIG","reqSigs":1,"type":"pubkeyhash","addrs":["RHyh1V9syARTf2pyxibz7v27D5paBeWza5"],"hex":"76a9145f69cb73016264270dae9f65c51f60d0e4d6fd4488ac"}}],"numvouts":1,"locktime":0,"size":92,"txid":"867ab5071349ef8d0dcd03a43017b6b440c9533cb26a8a6870127e7884ff96f6","tag":"3968374231439324584"}

int32_t iguana_rwmsgtx(struct iguana_info *coin,int32_t rwflag,cJSON *json,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,bits256 *txidp,char *vpnstr)
{
    int32_t i,len = 0; uint8_t *txstart = serialized; char txidstr[65]; cJSON *array=0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( json != 0 )
    {
        jaddnum(json,"version",msg->version);
        array = cJSON_CreateArray();
    }
    if ( coin->chain->hastimestamp != 0 )
    {
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->timestamp),&msg->timestamp);
        //printf("timestamp.%08x %u %s\n",msg->timestamp,msg->timestamp,utc_str(str,msg->timestamp));
        if ( json != 0 )
            jaddnum(json,"timestamp",msg->timestamp);
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
    if ( rwflag == 0 )
    {
        if ( len + sizeof(struct iguana_msgvin)*msg->tx_in > maxsize )
            return(-1);
        maxsize -= (sizeof(struct iguana_msgvin) * msg->tx_in);
        msg->vins = (struct iguana_msgvin *)&serialized[maxsize];
    }
    //printf("tx_in.%08x\n",msg->tx_in);
    if ( msg->tx_in > 0 && msg->tx_in*sizeof(struct iguana_msgvin) < maxsize )
    {
        for (i=0; i<msg->tx_in; i++)
        {
            len += iguana_vinparse(rwflag,&serialized[len],&msg->vins[i]);
            if ( array != 0 )
                jaddi(array,iguana_vinjson(coin,&msg->vins[i]));
        }
    }
    else
    {
        printf("invalid tx_in.%d\n",msg->tx_in);
        return(-1);
    }
    if ( array != 0 )
    {
        jadd(json,"vin",array);
        jaddnum(json,"numvins",msg->tx_in);
        array = cJSON_CreateArray();
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_out);
    if ( rwflag == 0 )
    {
        if ( len + sizeof(struct iguana_msgvout)*msg->tx_out > maxsize )
            return(-1);
        maxsize -= (sizeof(struct iguana_msgvout) * msg->tx_out);
        msg->vouts = (struct iguana_msgvout *)&serialized[maxsize];
    }
    if ( msg->tx_out > 0 && msg->tx_out*sizeof(struct iguana_msgvout) < maxsize )
    {
        for (i=0; i<msg->tx_out; i++)
        {
            len += iguana_voutparse(rwflag,&serialized[len],&msg->vouts[i]);
            if ( array != 0 )
                jaddi(array,iguana_voutjson(coin,&msg->vouts[i],i,*txidp));
        }
    }
    else
    {
        printf("invalid tx_out.%d\n",msg->tx_out);
        return(-1);
    }
    if ( array != 0 )
    {
        jadd(json,"vout",array);
        jaddnum(json,"numvouts",msg->tx_out);
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    //printf("lock_time.%08x\n",msg->lock_time);
    if ( strcmp(coin->symbol,"VPN") == 0 )
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

bits256 iguana_parsetxobj(struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,cJSON *txobj)
{
    int32_t i,numvins,numvouts,len = 0; cJSON *array=0; bits256 txid; char vpnstr[64];
    memset(msg,0,sizeof(*msg));
    vpnstr[0] = 0;
    msg->version = juint(txobj,"version");
    if ( coin->chain->hastimestamp != 0 )
        msg->timestamp = juint(txobj,"timestamp");
    if ( (array= jarray(&numvins,txobj,"vin")) != 0 )
    {
        msg->tx_in = numvins;
        if ( len + sizeof(struct iguana_msgvin)*msg->tx_in > maxsize )
            return(msg->txid);
        maxsize -= (sizeof(struct iguana_msgvin) * msg->tx_in);
        msg->vins = (struct iguana_msgvin *)&serialized[maxsize];
        if ( msg->tx_in > 0 && msg->tx_in*sizeof(struct iguana_msgvin) < maxsize )
        {
            for (i=0; i<msg->tx_in; i++)
                len += iguana_parsevinobj(coin,&serialized[len],maxsize,&msg->vins[i],jitem(array,i));
        }
    }
    if ( (array= jarray(&numvouts,txobj,"vout")) != 0 )
    {
        msg->tx_out = numvouts;
        if ( len + sizeof(struct iguana_msgvout)*msg->tx_out > maxsize )
            return(msg->txid);
        maxsize -= (sizeof(struct iguana_msgvout) * msg->tx_out);
        msg->vouts = (struct iguana_msgvout *)&serialized[maxsize];
        if ( msg->tx_out > 0 && msg->tx_out*sizeof(struct iguana_msgvout) < maxsize )
        {
            for (i=0; i<msg->tx_out; i++)
                len += iguana_parsevoutobj(coin,&serialized[len],maxsize,&msg->vouts[i],jitem(array,i));
        }
    }
    msg->lock_time = juint(txobj,"locktime");
    msg->txid = jbits256(txobj,"txid");
    msg->allocsize = iguana_rwmsgtx(coin,1,0,&serialized[len],maxsize-len,msg,&txid,vpnstr);
    //char str[65]; printf("json -> %s\n",bits256_str(str,txid));
    return(txid);
}

char *iguana_rawtxbytes(struct iguana_info *coin,uint8_t *serialized,int32_t datalen,cJSON *json,struct iguana_msgtx *msgtx)
{
    int32_t n; char *txbytes,vpnstr[64];
    vpnstr[0] = 0;
    //char str[65]; printf("%d of %d: %s\n",i,msg.txn_count,bits256_str(str,tx.txid));
    if ( (n= iguana_rwmsgtx(coin,1,json,serialized,datalen,msgtx,&msgtx->txid,vpnstr)) > 0 )
    {
        txbytes = malloc(n*2+1);
        init_hexbytes_noT(txbytes,serialized,n);
        return(txbytes);
    }
    return(0);
}

cJSON *bitcoin_txjson(struct iguana_info *coin,struct iguana_msgtx *msgtx)
{
    char vpnstr[2]; int32_t n; uint8_t *serialized; bits256 txid; cJSON *json = cJSON_CreateObject();
    vpnstr[0] = 0;
    serialized = malloc(IGUANA_MAXPACKETSIZE);
    if ( (n= iguana_rwmsgtx(coin,1,json,serialized,IGUANA_MAXPACKETSIZE,msgtx,&txid,vpnstr)) < 0 )
    {
        printf("bitcoin_txtest: n.%d\n",n);
    }
    free(serialized);
    return(json);
}

int32_t bitcoin_outputscript(struct iguana_info *coin,char *pubkeys[],int32_t *scriptlenp,uint8_t *scriptspace,bits256 txid,int32_t vout)
{
    struct iguana_txid T,*tx; int32_t height,numpubs = 1; char asmstr[8192]; struct iguana_msgvout v;
    if ( 0 )
    {
        *scriptlenp = 0;
        if ( (tx= iguana_txidfind(coin,&height,&T,txid)) != 0 )
        {
            *scriptlenp = iguana_voutset(coin,scriptspace,asmstr,height,&v,tx,vout);
            return(numpubs);
        }
    }
    //char *str = "2103506a52e95cdfbb9d17d702af6259ba7de8b7a604007999e0266edbf6e4bb6974ac";
    char *str = "76a914010966776006953d5567439e5e39f86a0d273bee88ac";
    *scriptlenp = (int32_t)strlen(str) >> 1;
    decode_hex(scriptspace,*scriptlenp,str);
    //pubkeys[0] = clonestr("03506a52e95cdfbb9d17d702af6259ba7de8b7a604007999e0266edbf6e4bb6974");
    pubkeys[0] = clonestr("0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6");
    return(numpubs);
}

int32_t bitcoin_hashtype(uint8_t *script,int32_t scriptlen,uint8_t *pk_script,int32_t pk_scriptlen)
{
    return(SIGHASH_ALL);
}

int32_t bitcoin_verifyvins(struct iguana_info *coin,int32_t *scriptlens,struct iguana_msgtx *msgtx,uint8_t *serialized,int32_t maxsize,bits256 myprivkey)
{
    char txidstr[128],bigstr[2560],coinaddr[64],vpnstr[64],str[65],*pubkeys[16];
    uint8_t *sig,mypubkey[128],pubkey[128],sigspace[8192],*saveinput,scriptspace[8192];
    bits256 txid,sigtxid,revsigtxid,mypub;
    int32_t n2,i,j,numpubs,plen,scriptlen,vini=0,siglen,numvins,hashtype,myvin = 1;
    vpnstr[0] = 0;
    memset(pubkeys,0,sizeof(pubkeys));
    numvins = msgtx->tx_in;
    mypub = bitcoin_pubkey(mypubkey,myprivkey);
    for (vini=0; vini<numvins; vini++)
    {
        for (i=0; i<numvins; i++)
            msgtx->vins[i].scriptlen = 0;
        saveinput = msgtx->vins[vini].script;
        sig = &msgtx->vins[vini].script[1];
        siglen = msgtx->vins[vini].script[0];
        numpubs = bitcoin_outputscript(coin,pubkeys,&scriptlen,scriptspace,msgtx->vins[vini].prev_hash,msgtx->vins[vini].prev_vout);
        msgtx->vins[vini].scriptlen = scriptlen;
        msgtx->vins[vini].script = scriptspace;
        for (j=0; j<numpubs; j++)
        {
            plen = (int32_t)strlen(pubkeys[j]);
            plen >>= 1;
            decode_hex(pubkey,plen,pubkeys[j]);
            bitcoin_address(coinaddr,coin->chain->pubtype,pubkey,plen);
            n2 = iguana_rwmsgtx(coin,1,0,serialized,maxsize,msgtx,&txid,vpnstr);
            hashtype = bitcoin_hashtype(saveinput,scriptlens[vini],scriptspace,scriptlen);
            msgtx->vins[vini].script = saveinput;
            if ( n2 > 0 )
            {
                n2 += iguana_rwnum(1,&serialized[n2],sizeof(hashtype),&hashtype);
                revsigtxid = bits256_doublesha256(txidstr,serialized,n2);
                for (i=0; i<sizeof(revsigtxid); i++)
                    sigtxid.bytes[31-i] = revsigtxid.bytes[i];
                if ( 1 && myvin != 0 )
                {
                    sig = sigspace;
                    siglen = bitcoin_sign(sig,sizeof(sigspace),sigtxid.bytes,sizeof(sigtxid),myprivkey);
                    printf("plen.%d siglen.%d %s\n",plen,siglen,bits256_str(str,myprivkey));
                    msgtx->vins[vini].scriptlen = siglen + plen + 2;
                    msgtx->vins[vini].script[0] = siglen;
                    memcpy(msgtx->vins[vini].script+1,sigspace,siglen);
                    msgtx->vins[vini].script[siglen + 1] = plen;
                    memcpy(msgtx->vins[vini].script+1+siglen+1,pubkey,plen);
                    cJSON *j = cJSON_CreateObject();
                    char *txstr = iguana_rawtxbytes(coin,malloc(10000),10000,j,msgtx);
                    printf("SIGNEDTX.(%s) %s\n",txstr,jprint(j,0));
                    siglen++;
                    //printf("retjson.(%s) %p\n",jprint(retjson,0),retjson);
                }
                if ( bitcoin_verify(sig,siglen-1,sigtxid.bytes,sizeof(sigtxid),0,pubkey,plen) < 0 )
                {
                    init_hexbytes_noT(bigstr,serialized,n2);
                    printf("(%s) doesnt verify hash2.%s\n",bigstr,bits256_str(str,sigtxid));
                    return(-1);
                } else printf("SIG.%d VERIFIED\n",vini);
            } else return(-1);
        }
    }
    return(0);
}

//printf("privkey.%s\n",bits256_str(str,privkey));
//EC_KEY *KEY = bitcoin_privkeyset(&pkey,privkey);
char *refstr = "01000000\
01\
eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2\
01000000\
8c\
4930460221009e0339f72c793a89e664a8a932df073962a3f84eda0bd9e02084a6a9567f75aa022100bd9cbaca2e5ec195751efdfac164b76250b1e21302e51ca86dd7ebd7020cdc0601410450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6\
ffffffff\
01\
605af40500000000\
19\
76a914097072524438d003d23a2f23edb65aae1bb3e46988ac\
00000000";

int32_t bitcoin_verifytx(struct iguana_info *coin,char *rawtxstr)
{
    int32_t i,len,maxsize,*scriptlens,numvins,retval = -1; uint8_t *serialized,*serialized2;
    struct iguana_msgtx msgtx; bits256 txid,myprivkey; char vpnstr[64];
    len = (int32_t)strlen(rawtxstr);
    maxsize = len + 32768;
    serialized = calloc(1,maxsize);
    serialized2 = calloc(1,maxsize);
    len >>= 1;
    vpnstr[0] = 0;
decode_hex(myprivkey.bytes,sizeof(myprivkey),"18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725");
    decode_hex(serialized,len,rawtxstr);
    memset(&msgtx,0,sizeof(msgtx));
    if ( iguana_rwmsgtx(coin,0,0,serialized,maxsize,&msgtx,&txid,vpnstr) > 0 )
    {
        numvins = msgtx.tx_in;
        scriptlens = calloc(numvins,sizeof(*scriptlens));
        for (i=0; i<numvins; i++)
            scriptlens[i] = msgtx.vins[i].scriptlen;
        if ( bitcoin_verifyvins(coin,scriptlens,&msgtx,serialized2,maxsize,myprivkey) == 0 )
            retval = 0;
        free(scriptlens);
    }
    free(serialized), free(serialized2);
    return(retval);
}

cJSON *bitcoin_txtest(struct iguana_info *coin,char *rawtxstr,bits256 txid)
{
    struct iguana_msgtx msgtx; char str[65],str2[65]; bits256 checktxid,blockhash,myprivkey;
    cJSON *retjson,*txjson; uint8_t *serialized,*serialized2; struct iguana_txid T,*tp;
    char vpnstr[64]; int32_t n,i,*scriptlens,height,n2,maxsize,len = (int32_t)strlen(rawtxstr);
rawtxstr = refstr;
    maxsize = len + 32768;
    serialized = calloc(1,maxsize);
    serialized2 = calloc(1,maxsize);
    len >>= 1;
    vpnstr[0] = 0;
decode_hex(myprivkey.bytes,sizeof(myprivkey),"18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725");
    memset(&msgtx,0,sizeof(msgtx));
    if ( len < maxsize )
    {
        decode_hex(serialized,len,rawtxstr);
        txjson = cJSON_CreateObject();
        retjson = cJSON_CreateObject();
        if ( (n= iguana_rwmsgtx(coin,0,txjson,serialized,maxsize,&msgtx,&txid,vpnstr)) < 0 )
        {
            printf("bitcoin_txtest len.%d: n.%d from (%s)\n",len,n,rawtxstr);
            free(serialized), free(serialized2);
            return(cJSON_Parse("{\"error\":\"cant parse txbytes\"}"));
        }
        scriptlens = calloc(msgtx.tx_in,sizeof(*scriptlens));
        for (i=0; i<msgtx.tx_in; i++)
            scriptlens[i] = msgtx.vins[i].scriptlen;
        if ( bitcoin_verifyvins(coin,scriptlens,&msgtx,serialized2,maxsize,myprivkey) < 0 )
            printf("sig verification error\n");
        else printf("sigs verified\n");
        for (i=0; i<msgtx.tx_in; i++)
            msgtx.vins[i].scriptlen = scriptlens[i];
        free(scriptlens);

        jadd(retjson,"result",txjson);
        if ( (tp= iguana_txidfind(coin,&height,&T,txid)) != 0 )
        {
            if ( height >= 0 )
            {
                blockhash = iguana_blockhash(coin,height);
                jaddnum(retjson,"height",height);
                jaddnum(retjson,"confirmations",coin->longestchain - height);
                jaddbits256(retjson,"blockhash",blockhash);
            }
        }
        //printf("retjson.(%s) %p\n",jprint(retjson,0),retjson);
        memset(checktxid.bytes,0,sizeof(checktxid));
        if ( (n2= iguana_rwmsgtx(coin,1,0,serialized2,maxsize,&msgtx,&checktxid,vpnstr)) < 0 || n != n2 )
        {
            printf("bitcoin_txtest: n.%d vs n2.%d\n",n,n2);
            free(serialized), free(serialized2);
            return(retjson);
        }
        if ( bits256_cmp(checktxid,txid) != 0 )
        {
            printf("bitcoin_txtest: txid.%s vs check.%s\n",bits256_str(str,txid),bits256_str(str2,checktxid));
        }
        checktxid = iguana_parsetxobj(coin,serialized,maxsize,&msgtx,jobj(retjson,"result"));
        if ( bits256_cmp(checktxid,txid) != 0 )
        {
            printf("bitcoin_txtest: txid.%s vs check2.%s\n",bits256_str(str,txid),bits256_str(str2,checktxid));
        }
        free(serialized), free(serialized2);
        return(retjson);
    }
    free(serialized), free(serialized2);
    return(cJSON_Parse("{\"error\":\"testing bitcoin txbytes\"}"));
}

/*{
    for (i=0; i<T->numinputs; i++)
        strcpy(T->inputs[i].sigs,"00");
        strcpy(vin->sigs,redeemscript);
        vin->sequence = (uint32_t)-1;
        T->nlocktime = 0;
        //disp_cointx(&T);
        emit_cointx(&hash2,data,sizeof(data),T,oldtx_format,SIGHASH_ALL);
        //printf("HASH2.(%llx)\n",(long long)hash2.txid);
        if ( bp_sign(&key,hash2.bytes,sizeof(hash2),&sig,&siglen) != 0 )
        {
            memcpy(sigbuf,sig,siglen);
            sigbuf[siglen++] = SIGHASH_ALL;
            init_hexbytes_noT(sigs[privkeyind],sigbuf,(int32_t)siglen);
            strcpy(vin->sigs,"00");
            for (i=0; i<n; i++)
            {
                if ( sigs[i][0] != 0 )
                {
                    sprintf(vin->sigs + strlen(vin->sigs),"%02x%s",(int32_t)strlen(sigs[i])>>1,sigs[i]);
                    //printf("(%s).%ld ",sigs[i],strlen(sigs[i]));
                }
            }
            len = (int32_t)(strlen(redeemscript)/2);
            if ( len >= 0xfd )
                sprintf(&vin->sigs[strlen(vin->sigs)],"4d%02x%02x",len & 0xff,(len >> 8) & 0xff);
            else sprintf(&vin->sigs[strlen(vin->sigs)],"4c%02x",len);
            sprintf(&vin->sigs[strlen(vin->sigs)],"%s",redeemscript);
            //printf("after A.(%s) othersig.(%s) siglen.%02lx -> (%s)\n",hexstr,othersig != 0 ? othersig : "",siglen,vin->sigs);
            //printf("vinsigs.(%s) %ld\n",vin->sigs,strlen(vin->sigs));
            _emit_cointx(hexstr,sizeof(hexstr),T,oldtx_format);
            //disp_cointx(&T);
            free(T);
            return(clonestr(hexstr));
        }
        else printf("error signing\n");
            free(T);
}*/

#define EXCHANGE_NAME "bitcoin"
#define UPDATE bitcoin ## _price
#define SUPPORTS bitcoin ## _supports
#define SIGNPOST bitcoin ## _signpost
#define TRADE bitcoin ## _trade
#define ORDERSTATUS bitcoin ## _orderstatus
#define CANCELORDER bitcoin ## _cancelorder
#define OPENORDERS bitcoin ## _openorders
#define TRADEHISTORY bitcoin ## _tradehistory
#define BALANCES bitcoin ## _balances
#define PARSEBALANCE bitcoin ## _parsebalance
#define WITHDRAW bitcoin ## _withdraw
#define CHECKBALANCE bitcoin ## _checkbalance
#define ALLPAIRS bitcoin ## _allpairs
#define FUNCS bitcoin ## _funcs
#define BASERELS bitcoin ## _baserels

static char *BASERELS[][2] = { {"btc","nxt"}, {"btc","btcd"}, {"btc","ltc"}, {"btc","vrc"}, {"btc","doge"} };
#include "exchange_supports.h"

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *quotes,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert)
{
    char url[1024],lrel[16],lbase[16];
    strcpy(lrel,rel), strcpy(lbase,base);
    tolowercase(lrel), tolowercase(lbase);
    sprintf(url,"http://api.quadrigacx.com/v2/order_book?book=%s_%s",lbase,lrel);
    return(exchanges777_standardprices(exchange,commission,base,rel,url,quotes,0,0,maxdepth,0,invert));
}

cJSON *SIGNPOST(void **cHandlep,int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *payload,char *path)
{
    if ( retstrp != 0 )
        *retstrp = clonestr("{\"error\":\"bitcoin is not yet\"}");
    return(cJSON_Parse("{}"));
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"bitcoin is not yet\"}"));
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    return(cJSON_Parse("{\"error\":\"bitcoin is not yet\"}"));
}

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    return(0);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"bitcoin is not yet\"}"));
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t quoteid,cJSON *argjson)
{
    return(clonestr("{\"error\":\"bitcoin is not yet\"}"));
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"bitcoin is not yet\"}"));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    return(clonestr("{\"error\":\"bitcoin is not yet\"}"));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    return(clonestr("{\"error\":\"bitcoin is not yet\"}"));
}

struct exchange_funcs bitcoin_funcs = EXCHANGE_FUNCS(bitcoin,EXCHANGE_NAME);

#include "exchange_undefs.h"
