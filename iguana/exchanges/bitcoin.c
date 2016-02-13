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

int32_t bitcoin_pubkeylen(const uint8_t *pubkey)
{
    if ( pubkey[0] == 2 || pubkey[0] == 3 )
        return(33);
    else if ( pubkey[0] == 4 )
        return(65);
    else return(-1);
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
	while ( isspace((uint32_t)(*coinaddr & 0xff)) )
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
        data[i+zeroes] = revdata[len - 1 - i];
    //printf("len.%d be_sz.%d zeroes.%d data[0] %02x\n",len,be_sz,zeroes,data[0]);
out:
	BN_clear_free(&bn58), BN_clear_free(&bn), BN_clear_free(&bnChar);
	BN_CTX_free(ctx);
	return(be_sz);
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
        hash = bits256_doublesha256(0,buf,len - 4);
        *addrtypep = *buf;
        memcpy(rmd160,buf+1,20);
        if ( (buf[len - 4]&0xff) == hash.bytes[31] && (buf[len - 3]&0xff) == hash.bytes[30] &&(buf[len - 2]&0xff) == hash.bytes[29] &&(buf[len - 1]&0xff) == hash.bytes[28] )
        {
            //printf("coinaddr.(%s) valid checksum\n",coinaddr);
            return(20);
        }
        else
        {
            int32_t i; char hexaddr[64];
            btc_convaddr(hexaddr,coinaddr);
            for (i=0; i<len; i++)
                printf("%02x ",buf[i]);
            char str[65]; printf("\nhex.(%s) checkhash.(%s) len.%d mismatch %02x %02x %02x %02x vs %02x %02x %02x %02x (%s)\n",hexaddr,coinaddr,len,buf[len - 4]&0xff,buf[len - 3]&0xff,buf[len - 2]&0xff,buf[len - 1]&0xff,hash.bytes[31],hash.bytes[30],hash.bytes[29],hash.bytes[28],bits256_str(str,hash));
        }
    }
	return(0);
}

void calc_rmd160_sha256(uint8_t rmd160[20],uint8_t *data,int32_t datalen)
{
    bits256 hash;
    vcalc_sha256(0,hash.bytes,data,datalen);
    calc_rmd160(0,rmd160,hash.bytes,sizeof(hash));
}

char *bitcoin_address(char *coinaddr,uint8_t addrtype,uint8_t *pubkey,int32_t len)
{
    int32_t i; uint8_t data[25]; bits256 hash; char checkaddr[65];
    if ( len != 20 )
        calc_rmd160_sha256(data+1,pubkey,len);
    else memcpy(data+1,pubkey,20);
    btc_convrmd160(checkaddr,addrtype,data+1);
    //for (i=0; i<20; i++)
    //    printf("%02x",data[i+1]);
    //printf(" RMD160 len.%d\n",len);
    data[0] = addrtype;
    hash = bits256_doublesha256(0,data,21);
    for (i=0; i<4; i++)
        data[21+i] = hash.bytes[31-i];
    if ( (coinaddr= bitcoin_base58encode(coinaddr,data,25)) != 0 )
    {
        uint8_t checktype,rmd160[20];
        bitcoin_addr2rmd160(&checktype,rmd160,coinaddr);
        if ( strcmp(checkaddr,coinaddr) != 0 )
            printf("checkaddr.(%s) vs coinaddr.(%s) %02x vs [%02x] memcmp.%d\n",checkaddr,coinaddr,addrtype,checktype,memcmp(rmd160,data+1,20));
    }
    return(coinaddr);
}

int32_t bitcoin_validaddress(struct iguana_info *coin,char *coinaddr)
{
    uint8_t rmd160[20],addrtype;
    if ( coin == 0 || coinaddr == 0 || coinaddr[0] == 0 )
        return(-1);
    else if ( bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr) < 0 )
        return(-1);
    else if ( addrtype != coin->chain->pubtype && addrtype != coin->chain->p2shtype )
        return(-1);
    else if ( bitcoin_address(coinaddr,addrtype,rmd160,sizeof(rmd160)) != coinaddr )
        return(-1);
    return(0);
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

bits256 bitcoin_pubkey33(uint8_t *data,bits256 privkey)
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

/*int32_t bitcoin_priv2wif(char *wifstr,uint8_t privkey[32],uint8_t addrtype)
{
    uint8_t tmp[128]; char hexstr[67]; cstring *btc_addr;
    memcpy(tmp,privkey,32);
    tmp[32] = 1;
    init_hexbytes_noT(hexstr,tmp,32);
    if ( (btc_addr= base58_encode_check(addrtype,true,tmp,33)) != 0 )
    {
        strcpy(wifstr,btc_addr->str);
        cstr_free(btc_addr,true);
    }
    printf("-> (%s) -> wif.(%s) addrtype.%02x\n",hexstr,wifstr,addrtype);
    return(0);
}

int32_t bitcoin_wif2priv(uint8_t *addrtypep,uint8_t privkey[32],char *wifstr)
{
    cstring *cstr; int32_t len = -1;
    if ( (cstr= base58_decode_check(addrtypep,(const char *)wifstr)) != 0 )
    {
        init_hexbytes_noT((void *)privkey,(void *)cstr->str,cstr->len);
        if ( cstr->str[cstr->len-1] == 0x01 )
            cstr->len--;
        memcpy(privkey,cstr->str,cstr->len);
        len = (int32_t)cstr->len;
        char tmp[138];
        btc_priv2wif(tmp,privkey,*addrtypep);
        printf("addrtype.%02x wifstr.(%llx) len.%d\n",*addrtypep,*(long long *)privkey,len);
        cstr_free(cstr,true);
    }
    return(len);
}*/

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
    script[n++] = OP_CHECKLOCKTIMEVERIFY;
    script[n++] = OP_DROP;
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

int32_t bitcoin_scriptsig(uint8_t *script,int32_t n,const struct vin_info *vp)
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
        n = bitcoin_p2shscript(script,n,vp->p2shscript,vp->p2shlen);
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
    uint8_t addrtype; char rmd160str[41],pubkeystr[256]; int32_t i,m,n,flag = 0,scriptlen = 0;
    m = n = 1;
    if ( type == IGUANA_SCRIPT_76A988AC || type == IGUANA_SCRIPT_76AC || type == IGUANA_SCRIPT_P2SH )
    {
        if ( type == IGUANA_SCRIPT_P2SH )
            addrtype = coin->chain->p2shtype;
        else addrtype = coin->chain->pubtype;
        init_hexbytes_noT(rmd160str,rmd160,20);
        btc_convrmd160(coinaddr,addrtype,rmd160);
    }
    switch ( type )
    {
        case IGUANA_SCRIPT_NULL:
            strcpy(asmstr,txi == 0 ? "coinbase " : "PoSbase ");
            flag++;
            coinaddr[0] = 0;
            break;
        case IGUANA_SCRIPT_76AC:
            init_hexbytes_noT(pubkeystr,(uint8_t *)vp->signers[0].pubkey,bitcoin_pubkeylen(vp->signers[0].pubkey));
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
        default: printf("unexpected script type\n"); break;
    }
    if ( n > 1 )
    {
        scriptlen = bitcoin_MofNspendscript(rmd160,script,0,vp);
        sprintf(asmstr,"%d ",m);
        for (i=0; i<n; i++)
        {
            init_hexbytes_noT(asmstr + strlen(asmstr),(uint8_t *)vp->signers[i].pubkey,bitcoin_pubkeylen(vp->signers[i].pubkey));
            strcat(asmstr," ");
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
        //vcalc_sha256(0,sha256,&vp->spendscript[3],vp->spendscript[2]);
        //calc_rmd160(0,vp->rmd160,sha256,sizeof(sha256));
        memcpy(vp->rmd160,&vp->spendscript[3],20);
        if ( (plen= vp->spendscript[2]+5) < vp->spendlen )
        {
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
    if ( type != IGUANA_SCRIPT_OPRETURN )
    {
        if ( vp->spendlen < sizeof(hexstr)/2-1)
        {
            static FILE *fp;
            init_hexbytes_noT(hexstr,vp->spendscript,vp->spendlen);
            char str[65]; printf("unparsed script.(%s).%d in %s len.%d\n",hexstr,vp->spendlen,bits256_str(str,vp->vin.prev_hash),vp->spendlen);
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
    if ( (vp->type= _iguana_calcrmd160(coin,vp)) >= 0 )
    {
        scriptlen = iguana_scriptgen(coin,&vp->M,&vp->N,vp->coinaddr,script,asmstr,vp->rmd160,vp->type,(const struct vin_info *)vp,vout);
        if ( scriptlen != pk_scriptlen || (scriptlen != 0 && memcmp(script,pk_script,scriptlen) != 0) )
        {
            if ( vp->type != IGUANA_SCRIPT_OPRETURN && vp->type != IGUANA_SCRIPT_DATA )
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
            hexstr = jstr(sigjson,"hex");
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

cJSON *iguana_voutjson(struct iguana_info *coin,struct iguana_msgvout *vout,int32_t txi,bits256 txid)
{
    // 035f1321ed17d387e4433b2fa229c53616057964af065f98bfcae2233c5108055e OP_CHECKSIG
    char scriptstr[8192+1],asmstr[16384]; int32_t i,m,n,scriptlen,asmtype; struct vin_info *vp;
    uint8_t space[8192]; cJSON *addrs,*skey,*json = cJSON_CreateObject();
    vp = calloc(1,sizeof(*vp));
    jaddnum(json,"value",dstr(vout->value));
    jaddnum(json,"n",txi);
    //"scriptPubKey":{"asm":"OP_DUP OP_HASH160 5f69cb73016264270dae9f65c51f60d0e4d6fd44 OP_EQUALVERIFY OP_CHECKSIG","reqSigs":1,"type":"pubkeyhash","addresses":["RHyh1V9syARTf2pyxibz7v27D5paBeWza5"]}
    if ( vout->pk_script != 0 && vout->pk_scriptlen*2+1 < sizeof(scriptstr) )
    {
        memset(vp,0,sizeof(*vp));
        if ( (asmtype= iguana_calcrmd160(coin,vp,vout->pk_script,vout->pk_scriptlen,txid,txi,0xffffffff)) >= 0 )
        {
            skey = cJSON_CreateObject();
            scriptlen = iguana_scriptgen(coin,&m,&n,vp->coinaddr,space,asmstr,vp->rmd160,asmtype,vp,txi);
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
        jaddstr(sigjson,"hex",scriptstr);
        jadd(json,"scriptSig",sigjson);
    }
    return(json);
}

int32_t iguana_vinparse(struct iguana_info *coin,int32_t rwflag,uint8_t *serialized,struct iguana_msgvin *msg)
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
            len += iguana_vinparse(coin,rwflag,&serialized[len],&msg->vins[i]);
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

bits256 iguana_parsetxobj(struct iguana_info *coin,int32_t *txstartp,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,cJSON *txobj) // json -> serialized + (msg,V)
{
    int32_t i,numvins,numvouts,len = 0; cJSON *array=0; bits256 txid; char vpnstr[64];
    memset(msg,0,sizeof(*msg));
    vpnstr[0] = 0;
    if ( (msg->version= juint(txobj,"version")) == 0 )
        msg->version = 1;
    if ( coin->chain->hastimestamp != 0 )
    {
        if ( (msg->timestamp= juint(txobj,"timestamp")) == 0 )
            msg->timestamp = (uint32_t)time(NULL);
    }
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
    *txstartp = len;
    msg->allocsize = iguana_rwmsgtx(coin,1,0,&serialized[len],maxsize-len,msg,&txid,vpnstr);
    //char str[65]; printf("json -> %s\n",bits256_str(str,txid));
    return(txid);
}

char *iguana_rawtxbytes(struct iguana_info *coin,cJSON *json,struct iguana_msgtx *msgtx)
{
    int32_t n; char *txbytes = 0,vpnstr[64]; uint8_t *serialized;
    serialized = malloc(IGUANA_MAXPACKETSIZE);
    vpnstr[0] = 0;
    //char str[65]; printf("%d of %d: %s\n",i,msg.txn_count,bits256_str(str,tx.txid));
    if ( (n= iguana_rwmsgtx(coin,1,json,serialized,IGUANA_MAXPACKETSIZE,msgtx,&msgtx->txid,vpnstr)) > 0 )
    {
        txbytes = malloc(n*2+1);
        init_hexbytes_noT(txbytes,serialized,n);
    }
    free(serialized);
    return(txbytes);
}

int32_t bitcoin_scriptget(struct iguana_info *coin,int32_t *hashtypep,struct vin_info *vp,uint8_t *scriptsig,int32_t len,int32_t type)
{
    char asmstr[IGUANA_MAXSCRIPTSIZE*3]; int32_t j,n,siglen,plen;
    j = n = 0;
    *hashtypep = SIGHASH_ALL;
    while ( (siglen= scriptsig[n]) >= 70 && siglen <= 73 && n+siglen+1 < len && j < 16 )
    {
        vp->signers[j].siglen = siglen;
        memcpy(vp->signers[j].sig,&scriptsig[n+1],siglen);
        if ( j == 0 )
            *hashtypep = vp->signers[j].sig[siglen-1];
        n += (siglen + 1);
        j++;
        if ( type == 0 && j > 1 )
            type = IGUANA_SCRIPT_MSIG;
    }
    vp->type = type;
    j = 0;
    while ( ((plen= scriptsig[n]) == 33 || plen == 65 ) && j < 16 )
    {
        memcpy(vp->signers[j].pubkey,&scriptsig[n+1],plen);
        calc_rmd160_sha256(vp->signers[j].rmd160,vp->signers[j].pubkey,plen);
        if ( j == 0 )
            memcpy(vp->rmd160,vp->signers[j].rmd160,20);
        n += (plen + 1);
        j++;
    }
    if ( n < len && (scriptsig[n] == 0x4c || scriptsig[n] == 0x4d) )
    {
        if ( scriptsig[n] == 0x4c )
            vp->p2shlen = scriptsig[n+1], n += 2;
        else vp->p2shlen = ((uint32_t)scriptsig[n+1] + ((uint32_t)scriptsig[n+2] << 8)), n += 3;
        memcpy(vp->p2shscript,&scriptsig[n],vp->p2shlen);
        vp->type = IGUANA_SCRIPT_P2SH;
    }
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

int32_t bitcoin_verifyvins(struct iguana_info *coin,bits256 *signedtxidp,char **signedtx,int32_t *scriptlens,struct iguana_msgtx *msgtx,uint8_t *serialized,int32_t maxsize,struct vin_info *V,int32_t sighashsingle)
{
    bits256 txid,sigtxid,revsigtxid; char txidstr[128],bigstr[2560],coinaddr[64],vpnstr[64],str[65];
    uint8_t *sig,*pubkey,*saveinput; struct vin_info *vp;
    int32_t n2,i,j,k,plen,vini=0,flag,numvins,hashtype,retval,siglen,asmtype,numvouts = msgtx->tx_out;
    vpnstr[0] = 0;
    *signedtx = 0;
    memset(signedtxidp,0,sizeof(*signedtxidp));
    numvins = msgtx->tx_in;
    retval = -numvins;
    for (vini=0; vini<numvins; vini++)
    {
        saveinput = msgtx->vins[vini].script;
        vp = &V[vini];
        for (i=0; i<numvins; i++)
            msgtx->vins[i].scriptlen = 0;
        sig = &msgtx->vins[vini].script[1];
        siglen = msgtx->vins[vini].script[0];
        vp->vin = msgtx->vins[vini];
        flag = 0;
        for (k=0; k<2; k++)
        {
            asmtype = (k == 0) ? IGUANA_SCRIPT_76A988AC : IGUANA_SCRIPT_76AC;
            if ( bitcoin_scriptget(coin,&hashtype,vp,saveinput,scriptlens[vini],asmtype) < 0 )
            {
                printf("cant get script for (%s).v%d\n",bits256_str(str,vp->vin.prev_hash),vp->vin.prev_vout);
                continue;
            }
            if ( sighashsingle != 0 && vini == 0 )
            {
                msgtx->tx_out = 1;
                hashtype = SIGHASH_SINGLE;
            } else msgtx->tx_out = numvouts;
            msgtx->vins[vini].script = vp->spendscript;
            msgtx->vins[vini].scriptlen = vp->spendlen;
            for (j=0; j<vp->N; j++)
            {
                pubkey = vp->signers[j].pubkey;
                if ( (plen= bitcoin_pubkeylen(pubkey)) < 0 )
                {
                    printf("illegal plen.%d [%02x]\n",plen,pubkey[0]);
                    break;
                }
                bitcoin_address(coinaddr,coin->chain->pubtype,pubkey,plen);
                n2 = iguana_rwmsgtx(coin,1,0,serialized,maxsize,msgtx,&txid,vpnstr);
                msgtx->vins[vini].script = saveinput;
                if ( n2 > 0 )
                {
                    n2 += iguana_rwnum(1,&serialized[n2],sizeof(hashtype),&hashtype);
                    printf("hashtype.%d [%02x]\n",hashtype,sig[siglen-1]);
                    revsigtxid = bits256_doublesha256(txidstr,serialized,n2);
                    for (i=0; i<sizeof(revsigtxid); i++)
                        sigtxid.bytes[31-i] = revsigtxid.bytes[i];
                    if ( 1 && bits256_nonz(vp->signers[j].privkey) != 0 )
                    {
                        vp->signers[j].siglen = bitcoin_sign(vp->signers[j].sig,sizeof(vp->signers[j].sig),sigtxid.bytes,sizeof(sigtxid),vp->signers[j].privkey);
                        sig = vp->signers[j].sig;
                        sig[vp->signers[j].siglen++] = hashtype;
                        siglen = vp->signers[j].siglen;
                        msgtx->vins[vini].scriptlen = bitcoin_scriptsig(msgtx->vins[vini].script,0,(const struct vin_info *)vp);
                        for (i=0; i<siglen; i++)
                            printf("%02x",sig[i]);
                        printf(" SIGNEDTX.[%02x] plen.%d siglen.%d\n",sig[siglen-1],plen,siglen);
                    }
                    if ( bitcoin_verify(sig,siglen,sigtxid.bytes,sizeof(sigtxid),0,vp->signers[j].pubkey,bitcoin_pubkeylen(vp->signers[j].pubkey)) < 0 )
                    {
                        init_hexbytes_noT(bigstr,serialized,n2);
                        printf("(%s) doesnt verify hash2.%s\n",bigstr,bits256_str(str,sigtxid));
                    }
                    else
                    {
                        *signedtx = iguana_rawtxbytes(coin,0,msgtx);
                        *signedtxidp = msgtx->txid;
                        printf("SIG.%d VERIFIED %s\n",vini,*signedtx);
                        flag = 1;
                        break;
                    }
                } else printf("bitcoin_verifyvins: vini.%d n2.%d\n",vini,n2);
            }
            if ( flag > 0 )
            {
                retval++;
                break;
            }
            if ( vp->type != IGUANA_SCRIPT_76A988AC && vp->type != IGUANA_SCRIPT_76AC )
                break;
        }
    }
    return(retval);
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

int32_t bitcoin_verifytx(struct iguana_info *coin,bits256 *signedtxidp,char **signedtx,char *rawtxstr,struct vin_info *V)
{
    int32_t i,len,maxsize,*scriptlens,numvins,retval = -1; uint8_t *serialized,*serialized2;
    struct iguana_msgtx msgtx; bits256 txid; char vpnstr[64];
    len = (int32_t)strlen(rawtxstr);
    maxsize = len + 32768;
    serialized = calloc(1,maxsize);
    serialized2 = calloc(1,maxsize);
    len >>= 1;
    vpnstr[0] = 0;
    decode_hex(serialized,len,rawtxstr);
    memset(&msgtx,0,sizeof(msgtx));
    if ( iguana_rwmsgtx(coin,0,0,serialized,maxsize,&msgtx,&txid,vpnstr) > 0 )
    {
        numvins = msgtx.tx_in;
        scriptlens = calloc(numvins,sizeof(*scriptlens));
        for (i=0; i<numvins; i++)
            scriptlens[i] = msgtx.vins[i].scriptlen;
        if ( bitcoin_verifyvins(coin,signedtxidp,signedtx,scriptlens,&msgtx,serialized2,maxsize,V,0) == 0 )
            retval = 0;
        else printf("bitcoin_verifytx: bitcoin_verifyvins error\n");
        for (i=0; i<numvins; i++)
            msgtx.vins[i].scriptlen = scriptlens[i];
        free(scriptlens);
    } else printf("bitcoin_verifytx: error iguana_rwmsgtx\n");
    free(serialized), free(serialized2);
    return(retval);
}

char *bitcoin_json2hex(struct iguana_info *coin,bits256 *txidp,cJSON *txjson)
{
    int32_t txstart; uint8_t *serialized; struct iguana_msgtx msgtx; char *txbytes = 0;
    serialized = malloc(IGUANA_MAXPACKETSIZE);
    *txidp = iguana_parsetxobj(coin,&txstart,serialized,IGUANA_MAXPACKETSIZE,&msgtx,txjson);
    if ( msgtx.allocsize != 0 )
    {
        txbytes = malloc(msgtx.allocsize*2 + 1);
        init_hexbytes_noT(txbytes,&serialized[txstart],msgtx.allocsize);
    } else printf("bitcoin_txtest: zero msgtx allocsize\n");
    free(serialized);
    return(txbytes);
}

cJSON *bitcoin_hex2json(struct iguana_info *coin,bits256 *txidp,struct iguana_msgtx *msgtx,char *txbytes)
{
    int32_t n,len; char vpnstr[64]; struct iguana_msgtx M; uint8_t *serialized; cJSON *txobj;
    txobj = cJSON_CreateObject();
    if ( msgtx == 0 )
    {
        msgtx = &M;
        memset(msgtx,0,sizeof(M));
    }
    len = (int32_t)strlen(txbytes) >> 1;
    serialized = malloc(len);
    decode_hex(serialized,len,txbytes);
    vpnstr[0] = 0;
    memset(txidp,0,sizeof(*txidp));
    //char str[65]; printf("%d of %d: %s\n",i,msg.txn_count,bits256_str(str,tx.txid));
    if ( (n= iguana_rwmsgtx(coin,0,txobj,serialized,len,msgtx,txidp,vpnstr)) <= 0 )
    {
        free_json(txobj);
        txobj = 0;
    }
    free(serialized);
    return(txobj);
}

cJSON *bitcoin_createtx(struct iguana_info *coin,int32_t locktime)
{
    cJSON *json = cJSON_CreateObject();
    if ( locktime == 0 )
    {
        jaddnum(json,"version",1);
        jaddnum(json,"locktime",0);
    }
    else
    {
        jaddnum(json,"version",4);
        jaddnum(json,"locktime",locktime);
    }
    if ( coin->chain->hastimestamp != 0 )
        jaddnum(json,"timestamp",time(NULL));
    jadd(json,"vin",cJSON_CreateArray());
    jadd(json,"vout",cJSON_CreateArray());
    return(json);
}

cJSON *bitcoin_addoutput(struct iguana_info *coin,cJSON *txobj,uint8_t *paymentscript,int32_t len,uint64_t satoshis)
{
    char *hexstr; cJSON *item,*skey,*vouts = jduplicate(jobj(txobj,"vout"));
    item = cJSON_CreateObject();
    jaddnum(item,"value",dstr(satoshis));
    skey = cJSON_CreateObject();
    hexstr = malloc(len*2 + 1);
    init_hexbytes_noT(hexstr,paymentscript,len);
    jaddstr(skey,"hex",hexstr);
    free(hexstr);
    jadd(item,"scriptPubkey",skey);
    jdelete(vouts,"vout");
    jadd(vouts,"vout",item);
    return(txobj);
}

cJSON *bitcoin_addinput(struct iguana_info *coin,cJSON *txobj,bits256 txid,int32_t vout,uint32_t sequence)
{
    cJSON *item,*vins = jduplicate(jobj(txobj,"vin"));
    item = cJSON_CreateObject();
    jaddbits256(item,"txid",txid);
    jaddnum(item,"vout",vout);
    jaddnum(item,"sequence",sequence);
    jdelete(vins,"vin");
    jadd(vins,"vin",item);
    return(txobj);
}

char *bitcoin_cltvtx(struct iguana_info *coin,char *changeaddr,char *senderaddr,char *senders_otheraddr,char *otheraddr,uint32_t locktime,uint64_t satoshis,bits256 txid,int32_t vout,uint64_t inputsatoshis,bits256 privkey)
{
    uint64_t change; char *rawtxstr,*signedtx; struct vin_info V; bits256 cltxid,signedtxid;
    int32_t cltvlen,len; uint32_t timestamp; char ps2h_coinaddr[65]; cJSON *txobj;
    uint8_t p2sh_rmd160[20],cltvscript[1024],paymentscript[64],rmd160[20],secret160[20],addrtype;
    timestamp = (uint32_t)time(NULL);
    bitcoin_addr2rmd160(&addrtype,secret160,senders_otheraddr);
    cltvlen = bitcoin_cltvscript(coin->chain->p2shtype,ps2h_coinaddr,p2sh_rmd160,cltvscript,0,senderaddr,otheraddr,secret160,locktime);
    txobj = bitcoin_createtx(coin,locktime);
    len = bitcoin_p2shspend(paymentscript,0,p2sh_rmd160);
    bitcoin_addoutput(coin,txobj,paymentscript,len,satoshis);
    bitcoin_addinput(coin,txobj,txid,vout,locktime);
    if ( inputsatoshis > (satoshis + 10000) )
    {
        change = inputsatoshis - (satoshis + 10000);
        if ( changeaddr != 0 && changeaddr[0] != 0 )
        {
            bitcoin_addr2rmd160(&addrtype,rmd160,changeaddr);
            if ( addrtype == coin->chain->pubtype )
                len = bitcoin_standardspend(paymentscript,0,rmd160);
            else if ( addrtype == coin->chain->p2shtype )
                len = bitcoin_standardspend(paymentscript,0,rmd160);
            else
            {
                printf("error with mismatched addrtype.%02x vs (%02x %02x)\n",addrtype,coin->chain->pubtype,coin->chain->p2shtype);
                return(0);
            }
            bitcoin_addoutput(coin,txobj,paymentscript,len,change);
        }
        else
        {
            printf("error no change address when there is change\n");
            return(0);
        }
    }
    rawtxstr = bitcoin_json2hex(coin,&cltxid,txobj);
    char str[65]; printf("CLTV.%s (%s)\n",bits256_str(str,cltxid),rawtxstr);
    memset(&V,0,sizeof(V));
    V.signers[0].privkey = privkey;
    bitcoin_verifytx(coin,&signedtxid,&signedtx,rawtxstr,&V);
    free(rawtxstr);
    if ( signedtx != 0 )
        printf("signed CLTV.%s (%s)\n",bits256_str(str,signedtxid),signedtx);
    else printf("error generating signedtx\n");
    free_json(txobj);
    return(signedtx);
}

cJSON *bitcoin_txtest(struct iguana_info *coin,char *rawtxstr,bits256 txid)
{
    struct iguana_msgtx msgtx; char str[65],str2[65]; bits256 checktxid,blockhash,signedtxid;
    cJSON *retjson,*txjson; uint8_t *serialized,*serialized2; struct iguana_txid T,*tp;
    struct vin_info *V; char vpnstr[64],*txbytes,*signedtx; int32_t n,txstart,height,n2,maxsize,len;
rawtxstr = refstr;
    len = (int32_t)strlen(rawtxstr);
    maxsize = len + 32768;
    serialized = calloc(1,maxsize);
    serialized2 = calloc(1,maxsize);
    len >>= 1;
    V = 0;
    vpnstr[0] = 0;
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
        V = calloc(msgtx.tx_in,sizeof(*V));
        {
            //char *pstr; int32_t plen;
            decode_hex(V[0].signers[0].privkey.bytes,sizeof(V[0].signers[0].privkey),"18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725");
            //pstr = "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6";
            //plen = (int32_t)strlen(pstr);
            //decode_hex(V[0].signers[0].pubkey,plen,pstr);
        }
        if ( bitcoin_verifytx(coin,&signedtxid,&signedtx,rawtxstr,V) != 0 )
            printf("bitcoin_verifytx error\n");
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
            free(serialized), free(serialized2), free(V);
            return(retjson);
        }
        if ( bits256_cmp(checktxid,txid) != 0 )
        {
            printf("bitcoin_txtest: txid.%s vs check.%s\n",bits256_str(str,txid),bits256_str(str2,checktxid));
        }
        checktxid = iguana_parsetxobj(coin,&txstart,serialized,maxsize,&msgtx,jobj(retjson,"result"));
        if ( bits256_cmp(checktxid,txid) != 0 )
        {
            printf("bitcoin_txtest: txid.%s vs check2.%s\n",bits256_str(str,txid),bits256_str(str2,checktxid));
        }
        if ( msgtx.allocsize != 0 )
        {
            txbytes = malloc(msgtx.allocsize*2 + 1);
            init_hexbytes_noT(txbytes,&serialized[txstart],msgtx.allocsize);
            if ( strcmp(txbytes,rawtxstr) != 0 )
                printf("bitcoin_txtest: reconstruction error: %s != %s\n",rawtxstr,txbytes);
            else printf("reconstruction PASSED\n");
            free(txbytes);
        } else printf("bitcoin_txtest: zero msgtx allocsize\n");
        free(serialized), free(serialized2), free(V);
        return(retjson);
    }
    free(serialized), free(serialized2);
    return(cJSON_Parse("{\"error\":\"testing bitcoin txbytes\"}"));
}

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

static char *BASERELS[][2] = { {"btcd","btc"}, {"nxt","btc"}, {"asset","btc"} };
#include "exchange_supports.h"

double UPDATE(struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *bidasks,int32_t maxdepth,double commission,cJSON *argjson,int32_t invert)
{
    cJSON *retjson,*bids,*asks; double hbla;
    bids = cJSON_CreateArray();
    asks = cJSON_CreateArray();
    instantdex_offerfind(SuperNET_MYINFO(0),exchange,bids,asks,0,base,rel);
    retjson = cJSON_CreateObject();
    cJSON_AddItemToObject(retjson,"bids",bids);
    cJSON_AddItemToObject(retjson,"asks",asks);
    hbla = exchanges777_json_orderbook(exchange,commission,base,rel,bidasks,maxdepth,retjson,0,"bids","asks",0,0,invert);
    free_json(retjson);
    return(hbla);
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    //struct supernet_info *myinfo = SuperNET_accountfind(argjson);
    return(clonestr("{\"error\":\"bitcoin is not yet\"}"));
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    //struct supernet_info *myinfo = SuperNET_accountfind(argjson);
    return(cJSON_Parse("{\"error\":\"bitcoin is not yet\"}"));
}

int32_t is_valid_BTCother(char *other)
{
    if ( iguana_coinfind(other) != 0 )
        return(1);
    else if ( strcmp(other,"NXT") == 0 || strcmp(other,"nxt") == 0 )
        return(1);
    else if ( is_decimalstr(other) > 0 )
        return(1);
    else return(0);
}

uint64_t TRADE(int32_t dotrade,char **retstrp,struct exchange_info *exchange,char *base,char *rel,int32_t dir,double price,double volume,cJSON *argjson)
{
    char *str,coinaddr[64]; uint64_t txid = 0; cJSON *tmp,*json=0; struct instantdex_accept *ap;
    struct supernet_info *myinfo; uint8_t pubkey[33]; struct iguana_info *other;
    myinfo = SuperNET_accountfind(argjson);
    //printf("TRADE with myinfo.%p\n",myinfo);
    if ( retstrp != 0 )
        *retstrp = 0;
    if ( strcmp(base,"BTC") == 0 || strcmp(base,"btc") == 0 )
    {
        base = rel;
        rel = "BTC";
        dir = -dir;
        volume *= price;
        price = 1. / price;
    }
    if ( is_valid_BTCother(base) != 0 && (strcmp(rel,"BTC") == 0 || strcmp(rel,"btc") == 0) )
    {
        if ( dotrade == 0 )
        {
            if ( retstrp != 0 )
                *retstrp = clonestr("{\"result\":\"would issue new trade\"}");
        }
        else
        {
            if ( (other= iguana_coinfind(base)) != 0 )
            {
                bitcoin_pubkey33(pubkey,myinfo->persistent_priv);
                bitcoin_address(coinaddr,other->chain->pubtype,pubkey,sizeof(pubkey));
                jaddstr(argjson,base,coinaddr);
            }
            else if ( strcmp(base,"NXT") == 0 || (is_decimalstr(base) > 0 && strlen(base) > 13) )
            {
                printf("NXT is not yet\n");
                return(0);
            }
            else return(0);
            json = cJSON_CreateObject();
            jaddstr(json,"base",base);
            jaddstr(json,"rel","BTC");
            jaddnum(json,dir > 0 ? "maxprice" : "minprice",price);
            jaddnum(json,"volume",volume);
            jaddstr(json,"BTC",myinfo->myaddr.BTC);
            //printf("trade dir.%d (%s/%s) %.6f vol %.8f\n",dir,base,"BTC",price,volume);
            if ( (str= instantdex_queueaccept(myinfo,&ap,exchange,base,"BTC",price,volume,-dir,dir > 0 ? "BTC" : base,INSTANTDEX_OFFERDURATION,myinfo->myaddr.nxt64bits)) != 0 )
            {
                if ( (tmp= cJSON_Parse(str)) != 0 )
                {
                    txid = j64bits(json,"orderid");
                    if ( (ap= instantdex_offerfind(myinfo,exchange,0,0,txid,"*","*")) != 0 )
                    {
                        if ( (str= instantdex_btcoffer(myinfo,exchange,ap)) != 0 )
                        {
                            json = cJSON_CreateObject();
                            jaddstr(json,"BTCoffer",str);
                        } else printf("null return from btcoffer\n");
                    } else printf("couldnt find just added offer\n");
                    free_json(tmp);
                } else printf("queueaccept return parse error.(%s)\n",str);
            } else printf("null return queueaccept\n");
            if ( retstrp != 0 )
                *retstrp = jprint(json,1);
            else free_json(json);
        }
    }
    return(txid);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t orderid,cJSON *argjson)
{
    struct instantdex_accept *ap; cJSON *retjson;
    struct supernet_info *myinfo = SuperNET_accountfind(argjson);
    if ( (ap= instantdex_offerfind(myinfo,exchange,0,0,orderid,"*","*")) != 0 )
    {
        retjson = cJSON_CreateObject();
        jadd(retjson,"result",instantdex_acceptjson(ap));
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"couldnt find orderid\"}"));
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t orderid,cJSON *argjson)
{
    struct instantdex_accept *ap; cJSON *retjson;
    struct supernet_info *myinfo = SuperNET_accountfind(argjson);
    if ( (ap= instantdex_offerfind(myinfo,exchange,0,0,orderid,"*","*")) != 0 )
    {
        ap->dead = (uint32_t)time(NULL);
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","killed orderid, but might have pending");
        jadd(retjson,"order",instantdex_acceptjson(ap));
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"couldnt find orderid\"}"));
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    cJSON *retjson,*bids,*asks;
    struct supernet_info *myinfo = SuperNET_accountfind(argjson);
    bids = cJSON_CreateArray();
    asks = cJSON_CreateArray();
    instantdex_offerfind(myinfo,exchange,bids,asks,0,"*","*");
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jadd(retjson,"bids",bids);
    jadd(retjson,"asks",asks);
    return(jprint(retjson,1));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    //struct supernet_info *myinfo = SuperNET_accountfind(argjson);
    return(clonestr("{\"error\":\"bitcoin is not yet\"}"));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    //struct supernet_info *myinfo = SuperNET_accountfind(argjson);
    return(clonestr("{\"error\":\"bitcoin is not yet\"}"));
}

struct exchange_funcs bitcoin_funcs = EXCHANGE_FUNCS(bitcoin,EXCHANGE_NAME);

#include "exchange_undefs.h"


#include "../../includes/iguana_apidefs.h"
#include "../../includes/iguana_apideclares.h"

char *_setVsigner(struct iguana_info *coin,struct vin_info *V,int32_t ind,char *pubstr,char *wifstr)
{
    uint8_t addrtype;
    decode_hex(V->signers[ind].pubkey,(int32_t)strlen(pubstr)/2,pubstr);
    btc_wif2priv(&addrtype,V->signers[ind].privkey.bytes,wifstr);
    if ( addrtype != coin->chain->pubtype )
        return(clonestr("{\"error\":\"invalid wifA\"}"));
    else return(0);
}

int32_t bitcoin_txaddspend(struct iguana_info *coin,cJSON *txobj,char *destaddress,double destamount)
{
    uint8_t outputscript[128],addrtype,rmd160[20]; int32_t scriptlen;
    if ( bitcoin_validaddress(coin,destaddress) == 0 && destamount > 0. )
    {
        bitcoin_addr2rmd160(&addrtype,rmd160,destaddress);
        scriptlen = bitcoin_standardspend(outputscript,0,rmd160);
        bitcoin_addoutput(coin,txobj,outputscript,scriptlen,destamount * SATOSHIDEN);
        return(0);
    } else return(-1);
}

P2SH_SPENDAPI(iguana,spendmsig,activecoin,vintxid,vinvout,destaddress,destamount,destaddress2,destamount2,M,N,pubA,wifA,pubB,wifB,pubC,wifC)
{
    struct vin_info V; uint8_t p2sh_rmd160[20],serialized[2096];
    char msigaddr[64],*retstr; cJSON *retjson,*txobj; struct iguana_info *active;
    bits256 signedtxid; char *signedtx; int scriptlens[1];
    struct iguana_msgtx msgtx;
    if ( (active= iguana_coinfind(activecoin)) == 0 )
        return(clonestr("{\"error\":\"activecoin isnt active\"}"));
    if ( M > N || N > 3 )
        return(clonestr("{\"error\":\"illegal M or N\"}"));
    memset(&V,0,sizeof(V));
    txobj = bitcoin_createtx(active,0);
    if ( destaddress[0] != 0 && destamount > 0. )
        bitcoin_txaddspend(active,txobj,destaddress,destamount);
    if ( destaddress2[0] != 0 && destamount2 > 0. )
        bitcoin_txaddspend(active,txobj,destaddress2,destamount2);
    bitcoin_addinput(active,txobj,vintxid,vinvout,0xffffffff);
    if ( pubA[0] != 0 && (retstr= _setVsigner(active,&V,0,pubA,wifA)) != 0 )
        return(retstr);
    if ( N >= 2 && pubB[0] != 0 && (retstr= _setVsigner(active,&V,1,pubB,wifC)) != 0 )
        return(retstr);
    if ( N == 3 && pubC[0] != 0 && (retstr= _setVsigner(active,&V,2,pubC,wifC)) != 0 )
        return(retstr);
    V.M = M, V.N = N, V.type = IGUANA_SCRIPT_P2SH;
    V.p2shlen = bitcoin_MofNspendscript(p2sh_rmd160,V.p2shscript,0,&V);
    bitcoin_address(msigaddr,active->chain->p2shtype,V.p2shscript,V.p2shlen);
    scriptlens[0] = 0;
    retjson = cJSON_CreateObject();
    if ( bitcoin_verifyvins(active,&signedtxid,&signedtx,scriptlens,&msgtx,serialized,sizeof(serialized),&V,0) == 0 )
    {
        jaddstr(retjson,"result","msigtx");
        if ( signedtx != 0 )
            jaddstr(retjson,"signedtx",signedtx), free(signedtx);
        jaddbits256(retjson,"txid",signedtxid);
    } else jaddstr(retjson,"error","couldnt sign tx");
    jaddstr(retjson,"msigaddr",msigaddr);
    return(jprint(retjson,1));
}
#include "../../includes/iguana_apiundefs.h"

